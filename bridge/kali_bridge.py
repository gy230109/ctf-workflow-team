"""Team CTF workflow component. See README.md for configuration and verified scope."""
import argparse
import base64
import datetime as dt
import hashlib
import ipaddress
import json
from pathlib import Path, PurePosixPath
import re
import shlex
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parent
CONFIG = json.loads((ROOT / "config/kali.json").read_text(encoding="utf-8-sig"))
for stream in (sys.stdout, sys.stderr):
    if hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8", errors="replace")


def run_id():
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:8]


def sha(path):
    with open(path, "rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def case_path(case):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", case):
        raise ValueError("case must be 1-64 letters, digits, underscores or hyphens")
    return CONFIG["guest_root"].rstrip("/") + "/" + case


REMOTE_SPEC = re.compile(r"^(?P<user>[^/\\@]+)@(?P<host>[^:]+):(?P<path>.*)$")


def local_log(case, label, record):
    folder = ROOT / "cases" / (case or "_connection") / "logs"
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / (run_id() + "-" + label + ".json")
    path.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Evidence: {path}", file=sys.stderr)
    return path


class Bridge:
    def __init__(self):
        result = subprocess.run(
            [CONFIG["vmrun"], "-T", "ws", "getGuestIPAddress", CONFIG["vmx"]],
            capture_output=True, timeout=15,
        )
        raw = result.stdout.decode("utf-8", "replace").strip()
        if result.returncode:
            raise RuntimeError("Cannot obtain Kali IP; check the VM and NAT services: " + raw)
        address = ipaddress.ip_address(raw)
        allowed_subnets = CONFIG.get("allowed_subnets", [CONFIG["subnet"]])
        if not isinstance(allowed_subnets, list) or not allowed_subnets:
            raise ValueError("allowed_subnets must be a nonempty list")
        if not any(address in ipaddress.ip_network(network) for network in allowed_subnets):
            raise RuntimeError(f"Kali IP {address} is outside configured Kali subnets")
        self.ip = str(address)
        known_hosts = (ROOT / CONFIG["known_hosts"]).resolve()
        if not known_hosts.is_file():
            raise RuntimeError("Pinned known_hosts file is missing")
        self.options = [
            "-o", "BatchMode=yes", "-o", "ConnectTimeout=4",
            "-o", "StrictHostKeyChecking=yes",
            "-o", f"HostKeyAlias={CONFIG['host_key_alias']}",
            "-o", f"UserKnownHostsFile={known_hosts.as_posix()}",
            "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=2",
        ]
        if CONFIG.get("identity_file"):
            self.options += ["-i", CONFIG["identity_file"], "-o", "IdentitiesOnly=yes"]
        self.target = f"{CONFIG['user']}@{self.ip}"

    def python(self, source, payload=None, timeout=20):
        # Use a JSON literal inside a quoted Python command; stdin carries the code.
        prefix = "import json\nP = json.loads(" + repr(json.dumps(payload or {})) + ")\n"
        started = time.monotonic()
        result = subprocess.run(
            [CONFIG["ssh"], "-T", *self.options, self.target,
             shlex.quote(CONFIG.get("guest_python", "python3")) + " -"],
            input=(prefix + source).encode("utf-8"), capture_output=True, timeout=timeout,
        )
        output = result.stdout.decode("utf-8", "replace")
        error = result.stderr.decode("utf-8", "replace")
        if result.returncode:
            raise RuntimeError(f"SSH/Python failed ({result.returncode}): {error or output}")
        try:
            data = json.loads(output)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Invalid guest response: {output[:2000]} {error[:1000]}") from exc
        data["guest_ip"] = self.ip
        data["transport_seconds"] = round(time.monotonic() - started, 3)
        return data

    def ssh(self, command, data=None, timeout=60):
        """Run one command on the pinned guest through the ssh client."""
        return subprocess.run(
            [CONFIG["ssh"], "-T", *self.options, self.target, command],
            input=data, capture_output=True, timeout=timeout,
        )

    def copy(self, source, destination, cwd=None):
        """Move one file over the ssh channel.

        The Windows OpenSSH client on this workstation cannot transfer files:
        both scp.exe and sftp.exe abort with "pipe: Unknown error" before they
        connect (verified 2026-10-09, clean PATH, Windows OpenSSH 9.5p1), while
        ssh.exe works.  Transfers therefore stream bytes through ssh itself,
        which also keeps everything on the pinned host key.
        """
        base = Path(cwd) if cwd else Path.cwd()
        origin = REMOTE_SPEC.match(source)
        target = REMOTE_SPEC.match(destination)
        if origin and not target:
            where = self._remote_path(origin)
            result = self.ssh("/bin/cat -- " + shlex.quote(where))
            if result.returncode:
                raise RuntimeError("SSH download failed: " +
                                   result.stderr.decode("utf-8", "replace"))
            local = Path(destination)
            if not local.is_absolute():
                local = base / local
            local.write_bytes(result.stdout)
            return
        if target and not origin:
            where = self._remote_path(target)
            if where.endswith("/"):
                where += Path(source).name
            payload = (base / source).read_bytes()
            result = self.ssh("/bin/cat > " + shlex.quote(where), data=payload)
            if result.returncode:
                raise RuntimeError("SSH upload failed: " +
                                   result.stderr.decode("utf-8", "replace"))
            return
        raise ValueError("copy() needs exactly one remote side: %s -> %s" % (source, destination))

    def _remote_path(self, spec):
        if spec.group("host") != self.ip:
            raise ValueError("Refusing to reach host outside the pinned VM: " + spec.group("host"))
        return spec.group("path")


STATUS = r'''
import importlib.util, os, shutil, subprocess
mem = {}
with open('/proc/meminfo') as f:
    for line in f:
        key, value = line.split(':', 1)
        if key in ('MemTotal', 'MemAvailable'):
            mem[key] = int(value.strip().split()[0]) * 1024
disk = shutil.disk_usage('/home/kali')
tools = ('python3','gcc','objdump','readelf','file','strings','burpsuite','wireshark',
         'tshark','binwalk','exiftool','7z','unzip','gdb','checksec','strace','ltrace','ghidra')
print(json.dumps({'user': subprocess.check_output(['id','-un'], text=True).strip(),
 'hostname': os.uname().nodename, 'python': __import__('sys').version.split()[0],
 'python_executable': __import__('sys').executable,
 'memory_bytes': mem, 'disk_bytes': {'total':disk.total,'used':disk.used,'free':disk.free},
 'tools': {x:shutil.which(x) for x in tools},
 'python_modules': {x:importlib.util.find_spec(x) is not None for x in ('sympy','pwn','Crypto','Cryptodome','z3','gmpy2','dnfile')}}))
'''

PREPARE = r'''
import hashlib, os, pathlib, shutil
root = pathlib.Path(P['root'])
for name in ('input','work','results'):
    (root/name).mkdir(parents=True, exist_ok=True)
pending = []
for item in P['files']:
    target = root/'input'/item['name']
    if target.exists():
        if not target.is_file() or target.is_symlink():
            raise RuntimeError('Existing input is not a regular original: '+item['name'])
        with target.open('rb') as f:
            digest = hashlib.file_digest(f,'sha256').hexdigest()
        if digest != item['sha256']:
            raise RuntimeError('Refusing to overwrite different original: '+item['name'])
    else:
        pending.append(item['name'])
free = shutil.disk_usage(root).free
required = sum(x['bytes'] for x in P['files'] if x['name'] in pending)
if required + 50*1024*1024 > free:
    raise RuntimeError('Insufficient Kali disk space for this transfer')
stage = root/'results'/P['id']
stage.mkdir(exist_ok=False)
print(json.dumps({'stage':str(stage),'pending':pending,'free_bytes':free}))
'''

COMMIT = r'''
import hashlib, os, pathlib
root = pathlib.Path(P['root'])
stage = pathlib.Path(P['stage'])
for item in P['files']:
    source = stage/item['name']
    target = root/'input'/item['name']
    if source.exists():
        with source.open('rb') as f:
            digest = hashlib.file_digest(f,'sha256').hexdigest()
        if digest != item['sha256']:
            raise RuntimeError('Transferred hash mismatch: '+item['name'])
        try:
            os.link(source,target)  # Atomic creation, never replaces an original.
        except FileExistsError:
            with target.open('rb') as f:
                if hashlib.file_digest(f,'sha256').hexdigest() != digest:
                    raise RuntimeError('Concurrent conflicting input: '+item['name'])
        source.unlink()
    with target.open('rb') as f:
        actual = hashlib.file_digest(f,'sha256').hexdigest()
    if actual != item['sha256']:
        raise RuntimeError('Original hash mismatch: '+item['name'])
(stage/'manifest.json').write_text(json.dumps(P['files'],indent=2),encoding='utf-8')
print(json.dumps({'verified':True,'case_root':str(root),'files':P['files']}))
'''

EXECUTE = r'''
import base64, datetime, os, pathlib, signal, subprocess, time
root = pathlib.Path(P['root'])
for name in ('input','work','results'):
    (root/name).mkdir(parents=True,exist_ok=True)
command = P['command']
if P.get('source') is not None:
    script = root/'results'/(P['id']+'.py')
    script.write_bytes(base64.b64decode(P['source']))
    command = [P.get('python', 'python3'),str(script)]
env = dict(os.environ, CTF_CASE_DIR=str(root), CTF_INPUT_DIR=str(root/'input'),
           CTF_WORK_DIR=str(root/'work'), CTF_RESULTS_DIR=str(root/'results'))
if P.get('python') and pathlib.Path(P['python']).is_absolute():
    env['PATH'] = str(pathlib.Path(P['python']).parent) + os.pathsep + env.get('PATH', '')
env.setdefault('TERM', 'xterm')
started = time.monotonic()
record = {'run_id':P['id'],'case_root':str(root),'cwd':str(root/'work'),
          'command':command,'timeout_seconds':P['timeout'],
          'started_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat()}
try:
    proc = subprocess.Popen(command,cwd=root/'work',env=env,stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,start_new_session=True)
    timed_out = False
    try:
        out, err = proc.communicate(timeout=P['timeout'])
    except subprocess.TimeoutExpired:
        timed_out = True
        os.killpg(proc.pid,signal.SIGKILL)
        out, err = proc.communicate()
    record.update(returncode=proc.returncode,timed_out=timed_out)
except OSError as exc:
    out, err = b'', str(exc).encode()
    record.update(returncode=127,timed_out=False)
record.update(duration_seconds=round(time.monotonic()-started,3),
              stdout_bytes=len(out),stderr_bytes=len(err),
              output_truncated=len(out)>1048576 or len(err)>1048576,
              stdout=out[:1048576].decode('utf-8','replace'),
              stderr=err[:1048576].decode('utf-8','replace'))
log = root/'results'/(P['id']+'.json')
log.write_text(json.dumps(record,ensure_ascii=False,indent=2),encoding='utf-8')
record['guest_log'] = str(log)
print(json.dumps(record,ensure_ascii=False))
'''

FETCH_INFO = r'''
import hashlib, pathlib
root = pathlib.Path(P['root']).resolve()
target = (root/P['relative']).resolve()
if not target.is_relative_to(root) or not target.is_file():
    raise RuntimeError('Requested output is not a file inside this case')
with target.open('rb') as f:
    digest = hashlib.file_digest(f,'sha256').hexdigest()
print(json.dumps({'path':str(target),'sha256':digest,'bytes':target.stat().st_size}))
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="action", required=True)
    subs.add_parser("status", help="Check live VM, resources and CTF tools")
    put = subs.add_parser("put", help="Upload and hash-verify originals without overwriting")
    put.add_argument("case")
    put.add_argument("files", nargs="+")
    command = subs.add_parser("run", help="Execute a tool; use -- before the command")
    command.add_argument("--timeout", type=int, default=60)
    command.add_argument("case")
    command.add_argument("command", nargs=argparse.REMAINDER)
    script = subs.add_parser("python", help="Execute a local Python script in Kali")
    script.add_argument("--timeout", type=int, default=60)
    script.add_argument("case")
    script.add_argument("script")
    fetch = subs.add_parser("fetch", help="Download and hash-verify a case output")
    fetch.add_argument("case")
    fetch.add_argument("relative", help="e.g. work/analysis.json")
    args = parser.parse_args()
    case = getattr(args, "case", None)
    remote = case_path(case) if case else None
    bridge = Bridge()
    if args.action == "status":
        data = bridge.python(STATUS)
    elif args.action == "put":
        paths = [Path(x).resolve(strict=True) for x in args.files]
        if any(not x.is_file() or x.name in ("manifest.json",) or
               re.search(r'[\x00-\x1f:/\\]', x.name) for x in paths):
            raise ValueError("Inputs must be ordinary files with valid basenames")
        if len({x.name for x in paths}) != len(paths):
            raise ValueError("Duplicate input basenames; give them separate cases")
        manifest = [{"name":x.name,"bytes":x.stat().st_size,"sha256":sha(x)} for x in paths]
        prepared = bridge.python(PREPARE, {"root":remote,"files":manifest,"id":run_id()})
        for path in paths:
            if path.name in prepared["pending"]:
                bridge.copy("./" + path.name, bridge.target + ":" + prepared["stage"] + "/", cwd=path.parent)
        data = bridge.python(COMMIT, {"root":remote,"files":manifest,"stage":prepared["stage"]})
    elif args.action in ("run", "python"):
        if not 1 <= args.timeout <= 600:
            raise ValueError("Timeout must be between 1 and 600 seconds")
        payload = {"root":remote,"id":run_id(),"timeout":args.timeout,"command":[],
                   "python":CONFIG.get("guest_python", "python3")}
        if args.action == "python":
            path = Path(args.script).resolve(strict=True)
            payload["source"] = base64.b64encode(path.read_bytes()).decode("ascii")
            payload["source_sha256"] = sha(path)
        else:
            payload["command"] = args.command[1:] if args.command[:1] == ["--"] else args.command
            if not payload["command"]:
                raise ValueError("Supply a command, e.g. run case -- file ../input/sample")
        data = bridge.python(EXECUTE, payload, timeout=args.timeout + 15)
        if "source_sha256" in payload:
            data["source_sha256"] = payload["source_sha256"]
    else:
        relative = PurePosixPath(args.relative)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("Output path must stay inside the case")
        data = bridge.python(FETCH_INFO, {"root":remote,"relative":str(relative)})
        destination = ROOT / "cases" / case / "downloads" / run_id()
        destination.mkdir(parents=True, exist_ok=False)
        target = destination / Path(data["path"]).name
        bridge.copy(bridge.target + ":" + data["path"], "./" + target.name, cwd=destination)
        if sha(target) != data["sha256"]:
            raise RuntimeError("Downloaded output hash mismatch")
        data.update(local_path=str(target),verified=True)
    local_log(case,args.action,data)
    print(json.dumps(data,ensure_ascii=False,indent=2))
    if args.action in ("run", "python"):
        return 124 if data["timed_out"] else (0 if data["returncode"] == 0 else 1)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        record = {"error":str(exc),"action":sys.argv[1] if len(sys.argv)>1 else None}
        local_log(None,"error",record)
        print(json.dumps(record,ensure_ascii=False),file=sys.stderr)
        sys.exit(1)
