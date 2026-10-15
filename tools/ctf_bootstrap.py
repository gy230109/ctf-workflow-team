"""Team CTF workflow component. See README.md for configuration and verified scope."""
from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import socket
import subprocess
import sys
import time
import urllib.request
import uuid

BASE = Path(__file__).resolve().parent.parent
HIDDEN = getattr(subprocess, "CREATE_NO_WINDOW", 0)
def expected_runtime():
    # A resident guardian must discover newly installed tools from disk rather
    # than retaining a catalogue imported before the upgrade.
    code='import sys,json;sys.path.insert(0,sys.argv[1]);import ctf_os;print(json.dumps([list(ctf_os.ALL_TOOLS),ctf_os.ctf_version.fingerprint()]))'
    result=subprocess.run([sys.executable,'-X','utf8','-c',code,str(BASE/'tools')],capture_output=True,text=True,encoding='utf-8',timeout=20,creationflags=HIDDEN)
    if result.returncode:raise RuntimeError('Failed to load current CTF runtime: '+result.stderr[-800:])
    names,digest=json.loads(result.stdout)
    return set(names),digest


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


class FileLock:
    """A process lock released by the OS after a crash; no stale PID deletion."""
    def __init__(self, path):
        self.path = Path(path)
        self.file = None

    def __enter__(self):
        import msvcrt
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.file = self.path.open("a+b")
        self.file.seek(0, 2)
        if self.file.tell() == 0:
            self.file.write(b"0")
            self.file.flush()
        self.file.seek(0)
        try:
            msvcrt.locking(self.file.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            self.file.close()
            self.file = None
            raise RuntimeError("Another CTF startup is already running")
        return self

    def __exit__(self, *_):
        import msvcrt
        if self.file:
            self.file.seek(0)
            msvcrt.locking(self.file.fileno(), msvcrt.LK_UNLCK, 1)
            self.file.close()


def http_json(url, timeout=3):
    # LAN/loopback checks must not inherit a browser or environment proxy.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(url, timeout=timeout) as response:
        if response.status != 200:
            raise RuntimeError(f"HTTP {response.status}")
        return json.load(response)


def catalog_ready(value):
    if not isinstance(value, dict) or not isinstance(value.get("tools"), list):
        return False
    names = {x.get("name") for x in value["tools"] if isinstance(x, dict)}
    expected,digest=expected_runtime()
    version=value.get('version',{})
    return names==expected and version.get('source_fingerprint')==digest and version.get('reload_required') is False


def latest_lease(content, mac):
    result = None
    for address, body in re.findall(r"lease\s+([\d.]+)\s*\{([^}]+)\}", content, re.S):
        if re.search(r"hardware ethernet\s+" + re.escape(mac) + r"\s*;", body, re.I):
            result = address
    return result


def gateway_recovery_command(container, web_service):
    for name in (container, web_service):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
            raise ValueError("Invalid configured container or service name")
    # Inspect only networking/state. Never dump container env or upstream secrets.
    n = shlex.quote(container)
    unit = shlex.quote(web_service)
    return f"""set -eu
sudo -n systemctl start docker.service {unit}
if [ "$(docker inspect -f '{{{{.State.Running}}}}' {n})" != true ]; then
    docker start {n} >/dev/null
fi
if [ "$(docker inspect -f '{{{{.HostConfig.NetworkMode}}}}' {n})" = bridge ]; then
    if ! docker inspect -f '{{{{json .NetworkSettings.Networks}}}}' {n} | python3 -c 'import json,sys;sys.exit(0 if "bridge" in json.load(sys.stdin) else 1)'; then
        docker network connect bridge {n}
    fi
fi
if [ "$(docker inspect -f '{{{{.HostConfig.RestartPolicy.Name}}}}' {n})" != unless-stopped ]; then
    docker update --restart unless-stopped {n} >/dev/null
fi
docker inspect -f '{{"running":{{{{.State.Running}}}},"restart_policy":"{{{{.HostConfig.RestartPolicy.Name}}}}","networks":{{{{json .NetworkSettings.Networks}}}},"ports":{{{{json .NetworkSettings.Ports}}}}}}' {n}
"""


class Bootstrap:
    def __init__(self, base=BASE, config=None):
        self.base = Path(base)
        self.cfg = config or read_json(self.base / "config/startup.json")
        runtime = read_json(self.base / "config/ctf_os.json")
        self.bridge = Path(runtime["kali_bridge"])
        self.bridge_python = runtime["kali_python"]
        self.kali = read_json(self.bridge.parent / "config/kali.json")
        self.vmrun = self.kali["vmrun"]
        self.ps = str(Path(os.environ["WINDIR"]) / "System32/WindowsPowerShell/v1.0/powershell.exe")
        self.log_dir = self.base / "logs/startup"
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.started = time.monotonic()
        self.deadline = self.started + self.cfg["timeout_seconds"]
        self.record = {
            "run_id": dt.datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6],
            "started_at": dt.datetime.now().astimezone().isoformat(),
            "status": "starting", "components": {}, "model_inference_verified": False,
        }
        self.archive = self.log_dir / (self.record["run_id"] + ".json")

    def save(self):
        self.record["elapsed_seconds"] = round(time.monotonic() - self.started, 2)
        write_json(self.archive, self.record)
        write_json(self.log_dir / "latest.json", self.record)

    def event(self, component, status, **detail):
        self.record["components"][component] = {"status": status, **detail}
        self.save()
        print(json.dumps({"component": component, "status": status, **detail}, ensure_ascii=False), flush=True)

    def run_command(self, argv, timeout=20):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("CTF startup exceeded its total deadline")
        result = subprocess.run(argv, capture_output=True, timeout=min(timeout, remaining), creationflags=HIDDEN)
        if result.returncode:
            error = (result.stderr or result.stdout).decode("utf-8", "replace")[-1200:]
            raise RuntimeError(f"Command exited {result.returncode}: {error}")
        return result.stdout.decode("utf-8", "replace").strip()

    def powershell(self, source, timeout=25):
        return self.run_command([self.ps, "-NoProfile", "-NonInteractive", "-Command", source], timeout)

    def start_services(self):
        expected = {"VMAuthdService", "VMnetDHCP", "VMware NAT Service"}
        if set(self.cfg["services"]) != expected:
            raise ValueError("Unexpected VMware service configuration")
        result = self.powershell("$ErrorActionPreference='Stop'; "
            "Get-Service -Name 'VMAuthdService','VMnetDHCP','VMware NAT Service' | ForEach-Object { "
            "if ($_.Status -ne 'Running') { Start-Service -Name $_.Name } }; "
            "Get-Service -Name 'VMAuthdService','VMnetDHCP','VMware NAT Service' | "
            "Select-Object Name,@{Name='Status';Expression={$_.Status.ToString()}} | ConvertTo-Json -Compress")
        services = json.loads(result)
        if not all(x["Status"] == "Running" for x in services):
            raise RuntimeError("VMware network services did not reach Running")
        self.event("vmware_network", "ready", services=services)

    def ensure_vm(self, name, vmx, running):
        path = Path(vmx)
        if not path.is_file():
            raise FileNotFoundError(f"VMX is missing: {path}")
        found = str(path).replace("/", "\\").casefold() in running
        if not found:
            self.run_command([self.vmrun, "-T", "ws", "start", str(path), "nogui"], timeout=60)
        self.event(name + "_vm", "running", vmx=str(path), reused=found)

    def start_vms(self):
        rows = self.run_command([self.vmrun, "-T", "ws", "list"]).splitlines()
        running = {x.strip().replace("/", "\\").casefold() for x in rows[1:]}
        self.ensure_vm("muteki", self.cfg["muteki"]["vmx"], running)
        self.ensure_vm("kali", self.kali["vmx"], running)

    def ensure_server(self):
        try:
            catalog = http_json(self.cfg["server_url"] + "/tools")
            if catalog_ready(catalog):
                self.event("ctf_os", "ready", tools=len(catalog["tools"]), reused=True)
                return
        except Exception:
            pass
        task = self.cfg["server_task"].replace("'", "''")
        self.powershell(f"$ErrorActionPreference='Stop'; Start-ScheduledTask -TaskName '{task}'")
        self.event("ctf_os", "waiting", detail="Requested the existing resident task")

    def muteki_ip(self):
        cfg = self.cfg["muteki"]
        address = None
        try:
            address = self.run_command([self.vmrun, "-T", "ws", "getGuestIPAddress", cfg["vmx"]], timeout=4)
            ipaddress.ip_address(address)
        except (RuntimeError, ValueError, subprocess.TimeoutExpired):
            lease = Path(os.environ["ProgramData"]) / "VMware/vmnetdhcp.leases"
            address = latest_lease(lease.read_text(encoding="utf-8", errors="replace"), cfg["mac"])
        if not address or not any(ipaddress.ip_address(address) in ipaddress.ip_network(n) for n in cfg["allowed_subnets"]):
            raise RuntimeError("Muteki has no address in its configured VMware subnet")
        return address

    def ssh(self, address, command, timeout=12):
        cfg = self.cfg["muteki"]
        root = Path(cfg["vmx"]).parent
        args = [self.kali["ssh"], "-T", "-i", str(root / "private/id_ed25519"),
            "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
            "-o", "HostKeyAlias=" + cfg["host_key_alias"],
            "-o", "UserKnownHostsFile=" + (root / "known_hosts").as_posix(),
            "-o", "ConnectTimeout=3", "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=1",
            cfg["user"] + "@" + address, command]
        return self.run_command(args, timeout)

    def kali_status(self):
        value = json.loads(self.run_command([self.bridge_python, "-X", "utf8", str(self.bridge), "status"], timeout=12))
        commands = value.get("tools", {})
        modules = value.get("python_modules", {})
        if not all(commands.get(x) for x in ("file", "strings", "objdump", "gdb")) or not all(modules.get(x) for x in ("pwn", "Crypto", "z3", "gmpy2", "sympy")):
            raise RuntimeError("Kali core commands/modules are incomplete")
        return {k: value.get(k) for k in ("guest_ip", "hostname", "python", "python_executable")}

    def bindings(self, address):
        sys.path.insert(0, str(self.base / "tools"))
        import muteki_apply_seats as mas
        # Use the VM's actual address, retaining the existing private password file.
        previous = mas.BASE
        mas.BASE = f"http://{address}:{self.cfg['muteki']['web_port']}"
        try:
            session = mas.login()
            try:
                response = session.get(mas.BASE + "/api/settings/profiles/health", timeout=10)
                response.raise_for_status()
                profiles = response.json().get("profiles", [])
                if not profiles or any(x.get("status") != "ok" for x in profiles):
                    raise RuntimeError("Enabled Muteki Profile binding health is not ok")
                return [{k: x.get(k) for k in ("profile_id", "model", "status", "detail")} for x in profiles]
            finally:
                session.close()
        finally:
            mas.BASE = previous

    def wait_ready(self):
        prepared = False
        address = None
        ready = set()
        needed = {"ctf_os", "muteki", "coding2api", "kali", "profile_bindings"}
        while time.monotonic() < self.deadline:
            if "ctf_os" not in ready:
                try:
                    value = http_json(self.cfg["server_url"] + "/tools")
                    if not catalog_ready(value):
                        raise RuntimeError("Port is not serving the expected CTF-OS tools")
                    self.event("ctf_os", "ready", tools=len(value["tools"]))
                    ready.add("ctf_os")
                except Exception as exc:
                    self.event("ctf_os", "waiting", detail=str(exc))
            if not prepared:
                try:
                    address = self.muteki_ip()
                    state = json.loads(self.ssh(address, gateway_recovery_command(
                        self.cfg["muteki"]["container"], self.cfg["muteki"]["web_service"]), timeout=25))
                    if state.get("running") is not True:
                        raise RuntimeError("Coding2API container is not running")
                    self.event("muteki_guest", "ready", address=address, gateway_networks=list(state.get("networks", {})), gateway_ports=state.get("ports"))
                    prepared = True
                except Exception as exc:
                    self.event("muteki_guest", "waiting", detail=str(exc))
            if prepared:
                urls = {
                    "muteki": f"http://{address}:{self.cfg['muteki']['web_port']}/api/auth/status",
                    "coding2api": f"http://{address}:{self.cfg['muteki']['gateway_port']}/health",
                }
                for name, url in urls.items():
                    if name in ready:
                        continue
                    try:
                        value = http_json(url)
                        if not isinstance(value, dict) or (name == "muteki" and value.get("session_protocol") != 2) or (name == "coding2api" and value.get("status") != "ok"):
                            raise RuntimeError("Unexpected service health response")
                        self.event(name, "ready", url=url)
                        ready.add(name)
                    except Exception as exc:
                        self.event(name, "waiting", url=url, detail=str(exc))
                if "muteki" in ready and "profile_bindings" not in ready:
                    try:
                        self.event("profile_bindings", "ready", profiles=self.bindings(address))
                        ready.add("profile_bindings")
                    except Exception as exc:
                        self.event("profile_bindings", "waiting", detail=str(exc))
            if "kali" not in ready:
                try:
                    self.event("kali", "ready", **self.kali_status())
                    ready.add("kali")
                except Exception as exc:
                    self.event("kali", "waiting", detail=str(exc))
            if ready == needed:
                return
            time.sleep(min(self.cfg["poll_seconds"], max(0, self.deadline - time.monotonic())))
        raise TimeoutError("Not ready before startup deadline: " + ", ".join(sorted(needed - ready)))

    def start(self):
        with FileLock(self.log_dir / "stack.lock"):
            self.save()
            try:
                self.start_services()
                self.ensure_server()
                if self.cfg.get('ctfd',{}).get('enabled') is True:
                    from ctf_ctfd_service import ensure as ensure_ctfd
                    self.event('ctfd_tunnel','starting',detail=ensure_ctfd())
                self.start_vms()
                self.wait_ready()
                self.record["status"] = "ready"
                self.record["ready_at"] = dt.datetime.now().astimezone().isoformat()
                self.save()
                return 0
            except Exception as exc:
                self.record.update(status="failed", error=str(exc))
                self.save()
                print(json.dumps({"status": "failed", "error": str(exc)}, ensure_ascii=False), flush=True)
                return 1


def _port_listener_pids(port):
    """Windows：当前占用指定本地 TCP 端口、处于 LISTENING 的进程 PID 集合。"""
    if os.name != "nt":
        return set()
    out = subprocess.run(["netstat", "-ano", "-p", "TCP"], capture_output=True,
                         timeout=15, creationflags=HIDDEN).stdout.decode('ascii','replace')
    pids = set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[0].upper() == "TCP" and parts[3].upper() == "LISTENING":
            if parts[1].rsplit(":", 1)[-1] == str(port):
                pids.add(parts[4])
    return pids


def _is_ctf_os(pid):
    """只认命令行里确实是 ctf_os.py 的进程，绝不盲杀。"""
    if os.name != "nt":
        return False
    source = ("[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; (Get-CimInstance Win32_Process -Filter 'ProcessId=%s').CommandLine" % pid)
    out = subprocess.run(["powershell", "-NoProfile", "-Command", source],
                         capture_output=True, text=True, encoding='utf-8',errors='replace',timeout=20,creationflags=HIDDEN).stdout
    entry=str(BASE/'tools/ctf_os.py').replace('/','\\').casefold()
    return bool(re.search(re.escape(entry)+r'(?=["\s]|$)',out.replace('/','\\').casefold()))


def stop_owned_idle(pid, port=8787):
    """Verify exact owner and no live clients in one shell; never kill a process tree."""
    entry=str(BASE/'tools/ctf_os.py').replace('/','\\').lower().replace("'","''")
    source=("$s=Get-CimInstance Win32_Process -Filter 'ProcessId="+str(int(pid))+"'; "
        "if(!$s -or !$s.CommandLine.Replace('/','\\').ToLower().Contains('"+entry+"')){throw 'Owner changed'}; "
        "if(@(Get-NetTCPConnection -State Established -LocalPort "+str(int(port))+" -ErrorAction SilentlyContinue).Count -gt 0){throw 'Live clients; reload deferred'}; "
        "Stop-Process -Id "+str(int(pid))+" -ErrorAction Stop")
    result=subprocess.run(['powershell','-NoProfile','-NonInteractive','-Command',source],capture_output=True,timeout=20)
    return result.returncode==0


def resident_server(base=BASE, config=None):
    """常驻守护 CTF-OS：健康就复用；发现旧实例不健康则（仅当确认是 ctf_os.py 时）杀掉重启。"""
    base = Path(base)
    cfg = config or read_json(base / "config/startup.json")
    log_dir = base / "logs/startup"
    with FileLock(log_dir / "server.lock"):
        while True:
            try:
                if catalog_ready(http_json(cfg["server_url"] + "/tools")):
                    time.sleep(15)
                    continue
            except Exception:
                pass
            with socket.socket() as client:
                client.settimeout(1)
                if client.connect_ex(("127.0.0.1", 8787)) == 0:
                    # 🔴 端口被占但这台实例不健康（常因改了源码没重启）：
                    # 只杀命令行确认为 ctf_os.py 的监听进程，其他一律拒绝，避免误杀。
                    stale = [p for p in _port_listener_pids(8787) if _is_ctf_os(p)]
                    if not stale:
                        raise RuntimeError("Port 8787 is occupied by a non-CTF-OS process; no process was killed")
                    if not all(stop_owned_idle(pid) for pid in stale):
                        print(json.dumps({'ctf_os':'reload_deferred','reason':'owner changed or live HTTP clients'}),flush=True)
                        time.sleep(15)
                        continue
                    time.sleep(2)
            args = [cfg["python"], "-X", "utf8", str(base / "tools/ctf_os.py"),
                "--host", "127.0.0.1", "--port", "8787", "--log", str(base / "logs/ctf_os.log"),
                "--audit", str(base / "logs/audit.jsonl"), "--hidden"]
            with (log_dir / "server-process.log").open("ab") as stderr:
                child = subprocess.Popen(args, cwd=base / "tools", stdout=subprocess.DEVNULL,
                    stderr=stderr, creationflags=HIDDEN)
                while child.poll() is None:
                    time.sleep(15)
                    try:
                        if not catalog_ready(http_json(cfg['server_url']+'/tools')):
                            if _is_ctf_os(child.pid) and stop_owned_idle(child.pid):
                                child.wait(timeout=10)
                                break
                    except Exception:
                        # A slow or active request is not permission to interrupt another task.
                        pass
                result = child.returncode
            if result:
                # 子进程异常退出（被杀/崩溃）绝不牵连守护本身：记录后短暂退避，
                # 回到循环顶部重新拉起，保证无人值守时也能自愈（否则杀一次就永久没人管了）。
                print(json.dumps({"ctf_os": "restarting", "exit_code": result}, ensure_ascii=False), flush=True)
                time.sleep(5)


def main():
    if os.name == "nt":
        import ctypes
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--start", action="store_true")
    args = parser.parse_args()
    if args.serve == args.start:
        parser.error("Choose --start or --serve")
    if args.serve:
        return resident_server()
    try:
        return Bootstrap().start()
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    sys.exit(main())
