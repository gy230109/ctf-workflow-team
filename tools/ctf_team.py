"""Team CTF workflow component. See README.md for configuration and verified scope."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

BASE = Path(__file__).resolve().parent.parent
BRIDGE = BASE / "bridge"


def run(argv, timeout=30, check=True, data=None):
    proc = subprocess.run([str(x) for x in argv], input=data, capture_output=True, timeout=timeout,
                          creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                          env=dict(os.environ, PYTHONUTF8="1", PYTHONIOENCODING="utf-8"))
    if check and proc.returncode:
        raise RuntimeError("执行失败 (%s): %s\n%s" % (proc.returncode, argv[0], proc.stderr.decode("utf-8", "replace")[-3000:]))
    return proc


def output(argv, timeout=30):
    return run(argv, timeout).stdout.decode("utf-8", "replace").strip()


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def find_vmrun():
    candidates = [shutil.which("vmrun")]
    if os.name == "nt":
        import winreg
        for view in (winreg.KEY_WOW64_32KEY, winreg.KEY_WOW64_64KEY):
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\VMware, Inc.\VMware Workstation", 0, winreg.KEY_READ | view) as key:
                    candidates.append(str(Path(winreg.QueryValueEx(key, "InstallPath")[0]) / "vmrun.exe"))
            except OSError:
                pass
        for env in ("ProgramFiles(x86)", "ProgramFiles"):
            if os.environ.get(env):
                candidates.append(str(Path(os.environ[env]) / "VMware" / "VMware Workstation" / "vmrun.exe"))
    return next((str(Path(x).resolve()) for x in candidates if x and Path(x).is_file()), None)


def inventory_paths(vmrun):
    paths = set()
    if vmrun:
        proc = run([vmrun, "-T", "ws", "list"], check=False)
        paths.update(line.strip() for line in proc.stdout.decode("utf-8", "replace").splitlines() if line.strip().lower().endswith(".vmx"))
    inventory = Path(os.environ.get("APPDATA", str(Path.home() / ".config"))) / "VMware" / "inventory.vmls"
    if inventory.is_file():
        text = inventory.read_text(encoding="utf-8", errors="replace")
        paths.update(match.replace("\\\\", "\\") for match in re.findall(r'\.config\s*=\s*"([^"]+\.vmx)"', text, re.I))
    return sorted(str(Path(p).resolve()) for p in paths if Path(p).is_file())


def discover():
    vmrun = find_vmrun()
    vms = []
    for path in inventory_paths(vmrun):
        text = Path(path).read_text(encoding="utf-8", errors="replace")
        def field(name):
            match = re.search(r'^' + re.escape(name) + r'\s*=\s*"([^"]*)"', text, re.M)
            return match.group(1) if match else ""
        display = field("displayName") or Path(path).stem
        vms.append({"vmx": path, "name": display, "guest_os": field("guestOS"),
                    "likely_kali": "kali" in (display + " " + path).lower()})
    return {"python": sys.executable, "python_version": sys.version.split()[0], "platform": sys.platform,
            "git": shutil.which("git"), "ssh": shutil.which("ssh"), "vmrun": vmrun, "vms": vms,
            "optional": {n: shutil.which(n) for n in ("node", "npx", "VBoxManage", "gh")},
            "scope": "首版自动桥接支持 VMware；检测到 VirtualBox 时需另配桥，不宣称已支持"}


def select_vm(vms, explicit=None):
    if explicit:
        path = Path(explicit).resolve(strict=True)
        if path.suffix.lower() != ".vmx":
            raise ValueError("--vmx 必须为 VMware VMX")
        return str(path)
    likely = [v for v in vms if v["likely_kali"]]
    if len(likely) == 1:
        return likely[0]["vmx"]
    raise ValueError("不能唯一确认 Kali VM；从发现清单中选择 --vmx，不猜测其他 VM")


def guest_address(vmrun, vmx, start=False):
    running = output([vmrun, "-T", "ws", "list"]).casefold()
    if vmx.casefold() not in running:
        if not start:
            raise ValueError("选中的 VM 未运行；使用 --start-vm 启动它")
        run([vmrun, "-T", "ws", "start", vmx, "nogui"], timeout=60)
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        proc = run([vmrun, "-T", "ws", "getGuestIPAddress", vmx], check=False, timeout=15)
        try:
            address = ipaddress.ip_address(proc.stdout.decode().strip())
            if proc.returncode == 0 and address.is_private and not address.is_loopback and not address.is_link_local:
                return str(address)
        except ValueError:
            pass
        time.sleep(2)
    raise RuntimeError("90 秒内未得到客机私有 IP；检查 VMware Tools、NAT 与 DHCP")


def trusted_host(keygen, host, source):
    if not source.is_file():
        return None
    proc = run([keygen, "-F", host, "-f", source], check=False)
    lines = [line for line in proc.stdout.decode("utf-8", "replace").splitlines() if line and not line.startswith("#")]
    return "\n".join(lines) + "\n" if lines else None


def configure(args):
    state = discover()
    vmrun = args.vmrun or state["vmrun"]
    ssh, keygen = state["ssh"], shutil.which("ssh-keygen")
    if not vmrun or not ssh or not keygen:
        raise ValueError("缺少 vmrun/ssh/ssh-keygen；先安装 VMware Workstation 和 Windows OpenSSH 客户端")
    vmx = select_vm(state["vms"], args.vmx)
    address = guest_address(vmrun, vmx, args.start_vm)
    alias = args.host_key_alias or address
    known = Path(args.known_hosts).expanduser().resolve() if args.known_hosts else Path.home() / ".ssh" / "known_hosts"
    trusted = trusted_host(keygen, alias, known)
    if not trusted:
        raise ValueError("未找到已信任的客机主机公钥。先在本机运行 ssh %s@%s 核对指纹并完成一次登录，或提供 --known-hosts/--host-key-alias。系统不会自动信任陌生密钥。" % (args.user, address))
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", args.user):
        raise ValueError("SSH 用户名不合法")
    identity = str(Path(args.identity_file).expanduser().resolve(strict=True)) if args.identity_file else None
    options = ["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=5",
               "-o", "HostKeyAlias=" + alias, "-o", "UserKnownHostsFile=" + known.as_posix()]
    if identity:
        options += ["-i", identity, "-o", "IdentitiesOnly=yes"]
    target = args.user + "@" + address
    actual = output([ssh, "-T", *options, target, "id -un; uname -s"], timeout=20).splitlines()
    if actual != [args.user, "Linux"]:
        raise ValueError("SSH 目标身份或操作系统与所选 Linux VM 不符")
    guest_root = args.guest_root or "/home/" + args.user + "/ctf-workbench/cases"
    if not re.fullmatch(r"/[A-Za-z0-9_./-]+", guest_root) or ".." in guest_root.split("/"):
        raise ValueError("guest-root 必须为简单绝对路径，不能越级")
    cfg = {"python": sys.executable, "ssh": ssh, "vmrun": vmrun, "vmx": vmx, "user": args.user,
           "guest_python": "python3", "subnet": str(ipaddress.ip_network(address + "/24", strict=False)),
           "allowed_subnets": [str(ipaddress.ip_network(address + "/24", strict=False))],
           "host_key_alias": alias, "known_hosts": "config/known_hosts", "guest_root": guest_root}
    if identity:
        cfg["identity_file"] = identity
    # Verify authentication before persisting; existing configs are never replaced
    # implicitly, and files contain paths/public keys only, no private key bytes.
    path = BRIDGE / "config" / "kali.json"
    if path.exists() and not args.replace_config:
        raise ValueError("已有桥配置；先检查现状，确需重配时加 --replace-config")
    path.parent.mkdir(parents=True, exist_ok=True)
    (path.parent / "known_hosts").write_text(trusted, encoding="utf-8")
    save(path, cfg)
    save(BASE / "config" / "ctf_os.json", {"kali_bridge": str(BRIDGE / "kali_bridge.py"), "kali_python": sys.executable,
                                           "distribution": "team"})
    return {"configured": True, "guest_ip": address, "vmx": vmx, "user": args.user, "config": str(path)}


GUEST_INSTALL = r'''import json, os, pathlib, shutil, subprocess, sys
required = {'file':'file', 'strings':'binutils', 'objdump':'binutils', 'gcc':'build-essential', 'gdb':'gdb'}
missing = sorted(set(p for n,p in required.items() if not shutil.which(n)))
venv = pathlib.Path.home() / 'ctf-workbench' / '.venv'
if not pathlib.Path('/usr/bin/python3').exists():
    raise RuntimeError('requires Debian/Kali python3')
probe = subprocess.run(['/usr/bin/python3','-c','import venv'], capture_output=True)
if probe.returncode or not venv.exists():
    missing += ['python3-venv']
if missing:
    root = [] if os.geteuid()==0 else ['sudo','-n']
    test = subprocess.run(root + ['true'], capture_output=True)
    if test.returncode:
        raise RuntimeError('Missing packages: '+','.join(missing)+'. Install these packages in an interactive guest terminal with sudo, then retry; no password is stored.')
    subprocess.run(root + ['apt-get','update'], check=True, stdout=sys.stderr, stderr=sys.stderr, timeout=300)
    subprocess.run(root + ['env','DEBIAN_FRONTEND=noninteractive','apt-get','install','-y',*sorted(set(missing))], check=True, stdout=sys.stderr, stderr=sys.stderr, timeout=600)
venv.parent.mkdir(parents=True, exist_ok=True)
if not (venv/'bin/python3').exists():
    subprocess.run(['/usr/bin/python3','-m','venv',str(venv)], check=True, stdout=sys.stderr, stderr=sys.stderr)
probe = subprocess.run([str(venv/'bin/python3'),'-c',"import importlib.util; names=['pwn','Crypto','z3','gmpy2','sympy','dnfile']; raise SystemExit(0 if all(importlib.util.find_spec(n) for n in names) else 1)"], capture_output=True)
if probe.returncode:
    subprocess.run([str(venv/'bin/python3'),'-m','pip','install','pwntools>=4.14,<5','pycryptodome>=3.20,<4','z3-solver>=4.13,<5','gmpy2>=2.2,<3','sympy>=1.13,<2','dnfile>=0.16,<1'], check=True, stdout=sys.stderr, stderr=sys.stderr, timeout=600)
print(json.dumps({'guest_python':str(venv/'bin/python3'),'installed_missing_packages':sorted(set(missing))}))
'''


def install_guest():
    sys.path.insert(0, str(BRIDGE))
    import kali_bridge
    result = kali_bridge.Bridge().python(GUEST_INSTALL, timeout=1200)
    cfg_path = BRIDGE / "config" / "kali.json"
    cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    cfg["guest_python"] = result["guest_python"]
    save(cfg_path, cfg)
    return result


def verify_install():
    sys.path.insert(0, str(BASE / "tools"))
    import ctf_os
    checks = [{"name": "interface_selftest", "exit": run([sys.executable, BASE / "tools" / "ctf_os.py", "--selftest"], check=False).returncode}]
    result = ctf_os.runtime.bridge_call(["status"])
    checks.append({"name": "kali_bridge", "ok": not ctf_os.runtime.failed(result), "detail": result})
    dependencies = ctf_os.runtime.kali_dependencies()
    deps = dependencies.get("dependencies") or {}
    core = not ctf_os.runtime.failed(dependencies) and all(deps.get("commands", {}).get(n) for n in ("file", "strings", "objdump", "gdb")) and all(deps.get("python_modules", {}).get(n) for n in ("pwn", "Crypto", "z3", "gmpy2", "sympy"))
    checks.append({"name": "core_guest_dependencies", "ok": core, "detail": deps})
    result = {"ready": all(c.get("ok", c.get("exit") == 0) for c in checks), "checks": checks,
              "tools": len(ctf_os.ALL_TOOLS), "scope": "核心接口与 Kali 环境验收，不代表可选组件或完整自动解题验收"}
    save(BASE / "logs" / "team-setup" / "verification.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["discover", "configure", "install-guest", "verify"])
    for field in ("vmx", "vmrun", "known-hosts", "host-key-alias", "identity-file", "guest-root"):
        parser.add_argument("--" + field)
    parser.add_argument("--user", default="kali")
    parser.add_argument("--start-vm", action="store_true")
    parser.add_argument("--replace-config", action="store_true")
    args = parser.parse_args()
    try:
        result = {"discover": discover, "configure": lambda: configure(args), "install-guest": install_guest, "verify": verify_install}[args.action]()
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 1 if result.get("ready") is False else 0
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False, indent=2))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
