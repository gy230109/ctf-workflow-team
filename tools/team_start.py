"""Team CTF workflow component. See README.md for configuration and verified scope."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import urllib.request

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE / "tools"))
import ctf_team


def catalog(port):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open("http://127.0.0.1:%d/tools" % port, timeout=3) as stream:
            data = json.load(stream)
        names = {item["name"] for item in data.get("tools", [])}
        return {"wp_init", "wp_build", "kali_run", "math_gcd"} <= names
    except Exception:
        return False


def main():
    try:
        port = int(os.environ.get("CTF_OS_PORT", "8787"))
        cfg_path = BASE / "bridge" / "config" / "kali.json"
        cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
        address = ctf_team.guest_address(cfg["vmrun"], cfg["vmx"], start=True)
        if not catalog(port):
            with socket.socket() as probe:
                if probe.connect_ex(("127.0.0.1", port)) == 0:
                    raise RuntimeError("Port occupied by another/incompatible process. No process was terminated. Change CTF_OS_PORT or stop the correct service yourself.")
            log = BASE / "logs" / "team-start" / "server.log"
            log.parent.mkdir(parents=True, exist_ok=True)
            with log.open("ab") as stream:
                subprocess.Popen([sys.executable, "-X", "utf8", BASE / "tools" / "ctf_os.py", "--host", "127.0.0.1", "--port", str(port)],
                                 stdin=subprocess.DEVNULL, stdout=stream, stderr=stream,
                                 creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            for _ in range(15):
                if catalog(port):
                    break
                time.sleep(1)
            else:
                raise RuntimeError("Service did not become reachable")
        verification = ctf_team.verify_install()
        result = {"ready": verification["ready"], "guest_ip": address, "port": port,
                  "checked_at": time.strftime("%Y-%m-%d %H:%M:%S"), "scope": "core only; optional services not started"}
        ctf_team.save(BASE / "logs" / "team-start" / "latest.json", result)
        print(json.dumps(result, ensure_ascii=False))
        return 0 if result["ready"] else 1
    except Exception as exc:
        result = {"ready": False, "error": str(exc), "checked_at": time.strftime("%Y-%m-%d %H:%M:%S")}
        ctf_team.save(BASE / "logs" / "team-start" / "latest.json", result)
        print(json.dumps(result, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
