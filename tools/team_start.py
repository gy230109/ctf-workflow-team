"""Team CTF workflow component. See README.md for configuration and verified scope."""
import json
import argparse
import os
from pathlib import Path
import socket
import re
import subprocess
import sys
import time
import urllib.request

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE / "tools"))
import ctf_team
import ctf_os


def catalog(port):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open("http://127.0.0.1:%d/tools" % port, timeout=3) as stream:
            data = json.load(stream)
        names = {item["name"] for item in data.get("tools", [])}
        return names == set(ctf_os.ALL_TOOLS)
    except Exception:
        return False


def reload_owned_idle(port):
    if os.name!='nt':raise RuntimeError('Owned listener reload currently requires Windows')
    script='$l=@(Get-NetTCPConnection -State Listen -LocalPort '+str(port)+' -ErrorAction Stop); if($l.Count -ne 1){throw "Unexpected listener"}; $s=Get-CimInstance Win32_Process -Filter ("ProcessId="+$l[0].OwningProcess); [pscustomobject]@{pid=$s.ProcessId;command=$s.CommandLine;active=@(Get-NetTCPConnection -State Established -LocalPort '+str(port)+' -ErrorAction SilentlyContinue).Count}|ConvertTo-Json -Compress'
    script='[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);'+script
    result=subprocess.run(['powershell','-NoProfile','-NonInteractive','-Command',script],capture_output=True,text=True,encoding='utf-8',timeout=15)
    if result.returncode:raise RuntimeError('Cannot verify owned listener')
    info=json.loads(result.stdout);entry=str(BASE/'tools/ctf_os.py').replace('/','\\').lower()
    command=str(info.get('command','')).replace('/','\\').lower()
    if not re.search(re.escape(entry)+r'(?=["\s]|$)',command) or not re.search(r'--port(?:\s+|=)'+str(port)+r'(?=\s|$)',command):
        raise RuntimeError('Listener belongs to another installation; no process terminated')
    if info.get('active',1)!=0:raise RuntimeError('Active HTTP clients; reload deferred, CLI remains usable')
    service=int(info['pid'])
    # Recheck the exact PID/command and active clients in the same Windows shell before stopping.
    quoted=command.replace("'","''")
    stop='$s=Get-CimInstance Win32_Process -Filter "ProcessId='+str(service)+'"; if(!$s -or $s.CommandLine.Replace("/","\\").ToLower() -ne \''+quoted+'\'){throw "Identity changed"}; if(@(Get-NetTCPConnection -State Established -LocalPort '+str(port)+' -ErrorAction SilentlyContinue).Count -gt 0){throw "Active clients"}; Stop-Process -Id '+str(service)+' -ErrorAction Stop'
    killed=subprocess.run(['powershell','-NoProfile','-NonInteractive','-Command',stop],capture_output=True,text=True,timeout=15)
    if killed.returncode:raise RuntimeError('Owned listener reload refused: '+killed.stderr[:500])
    return {'stopped_owned_pid':service,'active_clients':0}

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--reload',action='store_true');args=parser.parse_args()
    try:
        port = int(os.environ.get("CTF_OS_PORT", "8787"))
        if not 1<=port<=65535:raise ValueError('Invalid port')
        cfg_path = BASE / "bridge" / "config" / "kali.json"
        cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
        address = ctf_team.guest_address(cfg["vmrun"], cfg["vmx"], start=True)
        if not catalog(port):
            with socket.socket() as probe:
                if probe.connect_ex(("127.0.0.1", port)) == 0:
                    if args.reload:reload_owned_idle(port)
                    else:raise RuntimeError("Port has a stale or different catalogue. Use start.ps1 -Reload when idle, or choose CTF_OS_PORT. No process was terminated.")
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
