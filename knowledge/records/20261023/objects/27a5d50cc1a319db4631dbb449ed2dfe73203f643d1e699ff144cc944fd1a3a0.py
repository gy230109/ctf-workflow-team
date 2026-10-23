#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""跟踪 Muteki run：拉摘要 + 读事件流（SSE）+ 看工作区文件。"""
import json, os, sys, time
from pathlib import Path
import requests

BASE = os.environ.get("CTF_MUTEKI_BASE", "http://192.168.26.130:3001").rstrip("/")
PW = Path(os.environ.get("CTF_MUTEKI_PW_FILE",
                        r"D:\Apps\Muteki\vm\private\Web-Password.txt")).read_text(encoding="utf-8").strip()

s = requests.Session(); s.trust_env = False
r = s.post(BASE + "/api/auth/login", json={"password": PW}, timeout=20); r.raise_for_status()
s.headers.update({"Authorization": "[REDACTED_CREDENTIAL]" + r.json().get("token", ""), "X-Muteki-CSRF": "1"})

rid = sys.argv[1] if len(sys.argv) > 1 else "run-0586"
mode = sys.argv[2] if len(sys.argv) > 2 else "sum"
after = int(sys.argv[3]) if len(sys.argv) > 3 else 0
secs = float(sys.argv[4]) if len(sys.argv) > 4 else 8

if mode == "sum":
    r = s.get(BASE + "/api/runs", timeout=20)
    j = r.json()
    runs = j.get("runs", j if isinstance(j, list) else [])
    for it in runs:
        if it.get("run_id") == rid:
            print(json.dumps(it, ensure_ascii=False, indent=2))
            break
    else:
        print("未在列表中找到", rid, "；列表共", len(runs))
        for it in runs[-5:]:
            print("  ", it.get("run_id"), it.get("status"), it.get("name"))

elif mode == "ev":
    # SSE：只读 secs 秒
    r = s.get("%s/api/runs/%s/events?after=%d" % (BASE, rid, after),
              stream=True, timeout=(8, secs))
    print("HTTP", r.status_code)
    t0 = time.time()
    ev, buf = None, []
    try:
        for raw in r.iter_lines(decode_unicode=True):
            if raw is None:
                continue
            if raw.startswith("event:"):
                ev = raw[6:].strip()
            elif raw.startswith("id:"):
                buf.append("id=" + raw[3:].strip())
            elif raw.startswith("data:"):
                d = raw[5:].strip()
                try:
                    o = json.loads(d)
                    d = json.dumps(o, ensure_ascii=False)
                except Exception:
                    pass
                print("[%s] %s %s %s" % (time.strftime("%H:%M:%S"), ev or "", " ".join(buf), d[:400]))
                buf = []
            if time.time() - t0 > secs:
                break
    except Exception as e:
        print("（读取结束）", type(e).__name__, str(e)[:120])
    try:
        r.close()
    except Exception:
        pass
