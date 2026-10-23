#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""持续把某个 Muteki run 的事件流落成 JSONL（断线自动重连、按游标续读）。"""
import json, os, sys, time
from pathlib import Path
import requests

BASE = os.environ.get("CTF_MUTEKI_BASE", "http://192.168.26.130:3001").rstrip("/")
PW = Path(os.environ.get("CTF_MUTEKI_PW_FILE",
                        r"D:\Apps\Muteki\vm\private\Web-Password.txt")).read_text(encoding="utf-8").strip()
ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "run"
OUT.mkdir(parents=True, exist_ok=True)

rid = sys.argv[1] if len(sys.argv) > 1 else "run-0586"
mins = float(sys.argv[2]) if len(sys.argv) > 2 else 60

jl = OUT / ("%s.jsonl" % rid)
cur = OUT / ("%s.cursor" % rid)
after = int(cur.read_text().strip()) if cur.exists() else 0
f = jl.open("a", encoding="utf-8")

def login():
    s = requests.Session(); s.trust_env = False
    r = s.post(BASE + "/api/auth/login", json={"password": PW}, timeout=20)
    r.raise_for_status()
    s.headers.update({"Authorization": "[REDACTED_CREDENTIAL]" + r.json().get("token", ""),
                      "X-Muteki-CSRF": "1"})
    return s

deadline = time.time() + mins * 60
while time.time() < deadline:
    try:
        s = login()
        r = s.get("%s/api/runs/%s/events?after=%d" % (BASE, rid, after),
                  stream=True, timeout=(10, 30))
        for raw in r.iter_lines(decode_unicode=True):
            if raw is None:
                continue
            if raw.startswith("data:"):
                d = raw[5:].strip()
                try:
                    o = json.loads(d)
                except Exception:
                    continue
                seq = o.get("seq") or 0
                if seq <= after:
                    continue
                after = seq
                cur.write_text(str(after))
                f.write(json.dumps(o, ensure_ascii=False) + "\n"); f.flush()
                t = o.get("event_type")
                if t in ("tool.start", "blackboard.delta", "run.finished", "run.solved",
                         "flag.found", "worker.lifecycle", "cost.update"):
                    p = o.get("payload") or {}
                    brief = p.get("tool") or p.get("kind") or p.get("phase") or ""
                    if t == "blackboard.delta" and p.get("kind") == "fact_added":
                        brief = (p.get("fact") or "")[:100]
                    print("[%s] #%s %s %s" % (time.strftime("%H:%M:%S"), seq, t, str(brief)[:170]),
                          flush=True)
            if time.time() > deadline:
                break
        try:
            r.close()
        except Exception:
            pass
    except Exception as e:
        print("[%s] 重连中: %s %s" % (time.strftime("%H:%M:%S"), type(e).__name__,
                                     str(e)[:100]), flush=True)
        time.sleep(3)
f.close()
print("调度结束，事件已落", jl, "游标", after, flush=True)
