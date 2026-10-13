# -*- coding: utf-8 -*-
"""Team CTF workflow component. See README.md for configuration and verified scope."""
import argparse
import json
import os
import sys
import time
from pathlib import Path

import requests

BASE = os.environ.get("CTF_MUTEKI_BASE", "http://127.0.0.1:3001").rstrip("/")
PW_FILE = Path(os.environ.get("CTF_MUTEKI_PW_FILE",
                             str(Path(__file__).resolve().parent.parent / ".local" / "muteki-password.txt")))


def login():
    pw = PW_FILE.read_text(encoding="utf-8").strip()
    s = requests.Session()
    s.trust_env = False                 # 不走本机代理，直达 VMware 网络
    r = s.post(BASE + "/api/auth/login", json={"password": pw}, timeout=20)
    r.raise_for_status()
    tok = r.json().get("token") or ""
    s.headers.update({"Authorization": "Bearer " + tok, "X-Muteki-CSRF": "1"})
    return s


def show_runtimes(s):
    r = s.get(BASE + "/api/agent-runtimes", timeout=20)
    print("agent-runtimes:", r.status_code)
    if r.status_code != 200:
        print(" ", r.text[:200])
        return
    j = r.json()
    arr = j if isinstance(j, list) else (
        j.get("runtimes") or j.get("items") or j.get("instances") or [])
    for it in arr if isinstance(arr, list) else []:
        if isinstance(it, dict):
            print("  -", it.get("engine") or it.get("id") or it.get("runtime"),
                  "| enabled:", it.get("enabled"),
                  "| backend:", it.get("backend") or it.get("worker_backend"),
                  "| model:", it.get("model") or it.get("default_model"),
                  "| health:", it.get("health") or it.get("status"))
    if not arr:
        print("  keys:", list(j)[:15] if isinstance(j, dict) else type(j))
    if isinstance(j, dict):
        print("  count:", j.get("count"), "| transport:", j.get("transport_kind"),
              "| probed_at:", j.get("probed_at"))


def cmd_status(a):
    s = login()
    r = s.get(BASE + "/api/runs", timeout=20)
    print("/api/runs:", r.status_code)
    j = r.json()
    runs = j.get("runs", [])
    print("runs:", len(runs))
    for it in runs[-10:]:
        print("  %s | %s | %s | %s" % (it.get("run_id", "")[:12],
                                       it.get("status"), it.get("category"),
                                       it.get("name")))
    return 0


def cmd_runtimes(a):
    show_runtimes(login())
    return 0


def submit_run(s, *, dir_path=None, name="challenge", prompt=None,
               prompt_file=None, flag_format="flag{...}", category="crypto",
               expected_flags=1, dry_run=False, quiet=False):
    """派发一个 CTF run（**唯一**的派单实现，CLI 与 autopilot 共用）。

    返回 run_id；dry_run 或失败时返回 None。
    """
    def say(*a):
        if not quiet:
            print(*a)

    if prompt is None and prompt_file:
        prompt = Path(prompt_file).read_text(encoding="utf-8")
    if not prompt:
        raise ValueError("需要 prompt 或 prompt_file")

    files = []
    if dir_path:
        d = Path(dir_path)
        files = [p for p in sorted(d.rglob("*")) if p.is_file()
                 and p.name not in (".DS_Store",) and "__MACOSX" not in str(p)]

    body_ch = {
        "name": name, "description": prompt, "mode": "ctf",
        "category": category, "flag_format": flag_format,
        "expected_flags": expected_flags, "multi_flag": expected_flags > 1,
        "attachments": [],
    }
    body = {"kind": "swarm", "prompt": prompt, "mode": "ctf",
            "challenge": body_ch}

    if dry_run:
        say("== DRY RUN，不派发 ==")
        say("将上传文件：", [str(f) for f in files])
        say(json.dumps(body, ensure_ascii=False, indent=2)[:1500])
        return None

    r = s.post(BASE + "/api/runs", json={"legacy": True}, timeout=30)
    if r.status_code != 200:
        say("建 run 失败:", r.status_code, r.text[:300])
        return None
    run_id = r.json()["run_id"]
    say("run_id:", run_id)

    if files:
        handles = [("files", (f.name, f.open("rb"))) for f in files]
        try:
            r = s.post(BASE + "/api/runs/%s/uploads" % run_id, files=handles,
                       timeout=120)
        finally:
            for _, (_, fh) in handles:
                fh.close()
        say("uploads:", r.status_code)
        if r.status_code != 200:
            say("  ", r.text[:300])
            return None
        saved = r.json().get("files") or r.json().get("saved") or []
        paths = [x.get("path") if isinstance(x, dict) else x for x in saved]
        body_ch["attachments"] = paths
        say("  附件落盘:", paths)

    r = s.post(BASE + "/api/runs/%s/start" % run_id, json=body, timeout=60)
    say("start:", r.status_code)
    if r.status_code != 200:
        say("  ", r.text[:600])
        return None
    say("  已派发")
    return run_id


def stop_run(s, run_id):
    """尽力停止一个 run。返回 (ok, note)。端点不确定，逐个试。"""
    for ep, method in (("/api/runs/%s/stop" % run_id, "post"),
                       ("/api/runs/%s/cancel" % run_id, "post"),
                       ("/api/runs/%s" % run_id, "delete")):
        try:
            r = getattr(s, method)(BASE + ep, timeout=30)
            if r.status_code in (200, 202, 204):
                return True, "%s %d" % (method.upper(), r.status_code)
        except Exception:
            continue
    return False, "无可用的停止端点"


def get_run(s, run_id):
    """从 /api/runs 列表里取一个 run 的当前状态 dict。"""
    try:
        r = s.get(BASE + "/api/runs", timeout=20)
        for it in r.json().get("runs", []):
            if it.get("run_id") == run_id:
                return it
    except Exception:
        pass
    return None


def cmd_submit(a):
    s = login()
    rid = submit_run(s, dir_path=a.dir, name=a.name, prompt=a.prompt,
                     prompt_file=a.prompt_file, flag_format=a.flag_format,
                     category=a.category, expected_flags=a.expected_flags,
                     dry_run=a.dry_run)
    if rid:
        print("\nRUN_ID=%s" % rid)
        print("看板: %s" % BASE)
        return 0
    return 0 if a.dry_run else 1


def cmd_watch(a):
    s = login()
    deadline = time.time() + a.seconds
    last = None
    while time.time() < deadline:
        r = s.get(BASE + "/api/runs", timeout=20)
        runs = {x.get("run_id"): x for x in r.json().get("runs", [])}
        cur = runs.get(a.run_id)
        if cur:
            line = "status=%s name=%s" % (cur.get("status"), cur.get("name"))
            if line != last:
                print("[%s] %s" % (time.strftime("%H:%M:%S"), line))
                last = line
            if cur.get("status") in ("done", "finished", "stopped", "failed", "error"):
                print("终态:", cur.get("status"))
                break
        else:
            print("  （还没在列表里）")
        time.sleep(a.interval)
    return 0


def main():
    ap = argparse.ArgumentParser(description="Muteki Web API 客户端")
    sub = ap.add_subparsers(dest="cmd")

    p = sub.add_parser("status"); p.set_defaults(func=cmd_status)
    p = sub.add_parser("runtimes"); p.set_defaults(func=cmd_runtimes)

    p = sub.add_parser("submit")
    p.add_argument("--dir", help="题目附件目录")
    p.add_argument("--name", default="challenge")
    p.add_argument("--prompt-file")
    p.add_argument("--prompt")
    p.add_argument("--flag-format", default="flag{...}")
    p.add_argument("--category", default="crypto")
    p.add_argument("--expected-flags", type=int, default=1)
    p.add_argument("--dry-run", action="store_true")
    p.set_defaults(func=cmd_submit)

    p = sub.add_parser("watch")
    p.add_argument("--run-id", required=True)
    p.add_argument("--seconds", type=int, default=300)
    p.add_argument("--interval", type=float, default=10)
    p.set_defaults(func=cmd_watch)

    a = ap.parse_args()
    if not getattr(a, "cmd", None):
        ap.print_help()
        return 1
    return a.func(a)


if __name__ == "__main__":
    sys.exit(main())
