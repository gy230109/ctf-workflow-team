# -*- coding: utf-8 -*-
"""Team CTF workflow component. See README.md for configuration and verified scope."""
import argparse
import json
import os
import sys
from pathlib import Path

import requests

BASE = os.environ.get("CTF_MUTEKI_BASE", "http://127.0.0.1:3001").rstrip("/")
PW_FILE = Path(os.environ.get("CTF_MUTEKI_PW_FILE",
                              str(Path(__file__).resolve().parent.parent / ".local" / "muteki-password.txt")))

# 任何看起来像密钥/口令的字段名 —— 打印时一律脱敏
SECRET_HINTS = ("key", "token", "secret", "password", "authorization", "cookie")


def login() -> requests.Session:
    pw = PW_FILE.read_text(encoding="utf-8").strip()
    s = requests.Session()
    s.trust_env = False
    r = s.post(BASE + "/api/auth/login", json={"password": pw}, timeout=20)
    r.raise_for_status()
    tok = r.json().get("token") or ""
    s.headers.update({"Authorization": "Bearer " + tok, "X-Muteki-CSRF": "1"})
    return s


def get_json(s, path, **kw):
    r = s.get(BASE + path, timeout=30, **kw)
    return r.status_code, (r.json() if r.headers.get("content-type", "").startswith("application/json") else r.text)


def mask(obj, depth=0):
    """递归脱敏：命中 SECRET_HINTS 的字段只留后 4 位。"""
    if depth > 6:
        return obj
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if any(h in str(k).lower() for h in SECRET_HINTS):
                out[k] = ("***" + str(v)[-4:]) if v else ""
            else:
                out[k] = mask(v, depth + 1)
        return out
    if isinstance(obj, list):
        return [mask(v, depth + 1) for v in obj[:50]]
    if isinstance(obj, str) and len(obj) > 200:
        return obj[:200] + "..."
    return obj


def _items(payload):
    """不同端点返回的容器键不统一，统一抽成 list。"""
    if isinstance(payload, dict):
        for k in ("credentials", "endpoints", "items", "accounts", "config"):
            if isinstance(payload.get(k), list):
                return payload[k]
        if isinstance(payload.get("config"), dict):
            return _items(payload["config"])
    return payload if isinstance(payload, list) else []


def cmd_list(a):
    s = login()
    rows = {}
    for name, path in (("credentials", "/api/settings/credentials"),
                       ("model-endpoints", "/api/settings/model-endpoints"),
                       ("credential-accounts", "/api/settings/credential-accounts")):
        code, payload = get_json(s, path)
        print("\n=== %s  GET %s -> %s ===" % (name, path, code))
        if code != 200:
            print("   ", str(payload)[:300])
            continue
        rows[name] = payload
        for it in _items(payload):
            print("   ", json.dumps(mask(it), ensure_ascii=False)[:320])
    if a.raw_out:
        Path(a.raw_out).write_text(json.dumps(rows, ensure_ascii=False, indent=2),
                                   encoding="utf-8")
        print("\n原始结果已写入:", a.raw_out, "（含地址信息，别外传）")
    return 0


def cmd_endpoints(a):
    s = login()
    code, payload = get_json(s, "/api/settings/model-endpoints")
    print("GET /api/settings/model-endpoints ->", code)
    for it in _items(payload):
        print("   ", json.dumps(mask(it), ensure_ascii=False)[:400])
    return 0


def _test_one(s, cid, timeout=180, model=""):
    path = "/api/settings/credentials/%s/test" % cid
    # 端点要求显式给 model，否则回 200 + ok=false「请选择一个候选模型后执行真实测试」
    body = {"model": model} if model else {}
    try:
        r = s.post(BASE + path, json=body, timeout=timeout)
    except Exception as e:
        return {"credential_id": cid, "model": model or "(未指定)",
                "http": "EXC", "detail": str(e)[:200]}
    raw = r.text
    try:
        j = r.json()
    except Exception:
        j = {}
    return {
        "credential_id": cid,
        "model": model or "(未指定)",
        "http": r.status_code,
        "ok": j.get("ok"),
        "detail": str(j.get("detail") or j.get("message") or raw)[:300],
    }


def cmd_test(a):
    s = login()
    if a.all_:
        code, payload = get_json(s, "/api/settings/credentials")
        if code != 200:
            print("取凭证列表失败", code, str(payload)[:300])
            return 1
        targets = []
        for it in _items(payload):
            cid = str((it or {}).get("credential_id") or (it or {}).get("id") or "")
            if cid:
                targets.append(cid)
    else:
        targets = [a.credential_id]

    results = []
    for cid in targets:
        print("体检 %s model=%s ..." % (cid, a.model or "(默认)"), flush=True)
        res = _test_one(s, cid, model=a.model or "")
        results.append(res)
        print("   http=%s ok=%s  %s" % (res.get("http"), res.get("ok"),
                                        res.get("detail", "")))
    alive = [r["credential_id"] for r in results if r.get("ok") is True]
    print("\n== 汇总 ==")
    print("可用凭证 %d / %d : %s" % (len(alive), len(results), alive or "（无）"))
    return 0 if alive else 2


def main():
    ap = argparse.ArgumentParser(description="Muteki 上游体检探针（不派单）")
    sub = ap.add_subparsers(dest="cmd")

    p = sub.add_parser("list")
    p.add_argument("--raw-out", help="原始 JSON 落盘路径（含地址，别外传）")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("endpoints")
    p.set_defaults(func=cmd_endpoints)

    p = sub.add_parser("test")
    p.add_argument("credential_id", nargs="?", default="")
    p.add_argument("--all", dest="all_", action="store_true")
    p.add_argument("--model", default="", help="候选模型名（端点要求显式指定）")
    p.set_defaults(func=cmd_test)

    a = ap.parse_args()
    if not getattr(a, "cmd", None):
        ap.print_help()
        return 1
    return a.func(a)


if __name__ == "__main__":
    sys.exit(main())
