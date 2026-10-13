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

# PUT /api/settings/workers 允许携带的键（对齐 worker_config.WorkerConfigStore.set）
PUT_KEYS = [
    "engines", "start_workers", "max_workers", "worker_backend", "worker_network",
    "worker_container_scope", "worker_privilege", "worker_memory", "worker_cpus",
    "worker_pids_limit", "worker_output_limit", "worker_disk_limit",
    "worker_vpn_enabled", "race_scout", "race_timeout", "wall_clock_budget",
    "race_engines", "max_total_workers", "cost_budget_usd", "stage_policy",
    "llm_profiles", "worker_profiles", "overrides",
]

READBACK_FIELDS = [
    "worker_backend", "worker_network", "engines", "race_engines",
    "start_workers", "max_workers", "max_total_workers",
]


def login() -> requests.Session:
    pw = PW_FILE.read_text(encoding="utf-8").strip()
    s = requests.Session()
    s.trust_env = False
    r = s.post(BASE + "/api/auth/login", json={"password": pw}, timeout=20)
    r.raise_for_status()
    tok = r.json().get("token") or ""
    s.headers.update({"Authorization": "Bearer " + tok, "X-Muteki-CSRF": "1"})
    return s


def get_cfg(s: requests.Session) -> dict:
    r = s.get(BASE + "/api/settings/workers", timeout=30)
    r.raise_for_status()
    j = r.json()
    # 响应形如 {"config": {...}}；兼容裸 config。
    return j.get("config") if isinstance(j, dict) and isinstance(j.get("config"), dict) else j


def _dispatch_mode(cfg: dict) -> str:
    sp = cfg.get("stage_policy") or {}
    co = sp.get("coordinator") if isinstance(sp.get("coordinator"), dict) else {}
    return str((co or {}).get("dispatch_mode") or "fixed")


def _review_engine(cfg: dict) -> str:
    sp = cfg.get("stage_policy") or {}
    co = sp.get("coordinator") if isinstance(sp.get("coordinator"), dict) else {}
    rev = (co or {}).get("review") if isinstance((co or {}).get("review"), dict) else {}
    return str((rev or {}).get("engine") or "")


def describe(cfg: dict, *, json_out: bool = False) -> dict:
    seats = [s for s in (cfg.get("seats") or []) if isinstance(s, dict)]
    profs = [p for p in (cfg.get("worker_profiles") or []) if isinstance(p, dict)]
    if seats:
        enabled = [(s.get("id"), s.get("engine"), s.get("model"),
                    s.get("roles"), (s.get("capacity") or {}).get("max_running"),
                    s.get("credential_id"))
                   for s in seats if s.get("enabled")]
    else:
        enabled = [(p.get("name") or p.get("id"), p.get("engine"), p.get("model"),
                    p.get("roles"), p.get("max_running"), p.get("credential_id"))
                   for p in profs if p.get("enabled")]
    out = {k: cfg.get(k) for k in READBACK_FIELDS}
    out["dispatch_mode"] = _dispatch_mode(cfg)
    out["review_engine"] = _review_engine(cfg)
    out["enabled_seats"] = enabled
    if json_out:
        print(json.dumps(out, ensure_ascii=False, indent=2))
        return out
    for k in READBACK_FIELDS:
        print("  %-20s = %r" % (k, cfg.get(k)))
    print("  %-20s = %r" % ("dispatch_mode", out["dispatch_mode"]))
    print("  %-20s = %r" % ("review_engine", out["review_engine"]))
    print("  启用席位:")
    for e in enabled:
        print("    id=%s engine=%s model=%s roles=%s max_running=%s cred=%s" % e)
    return out


def cmd_snapshot(a) -> int:
    cfg = get_cfg(login())
    Path(a.out).write_text(json.dumps(cfg, ensure_ascii=False, indent=2),
                           encoding="utf-8")
    print("已保存快照:", a.out)
    describe(cfg)
    return 0


def cmd_readback(a) -> int:
    describe(get_cfg(login()), json_out=a.json)
    return 0


def cmd_apply(a) -> int:
    body = json.loads(Path(a.body).read_text(encoding="utf-8"))
    r = login().put(BASE + "/api/settings/workers", json=body, timeout=60)
    print("PUT /api/settings/workers ->", r.status_code)
    if r.status_code != 200:
        print(r.text[:1200])
        return 1
    print("已应用。回读：")
    describe(get_cfg(login()))
    return 0


def cmd_restore(a) -> int:
    snap = json.loads(Path(a.from_file).read_text(encoding="utf-8"))
    if isinstance(snap.get("config"), dict):
        snap = snap["config"]
    body = {k: snap[k] for k in PUT_KEYS if k in snap}
    print("回滚字段:", sorted(body))
    r = login().put(BASE + "/api/settings/workers", json=body, timeout=60)
    print("PUT ->", r.status_code)
    if r.status_code != 200:
        print(r.text[:1200])
        return 1
    describe(get_cfg(login()))
    return 0


def cmd_health(a) -> int:
    r = login().get(BASE + "/api/settings/profiles/health", timeout=60)
    print("GET /api/settings/profiles/health ->", r.status_code)
    print(json.dumps(r.json(), ensure_ascii=False, indent=2)[:4000])
    return 0 if r.status_code == 200 else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="Muteki 席位/派发配置工具")
    sub = ap.add_subparsers(dest="cmd")

    p = sub.add_parser("snapshot"); p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_snapshot)

    p = sub.add_parser("readback"); p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_readback)

    p = sub.add_parser("apply"); p.add_argument("--body", required=True)
    p.set_defaults(func=cmd_apply)

    p = sub.add_parser("restore"); p.add_argument("--from", dest="from_file",
                                                  required=True)
    p.set_defaults(func=cmd_restore)

    p = sub.add_parser("health"); p.set_defaults(func=cmd_health)

    a = ap.parse_args()
    if not getattr(a, "cmd", None):
        ap.print_help()
        return 1
    return a.func(a)


if __name__ == "__main__":
    sys.exit(main())
