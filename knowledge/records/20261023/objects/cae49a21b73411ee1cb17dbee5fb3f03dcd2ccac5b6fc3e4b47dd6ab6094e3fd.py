# -*- coding: utf-8 -*-
"""从 before 快照生成两个 PUT body（席位切换用）。

产出（写入本目录 after/）：
    identity-body.json  → PUT /api/settings/identity
    workers-body.json   → PUT /api/settings/workers

设计依据（workbuddy-status.md §9/§10.3）：
  - `max_workers` 是只读派生值 = Σ(engines 内 且 有普通角色的席位 × max_running)
  - 普通角色 = {race, bootstrap, explore, respond}；`review` 不计入
  - GLM  = 唯一普通解题席（enabled）
  - DS   = roles 只留 ["review"]，enabled  → 不进派生求和
  - Step = disabled（备用）
  - Pi   = disabled（回退）
  - dispatch_mode=fixed / start_workers=1 / max_total_workers=0
"""
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
BEFORE = HERE / "before" / "settings-workers.before.json"
AFTER = HERE / "after"

GLM_ID = "c2api-claude-glm53-local"
DS_ID = "c2api-claude-dsv41flash-local"
STEP_ID = "c2api-claude-step5p-local"


def load_before() -> dict:
    d = json.loads(BEFORE.read_text(encoding="utf-8"))
    return d.get("config") if isinstance(d.get("config"), dict) else d


def seat(id_, label, engine, cred, model, roles, race, max_run, max_rev,
         priority, enabled, effort="default"):
    return {
        "id": id_, "label": label, "engine": engine, "credential_id": cred,
        "model": model, "reasoning_effort": effort,
        "roles": list(roles), "race": bool(race),
        "capacity": {"max_running": max_run, "max_review_running": max_rev},
        "priority": priority, "enabled": bool(enabled),
    }


def main() -> int:
    cfg = load_before()
    AFTER.mkdir(parents=True, exist_ok=True)

    # ── 旧 5 席：原样保留，但 Pi 改 disabled（回退位）──────────────────
    seats = []
    for s in cfg.get("seats") or []:
        s = dict(s)
        if str(s.get("id")) == "seat_pi_b710d8":
            s["enabled"] = False                      # ← 保留为回退，不参与派发
        seats.append(s)
    have = {str(s.get("id")) for s in seats}

    # ── 新 3 席 ────────────────────────────────────────────────────────
    new = [
        # GLM：唯一普通解题席 → 进 max_workers 求和
        seat(GLM_ID, "claude-glm53-local", "claude", "account:c2api-claude",
             "glm-5.3", ["race", "bootstrap", "explore", "respond"],
             True, 1, 0, 60, True),
        # DeepSeek：只带 review → 不进求和，走复核通道
        seat(DS_ID, "claude-dsv41flash-local", "claude", "account:c2api-ds-claude",
             "deepseek-v4.1-flash", ["review"], False, 1, 1, 70, True),
        # Step：备用，disabled
        seat(STEP_ID, "claude-step5p-local", "claude", "account:c2api-step",
             "step-5-preview", ["race", "bootstrap", "explore", "respond"],
             True, 1, 0, 80, False),
    ]
    for s in new:
        if s["id"] not in have:
            seats.append(s)

    identity_body = {
        "worker_backend": cfg.get("worker_backend") or "container",
        "worker_network": cfg.get("worker_network") or "bridge",
        "seats": seats,
    }
    (AFTER / "identity-body.json").write_text(
        json.dumps(identity_body, ensure_ascii=False, indent=2), encoding="utf-8")

    # ── workers body：stage_policy（只改 review.engine）+ 计数 ─────────
    sp = json.loads(json.dumps(cfg.get("stage_policy") or {}))
    co = sp.setdefault("coordinator", {})
    co["dispatch_mode"] = "fixed"                     # 🔴 CTF+auto 会强制 max_workers=3
    rev = co.setdefault("review", {})
    rev["engine"] = DS_ID                             # 复核席 = DeepSeek 席位 id
    rev["enabled"] = True
    rev.setdefault("max_concurrent", 1)

    workers_body = {
        "worker_backend": cfg.get("worker_backend") or "container",
        "worker_network": cfg.get("worker_network") or "bridge",
        "engines": [GLM_ID],          # 普通名单只有 GLM（派生值=1）
        "start_workers": 1,
        "max_total_workers": 0,       # 0 = 累计不限，别设 1
        "stage_policy": sp,
    }
    # 注意：**不提交 max_workers** —— 它是派生值，提交也会被覆写。
    (AFTER / "workers-body.json").write_text(
        json.dumps(workers_body, ensure_ascii=False, indent=2), encoding="utf-8")

    print("已生成：")
    print("  ", AFTER / "identity-body.json", "seats =", len(seats))
    print("  ", AFTER / "workers-body.json")
    print("\n席位摘要：")
    for s in seats:
        cap = s.get("capacity") or {}
        print("   %-30s %-6s %-20s en=%-5s roles=%-52s max_run=%s" % (
            s.get("id"), s.get("engine"), s.get("model"), s.get("enabled"),
            ",".join(s.get("roles") or []), cap.get("max_running")))
    ordinary = [s for s in seats
                if s.get("enabled")
                and set(s.get("roles") or []) & {"race", "bootstrap", "explore", "respond"}]
    expect = sum(int((s.get("capacity") or {}).get("max_running") or 1)
                 for s in ordinary)
    print("\n预期派生 max_workers =", expect)
    return 0 if expect == 1 else 2


if __name__ == "__main__":
    sys.exit(main())
