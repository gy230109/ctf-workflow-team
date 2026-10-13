#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Team CTF workflow component. See README.md for configuration and verified scope."""
import argparse
import json
import queue
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import muteki_client as mc           # noqa: E402
import muteki_stall_probe as probe   # noqa: E402
from ctf_os_runtime import dispatch_lock

TERMINAL = ("run.finished", "run.solved", "run.failed", "run.stopped")
FINAL_STATUS = ("solved", "finished", "done", "failed", "stopped", "error", "cancelled")


def _log(msg):
    print("[%s] %s" % (time.strftime("%H:%M:%S"), msg), flush=True)


def _extract_terminal(payload):
    """从终态 payload 里取 (solved, flag, reason)。"""
    if not isinstance(payload, dict):
        return False, None, None
    flags = payload.get("flags") or []
    flag = payload.get("flag") or (flags[0] if flags else None)
    return bool(payload.get("solved")), flag, payload.get("reason")


def watch_once(s, run_id, *, budget_s, interval, tr, quiet=False):
    """Bound the monitor independently of a continuous or incomplete SSE stream."""
    deadline = time.monotonic() + budget_s
    events = queue.Queue(maxsize=256)
    stopped = threading.Event()
    responses = []

    def send(item):
        while not stopped.is_set():
            try:
                events.put(item, timeout=0.2)
                return
            except queue.Full:
                pass

    def read_events():
        after = 0
        while not stopped.is_set() and time.monotonic() < deadline:
            response = None
            try:
                response = s.get("%s/api/runs/%s/events?after=%d" % (mc.BASE, run_id, after),
                                 stream=True, timeout=(5, 2))
                responses.append(response)
                response.raise_for_status()
                for raw in response.iter_lines(decode_unicode=True, chunk_size=1):
                    if stopped.is_set():
                        break
                    if not raw or not raw.startswith("data:"):
                        continue
                    try:
                        ev = json.loads(raw[5:].strip())
                        seq = int(ev.get("seq") or 0)
                    except (ValueError, TypeError, AttributeError):
                        continue
                    if seq > after:
                        after = seq
                        send(ev)
                if not stopped.is_set():
                    cur = mc.get_run(s, run_id)
                    if cur and str(cur.get("status")) in FINAL_STATUS:
                        send({"event_type": "run.finished", "ts": time.time(),
                              "payload": {"solved": str(cur.get("status")) == "solved",
                                          "flag": cur.get("flag"), "reason": "status:" + str(cur.get("status"))}})
            except Exception as exc:
                if not stopped.is_set() and not quiet:
                    _log("SSE 重连: %s" % type(exc).__name__)
            finally:
                if response is not None:
                    response.close()
                    if response in responses:
                        responses.remove(response)
            stopped.wait(min(max(interval, 0.05), 2.0))

    reader = threading.Thread(target=read_events, daemon=True, name="ctf-sse-reader")
    reader.start()
    started_wall = time.time()
    last_verdict = None
    try:
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            try:
                ev = events.get(timeout=min(0.5, max(remaining, 0.001)))
            except queue.Empty:
                ev = None
            if ev:
                tr.feed(ev)
                if ev.get("event_type") in TERMINAL:
                    solved, flag, reason = _extract_terminal(ev.get("payload") or {})
                    return {"outcome": "terminal", "solved": solved, "flag": flag,
                            "reason": reason, "report": tr.report()}
            wall = time.time()
            if tr.t0 is None:
                tr.t0 = started_wall
            tr.now = max(tr.now or 0, wall)
            verdict = tr.verdict()
            if verdict != last_verdict and not quiet:
                _log("监控判定: %s" % verdict)
            last_verdict = verdict
            if verdict == "STALL_DEAD":
                return {"outcome": "stalled", "solved": False, "flag": None,
                        "reason": "stall_dead", "report": tr.report()}
        return {"outcome": "timeout", "solved": False, "flag": None,
                "reason": "per_attempt_timeout", "report": tr.report()}
    finally:
        stopped.set()
        # Close outside the monitor thread: a blocked reader must not hold the budget open.
        for response in list(responses):
            threading.Thread(target=response.close, daemon=True).start()
        reader.join(timeout=0.1)


def active_runs(s):
    r = s.get(mc.BASE + "/api/runs", timeout=20)
    r.raise_for_status()
    runs = r.json().get("runs")
    if not isinstance(runs, list):
        raise ValueError("无法确认现有任务状态，拒绝新增派单")
    return [x for x in runs if str(x.get("status")) not in FINAL_STATUS]


def run(a):
    try:
        with dispatch_lock():
            return _run(a)
    except RuntimeError as exc:
        _log(str(exc))
        return 2


def _run(a):
    s = mc.login()
    _log("已登录 Muteki: %s" % mc.BASE)

    if a.dry_run:
        mc.submit_run(s, dir_path=a.dir, name=a.name, prompt_file=a.prompt_file,
                      flag_format=a.flag_format, category=a.category,
                      expected_flags=a.expected_flags, dry_run=True)
        _log("DRY RUN 结束，未派发")
        return 0

    if a.max_attempts < 1 or a.goal < 1 or a.per_attempt <= 0 or a.total_budget <= 0 or a.backoff < 0:
        raise ValueError("尝试次数、目标和预算必须为正；backoff 不可为负")
    busy = active_runs(s)
    if busy:
        _log("已有未结束任务，拒绝重复派发: %s" % [x.get("run_id") for x in busy])
        return 2

    ledger = []
    flags = []
    t0 = time.monotonic()

    for attempt in range(1, a.max_attempts + 1):
        if time.monotonic() - t0 >= a.total_budget:
            _log("总时长已达上限 %.0fs，停止" % a.total_budget)
            break

        _log("===== 第 %d/%d 次派单 =====" % (attempt, a.max_attempts))
        if active_runs(s):
            _log("发现未结束任务，停止派发")
            break
        rid = mc.submit_run(s, dir_path=a.dir, name=a.name,
                            prompt_file=a.prompt_file, flag_format=a.flag_format,
                            category=a.category, expected_flags=a.expected_flags)
        if not rid:
            ledger.append({"attempt": attempt, "run_id": None,
                           "outcome": "submit_failed", "solved": False})
            _log("派单失败，跳过本轮")
            if active_runs(s):
                _log("派单失败但存在未结束任务，停止重试")
                break
            time.sleep(min(a.backoff, max(0, a.total_budget - (time.monotonic() - t0))))
            continue

        tr = probe.Tracker(a.warn, a.dead, a.grace, a.tool_timeout)
        remaining = max(0, a.total_budget - (time.monotonic() - t0))
        res = watch_once(s, rid, budget_s=min(a.per_attempt, remaining), interval=a.interval, tr=tr)

        # 终局再兜底查一次
        cur = mc.get_run(s, rid)
        if cur:
            res["final_status"] = cur.get("status")
            if str(cur.get("status")) == "solved":
                res["solved"] = True
                res["flag"] = res.get("flag") or cur.get("flag")

        res["attempt"] = attempt
        res["run_id"] = rid
        res["elapsed_s"] = round(time.monotonic() - t0, 1)
        ledger.append(res)

        r = res.get("report") or {}
        _log("本轮结果: outcome=%s solved=%s tool.start=%s 时长=%ss 距上次工具=%ss"
             % (res["outcome"], res.get("solved"), r.get("tool_starts"),
                r.get("duration_s"), r.get("since_last_tool_s")))

        if res.get("solved") and res.get("flag"):
            flags.append(res["flag"])
            _log("✅ 拿到 flag: %s" % res["flag"])
            if len(flags) >= a.goal:
                break
        elif res["outcome"] == "stalled":
            ok, note = mc.stop_run(s, rid)
            _log("判死 → 请求停止: ok=%s (%s)" % (ok, note))
        elif res["outcome"] == "timeout":
            ok, note = mc.stop_run(s, rid)
            _log("超时 → 请求停止: ok=%s (%s)" % (ok, note))

        if res["outcome"] in ("stalled", "timeout"):
            stopped_run = mc.get_run(s, rid)
            res["stop_confirmed"] = bool(stopped_run and str(stopped_run.get("status")) in FINAL_STATUS)
            if not res["stop_confirmed"]:
                _log("未确认旧任务结束，停止重派；请查看现有任务")
                break

        if attempt < a.max_attempts:
            time.sleep(min(a.backoff, max(0, a.total_budget - (time.monotonic() - t0))))

    summary = {
        "challenge": a.name,
        "attempts": len(ledger),
        "solved_count": sum(1 for x in ledger if x.get("solved")),
        "flags": flags,
        "total_elapsed_s": round(time.monotonic() - t0, 1),
        "ledger": ledger,
    }
    summary["pass_rate"] = (
        round(summary["solved_count"] / summary["attempts"], 3)
        if summary["attempts"] else None)
    summary["goal_reached"] = len(flags) >= a.goal

    if a.ledger:
        p = Path(a.ledger)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
        _log("台账已写: %s" % p)

    print(json.dumps({k: v for k, v in summary.items() if k != "ledger"},
                     ensure_ascii=False, indent=2))
    return 0 if summary["goal_reached"] else 1


def main():
    ap = argparse.ArgumentParser(description="Muteki 自动重派（判死即重来）")
    ap.add_argument("--dir", help="题目附件目录")
    ap.add_argument("--name", default="challenge")
    ap.add_argument("--prompt-file")
    ap.add_argument("--flag-format", default="flag{...}")
    ap.add_argument("--category", default="crypto")
    ap.add_argument("--expected-flags", type=int, default=1)

    ap.add_argument("--max-attempts", type=int, default=5)
    ap.add_argument("--per-attempt", type=float, default=1500.0)
    ap.add_argument("--total-budget", type=float, default=7200.0)
    ap.add_argument("--goal", type=int, default=1, help="收到几个 solved 才停")
    ap.add_argument("--backoff", type=float, default=20.0)

    ap.add_argument("--warn", type=float, default=180.0)
    ap.add_argument("--dead", type=float, default=600.0)
    ap.add_argument("--grace", type=float, default=300.0)
    ap.add_argument("--tool-timeout", type=float, default=600.0)
    ap.add_argument("--interval", type=float, default=5.0)

    ap.add_argument("--ledger", help="台账输出 json 路径")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    return run(a)


if __name__ == "__main__":
    sys.exit(main())
