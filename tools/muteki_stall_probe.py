#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Team CTF workflow component. See README.md for configuration and verified scope."""
import argparse
import io
import json
import os
import sys
import time
from pathlib import Path

BASE = os.environ.get("CTF_MUTEKI_BASE", "http://127.0.0.1:3001").rstrip("/")
GM_BASE = Path(os.environ.get("GM_BASE", str(Path(__file__).resolve().parent.parent)))

HEARTBEAT = "tool.start"
TERMINAL_EVENTS = ("run.finished", "run.solved", "run.failed", "run.stopped")

VERDICT_DESC = {
    "DONE": "已完成（无需关注）",
    "RUNNING": "正常推进",
    "STALL_WARN": "停滞告警：长时间没有工具调用",
    "STALL_DEAD": "判死：极长时间没有工具调用，基本不会自愈",
    "INIT": "尚未开始（preflight / 等首个工具调用）",
}


def _ts(ev):
    t = ev.get("ts")
    try:
        return float(t)
    except (TypeError, ValueError):
        return None


class Tracker:
    """吃事件流，维护"距上次工具调用多久"这一个数。"""

    def __init__(self, warn=180.0, dead=600.0, grace=300.0, tool_timeout=600.0):
        self.warn, self.dead, self.grace = warn, dead, grace
        self.tool_timeout = tool_timeout
        self.t0 = None
        self.now = None
        self.last_hb = None
        self.n_hb = 0
        self.in_flight = 0
        self.gaps = []
        self.events = 0
        self.terminal = None
        self.state = "INIT"

    def feed(self, ev):
        """返回一个告警元组 (kind, text)；无变化返回 None。"""
        et = ev.get("event_type")
        ts = _ts(ev)
        if ts is None:
            return None
        self.events += 1
        if self.t0 is None:
            self.t0 = ts
        self.now = ts
        alert = None

        if et == "tool.result":
            self.in_flight = max(0, self.in_flight - 1)

        if et == HEARTBEAT:
            if self.last_hb is not None:
                self.gaps.append(round(ts - self.last_hb, 1))
            self.last_hb = ts
            self.n_hb += 1
            self.in_flight += 1
            if self.state in ("STALL_WARN", "STALL_DEAD"):
                alert = ("RECOVER", "工具调用恢复（上次间隔 %.1fs）" % self.stall())
                self.state = "RUNNING"
            else:
                self.state = "RUNNING"

        if et in TERMINAL_EVENTS:
            self.terminal = et
            self.state = "DONE"
            alert = ("TERMINAL", et)

        if et == "progress.brief":
            ph = (ev.get("payload") or {}).get("phase")
            if ph in ("solved", "done"):
                self.state = "DONE"
                alert = ("SOLVED", "progress.brief phase=%s" % ph)

        return alert

    def stall(self):
        if self.now is None:
            return None
        base = self.last_hb if self.last_hb is not None else self.t0
        return round(self.now - base, 1)

    def verdict(self):
        if self.state == "DONE":
            return "DONE"
        s = self.stall()
        if s is None:
            return "INIT"
        if self.last_hb is None:
            # 还没开始干活：只跟 grace / dead 比
            if s >= self.dead:
                return "STALL_DEAD"
            return "STALL_WARN" if s >= self.grace else "INIT"
        # 🔴 防误报：有工具"在飞"（start 了还没 result）且未超 tool_timeout，
        #    说明可能是一个合法长任务（例如跑几分钟的爆破），不算停滞。
        if self.in_flight > 0 and s < self.tool_timeout:
            return "RUNNING"
        if s >= self.dead:
            return "STALL_DEAD"
        if s >= self.warn:
            return "STALL_WARN"
        return "RUNNING"

    def report(self):
        d = {
            "verdict": self.verdict(),
            "verdict_desc": VERDICT_DESC.get(self.verdict(), ""),
            "events": self.events,
            "tool_starts": self.n_hb,
            "tools_in_flight": self.in_flight,
            "duration_s": round(self.now - self.t0, 1) if self.now and self.t0 else None,
            "since_last_tool_s": self.stall(),
            "gap_median_s": _median(self.gaps),
            "gap_max_s": max(self.gaps) if self.gaps else None,
            "terminal_event": self.terminal,
            "thresholds": {"warn": self.warn, "dead": self.dead,
                           "grace": self.grace, "tool_timeout": self.tool_timeout},
        }
        return d


def _median(xs):
    if not xs:
        return None
    s = sorted(xs)
    return round(s[len(s) // 2], 1)


def load_jsonl(path):
    evs = []
    with io.open(path, "r", encoding="utf-8", errors="replace") as f:
        for ln in f:
            ln = ln.strip()
            if not ln:
                continue
            try:
                evs.append(json.loads(ln))
            except Exception:
                continue
    return evs


def _fmt(v, unit="s"):
    return "—" if v is None else "%s%s" % (v, unit)


def print_report(d, title=""):
    if title:
        print("=" * 72)
        print(title)
    print("  判定        : %s" % d["verdict"])
    print("  说明        : %s" % d["verdict_desc"])
    print("  事件总数    : %s" % d["events"])
    print("  工具调用数  : %s  (tool.start)" % d["tool_starts"])
    print("  工具在飞    : %s  (start 了还没 result)" % d["tools_in_flight"])
    print("  总时长      : %s" % _fmt(d["duration_s"]))
    print("  距上次工具  : %s   ← 判据" % _fmt(d["since_last_tool_s"]))
    print("  间隔 中位/最大: %s / %s" % (_fmt(d["gap_median_s"]), _fmt(d["gap_max_s"])))
    print("  终止事件    : %s" % d["terminal_event"])
    print("  阈值        : warn=%ss dead=%ss tool_timeout=%ss"
          % (d["thresholds"]["warn"], d["thresholds"]["dead"], d["thresholds"]["tool_timeout"]))


def analyze_file(path, warn, dead, grace, tool_timeout, as_json):
    evs = load_jsonl(path)
    tr = Tracker(warn, dead, grace, tool_timeout)
    for e in evs:
        tr.feed(e)
    d = tr.report()
    d["source"] = str(path)
    if as_json:
        print(json.dumps(d, ensure_ascii=False, indent=2))
    else:
        print_report(d, "离线复盘: %s" % path)
    return d


def login():
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from muteki_client import login as _login  # 复用同一份凭据配置
    return _login()


def watch(run_id, minutes, interval, warn, dead, grace, tool_timeout, as_json):
    import requests  # noqa: F401  (login 内部已用)
    s = login()
    tr = Tracker(warn, dead, grace, tool_timeout)
    after = 0
    deadline = time.time() + minutes * 60
    print("盯 run=%s  阈值 warn=%ss dead=%ss tool_timeout=%ss  上限 %.0f 分钟"
          % (run_id, warn, dead, tool_timeout, minutes))
    while time.time() < deadline:
        try:
            r = s.get("%s/api/runs/%s/events?after=%d" % (BASE, run_id, after),
                      stream=True, timeout=(10, 40))
            idle_since = time.time()
            for raw in r.iter_lines(decode_unicode=True):
                if raw is None:
                    continue
                if not raw.startswith("data:"):
                    continue
                try:
                    o = json.loads(raw[5:].strip())
                except Exception:
                    continue
                seq = o.get("seq") or 0
                if seq <= after:
                    continue
                after = seq
                idle_since = time.time()
                alert = tr.feed(o)
                if alert:
                    print("[%s] %-9s %s" % (time.strftime("%H:%M:%S"), alert[0], alert[1]),
                          flush=True)
            try:
                r.close()
            except Exception:
                pass
            # SSE 断流 = 没有新事件。必须用本机墙钟推进"现在"，否则永远发现不了空转。
            # Muteki 的 ts 与本机 time.time() 同为 Unix 秒，两个域一致；只容忍轻微时钟偏差。
            wall_now = time.time()
            if tr.t0 is not None:
                tr.now = max(tr.now or 0.0, wall_now)
            gap = wall_now - idle_since
            v = tr.verdict()
            if v in ("STALL_WARN", "STALL_DEAD"):
                print("[%s] %-9s 已 %.0fs 无新事件，连续无工具调用 ≈ %.0fs  判定=%s"
                      % (time.strftime("%H:%M:%S"), "ALERT", gap,
                         tr.stall() if tr.stall() is not None else gap, v), flush=True)
            if v == "STALL_DEAD":
                print("  → 建议：人工介入或直接暂停该 run（Muteki 不会自己报这个错）。")
                break
            time.sleep(min(max(interval, 1.0), 10.0))
        except Exception as e:
            print("[%s] 重连中: %s %s" % (time.strftime("%H:%M:%S"),
                                        type(e).__name__, str(e)[:100]), flush=True)
            time.sleep(3)
    d = tr.report()
    if as_json:
        print(json.dumps(d, ensure_ascii=False, indent=2))
    else:
        print_report(d, "在线盯守结束: %s" % run_id)
    return d


def selftest(warn, dead, grace, tool_timeout):
    """拿两个已知真实样本自检，期望：run-0006 → DONE，run-0889 → STALL_DEAD。"""
    cases = [
        (GM_BASE / "战例库/Muteki首跑-EasyRsa/run/run-0006.jsonl", "DONE", "成功样本"),
        (GM_BASE / "战例库/比赛-GameBoy/run/run-0889.jsonl", "STALL_DEAD", "空转样本"),
    ]
    ok = True
    for path, want, label in cases:
        if not path.exists():
            print("跳过（文件不存在）: %s" % path)
            ok = False
            continue
        d = analyze_file(path, warn, dead, grace, tool_timeout, as_json=False)
        got = d["verdict"]
        mark = "PASS" if got == want else "FAIL"
        if got != want:
            ok = False
        print("  [%s] %s  期望=%s 实得=%s（距上次工具 %ss）"
              % (mark, label, want, got, d["since_last_tool_s"]))
        print()
    print("自检结果:", "全部通过" if ok else "有失败项")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description="Muteki 空转探针")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--run-jsonl", help="离线：本地 run 事件 jsonl 路径")
    g.add_argument("--run-id", help="在线：盯一个 run（走 SSE 事件流）")
    g.add_argument("--selftest", action="store_true", help="拿已知样本自检")

    ap.add_argument("--warn", type=float, default=180.0, help="停滞告警阈值秒（默认 180）")
    ap.add_argument("--dead", type=float, default=600.0, help="判死阈值秒（默认 600）")
    ap.add_argument("--grace", type=float, default=300.0,
                    help="首个工具调用前的宽限秒（默认 300）")
    ap.add_argument("--tool-timeout", type=float, default=600.0,
                    help='单个工具「在飞」的最长容忍秒（默认 600，防长任务误报）')
    ap.add_argument("--minutes", type=float, default=30.0, help="在线模式时长（默认 30）")
    ap.add_argument("--interval", type=float, default=5.0, help="在线轮询/心跳秒")
    ap.add_argument("--json", action="store_true", help="机器可读输出")
    a = ap.parse_args()

    if a.selftest:
        return selftest(a.warn, a.dead, a.grace, a.tool_timeout)
    if a.run_jsonl:
        analyze_file(a.run_jsonl, a.warn, a.dead, a.grace, a.tool_timeout, a.json)
        return 0
    watch(a.run_id, a.minutes, a.interval, a.warn, a.dead, a.grace, a.tool_timeout, a.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
