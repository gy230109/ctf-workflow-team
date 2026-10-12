#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Team CTF workflow component. See README.md for configuration and verified scope."""
import json
import os
import sys
from collections import Counter

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

TERMINAL = ("run.finished", "run.solved", "run.failed", "run.stopped",
            "run.completed", "run.terminated", "run.error")
ERR_KEYS = ("error", "errors", "exception", "traceback", "reason",
            "failure_code", "failure_reason", "message", "detail")


def load(path):
    """逐行读 JSONL，坏行不致命。"""
    evs, bad = [], 0
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                evs.append(json.loads(line))
            except Exception:
                bad += 1
    return evs, bad


def g(obj, *names, default=None):
    """从多个候选键里取第一个非空值。"""
    if not isinstance(obj, dict):
        return default
    for n in names:
        v = obj.get(n)
        if v is not None and v != "":
            return v
    return default


def payload_of(ev):
    p = g(ev, "payload", default=None)
    return p if isinstance(p, dict) else {}


def harvest_errors(obj, path="", out=None, depth=0):
    """递归收集疑似错误文本。"""
    if out is None:
        out = []
    if depth > 6:
        return out
    if isinstance(obj, dict):
        for k, v in obj.items():
            lp = path + "/" + str(k)
            if isinstance(v, str) and v.strip() and k.lower() in ERR_KEYS:
                out.append((lp, v.strip().replace("\n", " ")[:220]))
            else:
                harvest_errors(v, lp, out, depth + 1)
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:80]):
            harvest_errors(v, "%s[%d]" % (path, i), out, depth + 1)
    return out


def tool_name(ev):
    p = payload_of(ev)
    return g(p, "tool", "tool_name", "name", "command_name",
             default=g(ev, "tool", "tool_name", default="?"))


def analyze(path):
    evs, bad = load(path)
    n = len(evs)
    types = Counter(g(e, "event_type", "type", default="?") for e in evs)
    seqs = [g(e, "seq") for e in evs if isinstance(g(e, "seq"), (int, float))]
    tss = [g(e, "ts", "timestamp") for e in evs
           if isinstance(g(e, "ts", "timestamp"), (int, float))]
    tss.sort()

    starts = [e for e in evs if g(e, "event_type", "type") == "tool.start"]
    tools = Counter(tool_name(e) for e in starts)
    results = sum(1 for e in evs if g(e, "event_type", "type") == "tool.result")

    term = sorted({t for t in types if t in TERMINAL})

    errs, seen = [], set()
    for e in evs:
        for p, m in harvest_errors(e):
            k = (p, m[:80])
            if k not in seen:
                seen.add(k)
                errs.append((p, m))

    preflight = [(g(e, "event_type", "type"), str(payload_of(e))[:300])
                 for e in evs
                 if "preflight" in json.dumps(payload_of(e), ensure_ascii=False).lower()]

    span = (tss[-1] - tss[0]) if len(tss) >= 2 else None
    max_gap, gap_at = None, None
    for a, b in zip(tss, tss[1:]):
        if max_gap is None or (b - a) > max_gap:
            max_gap, gap_at = (b - a), a

    last_tool_ts = None
    for e in evs:
        if g(e, "event_type", "type") == "tool.start":
            ts = g(e, "ts", "timestamp")
            if isinstance(ts, (int, float)):
                last_tool_ts = ts
    tail_silence = (tss[-1] - last_tool_ts) if (last_tool_ts and len(tss) >= 1) else None

    return {
        "file": os.path.basename(path),
        "bytes": os.path.getsize(path),
        "events": n,
        "bad_lines": bad,
        "types": dict(types.most_common()),
        "terminal": term,
        "tool_calls": len(starts),
        "tool_results": results,
        "tools": dict(tools.most_common(12)),
        "span_s": span,
        "max_gap_s": max_gap,
        "tail_silence_s": tail_silence,
        "errors": errs[:12],
        "preflight": preflight[:4],
        "first": types and g(evs[0], "event_type", "type") if evs else None,
        "last": g(evs[-1], "event_type", "type") if evs else None,
    }


def fmt(v, unit="s"):
    if v is None:
        return "—"
    return ("%.1f%s" % (v, unit)) if isinstance(v, float) else ("%s%s" % (v, unit))


def show(r):
    print("=" * 72)
    print("### %s   %.1f KB   %d 行事件   (坏行 %d)"
          % (r["file"], r["bytes"] / 1024.0, r["events"], r["bad_lines"]))
    print("  终止事件 : %s" % (", ".join(r["terminal"]) if r["terminal"] else "❌ 无（从未正常终止）"))
    print("  首/末事件: %s -> %s" % (r["first"], r["last"]))
    print("  干活量   : tool.start=%d  tool.result=%d" % (r["tool_calls"], r["tool_results"]))
    print("  时长     : 总 %s | 最大事件间隔 %s | 末次工具后静默 %s"
          % (fmt(r["span_s"]), fmt(r["max_gap_s"]), fmt(r["tail_silence_s"])))
    if r["tools"]:
        top = ", ".join("%s×%d" % (k, v) for k, v in list(r["tools"].items())[:8])
        print("  工具分布 : %s" % top)
    t = r["types"]
    keep = [x for x in t if x not in ("reasoning.delta", "blackboard.delta")]
    print("  事件类型 : %s" % ", ".join("%s×%d" % (k, t[k]) for k in keep[:12]))
    if r["preflight"]:
        print("  ⚠ preflight:")
        for a, b in r["preflight"]:
            print("      [%s] %s" % (a, b))
    if r["errors"]:
        print("  ⚠ 错误文本:")
        for p, m in r["errors"]:
            print("      %s = %s" % (p, m))
    else:
        print("  错误文本 : 无")


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    as_json = "--json" in sys.argv
    if not args:
        print(__doc__)
        return 2

    files = []
    for a in args:
        if os.path.isdir(a):
            files += sorted(os.path.join(a, f) for f in os.listdir(a)
                            if f.startswith("run-") and f.endswith(".jsonl"))
        else:
            files.append(a)
    if not files:
        print("没找到 run-*.jsonl")
        return 1

    reports = [analyze(f) for f in files]
    if as_json:
        print(json.dumps(reports, ensure_ascii=False, indent=2))
    else:
        for r in reports:
            show(r)
        print("=" * 72)
        ok = [r for r in reports if r["terminal"]]
        print("汇总: %d 个 run，其中 %d 个有终止事件，%d 个从未终止"
              % (len(reports), len(ok), len(reports) - len(ok)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
