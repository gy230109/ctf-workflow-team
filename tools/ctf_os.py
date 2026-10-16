#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Team CTF workflow component. See README.md for configuration and verified scope."""
import argparse
import hmac
import io
import json
import os
import re
import secrets
import shlex
import shutil
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

TOOLS_DIR = Path(__file__).resolve().parent
GM_BASE = TOOLS_DIR.parent
sys.path.insert(0, str(TOOLS_DIR))

# 复用已交付的解题工具表，不重写
import ctf_mcp_server as solver
import ctf_os_runtime as runtime
import ctf_knowledge as knowledge
import ctf_crypto as cryptanalysis
import ctf_x64dbg as windows_debug
import ctf_rea as rea
import ctf_wp as writeup
import ctf_version
import ctf_pcap
import ctf_task_health

# Specialist execution reuses this computer's verified Kali bridge.
try:
    import ctf_specialists as specialists
except ModuleNotFoundError as exc:
    if exc.name != "ctf_specialists":
        raise
    specialists = None

try:
    import ctf_extensions as extensions
except ModuleNotFoundError as exc:
    if exc.name != "ctf_extensions":
        raise
    extensions = None

try:
    import ctf_ctfd as ctfd
except ModuleNotFoundError as exc:
    if exc.name != "ctf_ctfd":
        raise
    ctfd = None

try:
    import ctf_cracktools as cracktools
except ModuleNotFoundError as exc:
    if exc.name != "ctf_cracktools":
        raise
    cracktools = None

DEFAULT_PORT = int(os.environ.get("CTF_OS_PORT", "8787"))

# ---- 鉴权 / 审计（默认关闭，对外提供前必须开）----
# 令牌为空 = 不鉴权（本机方便）；设了令牌后，127.0.0.1 来源仍然免令牌，
# 局域网/外部来源必须带 X-CTF-OS-Token 头或 ?token= 或 body 里的 token 字段。
AUTH_TOKEN = os.environ.get("CTF_OS_TOKEN", "")
AUDIT_FILE = str(GM_BASE / "logs" / "ctf_os_audit.jsonl")
_LOCAL_PEERS = ("127.0.0.1", "::1", "::ffff:127.0.0.1")
_SECRET_HINTS = ("key", "token", "secret", "password", "passwd",
                 "authorization", "cookie", "credential", "flag", "seed")
_audit_lock = threading.Lock()


def _redact(obj, depth=0):
    """审计落盘前抹掉密钥类字段 —— 协同文件里不许出现密码/Key/token。"""
    if depth > 4:
        return "..."
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if any(h in str(k).lower() for h in _SECRET_HINTS):
                out[k] = "***REDACTED***"
            else:
                out[k] = _redact(v, depth + 1)
        return out
    if isinstance(obj, (list, tuple)):
        return [_redact(x, depth + 1) for x in obj[:50]]
    if isinstance(obj, str) and len(obj) > 500:
        return obj[:500] + "...(%d chars)" % len(obj)
    return obj


def audit(kind, peer="", tool=None, args=None, ok=None, ms=0, note=""):
    if not AUDIT_FILE:
        return
    rec = {"ts": now(), "peer": peer, "kind": kind, "tool": tool,
           "args": _redact(args), "ok": ok, "ms": round(ms, 1)}
    if note:
        rec["note"] = note
    try:
        line = json.dumps(rec, ensure_ascii=False) + "\n"
        with _audit_lock:
            Path(AUDIT_FILE).parent.mkdir(parents=True, exist_ok=True)
            with io.open(AUDIT_FILE, "a", encoding="utf-8") as f:
                f.write(line)
    except Exception:
        pass


def now():
    return datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S")


# --------------------------------------------------------------------------
# 装备运维类工具（在解题工具之外新增）
# --------------------------------------------------------------------------

def _run_py(args, timeout=60, cwd=None):
    return runtime.run_process([sys.executable, "-X", "utf8"] + args,
                               timeout=timeout, cwd=str(cwd or TOOLS_DIR))


def tool_status(a):
    """现测全装备状态。**只读、安全、随便调**。"""
    out = {"checked_at": now(), "items": []}

    # Muteki：现测配置（不读记忆）
    try:
        import muteki_apply_seats as mas
        cfg = mas.get_cfg(mas.login())
        out["items"].append({
            "name": "Muteki", "kind": "比赛套", "ok": True,
            "engines": cfg.get("engines"),
            "dispatch_mode": mas._dispatch_mode(cfg),
            "planner": (cfg.get("llm_profiles") or {}).get("planner", {}).get("model"),
            "verified_scope": "配置 API 可访问；未执行模型推理或解题",
        })
    except Exception as e:
        out["items"].append({"name": "Muteki", "kind": "比赛套",
                             "ok": False, "detail": "%r" % (e,)})

    # Kali
    try:
        result = runtime.bridge_call(["status"])
        out["items"].append({"name": "Kali", "kind": "Linux 执行环境",
                             "ok": not runtime.failed(result), "bridge_status": result,
                             "verified_scope": "SSH 桥及客机状态；不代表完成解题"})
    except Exception as e:
        out["items"].append({"name": "Kali", "ok": False, "detail": "%r" % (e,)})

    # 本地关键脚本是否齐
    for n in ("gbdis.py", "ctf_mcp_server.py"):
        out["items"].append({"name": n, "kind": "本地工具",
                             "ok": (TOOLS_DIR / n).exists(),
                             "verified_scope": "脚本存在；功能未逐项执行"})

    # 战例库
    try:
        cases = sorted(p.name for p in (GM_BASE / "战例库").iterdir() if p.is_dir())
        out["items"].append({"name": "战例库", "ok": True, "count": len(cases),
                             "cases": cases})
    except Exception as e:
        out["items"].append({"name": "战例库", "ok": False, "detail": "%r" % (e,)})
    kb = knowledge.status()
    out["items"].append({"name": "HackTricks", "kind": "本地技术参考",
                         "ok": kb.get("ready", False), "knowledge_status": kb,
                         "verified_scope": "本地索引可读；资料不是解题成功证据"})
    try:
        dbg = windows_debug.status({})
        out["items"].append({"name": "x64dbg", "kind": "Windows 动态调试（按需启动）",
                             "ok": dbg.get("installed", False),
                             "service_reachable": dbg.get("reachable", False),
                             "debugger_status": dbg,
                             "verified_scope": "安装与本机 MCP 状态；不代表完成题目分析"})
    except Exception as e:
        out["items"].append({"name": "x64dbg", "ok": False, "detail": "%r" % (e,)})
    out["registered_tools"] = len(ALL_TOOLS)
    out["all_items_available"] = all(x.get("ok") for x in out["items"])
    out["solving_workflow_verified"] = False
    if a.get("deep") is True:
        dependencies = runtime.kali_dependencies()
        out["kali_dependencies"] = dependencies
        out["local_commands"] = {n: shutil.which(t.split()[0]) for n, (t, _, _) in LOCAL_CMDS.items()}
        deps = dependencies.get("dependencies") or {}
        commands = deps.get("commands") or {}
        modules = deps.get("python_modules") or {}
        out["missing_optional_kali_commands"] = [n for n, p in commands.items() if not p]
        out["core_dependencies_ready"] = (
            not runtime.failed(dependencies) and all(commands.get(n) for n in ("file", "strings", "objdump", "gdb"))
            and all(modules.get(n) for n in ("pwn", "Crypto", "z3", "gmpy2", "sympy")))
        out["doctor_passed"] = out["all_items_available"] and out["core_dependencies_ready"]
    return out


def tool_muteki_upstream_probe(a):
    """体检 Muteki 上游。**必须给 model**，否则端点回假红。"""
    cred = a.get("credential")
    if not cred:
        return {"error": "团队版必须显式提供 credential 和 model"}
    model = a.get("model")
    return _run_py(["muteki_upstream_probe.py", "test", cred, "--model", model],
                   timeout=200)


def tool_muteki_dispatch(a):
    """派一道题给 Muteki。🔴 **烧钱且改生产**，必须带 `"confirm": true`。"""
    if a.get("confirm") is not True:
        return {"error": "危险动作：请带 confirm=true。会消耗上游额度。"}
    d = a.get("dir") or ""
    prompt = a.get("prompt_file") or ""
    if not prompt or not Path(prompt).is_file():
        return {"error": "需要存在的 prompt_file；只提供附件目录不足以派发", "error_code": "invalid_arguments"}
    args = ["muteki_autopilot.py"]
    if d:
        args += ["--dir", d]
    if prompt:
        args += ["--prompt-file", prompt]
    args += ["--name", a.get("name", "ctf-os"),
             "--category", a.get("category", "crypto"),
             "--max-attempts", str(a.get("max_attempts", 1)),
             "--goal", str(a.get("goal", 1)),
             "--per-attempt", str(a.get("per_attempt", 900)),
             "--total-budget", str(a.get("total_budget", 900))]
    total = float(a.get("total_budget", 900))
    timeout = float(a.get("timeout", total + 180))
    if total <= 0 or timeout < total + 120:
        return {"error": "timeout 至少为 total_budget + 120，留出停止任务时间", "error_code": "invalid_arguments"}
    return _run_py(args, timeout=timeout)


def tool_case_list(a):
    """列出战例库 / 题目库内容。"""
    which = a.get("which", "战例库")
    p = GM_BASE / which
    if not p.exists():
        return {"error": "无此目录: %s" % which}
    return {"items": sorted(x.name for x in p.iterdir())}


def tool_kali_sage(a):
    """SageMath 实算（数论/符号/LLL/椭圆曲线）。

    不走"分析某个文件"的模板 —— Sage 是跑表达式，不是读 target。
    🔴 Sage 不在 Kali 的 apt 源里（候选：(无)），装在 /opt/sage，直接 `sage` 调用即可，
       别去 `apt install sagemath`。
    """
    code = a.get("code") or a.get("expr") or ""
    if not code:
        return {"error": "需要 code（Sage 表达式，如 print(factor(2026))）"}
    return tool_kali_run({"cmd": "sage -c %s" % shlex.quote(str(code)),
                          "timeout": int(a.get("timeout", 300)),
                          "confirm": True})


def tool_kali_run(a):
    """通过已验收的桥在独立 case 内执行。🔴 需要 confirm。"""
    if a.get("confirm") is not True:
        return {"error": "危险动作：请带 confirm=true"}
    argv = a.get("argv")
    if argv is None:
        if not a.get("cmd"):
            return {"error": "缺少 argv 或 cmd"}
        argv = ["bash", "-c", str(a["cmd"])]
    if not isinstance(argv, list) or not argv or any(not isinstance(x, str) for x in argv):
        return {"error": "argv 必须是非空字符串数组"}
    # 透传 local_file：调用方给了就必须真的上传，绝不静默忽略（否则 Kali 上表现为"文件不存在"）
    local = a.get("local_file") or None
    if local and not Path(local).is_file():
        return {"error": "本机文件不存在: %s" % local}
    return runtime.kali_execute(a, argv, local=local)


# --------------------------------------------------------------------------
# 安全工具集：本机命令 + Kali 命令（声明式定义，避免每个都写一遍包装代码）
# --------------------------------------------------------------------------

# (命令模板, 说明, 是否危险)
KALI_CMDS = {
    "kali_file":     ("file {target}", "识别文件**真实类型**（文件名骗人时必用）", False),
    "kali_strings":  ("strings -n {minlen} {target}", "提取可打印字符串", False),
    "kali_binwalk":  ("binwalk {target}", "固件/隐写分离，找内嵌文件", False),
    "kali_radare2":  ("r2 -q -c 'aaa;pdf' {target}", "radare2 反汇编主函数", False),
    "kali_objdump":  ("objdump -d -M intel {target}", "objdump 反汇编", False),
    "kali_nmap":     ("nmap {target}", "端口扫描", True),
    "kali_hashcat":  ("hashcat {target}", "哈希爆破", True),
    "kali_sqlmap":   ("sqlmap {target}", "SQL 注入检测", True),
    # --- 2026-10-12 补齐的逆向/密码重装备（Kali 侧已装并现测通过）---
    "kali_ghidra":   ("analyzeHeadless /tmp/ghidra-proj ctfos -import {target} "
                      "-deleteProject -noanalysis",
                      "Ghidra 无头反编译。**GUI 需 X，无头只能用 analyzeHeadless**；"
                      "Java 启动慢，超时给足", False),
    "kali_jadx":     ("jadx -d /tmp/jadx-out {target}", "jadx 反编译 APK/DEX/JAR", False),
}

LOCAL_CMDS = {
    "local_sqlmap": ("sqlmap {target}", "本机 sqlmap", True),
    "local_ffuf":   ("ffuf {target}", "本机 ffuf 目录/参数爆破", True),
    "local_objdump": ("objdump -d -M intel {target}", "本机 objdump 反汇编", False),
    "local_gdb":    ("gdb -q -batch -ex '{cmd}' {target}", "本机 gdb 批处理", False),
}


def _mk_remote_tool(name, tmpl, desc, dangerous):
    """Kali 上的工具：支持先上传本地文件再执行。

    关键设计：Kali 是**另一台机器**，看不到本机文件。所以凡是分析类工具，
    必须先经统一桥上传并校验文件 —— 否则命令会静默失败说"找不到文件"。
    """
    def _f(a):
        if dangerous and a.get("confirm") is not True:
            return {"error": "危险动作：请带 confirm=true"}
        target = a.get("target") or ""
        local = a.get("local_file") or ""
        if not target and not local:
            return {"error": "需要 target（Kali 上已有路径）或 local_file（本机文件，会自动上传）"}
        if local:
            lp = Path(local)
            if not lp.is_file():
                return {"error": "本机文件不存在: %s" % local}
            target = "../input/" + lp.name
        prefix = shlex.split(tmpl.format(target="", minlen=int(a.get("minlen", 6))))
        options = shlex.split(str(a.get("opts") or ""))
        targets = shlex.split(str(target)) if dangerous and not local else [str(target)]
        return runtime.kali_execute(a, prefix + options + targets, local=local or None)
    _f.__doc__ = desc
    return _f


def _mk_local_tool(name, tmpl, desc, dangerous):
    def _f(a):
        target = a.get("target") or ""
        if not target:
            return {"error": "需要 target"}
        if dangerous and a.get("confirm") is not True:
            return {"error": "危险动作：请带 confirm=true"}
        if name == "local_gdb":
            argv = ["gdb", "-q", "-batch", "-ex", str(a.get("cmd", "info functions")), str(target)]
        elif name == "local_objdump":
            argv = ["objdump", "-d", "-M", "intel", str(target)]
        else:
            argv = [tmpl.split()[0], *shlex.split(str(target)), *shlex.split(str(a.get("opts") or ""))]
        out = runtime.run_process(argv, timeout=int(a.get("timeout", 300)))
        out.update(command=argv, on="local")
        return out
    _f.__doc__ = desc
    return _f


def _scan_schema(dangerous, extra=None):
    props = {"target": {"type": "string", "description": "Kali 上路径（二选一）"},
             "local_file": {"type": "string", "description": "本机文件绝对路径，经桥上传并校验 SHA256"},
             "case": {"type": "string", "description": "独立题号；未提供时按文件摘要隔离"},
             "minlen": {"type": "integer"}, "opts": {"type": "string"},
             "timeout": {"type": "integer"}}
    if extra:
        props.update(extra)
    if dangerous:
        props["confirm"] = {"type": "boolean"}
    req = ["confirm"] if dangerous else []
    return {"type": "object", "properties": props, "required": req}


SEC_TOOLS = {}
for _n, (_t, _d, _dg) in KALI_CMDS.items():
    SEC_TOOLS[_n] = (_mk_remote_tool(_n, _t, _d, _dg), _d, _scan_schema(_dg))
SEC_TOOLS["kali_sage"] = (tool_kali_sage,
                          "SageMath 实算：factor / LLL / 椭圆曲线 / 符号运算。"
                          "装在 /opt/sage（不在 apt 源里），需 code 参数", {
    "type": "object",
    "properties": {"code": {"type": "string"}, "timeout": {"type": "integer"}},
    "required": ["code"]})
SEC_TOOLS["kali_run"] = (tool_kali_run, "在 Kali 上跑任意命令。危险，需 confirm", {
    "type": "object",
    "properties": {"cmd": {"type": "string"}, "argv": {"type": "array", "items": {"type": "string"}},
                   "local_file": {"type": "string",
                                  "description": "本机文件绝对路径，经桥上传并校验 SHA256；命令里用 ../input/<文件名> 引用"},
                   "case": {"type": "string"}, "timeout": {"type": "integer"},
                   "confirm": {"type": "boolean"}}, "required": ["confirm"]})
for _n, (_t, _d, _dg) in LOCAL_CMDS.items():
    SEC_TOOLS[_n] = (_mk_local_tool(_n, _t, _d, _dg), _d, _scan_schema(_dg,
                     {"cmd": {"type": "string"}}))


# --------------------------------------------------------------------------
# 战例沉淀的解题脚本包装（一次性脚本里有通用价值的那些）
# --------------------------------------------------------------------------

def tool_final_verify(a):
    """跑 `final_verify.py` 做本地三重校验（flag 进报告前必走）。"""
    return _run_py(["final_verify.py"] + list(a.get("args") or []), timeout=120)


def tool_gb_flag_verify(a):
    """GB flag 校验（战例库沉淀）。"""
    return _run_py(["gb_flag_verify.py"] + list(a.get("args") or []), timeout=120)


def tool_run_forensics(a):
    """对 Muteki 的 `run-*.jsonl` 取尸：抽死因/工具数/静默时长。"""
    p = a.get("path") or ""
    if not p:
        return {"error": "需要 path（run-*.jsonl 路径）"}
    return _run_py(["muteki_run_forensics.py", p], timeout=120)


def tool_xor_brute(a):
    """单字节/多字节 XOR 爆破。"""
    return _run_py(["xor_test.py"] + list(a.get("args") or []), timeout=120)


SCRIPT_TOOLS = {
    "final_verify": (tool_final_verify, "本地三重校验（flag 进报告前必走）", {
        "type": "object", "properties": {"args": {"type": "array"}}, "required": []}),
    "gb_flag_verify": (tool_gb_flag_verify, "GB ROM flag 校验", {
        "type": "object", "properties": {"args": {"type": "array"}}, "required": []}),
    "muteki_run_forensics": (tool_run_forensics, "Muteki run 日志取尸，抽死因", {
        "type": "object", "properties": {"path": {"type": "string"}},
        "required": ["path"]}),
    "xor_brute": (tool_xor_brute, "XOR 爆破", {
        "type": "object", "properties": {"args": {"type": "array"}}, "required": []}),
}


# --------------------------------------------------------------------------
# pwn.college 靶场（转调 tools/pwncollege/pc_flow.py，不重造轮子）
# --------------------------------------------------------------------------
PC_DIR = TOOLS_DIR / "pwncollege"


def _pc(args, timeout=180):
    return _run_py([str(PC_DIR / "pc_flow.py")] + [str(x) for x in args],
                   timeout=timeout, cwd=str(PC_DIR))


def tool_pc_find(a):
    """列出 pwn.college 未完成的题。不传 dojo = 全站（近万道）。"""
    args = ["find"]
    if a.get("dojo"):
        args += ["--dojo", str(a["dojo"])]
    if a.get("all"):
        args.append("--all")
    args += ["--limit", str(int(a.get("limit", 50)))]
    return _pc(args, timeout=300)


def tool_pc_pull(a):
    """拉题：启动容器 + 下载 /challenge 附件 + 交接 Kali。"""
    miss = [k for k in ("dojo", "module", "challenge") if not a.get(k)]
    if miss:
        return {"error": "缺少参数: %s" % ", ".join(miss)}
    return _pc(["pull", "--dojo", a["dojo"], "--module", a["module"],
                "--challenge", a["challenge"]], timeout=300)


def tool_pc_run(a):
    """在已启动的挑战容器里跑命令（题目二进制在 /challenge/ 下）。"""
    cmd = a.get("cmd") or a.get("command") or ""
    if not cmd:
        return {"error": "需要 cmd"}
    if not a.get("confirm"):
        return {"error": "危险动作：请带 confirm=true"}
    args = ["run", cmd]
    if a.get("stdin"):
        args += ["--stdin", str(a["stdin"])]
    if a.get("timeout"):
        args += ["--timeout", str(int(a["timeout"]))]
    return _pc(args, timeout=int(a.get("timeout", 120)) + 60)


def tool_pc_submit(a):
    """提交 flag。只提交真实运行得到的，绝不猜。"""
    miss = [k for k in ("dojo", "module", "challenge", "flag") if not a.get(k)]
    if miss:
        return {"error": "缺少参数: %s" % ", ".join(miss)}
    if not a.get("confirm"):
        return {"error": "危险动作：请带 confirm=true"}
    return _pc(["submit", "--dojo", a["dojo"], "--module", a["module"],
                "--challenge", a["challenge"], "--flag", a["flag"]], timeout=180)


def tool_pc_status(a):
    """当前活动的 pwn.college 挑战。"""
    return _pc(["status"], timeout=120)


def tool_pc_stop(a):
    """终止当前 pwn.college 容器。"""
    return _pc(["stop"], timeout=120)


PC_TOOLS = {
    "pc_find": (tool_pc_find,
                "列出 pwn.college 未完成的题。不传 dojo = 全站（近万道）", {
        "type": "object",
        "properties": {"dojo": {"type": "string"},
                       "all": {"type": "boolean"},
                       "limit": {"type": "integer", "default": 50}},
        "required": []}),
    "pc_pull": (tool_pc_pull,
                "拉题：启动容器 + 下载 /challenge 附件 + 交接 Kali", {
        "type": "object",
        "properties": {"dojo": {"type": "string"},
                       "module": {"type": "string"},
                       "challenge": {"type": "string"}},
        "required": ["dojo", "module", "challenge"]}),
    "pc_run": (tool_pc_run,
               "在已启动的挑战容器里跑命令（题目二进制在 /challenge/ 下）。危险，需 confirm", {
        "type": "object",
        "properties": {"cmd": {"type": "string"}, "stdin": {"type": "string"},
                       "timeout": {"type": "integer"},
                       "confirm": {"type": "boolean"}},
        "required": ["cmd", "confirm"]}),
    "pc_submit": (tool_pc_submit,
                  "提交 flag。只提交真实运行得到的，绝不猜。危险，需 confirm", {
        "type": "object",
        "properties": {"dojo": {"type": "string"}, "module": {"type": "string"},
                       "challenge": {"type": "string"},
                       "flag": {"type": "string"},
                       "confirm": {"type": "boolean"}},
        "required": ["dojo", "module", "challenge", "flag", "confirm"]}),
    "pc_status": (tool_pc_status, "当前活动的 pwn.college 挑战", {
        "type": "object", "properties": {}, "required": []}),
    "pc_stop": (tool_pc_stop, "终止当前 pwn.college 容器", {
        "type": "object", "properties": {}, "required": []}),
}


OPS_TOOLS = {
    "status": (tool_status, "现测全装备状态（只读、安全）", {
        "type": "object", "properties": {"deep": {"type": "boolean"}}, "required": []}),
    "muteki_upstream_probe": (tool_muteki_upstream_probe,
                              "体检 Muteki 上游。必给 model，否则假红", {
        "type": "object",
        "properties": {"credential": {"type": "string"},
                       "model": {"type": "string"}}, "required": ["model"]}),
    "muteki_dispatch": (tool_muteki_dispatch,
                        "派题给 Muteki。危险：烧额度，需 confirm", {
        "type": "object",
        "properties": {"dir": {"type": "string"}, "prompt_file": {"type": "string"},
                       "name": {"type": "string"}, "category": {"type": "string"},
                       "confirm": {"type": "boolean"}}, "required": ["confirm", "prompt_file"]}),
    "case_list": (tool_case_list, "列出战例库/题目库", {
        "type": "object",
        "properties": {"which": {"type": "string", "default": "战例库"}},
        "required": []}),
    "kali_run": (tool_kali_run, "在 Kali 上跑命令。危险，需 confirm", {
        "type": "object",
        "properties": {"cmd": {"type": "string"}, "timeout": {"type": "integer"},
                       "confirm": {"type": "boolean"}}, "required": ["cmd", "confirm"]}),
}

# 合并：解题工具 + 装备运维 + 安全工具集 + 脚本包装
ALL_TOOLS = dict(solver.TOOLS)
ALL_TOOLS.update(OPS_TOOLS)
ALL_TOOLS.update(SEC_TOOLS)
ALL_TOOLS.update({k:v for k,v in SCRIPT_TOOLS.items() if k == "muteki_run_forensics"})
ALL_TOOLS.update(PC_TOOLS)
ALL_TOOLS.update(knowledge.TOOLS)
ALL_TOOLS.update(ctf_pcap.TOOLS)
ALL_TOOLS.update(ctf_task_health.TOOLS)
ALL_TOOLS.update(cryptanalysis.TOOLS)
ALL_TOOLS.update(windows_debug.TOOLS)
ALL_TOOLS.update(rea.TOOLS)
ALL_TOOLS.update(writeup.TOOLS)
if specialists is not None:
    ALL_TOOLS.update(specialists.TOOLS)
if extensions is not None:
    ALL_TOOLS.update(extensions.TOOLS)
if ctfd is not None:
    ALL_TOOLS.update(ctfd.TOOLS)
if cracktools is not None:
    ALL_TOOLS.update(cracktools.TOOLS)

# An explicit per-call case prevents parallel agents from mixing challenges.
for _tool_name, (_fn, _desc, _schema) in ALL_TOOLS.items():
    if not _tool_name.startswith("wp_"):
        _schema.setdefault("properties", {})["wp_case"] = {
            "type": "string", "description": "先 wp_init；此调用自动记入指定题号的 WP"}
        _schema['properties']['wp_purpose'] = {'type':'string','description':'这一步的行动目的，自动写入 WP'}
        _schema['properties']['wp_expectation'] = {'type':'string','description':'预期检查的现象或条件；不是已验证结论'}
        _schema['properties']['wp_repeat_expected'] = {'type':'boolean','description':'本次为有意复查，不缓存或跳过执行'}

# 危险工具：派单/远程执行/爆破扫描 —— 这些会烧钱、改配置或对外发包
DANGEROUS = {"muteki_dispatch", "kali_run",
             "kali_nmap", "kali_hashcat", "kali_sqlmap",
             "local_sqlmap", "local_ffuf",
             "pc_run", "pc_submit", "win_debug_start", "win_debug_call"}
if specialists is not None:
    DANGEROUS.update(specialists.DANGEROUS)
if extensions is not None:
    DANGEROUS.update(extensions.DANGEROUS)
if ctfd is not None:
    DANGEROUS.update(ctfd.DANGEROUS)
if cracktools is not None:
    DANGEROUS.update(cracktools.DANGEROUS)


def _call_tool(name, args):
    if not isinstance(name, str) or name not in ALL_TOOLS:
        return {"ok": False, "error": "未知工具: %s" % name,
                "error_code": "unknown_tool",
                "可用工具": sorted(ALL_TOOLS)}
    if not isinstance(args, dict):
        return {"ok": False, "error": "参数必须是对象", "error_code": "invalid_arguments"}
    if name in DANGEROUS and args.get("confirm") is not True:
        return {"ok": False, "error": "危险动作：需要布尔值 confirm=true",
                "error_code": "confirmation_required"}
    try:
        out = ALL_TOOLS[name][0](args or {})
    except KeyError as e:
        # 别的 agent 最容易犯的错就是参数名猜错 —— 直接把正确参数名回给它
        props = list((ALL_TOOLS[name][2].get("properties") or {}).keys())
        return {"ok": False, "tool": name, "error_code": "invalid_arguments",
                "error": "缺少参数 %s" % (e,),
                "该工具的参数": props,
                "示例": {"tool": name, "args": {k: "..." for k in props}}}
    except Exception as e:
        return {"ok": False, "tool": name, "error": "%r" % (e,),
                "error_code": "execution_failed"}
    bad = runtime.failed(out)
    result = {"ok": not bad, "result": out, "tool": name, "dangerous": name in DANGEROUS}
    if bad:
        result["error_code"] = out.get("error_code") or ("timeout" if out.get("timed_out") else "execution_failed")
        result["error"] = out.get("error") or "工具执行失败；读取 result 中退出码与 stderr"
    return result


def call_tool(name, args):
    started = time.monotonic()
    wp_case = None
    if isinstance(args, dict) and isinstance(name, str) and not name.startswith("wp_"):
        wp_case = args.get("wp_case")
        if not wp_case and args.get("case"):
            try:
                wp_case = args["case"] if writeup.exists(args["case"]) else None
            except ValueError:
                pass
        if wp_case:
            try:
                if not writeup.exists(wp_case):
                    raise ValueError("先 wp_init；拒绝无记录地执行指定 WP 调用")
                writeup.status({"case": wp_case})
            except (ValueError, RuntimeError, OSError) as exc:
                return {"ok": False, "tool": name, "error": str(exc), "error_code": "wp_preflight_failed"}
    operation = None
    if wp_case:
        try:
            operation = writeup.begin_call(wp_case, name, args)
        except (ValueError, RuntimeError, OSError) as exc:
            return {'ok':False,'tool':name,'error':str(exc),'error_code':'wp_preflight_failed'}
    execution_args = {key:value for key,value in (args or {}).items() if key not in ('wp_purpose','wp_expectation','wp_repeat_expected')}
    result = _call_tool(name, execution_args)
    if operation:
        result['wp_operation'] = operation
    result.setdefault("tool", name)
    result["duration_ms"] = round((time.monotonic() - started) * 1000, 1)
    if wp_case:
        try:result['task_health']=ctf_task_health.observe(wp_case,name,args,result)
        except Exception as exc:result['task_health_error']=str(exc)
    call_id = "%d-%s" % (time.time_ns(), secrets.token_hex(4))
    try:
        path = GM_BASE / "logs" / "calls" / (call_id + ".json")
        path.parent.mkdir(parents=True, exist_ok=True)
        result["evidence_path"] = str(path)
        record = {"ts": now(), "call_id": call_id, "args": _redact(args), "response": result}
        # Outputs stay in local evidence, never in shared handoff documents.
        path.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError as exc:
        result.pop("evidence_path", None)
        result["evidence_error"] = str(exc)
    audit("tool", tool=name, args=args, ok=result["ok"], ms=result["duration_ms"])
    if wp_case:
        try:
            result["wp_record"] = writeup.record_call(wp_case, args, result)
        except (ValueError, RuntimeError, OSError) as exc:
            result["wp_record_error"] = str(exc)
    return result


def tools_catalog():
    return [{"name": n, "description": d, "inputSchema": s,
             "dangerous": n in DANGEROUS}
            for n, (_, d, s) in ALL_TOOLS.items()]


# --------------------------------------------------------------------------
# HTTP 层
# --------------------------------------------------------------------------

def mcp_handle(req):
    """MCP JSON-RPC 2.0 分发 —— HTTP 与 stdio 两种传输共用这一份逻辑。"""
    method = req.get("method")
    rid = req.get("id")
    params = req.get("params") or {}
    if method == "initialize":
        res = {"protocolVersion": "2025-06-18",
               "capabilities": {"tools": {}},
               "serverInfo": {"name": "ctf-os", "version": "0.1.0"}}
    elif method in ("notifications/initialized", "initialized"):
        return None if rid is None else {"jsonrpc": "2.0", "id": rid}
    elif method == "ping":
        res = {}
    elif method == "tools/list":
        res = {"tools": [{"name": t["name"], "description": t["description"],
                          "inputSchema": t["inputSchema"]}
                         for t in tools_catalog()]}
    elif method == "tools/call":
        name = params.get("name")
        t0 = time.time()
        got = call_tool(name, params.get("arguments", {}))
        audit("mcp", "stdio", name, params.get("arguments"),
              got.get("ok"), (time.time() - t0) * 1000)
        res = {"isError": not got.get("ok"),
               "content": [{"type": "text",
                            "text": json.dumps(got, ensure_ascii=False)}]}
    else:
        return {"jsonrpc": "2.0", "id": rid,
                "error": {"code": -32601, "message": "method not found"}}

    if rid is None:              # 通知不回包
        return {}
    return {"jsonrpc": "2.0", "id": rid, "result": res}


def parse_args_kv(s):
    """解析工具参数：优先当 JSON；不是 JSON 就按 `k=v1,v2` 免引号形式解析。

    🔴 为什么需要第二种写法：PowerShell / cmd 调外部程序时会吃掉 JSON 里的双引号
    （实测 `--args '{"values":[48,60]}'` 传进去变成了 `{values:[48,60]}`），
    跨 shell 传 JSON 极其不可靠。`values=48,60` 这种写法在所有 shell 里都安全。
    """
    if isinstance(s, list):
        # Each argv token is one key=value, so quoted paths keep their spaces.
        if len(s) > 1 or (len(s) == 1 and "=" in s[0]
                          and not re.search(r"\s+[A-Za-z_][A-Za-z0-9_]*=", s[0])):
            if any("=" not in x for x in s):
                return None
            merged = {}
            for part in s:
                key, value = part.split("=", 1)
                if not key:
                    return None
                merged[key] = _kv_value(value, key)
            return merged
        s = s[0] if s else ""
    s = (s or "").strip()
    if not s:
        return {}
    try:
        got = json.loads(s)
        return got if isinstance(got, dict) else None
    except Exception:
        pass
    # 支持 key="带 空格 的值"，否则 `cmd=objdump -s -j` 会被空格切成三段
    out = {}
    parts = re.findall(r'([A-Za-z_][\w.\-]*)=(?:"([^"]*)"|\'([^\']*)\'|(\S+))', s)
    if not parts:
        return None
    for k, dq, sq, bare in parts:
        v = dq or sq or bare
        if "=" in (v or ""):
            return None
        out[k] = _kv_value(v, k)
    return out or None


# 只有这些键才按逗号拆成数组。其余一律当单值字符串 ——
# 🔴 实测坑：`cmd=awk '{print $1,$2}'` 这类带逗号的命令被拆碎后执行结果是 127，
#    排查时看上去像"命令不存在"，其实是参数被拆了。
ARRAY_KEYS = {"values", "numbers", "moduli", "args", "argv",
              "files", "items", "list", "paths", "targets"}


def _scalar(x):
    if x.lower() in ("true", "false"):
        return x.lower() == "true"
    try:
        return int(x, 0)
    except ValueError:
        return x


def _kv_value(value, key=None):
    if key and key not in ARRAY_KEYS:
        return _scalar(value)          # 单值字段：绝不按逗号拆
    values = [_scalar(x) for x in value.split(",") if x != ""]
    return values[0] if len(values) == 1 else (values or "")


def run_stdio():
    """stdio 传输：由 MCP 客户端自己拉起本进程。

    好处是不需要 HTTP 服务常驻 —— 客户端在就有，客户端走就走。
    🔴 stdout 是协议通道，日志只能走 stderr（我们的日志本来就在 stderr）。
    """
    stdin = io.open(sys.stdin.fileno(), "r", encoding="utf-8", errors="replace")
    out = sys.stdout
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception:
            continue
        try:
            res = mcp_handle(req)
        except Exception as e:
            res = {"jsonrpc": "2.0", "id": (req or {}).get("id"),
                   "error": {"code": -32603, "message": "%r" % (e,)}}
        if res is None:
            continue
        out.write(json.dumps(res, ensure_ascii=False) + "\n")
        out.flush()
    return 0


class Handler(BaseHTTPRequestHandler):
    server_version = "CTF-OS/0.1"

    # ---- 鉴权 ----
    def _peer(self):
        try:
            return self.client_address[0]
        except Exception:
            return ""

    def _authorized(self, body=None):
        if not AUTH_TOKEN:                       # 没设令牌 = 不鉴权
            return True
        if self._peer() in _LOCAL_PEERS:         # 本机来源免令牌
            return True
        tok = self.headers.get("X-CTF-OS-Token") or ""
        if not tok and isinstance(body, dict):
            tok = str(body.get("token") or "")
        if not tok:
            tok = (parse_qs(urlparse(self.path).query).get("token") or [""])[0]
        return hmac.compare_digest(str(tok), AUTH_TOKEN)

    def _deny(self):
        audit("deny", self._peer(), note="未授权访问")
        return self._send(401, {
            "ok": False,
            "error": "未授权：需要 X-CTF-OS-Token 请求头（或 ?token= 、body 里的 token 字段）",
            "hint": "本机 127.0.0.1 来源免令牌；对外前用 --token 设一个"})

    def _send(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if not n:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode("utf-8"))
        except Exception:
            return None

    def log_message(self, fmt, *args):
        # 日志走 stderr，stdout 留给需要时看
        sys.stderr.write("[%s] %s\n" % (now(), fmt % args))

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
        self.end_headers()

    def do_GET(self):
        path = urlparse(self.path).path.rstrip("/") or "/"
        if not self._authorized():
            return self._deny()
        audit("get", self._peer(), note=path)
        if path in ("/", ""):
            return self._send(200, self._index())
        if path == "/tools":
            return self._send(200, {"count": len(ALL_TOOLS),
                                    "version": ctf_version.info(len(ALL_TOOLS)),
                                    "tools": tools_catalog()})
        if path == "/version":
            return self._send(200, ctf_version.info(len(ALL_TOOLS)))
        if path == "/status":
            return self._send(200, call_tool("status", {}))
        if path == "/openapi.json":
            return self._send(200, self._openapi())
        return self._send(404, {"error": "no route: %s" % path})

    def do_POST(self):
        path = urlparse(self.path).path.rstrip("/")
        req = self._body()
        if not self._authorized(req):
            return self._deny()
        if not isinstance(req, dict):
            return self._send(400, {"ok": False, "error": "请求必须是有效 JSON 对象", "error_code": "invalid_arguments"})
        t0 = time.time()

        if path == "/call":
            name = req.get("tool") or req.get("name")
            args = next((req[k] for k in ("args", "arguments", "params") if k in req), {})
            out = call_tool(name, args)
            audit("call", self._peer(), name, args, out.get("ok"),
                  (time.time() - t0) * 1000)
            return self._send(200, out)

        if path.startswith("/call/"):
            # 便捷形式：POST /call/<工具名>，body 直接就是参数表
            name = path[len("/call/"):]
            if isinstance(req, dict) and set(req) <= {"args", "arguments", "params"}:
                args = next((req[k] for k in ("args", "arguments", "params") if k in req), {})
            else:
                args = req if isinstance(req, dict) else {}
            out = call_tool(name, args)
            audit("call", self._peer(), name, args, out.get("ok"),
                  (time.time() - t0) * 1000)
            return self._send(200, out)

        if path == "/mcp":
            res = self._mcp(req)
            method = req.get("method")
            p = req.get("params") or {}
            audit("mcp", self._peer(),
                  p.get("name") if method == "tools/call" else method,
                  p.get("arguments"), None, (time.time() - t0) * 1000)
            return self._send(200, res)

        return self._send(404, {"error": "no route: %s" % path})

    # ---- MCP over HTTP（JSON-RPC 2.0）----
    def _mcp(self, req):
        return mcp_handle(req)

    def _index(self):
        return {
            "service": "ctf-os", "version": "0.1.0",
            "purpose": "强网杯作战系统统一入口 —— 给任意 agent 调用",
            "routes": {
                "GET /": "本说明",
                "GET /tools": "能力清单（含 schema）",
                "GET /status": "现测装备状态（只读）",
                "GET /openapi.json": "OpenAPI 描述，供函数调用型 agent 自动接入",
                "POST /call": '{"tool":"...","args":{...}}',
                "POST /mcp": "MCP JSON-RPC，MCP 客户端直接指到这里",
            },
            "tool_count": len(ALL_TOOLS),
            "dangerous_tools": sorted(DANGEROUS),
            "note": "标 dangerous 的工具必须带 confirm=true",
        }

    def _openapi(self):
        paths = {}
        for t in tools_catalog():
            paths["/call/%s" % t["name"]] = {
                "post": {
                    "summary": t["description"],
                    "requestBody": {"required": True,
                                    "content": {"application/json": {
                                        "schema": t["inputSchema"]}}},
                    "responses": {"200": {"description": "ok"}},
                }
            }
        return {"openapi": "3.0.0",
                "info": {"title": "ctf-os", "version": "0.1.0"},
                "paths": paths}


# --------------------------------------------------------------------------

def selftest():
    print("=== 接口自检（自建数据；不代表全部工具或解题流程已验收）===")
    fail = 0
    # 危险工具必须拒绝没有 confirm 的调用
    for name in sorted(DANGEROUS):
        out = call_tool(name, {"cmd": "id"})
        ok = out.get("ok") is False and out.get("error_code") == "confirmation_required"
        fail += 0 if ok else 1
        print("  %s %-22s 无 confirm 时拒绝调用" % ("PASS" if ok else "FAIL", name))
    # 解题工具抽查
    for name, args, field, expected in (
        ("math_gcd", {"values": ["0x3C", 24]}, "result", 12),
        ("crypto_rsa_decrypt", {"p": 61, "q": 53, "e": 17, "c": 2790}, "m", 65)):
        out = call_tool(name, args)
        ok = out.get("ok") and out.get("result", {}).get(field) == expected
        fail += 0 if ok else 1
        print("  %s %-22s 计算结果=%s 预期=%s" % ("PASS" if ok else "FAIL", name, out.get("result"), expected))
    print("\n注册工具: %d（类别存在重叠，不作可用数量相加）" % len(ALL_TOOLS))
    print("实际依赖体检：另运行 --doctor；模型调用与完整解题仍须独立验收")
    print("危险工具(需 confirm): %s" % ", ".join(sorted(DANGEROUS)))
    print("自检通过: %s" % (not fail))
    return 0 if not fail else 1


class _Tee(object):
    """同时写原 stderr 和日志文件（无窗口启动时靠它留痕）。"""

    def __init__(self, *streams):
        self._s = [x for x in streams if x]

    def write(self, data):
        for s in self._s:
            try:
                s.write(data)
                s.flush()
            except Exception:
                pass

    def flush(self):
        for s in self._s:
            try:
                s.flush()
            except Exception:
                pass


def main():
    ap = argparse.ArgumentParser(description="CTF-OS 统一服务入口")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--log", default="", help="日志同时写入该文件")
    ap.add_argument("--hidden", action="store_true",
                    help="Windows 下隐藏控制台窗口（计划任务拉起时用）")
    ap.add_argument("--token", default="",
                    help="访问令牌；设了之后非本机来源必须带令牌。"
                         "建议改用环境变量 CTF_OS_TOKEN，别写在命令行里")
    ap.add_argument("--audit", default="",
                    help="调用审计落盘的 JSONL 路径")
    ap.add_argument("--make-token", action="store_true",
                    help="生成一个随机令牌并打印，然后退出")
    ap.add_argument("--stdio", action="store_true",
                    help="MCP stdio 模式：由客户端拉起本进程，不需要 HTTP 服务常驻")
    ap.add_argument("--once", default="",
                    help="命令行直接调一个工具并退出（零配置接入，任何 agent 都能用）")
    ap.add_argument("--args", nargs="+", default=["{}"],
                    help='配合 --once 的参数，如 \'{"values":[48,60]}\'')
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--doctor", action="store_true", help="实际检查 Kali 桥和依赖；不调用模型、不派题")
    a = ap.parse_args()
    global AUTH_TOKEN, AUDIT_FILE
    AUTH_TOKEN = a.token or AUTH_TOKEN
    AUDIT_FILE = a.audit or AUDIT_FILE
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    if a.log:
        try:
            p = Path(a.log)
            p.parent.mkdir(parents=True, exist_ok=True)
            sys.stderr = _Tee(sys.stderr, io.open(str(p), "a", encoding="utf-8", errors="replace"))
        except OSError as exc:
            print("日志文件打不开：%s" % exc, file=sys.stderr)
    if a.make_token:
        print(secrets.token_urlsafe(24))
        return 0
    if a.stdio:
        return run_stdio()
    if a.once:
        args = parse_args_kv(a.args)
        if args is None:
            print(json.dumps({"ok": False,
                              "error": "--args 既不是合法 JSON 也不是 key=value 形式",
                              "建议": '--args values=48,60 这种免引号写法，'
                                      '任何 shell 都不会吃掉引号'},
                             ensure_ascii=False))
            return 2
        result = call_tool(a.once, args)
        print(json.dumps(result, ensure_ascii=False))
        return 0 if result["ok"] else 1
    if a.doctor:
        result = call_tool("status", {"deep": True})
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result.get("ok") and result["result"].get("doctor_passed") else 1
    if AUTH_TOKEN:
        sys.stderr.write("鉴权已开启：非 127.0.0.1 来源必须带 X-CTF-OS-Token\n")
    if AUDIT_FILE:
        try:
            Path(AUDIT_FILE).parent.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        sys.stderr.write("审计已开启：%s\n" % AUDIT_FILE)
    if a.hidden:
        try:  # pragma: no cover - 仅 Windows
            import ctypes
            ctypes.windll.user32.ShowWindow(
                ctypes.windll.kernel32.GetConsoleWindow(), 0)
        except Exception:
            pass
    if a.selftest:
        return selftest()
    srv = ThreadingHTTPServer((a.host, a.port), Handler)
    print("CTF-OS 监听 http://%s:%d  （工具 %d 个）" % (a.host, a.port, len(ALL_TOOLS)),
          file=sys.stderr)
    print("  GET  /status  GET /tools  POST /call  POST /mcp", file=sys.stderr)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
