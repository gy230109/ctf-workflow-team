#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Team CTF workflow component. See README.md for configuration and verified scope."""
import base64
import json
import math
import os
import re
import subprocess
import sys
from pathlib import Path

# 本机绝对路径只允许出现在这里：脚本不硬编码业务路径，全部相对 __file__ 推导
TOOLS_DIR = Path(__file__).resolve().parent
GM_BASE = TOOLS_DIR.parent

PROTOCOL_VERSION = "2025-06-18"
SERVER_INFO = {"name": "ctf-toolchain", "version": "0.1.0"}

# py_run 的执行上限，防止一条工具调用把机器拖死
PY_TIMEOUT = int(os.environ.get("CTF_MCP_PY_TIMEOUT", "20"))


def log(msg):
    """日志必须走 stderr —— stdout 是 JSON-RPC 协议通道。"""
    print(msg, file=sys.stderr, flush=True)


# --------------------------------------------------------------------------
# 工具实现
# --------------------------------------------------------------------------

def _parse_int(x):
    """接受十进制 / 0x 十六进制 / Python 字面量字符串。"""
    if isinstance(x, int):
        return x
    s = str(x).strip().replace(" ", "").replace("_", "")
    if s.lower().startswith("0x"):
        return int(s, 16)
    return int(s, 0) if re.fullmatch(r"[0-9]+", s) else int(s)


def tool_math_gcd(a):
    """最大公约数。RSA 多模数攻击的第一步。"""
    vals = a["values"] if isinstance(a.get("values"), list) else [a["a"], a["b"]]
    return {"result": math.gcd(*[_parse_int(v) for v in vals])}


def tool_math_modpow(a):
    """模幂 pow(base, exp, mod)。"""
    return {"result": pow(_parse_int(a["base"]), _parse_int(a["exp"]),
                          _parse_int(a["mod"]))}


def tool_math_modinv(a):
    """模逆元（Python 3.8+ 支持负指数）。"""
    try:
        return {"result": pow(_parse_int(a["a"]), -1, _parse_int(a["mod"]))}
    except ValueError as e:
        return {"error": "模逆不存在（不互素）: %s" % e}


def tool_crypto_shared_factors(a):
    """两两 GCD 找共享素因子 —— **多模数 RSA 永远先跑这一步**，比因式分解便宜几个数量级。"""
    nums = [_parse_int(v) for v in a["numbers"]]
    hits = []
    for i in range(len(nums)):
        for j in range(i + 1, len(nums)):
            g = math.gcd(nums[i], nums[j])
            if g > 1:
                hits.append({"pair": [i, j], "gcd": g})
    return {"count": len(hits), "shared": hits}


def tool_crypto_rsa_decrypt(a):
    """已知 p、q、e、c 的标准 RSA 解密，输出明文整数与可打印串。"""
    p, q, e, c = (_parse_int(a["p"]), _parse_int(a["q"]),
                  _parse_int(a["e"]), _parse_int(a["c"]))
    n = p * q
    phi = (p - 1) * (q - 1)
    try:
        d = pow(e, -1, phi)
    except ValueError:
        return {"error": "e 与 phi 不互素"}
    m = pow(c, d, n)
    try:
        raw = m.to_bytes((m.bit_length() + 7) // 8, "big")
        text = raw.decode("latin-1")
        printable = "".join(ch if 32 <= ord(ch) < 127 else "." for ch in text)
    except Exception:
        raw, printable = b"", ""
    return {"n": n, "d": d, "m": m, "bytes_hex": raw.hex(), "printable": printable}


def tool_util_hex(a):
    """字符串 -> hex。"""
    return {"result": a["text"].encode(a.get("encoding", "utf-8")).hex()}


def tool_util_unhex(a):
    """hex -> 字符串（不可解码时退化为 latin-1，避免直接抛错丢失信息）。"""
    raw = bytes.fromhex(a["hex"].replace(" ", "").replace("0x", ""))
    try:
        return {"result": raw.decode(a.get("encoding", "utf-8"))}
    except UnicodeDecodeError:
        return {"result": raw.decode("latin-1"), "note": "非 UTF-8，已按 latin-1 输出"}


def tool_util_b64(a):
    """base64 编/解码。"""
    if a.get("mode", "encode") == "encode":
        return {"result": base64.b64encode(a["data"].encode()).decode()}
    return {"result": base64.b64decode(a["data"]).decode("latin-1")}


def tool_util_rot(a):
    """凯撒/ROT 位移（同时给出 n 和 26-n 两个方向）。"""
    n = int(a.get("n", 13)) % 26

    def shift(s, k):
        out = []
        for ch in s:
            if ch.isalpha():
                base = ord("A") if ch.isupper() else ord("a")
                out.append(chr((ord(ch) - base + k) % 26 + base))
            else:
                out.append(ch)
        return "".join(out)

    t = a["text"]
    return {"n": n, "forward": shift(t, n), "reverse": shift(t, -n)}


def tool_util_int_bytes(a):
    """大整数 <-> 字节。这是 RSA 题里最容易搞错端序的地方，单独做成工具。"""
    if a.get("mode", "to_bytes") == "to_bytes":
        v = _parse_int(a["value"])
        return {"hex": v.to_bytes((v.bit_length() + 7) // 8, "big").hex(),
                "order": "big"}
    return {"int": int.from_bytes(bytes.fromhex(a["value"].replace(" ", "")),
                                  a.get("order", "big"))}


def _run_gbdis(args):
    """转调用战例库沉淀的 gbdis.py，不在这里重写 LR35902 逻辑。"""
    script = TOOLS_DIR / "gbdis.py"
    if not script.exists():
        return {"error": "未找到 %s" % script}
    py = sys.executable
    try:
        p = subprocess.run([py, "-X", "utf8", str(script)] + [str(x) for x in args],
                           capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
        return {"exit": p.returncode, "stdout": p.stdout[:1048576],
                "stderr": p.stderr[:1048576],
                "output_truncated": len(p.stdout) > 1048576 or len(p.stderr) > 1048576}
    except subprocess.TimeoutExpired:
        return {"error": "gbdis 执行超时"}


def tool_gb_disasm(a):
    """GB 反汇编：`python gbdis.py <rom> <start> [count]`"""
    return _run_gbdis([a["rom"], a["start"], a.get("count", 40)])


def tool_gb_find(a):
    """在 ROM 里搜字节序列：`gbdis.py <rom> find <hexbytes>`"""
    return _run_gbdis([a["rom"], "find", a["hexbytes"]])


def tool_gb_strings(a):
    """提取 GB 内联字符串簇：`gbdis.py <rom> strs <cluster>`"""
    return _run_gbdis([a["rom"], "strs", a.get("cluster", 8)])


def tool_flag_format_check(a):
    """**只做格式校验，不比对答案 flag**。

    规矩：flag 必须本地亲手跑出来。这个工具存在的意义是"检查"，不是"产出"。
    """
    cand = a["candidate"]
    pattern = a.get("pattern", r"^flag\{.+\}$|^GWHT\{.+\}$|^FLAG\{.+\}$")
    ok = re.search(pattern, cand, re.I) is not None
    inner = None
    m = re.search(r"\{([^{}]*)\}", cand)
    if m:
        inner = {"content": m.group(1), "length": len(m.group(1))}
    # 提示包装/空白这类低级错误，但不透露任何预期值
    hints = []
    if cand != cand.strip():
        hints.append("首尾有多余空白")
    return {"format_ok": ok, "inner": inner, "hints": hints}


def tool_py_run(a):
    """受限执行一段 Python 并返回 stdout。

    限制：子进程跑、有超时、清掉网络相关的代理环境变量。
    **注意这不是安全沙箱**，只是防手滑；不要拿它跑不可信代码之外的东西。
    """
    code = a["code"]
    env = {k: v for k, v in os.environ.items()
           if k.upper() not in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY")}
    env["PYTHONIOENCODING"] = "utf-8"
    try:
        p = subprocess.run([sys.executable, "-c", code],
                           capture_output=True, text=True, encoding="utf-8", errors="replace",
                           timeout=min(int(a.get("timeout", PY_TIMEOUT)), 120),
                           env=env, cwd=str(GM_BASE))
        return {"exit": p.returncode, "stdout": p.stdout[:1048576],
                "stderr": p.stderr[:1048576],
                "output_truncated": len(p.stdout) > 1048576 or len(p.stderr) > 1048576}
    except subprocess.TimeoutExpired:
        return {"error": "执行超时"}


# --------------------------------------------------------------------------
# 注册表
# --------------------------------------------------------------------------

TOOLS = {
    "math_gcd": (tool_math_gcd, "最大公约数。RSA 多模数攻击第一步。", {
        "type": "object",
        "properties": {"values": {"type": "array", "items": {},
                                  "description": "求这些数的公约数（≥2 个）"},
                       "a": {}, "b": {}},
        "required": [],
    }),
    "math_modpow": (tool_math_modpow, "模幂 pow(base, exp, mod)。", {
        "type": "object",
        "properties": {"base": {}, "exp": {}, "mod": {}},
        "required": ["base", "exp", "mod"],
    }),
    "math_modinv": (tool_math_modinv, "模逆元 a^-1 mod m。", {
        "type": "object",
        "properties": {"a": {}, "mod": {}},
        "required": ["a", "mod"],
    }),
    "crypto_shared_factors": (tool_crypto_shared_factors,
                              "两两 GCD 找共享素因子。多模数 RSA 永远先跑这一步。", {
        "type": "object",
        "properties": {"numbers": {"type": "array", "items": {}}},
        "required": ["numbers"],
    }),
    "crypto_rsa_decrypt": (tool_crypto_rsa_decrypt,
                           "已知 p,q,e,c 的标准 RSA 解密。", {
        "type": "object",
        "properties": {"p": {}, "q": {}, "e": {}, "c": {}},
        "required": ["p", "q", "e", "c"],
    }),
    "util_hex": (tool_util_hex, "字符串转 hex。", {
        "type": "object",
        "properties": {"text": {"type": "string"},
                       "encoding": {"type": "string", "default": "utf-8"}},
        "required": ["text"],
    }),
    "util_unhex": (tool_util_unhex, "hex 转字符串。", {
        "type": "object",
        "properties": {"hex": {"type": "string"},
                       "encoding": {"type": "string", "default": "utf-8"}},
        "required": ["hex"],
    }),
    "util_b64": (tool_util_b64, "base64 编解码（mode: encode/decode）。", {
        "type": "object",
        "properties": {"data": {"type": "string"},
                       "mode": {"type": "string", "default": "encode"}},
        "required": ["data"],
    }),
    "util_rot": (tool_util_rot, "凯撒位移，同时给出正反两个方向。", {
        "type": "object",
        "properties": {"text": {"type": "string"}, "n": {"type": "integer"}},
        "required": ["text"],
    }),
    "util_int_bytes": (tool_util_int_bytes,
                       "大整数与字节互转（RSA 里端序最容易错）。", {
        "type": "object",
        "properties": {"value": {}, "mode": {"type": "string",
                                             "default": "to_bytes"},
                       "order": {"type": "string", "default": "big"}},
        "required": ["value"],
    }),
    "gb_disasm": (tool_gb_disasm, "GameBoy ROM 反汇编（转调 gbdis.py）。", {
        "type": "object",
        "properties": {"rom": {"type": "string", "description": "ROM 文件绝对路径"},
                       "start": {}, "count": {"type": "integer"}},
        "required": ["rom", "start"],
    }),
    "gb_find": (tool_gb_find, "在 GB ROM 里搜索字节序列。", {
        "type": "object",
        "properties": {"rom": {"type": "string"}, "hexbytes": {"type": "string"}},
        "required": ["rom", "hexbytes"],
    }),
    "gb_strings": (tool_gb_strings, "提取 GB ROM 内联字符串簇。", {
        "type": "object",
        "properties": {"rom": {"type": "string"}, "cluster": {"type": "integer"}},
        "required": ["rom"],
    }),
    "flag_format_check": (tool_flag_format_check,
                          "只校验 flag 格式，不比对答案（规矩：flag 本地亲手跑）。", {
        "type": "object",
        "properties": {"candidate": {"type": "string"},
                       "pattern": {"type": "string"}},
        "required": ["candidate"],
    }),
    "py_run": (tool_py_run, "执行一段 Python 并返回 stdout（子进程+超时+去代理）。", {
        "type": "object",
        "properties": {"code": {"type": "string"}, "timeout": {"type": "integer"}},
        "required": ["code"],
    }),
}


def tools_list():
    return [{"name": n, "description": d, "inputSchema": s}
            for n, (_, d, s) in TOOLS.items()]


# --------------------------------------------------------------------------
# JSON-RPC over stdio
# --------------------------------------------------------------------------

def handle(req):
    method = req.get("method")
    rid = req.get("id")
    params = req.get("params") or {}

    if method == "initialize":
        return {"protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": SERVER_INFO}
    if method in ("notifications/initialized", "initialized"):
        return None  # 通知，不回包
    if method == "ping":
        return {}
    if method == "tools/list":
        return {"tools": tools_list()}
    if method == "tools/call":
        name = params.get("name")
        args = params.get("arguments") or {}
        if name not in TOOLS:
            return {"isError": True,
                    "content": [{"type": "text",
                                 "text": "未知工具: %s" % name}]}
        fn = TOOLS[name][0]
        try:
            out = fn(args)
        except Exception as e:
            log("tool %s raised: %r" % (name, e))
            return {"isError": True,
                    "content": [{"type": "text",
                                 "text": "工具执行异常: %r" % (e,)}]}
        return {"isError": isinstance(out, dict) and "error" in out,
                "content": [{"type": "text", "text": json.dumps(out, ensure_ascii=False)}]}
    return {"error": {"code": -32601, "message": "method not found: %s" % method}}


def serve():
    log("ctf-mcp server ready (stdio), tools=%d" % len(TOOLS))
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception as e:
            log("bad json: %r" % e)
            continue
        if "id" not in req:
            handle(req)
            continue
        resp = handle(req)
        if resp is None:
            continue
        if "error" in resp and "result" not in resp and len(resp) == 1:
            packet = {"jsonrpc": "2.0", "id": req["id"], "error": resp["error"]}
        else:
            packet = {"jsonrpc": "2.0", "id": req["id"], "result": resp}
        sys.stdout.write(json.dumps(packet, ensure_ascii=False) + "\n")
        sys.stdout.flush()


def mcp_config_snippet():
    """给 Trae 的 mcp.json 片段。注意 Windows 路径必须写成正斜杠或双反斜杠。"""
    return {
        "mcpServers": {
            "ctf-toolchain": {
                "command": sys.executable,
                "args": [str(TOOLS_DIR / "ctf_mcp_server.py")],
                "env": {"PYTHONIOENCODING": "utf-8"},
            }
        }
    }


def selftest():
    """不进 stdio，直接在本进程里把每个工具打一遍。

    这是必须的：MCP server 起不来时客户端只会报一句含糊的连接错误，
    靠它根本看不出是协议写错还是某个工具内部崩了。
    """
    cases = [
        ("math_gcd", {"values": ["0x3C", 24]}),
        ("math_modpow", {"base": 2, "exp": 10, "mod": 1000}),
        ("math_modinv", {"a": 17, "mod": 3120}),
        ("crypto_shared_factors", {"numbers": [15, 25, 35]}),
        ("crypto_rsa_decrypt", {"p": 61, "q": 53, "e": 17, "c": 2790}),
        ("util_hex", {"text": "flag"}),
        ("util_unhex", {"hex": "666c6167"}),
        ("util_b64", {"data": "flag"}),
        ("util_rot", {"text": "uryyb", "n": 13}),
        ("util_int_bytes", {"value": 12345}),
        ("flag_format_check", {"candidate": "flag{test}"}),
        ("py_run", {"code": "print(6*7)"}),
    ]
    fail = 0
    for name, args in cases:
        try:
            out = TOOLS[name][0](args)
            bad = isinstance(out, dict) and "error" in out
            fail += 1 if bad else 0
            print("  %s %-24s %s" % ("FAIL" if bad else "PASS", name,
                                     json.dumps(out, ensure_ascii=False)[:110]))
        except Exception as e:
            fail += 1
            print("  FAIL %-24s raised %r" % (name, e))
    # GB 三个工具依赖外部脚本 + ROM 文件，单独标记为可选
    print("  ---- GB 工具（需 ROM，此处只做存在性检查）----")
    for name in ("gb_disasm", "gb_find", "gb_strings"):
        ok = (TOOLS_DIR / "gbdis.py").exists()
        print("  %s %-24s %s" % ("PASS" if ok else "FAIL", name,
                                 "gbdis.py 存在" if ok else "缺 gbdis.py"))
    print("\n自检通过: %s" % (not fail))
    return 0 if not fail else 1


def main():
    if "--selftest" in sys.argv:
        return selftest()
    if "--config" in sys.argv:
        print(json.dumps(mcp_config_snippet(), ensure_ascii=False, indent=2))
        return 0
    serve()
    return 0


if __name__ == "__main__":
    sys.exit(main())
