"""Team CTF workflow component. See README.md for configuration and verified scope."""
import json
import os
import socket
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
CONFIG = BASE / "config" / "x64dbg.json"
MAX_RESPONSE = 2 * 1024 * 1024


def settings(args):
    arch = args.get("arch", "x64")
    if arch not in ("x64", "x32"):
        raise ValueError("arch 必须为 x64 或 x32")
    cfg = json.loads(CONFIG.read_text(encoding="utf-8-sig")) if CONFIG.exists() else {}
    root = Path(os.environ.get("CTF_X64DBG_ROOT") or cfg.get("debugger_root")
                or BASE.parent / "Apps" / "x64dbg-MCP" / "release")
    directory = root / arch
    executable = directory / (arch + "dbg.exe")
    private = directory / "mcp_config.json"
    plugin = directory / "plugins" / ("x64dbg-MCP-Server.dp64" if arch == "x64" else "x64dbg-MCP-Server.dp32")
    auth = json.loads(private.read_text(encoding="utf-8-sig"))
    if auth.get("IpAddress") != "127.0.0.1":
        raise ValueError("本机桥仅连接 127.0.0.1；请检查 x64dbg 的绑定配置")
    port, token = auth.get("Port"), auth.get("AuthToken")
    if type(port) is not int or not 1 <= port <= 65535 or not isinstance(token, str) or not 1 <= len(token) <= 64:
        raise ValueError("x64dbg 本机端口或鉴权配置无效")
    return {"arch": arch, "executable": executable, "plugin": plugin,
            "url": "http://127.0.0.1:%d/" % port, "port": port, "token": token}


def rpc(cfg, method, params=None, timeout=5):
    payload = {"jsonrpc": "2.0", "id": time.time_ns(), "method": method, "params": params or {}}
    request = urllib.request.Request(cfg["url"], data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                 "Authorization": "Bearer " + cfg["token"]})
    # Loopback calls must not inherit the machine's proxy settings.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=timeout) as response:
            raw = response.read(MAX_RESPONSE + 1)
        if len(raw) > MAX_RESPONSE:
            raise ValueError("x64dbg 响应超过 2MiB 限制")
        value = json.loads(raw)
    except urllib.error.HTTPError as exc:
        code = exc.code
        exc.close()
        raise RuntimeError("x64dbg HTTP %d；检查服务及本机鉴权配置" % code) from None
    except (urllib.error.URLError, TimeoutError, OSError):
        raise RuntimeError("x64dbg 连接失败或超时；执行状态可能已变化，先查状态，不要自动重试动作") from None
    if value.get("id") != payload["id"] or value.get("jsonrpc") != "2.0":
        raise ValueError("x64dbg JSON-RPC 响应身份无效")
    if "error" in value:
        raise RuntimeError("x64dbg JSON-RPC 错误: %s" % value["error"].get("message", "unknown"))
    if not isinstance(value.get("result"), dict):
        raise ValueError("x64dbg 缺少有效 result")
    return value["result"]


def check_identity(cfg):
    result = rpc(cfg, "initialize", {"protocolVersion": "2024-11-05", "capabilities": {},
                 "clientInfo": {"name": "ctf-os-x64dbg", "version": "1"}})
    info = result.get("serverInfo") or {}
    if info.get("name") != "x64dbg-MCP Server":
        raise ValueError("端口上的服务不是预期的 x64dbg-MCP Server")
    return info


def require_confirmation(args):
    if args.get("confirm") is not True:
        raise ValueError("启动调试器或通用调试调用需要布尔值 confirm=true")


def status(args):
    cfg = settings(args)
    result = {"arch": cfg["arch"], "executable": str(cfg["executable"]),
              "installed": cfg["executable"].is_file() and cfg["plugin"].is_file(),
              "endpoint": cfg["url"], "reachable": False,
              "verified_scope": "调试服务和当前状态；不代表题目已解出"}
    try:
        result["server"] = check_identity(cfg)
        result["debug_state"] = rpc(cfg, "tools/call", {"name": "GetDebugState", "arguments": {}})
        result["reachable"] = True
    except (RuntimeError, ValueError) as exc:
        result["service_detail"] = str(exc)
    return result


def start(args):
    require_confirmation(args)
    cfg = settings(args)
    if not cfg["executable"].is_file() or not cfg["plugin"].is_file():
        raise ValueError("x64dbg 或 MCP 插件缺失")
    # An occupied port must be identified before starting another debugger.
    try:
        with socket.create_connection(("127.0.0.1", cfg["port"]), timeout=1):
            occupied = True
    except OSError:
        occupied = False
    if occupied:
        info = check_identity(cfg)
        return {"arch": cfg["arch"], "already_running": True, "server": info, "endpoint": cfg["url"]}
    if os.name != "nt":
        raise ValueError("调试器需要 Windows")
    startup = subprocess.STARTUPINFO()
    startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startup.wShowWindow = 0
    proc = subprocess.Popen([str(cfg["executable"])], cwd=str(cfg["executable"].parent),
                            startupinfo=startup, stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return {"error": "调试器在启动期间退出", "exit": proc.returncode, "pid": proc.pid}
        try:
            info = check_identity(cfg)
            return {"arch": cfg["arch"], "already_running": False,
                    "pid": proc.pid, "server": info, "endpoint": cfg["url"]}
        except RuntimeError:
            time.sleep(0.2)
    return {"error": "调试器已启动但 MCP 未就绪；检查进程，不要重复启动", "pid": proc.pid,
            "error_code": "startup_timeout"}


def catalog(args):
    cfg = settings(args)
    info = check_identity(cfg)
    tools = rpc(cfg, "tools/list").get("tools", [])
    keyword = args.get("query", "")
    if not isinstance(keyword, str) or len(keyword) > 200:
        raise ValueError("query 必须为不超过 200 字符的字符串")
    selected = [t for t in tools if keyword.lower() in
                (t["name"] + " " + t.get("description", "")).lower()]
    return {"server": info, "total": len(tools), "count": len(selected), "tools": selected}


def call(args):
    require_confirmation(args)
    name = args["tool"]
    if not isinstance(name, str) or not name or len(name) > 100:
        raise ValueError("tool 必须是 win_debug_tools 返回的名称")
    params = args.get("params", {})
    if args.get("params_file"):
        if "params" in args:
            raise ValueError("params 与 params_file 只能选一个")
        params = json.loads(Path(args["params_file"]).read_text(encoding="utf-8-sig"))
    elif isinstance(params, str):
        params = json.loads(params)
    if not isinstance(params, dict):
        raise ValueError("params 必须为 JSON 对象")
    timeout = float(args.get("timeout", 35))
    if not 5 <= timeout <= 600:
        raise ValueError("timeout 必须为 5–600 秒")
    # Keep the debugger's wait within the HTTP deadline; timeout is not a stop.
    if name in ("run", "RunToAddress", "WaitForPause", "WaitForEvent"):
        params = dict(params)
        params.setdefault("timeoutMs", min(30000, int((timeout - 5) * 1000)))
        if type(params["timeoutMs"]) is not int or not 1 <= params["timeoutMs"] <= (timeout - 5) * 1000:
            raise ValueError("params.timeoutMs 必须为正整数且至少比 HTTP timeout 短 5 秒")
    if name == "LoadBinary":
        path = params.get("filePath")
        if not isinstance(path, str) or not Path(path).is_absolute() or not Path(path).is_file() or any(c in path for c in '\"\r\n'):
            raise ValueError("LoadBinary 需要存在的绝对 filePath，且不能含命令分隔字符")
        if params.get("arguments"):
            raise ValueError("插件 v1.5 未实现 LoadBinary.arguments，请勿依赖此参数")
    cfg = settings(args)
    check_identity(cfg)
    result = rpc(cfg, "tools/call", {"name": name, "arguments": params}, timeout=timeout)
    texts = "\n".join(c.get("text", "") for c in result.get("content", []) if c.get("type") == "text")
    out = {"arch": cfg["arch"], "debugger_tool": name, "mcp_result": result}
    if result.get("isError") or texts.lstrip().startswith(("Error:", "TIMEOUT")):
        out.update(error=texts or "x64dbg 工具返回错误", error_code="debugger_failed")
    return out


ARCH = {"type": "string", "enum": ["x64", "x32"], "default": "x64"}
TOOLS = {
    "win_debug_status": (status, "检查 Windows x64dbg 安装、MCP 服务和当前调试状态；只读，不自动启动。", {
        "type": "object", "properties": {"arch": ARCH}}),
    "win_debug_start": (start, "按需启动 Windows x64dbg MCP；需要 confirm=true，不加载程序。", {
        "type": "object", "properties": {"arch": ARCH, "confirm": {"type": "boolean"}}, "required": ["confirm"]}),
    "win_debug_tools": (catalog, "查询 x64dbg 实际工具及参数；query 可按英文名称过滤。先启动对应架构的服务。", {
        "type": "object", "properties": {"arch": ARCH, "query": {"type": "string"}}}),
    "win_debug_call": (call, "调用 x64dbg 工具并由 CTF-OS 留证据；通用调试接口需要 confirm=true。先查状态和参数；超时不代表目标停止，勿自动重试。未知附件须先静态分析并使用合适虚拟机。", {
        "type": "object", "properties": {"arch": ARCH, "tool": {"type": "string"},
            "params": {"oneOf": [{"type": "object"}, {"type": "string"}]},
            "params_file": {"type": "string"}, "timeout": {"type": "number", "default": 35},
            "confirm": {"type": "boolean"}}, "required": ["tool", "confirm"]}),
}
