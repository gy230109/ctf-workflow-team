"""Team CTF workflow component. See README.md for configuration and verified scope."""
import json
import os
import shutil
import subprocess
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
CONFIG = BASE / "config" / "rea.json"
MAX_OUTPUT = 4 * 1024 * 1024
MIN_TIMEOUT, MAX_TIMEOUT = 5, 600

# 只读逆向分析类子命令：不改外部状态，可直接调用。
READ_ONLY = {
    "capabilities", "providers", "doctor",
    "analyze", "inspect", "inspect-artifact", "inspect-binary-layout",
    "inspect-managed-artifact", "inspect-managed-members",
    "inspect-managed-native-boundaries", "inspect-keyed-archive",
    "inspect-pe-resources", "inspect-native-load-image", "inspect-native-api",
    "inspect-native-data-type", "inspect-native-instruction",
    "inspect-recorded-crash", "inspect-firmware-regions", "inspect-evm-interface",
    "inspect-android-package", "inspect-android-class", "inspect-android-method",
    "inspect-adb-client", "inspect-apktool-client", "inspect-jeb-client",
    "search", "search-android-classes", "decompile", "instructions",
    "function", "xrefs", "read-bytes", "address-to-file-offset",
    "trace", "trace-android-references", "trace-native-values",
    "compare-managed-members", "compare", "list-architectures",
    "demangle-swift", "evidence-export",
}
# 会改外部状态（写配置 / 装包 / 传文件 / 起停设备应用）：需要 confirm=true。
MUTATING = {
    "setup", "uninstall", "update",
    "install-adb-package", "uninstall-adb-package", "push-adb-file",
    "start-adb-activity", "start-adb-app", "stop-adb-app", "pull-adb-file",
    "pull-adb-package",
}


def settings():
    cfg = json.loads(CONFIG.read_text(encoding="utf-8-sig")) if CONFIG.exists() else {}
    npx = cfg.get("npx") or shutil.which("npx")
    if not npx:
        raise ValueError("未找到 npx；请在 config/rea.json 设置 npx，或安装 Node.js")
    env = dict(os.environ)
    for key, name in (("ghidra_install_dir", "GHIDRA_INSTALL_DIR"),
                      ("java_home", "JAVA_HOME"), ("provider", "REA_ANALYSIS_PROVIDER")):
        if cfg.get(key):
            env[name] = cfg[key]
    return {"npx": npx, "package": cfg.get("package", "rea-agents@6.4.0"),
            "env": env, "config": cfg}


def run_rea(cfg, argv, timeout):
    try:
        proc = subprocess.run([cfg["npx"], "-y", cfg["package"]] + argv,
                              capture_output=True, timeout=timeout, env=cfg["env"],
                              cwd=str(BASE))
    except subprocess.TimeoutExpired:
        raise RuntimeError("REA 调用超时（%ds）；超时不代表分析失败，可加大 timeout 后重试只读命令"
                           % timeout) from None
    out = proc.stdout.decode("utf-8", "replace").lstrip("\ufeff")
    err = proc.stderr.decode("utf-8", "replace")
    return proc.returncode, out, err


def parse_json(out, err, code):
    text = out.strip()
    if not text:
        raise RuntimeError("REA 无标准输出，退出码 %d；stderr: %s" % (code, err.strip()[:400] or "(空)"))
    start = text.find("{")
    if start < 0:
        raise RuntimeError("REA 输出不是 JSON：%s" % text[:300])
    try:
        return json.loads(text[start:])
    except ValueError as exc:
        raise RuntimeError("REA JSON 解析失败：%s；首段：%s" % (exc, text[:300]))


def status(a):
    cfg = settings()
    code, out, err = run_rea(cfg, ["providers", "--format", "json"], 120)
    doc = parse_json(out, err, code)
    engines = [{"id": c.get("provider", {}).get("id"),
                "status": c.get("availability", {}).get("status"),
                "code": c.get("availability", {}).get("code"),
                "reason": c.get("availability", {}).get("reason")}
               for c in doc.get("analysis_provider_candidates", [])]
    return {"package": cfg["package"],
            "ghidra_install_dir": cfg["config"].get("ghidra_install_dir"),
            "java_home": cfg["config"].get("java_home"),
            "engines": engines,
            "binding": doc.get("analysis_provider_binding"),
            "verified_scope": "引擎配置与绑定状态；不代表题目已解出"}


def ops(a):
    cfg = settings()
    code, out, err = run_rea(cfg, ["capabilities", "--format", "json"], 120)
    doc = parse_json(out, err, code)
    caps = doc.get("capabilities", [])
    available = [c["operation"] for c in caps if c.get("available")]
    unavailable = [{"operation": c["operation"], "code": c.get("availability_code"),
                    "reason": c.get("reason")} for c in caps if not c.get("available")]
    return {"total": len(caps), "available": available, "unavailable": unavailable}


def call(a):
    cfg = settings()
    command = a.get("command")
    if not isinstance(command, str) or not command or len(command) > 60:
        raise ValueError("command 必须是 REA 子命令名，例如 inspect")
    if command not in READ_ONLY and command not in MUTATING:
        raise ValueError("command 不在允许列表；只读命令：%s" % sorted(READ_ONLY))
    if command in MUTATING and a.get("confirm") is not True:
        raise ValueError("修改外部状态的子命令需要布尔值 confirm=true")
    raw_args = a.get("args", [])
    if isinstance(raw_args, str):
        # CLI 单值参数不按逗号拆，会原样传字符串；JSON 数组串则解析。
        text = raw_args.strip()
        parsed = None
        if text.startswith("["):
            try:
                parsed = json.loads(text)
            except ValueError:
                parsed = None
        raw_args = parsed if isinstance(parsed, list) else ([text] if text else [])
    if not isinstance(raw_args, list):
        raise ValueError("args 必须为字符串数组")
    # CLI 数组键会把纯数字标量还原成 int，这里统一成字符串。
    raw_args = [x if isinstance(x, str) else str(x) for x in raw_args]
    timeout = float(a.get("timeout", 300))
    if not MIN_TIMEOUT <= timeout <= MAX_TIMEOUT:
        raise ValueError("timeout 必须为 %d–%d 秒" % (MIN_TIMEOUT, MAX_TIMEOUT))
    argv = [command] + raw_args
    if "--format" not in argv:
        argv += ["--format", "json"]
    code, out, err = run_rea(cfg, argv, timeout)
    result = {"command": command, "argv": argv, "exit_code": code}
    if err.strip():
        result["stderr"] = err.strip()[:1000]
    result["result"] = parse_json(out, err, code)
    return result


COMMAND = {"type": "string", "description": "REA 子命令，如 inspect / inspect-managed-artifact / decompile"}
TOOLS = {
    "rea_status": (status, "检查 REA 分析引擎配置与绑定状态（Ghidra 是否可用）。只读，不分析目标。", {
        "type": "object", "properties": {}}),
    "rea_ops": (ops, "列出 REA 可用与不可用 operation。只读。", {
        "type": "object", "properties": {}}),
    "rea_run": (call, "调用 REA 逆向分析子命令并留证据；只读命令直接跑，改外部状态的命令需要 confirm=true。默认输出 JSON。原生二进制分析需要已配置的 Ghidra 引擎。", {
        "type": "object", "properties": {"command": COMMAND,
            "args": {"type": "array", "items": {"type": "string"}},
            "timeout": {"type": "number", "default": 300},
            "confirm": {"type": "boolean"}}, "required": ["command"]}),
}
