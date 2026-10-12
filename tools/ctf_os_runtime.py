"""Team CTF workflow component. See README.md for configuration and verified scope."""
import hashlib
import contextlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent


@contextlib.contextmanager
def dispatch_lock():
    """Single local dispatcher; OS releases the lock even if the process exits."""
    path = BASE / "logs" / "muteki_dispatch.lock"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as stream:
        if path.stat().st_size == 0:
            stream.write(b"0")
            stream.flush()
        stream.seek(0)
        if os.name == "nt":
            import msvcrt
            acquire = lambda: msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            release = lambda: (stream.seek(0), msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1))
        else:
            import fcntl
            acquire = lambda: fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            release = lambda: fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
        try:
            acquire()
        except OSError as exc:
            raise RuntimeError("本机已有派发器运行，拒绝重复派单") from exc
        try:
            yield
        finally:
            release()


def settings():
    path = Path(os.environ.get("CTF_OS_CONFIG", str(BASE / "config" / "ctf_os.json")))
    cfg = json.loads(path.read_text(encoding="utf-8-sig")) if path.exists() else {}
    for key, env in (("kali_bridge", "CTF_KALI_BRIDGE"), ("kali_python", "CTF_KALI_PYTHON")):
        if os.environ.get(env):
            cfg[key] = os.environ[env]
    return cfg


def failed(result):
    if not isinstance(result, dict):
        return False
    return (bool(result.get("error")) or result.get("timed_out") is True
            or result.get("ok") is False
            or any(result.get(k) not in (None, 0) for k in ("exit", "exit_code", "returncode")))


def run_process(argv, timeout=60, cwd=None):
    timeout = float(timeout)
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    env = dict(os.environ, PYTHONUTF8="1", PYTHONIOENCODING="utf-8")
    try:
        p = subprocess.run(argv, capture_output=True, timeout=timeout, cwd=cwd, env=env)
        out, err = p.stdout, p.stderr
        result = {"exit": p.returncode, "timed_out": False}
    except subprocess.TimeoutExpired as exc:
        out, err = exc.stdout or b"", exc.stderr or b""
        result = {"exit": 124, "timed_out": True, "error": "执行超时"}
    result.update(stdout=out[:1048576].decode("utf-8", "replace"),
                  stderr=err[:1048576].decode("utf-8", "replace"),
                  stdout_bytes=len(out), stderr_bytes=len(err),
                  output_truncated=len(out) > 1048576 or len(err) > 1048576)
    return result


def bridge_call(args, timeout=90):
    cfg = settings()
    entry = cfg.get("kali_bridge")
    if not entry or not Path(entry).is_file():
        return {"error": "Kali 桥未配置或不存在；检查 config/ctf_os.json", "error_code": "bridge_unavailable"}
    process = run_process([cfg.get("kali_python") or sys.executable, "-X", "utf8", entry, *args], timeout)
    try:
        result = json.loads(process["stdout"])
    except (ValueError, TypeError):
        return dict(process, error=process.get("error") or "Kali 桥未返回有效 JSON",
                    error_code="bridge_failed")
    if not isinstance(result, dict):
        return dict(process, error="Kali 桥返回值不是对象", error_code="bridge_failed")
    result["bridge_exit"] = process["exit"]
    if process["exit"] and not failed(result):
        result.update(error="Kali 桥执行失败", stderr=process["stderr"], exit=process["exit"])
    return result


def kali_execute(args, argv, local=None):
    timeout = int(args.get("timeout", 60))
    if not 1 <= timeout <= 600:
        return {"error": "Kali timeout 必须在 1–600 秒之间", "error_code": "invalid_arguments"}
    digest = None
    if local:
        path = Path(local).resolve(strict=True)
        if not path.is_file():
            return {"error": "local_file 必须是文件"}
        with path.open("rb") as f:
            digest = hashlib.file_digest(f, "sha256").hexdigest()
    case = str(args.get("case") or ("ctfos_" + digest[:24] if digest else "ctfos_commands"))
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", case):
        return {"error": "case 只允许字母、数字、下划线、连字符", "error_code": "invalid_arguments"}
    if local:
        upload = bridge_call(["put", case, str(path)], timeout=180)
        if failed(upload) or upload.get("verified") is not True:
            return {"error": "Kali 上传未通过摘要校验", "error_code": "upload_failed", "detail": upload}
    result = bridge_call(["run", "--timeout", str(timeout), case, "--", *argv], timeout=timeout + 40)
    result.update(case=case, on="kali", transport="verified_bridge")
    if local:
        result.update(input_sha256=digest, upload_verified=True)
    return result


def kali_dependencies():
    source = '''import importlib.util,json,shutil
commands=['file','strings','binwalk','r2','objdump','gdb','nmap','hashcat','sqlmap','checksec','tshark','sage','jadx','ghidra']
modules=['pwn','Crypto','z3','gmpy2','sympy','dnfile']
print(json.dumps({'commands':{n:shutil.which(n) for n in commands},'python_modules':{n:importlib.util.find_spec(n) is not None for n in modules}}))'''
    result = kali_execute({"case": "ctfos_doctor", "timeout": 30}, ["python3", "-c", source])
    if not failed(result):
        result["dependencies"] = json.loads(result["stdout"])
    return result
