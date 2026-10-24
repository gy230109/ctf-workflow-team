"""Portable, case-scoped CTF evidence and Chinese writeup generation.

Raw evidence is private. Rendered terminal output is never called a screenshot.
The generator does not call a model, solve a challenge or assert a valid flag.
"""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import textwrap
import uuid
from datetime import datetime, timezone

BASE = Path(__file__).resolve().parent.parent
ROOT = BASE / "wp" / "cases"


def canonical(obj):
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def case_dir(case):
    if not isinstance(case, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", case):
        raise ValueError("case 必须是 1–64 位字母、数字、下划线或连字符")
    path = (ROOT / case).resolve()
    if not path.is_relative_to(ROOT.resolve()):
        raise ValueError("case 路径越界")
    return path


def exists(case):
    return (case_dir(case) / "session.json").is_file()


@contextlib.contextmanager
def locked(folder):
    folder.mkdir(parents=True, exist_ok=True)
    with (folder / ".lock").open("a+b") as stream:
        if stream.tell() == 0:
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
            raise RuntimeError("此 WP 正在写入，请重试；不同题请用不同 case") from exc
        try:
            yield
        finally:
            release()


def write_json(path, obj):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                     delete=False, suffix=".tmp") as stream:
        json.dump(obj, stream, ensure_ascii=False, indent=2)
        temp = Path(stream.name)
    os.replace(temp, path)


def records(folder):
    path = folder / "timeline.jsonl"
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()] if path.exists() else []


def verify(folder):
    rows = records(folder)
    previous = "0" * 64
    for seq, event in enumerate(rows, 1):
        if event.get("seq") != seq or event.get("previous") != previous:
            raise ValueError("WP 时间线被删除或重排，拒绝生成")
        body = {k: v for k, v in event.items() if k != "sha256"}
        if hashlib.sha256(canonical(body).encode()).hexdigest() != event.get("sha256"):
            raise ValueError("WP 时间线摘要不匹配")
        for item in event.get("files", []):
            path = (folder / item["path"]).resolve()
            if not path.is_relative_to(folder.resolve()) or not path.is_file() or digest(path) != item["sha256"]:
                raise ValueError("WP 原始证据缺失或被改动: " + item["path"])
        previous = event["sha256"]
    # A checkpoint detects accidental deletion of the last event too. It is not
    # a cryptographic signature against someone rewriting all local files.
    checkpoint = folder / "checkpoint.json"
    if checkpoint.exists():
        saved = json.loads(checkpoint.read_text(encoding="utf-8"))
        if saved != {"count": len(rows), "head": previous}:
            raise ValueError("WP 时间线与检查点不一致")
    return rows


def append(folder, kind, data, files=None):
    rows = verify(folder)
    event = {"seq": len(rows) + 1, "at": datetime.now(timezone.utc).isoformat(),
             "previous": rows[-1]["sha256"] if rows else "0" * 64,
             "kind": kind, "data": data, "files": files or []}
    event["sha256"] = hashlib.sha256(canonical(event).encode()).hexdigest()
    with (folder / "timeline.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(canonical(event) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    write_json(folder / "checkpoint.json", {"count": event["seq"], "head": event["sha256"]})
    return event


def file_record(folder, path, kind):
    return {"path": path.relative_to(folder).as_posix(), "sha256": digest(path), "kind": kind}


def init(a):
    folder = case_dir(a["case"])
    with locked(folder):
        path = folder / "session.json"
        if path.exists():
            verify(folder)
            return {"case": a["case"], "created": False, "path": str(folder)}
        metadata = {"case": a["case"], "title": str(a.get("title") or a["case"]),
                    "category": str(a.get("category") or "未分类"),
                    "competition": str(a.get("competition") or "未填写"),
                    "created_at": datetime.now(timezone.utc).isoformat()}
        write_json(path, metadata)
        append(folder, "session", metadata, [file_record(folder, path, "metadata")])
    return {"case": a["case"], "created": True, "path": str(folder),
            "usage": "后续 CTF-OS 调用加 wp_case=<题号> 自动留证；wp_note 补思路；wp_build 生成中文 WP"}


def _plain_file(value):
    path = Path(value).absolute()
    if any(p.is_symlink() or getattr(p, "is_junction", lambda: False)()
           for p in (path, *path.parents)):
        raise ValueError("不接受符号链接或位于符号链接目录的文件")
    if not path.is_file():
        raise ValueError("附件或输入必须是现存的普通文件")
    return path.resolve(strict=True)


def _copy_bounded(source, target, limit):
    """Bound writes even if a source grows after its preflight stat."""
    written, created = 0, False
    try:
        with source.open("rb") as incoming:
            with target.open("xb") as outgoing:
                created = True
                while True:
                    chunk = incoming.read(1048576)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > limit:
                        raise ValueError("文件在复制时超过大小上限")
                    outgoing.write(chunk)
    except Exception:
        if created:
            target.unlink(missing_ok=True)
        raise


def intake(a):
    """Append protected task context without rewriting the original session."""
    folder = case_dir(a["case"])
    if not exists(a["case"]):
        raise ValueError("先 wp_init")
    description = str(a.get("description") or "").strip()
    source = a.get("source") or ""
    if len(description) > 200000 or len(canonical(source)) > 20000:
        raise ValueError("题面或来源说明过长")
    items = a.get("attachments") or []
    if not isinstance(items, list) or len(items) > 32:
        raise ValueError("attachments 必须是最多 32 个文件的列表")
    prepared, total = [], 0
    for item in items:
        info = {"path": item} if isinstance(item, str) else item
        if not isinstance(info, dict) or not info.get("path"):
            raise ValueError("每个附件必须有 path")
        path = _plain_file(info["path"])
        size = path.stat().st_size
        total += size
        if size > 512 * 1024 * 1024 or total > 10 * 1024 * 1024 * 1024:
            raise ValueError("附件超过单个 512 MiB 或合计 10 GiB 上限；请分题或使用原件索引")
        sha = digest(path)
        if info.get("sha256") and str(info["sha256"]).lower() != sha:
            raise ValueError("附件 SHA256 与提供的摘要不符")
        name = str(info.get("name") or path.name)
        if not name or len(name) > 512:
            raise ValueError("附件名无效")
        prepared.append((path, size, sha, name))
    with locked(folder):
        verify(folder)
        target_dir = folder / "intake" / uuid.uuid4().hex
        target_dir.mkdir(parents=True)
        artifacts, files = [], []
        for index, (path, size, sha, name) in enumerate(prepared, 1):
            suffix = path.suffix.lower() if len(path.suffix) <= 20 else ".bin"
            target = target_dir / ("%02d" % index + suffix)
            _copy_bounded(path, target, size)
            if digest(target) != sha or digest(path) != sha:
                raise ValueError("附件复制时发生变化；拒绝保存题面事件")
            item = {"name": name, "bytes": size, "sha256": sha,
                    "path": target.relative_to(folder).as_posix()}
            artifacts.append(item)
            files.append(dict(file_record(folder, target, "original_attachment"),
                              original_name=name, source_role="challenge_handout"))
        data = {"description": description, "source": source, "artifacts": artifacts}
        context_path = target_dir / "context.json"
        write_json(context_path, data)
        event = append(folder, "intake", data,
                       [file_record(folder, context_path, "task_context"), *files])
    return {"case": a["case"], "step": event["seq"], "attachments": len(artifacts),
            "bytes": total, "path": str(context_path)}


def section(a):
    folder = case_dir(a["case"])
    if not exists(a["case"]):
        raise ValueError("先 wp_init")
    name = a.get("section")
    if name not in ("overview", "analysis", "solution", "validation", "reproduction"):
        raise ValueError("section 只能为 overview/analysis/solution/validation/reproduction")
    text = str(a.get("text") or "").strip()
    if not text or len(text) > 100000:
        raise ValueError("章节 text 必须为 1–100000 字符")
    steps = a.get("source_steps") or []
    if not isinstance(steps, list) or any(type(x) is not int for x in steps):
        raise ValueError("source_steps 必须为实际调用/截图步骤号列表")
    if name != "overview" and not steps:
        raise ValueError("分析、解法、验证和复现章节必须引用实际证据步骤")
    with locked(folder):
        rows = verify(folder)
        if any(not 1 <= x <= len(rows) or rows[x-1]["kind"] not in ("call", "capture") for x in steps):
            raise ValueError("source_steps 只能引用实际调用或截图")
        event = append(folder, "writeup_section", {"section": name, "text": text,
                       "source_steps": list(dict.fromkeys(steps)),
                       "claim_type": "agent_annotation"})
    return {"case": a["case"], "step": event["seq"], "section": name,
            "latest_revision": True, "independent_verification": False}


def _snapshot_inputs(folder, args, operation_id):
    snapshots, files, errors = [], [], []
    suffixes = {".py", ".sage", ".sh", ".ps1", ".js", ".c", ".cpp"}
    for field in ("local_file", "script_file", "request_file"):
        value = args.get(field)
        if not isinstance(value, str) or not value:
            continue
        if field != "request_file" and Path(value).suffix.lower() not in suffixes:
            continue
        kind = "request_snapshot" if field == "request_file" else "script_snapshot"
        try:
            source = _plain_file(value)
            if source.stat().st_size > 1048576:
                raise ValueError("执行前输入快照超过 1 MiB")
            if field == "request_file":
                json.loads(source.read_text(encoding="utf-8-sig"))
            sha = digest(source)
            target = folder / "inputs" / operation_id / (field + source.suffix.lower())
            target.parent.mkdir(parents=True, exist_ok=True)
            _copy_bounded(source, target, 1048576)
            if digest(target) != sha or digest(source) != sha:
                raise ValueError("输入在执行前复制时发生变化")
            item = dict(file_record(folder, target, kind), source_role="pre_execution_input",
                        original_name=source.name, field=field,
                        source="执行前保存的显式工具输入；不代表脚本执行成功")
            files.append(item)
            snapshots.append({"field": field, "original_path": str(source), "sha256": sha,
                              "path": item["path"], "kind": kind})
        except (OSError, ValueError, TypeError) as exc:
            errors.append({"kind": kind, "field": field, "error": str(exc),
                           "phase": "pre_execution", "action_replayed": False})
    return snapshots, files, errors


def begin_call(case, tool, args):
    folder = case_dir(case)
    operation_id = uuid.uuid4().hex
    with locked(folder):
        if not (folder / "session.json").is_file():
            raise ValueError("先 wp_init")
        verify(folder)
        snapshots, inputs, errors = _snapshot_inputs(folder, args, operation_id)
        path = folder / 'raw' / (operation_id + '-begin.json')
        write_json(path, {'tool': tool, 'arguments': args, 'operation_id': operation_id})
        event = append(folder, 'operation_started', {'operation_id': operation_id, 'tool': tool,
            'purpose': str(args.get('wp_purpose') or ''), 'expectation': str(args.get('wp_expectation') or ''),
            'input_snapshots': snapshots, 'capture_errors': errors},
            [file_record(folder, path, 'operation_input'), *inputs])
    return {'operation_id': operation_id, 'step': event['seq']}


def record_call(case, args, result):
    folder = case_dir(case)
    if not (folder / "session.json").is_file():
        raise ValueError("先 wp_init；拒绝把调用混入未初始化的题目")
    from ctf_wp_assets import collect
    # collect() historically copied scripts after execution. Only the protected
    # operation_started snapshot may now be described as the executed input.
    assets, capture_errors = collect(folder, {k: v for k, v in args.items()
                                            if k not in ('local_file', 'script_file')}, result)
    with locked(folder):
        rows = verify(folder)
        operation_id = (result.get('wp_operation') or {}).get('operation_id')
        started = next((e for e in reversed(rows) if e['kind'] == 'operation_started'
                        and e['data'].get('operation_id') == operation_id), None) if operation_id else None
        if started:
            capture_errors.extend(started['data'].get('capture_errors', []))
            assets = [*started.get('files', [])[1:], *assets]
            for item in started['data'].get('input_snapshots', []):
                try:
                    original = _plain_file(item['original_path'])
                    if digest(original) != item['sha256']:
                        raise ValueError('原输入在工具执行后已发生变化；执行前快照仍保留')
                except (OSError, ValueError) as exc:
                    capture_errors.append({'kind': item['kind'], 'field': item['field'],
                        'error': str(exc), 'phase': 'post_execution_compare', 'action_replayed': False})
        elif any(isinstance(args.get(field), str) and Path(args[field]).suffix.lower()
                 in {'.py', '.sage', '.sh', '.ps1', '.js', '.c', '.cpp'}
                 for field in ('local_file', 'script_file')) or args.get('request_file'):
            capture_errors.append({'kind': 'input_snapshot', 'error': '缺少执行前记录；未把执行后文件冒充输入快照',
                                   'action_replayed': False})
        seq = len(rows) + 1
        path = folder / "raw" / ("%04d-call.json" % seq)
        # Full local evidence, including commands. Never publish this directory.
        write_json(path, {"arguments": args, "response": result})
        event = append(folder, "call", {"tool": result.get("tool"), "ok": result.get("ok"),
                       'operation_id': operation_id,
                       'purpose': str(args.get('wp_purpose') or ''), 'expectation': str(args.get('wp_expectation') or ''),
                       'capture_errors': capture_errors,
                       "source_evidence": result.get("evidence_path"),
                       "duration_ms": result.get("duration_ms")}, [file_record(folder, path, "tool_output"), *assets])
    return {"case": case, "step": event["seq"], "path": str(path), 'assets': len(assets),
            'operation_id': event['data'].get('operation_id'), 'capture_errors': capture_errors}


def note(a):
    folder = case_dir(a["case"])
    if not exists(a["case"]):
        raise ValueError("先 wp_init")
    status = a.get("status", "hypothesis")
    if status not in ("observed", "hypothesis", "todo"):
        raise ValueError("status 只能为 observed/hypothesis/todo")
    text = str(a.get("text") or "").strip()
    if not text:
        raise ValueError("text 不能为空")
    with locked(folder):
        rows = verify(folder)
        step = a.get("source_step")
        if step is not None and (type(step) is not int or not 1 <= step <= len(rows)):
            raise ValueError("source_step 不存在")
        if status == "observed" and (step is None or rows[step-1]["kind"] not in ("call", "capture")):
            raise ValueError("观察必须引用实际调用或截图的 source_step")
        event = append(folder, "note", {"text": text, "status": status, "source_step": step})
    return {"step": event["seq"], "case": a["case"], "status": status}


def capture(a):
    try:
        return _capture(a)
    except Exception as exc:
        # An unsuccessful screen capture is itself a recordable gap. Preserve
        # the original exception and never rerun the tool that needed evidence.
        try:
            if exists(a["case"]):
                folder = case_dir(a["case"])
                with locked(folder):
                    append(folder, "capture_failed", {"mode": a.get("mode", "kali_vm"),
                        "error": str(exc), "caption": str(a.get("caption") or ""),
                        "action_replayed": False})
        except Exception as recording_exc:
            if hasattr(exc, "add_note"):
                exc.add_note("截图失败记录未写入：" + str(recording_exc))
        raise


def _capture(a):
    folder = case_dir(a["case"])
    if not exists(a["case"]):
        raise ValueError("先 wp_init")
    with locked(folder):
        seq = len(verify(folder)) + 1
        path = folder / "images" / ("%04d.png" % seq)
        path.parent.mkdir(exist_ok=True)
        mode = a.get("mode", "kali_vm")
        if mode == "kali_vm":
            import ctf_os_runtime as runtime
            bridge = Path(runtime.settings().get("kali_bridge") or "")
            config = bridge.parent / "config" / "kali.json"
            if not config.is_file():
                raise ValueError("Kali 桥未配置，不能截图")
            cfg = json.loads(config.read_text(encoding="utf-8-sig"))
            proc = subprocess.run([cfg["vmrun"], "-T", "ws", "captureScreen", cfg["vmx"], str(path)],
                                  capture_output=True, timeout=30,
                                  creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            if proc.returncode:
                # Some VMware versions require a guest password for VIX screen
                # capture. Reuse the pinned SSH bridge, not password arguments
                # or weakened X11 authentication. A logged-in desktop can use
                # its own Xauthority; the login screen requires existing sudo.
                filename = "wp-screen-%04d-%s.png" % (seq, uuid.uuid4().hex[:8])
                code = GUEST_SCREEN.replace("__FILENAME__", filename)
                result = runtime.kali_execute({"case": a["case"], "timeout": 40}, ["python3", "-c", code])
                if runtime.failed(result):
                    raise RuntimeError("实际桌面截图失败；读取 Kali 桥错误：" + str(result.get("stderr") or result.get("error") or result))
                downloaded = runtime.bridge_call(["fetch", a["case"], "results/" + filename], timeout=90)
                if runtime.failed(downloaded) or downloaded.get("verified") is not True:
                    raise RuntimeError("截图回收 SHA256 校验失败")
                shutil.copyfile(downloaded["local_path"], path)
                capture_info = json.loads(result["stdout"])
                source = "固定 SSH 身份的 Kali 桥 → xfce4-screenshooter 实际 X11 画面（%s）→ SHA256 回收校验" % capture_info["display"]
            else:
                source = "vmrun captureScreen：配置中的 Kali 虚拟机实际画面"
            image_kind = "vm_screenshot"
        elif mode == 'windows_window':
            from ctf_wp_windows import capture_window
            info = capture_window(path, process_id=a.get('process_id'))
            source = info['source']
            image_kind = 'windows_screenshot'
        elif mode == "file":
            source_file = Path(a["file_path"]).resolve(strict=True)
            if source_file.suffix.lower() != ".png":
                raise ValueError("导入图片目前只支持 PNG")
            if not a.get("source"):
                raise ValueError("导入图片必须描述 source；系统不推断其内容真实性")
            shutil.copyfile(source_file, path)
            source = str(a["source"])
            image_kind = "imported_image"
        else:
            raise ValueError("mode 只能为 kali_vm、windows_window 或 file")
        if not path.is_file() or path.read_bytes()[:8] != b"\x89PNG\r\n\x1a\n":
            raise ValueError("截图未生成有效 PNG")
        event = append(folder, "capture", {"source": source, "image_kind": image_kind,
                       "caption": str(a.get("caption") or "关键画面")}, [file_record(folder, path, image_kind)])
    return {"case": a["case"], "step": event["seq"], "path": str(path), "kind": image_kind}


GUEST_SCREEN = r'''import json, os, pathlib, subprocess, tempfile
name = '__FILENAME__'
target = pathlib.Path(os.environ['CTF_RESULTS_DIR']) / name
program = '/usr/bin/xfce4-screenshooter'
if not pathlib.Path(program).is_file():
    raise RuntimeError('xfce4-screenshooter is not installed; install it in the guest or import a real screenshot')
display = None
auth = None
for process in pathlib.Path('/proc').iterdir():
    if not process.name.isdigit():
        continue
    try:
        args = (process/'cmdline').read_bytes().decode().strip('\0').split('\0')
        if not args or pathlib.Path(args[0]).name != 'Xorg':
            continue
        display = next((x for x in args if __import__('re').fullmatch(r':\d+', x)), None)
        if '-auth' in args:
            auth = args[args.index('-auth')+1]
        if display:
            break
    except (OSError, ValueError, IndexError):
        continue
if not display:
    raise RuntimeError('No active Xorg desktop; a pure SSH log is not a screenshot')
env = dict(os.environ, DISPLAY=display, XAUTHORITY=str(pathlib.Path.home()/'.Xauthority'))
proc = subprocess.run([program,'--fullscreen','--save',str(target)], env=env, capture_output=True, timeout=20)
method = 'desktop-user'
if proc.returncode:
    if not auth:
        raise RuntimeError(proc.stderr.decode(errors='replace') or proc.stdout.decode(errors='replace'))
    sudo = subprocess.run(['sudo','-n','true'], capture_output=True)
    if sudo.returncode:
        raise RuntimeError('Desktop login required or no existing sudo access; refusing to disable X11 authentication')
    proc = subprocess.run(['sudo','-n','env','DISPLAY='+display,'XAUTHORITY='+auth,program,'--fullscreen','--save',str(target)], capture_output=True, timeout=20)
    if proc.returncode:
        raise RuntimeError(proc.stderr.decode(errors='replace') or proc.stdout.decode(errors='replace'))
    subprocess.run(['sudo','-n','chown',str(os.getuid())+':'+str(os.getgid()),str(target)], check=True)
    method = 'existing-sudo-with-server-xauthority'
if not target.is_file() or target.read_bytes()[:8] != b'\x89PNG\r\n\x1a\n':
    raise RuntimeError('Capture did not produce a PNG')
target.chmod(0o600)
print(json.dumps({'display':display,'method':method,'file':str(target)}))
'''


def scrub(text):
    """Best-effort textual redaction; image pixels require separate review."""
    text = str(text)
    text = re.sub(r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----", "[私钥已遮盖]", text, flags=re.S)
    text = re.sub(r"(?i)\b(?:flag|ctf|gwht|qwb|pwn\.college)\{[^}\n]*\}", "[FLAG 已遮盖]", text)
    text = re.sub(r"(?i)\b(sk-|gh[pousr]_|github_pat_)[A-Za-z0-9_-]{12,}", "[凭据已遮盖]", text)
    text = re.sub(r"(?i)(Bearer\s+)[A-Za-z0-9_.=-]+", r"\1[已遮盖]", text)
    text = re.sub(r'''(?i)(["']?(?:password|passwd|token|api[_-]?key|authorization|cookie|secret|submission_flag)["']?\s*[:=]\s*)(["'][^"'\n]*["']|[^\s,}\n]+)''', r'\1"[已遮盖]"', text)
    return text


def fence(text, keep_flags=False):
    if not keep_flags: text = scrub(text)
    marker = "`" * max(3, 1 + max([len(x) for x in re.findall(r"`+", text)] or [0]))
    return marker + "text\n" + text + "\n" + marker


def render_log(text, path):
    try:
        from PIL import Image, ImageDraw, ImageFont
    except ImportError:
        return False
    fonts = [Path(os.environ.get("WINDIR", "")) / "Fonts" / "msyh.ttc",
             Path("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf")]
    font_path = next((p for p in fonts if p.is_file()), None)
    font = ImageFont.truetype(str(font_path), 16) if font_path else ImageFont.load_default()
    lines = ["LOG RENDER — NOT A SCREENSHOT", "真实工具日志渲染图；不是电脑屏幕截图", ""]
    for line in scrub(text).splitlines():
        lines.extend(textwrap.wrap(line, 95, replace_whitespace=False) or [""])
    if len(lines) > 120:
        lines = lines[:120] + ["... image truncated; read the Markdown and raw evidence"]
    image = Image.new("RGB", (1200, 40 + len(lines) * 25), "#111827")
    ImageDraw.Draw(image).multiline_text((20, 15), "\n".join(lines), font=font, fill="#e5e7eb", spacing=7)
    image.save(path, "PNG")
    return True


def build(a):
    from ctf_wp_export import build as export
    return export(a)


def review(a):
    from ctf_wp_review import analyze
    folder = case_dir(a["case"])
    if not exists(a["case"]):
        raise ValueError("WP 尚未初始化")
    with locked(folder):
        return dict(analyze(folder, verify(folder)), case=a["case"])


def status(a):
    folder = case_dir(a["case"])
    with locked(folder):
        rows = verify(folder)
        if not exists(a["case"]):
            raise ValueError("WP 尚未初始化")
    completed = {e['data'].get('operation_id') for e in rows if e['kind'] == 'call'}
    pending = [e['data'] for e in rows if e['kind'] == 'operation_started' and e['data']['operation_id'] not in completed]
    from ctf_wp_review import analyze
    quality = analyze(folder, rows)
    return {"case": a["case"], "records": len(rows), "integrity_verified": True,
            "calls": sum(e["kind"] == "call" for e in rows),
            "captures": sum(e["kind"] == "capture" for e in rows), 'pending_operations': pending,
            'recorded_assets': sum(max(0, len(e.get('files', []))-1) for e in rows if e['kind']=='call'),
            'capture_errors': quality['capture_errors'], 'review': quality,
            'submission_ready': quality['submission_ready'], "solved_verified": False}


CASE = {"case": {"type": "string", "description": "独立题号，1–64 位英文/数字/下划线/连字符"}}


def schema(extra=None, required=None):
    return {"type": "object", "properties": dict(CASE, **(extra or {})), "required": ["case"] + (required or [])}


TOOLS = {
    "wp_init": (init, "初始化一题的私有 WP 记录；后续调用加 wp_case 自动记录", schema({
        "title": {"type": "string"}, "category": {"type": "string"}, "competition": {"type": "string"}})),
    "wp_note": (note, "补充观察/假设/待办；观察必须引用真实证据步骤", schema({
        "text": {"type": "string"}, "status": {"type": "string", "enum": ["observed", "hypothesis", "todo"]},
        "source_step": {"type": "integer"}}, ["text"])),
    "wp_intake": (intake, "追加题面、来源和原始附件；最多 32 个、每个 512 MiB、合计 10 GiB；不执行附件", schema({
        "description": {"type": "string"}, "source": {},
        "attachments": {"type": "array", "maxItems": 32, "items": {"oneOf": [
            {"type": "string"}, {"type": "object", "properties": {
                "path": {"type": "string"}, "name": {"type": "string"}, "sha256": {"type": "string"}},
                "required": ["path"]}]}}})),
    "wp_section": (section, "追加有来源的 WP 章节；同章节最新版生效，文字不能代替真实验证回执", schema({
        "section": {"type": "string", "enum": ["overview", "analysis", "solution", "validation", "reproduction"]},
        "text": {"type": "string"}, "source_steps": {"type": "array", "items": {"type": "integer"}}},
        ["section", "text"])),
    "wp_review": (review, "只读检查 WP 的题面、目的、结论、章节及采集缺项；普通草稿缺项不作为工具失败", schema()),
    "wp_capture": (capture, "采集 Kali VM 或指定 Windows 进程的实际截图，或导入客户端 PNG；不生成假截图", schema({
        "mode": {"type": "string", "enum": ["kali_vm", "windows_window", "file"]}, "file_path": {"type": "string"},
        'process_id': {'type': 'integer'},
        "source": {"type": "string"}, "caption": {"type": "string"}})),
    "wp_build": (build, "验证证据并生成中文 WP，默认不导出截图；不判定解题成功", schema({
        "include_images": {"type": "boolean", "default": False}, 'summary': {'type':'string'},
        'include_log_renders': {'type':'boolean','default':True},
        'formats': {'type':'array','items':{'type':'string','enum':['docx','pdf']},'description':'默认 Word/PDF；[] 只导出 Markdown/HTML'},
        'bundle': {'type':'boolean', 'default':True}, 'private_bundle':{'type':'boolean','default':False},
        'expose_flag': {'type':'boolean', 'default':False}})),
    "wp_status": (status, "验证 WP 时间线及文件摘要并查看采集数量", schema()),
}
