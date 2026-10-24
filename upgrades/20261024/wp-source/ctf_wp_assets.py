"""Attach verified per-call artifacts; capture failure never replays the action."""
import hashlib
from pathlib import Path
import shutil
import uuid

KINDS = {'browser_screenshot', 'browser_trace', 'terminal_recording', 'windows_screenshot', 'script_snapshot','data_export'}


def collect(folder, args, result):
    import ctf_wp as wp
    payload = result.get('result') or {}
    items = list(payload.get('evidence_artifacts') or []) if isinstance(payload, dict) else []
    errors = list(payload.get('capture_errors') or []) if isinstance(payload, dict) else []
    if result.get('tool') == 'win_debug_call':
        try:
            import ctf_x64dbg
            from ctf_wp_windows import capture_window
            cfg = ctf_x64dbg.settings(args)
            image = folder / 'images' / ('debug-' + uuid.uuid4().hex + '.png')
            image.parent.mkdir(exist_ok=True)
            info = capture_window(image, executable=str(cfg['executable']))
            items.append({'path': str(image), 'sha256': wp.digest(image), 'kind': 'windows_screenshot', 'source': info['source']})
        except Exception as exc:
            errors.append({'kind': 'windows_screenshot', 'error': str(exc), 'action_replayed': False})
    for field in ('local_file', 'script_file'):
        value = args.get(field)
        if isinstance(value, str):
            path = Path(value)
            if path.suffix.lower() in {'.py', '.sage', '.sh', '.ps1', '.js', '.c', '.cpp'} and path.is_file() and path.stat().st_size <= 1048576:
                items.append({'path': str(path), 'sha256': wp.digest(path), 'kind': 'script_snapshot',
                              'source': 'Input script supplied to this tool; original filename: ' + path.name})
    files = []
    for item in items[:12]:
        try:
            kind = item['kind']
            if kind not in KINDS:
                raise ValueError('Unknown evidence kind')
            path = Path(item['path'])
            if path.is_symlink() or not path.is_file() or path.stat().st_size > 67108864:
                raise ValueError('Artifact missing, linked, or larger than 64 MiB')
            if wp.digest(path) != item['sha256']:
                raise ValueError('Artifact SHA256 mismatch')
            if kind.endswith('screenshot') and path.read_bytes()[:8] != b'\x89PNG\r\n\x1a\n':
                raise ValueError('Screenshot is not PNG')
            target = folder / 'assets' / (uuid.uuid4().hex + path.suffix.lower())
            target.parent.mkdir(exist_ok=True)
            shutil.copyfile(path, target)
            if wp.digest(target) != item['sha256']:
                raise ValueError('Artifact changed while copying')
            files.append(dict(wp.file_record(folder, target, kind), source=str(item.get('source') or ''),
                              original_name=path.name))
        except Exception as exc:
            errors.append({'kind': item.get('kind'), 'error': str(exc), 'action_replayed': False})
    if len(items) > 12:
        errors.append({'error': 'Per-call artifact count exceeds 12; extra artifacts omitted'})
    return files, errors
