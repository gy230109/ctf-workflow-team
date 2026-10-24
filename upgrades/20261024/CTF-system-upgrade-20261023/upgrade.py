"""Install a checksummed CTF patch, with a journal and guarded rollback.

Run without --apply to inspect the plan. This script grants no OS permissions.
"""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import subprocess
import sys

PACKAGE = Path(__file__).resolve().parent
BEGIN = '# BEGIN CTF_SYSTEM_SHARED_PROTOCOL_V1'
END = '# END CTF_SYSTEM_SHARED_PROTOCOL_V1'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def current(path):
    return path.read_bytes() if path.exists() else None


def hash_or_none(data):
    return digest(data) if data is not None else None


def inside(root, relative):
    rel = PurePosixPath(relative)
    if rel.is_absolute() or not rel.parts or any(p in {'..', '.'} or ':' in p or '\\' in p for p in rel.parts):
        raise ValueError('Invalid relative path in manifest: ' + relative)
    target = root.joinpath(*rel.parts)
    if not target.resolve().is_relative_to(root.resolve()):
        raise ValueError('Path escapes the selected installation: ' + relative)
    return target


def atomic_write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.ctf-' + secrets.token_hex(6) + '.tmp')
    try:
        temporary.write_bytes(data)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def save(path, value):
    atomic_write(path, (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode('utf-8'))


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


@contextmanager
def installation_lock(root):
    path = inside(root, '.local/ctf-upgrade.lock')
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        raise ValueError('Another upgrade or rollback is in progress; inspect its journal first.')
    try:
        with os.fdopen(descriptor, 'w') as stream:
            stream.write(str(os.getpid()))
        yield
    finally:
        path.unlink(missing_ok=True)


def harness_block(root, python, mode):
    """Append a normal loader patch; keep every existing byte outside our block."""
    quote = lambda value: json.dumps(str(value), ensure_ascii=False)
    module = (root/'integrations/deepseek-harness/ctf-route-guard.mjs').as_uri()
    return ('\n' + BEGIN + '\n- insert:\n'
            '    - id: ctf-system-shared-workflow\n'
            f'      name: {quote(module)}\n'
            '      config:\n'
            f'        mode: {mode}\n' + END + '\n')


def profile_update(original, root, python, mode):
    text = (original or b'').decode('utf-8-sig')
    # Existing MCP registration must already point at this system. The upgrade
    # never creates a second server or guesses how a different profile is wired.
    if not re.search(r'(?m)^\s*serverName:\s*[\'"]?ctf[_-]system[\'"]?\s*$', text):
        raise ValueError('Selected Harness profile has no CTF MCP connection; install the existing CTF connection first.')
    normalize = lambda value: re.sub(r'/+', '/', str(value).replace('\\', '/')).casefold()
    if normalize(root/'tools/ctf_entry.py') not in normalize(text):
        raise ValueError('Selected Harness profile points at another CTF root; its MCP connection was not changed.')
    if text.count(BEGIN) != text.count(END) or text.count(BEGIN) > 1:
        raise ValueError('Malformed managed Harness block; repair it before upgrading.')
    block = harness_block(root, python, mode)
    encoded = block.encode('utf-8')
    if BEGIN.encode() in (original or b''):
        pattern = re.compile(re.escape(BEGIN.encode()) + rb'.*?' + re.escape(END.encode()) + rb'(?:\r?\n)?', re.S)
        return pattern.sub(lambda _: encoded.lstrip(b'\n'), original, count=1)
    return (original or b'') + encoded


def make_plan(root, profile=None, mode='after_ctf_intake', package=PACKAGE):
    root = root.resolve(strict=True)
    if not (root/'tools/ctf_entry.py').is_file():
        raise ValueError('Target is not an existing CTF installation.')
    manifest = read(package/'upgrade-manifest.json')
    plans = []
    for entry in manifest['files']:
        path = inside(root, entry['path'])
        source = inside(package/'payload', entry['path'])
        data = source.read_bytes()
        if digest(data) != entry['sha256']:
            raise ValueError('Package checksum mismatch: ' + entry['path'])
        old = current(path)
        actual = hash_or_none(old)
        if actual not in {entry['previous_sha256'], entry['sha256']}:
            raise ValueError('Installed file differs from the supported baseline: ' + entry['path'])
        if old != data:
            plans.append({'path': path, 'data': data, 'old': old, 'label': entry['path']})
    if profile is not None:
        profile = profile.resolve(strict=True)
        if profile.name != 'cordis.patch.yml':
            raise ValueError('Select the explicit Harness cordis.patch.yml file.')
        if profile.is_relative_to(root):
            raise ValueError('Harness profile must be separate from the system installation.')
        original = profile.read_bytes()
        updated = profile_update(original, root, sys.executable, mode)
        if updated != original:
            plans.append({'path': profile, 'data': updated, 'old': original, 'label': 'Harness route policy'})
    return plans


def verify(root):
    request = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
               'params': {'name': 'ctf_system_status', 'arguments': {}}}
    result = subprocess.run([sys.executable, '-X', 'utf8', '-B', str(root/'tools/ctf_entry.py'),
                             '--stdio', '--root', str(root)],
                            input=json.dumps(request) + '\n', capture_output=True,
                            text=True, encoding='utf-8', cwd=root, timeout=90,
                            env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
    if result.returncode:
        raise RuntimeError('Runtime verification failed: ' + result.stderr[-1000:])
    receipt = json.loads(result.stdout)['result']['structuredContent']
    if receipt.get('ok') is not True or receipt.get('contract', {}).get('version') != 'ctf-system/1.1':
        raise RuntimeError('Runtime did not report the new shared protocol.')
    if receipt['contract'].get('workflow_owner') != 'CTF_system' or len(receipt['contract']['operations']) != 8:
        raise RuntimeError('Runtime returned an unexpected public interface.')
    return {'ok': True, 'registered_tools': receipt['registered_tools'],
            'contract': receipt['contract'], 'model_inference_verified': False}


def _restore(journal_path, apply=False):
    journal_path = journal_path.resolve(strict=True)
    journal = read(journal_path)
    root = Path(journal['target']).resolve(strict=True)
    backup = journal_path.parent
    if backup.parent != root/'.local/ctf-upgrades':
        raise ValueError('Journal must be inside the selected installation upgrade directory.')
    plans = []
    for entry in reversed(journal['files']):
        path = Path(entry['path'])
        if path != Path(journal.get('harness_profile') or '') and not path.resolve().is_relative_to(root):
            raise ValueError('Unexpected path in rollback journal.')
        actual = hash_or_none(current(path))
        if actual == entry['previous_sha256']:
            continue
        if actual != entry['installed_sha256']:
            raise ValueError('Rollback would overwrite a later edit: ' + str(path))
        old = None
        if entry['backup'] is not None:
            old = inside(backup, entry['backup']).read_bytes()
            if digest(old) != entry['previous_sha256']:
                raise ValueError('Backup checksum mismatch: ' + str(path))
        plans.append((path, old))
    if apply:
        for path, old in plans:
            if old is None:
                path.unlink(missing_ok=True)
            else:
                atomic_write(path, old)
        journal['state'] = 'rolled_back'
        save(journal_path, journal)
    return {'action': 'rollback', 'applied': apply, 'files': [str(p) for p, _ in plans]}


def restore(journal_path, apply=False):
    if not apply:
        return _restore(journal_path)
    root = Path(read(journal_path)['target']).resolve(strict=True)
    with installation_lock(root):
        return _restore(journal_path, apply=True)


def _install(root, profile=None, mode='after_ctf_intake', apply=False, package=PACKAGE, verifier=verify):
    root = root.resolve(strict=True)
    plans = make_plan(root, profile, mode, package)
    result = {'action': 'install', 'applied': False, 'target': str(root),
              'files': [str(p['path']) for p in plans], 'route_mode': mode,
              'harness_profile': str(profile) if profile else None}
    if not apply:
        return result
    if list((root/'.local/ctf-system/tasks').glob('ctf-*/operation.lock')):
        raise ValueError('A task operation is running; close the AI client and finish that operation first.')
    if not plans:
        result.update(applied=True, unchanged=True, verification=verifier(root))
        return result
    backup = inside(root, '.local/ctf-upgrades/' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ-') + secrets.token_hex(4))
    backup.mkdir(parents=True, exist_ok=False)
    journal = {'target': str(root), 'harness_profile': str(profile.resolve()) if profile else None,
               'state': 'prepared', 'files': []}
    for i, item in enumerate(plans):
        old = item['old']
        name = f'originals/{i:03}.bin' if old is not None else None
        if name:
            atomic_write(backup/name, old)
        journal['files'].append({'path': str(item['path']), 'backup': name,
                                 'previous_sha256': hash_or_none(old),
                                 'installed_sha256': digest(item['data'])})
    journal_path = backup/'journal.json'
    save(journal_path, journal)
    try:
        for item in plans:
            if current(item['path']) != item['old']:
                raise RuntimeError('File changed during upgrade: ' + str(item['path']))
            atomic_write(item['path'], item['data'])
        result['verification'] = verifier(root)
        journal['state'] = 'installed'
        save(journal_path, journal)
    except Exception as exc:
        try:
            _restore(journal_path, apply=True)
        except Exception as rollback_error:
            raise RuntimeError(f'Upgrade failed ({exc}); rollback needs review ({rollback_error}); journal: {journal_path}') from exc
        raise RuntimeError(f'Upgrade failed and was rolled back: {exc}; journal: {journal_path}') from exc
    result.update(applied=True, journal=str(journal_path),
                  next='Restart the AI client and call ctf_system_status. No live model call was made by this installer.')
    return result


def install(root, profile=None, mode='after_ctf_intake', apply=False, package=PACKAGE, verifier=verify):
    root = root.resolve(strict=True)
    if not apply:
        return _install(root, profile, mode, False, package, verifier)
    with installation_lock(root):
        return _install(root, profile, mode, True, package, verifier)


def main():
    if sys.version_info < (3, 11):
        raise SystemExit('Python 3.11 or newer is required.')
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    setup = commands.add_parser('install')
    setup.add_argument('--target', type=Path, default=Path('D:/强网杯大师'))
    setup.add_argument('--harness-profile', type=Path)
    setup.add_argument('--route-mode', choices=['after_ctf_intake', 'always'], default='after_ctf_intake')
    setup.add_argument('--apply', action='store_true')
    undo = commands.add_parser('rollback')
    undo.add_argument('--journal', type=Path, required=True)
    undo.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    try:
        if args.command == 'install':
            value = install(args.target, args.harness_profile, args.route_mode, args.apply)
        else:
            value = restore(args.journal, args.apply)
    except Exception as exc:
        print(json.dumps({'ok': False, 'error': str(exc)}, ensure_ascii=False))
        return 1
    print(json.dumps(dict(ok=True, **value), ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
