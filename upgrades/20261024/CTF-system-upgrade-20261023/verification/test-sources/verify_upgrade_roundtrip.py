"""Install the built patch into a disposable copy of the real baseline, then undo."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from build_upgrade import prepare, PAYLOAD
from upgrade import install, restore

BASELINE = Path('D:/强网杯大师')
PROFILE = Path.home()/'.dsh/profiles/desktop/cordis.patch.yml'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


def main():
    checks = []
    def check(name, condition):
        checks.append({'name': name, 'passed': bool(condition)})
        if not condition:
            raise AssertionError(name)

    package = prepare()
    originals = {name: sha(BASELINE/name) for name in PAYLOAD}
    original_profile = sha(PROFILE)
    # This is a read-only plan against the actual destination and actual profile.
    plan = install(BASELINE, PROFILE, package=package)
    check('real_installation_baseline_matches', not plan['applied'] and len(plan['files']) >= 7)
    (ROOT/'.build').mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='upgrade-roundtrip-', dir=ROOT/'.build') as temporary:
        target = Path(temporary)/'CTF 安装 目录'
        shutil.copytree(BASELINE/'tools', target/'tools', ignore=shutil.ignore_patterns('__pycache__'))
        sentinel = target/'.local/ctf-system/tasks/ctf-0123456789abcdef/task.json'
        sentinel.parent.mkdir(parents=True)
        sentinel.write_text('{"fixture":"preserve this task"}', encoding='utf-8')
        task_sha = sha(sentinel)
        profile = Path(temporary)/'harness/cordis.patch.yml'
        profile.parent.mkdir()
        initial_profile = ('# Fixture connected profile\r\n- insert:\r\n    - id: mcp-ctf-system\r\n'
                           '      config:\r\n        serverName: ctf_system\r\n'
                           f'        args: [{json.dumps((target/"tools/ctf_entry.py").as_posix(),ensure_ascii=False)}]\r\n').encode('utf-8')
        profile.write_bytes(initial_profile)
        before = {name: sha(target/name) for name in PAYLOAD}
        installed = install(target, profile, apply=True, package=package)
        check('real_entry_loads_after_upgrade', installed['verification']['ok'])
        check('real_109_tools_after_upgrade', installed['verification']['registered_tools'] == 109)
        check('new_protocol_after_upgrade', installed['verification']['contract']['version'] == 'ctf-system/1.1')
        check('task_bytes_preserved_during_upgrade', sha(sentinel) == task_sha)
        check('profile_original_bytes_preserved', profile.read_bytes().startswith(initial_profile))
        harness = subprocess.run(['D:/noje/node.exe', str(ROOT/'tests/verify_harness_patch.mjs'),
                                  str(profile), str(PROFILE), str(ROOT/'harness-patch-verification.json')],
                                 capture_output=True, text=True, encoding='utf-8', timeout=30)
        if harness.returncode:
            raise RuntimeError(harness.stderr)
        check('installed_Harness_plugin_loads_from_generated_patch', json.loads(harness.stdout)['passed'])
        repeated = install(target, profile, apply=True, package=package)
        check('repeat_install_does_not_duplicate_policy', repeated.get('unchanged') is True)
        undone = restore(Path(installed['journal']), apply=True)
        check('rollback_completed', undone['applied'])
        check('all_patched_files_restored_or_removed', {name: sha(target/name) for name in PAYLOAD} == before)
        check('profile_restored_exactly', profile.read_bytes() == initial_profile)
        check('task_bytes_preserved_after_rollback', sha(sentinel) == task_sha)
    check('actual_D_installation_untouched', {name: sha(BASELINE/name) for name in PAYLOAD} == originals)
    check('actual_Harness_profile_untouched', sha(PROFILE) == original_profile)
    report = {'passed': all(c['passed'] for c in checks), 'checks': checks,
              'scope': 'Real source copy, actual installer, real MCP runtime and exact rollback; D installation and active Harness profile were read only.'}
    (ROOT/'install-roundtrip.json').write_text(json.dumps(report, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(report, ensure_ascii=False))


if __name__ == '__main__':
    main()
