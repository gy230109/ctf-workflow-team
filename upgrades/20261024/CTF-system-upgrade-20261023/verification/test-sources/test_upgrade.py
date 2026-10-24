"""Exercise installation and rollback using disposable filesystem installations."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import upgrade


class UpgradeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.target = self.base/'安装 目录'
        self.package = self.base/'package'
        (self.target/'tools').mkdir(parents=True)
        (self.target/'tools/ctf_entry.py').write_bytes(b'original entry')
        (self.target/'tools/component.py').write_bytes(b'original component')
        (self.target/'.local/ctf-system/tasks/ctf-0123456789abcdef').mkdir(parents=True)
        self.task = self.target/'.local/ctf-system/tasks/ctf-0123456789abcdef/task.json'
        self.task.write_bytes(b'original task evidence')
        self.profile = self.base/'profile/cordis.patch.yml'
        self.profile.parent.mkdir()
        self.original_profile = ('# 用户原配置\r\n- insert:\r\n    - id: mcp-ctf-system\r\n'
                                 '      config:\r\n        serverName: ctf_system\r\n'
                                 f'        args: [{json.dumps(str(self.target/"tools/ctf_entry.py"),ensure_ascii=False)}]\r\n').encode('utf-8')
        self.profile.write_bytes(self.original_profile)
        entries = []
        for name, content in [('tools/component.py', b'new component'), ('tools/new_module.py', b'new module')]:
            path = self.package/'payload'/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
            entries.append({'path': name, 'sha256': upgrade.digest(content),
                            'previous_sha256': upgrade.hash_or_none(upgrade.current(self.target/name))})
        (self.package/'upgrade-manifest.json').write_text(json.dumps({'files': entries}), encoding='utf-8')

    def tearDown(self):
        self.temp.cleanup()

    def install(self, **kwargs):
        return upgrade.install(self.target, self.profile, package=self.package,
                               verifier=kwargs.pop('verifier', lambda _: {'ok': True}), **kwargs)

    def test_plan_writes_nothing(self):
        self.assertFalse(self.install()['applied'])
        self.assertEqual(self.profile.read_bytes(), self.original_profile)
        self.assertFalse((self.target/'.local/ctf-upgrades').exists())

    def test_install_repeat_and_rollback_preserve_task_and_profile(self):
        result = self.install(apply=True)
        self.assertTrue(result['applied'])
        self.assertTrue(self.profile.read_bytes().startswith(self.original_profile))
        self.assertTrue(self.install(apply=True)['unchanged'])
        self.assertEqual(self.task.read_bytes(), b'original task evidence')
        upgrade.restore(Path(result['journal']), apply=True)
        self.assertEqual(self.profile.read_bytes(), self.original_profile)
        self.assertEqual((self.target/'tools/component.py').read_bytes(), b'original component')
        self.assertFalse((self.target/'tools/new_module.py').exists())
        self.assertEqual(self.task.read_bytes(), b'original task evidence')

    def test_changed_baseline_stops_before_any_install_write(self):
        (self.target/'tools/component.py').write_bytes(b'another upgrade')
        with self.assertRaisesRegex(ValueError, 'baseline'):
            self.install(apply=True)
        self.assertEqual(self.profile.read_bytes(), self.original_profile)
        self.assertFalse((self.target/'tools/new_module.py').exists())

    def test_package_checksum_failure_stops_before_any_install_write(self):
        (self.package/'payload/tools/new_module.py').write_bytes(b'corrupted')
        with self.assertRaisesRegex(ValueError, 'checksum'):
            self.install(apply=True)
        self.assertEqual((self.target/'tools/component.py').read_bytes(), b'original component')

    def test_runtime_verification_failure_rolls_everything_back(self):
        def fail(_):
            raise RuntimeError('broken runtime')
        with self.assertRaisesRegex(RuntimeError, 'was rolled back'):
            self.install(apply=True, verifier=fail)
        self.assertEqual(self.profile.read_bytes(), self.original_profile)
        self.assertEqual((self.target/'tools/component.py').read_bytes(), b'original component')
        self.assertFalse((self.target/'tools/new_module.py').exists())

    def test_partial_write_failure_restores_already_changed_files(self):
        original_write = upgrade.atomic_write
        def write(path, data):
            if path == self.target/'tools/new_module.py' and data == b'new module':
                raise OSError('fixture disk failure')
            return original_write(path, data)
        with patch.object(upgrade, 'atomic_write', side_effect=write):
            with self.assertRaisesRegex(RuntimeError, 'was rolled back'):
                self.install(apply=True)
        self.assertEqual((self.target/'tools/component.py').read_bytes(), b'original component')
        self.assertEqual(self.profile.read_bytes(), self.original_profile)

    def test_concurrent_installer_is_rejected(self):
        with upgrade.installation_lock(self.target):
            with self.assertRaisesRegex(ValueError, 'in progress'):
                self.install(apply=True)
        self.assertEqual(self.profile.read_bytes(), self.original_profile)

    def test_rollback_refuses_to_overwrite_later_edits(self):
        result = self.install(apply=True)
        changed = self.target/'tools/component.py'
        changed.write_bytes(b'new user edit')
        before = self.profile.read_bytes()
        with self.assertRaisesRegex(ValueError, 'later edit'):
            upgrade.restore(Path(result['journal']), apply=True)
        self.assertEqual(changed.read_bytes(), b'new user edit')
        self.assertEqual(self.profile.read_bytes(), before)

    def test_running_task_stops_upgrade(self):
        self.task.with_name('operation.lock').write_text('123')
        with self.assertRaisesRegex(ValueError, 'running'):
            self.install(apply=True)
        self.assertEqual(self.profile.read_bytes(), self.original_profile)

    def test_profile_must_point_to_selected_system(self):
        self.profile.write_text('serverName: ctf_system\nargs: [another-installation]', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'another CTF root'):
            self.install(apply=True)

    def test_invalid_manifest_paths_are_rejected(self):
        manifest = upgrade.read(self.package/'upgrade-manifest.json')
        manifest['files'][0]['path'] = '../outside.py'
        (self.package/'upgrade-manifest.json').write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, 'Invalid relative path'):
            self.install(apply=True)

    def test_managed_policy_changes_do_not_rewrite_other_profile_content(self):
        first = upgrade.profile_update(self.original_profile, self.target, sys.executable, 'after_ctf_intake')
        second = upgrade.profile_update(first, self.target, sys.executable, 'always')
        self.assertTrue(second.startswith(self.original_profile))
        self.assertEqual(second.count(upgrade.BEGIN.encode()), 1)
        self.assertIn(b'mode: always', second)
        self.assertEqual(upgrade.profile_update(second, self.target, sys.executable, 'always'), second)


if __name__ == '__main__':
    unittest.main()
