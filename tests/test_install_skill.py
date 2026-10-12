"""Portable skill install/discovery without using real user directories or VMs."""
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import install_skill as installer


def module_from_file(path):
    spec = importlib.util.spec_from_file_location("skill_locator_fixture", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


locator = module_from_file(ROOT / "skills/ctf-team-workflow/scripts/locate_system.py")


class InstallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ctf-skill-test-")
        self.folder = Path(self.temp.name)
        self.repo = self.folder / "仓库 with spaces"
        self.home = self.folder / "fixture-user"
        self.repo.mkdir()
        for name in locator.REQUIRED:
            path = self.repo/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fixture", encoding="utf-8")
        shutil.copytree(ROOT / "skills", self.repo / "skills")
        self.other = self.folder / "other-project"
        self.other.mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def install(self, client="codex"):
        return installer.install(client, self.repo, self.home)

    def locate(self, **args):
        return locator.locate(home=self.home, cwd=self.other, skill_file=self.home/"outside.py", environment={}, **args)

    def test_both_clients_install_and_locate_without_deployment_claim(self):
        result = self.install("both")
        self.assertTrue(all(x["files_verified"] for x in result["installed"]))
        self.assertFalse(result["deployment_verified"])
        for client in ("codex", "claude"):
            self.assertEqual(installer.hashes(installer.target_path(self.home, client)), installer.hashes(self.repo/"skills"/installer.NAME))
        found = self.locate()
        self.assertEqual(found["repository"], str(self.repo.resolve()))
        self.assertEqual(found["root_source"], "user_location_record")
        self.assertFalse(found["deployment_verified"])
        self.assertFalse(found["host_venv_present"])

    def test_new_process_from_unrelated_directory_finds_installed_repo(self):
        self.install()
        script = installer.target_path(self.home, "codex") / "scripts/locate_system.py"
        bootstrap = "import importlib.util,json,sys; s=importlib.util.spec_from_file_location('locator',sys.argv[1]); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); print(json.dumps(m.locate(home=sys.argv[2],environment={})))"
        proc = subprocess.run([sys.executable, "-c", bootstrap, str(script), str(self.home)], cwd=self.other,
                              capture_output=True, text=True, timeout=10)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(proc.stdout)["repository"], str(self.repo.resolve()))

    def test_reinstall_and_update_owned_skill_preserve_other_skill(self):
        self.install()
        other = self.home / ".agents/skills/unrelated/SKILL.md"
        other.parent.mkdir(parents=True)
        other.write_text("do not alter", encoding="utf-8")
        self.install()
        skill = self.repo / "skills" / installer.NAME / "SKILL.md"
        skill.write_text(skill.read_text(encoding="utf-8")+"\nfixture update\n", encoding="utf-8")
        self.install()
        self.assertEqual((installer.target_path(self.home, "codex")/"SKILL.md").read_bytes(), skill.read_bytes())
        self.assertEqual(other.read_text(encoding="utf-8"), "do not alter")

    def test_changed_or_foreign_skill_not_overwritten(self):
        self.install()
        skill = installer.target_path(self.home, "codex")/"SKILL.md"
        skill.write_text("local change", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "拒绝覆盖"):
            self.install()
        self.assertEqual(skill.read_text(encoding="utf-8"), "local change")

    def test_preflight_all_targets_before_any_install(self):
        collision = installer.target_path(self.home, "claude")/"SKILL.md"
        collision.parent.mkdir(parents=True)
        collision.write_text("foreign", encoding="utf-8")
        with self.assertRaises(ValueError):
            self.install("both")
        self.assertFalse(installer.target_path(self.home, "codex").exists())

    def test_moved_repo_requires_record_update(self):
        self.install()
        moved = self.folder / "moved"
        self.repo.rename(moved)
        with self.assertRaisesRegex(ValueError, "未找到"):
            self.locate()
        installer.install("codex", moved, self.home)
        self.assertEqual(self.locate()["repository"], str(moved.resolve()))

    def test_explicit_repo_overrides_location_but_invalid_environment_fails(self):
        self.install()
        other = self.folder / "other-repo"
        shutil.copytree(self.repo, other)
        self.assertEqual(self.locate(repo=other)["repository"], str(other.resolve()))
        with self.assertRaisesRegex(ValueError, "指定仓库"):
            locator.locate(home=self.home, environment={"CTF_WORKFLOW_HOME": str(self.other)})

    def test_checkout_and_stale_record_fallback_are_marked(self):
        self.home.mkdir()
        record = self.home / ".ctf-workflow-team/location.json"
        record.parent.mkdir()
        record.write_text("{}", encoding="utf-8")
        found = locator.locate(home=self.home, cwd=self.repo/"tools", skill_file=self.home/"outside.py", environment={})
        self.assertTrue(found["location_record_stale"])
        self.assertEqual(found["root_source"], "working_directory")
        source = locator.locate(home=self.home, cwd=self.other,
                                skill_file=self.repo/"skills"/installer.NAME/"scripts/locate_system.py", environment={})
        self.assertEqual(source["root_source"], "skill_checkout")

    def test_extra_files_and_symlinks_are_not_installed(self):
        source = self.repo / "skills" / installer.NAME
        (source/"secret.txt").write_text("fixture", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "白名单"):
            self.install()
        (source/"secret.txt").unlink()
        try:
            (source/"link").symlink_to(self.other, target_is_directory=True)
        except OSError:
            return
        with self.assertRaisesRegex(ValueError, "符号链接"):
            self.install()

    def test_fresh_cli_locator_returns_json_with_no_import_of_repo(self):
        found = subprocess.run([sys.executable, str(ROOT/"skills"/installer.NAME/"scripts/locate_system.py"), "--repo", str(self.repo)],
                               capture_output=True, text=True, timeout=10)
        self.assertEqual(found.returncode, 0, found.stderr)
        self.assertEqual(json.loads(found.stdout)["repository"], str(self.repo.resolve()))
        # tools/ctf_os.py is deliberately invalid Python in this fixture: locating must not execute it.


if __name__ == "__main__":
    unittest.main()
