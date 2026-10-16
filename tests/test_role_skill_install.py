"""Exercise role playbook installation using isolated D-drive client homes only."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import tomllib
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import connect_ai

LEGACY_FILES = ("SKILL.md", "agents/openai.yaml", "scripts/system.py")
ROLE_FILES = (
    "references/roles/a-web.md", "references/roles/b-pwn.md",
    "references/roles/d-reverse.md", "references/roles/g-crypto.md",
)
WP_FILES = ("references/wp-guide.md",)


class RoleSkillInstallTests(unittest.TestCase):
    def setUp(self):
        # Explicitly keep every fixture and installed client file off the real home.
        scratch = ROOT.parents[1] / "logs" / "role-skill-install-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix="fixture-", dir=scratch)
        self.folder = Path(self.temp.name)
        self.repo = self.folder / "portable repository"
        self.home = self.folder / "fake-home"
        self.source = self.repo / "skills/ctf-system"
        for name in ("tools/ctf_entry.py", "tools/ctf_product.py", "tools/ctf_os.py"):
            target = self.repo / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("# fixture; not executed\n", encoding="utf-8")
        for name in LEGACY_FILES + ROLE_FILES + WP_FILES:
            target = self.source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("fixture " + name + "\n", encoding="utf-8")
        for client in (".codex", ".trae", ".workbuddy"):
            (self.home / client).mkdir(parents=True)
        self.other_server = {"command": "unrelated-service", "args": ["keep-me"]}
        for client in (".trae", ".workbuddy"):
            (self.home / client / "mcp.json").write_text(json.dumps({
                "mcpServers": {"unrelated": self.other_server},
                "clientSetting": "preserve",
            }), encoding="utf-8")
        self.codex_prefix = (
            '# retain this comment\nmodel = "fixture-existing-model"\n\n'
            '[mcp_servers.unrelated]\ncommand = "unrelated-service"\n'
            'args = ["keep-me"]\n'
        )
        (self.home / ".codex/config.toml").write_text(self.codex_prefix, encoding="utf-8")
        self.unrelated_skill = self.home / ".trae/skills/unrelated/SKILL.md"
        self.unrelated_skill.parent.mkdir(parents=True)
        self.unrelated_skill.write_text("retain unrelated skill", encoding="utf-8")

    def tearDown(self):
        self.temp.cleanup()

    def install(self):
        return connect_ai.install(root=self.repo, home=self.home, python=sys.executable)

    def installed(self, client, name):
        return self.home / client / "skills/ctf-system" / name

    def test_all_three_clients_receive_entry_role_and_wp_playbooks(self):
        self.assertEqual(connect_ai.FILES, LEGACY_FILES + ROLE_FILES + WP_FILES)
        result = self.install()
        self.assertTrue(result["ok"])
        self.assertEqual(result["clients_detected"], ["codex", "trae", "workbuddy"])
        self.assertFalse(result["model_accounts_modified"])
        self.assertFalse(result["client_sessions_verified"])
        registry = json.loads((self.home / ".ctf-system/installed-files.json").read_text(encoding="utf-8"))
        for client in (".codex", ".trae", ".workbuddy"):
            for name in connect_ai.FILES:
                target = self.installed(client, name)
                self.assertEqual(target.read_bytes(), (self.source / name).read_bytes())
                self.assertEqual(registry[str(target)], hashlib.sha256(target.read_bytes()).hexdigest())

    def test_unrelated_mcp_configs_model_and_skill_remain(self):
        self.install()
        for client in (".trae", ".workbuddy"):
            data = json.loads((self.home / client / "mcp.json").read_text(encoding="utf-8"))
            self.assertEqual(data["mcpServers"]["unrelated"], self.other_server)
            self.assertEqual(data["clientSetting"], "preserve")
            self.assertIn("ctf-system", data["mcpServers"])
        text = (self.home / ".codex/config.toml").read_text(encoding="utf-8")
        self.assertTrue(text.startswith(self.codex_prefix))
        data = tomllib.loads(text)
        self.assertEqual(data["model"], "fixture-existing-model")
        self.assertEqual(data["mcp_servers"]["unrelated"], self.other_server)
        policy = data["mcp_servers"]["ctf-system"]
        self.assertEqual(policy["tools"]["ctf_team_role"]["approval_mode"], "approve")
        self.assertEqual(policy["default_tools_approval_mode"], "prompt")
        self.assertNotIn("ctf_call", policy["tools"])
        self.assertEqual(self.unrelated_skill.read_text(encoding="utf-8"), "retain unrelated skill")

    def test_identical_reinstall_does_not_rewrite_clients(self):
        self.install()
        registry_path = self.home / ".ctf-system/installed-files.json"
        first_registry = registry_path.read_bytes()
        result = self.install()
        self.assertEqual(result["changed_files"], [])
        self.assertEqual(first_registry, registry_path.read_bytes())

    def test_owned_role_update_is_backed_up(self):
        self.install()
        role = ROLE_FILES[0]
        previous = (self.source / role).read_bytes()
        (self.source / role).write_text("updated owned role\n", encoding="utf-8")
        result = self.install()
        changes = result["changed_files"]
        self.assertEqual(len(changes), 3)
        for record in changes:
            self.assertEqual(Path(record["backup"]).read_bytes(), previous)
            self.assertEqual(Path(record["file"]).read_text(encoding="utf-8"), "updated owned role\n")

    def test_external_role_change_refuses_before_any_client_write(self):
        self.install()
        skill = self.installed(".codex", "SKILL.md")
        previous_skill = skill.read_bytes()
        (self.source / "SKILL.md").write_text("pending update\n", encoding="utf-8")
        changed = self.installed(".workbuddy", ROLE_FILES[-1])
        changed.write_text("external local edit\n", encoding="utf-8")
        registry_path = self.home / ".ctf-system/installed-files.json"
        previous_registry = registry_path.read_bytes()
        with self.assertRaisesRegex(ValueError, "Skill modified outside this installer"):
            self.install()
        self.assertEqual(skill.read_bytes(), previous_skill)
        self.assertEqual(changed.read_text(encoding="utf-8"), "external local edit\n")
        self.assertEqual(registry_path.read_bytes(), previous_registry)

    def test_legacy_three_file_owned_registry_accepts_incremental_upgrade(self):
        with patch.object(connect_ai, "FILES", LEGACY_FILES):
            self.install()
        for client in (".codex", ".trae", ".workbuddy"):
            self.assertFalse(self.installed(client, ROLE_FILES[0]).exists())
        (self.source / "SKILL.md").write_text("new role-aware entry\n", encoding="utf-8")
        result = self.install()
        self.assertTrue(result["ok"])
        for client in (".codex", ".trae", ".workbuddy"):
            self.assertEqual(self.installed(client, "SKILL.md").read_text(encoding="utf-8"), "new role-aware entry\n")
            for name in ROLE_FILES + WP_FILES:
                self.assertEqual(self.installed(client, name).read_bytes(), (self.source / name).read_bytes())
        backups = [r for r in result["changed_files"] if r["backup"]]
        self.assertEqual(len(backups), 3)
        self.assertTrue(all(Path(r["backup"]).read_text(encoding="utf-8") == "fixture SKILL.md\n" for r in backups))

    def test_missing_role_rejected_before_installation(self):
        (self.source / ROLE_FILES[-1]).unlink()
        with self.assertRaisesRegex(ValueError, "Skill entry missing"):
            self.install()
        self.assertFalse((self.home / ".ctf-system").exists())
        self.assertFalse(self.installed(".codex", "SKILL.md").exists())

    def test_role_only_install_gains_wp_guide_without_rewriting_unrelated_clients(self):
        with patch.object(connect_ai, "FILES", LEGACY_FILES + ROLE_FILES):
            self.install()
        result = self.install()
        self.assertEqual(len(result["changed_files"]), 3)
        for client in (".codex", ".trae", ".workbuddy"):
            target = self.installed(client, WP_FILES[0])
            self.assertEqual(target.read_bytes(), (self.source / WP_FILES[0]).read_bytes())
        self.assertEqual(self.unrelated_skill.read_text(encoding="utf-8"), "retain unrelated skill")

    def test_missing_wp_guide_rejected_before_installation(self):
        (self.source / WP_FILES[0]).unlink()
        with self.assertRaisesRegex(ValueError, "Skill entry missing"):
            self.install()
        self.assertFalse((self.home / ".ctf-system").exists())


if __name__ == "__main__":
    unittest.main()
