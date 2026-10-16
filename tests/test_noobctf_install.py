"""Installer policy tests; downloads and upstream challenge code never execute."""
import importlib.util
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("install_noobctf", ROOT / "tools/install_noobctf.py")
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)


class NoobCTFInstall(unittest.TestCase):
    def setUp(self):
        output = ROOT / "logs/test-noobctf-install"
        output.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=output)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repo = self.root / "references/noobctf"
        self.calls = []
        self.head = installer.PINNED_COMMIT
        self.origin = installer.UPSTREAM
        self.status = ""
        self.builds = 0
        self.index_state = {"ready": False}
        self.reference = types.SimpleNamespace(
            locations=lambda source: ({"url": installer.UPSTREAM[:-4]}, self.repo, self.root / "references/indexes/noobctf.sqlite3"),
            status=lambda source: dict(self.index_state), build=self.build, TEXT_SUFFIXES={".md"},
        )

    def build(self, source):
        self.assertEqual(source, "noobctf")
        self.builds += 1
        self.index_state = {"ready": True, "commit": installer.PINNED_COMMIT, "indexed_files": 626}
        return dict(self.index_state)

    def fake_git(self, *args, **kwargs):
        args = tuple(map(str, args))
        self.calls.append(args)
        if args[0] == "clone":
            (Path(args[-1]) / ".git").mkdir(parents=True)
            return ""
        operation = args[2:]
        if operation == ("rev-parse", "HEAD"):
            return self.head
        if operation in (("config", "--get", "remote.origin.url"), ("remote", "get-url", "origin")):
            return self.origin
        if operation[:1] == ("status",):
            return self.status
        if "fetch" in operation:
            return ""
        if operation == ("ls-tree", "-rz", "HEAD"):
            return "100644 blob " + "c" * 40 + "\tCTF/example.md\0"
        if operation[:2] == ("update-ref", "HEAD"):
            self.head = operation[2]
            return ""
        raise AssertionError(args)

    def existing(self, managed=False):
        (self.repo / ".git").mkdir(parents=True)
        if managed:
            (self.repo / ".git" / installer.MARKER).write_text(
                json.dumps(installer.EXPECTED_MARKER), encoding="utf-8")

    def test_download_uses_fixed_official_source_without_checkout(self):
        with patch.object(installer, "_git", side_effect=self.fake_git):
            result = installer.install(self.root, self.reference)
        clone = next(c for c in self.calls if c[0] == "clone")
        self.assertEqual(clone[1:6], ("--filter=blob:none", "--depth", "1", "--no-checkout", installer.UPSTREAM))
        self.assertTrue(result["ready"])
        self.assertFalse(result["executes_source"])
        self.assertEqual(result["commit"], installer.PINNED_COMMIT)
        self.assertFalse(any("checkout" == part or "reset" == part for c in self.calls for part in c))

    def test_new_clone_fetches_pinned_commit_when_upstream_head_advanced(self):
        self.head = "a" * 40
        with patch.object(installer, "_git", side_effect=self.fake_git):
            installer.install(self.root, self.reference)
        self.assertIn(("-C", next(c[-1] for c in self.calls if c[0] == "clone"), "fetch", "--depth", "1", "origin", installer.PINNED_COMMIT), self.calls)

    def test_existing_other_origin_is_retained(self):
        self.existing()
        private = self.repo / "local.txt"
        private.write_text("keep", encoding="utf-8")
        self.origin = "https://example.invalid/other.git"
        with patch.object(installer, "_git", side_effect=self.fake_git):
            with self.assertRaisesRegex(ValueError, "origin.*retained"):
                installer.install(self.root, self.reference)
        self.assertEqual(private.read_text(), "keep")
        self.assertEqual(self.builds, 0)
        self.assertFalse(any(c[0] == "clone" for c in self.calls))

    def test_existing_other_commit_is_not_changed(self):
        self.existing()
        self.head = "b" * 40
        with patch.object(installer, "_git", side_effect=self.fake_git):
            with self.assertRaisesRegex(ValueError, "HEAD.*retained"):
                installer.install(self.root, self.reference)
        self.assertFalse(any("fetch" in c or "update-ref" in c for c in self.calls))

    def test_existing_checkout_local_changes_are_retained(self):
        self.existing()
        self.status = " M README.md"
        with patch.object(installer, "_git", side_effect=self.fake_git):
            with self.assertRaisesRegex(ValueError, "local modifications.*retained"):
                installer.install(self.root, self.reference)
        self.assertEqual(self.builds, 0)

    def test_managed_object_store_rejects_added_worktree_files(self):
        self.existing(managed=True)
        (self.repo / "README.md").write_text("local", encoding="utf-8")
        with patch.object(installer, "_git", side_effect=self.fake_git):
            with self.assertRaisesRegex(ValueError, "working-tree.*retained"):
                installer.install(self.root, self.reference)

    def test_second_install_reuses_repository_and_index(self):
        with patch.object(installer, "_git", side_effect=self.fake_git):
            first = installer.install(self.root, self.reference)
            second = installer.install(self.root, self.reference)
        self.assertFalse(first["repository_reused"])
        self.assertTrue(second["repository_reused"])
        self.assertTrue(second["index_reused"])
        self.assertEqual(self.builds, 1)
        self.assertEqual(sum(c[0] == "clone" for c in self.calls), 1)


if __name__ == "__main__":
    unittest.main()
