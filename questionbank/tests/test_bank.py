import hashlib
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import sys
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import bank
from prompt_extract import extract_question


def task(raw=b"player handout\n"):
    commit = "a" * 40
    blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    return {"id": "example-001", "name": "Example", "category": "misc", "difficulty": "easy", "source_id": "example",
            "repository": "organizer/challenges", "commit": commit, "origin_path": "misc/example", "source_url": "https://example.invalid/reference",
            "split": "practice", "description": "Decode the supplied handout.", "content_type": "competition_ctf", "tags": [],
            "family_key": "example:001", "grading": "manual", "environment": {"kind": "static"}, "practice_readiness": "public_handouts",
            "public_files": [{"path": "misc/example/publish/data.txt", "url": "https://raw.githubusercontent.com/organizer/challenges/" + commit + "/misc/example/publish/data.txt",
                              "git_blob_sha1": blob, "bytes": len(raw)}]}


class BankTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.patches = [patch.object(bank, "ROOT", self.root), patch.object(bank, "DATA", self.root / "data"), patch.object(bank, "HANDOUTS", self.root / "public_handouts")]
        for item in self.patches: item.start()

    def tearDown(self):
        for item in reversed(self.patches): item.stop()
        self.temporary.cleanup()

    def test_holdout_is_not_selected_or_opened_by_default(self):
        value = task(); value["split"] = "holdout"
        self.assertEqual(bank.selection([value], SimpleNamespace(split="training")), [])
        with self.assertRaisesRegex(ValueError, "reserved"):
            bank.require_task([value], value["id"])
        with self.assertRaisesRegex(ValueError, "requires"):
            bank.selection([value], SimpleNamespace(split="holdout", evaluation=False))

    def test_alias_is_not_counted_as_an_extra_assignment(self):
        value = task(); value["alias_of"] = "original"
        self.assertEqual(bank.selection([value], SimpleNamespace(split="training")), [])

    def test_download_hash_then_prepare_blind_task(self):
        value = task()
        with patch.object(bank, "download_bytes", return_value=b"player handout\n"):
            bank.fetch_task(value)
        out = self.root / "practice"
        bank.prepare_task(value, out)
        view = json.loads((out / "task.json").read_text())
        self.assertTrue(view["handouts_complete"])
        self.assertEqual((out / view["handouts"][0]["path"]).read_bytes(), b"player handout\n")
        for key in ("source_url", "origin_path", "repository", "commit", "flag", "answer"):
            self.assertNotIn(key, view)

    def test_bad_hash_and_literal_reference_are_not_marked_downloaded(self):
        with patch.object(bank, "download_bytes", return_value=b"different data"):
            with self.assertRaisesRegex(ValueError, "checksum"):
                bank.fetch_task(task())
        raw = b"flag{synthetic_reference_for_testing_only}"
        with patch.object(bank, "download_bytes", return_value=raw):
            with self.assertRaisesRegex(ValueError, "review"):
                bank.fetch_task(task(raw))
        self.assertEqual(bank.read_downloads(), {})

    def test_review_required_and_lfs_pointer_are_rejected(self):
        value = task(); value["public_files_need_review"] = True
        with self.assertRaisesRegex(ValueError, "reviewed"):
            bank.fetch_task(value)
        raw = b"version https://git-lfs.github.com/spec/v1\noid sha256:example\nsize 50\n"
        with patch.object(bank, "download_bytes", return_value=raw):
            with self.assertRaisesRegex(ValueError, "LFS"):
                bank.fetch_task(task(raw))

    def test_download_cannot_redirect_to_arbitrary_host(self):
        value = task(); value["public_files"][0]["url"] = "https://127.0.0.1/private"
        with self.assertRaises(ValueError):
            bank.handout_url(value, value["public_files"][0])
        handler = bank.PublicOnlyRedirect()
        with self.assertRaisesRegex(ValueError, "redirect"):
            handler.redirect_request(None, None, 302, "Found", {}, "https://internal.example/private")

    def test_local_manifest_escape_and_corruption_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "invalid"):
            bank.verified_local({"local_path": "../outside.txt", "sha256": "x"})
        folder = self.root / "public_handouts"; folder.mkdir()
        path = folder / "changed.txt"; path.write_text("corrupted")
        with self.assertRaisesRegex(ValueError, "checksum"):
            bank.verified_local({"local_path": "public_handouts/changed.txt", "sha256": "0" * 64})

    def test_archives_with_traversal_or_reference_material_are_rejected(self):
        for name in ("../outside.txt", "solve/answer.py", "flag.txt"):
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, "w") as archive: archive.writestr(name, "not executed")
            with self.assertRaises(ValueError): bank.validate_archive(stream.getvalue())

    def test_solver_view_omits_old_remote_endpoint(self):
        value = task(); value["description"] = "Open https://old-competition.example/path to begin."
        view = bank.solver_view(value, {})
        self.assertNotIn("old-competition.example", view["description"])

    def test_question_code_comments_do_not_truncate_prompt_or_leak_solution(self):
        original = "# Title\n## 题目描述\nRead this.\n```sh\n# Hint: not a heading\ncommand\n```\n### Stage two\nKeep this subtask.\n## 题解\nREFERENCE MATERIAL\n"
        extracted = extract_question(original)
        self.assertIn("Keep this subtask", extracted["description"])
        self.assertIn("# Hint", extracted["description"])
        self.assertNotIn("REFERENCE MATERIAL", extracted["description"])
        self.assertTrue(extracted["full_prompt_available"])


if __name__ == "__main__": unittest.main()
