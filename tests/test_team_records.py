import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("team_records", Path(__file__).resolve().parents[1] / "tools/team_records.py")
records = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(records)


class TeamRecordTests(unittest.TestCase):
    def fixture(self, root):
        content = b"observed tool output\n"
        (root / "objects").mkdir()
        obj = root / "objects/evidence.txt"
        obj.write_bytes(content)
        manifest = root / "manifest.json"
        manifest.write_text(json.dumps({"format": 1, "snapshot": "test", "encrypted": False,
            "files": [{"source": "case", "path": "raw/output.txt", "object": "objects/evidence.txt",
                       "bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}]}), encoding="utf-8")
        return manifest

    def test_restore_preserves_evidence_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self.fixture(root)
            output = root / "restored"
            records.restore(output, manifest)
            self.assertEqual((output / "case/raw/output.txt").read_bytes(), b"observed tool output\n")
            with self.assertRaises(ValueError):
                records.restore(output, manifest)

    def test_tamper_is_detected_before_destination_is_created(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self.fixture(root)
            (root / "objects/evidence.txt").write_bytes(b"modified")
            with self.assertRaises(ValueError):
                records.restore(root / "restored", manifest)
            self.assertFalse((root / "restored").exists())

    def test_rejects_traversal_and_case_collision(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self.fixture(root)
            data = json.loads(manifest.read_text(encoding="utf-8"))
            data["files"][0]["path"] = "../escape.txt"
            manifest.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaises(ValueError):
                records.load_manifest(manifest)
            data["files"][0]["path"] = "output.txt"
            data["files"].append(dict(data["files"][0], path="OUTPUT.TXT"))
            manifest.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaises(ValueError):
                records.load_manifest(manifest)


if __name__ == "__main__":
    unittest.main()
