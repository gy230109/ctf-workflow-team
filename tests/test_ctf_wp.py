"""Evidence isolation, error fidelity and export integrity, using only fixtures."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import ctf_wp as wp
import ctf_os as service


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.patcher = patch.object(wp, "ROOT", Path(self.temp.name))
        self.patcher.start()
        wp.init({"case": "fixture", "title": "WP 系统验收（不是比赛题）"})

    def tearDown(self):
        self.patcher.stop()
        self.temp.cleanup()

    def record(self, ok=True):
        return wp.record_call("fixture", {"cmd": "printf example"}, {
            "tool": "fixture", "ok": ok, "duration_ms": 1,
            "result": {"stdout": "example", "stderr": "" if ok else "real failure", "exit": 0 if ok else 1}})

    def test_invalid_case_never_escapes(self):
        for name in ("../outside", "a/b", "a\\b", ".", "", "中文", "a" * 65):
            with self.assertRaises(ValueError):
                wp.case_dir(name)

    def test_resume_does_not_overwrite_metadata(self):
        result = wp.init({"case": "fixture", "title": "changed"})
        self.assertFalse(result["created"])
        self.assertNotIn("changed", (wp.case_dir("fixture") / "session.json").read_text(encoding="utf-8"))

    def test_automatic_ctfos_recording(self):
        result = service.call_tool("math_gcd", {"values": [48, 60], "wp_case": "fixture"})
        self.assertTrue(result["ok"])
        self.assertEqual(result["wp_record"]["step"], 2)
        self.assertEqual(wp.status({"case": "fixture"})["calls"], 1)

    def test_case_parameter_records_only_initialized_case(self):
        result = service.call_tool("math_gcd", {"values": [48, 60], "case": "fixture"})
        self.assertIn("wp_record", result)
        unrelated = service.call_tool("math_gcd", {"values": [48, 60], "case": "unrelated"})
        self.assertNotIn("wp_record", unrelated)

    def test_missing_wp_prevents_tool_execution(self):
        with patch.object(service, "_call_tool") as execute:
            result = service.call_tool("math_gcd", {"wp_case": "missing", "values": [48, 60]})
        execute.assert_not_called()
        self.assertEqual(result["error_code"], "wp_preflight_failed")

    def test_failure_is_preserved_in_report(self):
        self.record(False)
        path = Path(wp.build({"case": "fixture"})["path"])
        text = path.read_text(encoding="utf-8")
        self.assertIn("失败（保留错误，不当作成功）", text)
        self.assertIn("real failure", text)
        self.assertIn('"exit": 1', text)
        self.assertIn("非屏幕截图", text)

    def test_raw_mutation_blocks_export(self):
        result = self.record()
        Path(result["path"]).write_text("{}", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "证据缺失或被改动"):
            wp.build({"case": "fixture"})

    def test_deletion_of_tail_is_detected(self):
        self.record()
        path = wp.case_dir("fixture") / "timeline.jsonl"
        path.write_text(path.read_text(encoding="utf-8").splitlines()[0] + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "检查点"):
            wp.status({"case": "fixture"})

    def test_reordering_is_detected(self):
        self.record()
        path = wp.case_dir("fixture") / "timeline.jsonl"
        rows = path.read_text(encoding="utf-8").splitlines()
        path.write_text("\n".join(reversed(rows)) + "\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            wp.status({"case": "fixture"})

    def test_observation_requires_real_source(self):
        with self.assertRaises(ValueError):
            wp.note({"case": "fixture", "text": "a guess", "status": "observed", "source_step": 1})
        self.record()
        self.assertEqual(wp.note({"case": "fixture", "text": "actual output", "status": "observed", "source_step": 2})["status"], "observed")

    def test_case_isolation(self):
        wp.init({"case": "another"})
        self.record()
        self.assertEqual(wp.status({"case": "another"})["calls"], 0)

    def test_common_secret_redaction(self):
        raw = 'password="local-fixture" token=abcdef Cookie: abc sk-abcdefghijklmnopqrst flag{fixture} Bearer fixture123'
        redacted = wp.scrub(raw)
        for value in ("local-fixture", "abcdef", "fixture123", "flag{fixture}", "sk-abcdefghijklmnopqrst"):
            self.assertNotIn(value, redacted)

    def test_png_import_and_export_exclusion(self):
        from PIL import Image
        image = Path(self.temp.name) / "fixture.png"
        Image.new("RGB", (20, 20), "red").save(image)
        wp.capture({"case": "fixture", "mode": "file", "file_path": str(image), "source": "self-created test image"})
        included = wp.build({"case": "fixture", "include_images": True})
        excluded = wp.build({"case": "fixture"})
        self.assertEqual(included["images_included"], 1)
        self.assertEqual(excluded["images_included"], 0)
        self.assertNotEqual(included["path"], excluded["path"])
        self.assertFalse(list(Path(excluded["path"]).parent.glob("images/*capture.png")))

    def test_capture_failure_never_adds_event(self):
        with patch("ctf_os_runtime.settings", return_value={}):
            with self.assertRaises(ValueError):
                wp.capture({"case": "fixture"})
        self.assertEqual(wp.status({"case": "fixture"})["captures"], 0)

    def test_no_solved_claim_or_inference(self):
        self.record()
        result = wp.build({"case": "fixture"})
        self.assertFalse(result["solved_verified"])
        text = Path(result["path"]).read_text(encoding="utf-8")
        self.assertTrue(all(heading in text for heading in ("## 已验证", "## 未验证", "## 未完成")))


if __name__ == "__main__":
    unittest.main()
