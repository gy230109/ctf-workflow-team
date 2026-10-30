"""WP upgrade regression fixtures; no challenge answers or remote operations."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import ctf_wp as wp


class ReviewTests(unittest.TestCase):
    def setUp(self):
        temp_root = Path("D:/Temp") if sys.platform == "win32" and Path("D:/Temp").is_dir() else Path(tempfile.gettempdir())
        self.temp = tempfile.TemporaryDirectory(prefix="wp-review-", dir=temp_root)
        self.root = Path(self.temp.name)
        self.patch = patch.object(wp, "ROOT", self.root / "cases")
        self.patch.start()
        wp.init({"case": "fixture", "title": "自建 WP 记录验收"})

    def tearDown(self):
        self.patch.stop()
        self.temp.cleanup()

    def call(self, args=None, result=None):
        args = args or {"wp_purpose": "检查自建输出"}
        operation = wp.begin_call("fixture", "fixture", args)
        response = {"ok": True, "tool": "fixture", "result": {"stdout": "fixture"},
                    "wp_operation": operation}
        response.update(result or {})
        return wp.record_call("fixture", args, response)

    def test_intake_is_append_only_and_copies_verified_original(self):
        folder = wp.case_dir("fixture")
        initial = (folder / "session.json").read_bytes()
        original = self.root / "handout.txt"
        original.write_text("original fixture", encoding="utf-8")
        result = wp.intake({"case": "fixture", "description": "自建题面", "source": {"kind": "fixture"},
                            "attachments": [{"path": str(original), "sha256": wp.digest(original)}]})
        self.assertEqual(result["attachments"], 1)
        self.assertEqual(initial, (folder / "session.json").read_bytes())
        event = wp.verify(folder)[-1]
        self.assertEqual(event["kind"], "intake")
        original.write_text("external changed", encoding="utf-8")
        self.assertEqual((folder / event["data"]["artifacts"][0]["path"]).read_text(encoding="utf-8"), "original fixture")
        wp.verify(folder)

    def test_intake_rejects_digest_mismatch_and_directory(self):
        original = self.root / "fixture.bin"
        original.write_bytes(b"fixture")
        with self.assertRaisesRegex(ValueError, "SHA256"):
            wp.intake({"case": "fixture", "attachments": [{"path": str(original), "sha256": "0" * 64}]})
        with self.assertRaises(ValueError):
            wp.intake({"case": "fixture", "attachments": [str(self.root)]})
        self.assertEqual(len(wp.verify(wp.case_dir("fixture"))), 1)

    def test_intake_rejects_link(self):
        source = self.root / "original.bin"
        source.write_bytes(b"fixture")
        with patch.object(Path, "is_symlink", return_value=True):
            with self.assertRaisesRegex(ValueError, "符号链接"):
                wp.intake({"case": "fixture", "attachments": [str(source)]})

    def test_changed_intake_snapshot_is_detected(self):
        original = self.root / "original.txt"
        original.write_text("fixture", encoding="utf-8")
        wp.intake({"case": "fixture", "attachments": [str(original)]})
        item = wp.verify(wp.case_dir("fixture"))[-1]["data"]["artifacts"][0]
        (wp.case_dir("fixture") / item["path"]).write_text("changed", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "证据缺失或被改动"):
            wp.review({"case": "fixture"})

    def test_draft_review_is_not_tool_failure(self):
        review = wp.review({"case": "fixture"})
        self.assertTrue(review["ok"])
        self.assertEqual(review["status"], "draft")
        self.assertFalse(review["submission_ready"])
        self.assertFalse(review["solved_verified"])
        self.assertIn("missing_description", {x["code"] for x in review["issues"]})

    def test_section_requires_actual_evidence_and_latest_wins(self):
        for steps in ([1], [99], [True], []):
            with self.assertRaises(ValueError):
                wp.section({"case": "fixture", "section": "analysis", "text": "fixture", "source_steps": steps})
        recorded = self.call()
        for text in ("earlier", "latest"):
            wp.section({"case": "fixture", "section": "analysis", "text": text,
                        "source_steps": [recorded["step"]]})
        review = wp.review({"case": "fixture"})
        self.assertEqual(review["sections"]["analysis"]["text"], "latest")
        self.assertFalse(review["platform_answer_verified"])

    def test_prose_claim_does_not_certify_answer(self):
        recorded = self.call()
        wp.section({"case": "fixture", "section": "validation", "text": "平台接受，题目已解决",
                    "source_steps": [recorded["step"]]})
        review = wp.review({"case": "fixture"})
        self.assertFalse(review["platform_answer_verified"])
        self.assertFalse(review["submission_ready"])

    def test_capture_failure_is_persisted_and_original_error_raised(self):
        with patch("ctf_os_runtime.settings", return_value={}):
            with self.assertRaisesRegex(ValueError, "Kali 桥未配置"):
                wp.capture({"case": "fixture"})
        status = wp.status({"case": "fixture"})
        self.assertEqual(status["captures"], 0)
        self.assertEqual(status["capture_errors"][0]["kind"], "capture_failed")
        self.assertFalse(status["review"]["recording_complete"])

    def test_input_snapshot_is_saved_before_execution_and_mutation_reported(self):
        script = self.root / "solver.py"
        script.write_text("print('before')", encoding="utf-8")
        args = {"script_file": str(script), "wp_purpose": "运行自建脚本"}
        operation = wp.begin_call("fixture", "fixture", args)
        script.write_text("print('after')", encoding="utf-8")
        result = wp.record_call("fixture", args, {"tool": "fixture", "ok": True, "result": {}, "wp_operation": operation})
        event = wp.verify(wp.case_dir("fixture"))[-1]
        item = next(x for x in event["files"] if x["kind"] == "script_snapshot")
        self.assertEqual(item["source_role"], "pre_execution_input")
        self.assertEqual((wp.case_dir("fixture") / item["path"]).read_text(encoding="utf-8"), "print('before')")
        self.assertEqual(result["capture_errors"][0]["phase"], "post_execution_compare")

    def test_request_file_json_is_protected_and_pending_visible(self):
        request = self.root / "request.json"
        request.write_text(json.dumps({"action": "fixture"}), encoding="utf-8")
        wp.begin_call("fixture", "fixture", {"request_file": str(request)})
        review = wp.review({"case": "fixture"})
        self.assertEqual(len(review["pending_operations"]), 1)
        event = wp.verify(wp.case_dir("fixture"))[-1]
        self.assertEqual(event["files"][1]["kind"], "request_snapshot")
        self.assertEqual(event["files"][1]["source_role"], "pre_execution_input")

    def test_legacy_post_run_script_not_mislabelled_as_input(self):
        script = self.root / "fixture.py"
        script.write_text("print('fixture')", encoding="utf-8")
        recorded = wp.record_call("fixture", {"script_file": str(script)},
                                  {"tool": "fixture", "ok": True, "result": {}})
        event = wp.verify(wp.case_dir("fixture"))[-1]
        self.assertFalse(any(x["kind"] == "script_snapshot" for x in event["files"]))
        self.assertTrue(recorded["capture_errors"])

    def test_ready_requires_all_content_and_correct_receipt(self):
        wp.intake({"case": "fixture", "description": "自建验收题面"})
        recorded = self.call(result={"tool": "ctfd_submit", "result": {
            "candidate_verified": True, "judge_status": "correct", "challenge_id": "synthetic-fixture"}})
        wp.note({"case": "fixture", "status": "observed", "source_step": recorded["step"], "text": "读取自建结构化正确回执"})
        from PIL import Image
        image = self.root / 'ready-fixture.png'
        Image.new('RGB', (24, 24), 'white').save(image)
        wp.capture({'case':'fixture', 'mode':'file', 'file_path':str(image),
                    'source':'Software test image fixture only; not a real challenge screenshot',
                    'source_step':recorded['step'], 'stage':'process_and_result'})
        for name in ("overview", "analysis", "solution", "validation", "reproduction"):
            wp.section({"case": "fixture", "section": name, "text": "自建验收章节",
                        "source_steps": [recorded["step"]]})
        ready = wp.review({"case": "fixture"})
        self.assertTrue(ready["submission_ready"])
        self.assertTrue(ready["platform_answer_verified"])
        self.assertFalse(ready["solved_verified"])

    def test_already_solved_receipt_does_not_certify_new_candidate(self):
        self.call(result={"tool": "ctfd_submit", "result": {
            "candidate_verified": False, "judge_status": "already_solved"}})
        self.assertFalse(wp.review({"case": "fixture"})["platform_answer_verified"])


if __name__ == "__main__":
    unittest.main()
