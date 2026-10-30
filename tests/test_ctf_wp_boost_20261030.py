"""20261030 WP 短板改进回归：空工具查询、步骤号报错、事后补目的、自动像素预检、交付占用回退。"""
import random
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import ctf_wp as wp


def noise_png(path, width=400, height=200, seed=3):
    from PIL import Image
    img = Image.new("RGB", (width, height))
    px = img.load()
    random.seed(seed)
    for y in range(height):
        for x in range(width):
            px[x, y] = (random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))
    img.save(path)


class WPBoostTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=r"D:\Temp" if sys.platform == "win32" else None)
        self.patcher = patch.object(wp, "ROOT", Path(self.temp.name))
        self.patcher.start()
        wp.init({"case": "fixture", "title": "WP 短板改进回归（自建样例）"})

    def tearDown(self):
        self.patcher.stop()
        self.temp.cleanup()

    def record(self):
        started = wp.begin_call("fixture", "fixture", {"wp_purpose": "自建样例调用"})
        return wp.record_call("fixture", {}, {"tool": "fixture", "ok": True,
            "result": {"stdout": "fixture"}, "wp_operation": started})

    def test_section_error_lists_usable_steps(self):
        recorded = self.record()
        with self.assertRaises(ValueError) as ctx:
            wp.section({"case": "fixture", "section": "analysis", "text": "x",
                        "source_steps": [1, 999]})
        message = str(ctx.exception)
        self.assertIn("可引用的步骤号", message)
        self.assertIn(str(recorded["step"]), message)
        self.assertIn("wp_record.step", message)

    def test_amend_purpose_clears_gap_and_is_marked(self):
        # 无目的调用 → missing_purpose；补记后 issue 消失且带事后标记。
        started = wp.begin_call("fixture", "fixture", {})
        recorded = wp.record_call("fixture", {}, {"tool": "fixture", "ok": True,
            "result": {}, "wp_operation": started})
        review = wp.review({"case": "fixture"})
        self.assertIn("missing_purpose", {x["code"] for x in review["issues"]})
        result = wp.note({"case": "fixture", "status": "observed",
                          "source_step": recorded["step"], "amend_purpose": True,
                          "text": "事后补记的目的：验证补记通道"})
        self.assertTrue(result["recorded_after_the_fact"])
        review = wp.review({"case": "fixture"})
        self.assertNotIn("missing_purpose", {x["code"] for x in review["issues"]})
        self.assertEqual(review["quality"]["purposes_amended_after_the_fact"], [recorded["step"]])

    def test_amend_purpose_rejects_already_purposed_call(self):
        recorded = self.record()
        with self.assertRaises(ValueError):
            wp.note({"case": "fixture", "status": "observed",
                     "source_step": recorded["step"], "amend_purpose": True,
                     "text": "该调用已有目的，应拒绝重复补记"})

    def test_auto_pixel_review_draft_is_accepted_and_marked(self):
        recorded = self.record()
        image = Path(self.temp.name) / "live.png"
        noise_png(image, 1324, 724, seed=5)
        folder = wp.case_dir("fixture")
        with wp.locked(folder):
            rows = wp.verify(folder)
            seq = len(rows) + 1
            path = folder / "images" / ("%04d.png" % seq)
            path.parent.mkdir(exist_ok=True)
            import shutil
            shutil.copyfile(image, path)
            event = wp.append(folder, "capture",
                {"source": "vmrun captureScreen：配置中的 Kali 虚拟机实际画面",
                 "image_kind": "vm_screenshot", "caption": "关键画面",
                 "source_step": recorded["step"], "stage": "process"},
                [wp.file_record(folder, path, "vm_screenshot")])
            auto = wp._auto_pixel_review(folder, event,
                "vmrun captureScreen：配置中的 Kali 虚拟机实际画面", "process")
        self.assertTrue(auto["ok"])
        from ctf_wp_capture_review import eligible
        candidates = eligible(folder, wp.verify(folder))
        accepted = [c for c in candidates if c["accepted"]]
        self.assertEqual(len(accepted), 1)
        self.assertIn("自动像素预检", accepted[0]["review"]["observed_content"])
        self.assertIn("auto pixel pre-check", accepted[0]["review"]["scope"])

    def test_auto_pixel_review_rejects_blank_frame(self):
        from PIL import Image
        recorded = self.record()
        image = Path(self.temp.name) / "blank.png"
        Image.new("RGB", (1324, 724), "black").save(image)
        folder = wp.case_dir("fixture")
        with wp.locked(folder):
            rows = wp.verify(folder)
            seq = len(rows) + 1
            path = folder / "images" / ("%04d.png" % seq)
            path.parent.mkdir(exist_ok=True)
            import shutil
            shutil.copyfile(image, path)
            event = wp.append(folder, "capture",
                {"source": "vmrun captureScreen", "image_kind": "vm_screenshot",
                 "caption": "空白画面", "source_step": recorded["step"], "stage": "process"},
                [wp.file_record(folder, path, "vm_screenshot")])
            auto = wp._auto_pixel_review(folder, event, "vmrun captureScreen", "process")
        self.assertFalse(auto["ok"])
        self.assertIn("人工", auto["action"])

    def test_deliver_falls_back_when_target_locked(self):
        import zipfile
        import ctf_competition as comp
        root = Path(self.temp.name)
        case_dir = root / "wp" / "cases" / "ctf-1234567890abcdef" / "reports" / "r1"
        case_dir.mkdir(parents=True)
        src = case_dir / "writeup.docx"
        with zipfile.ZipFile(src, "w") as z:
            z.writestr("x", "y")
        delivery = root / "delivery"
        delivery.mkdir()
        task = {"task_id": "ctf-1234567890abcdef", "title": "占用回退", "answer_verified": False}
        target = delivery / "占用回退-WP-90abcdef.docx"
        if sys.platform == "win32":
            import msvcrt
            with open(target, "wb") as f:
                f.write(b"locked")
                f.flush()
                msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
                try:
                    out = comp.deliver(task, {"result": {"formats": {"docx": {"ok": True, "path": str(src)}}}},
                                       {"delivery_dir": str(delivery)}, root)
                finally:
                    msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            target.write_bytes(b"locked")
            out = comp.deliver(task, {"result": {"formats": {"docx": {"ok": True, "path": str(src)}}}},
                               {"delivery_dir": str(delivery)}, root)
        self.assertTrue(Path(out["path"]).is_file())
        self.assertNotEqual(Path(out["path"]), target)
        self.assertEqual(target.read_bytes(), b"locked")

    def test_empty_tools_query_returns_full_catalog(self):
        from ctf_product import Product
        product = Product(Path(__file__).resolve().parents[1])
        result = product.tools()
        self.assertGreater(result["count"], 100)
        self.assertEqual(result["count"], result["total"])
        by_name = product.tools(name="")
        self.assertEqual(by_name["count"], by_name["total"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
