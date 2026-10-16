"""Portable optional renderers, path confinement and document structure."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile
import xml.etree.ElementTree as ET

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE / "tools"))
import ctf_wp_formats as formats


HAS_DOCX = importlib.util.find_spec("docx") is not None
HAS_PDF = importlib.util.find_spec("reportlab") is not None
HAS_PYPDF = importlib.util.find_spec("pypdf") is not None


class FormatTests(unittest.TestCase):
    def setUp(self):
        scratch = BASE / "logs" / "wp-format-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=scratch)
        self.folder = Path(self.temp.name)
        self.model = {"schema_version": 2, "title": "CTF 自建验收记录",
            "subtitle": "仅验证导出功能", "blocks": [
                {"type": "heading", "level": 1, "text": "解题过程"},
                {"type": "paragraph", "text": "中文与 English 均应清晰。保留实际观察和待办。"},
                {"type": "code", "text": "print('中文样例')\n" + "abcdef012345" * 100},
                {"type": "table", "headers": ["步骤", "观察"],
                 "rows": [["1", "运行自建样例"], ["2", "验证没有裁掉长路径 " + "a" * 150]]},
            ]}

    def tearDown(self):
        self.temp.cleanup()

    def image(self):
        from PIL import Image, ImageDraw
        (self.folder / "images").mkdir(exist_ok=True)
        path = self.folder / "images" / "tall.png"
        image = Image.new("RGB", (600, 2400), "white")
        draw = ImageDraw.Draw(image)
        draw.rectangle((5, 5, 594, 2394), outline="black", width=4)
        for y in range(80, 2350, 120):
            draw.text((25, y), "Actual fixture image row " + str(y), fill="black")
        image.save(path)
        return {"type": "image", "path": "images/tall.png", "caption": "自建截图样例"}

    @unittest.skipUnless(HAS_DOCX, "python-docx is optional")
    def test_docx_chinese_title_letter_table_and_long_code(self):
        result = formats.export(self.model, self.folder, ["docx"])
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["template_version"], formats.TEMPLATE_VERSION)
        with zipfile.ZipFile(self.folder / "writeup.docx") as archive:
            raw = archive.read("word/document.xml")
            xml = ET.fromstring(raw)
            ns = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
            texts = "".join(xml.itertext())
            self.assertIn("中文", texts)
            self.assertIn("CTF 自建验收记录", texts)
            title_style = xml.find("w:body/w:p/w:pPr/w:pStyle", ns)
            self.assertEqual(title_style.get("{" + ns["w"] + "}val"), "Title")
            page = xml.find(".//w:pgSz", ns)
            self.assertEqual(page.get("{" + ns["w"] + "}w"), "12240")
            self.assertEqual(page.get("{" + ns["w"] + "}h"), "15840")
            self.assertIsNotNone(xml.find(".//w:tblHeader", ns))
            self.assertIn(b'Consolas', archive.read("word/styles.xml"))
            self.assertIn(b'PAGE', archive.read("word/footer1.xml"))
            self.assertNotIn("a" * 300, texts)

    @unittest.skipUnless(HAS_PDF and HAS_PYPDF, "reportlab and pypdf are optional")
    def test_pdf_chinese_long_tokens_many_pages(self):
        self.model["blocks"].insert(2, self.image())
        self.model["blocks"].append({"type": "code", "text": "\n".join("x" * 400 for _ in range(80))})
        result = formats.export(self.model, self.folder, ["pdf"])
        self.assertTrue(result["ok"], result)
        from pypdf import PdfReader
        pages = PdfReader(self.folder / "writeup.pdf").pages
        self.assertGreater(len(pages), 2)
        self.assertTrue(all(round(float(page.mediabox.width)) == 612 for page in pages))
        text = "\n".join(page.extract_text() for page in pages)
        self.assertIn("中文", text)
        self.assertIn("CTF 自建验收记录", text)
        self.assertIn("第 1 页", text)

    @unittest.skipUnless(HAS_DOCX and HAS_PDF, "render libraries are optional")
    def test_tall_image_fits_and_can_be_disabled(self):
        self.model["blocks"].append(self.image())
        enabled = formats.export(self.model, self.folder, ["docx", "pdf"])
        self.assertTrue(enabled["ok"], enabled)
        with zipfile.ZipFile(self.folder / "writeup.docx") as archive:
            self.assertTrue(any(name.startswith("word/media/") for name in archive.namelist()))
        self.model["include_images"] = False
        # A disabled image is neither read nor required to exist.
        self.model["blocks"][-1]["path"] = "images/missing.png"
        disabled = formats.export(self.model, self.folder, "docx,pdf")
        self.assertTrue(disabled["ok"], disabled)
        with zipfile.ZipFile(self.folder / "writeup.docx") as archive:
            self.assertFalse(any(name.startswith("word/media/") for name in archive.namelist()))
        if HAS_PYPDF:
            from pypdf import PdfReader
            self.assertFalse(any(page.images for page in PdfReader(self.folder / "writeup.pdf").pages))

    def test_dependency_failure_has_hint_and_leaves_no_empty_file(self):
        original = formats.importlib.import_module
        def import_without_docx(name):
            if name == "docx":
                raise ModuleNotFoundError("No module named 'docx'")
            return original(name)
        with patch.object(formats.importlib, "import_module", side_effect=import_without_docx):
            result = formats.export(self.model, self.folder, ["docx"])
        self.assertFalse(result["ok"])
        self.assertEqual(result["formats"]["docx"]["error_code"], "dependency_missing")
        self.assertIn("python-docx", result["formats"]["docx"]["install_hint"])
        self.assertFalse((self.folder / "writeup.docx").exists())
        self.assertFalse(list(self.folder.glob(".wp-render-*")))

    @unittest.skipUnless(HAS_DOCX, "python-docx is optional")
    def test_one_missing_renderer_does_not_hide_other_success(self):
        original = formats.importlib.import_module
        def import_without_pdf(name):
            if name.startswith("reportlab"):
                raise ModuleNotFoundError("No module named 'reportlab'")
            return original(name)
        with patch.object(formats.importlib, "import_module", side_effect=import_without_pdf):
            result = formats.export(self.model, self.folder, ["docx", "pdf"])
        self.assertFalse(result["ok"])
        self.assertTrue(result["formats"]["docx"]["ok"])
        self.assertEqual(result["formats"]["pdf"]["error_code"], "dependency_missing")
        self.assertFalse((self.folder / "writeup.pdf").exists())
        self.assertFalse(list(self.folder.glob(".wp-render-*")))

    def test_symlink_asset_is_rejected_when_available(self):
        destination = self.folder / "original.txt"
        destination.write_text("fixture", encoding="utf-8")
        link = self.folder / "link.txt"
        try:
            link.symlink_to(destination)
        except OSError:
            self.skipTest("Creating symlinks is not permitted on this machine")
        result = formats.export({"schema_version": 2, "blocks": [
            {"type": "link", "target": "link.txt"}]}, self.folder, ["docx"])
        self.assertFalse(result["ok"])
        self.assertIn("Symbolic", result["error"])

    @unittest.skipUnless(HAS_DOCX, "python-docx is optional")
    def test_failed_render_preserves_old_output_but_does_not_return_it(self):
        previous = formats.export(self.model, self.folder, ["docx"])
        self.assertTrue(previous["ok"], previous)
        content = (self.folder / "writeup.docx").read_bytes()
        with patch.object(formats, "_docx", side_effect=ValueError("fixture renderer failure")):
            result = formats.export(self.model, self.folder, ["docx"])
        self.assertFalse(result["ok"])
        self.assertNotIn("path", result["formats"]["docx"])
        self.assertEqual(content, (self.folder / "writeup.docx").read_bytes())
        self.assertFalse(list(self.folder.glob(".wp-render-*")))

    def test_images_and_links_cannot_escape_report(self):
        for kind, key in (("image", "path"), ("link", "target")):
            for path in ("../outside.png", "C:/outside.png", "/tmp/out.png", "https://example.test/x", "..\\outside.png"):
                with self.subTest(kind=kind, path=path):
                    model = {"schema_version": 2, "blocks": [{"type": kind, key: path}]}
                    result = formats.export(model, self.folder, ["docx"])
                    self.assertFalse(result["ok"])
                    self.assertFalse(result["formats"])
        result = formats.export({"schema_version": 2, "blocks": [
            {"type": "link", "target": "missing.txt"}]}, self.folder, ["docx"])
        self.assertIn("missing", result["error"].lower())

    @unittest.skipUnless(HAS_DOCX and HAS_PDF, "render libraries are optional")
    def test_relative_link_preserves_report_evidence_target(self):
        (self.folder / "evidence").mkdir()
        (self.folder / "evidence" / "真实输出.txt").write_text("Fixture only", encoding="utf-8")
        self.model["blocks"].append({"type": "link", "text": "完整真实输出", "target": "evidence/真实输出.txt"})
        result = formats.export(self.model, self.folder, "docx,pdf")
        self.assertTrue(result["ok"], result)
        with zipfile.ZipFile(self.folder / "writeup.docx") as archive:
            self.assertIn("evidence/真实输出.txt", archive.read("word/_rels/document.xml.rels").decode())

    def test_schema_and_formats_fail_clearly(self):
        for model in ({}, {"schema_version": 1, "blocks": []},
                      {"schema_version": 2, "blocks": [{"type": "execute", "text": "x"}]},
                      {"schema_version": 2, "blocks": [{"type": "table", "headers": ["x"], "rows": [[1, 2]]}]}):
            result = formats.export(model, self.folder, ["docx"])
            self.assertFalse(result["ok"])
            self.assertIn("error", result)
        self.assertFalse(formats.export(self.model, self.folder, ["exe"])["ok"])


if __name__ == "__main__":
    unittest.main()
