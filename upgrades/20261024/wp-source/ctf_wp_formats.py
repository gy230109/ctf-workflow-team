"""Optional Word/PDF rendering for a CTF WP block model.

This module renders supplied evidence; it never executes model text, fetches URLs,
or infers a challenge outcome.  Optional libraries are imported only when the
requested renderer runs.  Relative asset links are confined to the report folder.
"""
from __future__ import annotations

import argparse
import importlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import sys
import tempfile
import unicodedata
from xml.sax.saxutils import escape


GENERATOR_VERSION = "ctf-wp-formats/2.0.0"
TEMPLATE_VERSION = "ctf-wp-letter/1.0.0"
FORMATS = ("docx", "pdf")
_BLOCKS = {"heading", "paragraph", "code", "image", "table", "link"}
_BAD_XML = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff\ufffe\uffff]")


def _text(value):
    if value is None:
        return ""
    return _BAD_XML.sub(lambda match: "[U+%04X]" % ord(match.group()), str(value))


def _local_asset(folder, value, must_exist=True):
    """Resolve a relative, regular report asset without following symlinks."""
    value = str(value or "")
    if not value or "\x00" in value or "\\" in value or ":" in value:
        raise ValueError("Asset must be a relative path inside the report directory")
    relative = PurePosixPath(value)
    if relative.is_absolute() or PureWindowsPath(value).is_absolute() or ".." in relative.parts:
        raise ValueError("Asset escapes the report directory")
    target = folder.joinpath(*relative.parts)
    for candidate in [target, *target.parents]:
        if candidate == folder.parent:
            break
        if candidate.is_symlink():
            raise ValueError("Symbolic links are not valid report assets")
    resolved = target.resolve()
    try:
        resolved.relative_to(folder)
    except ValueError as exc:
        raise ValueError("Asset escapes the report directory") from exc
    if must_exist and not resolved.is_file():
        raise ValueError("Report asset is missing: " + value)
    return resolved


def _validated(model, folder):
    if not isinstance(model, dict) or not isinstance(model.get("blocks"), list):
        raise ValueError("Report model must contain a blocks list")
    if model.get("schema_version") != 2:
        raise ValueError("Unsupported report schema_version; expected 2")
    include_images = model.get("include_images", True)
    if not isinstance(include_images, bool):
        raise ValueError("include_images must be boolean")
    normalized = dict(model)
    normalized["title"] = _text(model.get("title") or "CTF 解题记录")
    normalized["subtitle"] = _text(model.get("subtitle"))
    normalized["blocks"] = []
    for raw in model["blocks"]:
        if not isinstance(raw, dict) or raw.get("type") not in _BLOCKS:
            raise ValueError("Unsupported report block")
        block = dict(raw)
        kind = block["type"]
        if kind == "image" and not include_images:
            continue
        if kind == "heading":
            level = block.get("level", 1)
            if isinstance(level, bool) or not isinstance(level, int) or not 1 <= level <= 3:
                raise ValueError("Heading level must be 1, 2 or 3")
        if kind in {"link", "image"}:
            key = "target" if kind == "link" else "path"
            block["_asset"] = _local_asset(folder, block.get(key))
        if kind == "table":
            headers, rows = block.get("headers"), block.get("rows")
            if not isinstance(headers, list) or not headers or not isinstance(rows, list):
                raise ValueError("Table must contain non-empty headers and a rows list")
            if len(headers) > 8:
                raise ValueError("Tables support at most 8 columns; split a wider table")
            if any(not isinstance(row, list) or len(row) != len(headers) for row in rows):
                raise ValueError("Table row width does not match headers")
        normalized["blocks"].append(block)
    return normalized


def _wrap_cells(text, limit=85):
    """Display-wrap code, including unbroken ASCII and Chinese sequences."""
    out = []
    for line in _text(text).expandtabs(4).split("\n"):
        segment, width = "", 0
        for char in line:
            amount = 2 if unicodedata.east_asian_width(char) in {"W", "F"} else 1
            if segment and width + amount > limit:
                out.append(segment)
                segment, width = "", 0
            segment += char
            width += amount
        out.append(segment)
    return "\n".join(out)


def _docx(model, folder, target):
    docx = importlib.import_module("docx")
    shared = importlib.import_module("docx.shared")
    xml = importlib.import_module("docx.oxml")
    ns = importlib.import_module("docx.oxml.ns")
    enum = importlib.import_module("docx.enum.text")
    tables = importlib.import_module("docx.enum.table")
    document = docx.Document()
    section = document.sections[0]
    section.page_width = shared.Inches(8.5)
    section.page_height = shared.Inches(11)
    section.top_margin = section.bottom_margin = shared.Inches(1)
    section.left_margin = section.right_margin = shared.Inches(1)
    section.header_distance = section.footer_distance = shared.Inches(0.45)

    def set_font(style, size, latin="Arial", east_asia="Microsoft YaHei"):
        style.font.name = latin
        style.font.size = shared.Pt(size)
        style.font.color.rgb = shared.RGBColor(0, 0, 0)
        fonts = style.element.get_or_add_rPr().get_or_add_rFonts()
        fonts.set(ns.qn("w:eastAsia"), east_asia)
        fonts.set(ns.qn("w:ascii"), latin)
        fonts.set(ns.qn("w:hAnsi"), latin)
        # The default Word template can otherwise retain theme colors/borders.
        ppr = style.element.find(ns.qn("w:pPr"))
        if ppr is not None:
            for border in list(ppr.findall(ns.qn("w:pBdr"))):
                ppr.remove(border)

    for name, size in (("Normal", 11), ("Title", 22), ("Subtitle", 11),
                       ("Heading 1", 16), ("Heading 2", 13), ("Heading 3", 11)):
        set_font(document.styles[name], size)
    normal = document.styles["Normal"].paragraph_format
    normal.line_spacing = 1.2
    normal.space_after = shared.Pt(7)
    for name in ("Heading 1", "Heading 2", "Heading 3"):
        formatting = document.styles[name].paragraph_format
        formatting.space_before = shared.Pt(14)
        formatting.space_after = shared.Pt(6)
        formatting.keep_with_next = True
    code_style = document.styles.add_style("CTF Code", 1)
    set_font(code_style, 9, "Consolas")
    code_style.paragraph_format.space_after = shared.Pt(5)
    code_style.paragraph_format.line_spacing = 1.05
    code_style.paragraph_format.keep_together = False
    code_style.paragraph_format.widow_control = False
    caption_style = document.styles.add_style("CTF Caption", 1)
    set_font(caption_style, 9)
    caption_style.paragraph_format.space_after = shared.Pt(8)

    document.core_properties.title = model["title"]
    document.core_properties.subject = model["subtitle"]
    document.core_properties.author = ""
    document.core_properties.last_modified_by = ""
    document.core_properties.comments = GENERATOR_VERSION + "; " + TEMPLATE_VERSION
    document.add_paragraph(model["title"], "Title")
    if model["subtitle"]:
        document.add_paragraph(model["subtitle"], "Subtitle")

    footer = section.footer.paragraphs[0]
    footer.alignment = enum.WD_ALIGN_PARAGRAPH.CENTER
    footer.add_run("第 ")
    field = xml.OxmlElement("w:fldSimple")
    field.set(ns.qn("w:instr"), "PAGE")
    footer._p.append(field)
    footer.add_run(" 页")
    for run in footer.runs:
        run.font.size = shared.Pt(9)

    for block in model["blocks"]:
        kind = block["type"]
        if kind == "heading":
            document.add_paragraph(_text(block.get("text")), "Heading " + str(block.get("level", 1)))
        elif kind == "paragraph":
            document.add_paragraph(_text(block.get("text")))
        elif kind == "code":
            # Newlines below are display wraps; original scripts remain separate evidence.
            for line in _wrap_cells(block.get("text")).split("\n"):
                document.add_paragraph(line or " ", "CTF Code")
        elif kind == "link":
            paragraph = document.add_paragraph()
            hyperlink = xml.OxmlElement("w:hyperlink")
            relationship = document.part.relate_to(
                block["target"],
                "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink",
                is_external=True,
            )
            hyperlink.set(ns.qn("r:id"), relationship)
            run = xml.OxmlElement("w:r")
            text = xml.OxmlElement("w:t")
            text.text = _text(block.get("text") or block["target"])
            run.append(text)
            hyperlink.append(run)
            paragraph._p.append(hyperlink)
        elif kind == "image":
            image_module = importlib.import_module("PIL.Image")
            with image_module.open(block["_asset"]) as picture:
                width, height = picture.size
            if width <= 0 or height <= 0:
                raise ValueError("Invalid image dimensions")
            factor = min(6.5 / width, 7.6 / height)
            paragraph = document.add_paragraph()
            paragraph.paragraph_format.keep_with_next = bool(block.get("caption"))
            paragraph.alignment = enum.WD_ALIGN_PARAGRAPH.CENTER
            paragraph.add_run().add_picture(str(block["_asset"]),
                width=shared.Inches(width * factor), height=shared.Inches(height * factor))
            if block.get("caption"):
                caption = document.add_paragraph(_text(block["caption"]), "CTF Caption")
                caption.alignment = enum.WD_ALIGN_PARAGRAPH.CENTER
        elif kind == "table":
            count = len(block["headers"])
            table = document.add_table(rows=1, cols=count)
            table.autofit = False
            weights = _column_weights(block["headers"], block["rows"])
            for column, weight in zip(table.columns, weights):
                column.width = shared.Inches(6.5 * weight)
            repeat = xml.OxmlElement("w:tblHeader")
            repeat.set(ns.qn("w:val"), "true")
            table.rows[0]._tr.get_or_add_trPr().append(repeat)
            for index, value in enumerate(block["headers"]):
                table.rows[0].cells[index].text = _text(value)
            for row in block["rows"]:
                cells = table.add_row().cells
                for index, value in enumerate(row):
                    cells[index].text = _text(value)
            borders = xml.OxmlElement("w:tblBorders")
            for side in ("top", "left", "bottom", "right", "insideH", "insideV"):
                border = xml.OxmlElement("w:" + side)
                for key, value in (("val", "single"), ("sz", "4"), ("color", "D9D9D9")):
                    border.set(ns.qn("w:" + key), value)
                borders.append(border)
            table._tbl.tblPr.append(borders)
            for row_index, row in enumerate(table.rows):
                for column_index, cell in enumerate(row.cells):
                    cell.width = shared.Inches(6.5 * weights[column_index])
                    cell.vertical_alignment = tables.WD_CELL_VERTICAL_ALIGNMENT.CENTER
                    margins = xml.OxmlElement("w:tcMar")
                    for side in ("top", "left", "bottom", "right"):
                        margin = xml.OxmlElement("w:" + side)
                        margin.set(ns.qn("w:w"), "90")
                        margin.set(ns.qn("w:type"), "dxa")
                        margins.append(margin)
                    cell._tc.get_or_add_tcPr().append(margins)
                    if row_index == 0:
                        shade = xml.OxmlElement("w:shd")
                        shade.set(ns.qn("w:fill"), "E9EEF3")
                        cell._tc.get_or_add_tcPr().append(shade)
                    for paragraph in cell.paragraphs:
                        paragraph.paragraph_format.space_after = shared.Pt(3)
                        paragraph.paragraph_format.space_before = shared.Pt(3)
                        for run in paragraph.runs:
                            run.font.size = shared.Pt(9)
                            run.bold = row_index == 0
            document.add_paragraph().paragraph_format.space_after = shared.Pt(2)
    document.save(str(target))


def _column_weights(headers, rows):
    # Limit outliers so one long path cannot crush all other columns.
    lengths = []
    for index, header in enumerate(headers):
        values = [_text(header)] + [_text(row[index]) for row in rows[:100]]
        longest = max((len(value) for value in values), default=6)
        lengths.append(max(8, min(longest, 42)))
    total = sum(lengths)
    return [value / total for value in lengths]


def _pdf_font(pdfmetrics):
    """Use a configured embeddable CJK TTF, or ReportLab's Chinese CID font."""
    configured = os.environ.get("CTF_WP_PDF_FONT")
    if configured:
        path = Path(configured)
        if not path.is_file():
            raise ValueError("CTF_WP_PDF_FONT does not name an existing font file")
        ttfont = importlib.import_module("reportlab.pdfbase.ttfonts").TTFont
        pdfmetrics.registerFont(ttfont("CTFWPChinese", str(path)))
        return "CTFWPChinese"
    cidfont = importlib.import_module("reportlab.pdfbase.cidfonts").UnicodeCIDFont
    if "STSong-Light" not in pdfmetrics.getRegisteredFontNames():
        pdfmetrics.registerFont(cidfont("STSong-Light"))
    return "STSong-Light"


def _pdf(model, folder, target):
    platypus = importlib.import_module("reportlab.platypus")
    styles = importlib.import_module("reportlab.lib.styles")
    colors = importlib.import_module("reportlab.lib.colors")
    metrics = importlib.import_module("reportlab.pdfbase.pdfmetrics")
    units = importlib.import_module("reportlab.lib.units")
    pagesizes = importlib.import_module("reportlab.lib.pagesizes")
    inch = units.inch
    width = 6.5 * inch
    font = _pdf_font(metrics)
    base = dict(fontName=font, textColor=colors.black, wordWrap="CJK", splitLongWords=True)
    body = styles.ParagraphStyle("CTFBody", fontSize=11, leading=16, spaceAfter=8, **base)
    title = styles.ParagraphStyle("CTFTitle", fontSize=22, leading=28, spaceAfter=12, **base)
    subtitle = styles.ParagraphStyle("CTFSubtitle", fontSize=10, leading=14, spaceAfter=12, **base)
    headings = {
        level: styles.ParagraphStyle("CTFH" + str(level), fontSize=size, leading=size + 6,
            spaceBefore=13, spaceAfter=7, keepWithNext=True, **base)
        for level, size in ((1, 16), (2, 13), (3, 11))
    }
    code = styles.ParagraphStyle("CTFCode", fontSize=9, leading=12, spaceAfter=5, **base)
    cellstyle = styles.ParagraphStyle("CTFCell", fontSize=9, leading=13, spaceAfter=0, **base)
    captionstyle = styles.ParagraphStyle("CTFCaption", fontSize=9, leading=12, spaceAfter=9,
                                          alignment=1, **base)

    def paragraph(value, style=body):
        return platypus.Paragraph(escape(_text(value)).replace("\n", "<br/>"), style)

    story = [paragraph(model["title"], title)]
    if model["subtitle"]:
        story.append(paragraph(model["subtitle"], subtitle))
    for block in model["blocks"]:
        kind = block["type"]
        if kind == "heading":
            story.append(paragraph(block.get("text"), headings[block.get("level", 1)]))
        elif kind == "paragraph":
            story.append(paragraph(block.get("text")))
        elif kind == "code":
            # One flowable per display line: arbitrarily long output can paginate.
            for line in _wrap_cells(block.get("text"), 78).split("\n"):
                display = escape(line).replace(" ", "&#160;") or "&#160;"
                story.append(platypus.Paragraph(display, code))
        elif kind == "link":
            label = _text(block.get("text") or block["target"])
            # Plain relative file link, never file:// or a network URL.
            story.append(platypus.Paragraph(
                '<link href="' + escape(block["target"], {'"': "&quot;"}) + '">' +
                escape(label) + "</link>", body))
        elif kind == "image":
            picture = platypus.Image(str(block["_asset"]))
            factor = min(width / picture.imageWidth, 7.6 * inch / picture.imageHeight)
            picture.drawWidth = picture.imageWidth * factor
            picture.drawHeight = picture.imageHeight * factor
            picture.keepWithNext = bool(block.get("caption"))
            story.append(picture)
            if block.get("caption"):
                story.append(paragraph(block["caption"], captionstyle))
            story.append(platypus.Spacer(1, 6))
        elif kind == "table":
            data = [[paragraph(value, cellstyle) for value in block["headers"]]]
            data.extend([[paragraph(value, cellstyle) for value in row] for row in block["rows"]])
            table = platypus.LongTable(data,
                colWidths=[width * weight for weight in _column_weights(block["headers"], block["rows"])],
                repeatRows=1, hAlign="LEFT", splitByRow=1, splitInRow=1,
                spaceAfter=10)
            table.setStyle(platypus.TableStyle([
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D9D9D9")),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E9EEF3")),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.black),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ]))
            story.append(table)

    def page_number(canvas, document):
        canvas.saveState()
        canvas.setFont(font, 9)
        canvas.drawCentredString(4.25 * inch, 0.5 * inch, "第 %d 页" % document.page)
        canvas.restoreState()

    document = platypus.SimpleDocTemplate(str(target), pagesize=pagesizes.letter,
        leftMargin=inch, rightMargin=inch, topMargin=inch, bottomMargin=inch,
        title=model["title"], author="", subject=model["subtitle"],
        creator=GENERATOR_VERSION + "; " + TEMPLATE_VERSION,
    )
    document.build(story, onFirstPage=page_number, onLaterPages=page_number)


def export(model, folder, formats=("docx", "pdf")):
    """Create each requested format atomically; failures never leave empty files.

    ``model.include_images=false`` omits image blocks from both document formats.
    Per-format errors permit a successful Word export even when PDF dependencies
    are unavailable (and vice versa). Existing successful outputs are untouched
    by a failed rebuild, but are never returned as current results.
    """
    result = {"ok": False, "generator_version": GENERATOR_VERSION,
              "template_version": TEMPLATE_VERSION, "formats": {}, "warnings": []}
    if isinstance(formats, str):
        formats = [item.strip().lower() for item in formats.split(",") if item.strip()]
    try:
        formats = list(dict.fromkeys(formats))
        if not formats or any(fmt not in FORMATS for fmt in formats):
            raise ValueError("formats must contain docx and/or pdf")
        directory = Path(folder)
        if directory.is_symlink():
            raise ValueError("Report output directory cannot be a symbolic link")
        directory = directory.resolve()
        if not directory.is_dir():
            raise ValueError("Report output directory must already exist")
        normalized = _validated(model, directory)
    except Exception as exc:
        result["error"] = str(exc)
        return result
    for fmt in formats:
        target = directory / ("writeup." + fmt)
        temporary = None
        try:
            if target.is_symlink() or (target.exists() and not target.is_file()):
                raise ValueError("Output must be a regular file")
            descriptor, name = tempfile.mkstemp(prefix=".wp-render-", suffix="." + fmt, dir=directory)
            os.close(descriptor)
            temporary = Path(name)
            {"docx": _docx, "pdf": _pdf}[fmt](normalized, directory, temporary)
            minimum = 64
            if temporary.stat().st_size < minimum:
                raise ValueError("Renderer produced an empty or invalid output")
            with temporary.open("rb") as handle:
                signature = handle.read(5)
            if not (signature[:2] == b"PK" if fmt == "docx" else signature == b"%PDF-"):
                raise ValueError("Renderer output has the wrong file signature")
            os.replace(temporary, target)
            result["formats"][fmt] = {"ok": True, "path": str(target), "bytes": target.stat().st_size}
        except (ImportError, ModuleNotFoundError) as exc:
            result["formats"][fmt] = {"ok": False, "error_code": "dependency_missing",
                "error": str(exc), "install_hint": "python -m pip install " +
                ("python-docx Pillow" if fmt == "docx" else "reportlab Pillow")}
        except Exception as exc:
            result["formats"][fmt] = {"ok": False, "error_code": "render_failed", "error": str(exc)}
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
    result["ok"] = all(item["ok"] for item in result["formats"].values())
    if any(block.get("type") == "code" for block in normalized["blocks"]):
        result["warnings"].append("Document code is display-wrapped; use the original evidence script for replay.")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--formats", default="docx,pdf")
    args = parser.parse_args(argv)
    try:
        model = json.loads(Path(args.model).read_text(encoding="utf-8"))
        result = export(model, args.output, args.formats)
    except Exception as exc:
        result = {"ok": False, "error": str(exc), "generator_version": GENERATOR_VERSION,
                  "template_version": TEMPLATE_VERSION, "formats": {}}
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
