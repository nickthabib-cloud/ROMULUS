"""A small WordprocessingML writer: the styled base template, text escaping and the package parts.

The executive report is written with the standard library only. The body is streamed into its package part, so a
report with many findings never holds a second copy of itself in memory. Every piece of text is escaped here and
placed only in text nodes: telemetry never reaches an attribute, a relationship target, a style name or a field.
"""
from __future__ import annotations

import re
from xml.sax.saxutils import escape

W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
R_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
WP_NS = "http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing"
A_NS = "http://schemas.openxmlformats.org/drawingml/2006/main"
PIC_NS = "http://schemas.openxmlformats.org/drawingml/2006/picture"
PKG_REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
REL_TYPE = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/"

# characters XML 1.0 forbids, then the invisible controls that can disguise text (bidirectional overrides and
# isolates, zero-width marks, the byte-order mark)
_XML_INVALID = re.compile(r"[^\x09\x0a\x0d\x20-\ud7ff\ue000-\ufffd\U00010000-\U0010ffff]")
_INVISIBLE = re.compile(r"[\u061c\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]")

# the severity colour system, shared by text badges and the attack-path image
LANE_COLORS = {"urgent": "B91C1C", "high": "C2410C", "lead": "A16207", "mention": "475569", "context": "6B7280"}
HYPOTHESIS_COLOR = "6D28D9"
MUTED_COLOR = "6B7280"
INK = "1F2937"
ACCENT = "1F3A5F"
EMU_PER_INCH = 914400
# US Letter with one-inch margins: the text column is 6.5 inches wide
TEXT_WIDTH_TWIPS = 9360


def clean(value) -> str:
    """Text safe for a WordprocessingML text node: forbidden and invisible control characters removed."""
    return _INVISIBLE.sub("", _XML_INVALID.sub("", "" if value is None else str(value)))


def text_xml(value) -> str:
    """Escaped character data for a `w:t` node."""
    return escape(clean(value))


_HEX_COLOR = re.compile(r"[0-9A-F]{6}")
_TOKEN = re.compile(r"[A-Za-z][A-Za-z0-9]*")
_ALIGN = frozenset({"left", "center", "right", "both"})


def hex_color(value) -> str:
    """A colour for an attribute: six upper-case hex digits, never anything else."""
    if not isinstance(value, str) or not _HEX_COLOR.fullmatch(value):
        raise ValueError(f"not a colour: {value!r}")
    return value


def token(value) -> str:
    """A style or relationship id for an attribute: a letter, then letters and digits."""
    if not isinstance(value, str) or not _TOKEN.fullmatch(value):
        raise ValueError(f"not an identifier: {value!r}")
    return value


def run(value, *, bold=False, italic=False, color=None, size=None, style=None) -> str:
    """One text run. Its properties follow the schema order (rStyle, b, i, color, sz). Only `value` may carry
    manifest text; every attribute value is checked to be a colour or an identifier."""
    props = []
    if style:
        props.append(f'<w:rStyle w:val="{token(style)}"/>')
    if bold:
        props.append("<w:b/>")
    if italic:
        props.append("<w:i/>")
    if color:
        props.append(f'<w:color w:val="{hex_color(color)}"/>')
    if size:
        props.append(f'<w:sz w:val="{int(size)}"/>')
    rpr = f"<w:rPr>{''.join(props)}</w:rPr>" if props else ""
    return f'<w:r>{rpr}<w:t xml:space="preserve">{text_xml(value)}</w:t></w:r>'


def paragraph(runs: str = "", *, style=None, keep_next=False, page_break_before=False, align=None,
              shade=None) -> str:
    """One paragraph of prepared runs. Its properties follow the schema order (pStyle, keepNext, pageBreakBefore,
    shd, jc)."""
    props = []
    if style:
        props.append(f'<w:pStyle w:val="{token(style)}"/>')
    if keep_next:
        props.append("<w:keepNext/>")
    if page_break_before:
        props.append("<w:pageBreakBefore/>")
    if shade:
        props.append(f'<w:shd w:val="clear" w:color="auto" w:fill="{hex_color(shade)}"/>')
    if align:
        if align not in _ALIGN:
            raise ValueError(f"not an alignment: {align!r}")
        props.append(f'<w:jc w:val="{align}"/>')
    ppr = f"<w:pPr>{''.join(props)}</w:pPr>" if props else ""
    return f"<w:p>{ppr}{runs}</w:p>"


def cell(content: str, width: int, *, fill=None) -> str:
    """One table cell holding prepared paragraphs (a cell always ends with a paragraph)."""
    shade = f'<w:shd w:val="clear" w:color="auto" w:fill="{hex_color(fill)}"/>' if fill else ""
    return (f'<w:tc><w:tcPr><w:tcW w:w="{int(width)}" w:type="dxa"/>{shade}</w:tcPr>'
            f"{content or paragraph()}</w:tc>")


def table_start(widths: list[int], header: list[str]) -> str:
    """A grid table's properties, its column grid and its repeated header row."""
    grid = "".join(f'<w:gridCol w:w="{width}"/>' for width in widths)
    head = "".join(cell(paragraph(run(title, bold=True, color="FFFFFF"), style="TableText"), width, fill=ACCENT)
                   for title, width in zip(header, widths, strict=True))
    return ('<w:tbl><w:tblPr><w:tblStyle w:val="ReportTable"/><w:tblW w:w="0" w:type="auto"/>'
            '<w:tblLayout w:type="fixed"/><w:tblLook w:val="04A0" w:firstRow="1" w:lastRow="0" w:firstColumn="0" '
            'w:lastColumn="0" w:noHBand="0" w:noVBand="1"/></w:tblPr>'
            f"<w:tblGrid>{grid}</w:tblGrid>"
            f'<w:tr><w:trPr><w:cantSplit/><w:tblHeader/></w:trPr>{head}</w:tr>')


def table_row(cells: list[str]) -> str:
    return f"<w:tr><w:trPr><w:cantSplit/></w:trPr>{''.join(cells)}</w:tr>"


TABLE_END = "</w:tbl>"


def inline_image(rel_id: str, width_emu: int, height_emu: int, picture_id: int, name: str, alt: str) -> str:
    """An inline picture in its own run. `name` and `alt` are fixed renderer text, never telemetry."""
    return (f'<w:r><w:drawing><wp:inline distT="0" distB="0" distL="0" distR="0">'
            f'<wp:extent cx="{width_emu}" cy="{height_emu}"/>'
            f'<wp:docPr id="{picture_id}" name="{escape(name)}" descr="{escape(alt)}"/>'
            f'<wp:cNvGraphicFramePr><a:graphicFrameLocks noChangeAspect="1"/></wp:cNvGraphicFramePr>'
            f'<a:graphic><a:graphicData uri="{PIC_NS}"><pic:pic>'
            f'<pic:nvPicPr><pic:cNvPr id="{picture_id}" name="{escape(name)}"/><pic:cNvPicPr/></pic:nvPicPr>'
            f'<pic:blipFill><a:blip r:embed="{token(rel_id)}"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill>'
            f'<pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="{width_emu}" cy="{height_emu}"/></a:xfrm>'
            f'<a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr>'
            f"</pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing></w:r>")


DOCUMENT_START = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                  f'<w:document xmlns:w="{W_NS}" xmlns:r="{R_NS}" xmlns:wp="{WP_NS}" xmlns:a="{A_NS}" '
                  f'xmlns:pic="{PIC_NS}"><w:body>')


def document_end(header_rel: str, footer_rel: str) -> str:
    """The section properties (always the body's last child) and the closing tags."""
    return (f'<w:sectPr><w:headerReference w:type="default" r:id="{header_rel}"/>'
            f'<w:footerReference w:type="default" r:id="{footer_rel}"/>'
            '<w:pgSz w:w="12240" w:h="15840"/>'
            '<w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" w:header="708" w:footer="708" '
            'w:gutter="0"/></w:sectPr></w:body></w:document>')


def header_part(banner: str) -> str:
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            f'<w:hdr xmlns:w="{W_NS}" xmlns:r="{R_NS}">'
            f'{paragraph(run(banner), style="Banner")}</w:hdr>')


def footer_part(banner: str, title: str) -> str:
    # the page number is the only field in the package, and it lives in the footer, never in the body
    page = '<w:fldSimple w:instr=" PAGE "><w:r><w:t>1</w:t></w:r></w:fldSimple>'
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            f'<w:ftr xmlns:w="{W_NS}" xmlns:r="{R_NS}">'
            f'{paragraph(run(title + " · page ") + page, style="FooterText")}'
            f'{paragraph(run(banner), style="Banner")}</w:ftr>')


def _style(kind: str, style_id: str, name: str, *, based_on=None, next_style=None, ppr="", rpr="",
           extra="") -> str:
    parts = [f'<w:style w:type="{kind}" w:styleId="{style_id}"{extra}><w:name w:val="{name}"/>']
    if based_on:
        parts.append(f'<w:basedOn w:val="{based_on}"/>')
    if next_style:
        parts.append(f'<w:next w:val="{next_style}"/>')
    parts.append('<w:qFormat/>' if kind == "paragraph" else "")
    if ppr:
        parts.append(f"<w:pPr>{ppr}</w:pPr>")
    if rpr:
        parts.append(f"<w:rPr>{rpr}</w:rPr>")
    parts.append("</w:style>")
    return "".join(parts)


def _heading(level: int, size: int, before: int) -> str:
    return _style("paragraph", f"Heading{level}", f"heading {level}", based_on="Normal", next_style="Normal",
                  ppr=(f'<w:keepNext/><w:keepLines/><w:spacing w:before="{before}" w:after="120"/>'
                       f'<w:outlineLvl w:val="{level - 1}"/>'),
                  rpr=f'<w:b/><w:color w:val="{ACCENT}"/><w:sz w:val="{size}"/>')


def styles_part() -> str:
    """The base template: page text, headings with outline levels (so the navigation pane and a table of contents
    work), the banner, callouts, captions and the report table style."""
    fonts = '<w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:eastAsia="Calibri" w:cs="Calibri"/>'
    border = '<w:{side} w:val="single" w:sz="4" w:space="0" w:color="D1D5DB"/>'
    borders = "".join(border.format(side=side) for side in ("top", "left", "bottom", "right", "insideH", "insideV"))
    styles = [
        _style("paragraph", "Normal", "Normal", extra=' w:default="1"',
               ppr='<w:spacing w:after="100" w:line="264" w:lineRule="auto"/>',
               rpr=f'{fonts}<w:color w:val="{INK}"/><w:sz w:val="21"/><w:szCs w:val="21"/>'),
        _style("paragraph", "Title", "Title", based_on="Normal", next_style="Subtitle",
               ppr='<w:spacing w:before="2400" w:after="240"/>',
               rpr=f'<w:b/><w:color w:val="{ACCENT}"/><w:sz w:val="56"/>'),
        _style("paragraph", "Subtitle", "Subtitle", based_on="Normal", next_style="Normal",
               ppr='<w:spacing w:after="360"/>', rpr=f'<w:color w:val="{MUTED_COLOR}"/><w:sz w:val="28"/>'),
        _heading(1, 32, 360), _heading(2, 26, 240), _heading(3, 22, 160),
        _style("paragraph", "Banner", "Classification banner", based_on="Normal",
               ppr='<w:spacing w:before="0" w:after="0"/><w:jc w:val="center"/>',
               rpr='<w:b/><w:color w:val="166534"/><w:sz w:val="18"/>'),
        _style("paragraph", "FooterText", "Footer text", based_on="Normal",
               ppr='<w:spacing w:before="0" w:after="0"/><w:jc w:val="center"/>',
               rpr=f'<w:color w:val="{MUTED_COLOR}"/><w:sz w:val="16"/>'),
        _style("paragraph", "Muted", "Muted", based_on="Normal",
               rpr=f'<w:i/><w:color w:val="{MUTED_COLOR}"/>'),
        _style("paragraph", "Callout", "Callout", based_on="Normal",
               ppr=('<w:pBdr><w:left w:val="single" w:sz="24" w:space="8" w:color="C2410C"/></w:pBdr>'
                    '<w:shd w:val="clear" w:color="auto" w:fill="FFF7ED"/><w:spacing w:before="120" w:after="120"/>'
                    '<w:ind w:left="240"/>')),
        _style("paragraph", "AiCallout", "AI callout", based_on="Normal",
               ppr=(f'<w:pBdr><w:left w:val="single" w:sz="24" w:space="8" w:color="{HYPOTHESIS_COLOR}"/>'
                    '</w:pBdr><w:shd w:val="clear" w:color="auto" w:fill="F5F3FF"/>'
                    '<w:spacing w:before="120" w:after="120"/><w:ind w:left="240"/>')),
        _style("paragraph", "Caption", "caption", based_on="Normal", next_style="Normal",
               ppr='<w:spacing w:before="60" w:after="200"/>',
               rpr=f'<w:i/><w:color w:val="{MUTED_COLOR}"/><w:sz w:val="18"/>'),
        _style("paragraph", "ListLine", "List line", based_on="Normal",
               ppr='<w:spacing w:after="60"/><w:ind w:left="360" w:hanging="200"/>'),
        _style("paragraph", "TableText", "Table text", based_on="Normal",
               ppr='<w:spacing w:before="20" w:after="20" w:line="240" w:lineRule="auto"/>',
               rpr='<w:sz w:val="17"/><w:szCs w:val="17"/>'),
        _style("table", "ReportTable", "Report table", extra="",
               ppr="", rpr="").replace(
            "</w:style>",
            f'<w:tblPr><w:tblBorders>{borders}</w:tblBorders><w:tblCellMar><w:top w:w="40" w:type="dxa"/>'
            '<w:left w:w="80" w:type="dxa"/><w:bottom w:w="40" w:type="dxa"/><w:right w:w="80" w:type="dxa"/>'
            "</w:tblCellMar></w:tblPr></w:style>"),
    ]
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            f'<w:styles xmlns:w="{W_NS}"><w:docDefaults><w:rPrDefault><w:rPr>{fonts}<w:sz w:val="21"/>'
            '<w:lang w:val="en-US"/></w:rPr></w:rPrDefault><w:pPrDefault><w:pPr/></w:pPrDefault></w:docDefaults>'
            f'{"".join(styles)}</w:styles>')


SETTINGS_PART = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                 f'<w:settings xmlns:w="{W_NS}"><w:defaultTabStop w:val="720"/>'
                 '<w:characterSpacingControl w:val="doNotCompress"/>'
                 '<w:compat><w:compatSetting w:name="compatibilityMode" w:uri="http://schemas.microsoft.com/office/word" '
                 'w:val="15"/></w:compat></w:settings>')


def content_types(*, image: bool) -> str:
    main = "application/vnd.openxmlformats-officedocument.wordprocessingml"
    overrides = [("/word/document.xml", f"{main}.document.main+xml"), ("/word/styles.xml", f"{main}.styles+xml"),
                 ("/word/settings.xml", f"{main}.settings+xml"), ("/word/header1.xml", f"{main}.header+xml"),
                 ("/word/footer1.xml", f"{main}.footer+xml"),
                 ("/docProps/core.xml", "application/vnd.openxmlformats-package.core-properties+xml")]
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            + ('<Default Extension="png" ContentType="image/png"/>' if image else "")
            + "".join(f'<Override PartName="{name}" ContentType="{kind}"/>' for name, kind in overrides)
            + "</Types>")


PACKAGE_RELS = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                f'<Relationships xmlns="{PKG_REL_NS}">'
                f'<Relationship Id="rId1" Type="{REL_TYPE}officeDocument" Target="word/document.xml"/>'
                '<Relationship Id="rId2" '
                'Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" '
                'Target="docProps/core.xml"/></Relationships>')


def core_properties(title: str) -> str:
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/">'
            f"<dc:title>{text_xml(title)}</dc:title><dc:creator>ROMULUS</dc:creator></cp:coreProperties>")


def document_rels(relationships: list[tuple[str, str, str, bool]]) -> str:
    """(id, type, target, external) rows. Targets are renderer-chosen part names or content-digest filenames."""
    rows = "".join(f'<Relationship Id="{rid}" Type="{REL_TYPE}{kind}" Target="{escape(target, {chr(34): "&quot;"})}"'
                   + (' TargetMode="External"' if external else "") + "/>"
                   for rid, kind, target, external in relationships)
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            f'<Relationships xmlns="{PKG_REL_NS}">{rows}</Relationships>')
