"""Executive Word document rendered from the same immutable report manifest."""
import json
import re
from xml.etree.ElementTree import Element, SubElement, tostring
from zipfile import ZIP_DEFLATED, ZipFile

from romulus.report.markdown import BANNER, is_ranked, outcome_sentence, ranked_sections

_WORD = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
_XML_INVALID = re.compile(r"[^\x09\x0a\x0d\x20-\ud7ff\ue000-\ufffd\U00010000-\U0010ffff]")


def write(m, path, technical_name):
    document = Element(f"{{{_WORD}}}document")
    body = SubElement(document, f"{{{_WORD}}}body")

    def paragraph(value, *, bold=False):
        p = SubElement(body, f"{{{_WORD}}}p")
        r = SubElement(p, f"{{{_WORD}}}r")
        if bold:
            SubElement(SubElement(r, f"{{{_WORD}}}rPr"), f"{{{_WORD}}}b")
        text = SubElement(r, f"{{{_WORD}}}t", {"{http://www.w3.org/XML/1998/namespace}space": "preserve"})
        text.text = _XML_INVALID.sub("", str(value))

    paragraph(BANNER)
    paragraph("ROMULUS executive report", bold=True)
    paragraph(f"Hunt {m['hunt']['id']} — revision {m['revision']['number']}")
    paragraph(outcome_sentence(m))
    if not m["integrity"]["finalizable"]:
        paragraph("Degraded report: incomplete evidence or host lists are identified in the technical report.")
    paragraph(f"Technical report: {technical_name}. This contains the full findings, citations and coverage gaps.")
    if is_ranked(m):
        confirmed, reported, pool = ranked_sections(m)
        sections = (("Confirmed", "Confirmed findings, reported on their own.", confirmed),
                    ("Reported entities", "Findings on entities that meet the evidence bar, in rank order.", reported),
                    ("Ranked findings (not reported)", "Leads below the evidence bar, in rank order.", pool))
        ordered = []
        for title, intro, rows in sections:
            ordered.append((title, intro, None))
            ordered.extend((None, None, finding) for finding in rows)
    else:
        ordered = [(None, None, finding) for finding in m["findings"]]
    for title, intro, finding in ordered:
        if finding is None:
            paragraph(title, bold=True)
            paragraph(intro)
            continue
        if is_ranked(m):
            entity = finding.get("entity") or {}
            where = f"{entity.get('kind')}:{entity.get('value')}" if entity.get("value") is not None else "unattributed"
            paragraph(f"{finding['rule_id']} — {where} (rule estimate: {finding['lane']})", bold=True)
        else:
            paragraph(f"{finding['rule_id']} — {finding['lane']}", bold=True)
        paragraph(finding["claim"])
        if ref := finding.get("fleet_hosts"):
            amount = str(ref["count"]) if ref["complete"] else f"{ref['count']} of {ref['expected_count']}"
            if finding.get("fleet_member_kind") == "external_address":
                paragraph(f"{amount} outside addresses retained; outside address list "
                          f"{'complete' if ref['complete'] else 'partial'}. See {technical_name}, Fleet host "
                          f"appendix, finding {finding['id']}, for every retained outside address.")
            else:
                paragraph(f"{amount} reporting hosts retained; host list {'complete' if ref['complete'] else 'partial'}. "
                          f"See {technical_name}, Fleet host appendix, finding {finding['id']}, for every retained host.")
        for check in finding["next_checks"]:
            paragraph("Recommended check: "+check)
    if assessment := m.get("ai_assessment"):
        paragraph("AI assessment", bold=True)
        paragraph(assessment.get("header") or "Template narrative.")
        assessment_body = assessment.get("body") or {}
        confidence = assessment_body.get("confidence") or {}
        if confidence.get("overall"):
            paragraph(f"Overall confidence: {confidence['overall']}")
        steps = []
        for step in assessment_body.get("key_steps") or []:
            sentence = dict(step.get("sentence") or {})
            prefix = " · ".join(str(value) for value in (step.get("time"), step.get("tactic")) if value)
            if prefix:
                sentence["text"] = f"{prefix}: {sentence.get('text', '')}"
            steps.append(sentence)
        for title, sentences in (
            ("Overall", assessment_body.get("overall") or []), ("Key steps", steps),
            ("Confidence", confidence.get("reasons") or []),
            ("Alternatives", assessment_body.get("alternatives") or []),
            ("Gaps", assessment_body.get("gaps") or []),
            ("Next checks", assessment_body.get("next_checks") or []),
        ):
            if sentences:
                paragraph(title, bold=True)
            for sentence in sentences:
                cites = ", ".join(str(cite) for cite in sentence.get("cites") or [])
                suffix = f" [{cites}]" if cites else ""
                marker = (" Cites only content flagged as possible prompt injection."
                          if sentence.get("suspicious_content") else "")
                paragraph(f"{sentence.get('kind', 'inferred')}: {sentence.get('text', '')}{suffix}{marker}")
        checker = assessment.get("checker") or {}
        paragraph(f"Checker changes: {json.dumps(checker, sort_keys=True) if checker else 'none'}.")
    if visibility := m["coverage"].get("zeek_visibility"):
        ref = visibility["snapshot"]
        paragraph("Zeek sensor visibility", bold=True)
        shown = len(visibility.get('preview', []))
        paragraph(f"Preview of {shown} of {ref['count']} statements; "
                  f"{ref['count']-shown} omitted from this preview. Full text also in {technical_name}.")
        p = SubElement(body, f"{{{_WORD}}}p")
        link = SubElement(p, f"{{{_WORD}}}hyperlink", {
            "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id": "visibility"})
        SubElement(SubElement(link, f"{{{_WORD}}}r"), f"{{{_WORD}}}t").text = ref['filename']
        for note in [*visibility.get("notes", []), *visibility.get("unresolved", [])]:
            paragraph(note)
        for row in visibility.get("preview", []):
            paragraph(row["reason"])
    for link in (m.get("investigations") or {}).get("link_accounting", []):
        if link.get("link_type") in {"zeek_uid", "zeek_file", "certificate", "address_host"}:
            paragraph(f"{link['link_type']}: {link.get('status', 'unresolved')}; " + "; ".join(link.get("reasons", [])))
    paragraph(BANNER)
    section = SubElement(body, f"{{{_WORD}}}sectPr")
    SubElement(section, f"{{{_WORD}}}pgSz", {f"{{{_WORD}}}w": "12240", f"{{{_WORD}}}h": "15840"})
    SubElement(section, f"{{{_WORD}}}pgMar", {f"{{{_WORD}}}{side}": "1440" for side in ("top", "right", "bottom", "left")})
    content_types = ('<?xml version="1.0" encoding="UTF-8"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/word/document.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        '</Types>')
    relationships = ('<?xml version="1.0" encoding="UTF-8"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="word/document.xml"/></Relationships>')
    with ZipFile(path, "w", compression=ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", content_types)
        archive.writestr("_rels/.rels", relationships)
        archive.writestr("word/document.xml", tostring(document, encoding="utf-8", xml_declaration=True))
        if visibility:
            namespace = "http://schemas.openxmlformats.org/package/2006/relationships"
            rels = Element(f"{{{namespace}}}Relationships")
            SubElement(rels, f"{{{namespace}}}Relationship", {
                "Id": "visibility", "Target": visibility["snapshot"]["filename"], "TargetMode": "External",
                "Type": "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink"})
            archive.writestr("word/_rels/document.xml.rels", tostring(rels, encoding="utf-8", xml_declaration=True))
