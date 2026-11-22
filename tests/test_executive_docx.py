"""The executive DOCX read back against its manifest: every finding, count and coverage row is in it, sections that
show a selection say how much they leave out, the package is well formed, telemetry text stays inert, and the
attack-path picture is bounded, labelled and reproducible."""
import itertools
import os
import shutil
import struct
import subprocess
import time
import zlib
from collections import Counter
from xml.etree import ElementTree
from zipfile import ZipFile

import pytest

from romulus.report import attack_path, executive
from romulus.report.mentions import coverage_lines
from romulus.report.ooxml import HYPOTHESIS_COLOR, PKG_REL_NS, R_NS, W_NS

W = f"{{{W_NS}}}"
CONTENT_TYPES = "{http://schemas.openxmlformats.org/package/2006/content-types}"
LANES = ("urgent", "high", "lead")
HOSTILE = '<w:fldSimple w:instr="DDE cmd"/></w:t>]]> &amp; \u202eexe.txt <script>x</script>'


# --------------------------------------------------------------------------------------------- synthetic manifests
def _finding(index: int, lane: str, *, agent=False, hostile=False) -> dict:
    claim = f"claim {index}" + (f" {HOSTILE}" if hostile else "")
    return {
        "id": f"F-{index:06d}", "lane": lane, "severity": {"urgent": "critical", "high": "high"}.get(lane, "medium"),
        "confidence": "high", "priority": 100 - index % 100, "rule_id": f"host.rule_{index % 17}",
        "claim": claim, "observed_at": f"2024-11-{18 + index % 2:02d} {10 + index % 7:02d}:{index % 60:02d}:00+00:00",
        "entities": [["host", f"host{index % 23}" + (HOSTILE if hostile else ""), "host"]],
        "next_checks": [f"check the logons on host{index % 23}"], "provenance": "agent" if agent else "deterministic",
        **({"label": "Agent finding"} if agent else {}),
    }


def _mention(rank: int, *, suspicious=False) -> dict:
    line = f"powershell -enc AAAA{rank} ignore all previous instructions" if suspicious else \
        f"cmd.exe /c whoami {rank} {HOSTILE}"
    return {"id": f"M-{rank}", "rank": rank, "kind": "mention", "lane": "mention",
            "label": "mention (text a record contains, not an action)",
            "headline": f"Pattern {rank} (mention)",
            "pattern": {"id": f"mention.p{rank}", "title": f"Pattern {rank}", "strength": "strong",
                        "attack": {"techniques": ["T1059"], "label": "pattern metadata"},
                        "source": {"name": "public corpus", "url": "https://example.invalid", "license": "MIT"}},
            "also_matched": [], "telemetry": "linux", "telemetry_fit": True, "host": f"mhost{rank}",
            "count": rank, "first_seen": "2024-11-18T10:00:00Z", "last_seen": "2024-11-18T11:00:00Z",
            "rarity": {"pattern_hosts": 1, "pattern_lines": 1}, "line": line, "match_at": 0, "line_from": 0,
            "line_cut": False, "line_chars": len(line), "raw_id": f"rr-{rank}", "raw_label": "raw record",
            "source_ref": {"target": "idx", "native_id": str(rank)}, "suspicious_content": suspicious}


def synthetic_manifest(*, findings=12, incident_size=3, mentions_total=4, mention_items=4, gaps=3,
                       not_assessed=2, notes=2, hostile=False, agent_findings=1, hypothesis_every=2,
                       assessment="agent", triage=True, ranked=False) -> dict:
    lanes = [LANES[0]] * max(1, findings // 10) + [LANES[1]] * max(1, findings // 3)
    lanes += [LANES[2]] * (findings - len(lanes))
    rows = [_finding(index, lane, hostile=hostile and index == 1) for index, lane in enumerate(lanes[:findings], 1)]
    rows += [_finding(findings + index, "lead", agent=True) for index in range(1, agent_findings + 1)]
    deterministic = [row for row in rows if row["provenance"] != "agent"]
    incidents, edges = [], []
    for start in range(0, len(deterministic), incident_size):
        members = [row["id"] for row in deterministic[start:start + incident_size]]
        incidents.append({
            "id": f"I-{start:06d}", "finding_ids": members, "timeline": members, "entry_point": members[0],
            "attack_techniques": ["T1003"], "attack_tactics": ["credential-access"],
            "hosts": [f"host{start % 23}"], "accounts": [], "link_ids": [],
            "observed_edges": len(members) - 1, "hypothesis_edges": 0, "inferred_edges": 0,
            "open_ends": {"unexpanded_anchors": [], "pending_anchors": [], "partial_anchors": [], "unresolved_links": []},
            "narrative": [{"text": f"{len(members)} finding(s) on host{start % 23}.", "cites": members,
                           "kind": "observed"}],
        })
        edges += [{"id": f"E-{a}-{b}", "from": a, "to": b, "link_id": None, "link_type": "same_process",
                   "style": "observed", "kind": "expansion", "incident_role": "evidence"}
                  for a, b in itertools.pairwise(members)]
    for index, (left, right) in enumerate(itertools.pairwise(incidents)):
        if hypothesis_every and index % hypothesis_every == 0:
            edges.append({"id": f"H-{index}", "from": left["finding_ids"][0], "to": right["finding_ids"][0],
                          "link_id": None, "link_type": "same_account_window", "style": "inferred",
                          "kind": "expansion", "incident_role": "hypothesis"})
    sentence = {"text": "the attacker read credentials" + (f" {HOSTILE}" if hostile else ""), "kind": "inferred",
                "cites": [deterministic[0]["id"]]}
    ai = {"agent": {"source": "agent", "header": "AI-generated hypothesis from the cited evidence. Not confirmed.",
                    "model": {}, "body": {"overall": [sentence], "key_steps": [], "confidence": {"overall": "low",
                                                                                                "reasons": []},
                                          "alternatives": [], "gaps": [], "next_checks": []}, "checker": {}},
          "template": {"source": "template", "header": "Template narrative: no AI assessment was produced (off).",
                       "model": {}, "body": {"overall": []}, "checker": {}},
          None: None}[assessment]
    manifest = {
        "schema": "report-manifest@2",
        "hunt": {"id": "h-synthetic", "style": "sweep", "hypothesis": "", "targets": ["logs-host", "arkime"],
                 "window": {"start": "2024-11-18T10:00:00+00:00", "end": "2024-11-19T10:00:00+00:00"}},
        "revision": {"number": 1, "id": "h-synthetic-r1", "supersedes": None},
        "execution_state": "partial", "detection_result": "reportable_findings", "stop_reason": "done",
        "lane_counts": dict(Counter(row["lane"] for row in deterministic)), "findings": rows, "context_items": 7,
        "coverage": {
            "rules": [{"rule_id": f"host.rule_{n}", "states": {}, "records_evaluated": n,
                       "search_result": "searched in part" if n % 3 == 0 else "searched in full"} for n in range(17)],
            "gaps": [{"target": f"target{n}", "partition": f"2024-11-18 part {n}",
                      "rules": {f"host.rule_{n % 17}": "partial"},
                      "reasons": [f"gap reason {n}" + (f" {HOSTILE}" if hostile and n == 0 else "")]}
                     for n in range(gaps)],
            "not_assessed": [{"target": f"target{n}", "dataset": f"dataset{n}", "records": n * 10 or None,
                              "count_scope": "records retrieved in the hunt window", "reason": f"unassessed {n}"}
                             for n in range(not_assessed)],
            "notes": [{"target": f"target{n}", "records": n, "note": f"coverage note {n}"} for n in range(notes)],
        },
        "integrity": {"broken_citations": 0, "finalizable": True},
        "incident_graph": {"nodes": [], "edges": edges, "links": [], "agent_links": [], "incidents": incidents},
        "analyst_links": [], "versions": {"pack": "61", "romulus": "0.1.0"}, "generated_by": "test", "banners": [],
        "agent": {"status": "disabled"}, "ai_assessment": ai,
    }
    if mentions_total is not None:
        items = [_mention(rank, suspicious=rank == 2) for rank in range(1, mention_items + 1)]
        manifest["mentions"] = {
            "kind": "mention", "lane": "mention", "label": "mention: text a record contains, not an action",
            "lane_note": "the mention lane sits between context and lead", "status": "partial",
            "status_text": "partial",
            "coverage": {"status": "partial", "patterns": {"patterns": 336, "files": [{}], "digest": "ab" * 8},
                         "records_offered": 10, "lines_scanned": 10, "lines_matched": mentions_total,
                         "not_scanned": {}, "reasons": ["the scan stopped at its byte budget"]},
            "total": mentions_total, "shown": len(items), "not_shown": mentions_total - len(items),
            "order": "pattern strength", "items": items, "losses": {"items": [], "more": False, "note": ""}}
    if triage:
        manifest["ai_triage"] = {
            "label": "AI triage order (AI-generated, unconfirmed)", "status": "completed", "stale": True,
            "order_verified": True, "groups": {"total": 3, "eligible": 3, "triaged": 3, "not_triaged": 0},
            "sections": [{"section": 0, "title": "Urgent", "promoted": [{
                "group_id": "G1", "position": 1, "best_position": 9, "rule_id": "host.rule_1",
                "entity": {"kind": "host", "value": "host1"}, "finding_count": 2, "case_findings": 2,
                "finding_ids": [deterministic[0]["id"]], "moved_ids": [deterministic[0]["id"]], "moved": 1,
                "nothing_cited": False, "in_deterministic_place": 1, "assessment": "likely_attack",
                "incident_label": "credential theft", "rationale": "triage rationale" + (HOSTILE if hostile else ""),
                "cites": [deterministic[0]["id"]]}]}, {"section": 1, "title": "High", "promoted": []}]}
    if ranked:
        _rank(manifest)
    return manifest


def _rank(manifest: dict) -> None:
    """An evidence ranking over the findings: every third non-urgent finding's entity is reported."""
    entities = {}
    for position, finding in enumerate(manifest["findings"], 1):
        host = finding["entities"][0][1]
        reported = finding["lane"] == "urgent" or position % 3 == 0
        finding.update(rank=float(10_000 - position), rank_position=position, reported=reported,
                       entity={"kind": "host", "value": host}, rank_reasons=["test rank"])
        entity = entities.setdefault(host, {"kind": "host", "value": host, "position": len(entities) + 1,
                                            "score": 1.0, "reported": False, "confirmed": 0, "tactics": [],
                                            "rules": 1, "cooccurrence": 0, "findings": 0, "reasons": ["test"],
                                            "finding_ids": []})
        entity["reported"] = entity["reported"] or reported
        entity["finding_ids"].append(finding["id"])
    manifest["ranking"] = {"status": "complete", "pass": "final"}
    manifest["entities"] = list(entities.values())


# ------------------------------------------------------------------------------------------------------- read back
def _text(node) -> str:
    return "".join(item.text or "" for item in node.iter(f"{W}t"))


def read_back(path):
    """The body as blocks in order: ("p", style, text) and ("tbl", rows of cell texts)."""
    with ZipFile(path) as archive:
        root = ElementTree.fromstring(archive.read("word/document.xml"))
    blocks = []
    for child in root.find(f"{W}body"):
        if child.tag == f"{W}p":
            style = child.find(f"{W}pPr/{W}pStyle")
            blocks.append(("p", style.get(f"{W}val") if style is not None else None, _text(child)))
        elif child.tag == f"{W}tbl":
            blocks.append(("tbl", [[_text(cell) for cell in row.findall(f"{W}tc")] for row in child.findall(f"{W}tr")]))
    return blocks


def _table_after(blocks, heading: str) -> list[list[str]]:
    start = next(index for index, block in enumerate(blocks)
                 if block[0] == "p" and block[1] and block[1].startswith("Heading") and block[2] == heading)
    return next(block[1] for block in blocks[start + 1:] if block[0] == "tbl")


def _section(blocks, heading: str) -> list:
    start = next(index for index, block in enumerate(blocks)
                 if block[0] == "p" and block[1] == "Heading1" and block[2] == heading)
    end = next((index for index, block in enumerate(blocks[start + 1:], start + 1)
                if block[0] == "p" and block[1] == "Heading1"), len(blocks))
    return blocks[start:end]


def _paragraphs(blocks) -> list[str]:
    return [block[2] for block in blocks if block[0] == "p"]


def _write(tmp_path, manifest, name="executive.docx"):
    path = tmp_path / name
    executive.write(manifest, path, "technical.md")
    return path


def _sections(manifest: dict) -> dict[str, str]:
    """Each finding's report section, from the shared Markdown helpers (ranked) or its lane."""
    from romulus.report.markdown import is_ranked, ranked_sections
    if is_ranked(manifest):
        titles = ("Confirmed", "Reported entities", "Ranked findings (not reported)")
        return {finding["id"]: title for title, rows in zip(titles, ranked_sections(manifest), strict=True)
                for finding in rows}
    return {finding["id"]: executive.LANE_TITLES[finding["lane"]] for finding in manifest["findings"]}


@pytest.mark.parametrize("ranked", [False, True], ids=["lanes", "ranked"])
def test_every_finding_count_and_coverage_row_reads_back(tmp_path, ranked):
    manifest = synthetic_manifest(ranked=ranked)
    blocks = read_back(_write(tmp_path, manifest))
    index = _table_after(blocks, executive.FINDING_INDEX_TITLE)[1:]
    # one index row per finding, matched on exact cell values (an id is never found inside another)
    assert len(index) == len(manifest["findings"])
    assert {row[1]: row[3] for row in index} == {finding["id"]: finding["lane"] for finding in manifest["findings"]}
    assert [int(row[0]) for row in index] == list(range(1, len(index) + 1))
    # each finding's section is the report's: confirmed, reported or not for a ranked report, else its lane
    sections = _sections(manifest)
    assert {row[1]: row[2] for row in index} == sections
    # strong indicators first: urgent (or confirmed) findings precede every other one in report order
    lanes = [row[3] for row in index]
    assert lanes[:lanes.count("urgent")] == ["urgent"] * lanes.count("urgent")
    if ranked:
        order = [row[2] for row in index]
        assert order == sorted(order, key=["Confirmed", "Reported entities",
                                           "Ranked findings (not reported)"].index)
        assert {"Confirmed", "Reported entities", "Ranked findings (not reported)"} <= set(order)
        key = _paragraphs(_section(blocks, "Key findings"))
        assert key.index("Confirmed") < key.index("Reported entities") < key.index("Ranked findings (not reported)")
    else:
        assert lanes == sorted(lanes, key=lambda lane: LANES.index(lane))
    # the bottom-line counts are the manifest's
    glance = dict(tuple(row) for row in _table_after(blocks, "Bottom line up front")[1:])
    deterministic = Counter(f["lane"] for f in manifest["findings"] if f["provenance"] != "agent")
    for lane in LANES:
        assert glance[lane] == str(deterministic[lane])
    assert glance["Findings the AI agent added (unconfirmed)"] == "1"
    assert glance["Mentions kept (text records contain, not findings)"].startswith(f"{manifest['mentions']['total']} ")
    assert glance["Coverage gaps (partitions not fully searched)"] == str(len(manifest["coverage"]["gaps"]))
    assert glance["Data not assessed (rows)"] == str(len(manifest["coverage"]["not_assessed"]))
    # every coverage gap, not-assessed row and coverage note, cell for cell
    gaps = _table_after(blocks, "Coverage gaps")[1:]
    assert [(row[0], row[1], row[3]) for row in gaps] == [
        (gap["target"], gap["partition"], "; ".join(gap["reasons"])) for gap in manifest["coverage"]["gaps"]]
    unassessed = _table_after(blocks, "Data not assessed")[1:]
    assert [(row[0], row[1], row[4]) for row in unassessed] == [
        (row["target"], row["dataset"], row["reason"]) for row in manifest["coverage"]["not_assessed"]]
    text = _paragraphs(blocks)
    for note in manifest["coverage"]["notes"]:
        assert f"{note['target']}: {note['note']}" in text
    results = dict(tuple(row) for row in _table_after(blocks, "Rules by search result")[1:])
    assert results == {key: str(value) for key, value in
                       Counter(row["search_result"] for row in manifest["coverage"]["rules"]).items()}
    assert any("The hunt is partial" in value for value in text)
    # the agent finding keeps its label; mentions are never findings
    assert any(row[8].startswith("Agent finding (AI-proposed, unconfirmed)") for row in index)
    assert not any(row[1].startswith("M-") for row in index)


def test_mentions_are_labelled_counted_and_never_findings(tmp_path):
    manifest = synthetic_manifest(mentions_total=57, mention_items=30)
    blocks = read_back(_write(tmp_path, manifest))
    section = _section(blocks, executive.MENTION_SECTION_TITLE)
    text = _paragraphs(section)
    view = manifest["mentions"]
    assert f"{view['label']}." in text and f"{view['lane_note']}." in text
    shown = min(executive.EXECUTIVE_MENTIONS, len(view["items"]))
    assert any(value.startswith(f"57 mention(s) kept; coverage partial. {shown} listed here; the other {57 - shown} ")
               for value in text)
    assert f"{57 - shown} more mention(s) not listed here." in text
    for line in coverage_lines(view):
        assert line in text
    rows = next(block[1] for block in section if block[0] == "tbl")[1:]
    assert len(rows) == shown
    by_rank = {row[0]: row for row in rows}
    # pattern, strength, source, host, count and the text around the match, labelled as a mention
    assert by_rank["1"][1] == "Pattern 1 (mention) [mention.p1]" and by_rank["1"][2] == "strong"
    assert by_rank["1"][3] == "public corpus" and by_rank["1"][4] == "mhost1" and by_rank["1"][6] == "1"
    assert by_rank["1"][5] == "rr-1 (idx/1)"
    assert by_rank["1"][8].startswith("cmd.exe /c whoami 1")
    # text flagged as possible prompt injection is withheld, and says where the record is
    assert "ignore all previous instructions" not in by_rank["2"][8] and "withheld" in by_rank["2"][8]
    assert "rr-2" in by_rank["2"][8]


def test_ai_output_is_labelled_and_a_hunt_without_the_agent_says_so(tmp_path):
    blocks = read_back(_write(tmp_path, synthetic_manifest(assessment="agent")))
    section = _paragraphs(_section(blocks, "AI assessment"))
    assert executive.AI_LABEL in section
    assert any(value.startswith("inferred: the attacker read credentials [F-") for value in section)
    triage = _paragraphs(_section(blocks, "AI triage order (AI-generated, unconfirmed)"))
    assert any(value.startswith("AI-generated and unconfirmed.") for value in triage)
    assert "Stale: the hunt's findings or order changed after this triage pass." in triage
    assert "No group promoted; the deterministic order stands." in triage
    template = _paragraphs(_section(read_back(_write(tmp_path, synthetic_manifest(assessment="template"), "t.docx")),
                                    "AI assessment"))
    assert "Template narrative: no AI assessment was produced (off)." in template
    assert executive.AI_LABEL not in template
    none = _paragraphs(_section(read_back(_write(tmp_path, synthetic_manifest(assessment=None, triage=False),
                                                 "n.docx")), "AI assessment"))
    assert executive.NO_AI_ASSESSMENT in none


def test_attack_path_draws_observed_and_hypothesis_links_and_lists_its_steps(tmp_path):
    manifest = synthetic_manifest(findings=9, incident_size=3, hypothesis_every=1)
    path = _write(tmp_path, manifest)
    blocks = read_back(path)
    section = _section(blocks, executive.ATTACK_PATH_TITLE)
    text = _paragraphs(section)
    assert "Every incident, finding and link of the incident graph is drawn." in text
    steps = [block[1] for block in section if block[0] == "tbl"][1][1:]
    index = {row[1]: row[0] for row in _table_after(blocks, executive.FINDING_INDEX_TITLE)[1:]}
    # each box carries the finding's row number in the index
    assert all(row[0] == f"F{index[row[2]]}" for row in steps)
    assert len(steps) == 9
    hypotheses = [value for value in text if value.startswith("H: ")]
    assert len(hypotheses) == 2 and all("a hypothesis, not proven" in value for value in hypotheses)
    with ZipFile(path) as archive:
        image = archive.read("word/media/attack-path.png")
        relationships = ElementTree.fromstring(archive.read("word/_rels/document.xml.rels"))
    assert any(rel.get("Target") == "media/attack-path.png" for rel in relationships)
    assert _png_pixels(image)[1].count(bytes.fromhex(HYPOTHESIS_COLOR)) > 0


def test_an_unknown_link_strength_is_drawn_as_a_hypothesis():
    assert attack_path.edge_style({"style": "observed"}) == "observed"
    for style in ("inferred", "agent", "agent_hypothesis", "something new", None):
        assert attack_path.edge_style({"style": style}) == "hypothesis"


def test_no_incident_means_no_picture_and_says_so(tmp_path):
    manifest = synthetic_manifest()
    manifest["incident_graph"] = {"nodes": [], "edges": [], "links": [], "incidents": []}
    path = _write(tmp_path, manifest)
    assert executive.NO_ATTACK_PATH in _paragraphs(read_back(path))
    with ZipFile(path) as archive:
        assert not any(name.startswith("word/media/") for name in archive.namelist())
        assert "png" not in archive.read("[Content_Types].xml").decode()


def _png_pixels(data: bytes) -> tuple[tuple[int, int], bytes]:
    """Check every chunk's CRC and return the size and the unfiltered pixel rows (filter type 0 only)."""
    assert data[:8] == b"\x89PNG\r\n\x1a\n"
    offset, idat, size = 8, b"", None
    while offset < len(data):
        (length,) = struct.unpack(">I", data[offset:offset + 4])
        kind, body = data[offset + 4:offset + 8], data[offset + 8:offset + 8 + length]
        (crc,) = struct.unpack(">I", data[offset + 8 + length:offset + 12 + length])
        assert zlib.crc32(kind + body) == crc
        if kind == b"IHDR":
            size = struct.unpack(">II", body[:8])
            assert body[8:] == b"\x08\x02\x00\x00\x00"
        elif kind == b"IDAT":
            idat += body
        offset += 12 + length
    raw = zlib.decompress(idat)
    width, height = size
    stride = width * 3 + 1
    assert len(raw) == stride * height and all(raw[row * stride] == 0 for row in range(height))
    return size, b"".join(raw[row * stride + 1:(row + 1) * stride] for row in range(height))


def test_large_manifest_renders_bounded_with_honest_overflow_notes(tmp_path):
    manifest = synthetic_manifest(findings=5000, incident_size=40, mentions_total=123_456, mention_items=200,
                                  gaps=400, not_assessed=150, notes=30, agent_findings=25, ranked=True)
    started = time.monotonic()
    path = _write(tmp_path, manifest)
    elapsed = time.monotonic() - started
    assert elapsed < 60, elapsed
    blocks = read_back(path)
    # nothing reportable is lost: every finding is in the index, with its lane
    index = _table_after(blocks, executive.FINDING_INDEX_TITLE)[1:]
    assert {row[1]: row[3] for row in index} == {f["id"]: f["lane"] for f in manifest["findings"]}
    assert {row[1]: row[2] for row in index} == _sections(manifest)
    # key findings describe a bounded number and say how many more there are and where
    key = _section(blocks, "Key findings")
    cards = [block for block in key if block[0] == "p" and block[1] == "Heading3"]
    assert len(cards) == executive.KEY_FINDING_DETAILS
    sections = executive.report_order(manifest)
    described = executive.KEY_FINDING_DETAILS
    for _title, _intro, findings in sections:
        shown = min(len(findings), max(0, described))
        described -= shown
        if shown < len(findings):
            assert any(value.startswith(f"{shown} of {len(findings)} finding(s) in this section are described here; "
                                        f"the other {len(findings) - shown} are listed in ")
                       for value in _paragraphs(key))
    # urgent findings are described first
    urgent = [f["id"] for f in manifest["findings"] if f["lane"] == "urgent"]
    first_cards = [block[2] for block in cards[:len(urgent)]]
    assert len(first_cards) == min(len(urgent), executive.KEY_FINDING_DETAILS)
    # the picture is bounded, and the note names exactly what is not drawn
    numbers = {row[1]: int(row[0]) for row in index}
    plan = attack_path.layout(manifest, numbers)
    counts = plan["counts"]
    assert counts["incidents_drawn"] == attack_path.MAX_INCIDENTS
    assert counts["findings_drawn"] <= attack_path.MAX_INCIDENTS * attack_path.MAX_STEPS
    graph = manifest["incident_graph"]
    assert counts["incidents"] == len(graph["incidents"])
    assert counts["findings"] == sum(len(item["finding_ids"]) for item in graph["incidents"])
    assert counts["observed_links"] == sum(edge["style"] == "observed" for edge in graph["edges"])
    assert counts["hypothesis_links"] == sum(edge["style"] != "observed" for edge in graph["edges"])
    text = _paragraphs(_section(blocks, executive.ATTACK_PATH_TITLE))
    assert any(value.startswith(f"Drawn: {counts['incidents_drawn']} of {counts['incidents']} incident(s), "
                                f"{counts['findings_drawn']} of {counts['findings']} finding(s) in incidents, "
                                f"{counts['observed_drawn']} of {counts['observed_links']} observed link(s) and "
                                f"{counts['hypothesis_drawn']} of {counts['hypothesis_links']} hypothesis link(s).")
               for value in text)
    with ZipFile(path) as archive:
        (width, height), _pixels = _png_pixels(archive.read("word/media/attack-path.png"))
    assert width == attack_path.WIDTH
    assert height <= attack_path.LEGEND_H + attack_path.MAX_INCIDENTS * attack_path.ROW_H + 10
    # an incident longer than a row shows "+N" and its drawn count
    drawn = _table_after(blocks, "Incidents drawn")[1:]
    assert all(row[2] == f"{attack_path.MAX_STEPS - 1} of 40" for row in drawn)
    # mentions: the total and the remainder are stated exactly
    mentions = _paragraphs(_section(blocks, executive.MENTION_SECTION_TITLE))
    assert f"{123_456 - executive.EXECUTIVE_MENTIONS} more mention(s) not listed here." in mentions
    # every coverage row is present
    assert len(_table_after(blocks, "Coverage gaps")) == 401
    assert len(_table_after(blocks, "Data not assessed")) == 151


def test_package_is_well_formed(tmp_path):
    manifest = synthetic_manifest()
    manifest["coverage"]["zeek_visibility"] = {
        "snapshot": {"count": 3, "filename": "zeek-visibility-" + "a" * 64 + ".jsonl", "sha256": "a" * 64},
        "preview": [{"reason": "sensor A: estimated 2 % capture loss"}], "notes": [], "unresolved": []}
    path = _write(tmp_path, manifest)
    with ZipFile(path) as archive:
        names = set(archive.namelist())
        types = ElementTree.fromstring(archive.read("[Content_Types].xml"))
        defaults = {item.get("Extension") for item in types.iter(f"{CONTENT_TYPES}Default")}
        overrides = {item.get("PartName").lstrip("/") for item in types.iter(f"{CONTENT_TYPES}Override")}
        assert all(name.rsplit(".", 1)[-1] in defaults or name in overrides for name in names)
        assert overrides <= names
        package = ElementTree.fromstring(archive.read("_rels/.rels"))
        assert {rel.get("Target") for rel in package.iter(f"{{{PKG_REL_NS}}}Relationship")} <= names
        rels = {rel.get("Id"): rel for rel in ElementTree.fromstring(
            archive.read("word/_rels/document.xml.rels")).iter(f"{{{PKG_REL_NS}}}Relationship")}
        for rel in rels.values():
            if rel.get("TargetMode") == "External":
                assert rel.get("Target") == manifest["coverage"]["zeek_visibility"]["snapshot"]["filename"]
            else:
                assert "word/" + rel.get("Target") in names
        document = ElementTree.fromstring(archive.read("word/document.xml"))
        for part in ("word/styles.xml", "word/settings.xml"):
            ElementTree.fromstring(archive.read(part))
        # the classification banner is on every page: in the header and in the footer
        for part in ("word/header1.xml", "word/footer1.xml"):
            assert executive.BANNER in [_text(p) for p in ElementTree.fromstring(archive.read(part)).iter(f"{W}p")]
        styles = {style.get(f"{W}styleId") for style in ElementTree.fromstring(
            archive.read("word/styles.xml")).iter(f"{W}style")}
    # every relationship reference resolves
    for node in document.iter():
        for key in (f"{{{R_NS}}}id", f"{{{R_NS}}}embed"):
            if node.get(key):
                assert node.get(key) in rels
    body = document.find(f"{W}body")
    assert body[-1].tag == f"{W}sectPr"
    section = [child.tag for child in body[-1]]
    assert section[:2] == [f"{W}headerReference", f"{W}footerReference"]
    # schema order: properties first, a table's grid before its rows, a cell ending in a paragraph
    for node in document.iter():
        children = list(node)
        if node.tag in (f"{W}p", f"{W}r") and children:
            props = f"{W}pPr" if node.tag == f"{W}p" else f"{W}rPr"
            assert all(child.tag != props for child in children[1:])
        if node.tag == f"{W}tbl":
            assert [child.tag for child in children[:2]] == [f"{W}tblPr", f"{W}tblGrid"]
            assert all(child.tag == f"{W}tr" for child in children[2:])
        if node.tag == f"{W}tc":
            assert children[-1].tag == f"{W}p"
        if node.tag in (f"{W}pStyle", f"{W}rStyle", f"{W}tblStyle"):
            assert node.get(f"{W}val") in styles
    # the banner is on every page (header and footer) and opens and closes the body
    text = _paragraphs(read_back(path))
    assert text[0] == executive.BANNER and text[-1] == executive.BANNER


def test_telemetry_text_stays_inert(tmp_path):
    manifest = synthetic_manifest(hostile=True)
    path = _write(tmp_path, manifest, "hostile.docx")
    with ZipFile(path) as archive:
        raw = archive.read("word/document.xml").decode("utf-8")
        rels = archive.read("word/_rels/document.xml.rels").decode("utf-8")
        document = ElementTree.fromstring(raw)
    # no field, hyperlink or external relationship came from the text, and the bidi override is gone
    assert not any(node.tag in (f"{W}fldSimple", f"{W}hyperlink", f"{W}instrText", f"{W}fldChar")
                   for node in document.iter())
    assert "External" not in rels and "<script>" not in raw and "\u202e" not in raw
    words = "\n".join(_paragraphs(read_back(path)))
    for table in (block[1] for block in read_back(path) if block[0] == "tbl"):
        words += "\n".join(cell for row in table for cell in row)
    visible = HOSTILE.replace("\u202e", "")
    # the hostile text is shown literally in the claim, entity, gap reason, triage rationale, mention and assessment
    assert words.count(visible) >= 6
    # nothing telemetry-derived reaches an attribute value
    for node in document.iter():
        for value in node.attrib.values():
            assert "script" not in value and "DDE" not in value


def test_writing_twice_gives_the_same_bytes(tmp_path):
    manifest = synthetic_manifest()
    assert _write(tmp_path, manifest, "a.docx").read_bytes() == _write(tmp_path, manifest, "b.docx").read_bytes()


def _soffice():
    for name in ("soffice", "libreoffice"):
        if found := shutil.which(name):
            return found
    for candidate in (r"C:\Program Files\LibreOffice\program\soffice.exe", "/usr/bin/soffice",
                      "/Applications/LibreOffice.app/Contents/MacOS/soffice"):
        if os.path.exists(candidate):
            return candidate
    return None


@pytest.mark.skipif(_soffice() is None, reason="LibreOffice is not installed")
def test_libreoffice_renders_the_report_to_pages(tmp_path):
    path = _write(tmp_path, synthetic_manifest(findings=60, incident_size=4, mentions_total=40, mention_items=30))
    profile = (tmp_path / "profile").as_uri()
    subprocess.run([_soffice(), f"-env:UserInstallation={profile}", "--headless", "--convert-to", "pdf",
                    "--outdir", str(tmp_path), str(path)], check=True, timeout=300, capture_output=True)
    pdf = (tmp_path / "executive.pdf").read_bytes()
    assert pdf.startswith(b"%PDF")
    pages = pdf.count(b"/Type /Page") - pdf.count(b"/Type /Pages")
    pages = pages if pages > 0 else pdf.count(b"/Type/Page") - pdf.count(b"/Type/Pages")
    assert pages > 1
