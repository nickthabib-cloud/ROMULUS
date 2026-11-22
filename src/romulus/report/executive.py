"""Executive Word document rendered from the same immutable report manifest.

Layout: a title page, the bottom line, the hunt's scope, key findings (confirmed or urgent ones first, on their own),
the attack-path picture, the AI assessment and the AI triage view (each labelled as AI output), the mention pool
(labelled as mentions, never as findings), recommendations, coverage limitations, and an index of every finding.

It formats the manifest and never re-evaluates it. Nothing reportable is left out: sections that show a bounded
selection say how many items they do not show and where those are, and the finding index lists every finding. All
manifest text is untrusted and is written only as escaped text nodes (see `romulus.report.ooxml`).
"""
import json
from collections import Counter
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

from romulus.detect.netdef import coverage_shown
from romulus.evidence.raw_citation import RAW_LABEL_PLURAL
from romulus.report import attack_path, ooxml
from romulus.report.markdown import (
    BANNER,
    MENTION_SECTION_TITLE,
    NARRATIVE_EMPTY,
    NARRATIVE_NOTE,
    NARRATIVE_TITLE,
    cite_text,
    is_ranked,
    narrative_context_reason,
    narrative_heading,
    narrative_muted,
    narrative_step_label,
    narrative_step_text,
    narrative_steps_more,
    narrative_support,
    narrative_weak_reason,
    outcome_sentence,
    ranked_sections,
)
from romulus.report.mentions import coverage_lines, snippet
from romulus.report.ooxml import LANE_COLORS, MUTED_COLOR, cell, paragraph, run

_WORD = ooxml.W_NS
# the findings described in full under Key findings, in report order (confirmed or urgent first); every finding is
# listed in the finding index whatever this is
KEY_FINDING_DETAILS = 40
# the top of the mention pool the executive report lists, and the characters of text shown around each match
EXECUTIVE_MENTIONS = 25
EXECUTIVE_MENTION_CHARS = 160
# recommended checks gathered from the findings when no recommendation set is in the manifest
EXECUTIVE_CHECKS = 25
# narrative sentences shown per drawn incident, hypothesis links listed, analyst links listed
INCIDENT_SENTENCES = 12
HYPOTHESIS_LINKS = 40
ANALYST_LINKS = 20
FINDING_INDEX_TITLE = "Appendix A: every finding"
ATTACK_PATH_TITLE = "Attack path"
NO_ATTACK_PATH = "No reportable finding formed an incident, so there is no attack path to draw."
AI_LABEL = ("AI-generated: a model's reading of the cited evidence, not confirmed by an analyst. The deterministic "
            "findings above do not depend on it.")
NO_AI_ASSESSMENT = ("This report carries no AI assessment: none is stored for this hunt. The incident accounts under "
                    "Attack path are template narratives built from typed fields only.")
LANE_TITLES = {"urgent": "Urgent findings", "high": "High findings", "lead": "Investigative leads"}
_FIXED_TIME = (1980, 1, 1, 0, 0, 0)
_FLUSH_BYTES = 1 << 16
_PICTURE_WIDTH_EMU = int(6.5 * ooxml.EMU_PER_INCH)


class _Body:
    """The document body, streamed into its package part in chunks."""

    def __init__(self, stream):
        self.stream, self.chunks, self.size = stream, [], 0

    def add(self, xml: str) -> None:
        self.chunks.append(xml)
        self.size += len(xml)
        if self.size >= _FLUSH_BYTES:
            self.flush()

    def flush(self) -> None:
        self.stream.write("".join(self.chunks).encode("utf-8"))
        self.chunks, self.size = [], 0

    def p(self, value, *, style=None, bold=False, italic=False, color=None, keep_next=False, page_break=False,
          align=None):
        self.add(paragraph(run(value, bold=bold, italic=italic, color=color), style=style, keep_next=keep_next,
                           page_break_before=page_break, align=align))

    def runs(self, runs: str, *, style=None, keep_next=False):
        self.add(paragraph(runs, style=style, keep_next=keep_next))

    def heading(self, value, level: int = 1, *, page_break=False):
        self.add(paragraph(run(value), style=f"Heading{level}", page_break_before=page_break))

    def table(self, header: list[str], widths: list[int], rows) -> int:
        """A grid table; each cell value is text or a dict (text, fill, color, bold). Returns the row count."""
        self.add(ooxml.table_start(widths, header))
        count = 0
        for values in rows:
            cells = []
            for value, width in zip(values, widths, strict=True):
                spec = value if isinstance(value, dict) else {"text": value}
                cells.append(cell(paragraph(run(spec.get("text", ""), bold=spec.get("bold", False),
                                                color=spec.get("color")), style="TableText"),
                                  width, fill=spec.get("fill")))
            self.add(ooxml.table_row(cells))
            count += 1
        if not count:
            self.add(ooxml.table_row([cell(paragraph(run("none"), style="TableText"), width) for width in widths]))
        self.add(ooxml.TABLE_END)
        # a paragraph after every table keeps two tables from merging and gives Word a place for the cursor
        self.add(paragraph(style="TableText"))
        return count


def _lane_badge(lane) -> dict:
    color = LANE_COLORS.get(str(lane))
    return {"text": str(lane), "fill": color, "color": "FFFFFF", "bold": True} if color else {"text": str(lane)}


def _time(value) -> str:
    return str(value)[:19] if value else "not recorded"


def _where(finding: dict, ranked: bool) -> str:
    if ranked:
        entity = finding.get("entity") or {}
        return f"{entity.get('kind')}:{entity.get('value')}" if entity.get("value") is not None else "unattributed"
    entities = finding.get("entities") or []
    hosts = [str(item[1]) for item in entities if len(item) > 1 and item[0] == "host"]
    if hosts:
        return ", ".join(hosts[:3]) + (f" and {len(hosts) - 3} more" if len(hosts) > 3 else "")
    if entities and len(entities[0]) > 1:
        return f"{entities[0][0]}:{entities[0][1]}"
    return "no entity recorded"


def report_order(m: dict) -> list[tuple[str, str, list[dict]]]:
    """The findings in report order, as (section title, section intro, findings). Every finding is in exactly one
    section: confirmed, reported and ranked-pool sections for a ranked report, lanes otherwise."""
    if is_ranked(m):
        confirmed, reported, pool = ranked_sections(m)
        return [("Confirmed", "Confirmed findings, reported on their own whatever their entity.", confirmed),
                ("Reported entities", "Findings on entities that meet the evidence bar, in rank order.", reported),
                ("Ranked findings (not reported)", "Leads below the evidence bar, in rank order.", pool)]
    by_lane: dict[str, list[dict]] = {}
    for finding in m["findings"]:
        by_lane.setdefault(finding["lane"], []).append(finding)
    sections = []
    for lane, findings in by_lane.items():
        intro = ("Strong indicators, reported on their own." if lane == "urgent" else
                 "Findings an analyst should review." if lane == "high" else
                 "Investigative leads for review." if lane == "lead" else "")
        sections.append((LANE_TITLES.get(lane, f"Findings in lane {lane}"), intro, findings))
    return sections


def _numbers(sections) -> dict[str, int]:
    numbers, index = {}, 0
    for _title, _intro, findings in sections:
        for finding in findings:
            index += 1
            numbers[finding["id"]] = index
    return numbers


def _title_page(body: _Body, m: dict, technical_name: str) -> None:
    hunt, revision = m["hunt"], m.get("revision") or {}
    body.p(BANNER, style="Banner")
    body.p("ROMULUS executive report", style="Title")
    body.p(f"Hunt {hunt['id']} — revision {revision.get('number')}", style="Subtitle")
    window = hunt.get("window") or {}
    rows = [("Hunt window (UTC)", f"{window.get('start')} to {window.get('end')}"),
            ("Sources", ", ".join(str(target) for target in hunt.get("targets") or []) or "none recorded"),
            ("Execution state", m.get("execution_state")), ("Detection result", m.get("detection_result")),
            ("Report revision", revision.get("id") or revision.get("number")),
            ("Generated by", m.get("generated_by")),
            ("Technical report", technical_name)]
    body.table(["Item", "Value"], [2600, 6760], ([label, "" if value is None else str(value)] for label, value in rows))
    body.p("This report summarises the hunt for leadership. The technical report holds every finding's evidence, "
           "citations and the full coverage tables.", style="Muted")


def _bottom_line(body: _Body, m: dict, technical_name: str, sections, plan: dict) -> None:
    body.heading("Bottom line up front", page_break=True)
    body.p(outcome_sentence(m), style="Callout")
    deterministic = [finding for finding in m["findings"] if finding.get("provenance", "deterministic") != "agent"]
    lanes = Counter(finding["lane"] for finding in deterministic)
    agent = len(m["findings"]) - len(deterministic)
    mentions = m.get("mentions")
    coverage = m.get("coverage") or {}
    assessment = m.get("ai_assessment") or {}
    counts = plan["counts"]
    multi_step = sum(len(item.get("finding_ids") or []) > 1
                     for item in (m.get("incident_graph") or {}).get("incidents") or [])
    rows = [[_lane_badge(lane), str(lanes[lane])] for lane in ("urgent", "high", "lead")]
    rows += [[_lane_badge(lane), str(count)] for lane, count in sorted(lanes.items())
             if lane not in ("urgent", "high", "lead")]
    rows += [["Findings the AI agent added (unconfirmed)", str(agent)],
             ["Incidents (linked by observed evidence)",
              f"{counts['incidents']} ({multi_step} with more than one finding)"],
             ["Mentions kept (text records contain, not findings)",
              f"{mentions['total']} ({mentions.get('status_text') or mentions.get('status')})" if mentions
              else "not part of this report"],
             ["Coverage gaps (partitions not fully searched)", str(len(coverage.get("gaps") or []))],
             ["Data not assessed (rows)", str(len(coverage.get("not_assessed") or []))],
             ["AI assessment status", "AI-generated, unconfirmed" if assessment.get("source") == "agent" else
              "template narrative" if assessment else "none"],
             ["Report integrity", "complete" if m["integrity"]["finalizable"] else "degraded"]]
    body.table(["Measure", "Count"], [6200, 3160], rows)
    if not m["integrity"]["finalizable"]:
        body.p("Degraded report: incomplete evidence or host lists are identified in the technical report.",
               style="Callout")
    first = next((findings for _title, _intro, findings in sections if findings), [])
    urgent = sum(finding["lane"] == "urgent" for finding in m["findings"])
    if urgent:
        body.p(f"Act first on the {urgent} urgent or confirmed finding(s) under Key findings; each lists the checks "
               "its rule recommends.")
    elif first:
        body.p("Review the findings under Key findings in the order shown; each lists the checks its rule "
               "recommends.")
    body.p(f"Technical report: {technical_name}. This contains the full findings, citations and coverage gaps.")


def _scope(body: _Body, m: dict) -> None:
    hunt = m["hunt"]
    body.heading("Hunt scope")
    window = hunt.get("window") or {}
    body.p(f"ROMULUS searched {', '.join(str(target) for target in hunt.get('targets') or []) or 'no recorded source'} "
           f"from {window.get('start')} to {window.get('end')} (UTC, half-open window).")
    if hunt.get("hypothesis"):
        body.p(f"Hunt hypothesis: {hunt['hypothesis']}")
    if m.get("stop_reason"):
        body.p(f"Stop reason: {m['stop_reason']}")
    for egress in m.get("banners") or []:
        body.p(f"Model egress: {egress}", style="Muted")
    network = (m.get("internal_networks") or {})
    if network.get("warning"):
        body.p(f"Internal networks: {network['warning']}", style="Callout")
    network_coverage = (m.get("coverage") or {}).get("internal_networks") or {}
    if coverage_shown(network_coverage):
        body.heading("Internal-network coverage", 2)
        body.p(network_coverage["summary"])
    coverage = m.get("coverage") or {}
    body.p(f"Not examined, or examined only in part: {len(coverage.get('gaps') or [])} coverage gap(s) and "
           f"{len(coverage.get('not_assessed') or [])} row(s) of data not assessed. They are listed under Coverage "
           "limitations; what was not searched is unknown, not absent.")


def open_ends_text(incident: dict) -> str:
    """What an incident's expansion left open, in a few words ("none" when nothing is open)."""
    ends = incident.get("open_ends") or {}
    parts = [(len(ends.get("unexpanded_anchors") or []) + len(ends.get("pending_anchors") or []),
              "anchor(s) not expanded"),
             (len(ends.get("partial_anchors") or []), "expanded in part"),
             (len(ends.get("unresolved_links") or []), "link(s) not resolved")]
    return "; ".join(f"{count} {words}" for count, words in parts if count) or "none"


def _finding_card(body: _Body, finding: dict, number: int, ranked: bool, technical_name: str) -> None:
    body.add(paragraph(run(f"{number}. {finding.get('rule_title') or finding['rule_id']}"), style="Heading3"))
    lane = finding["lane"]
    badge = run(str(lane).upper(), bold=True, color=LANE_COLORS.get(str(lane)))
    estimate = "rule estimate" if ranked else "lane"
    body.runs(badge + run(f" ({estimate}) · severity {finding.get('severity')} · confidence "
                          f"{finding.get('confidence')} · {_where(finding, ranked)} · observed "
                          f"{_time(finding.get('observed_at'))} · finding {finding['id']} · rule {finding['rule_id']}",
                          color=MUTED_COLOR))
    if finding.get("provenance") == "agent":
        body.p(f"{finding.get('label') or 'Agent finding'}: proposed by the AI agent, not confirmed.",
               style="AiCallout")
    body.p(finding["claim"])
    if raws := finding.get("raw_citations"):
        # source references only: the record text stays in the technical report, fenced
        shown = ", ".join(f"{raw.get('target', '')}/{raw.get('native_id', '')}" if raw["status"] == "retained"
                          else f"{raw['id']} ({raw['status']})" for raw in raws[:5])
        more = f", and {len(raws) - 5} more" if len(raws) > 5 else ""
        body.p(f"Cites {len(raws)} {RAW_LABEL_PLURAL}. Sources: {shown}{more}. Their text is in {technical_name}.",
               style="Muted")
    if ref := finding.get("fleet_hosts"):
        amount = str(ref["count"]) if ref["complete"] else f"{ref['count']} of {ref['expected_count']}"
        side = {"external_address": "outside", "internal_address": "internal"}.get(finding.get("fleet_member_kind"))
        if side:
            body.p(f"{amount} {side} addresses retained; {side} address list "
                   f"{'complete' if ref['complete'] else 'partial'}. See {technical_name}, Fleet host "
                   f"appendix, finding {finding['id']}, for every retained {side} address.")
        else:
            body.p(f"{amount} reporting hosts retained; host list {'complete' if ref['complete'] else 'partial'}. "
                   f"See {technical_name}, Fleet host appendix, finding {finding['id']}, for every retained host.")
    for check in finding.get("next_checks") or []:
        body.p("Recommended check: " + str(check), style="ListLine")


def _key_findings(body: _Body, m: dict, sections, numbers: dict, technical_name: str) -> None:
    ranked = is_ranked(m)
    body.heading("Key findings")
    if ranked:
        body.p("Findings are ordered by the evidence in this hunt. The lane shown is each rule's own estimate; "
               "ranking orders and groups findings and leaves none out.")
    else:
        body.p("Urgent findings come first and are reported on their own; then high findings, then investigative "
               "leads, by priority within a lane.")
    budget = KEY_FINDING_DETAILS
    for title, intro, findings in sections:
        body.heading(title, 2)
        if intro:
            body.p(intro)
        if not findings:
            body.p("None.")
            continue
        shown = findings[:max(0, budget)]
        budget -= len(shown)
        for finding in shown:
            _finding_card(body, finding, numbers[finding["id"]], ranked, technical_name)
        if len(shown) < len(findings):
            body.p(f"{len(shown)} of {len(findings)} finding(s) in this section are described here; the other "
                   f"{len(findings) - len(shown)} are listed in {FINDING_INDEX_TITLE} with their lane and claim, and "
                   f"in full in {technical_name}.", style="Callout")


def _attack_path(body: _Body, m: dict, plan: dict, technical_name: str, image_rel: str | None) -> None:
    body.heading(ATTACK_PATH_TITLE)
    counts = plan["counts"]
    if not plan["rows"]:
        body.p(NO_ATTACK_PATH)
        return
    body.p("Incidents join findings only through observed typed links. Each row is one incident; each box is a "
           "finding, numbered by its row in the finding index and coloured by lane. Solid arrows are observed links. "
           "Dashed arrows marked H are hypotheses: inferred links that are not shown to be the same actor.")
    if image_rel:
        body.add(paragraph(ooxml.inline_image(image_rel, _PICTURE_WIDTH_EMU, plan["height_emu"], 1,
                                              "attack-path.png", "Attack path diagram"), align="center"))
    body.p("Figure 1. Attack path: incidents in rows, steps in time order. Solid = observed link; dashed with H = "
           "hypothesis (inferred, not proven); grey = time order only.", style="Caption")
    if attack_path.everything_drawn(counts):
        # drawn in full is a statement about the picture, not about the attack: what was linked, not all that happened
        body.p("The picture draws every incident, finding and link the incident graph records. It shows what was "
               "linked, not a complete account of the activity.", style="Muted")
    else:
        body.p(f"Drawn: {counts['incidents_drawn']} of {counts['incidents']} incident(s), "
               f"{counts['findings_drawn']} of {counts['findings']} finding(s) in incidents, "
               f"{counts['observed_drawn']} of {counts['observed_links']} observed link(s) and "
               f"{counts['hypothesis_drawn']} of {counts['hypothesis_links']} hypothesis link(s). Every finding is "
               f"in {FINDING_INDEX_TITLE}; incidents not drawn are in {technical_name} (Incidents).", style="Callout")
        not_drawn = counts["not_drawn"]
        for key, text in (
                ("listed_here", ("link(s) between drawn boxes are not drawn, because their rows are not adjacent "
                                 "or a box has no free connection point; they are listed under Links not drawn below")),
                ("beyond_picture", (f"link(s) reach an incident or step that is not drawn; they are in "
                                    f"{technical_name} (Incidents and Expansion links)")),
                ("outside_incidents", ("AI-agent link(s) join a finding to an entity, or to a finding in no "
                                       f"incident; they are in {technical_name} (Agent hypothesis edges)")),
                ("agent_cites", ("AI-agent citation(s): an agent finding cites the evidence of another finding; "
                                 f"each agent finding and what it cites are in {technical_name} (Finding details)"))):
            if not_drawn.get(key):
                body.p(f"{not_drawn[key]} {text}.", style="ListLine")
    by_id, numbers = plan["by_id"], plan["numbers"]
    open_rows = [row for row in plan["rows"] if open_ends_text(row["incident"]) != "none"]
    if open_rows:
        body.p(f"{len(open_rows)} drawn incident(s) have open ends: anchors not expanded, expanded only in part, or "
               "links not fully resolved. Their accounts may be incomplete (Open ends column).", style="Callout")
    body.heading("Incidents drawn", 2)
    body.table(["Row", "Incident", "Steps drawn", "Hosts", "Accounts", "ATT&CK tactics", "Observed / inferred links",
                "Open ends"],
               [550, 1300, 800, 1500, 1100, 1400, 1110, 1600],
               ([row["label"], row["incident"].get("id"), f"{len(row['steps'])} of {row['total_steps']}",
                 ", ".join(row["incident"].get("hosts") or []) or "none",
                 ", ".join(row["incident"].get("accounts") or []) or "none",
                 ", ".join(row["incident"].get("attack_tactics") or []) or "none",
                 f"{row['incident'].get('observed_edges', 0)} / {row['incident'].get('inferred_edges', 0)}",
                 open_ends_text(row["incident"])]
                for row in plan["rows"]))
    body.heading("Steps drawn", 2)
    body.table(["Box", "Row", "Finding", "Lane", "Rule", "Time (UTC)"], [700, 600, 2000, 1000, 3260, 1800],
               ([f"F{numbers.get(item, '?')}", row["label"], item, _lane_badge(by_id.get(item, {}).get("lane")),
                 by_id.get(item, {}).get("rule_title") or by_id.get(item, {}).get("rule_id") or "not in this report",
                 _time(by_id.get(item, {}).get("observed_at"))]
                for row in plan["rows"] for item in row["steps"]))
    hypotheses = [edge for edge in plan["edges"] if edge["style"] == "hypothesis"]
    if hypotheses:
        body.heading("Hypothesis links drawn", 2)
        for edge in hypotheses[:HYPOTHESIS_LINKS]:
            body.p(f"H: F{numbers.get(edge['from'], '?')} to F{numbers.get(edge['to'], '?')} "
                   f"({str(edge['link_type']).replace('_', ' ') or 'link'}): a hypothesis, not proven "
                   f"(findings {edge['from']} and {edge['to']}).", style="ListLine")
        if len(hypotheses) > HYPOTHESIS_LINKS:
            body.p(f"{len(hypotheses) - HYPOTHESIS_LINKS} more drawn hypothesis link(s) are listed in "
                   f"{technical_name}.", style="Muted")
    if unrouted := plan["unrouted"]:
        body.heading("Links not drawn", 2)
        for link in unrouted[:HYPOTHESIS_LINKS]:
            kind = "observed link" if link["style"] == "observed" else "hypothesis, not proven"
            repeat = f", {link['count']} stored links" if link["count"] > 1 else ""
            body.p(f"F{numbers.get(link['from'], '?')} to F{numbers.get(link['to'], '?')} "
                   f"({str(link['link_type']).replace('_', ' ') or 'link'}): {kind}{repeat} "
                   f"(findings {link['from']} and {link['to']}).", style="ListLine")
        if len(unrouted) > HYPOTHESIS_LINKS:
            body.p(f"{len(unrouted) - HYPOTHESIS_LINKS} more link(s) between drawn boxes are not drawn; they are in "
                   f"{technical_name} (Expansion links, Agent hypothesis edges).", style="Muted")
    narrated = [row["incident"] for row in plan["rows"] if len(row["incident"].get("finding_ids") or []) > 1]
    if narrated:
        body.heading("Incident accounts (template, from typed fields)", 2)
        for row in plan["rows"]:
            incident = row["incident"]
            if len(incident.get("finding_ids") or []) < 2:
                continue
            body.p(f"{row['label']} ({incident.get('id')})", bold=True, keep_next=True)
            # only the observed step sentences are bounded: the mapping, hypothesis and gap sentences (one each,
            # bounded where they are built) always show, so an account never reads as complete when it is not
            observed_shown = 0
            for sentence in incident.get("narrative") or []:
                kind = sentence.get("kind", "observed")
                if kind == "observed":
                    observed_shown += 1
                    if observed_shown > INCIDENT_SENTENCES:
                        continue
                prefix = "" if kind == "observed" else f"{kind}: "
                body.p(prefix + str(sentence.get("text", "")), style="ListLine",
                       color=ooxml.HYPOTHESIS_COLOR if kind == "hypothesis" else None)
            if observed_shown > INCIDENT_SENTENCES:
                body.p(f"{observed_shown - INCIDENT_SENTENCES} more observed step sentence(s) of this account are in "
                       f"{technical_name}.", style="Muted")
    analyst = m.get("analyst_links") or []
    if analyst:
        body.heading("Analyst-asserted links (not proven)", 2)
        for link in analyst[:ANALYST_LINKS]:
            body.p(f"{link.get('from_finding')} to {link.get('to_finding')}: {link.get('relation')}, asserted by "
                   f"{link.get('actor')}; {link.get('status') or 'analyst assertion, not proven'}.", style="ListLine")
        if len(analyst) > ANALYST_LINKS:
            body.p(f"{len(analyst) - ANALYST_LINKS} more analyst link(s) are listed in {technical_name}.",
                   style="Muted")


def _assessment(body: _Body, m: dict) -> None:
    assessment = m.get("ai_assessment")
    body.heading("AI assessment")
    if not assessment:
        body.p(NO_AI_ASSESSMENT)
        return
    body.p(assessment.get("header") or "Template narrative.", style="AiCallout")
    if assessment.get("source") == "agent":
        body.p(AI_LABEL, style="Muted")

    def statement(sentence, *, muted=False):
        cites = ", ".join(cite_text(None, cite) for cite in sentence.get("cites") or [])
        suffix = f" [{cites}]" if cites else ""
        marker = " Cites only content flagged as possible prompt injection." if sentence.get("suspicious_content") else ""
        body.p(f"{sentence.get('kind', 'inferred')}: {sentence.get('text', '')}{suffix}{marker}", style="ListLine",
               italic=muted, color=MUTED_COLOR if muted else None)

    if "narrative" in assessment:
        body.heading(NARRATIVE_TITLE, 2)
        body.p(NARRATIVE_NOTE)
        for number, story in enumerate(assessment["narrative"], 1):
            weak = narrative_weak_reason(story)
            muted = narrative_muted(story)
            body.p(f"{number}. {narrative_heading(story)}", bold=True, italic=muted,
                   color=MUTED_COLOR if muted else None, keep_next=True)
            if weak:
                body.p(weak, italic=True, color=MUTED_COLOR)
            if context := narrative_context_reason(story):
                body.p(context)
            # each finding a context paragraph lifts out: bold and never muted
            for step in story.get("attack_steps") or []:
                body.p(f"{narrative_step_label(step)}: {narrative_step_text(step)} (finding {step.get('finding')})",
                       bold=True, style="ListLine")
            if more := narrative_steps_more(story):
                body.p(more, bold=True)
            # a sentence citing a lifted finding stays in full ink
            for sentence in story["sentences"]:
                statement(sentence, muted=muted and not sentence.get("strong_support"))
            if support := narrative_support(story):
                body.p(support, italic=True, color=MUTED_COLOR)
        if not assessment["narrative"]:
            body.p(NARRATIVE_EMPTY)
        body.heading("Assessment details", 2)
    assessment_body = assessment.get("body") or {}
    confidence = assessment_body.get("confidence") or {}
    if confidence.get("overall"):
        body.p(f"Overall confidence: {confidence['overall']}", bold=True)
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
            body.heading(title, 3)
        for sentence in sentences:
            statement(sentence)
    checker = assessment.get("checker") or {}
    body.p(f"Checker changes: {json.dumps(checker, sort_keys=True) if checker else 'none'}.", style="Muted")


def _triage(body: _Body, m: dict) -> None:
    view = m.get("ai_triage")
    if not view:
        return
    body.heading(view.get("label") or "AI triage order")
    body.p("AI-generated and unconfirmed. A model read one card per rule and primary target and proposed which groups "
           "an analyst should see first. It never reorders, hides or relabels the deterministic findings above: "
           "lanes, ranks, the reported set and citations are unchanged.", style="AiCallout")
    groups = view.get("groups") or {}
    body.p(f"Status: {view.get('status') or 'unknown'}" + (f" ({view['reason']})" if view.get("reason") else "")
           + f". Groups: {groups.get('total', 0)} in total, {groups.get('eligible', 0)} eligible, "
           f"{groups.get('triaged', 0)} triaged, {groups.get('not_triaged', 0)} not triaged (deterministic order "
           f"kept). Assessments: {json.dumps(groups.get('by_assessment') or {}, sort_keys=True)}. Model: "
           f"{(view.get('provider') or {}).get('provider') or 'unknown'}/{view.get('model') or 'unknown'}.")
    if view.get("stale"):
        body.p("Stale: the hunt's findings or order changed after this triage pass.", style="Callout")
    if view.get("verification_error"):
        body.p(f"Unverified: this view could not be checked against the hunt ({view['verification_error']}); the "
               "deterministic order above is authoritative.", style="Callout")
    if (view.get("last_attempt") or {}).get("status") == "failed":
        body.p(f"A later triage attempt failed: {view['last_attempt'].get('reason') or ''}", style="Callout")
    for section in view.get("sections") or []:
        body.heading(section.get("title") or "Section", 2)
        if not section.get("promoted"):
            body.p("No group promoted; the deterministic order stands.")
            continue
        body.table(["Triage #", "Rule", "Target", "Findings moved", "Deterministic position", "Assessment",
                    "Incident label", "Rationale (AI)", "Cites"],
                   [700, 1200, 1100, 1000, 900, 900, 1000, 1660, 900],
                   ([str(group.get("position")), group.get("rule_id"),
                     (f"{(group.get('entity') or {}).get('kind')}:{(group.get('entity') or {}).get('value')}"
                      if (group.get("entity") or {}).get("value") is not None else
                      (group.get("entity") or {}).get("kind") or "unattributed"),
                     ("promoted, nothing cited" if group.get("nothing_cited") else f"{group.get('moved', 0)} moved")
                     + f", {group.get('in_deterministic_place', 0)} in deterministic place",
                     str(group.get("best_position")), group.get("assessment") or "",
                     group.get("incident_label") or "", group.get("rationale") or "",
                     ", ".join(str(item) for item in group.get("cites") or [])]
                    for group in section["promoted"]))


def _mentions(body: _Body, m: dict, technical_name: str) -> None:
    view = m.get("mentions")
    if not view:
        return
    body.heading(MENTION_SECTION_TITLE)
    body.p(f"{view['label']}.", style="Muted")
    body.p(f"{view['lane_note']}.", style="Muted")
    items = view.get("items") or []
    shown = items[:EXECUTIVE_MENTIONS]
    body.p(f"{view['total']} mention(s) kept; coverage {view.get('status_text') or view['status']}. {len(shown)} "
           f"listed here; the other {view['total'] - len(shown)} are in {technical_name} (its top mentions) and on "
           "the web Mentions list, which pages through all of them.")
    body.heading("Mention coverage", 2)
    for line in coverage_lines(view):
        body.p(line, style="ListLine")
    if not items:
        body.p("No mention was kept." if view.get("status") != "not_scanned" else
               "Unparsed text was not scanned, so this is not a finding that no mention exists.")
        return
    body.p(f"Order: {view.get('order')}. Each row is text a record contains, matched by a curated pattern: a mention, "
           "not an action and not a finding. The text is untrusted telemetry, shown as data; text flagged as "
           "possible prompt injection is withheld here.", style="Muted")

    def text_of(item):
        if item.get("suspicious_content"):
            return (f"(withheld: flagged as possible prompt injection; raw record {item.get('raw_id')} in "
                    f"{technical_name})")
        line, _at, before, after = snippet(item.get("line") or "", int(item.get("match_at") or 0),
                                           EXECUTIVE_MENTION_CHARS)
        return ("…" if before or item.get("line_from") else "") + line + ("…" if after or item.get("line_cut") else "")

    def pattern_source(item):
        source = (item.get("pattern") or {}).get("source")
        return str((source.get("name") if isinstance(source, dict) else source) or "not recorded")

    def record(item):
        ref = item.get("source_ref") or {}
        return f"{item.get('raw_id')} ({ref.get('target')}/{ref.get('native_id')})"

    body.table(["#", "Mention (pattern)", "Strength", "Pattern source", "Host", "Record (source)", "Lines",
                "First seen (UTC)", "Text around the match"],
               [400, 1500, 700, 1000, 1000, 1300, 500, 1100, 1860],
               ([str(item.get("rank")), f"{item.get('headline')} [{(item.get('pattern') or {}).get('id')}]",
                 (item.get("pattern") or {}).get("strength") or "", pattern_source(item),
                 item.get("host") or "no host", record(item), str(item.get("count")),
                 item.get("first_seen") or "not recorded", text_of(item)] for item in shown))
    if view["total"] > len(shown):
        body.p(f"{view['total'] - len(shown)} more mention(s) not listed here.", style="Muted")


def _recommendations(body: _Body, m: dict, sections, numbers: dict, technical_name: str) -> None:
    """Recommendations from the manifest when it carries them; until then, the checks the rules recommend."""
    body.heading("Recommendations")
    body.p("Suggestions for human decision, never automated actions.", style="Muted")
    items = m.get("recommendations")
    if items:
        known = ("immediate", "near_term", "longer_term")
        groups = [(priority, [item for item in items if item.get("priority") == priority]) for priority in known]
        groups.append(("other", [item for item in items if item.get("priority") not in known]))
        for priority, chosen in groups:
            if not chosen:
                continue
            body.heading(priority.replace("_", "-").capitalize(), 2)
            for item in chosen:
                addressed = ", ".join(f"F{numbers[f]}" if f in numbers else str(f)
                                      for f in item.get("finding_ids") or [])
                mitigations = ", ".join(str(value) for value in item.get("mitigations") or [])
                body.p(str(item.get("text") or "") + (f" (addresses {addressed})" if addressed else "")
                       + (f"; ATT&CK mitigation {mitigations}" if mitigations else ""), style="ListLine")
        return
    body.p("No recommendation set is part of this report revision. The checks the rules recommend for the findings "
           "follow, most common first within report order; each is listed with its finding under Key findings and "
           f"in {technical_name}.")
    checks: dict[str, list[int]] = {}
    for _title, _intro, findings in sections:
        for finding in findings:
            for check in finding.get("next_checks") or []:
                checks.setdefault(str(check), []).append(numbers[finding["id"]])
    ordered = sorted(checks.items(), key=lambda pair: (-len(pair[1]), pair[1][0]))
    for check, rows in ordered[:EXECUTIVE_CHECKS]:
        where = ", ".join(f"F{row}" for row in rows[:6]) + (f" and {len(rows) - 6} more" if len(rows) > 6 else "")
        body.p(f"{check} ({len(rows)} finding(s): {where})", style="ListLine")
    if not ordered:
        body.p("The findings in this report carry no recommended checks.")
    elif len(ordered) > EXECUTIVE_CHECKS:
        body.p(f"{len(ordered) - EXECUTIVE_CHECKS} more distinct check(s) are listed with their findings in "
               f"{technical_name}.", style="Muted")


def _coverage(body: _Body, m: dict, technical_name: str) -> None:
    coverage = m.get("coverage") or {}
    body.heading("Coverage limitations")
    body.p("ROMULUS reports what it finds and never claims that nothing is there. Partitions it searched only in "
           "part, and data no rule read, are its blind spots: what they hold is unknown, not absent.")
    if m.get("execution_state") != "completed_within_scope":
        body.p(f"The hunt is {m.get('execution_state')}: some sources, windows or tasks were not fully searched.",
               style="Callout")
    integrity = m.get("integrity") or {}
    if not integrity.get("finalizable", True):
        body.p("Report integrity: " + ", ".join(f"{key.replace('_', ' ')} {value}" for key, value in integrity.items()
                                                if isinstance(value, int) and not isinstance(value, bool) and value),
               style="Callout")
    results = Counter(str(row.get("search_result")) for row in coverage.get("rules") or [])
    body.heading("Rules by search result", 2)
    body.table(["Search result", "Rules"], [7360, 2000], ([result, str(count)] for result, count in
                                                         sorted(results.items())))
    gaps = coverage.get("gaps") or []
    body.heading("Coverage gaps", 2)
    body.p(f"{len(gaps)} source partition(s) where at least one rule was not fully searched, and why.")

    def named(gap):
        rules = gap.get("rules") or {}
        if gap.get("every_rule_there"):
            return f"every rule evaluated there ({len(rules)})"
        return ", ".join(f"{rule} ({state})" for rule, state in rules.items())

    body.table(["Target", "Partition", "Rules searched in part", "Reasons"], [1700, 1700, 2960, 3000],
               ([gap.get("target"), gap.get("partition"), named(gap), "; ".join(gap.get("reasons") or [])]
                for gap in gaps))
    unassessed = coverage.get("not_assessed") or []
    body.heading("Data not assessed", 2)
    body.p(f"{len(unassessed)} row(s) of data in scope that no rule evaluated. It was not searched and is not counted "
           "as evaluated.")
    body.table(["Target", "Dataset", "Records", "Count scope", "Reason"], [1500, 1700, 1000, 2400, 2760],
               ([item.get("target"), item.get("dataset") or "any",
                 "unknown" if item.get("records") is None else str(item["records"]), item.get("count_scope"),
                 item.get("reason")] for item in unassessed))
    if notes := coverage.get("notes"):
        body.heading("Coverage notes", 2)
        body.p("About records that were retrieved and evaluated. These are not gaps.", style="Muted")
        for item in notes:
            body.p(f"{item.get('target')}: {item.get('note')}", style="ListLine")
    baseline = (coverage.get("baseline") or {}).get("specs") or []
    if baseline:
        body.heading("Baseline snapshot", 2)
        body.table(["Spec", "Status", "Unresolved observations"], [4360, 3000, 2000],
                   ([spec.get("id"), spec.get("status"), str(spec.get("unresolved_count"))] for spec in baseline))
    if visibility := coverage.get("zeek_visibility"):
        ref = visibility["snapshot"]
        body.heading("Zeek sensor visibility", 2)
        shown = len(visibility.get("preview", []))
        body.p(f"Preview of {shown} of {ref['count']} statements; {ref['count'] - shown} omitted from this preview. "
               f"Full text also in {technical_name}.")
        body.add(f'<w:p><w:hyperlink r:id="visibility">{run(ref["filename"], color="1D4ED8")}</w:hyperlink></w:p>')
        for note in [*visibility.get("notes", []), *visibility.get("unresolved", [])]:
            body.p(note, style="ListLine")
        for row in visibility.get("preview", []):
            body.p(row["reason"], style="ListLine")
    links = [link for link in (m.get("investigations") or {}).get("link_accounting", [])
             if link.get("link_type") in {"zeek_uid", "zeek_file", "certificate", "address_host"}]
    if links:
        body.heading("Network link resolution", 2)
        for link in links:
            body.p(f"{link['link_type']}: {link.get('status', 'unresolved')}; " + "; ".join(link.get("reasons", [])),
                   style="ListLine")
    if raw := m.get("raw_records"):
        body.p(f"Raw records kept for citation: {raw.get('stored', 0)} stored, {raw.get('refused_at_cap', 0)} not "
               f"stored at the cap, {len(raw.get('broken') or [])} cited but no longer kept.", style="Muted")
    body.p(f"Context-only items (not listed in this report): {m.get('context_items', 0)}. They remain in the JSON "
           "manifest and the database.", style="Muted")


def _finding_index(body: _Body, m: dict, sections, numbers: dict, technical_name: str) -> None:
    ranked = is_ranked(m)
    body.heading(FINDING_INDEX_TITLE, page_break=True)
    body.p(f"Every finding in this report, {len(numbers)} in all, in report order. The number is the F-number used in "
           f"the attack path. Full evidence for each is in {technical_name}.")
    lane_title = "Lane (rule estimate)" if ranked else "Lane"
    # the section says where each finding stands in the report (for a ranked report: confirmed, reported or not)
    body.table(["#", "Finding", "Section", lane_title, "Severity / confidence", "Time (UTC)", "Rule",
                "Entity or host", "Claim"],
               [450, 1200, 1000, 700, 650, 1000, 1200, 1000, 2160],
               ([str(numbers[finding["id"]]), finding["id"], title, _lane_badge(finding["lane"]),
                 f"{finding.get('severity')} / {finding.get('confidence')}", _time(finding.get("observed_at")),
                 finding.get("rule_title") or finding["rule_id"], _where(finding, ranked),
                 ("Agent finding (AI-proposed, unconfirmed): " if finding.get("provenance") == "agent" else "")
                 + str(finding["claim"])]
                for title, _intro, findings in sections for finding in findings))


def _versions(body: _Body, m: dict) -> None:
    versions = m.get("versions") or {}
    body.heading("Versions", 2)
    body.table(["Component", "Version"], [3000, 6360],
               ([key, str(value)] for key, value in sorted(versions.items()) if not isinstance(value, (dict, list))))


def write(m, path, technical_name):
    """Write the executive DOCX for manifest `m` to `path`; `technical_name` names the technical report beside it."""
    sections = report_order(m)
    numbers = _numbers(sections)
    plan = attack_path.layout(m, numbers)
    image = attack_path.render_png(plan) if plan["rows"] else None
    if image is not None:
        width, height = int.from_bytes(image[16:20], "big"), int.from_bytes(image[20:24], "big")
        plan["height_emu"] = _PICTURE_WIDTH_EMU * height // width
    visibility = (m.get("coverage") or {}).get("zeek_visibility")
    relationships = [("rIdStyles", "styles", "styles.xml", False), ("rIdSettings", "settings", "settings.xml", False),
                     ("rIdHeader", "header", "header1.xml", False), ("rIdFooter", "footer", "footer1.xml", False)]
    if image is not None:
        relationships.append(("rIdAttackPath", "image", "media/attack-path.png", False))
    if visibility:
        # the appendix filename is the visibility snapshot's content digest, checked by the bundle writer
        relationships.append(("visibility", "hyperlink", visibility["snapshot"]["filename"], True))
    title = f"ROMULUS executive report: hunt {m['hunt']['id']}"

    def part(name):
        info = ZipInfo(name, date_time=_FIXED_TIME)
        info.compress_type = ZIP_DEFLATED
        return info

    with ZipFile(path, "w", compression=ZIP_DEFLATED) as archive:
        archive.writestr(part("[Content_Types].xml"), ooxml.content_types(image=image is not None))
        archive.writestr(part("_rels/.rels"), ooxml.PACKAGE_RELS)
        archive.writestr(part("docProps/core.xml"), ooxml.core_properties(title))
        # the body's size is not known before it is written, and a mission-scale report can pass the 2 GiB a plain
        # zip entry can hold, so its entry always carries the zip64 sizes (Word and LibreOffice read them)
        with archive.open(part("word/document.xml"), "w", force_zip64=True) as stream:
            body = _Body(stream)
            body.add(ooxml.DOCUMENT_START)
            _title_page(body, m, technical_name)
            _bottom_line(body, m, technical_name, sections, plan)
            _scope(body, m)
            _key_findings(body, m, sections, numbers, technical_name)
            _attack_path(body, m, plan, technical_name, "rIdAttackPath" if image is not None else None)
            _assessment(body, m)
            _triage(body, m)
            _mentions(body, m, technical_name)
            _recommendations(body, m, sections, numbers, technical_name)
            _coverage(body, m, technical_name)
            _finding_index(body, m, sections, numbers, technical_name)
            _versions(body, m)
            body.p(BANNER, style="Banner")
            body.add(ooxml.document_end("rIdHeader", "rIdFooter"))
            body.flush()
        archive.writestr(part("word/_rels/document.xml.rels"), ooxml.document_rels(relationships))
        archive.writestr(part("word/styles.xml"), ooxml.styles_part())
        archive.writestr(part("word/settings.xml"), ooxml.SETTINGS_PART)
        archive.writestr(part("word/header1.xml"), ooxml.header_part(BANNER))
        archive.writestr(part("word/footer1.xml"), ooxml.footer_part(BANNER, "ROMULUS executive report"))
        if image is not None:
            archive.writestr(part("word/media/attack-path.png"), image)
