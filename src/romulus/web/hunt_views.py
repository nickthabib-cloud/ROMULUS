"""Read models for the hunt workspace: the header every tab shares and each tab's bounded data.

Each tab reads only what it shows. The Overview and Findings tabs use indexed, bounded queries; the Coverage,
Timeline and Run details tabs reuse the report's own builders, so the page and the report never disagree.
"""
from __future__ import annotations

import re
from urllib.parse import quote, urlencode

from sqlalchemy import func, select

from romulus.report.manifest import UNRESOLVED_STATES
from romulus.store import schema as t
from romulus.store.repo import FINAL_RANK_PASS
from romulus.web import agent_views
from romulus.web.finding_order import (
    RANKED_LANES,
    SEGMENT_TITLES,
    finding_order,
    finding_page,
    ranked_finding_page,
    segment_sizes,
)

# (key, label, path suffix). Every tab is its own URL, so links, the back button and pages without scripts work.
TABS = (("overview", "Overview", ""), ("findings", "Findings", "/findings"),
        ("mentions", "Mentions", "/mentions"),
        ("assessment", "AI assessment", "/assessment"), ("triage", "Triage", "/triage"),
        ("timeline", "Timeline", "/timeline"), ("coverage", "Coverage", "/coverage"), ("run", "Run details", "/run"))
LANES = ("urgent", "high", "lead", "context", "suppressed")
PAGE_SIZE = 50
TOP_FINDINGS = 10
FINDING_COLUMNS = ("id", "lane", "severity", "confidence", "priority", "ts", "rule_id", "claim", "provenance",
                   "agent_hypothesis_id", "entities")
# Report-order segments that hold the Reported set: confirmed (ranked and late) and reported.
REPORTED_SEGMENTS = (0, 1, 2)


def hunt_url(hunt_id: str, suffix: str = "", **params) -> str:
    query = {key: value for key, value in params.items() if value not in (None, "")}
    return "/hunts/" + quote(hunt_id, safe="") + suffix + ("?" + urlencode(query) if query else "")


def one_line(text, limit: int = 140) -> dict:
    """A one-line summary of a long text and whether the full text says more. Whitespace is collapsed; the summary
    ends at the first sentence when that fits, else at a word boundary."""
    full = str(text or "")
    flat = re.sub(r"\s+", " ", full).strip()
    if len(flat) <= limit:
        return {"summary": flat, "more": flat != full.strip()}
    sentence = re.match(rf"(.{{20,{limit}}}?[.;])(\s|$)", flat)
    if sentence:
        return {"summary": sentence.group(1), "more": True}
    cut = flat[:limit].rsplit(" ", 1)[0] or flat[:limit]
    return {"summary": cut + " …", "more": True}


def _entity(entities) -> str | None:
    for item in entities or []:
        if isinstance(item, (list, tuple)) and len(item) >= 2 and (len(item) < 3 or item[2] != "observer"):
            return f"{item[0]}:{item[1]}"
    return None


def _columns():
    return tuple(t.candidate.c[key] for key in FINDING_COLUMNS)


def _decorate(rows):
    for row in rows:
        row["entity_label"] = row.get("entity_label") or (
            f"{row['entity_kind']}:{row['entity']}" if row.get("entity") is not None else _entity(row.get("entities")))
        row.pop("entities", None)
    return rows


# ------------------------------------------------------------------------------------------------------------ header
def header(repo, hunt: dict, user: dict, tab: str) -> dict:
    """What the sticky header shows on every tab: status, live stream state, headline counts and the actions."""
    hunt_id = hunt["id"]
    run = repo.agent_run(hunt_id)
    ai_state = None
    if run is not None:
        ai_state = ("interrupted (lease expired)" if run["state"] == "running" and not repo.agent_lease_live(hunt_id)
                    else run["state"])
    with repo.engine.connect() as connection:
        latest = connection.execute(select(t.report_manifest.c.id, t.report_manifest.c.revision,
                                           t.report_manifest.c.created_at)
                                    .where(t.report_manifest.c.hunt_id == hunt_id)
                                    .order_by(t.report_manifest.c.revision.desc()).limit(1)).mappings().first()
        # one grouped read over ix_candidate_hunt_provenance_lane: deterministic and AI agent findings per lane
        counted = connection.execute(select(t.candidate.c.provenance, t.candidate.c.lane, func.count()).where(
            t.candidate.c.hunt_id == hunt_id).group_by(t.candidate.c.provenance, t.candidate.c.lane)).all()
    lanes, agent_lanes, lanes_all = {}, {}, {}
    for provenance, lane, count in counted:
        target = agent_lanes if provenance == "agent" else lanes
        target[lane] = target.get(lane, 0) + count
        lanes_all[lane] = lanes_all.get(lane, 0) + count
    return {"tab": tab, "tabs": [{"key": key, "label": label, "url": hunt_url(hunt_id, suffix)}
                                 for key, label, suffix in TABS],
            # `lanes` counts deterministic findings (as the live stream does); the lists include agent findings
            "lanes": lanes, "agent_lanes": agent_lanes, "lanes_all": lanes_all,
            "agent_total": sum(agent_lanes.values()),
            "reportable": sum(lanes_all.get(lane, 0) for lane in RANKED_LANES),
            "agent_reportable": sum(agent_lanes.get(lane, 0) for lane in RANKED_LANES),
            "ai_state": ai_state, "has_agent": run is not None,
            "live": agent_views.stream_live(repo, hunt, run), "stream_cursor": repo.agent_change_max_seq(hunt_id),
            "latest_report": dict(latest) if latest else None,
            "reassess_refusal": repo.agent_reassessment_refusal(hunt_id) if run is not None else None,
            "hunt_url": hunt_url}


# ---------------------------------------------------------------------------------------------------------- overview
def overview(repo, hunt: dict) -> dict:
    """Headline counts, the top Reported findings in report order and the same findings in time order, the AI
    assessment's overall statements, and one-line pointers to run notices. Every read here is bounded."""
    hunt_id = hunt["id"]
    ranked = repo.has_rank_pass(hunt_id, FINAL_RANK_PASS)
    if ranked:
        rows, _, _ = ranked_finding_page(repo, hunt_id, pass_no=FINAL_RANK_PASS, limit=TOP_FINDINGS,
                                         columns=_columns())
        top = [row for row in rows if row["segment"] in REPORTED_SEGMENTS]
        sizes = segment_sizes(repo, hunt_id, pass_no=FINAL_RANK_PASS)
        reported_total = sum(sizes[index] for index in REPORTED_SEGMENTS)
        sections = [{"title": "confirmed", "count": sizes[0] + sizes[1]},
                    {"title": "reported", "count": sizes[2]},
                    {"title": "ranked, not reported", "count": sizes[3]},
                    {"title": "not ranked", "count": sizes[4]}]
    else:
        top, more, _ = finding_page(repo, hunt_id, limit=TOP_FINDINGS, columns=_columns(),
                                    predicates=(finding_order()[0][0] < len(RANKED_LANES),))
        reported_total = len(top) + more
        sections = []
    _decorate(top)
    view = agent_views.assessment_view(repo, hunt_id)
    overall = next((section for section in (view or {}).get("sections", []) if section["name"] == "overall"), None)
    agent_audit = repo.latest_audit(hunt_id, "hunt.agent_summary")
    with repo.engine.connect() as connection:
        # any model call that left the host, whichever pass made it (the agent or a separately configured triage)
        remote_calls = connection.execute(select(t.model_call.c.id).where(
            t.model_call.c.hunt_id == hunt_id, t.model_call.c.egress == "remote").limit(1)).first() is not None
    configured = hunt["manifest"].get("ai_agent") or {}
    flags = ((agent_audit or {}).get("detail") or {}).get("analyst_flags") or []
    return {"ranked": ranked, "top": top, "top_more": max(0, reported_total - len(top)),
            "reported_total": reported_total, "sections": sections,
            "chronological": sorted(top, key=lambda row: (row["ts"] is None, str(row["ts"] or ""), row["id"])),
            "assessment": view, "overall": overall, "remote_calls": remote_calls,
            "remote_configured": configured.get("egress") == "remote" and bool(configured.get("requested")),
            "analyst_flags": [{"case_id": agent_views.clip(flag.get("case_id"), 200),
                               "message": agent_views.clip(flag.get("message") or flag.get("reason"), 600)}
                              for flag in flags[:20] if isinstance(flag, dict)],
            "analyst_flags_more": max(0, len(flags) - 20)}


def reports(repo, hunt_id: str) -> list[dict]:
    with repo.engine.connect() as connection:
        return [dict(row) for row in connection.execute(
            select(t.report_manifest.c.id, t.report_manifest.c.revision, t.report_manifest.c.created_at)
            .where(t.report_manifest.c.hunt_id == hunt_id).order_by(t.report_manifest.c.revision.desc())).mappings()]


# ---------------------------------------------------------------------------------------------------------- findings
def findings(repo, hunt_id: str, *, lane: str = "", rule: str = "", after: str = "") -> dict:
    """One page of findings. Without filters, the Reported findings in report order when the hunt has its final
    ranking, else in the rule estimate's order; with a lane or rule filter, in the rule estimate's order. Raises
    ValueError for a cursor that does not belong to the listing."""
    lane = lane if lane in LANES else ""
    rule = rule.strip()[:256]
    columns = _columns()
    rule_where = (t.candidate.c.rule_id == rule,) if rule else ()
    has_rank = repo.has_rank_pass(hunt_id, FINAL_RANK_PASS)
    ranked = not lane and not rule and has_rank
    if ranked:
        rows, more, cursor = ranked_finding_page(repo, hunt_id, pass_no=FINAL_RANK_PASS, after=after,
                                                 columns=columns)
    elif lane in RANKED_LANES:
        # a ranked lane is selected by its rank in the order index (the same rows as lane == it)
        rows, more, cursor = finding_page(repo, hunt_id, after=after, columns=columns, lane=lane,
                                          predicates=rule_where)
    elif lane:
        rows, more, cursor = finding_page(repo, hunt_id, after=after, columns=columns,
                                          predicates=(t.candidate.c.lane == lane, *rule_where))
    else:
        rows, more, cursor = finding_page(repo, hunt_id, after=after, columns=columns,
                                          predicates=(finding_order()[0][0] < len(RANKED_LANES), *rule_where))
    _decorate(rows)
    return {"rows": rows, "more": more, "lane": lane, "rule": rule, "ranked": ranked, "has_rank": has_rank,
            "after": after,
            "segment_titles": SEGMENT_TITLES,
            "next_url": hunt_url(hunt_id, "/findings", lane=lane, rule=rule, after=cursor) if cursor else None,
            "first_url": hunt_url(hunt_id, "/findings", lane=lane, rule=rule) if after else None}


# ---------------------------------------------------------------------------------------------------------- coverage
COVERAGE_CLASSES = (("attention", "Searched in part or unresolved"), ("matched", "Rule matched"),
                    ("positive", "Positive-only"), ("full", "Searched in full"), ("none", "No data in scope"))


def coverage_class(row: dict) -> str:
    result = str(row.get("search_result") or "")
    if (result.startswith("searched in part") or "coverage incomplete" in result
            or any(state in UNRESOLVED_STATES for state in row.get("states") or {})):
        return "attention"
    if result.startswith("none (rule matched)"):
        return "matched"
    if result.startswith("searched in full"):
        return "full"
    if result.startswith("no data in scope"):
        return "none"
    return "positive"


def coverage_page(rows: list[dict], *, show: str = "", page: int = 1) -> dict:
    """Per-rule coverage rows, those searched in part or unresolved first, then the rest in rule order; one page of
    them with the count of every class, so every row stays reachable."""
    order = {key: index for index, (key, _) in enumerate(COVERAGE_CLASSES)}
    classified = sorted(({**row, "class": coverage_class(row)} for row in rows),
                        key=lambda row: (row["class"] != "attention", order[row["class"]], row["rule_id"]))
    counts = {key: 0 for key, _ in COVERAGE_CLASSES}
    for row in classified:
        counts[row["class"]] += 1
    show = show if show in counts else ""
    selected = [row for row in classified if not show or row["class"] == show]
    pages = max(1, -(-len(selected) // PAGE_SIZE))
    page = min(max(1, page), pages)
    start = (page - 1) * PAGE_SIZE
    return {"rows": selected[start:start + PAGE_SIZE], "total": len(selected), "all": len(classified),
            "first": start + 1 if selected else 0, "last": min(start + PAGE_SIZE, len(selected)),
            "page": page, "pages": pages, "show": show, "counts": counts, "classes": COVERAGE_CLASSES,
            "more": max(0, len(selected) - start - PAGE_SIZE)}


# --------------------------------------------------------------------------------------------------------- run details
DETAIL_BYTES = 16384


def detail_rows(value, *, limit: int = DETAIL_BYTES) -> list[dict]:
    """A mapping as key/value rows: scalars inline, nested values as a one-line summary with an expandable JSON view
    bounded to `limit` bytes (the report's JSON manifest carries every value in full)."""
    rows = []
    for key, item in (value or {}).items() if isinstance(value, dict) else ():
        if isinstance(item, (list, dict)) and not item:
            rows.append({"key": str(key), "summary": "none", "more": False, "full": "", "json": None})
        elif item is None or isinstance(item, (str, int, float, bool)):
            text = "" if item is None else str(item)
            rows.append({"key": str(key), **one_line(text), "full": text, "json": None})
        else:
            size = len(item) if isinstance(item, (list, dict)) else 0
            noun = "item" if isinstance(item, list) else "field"
            summary = f"{size} {noun}{'' if size == 1 else 's'}"
            if isinstance(item, list) and item and all(isinstance(entry, (str, int, float)) for entry in item):
                summary = one_line(", ".join(str(entry) for entry in item))["summary"]
            rows.append({"key": str(key), "summary": summary, "more": True, "full": None,
                         "json": agent_views.json_text(item, limit)})
    return rows


def tasks_page(repo, hunt_id: str, *, after: str = "") -> dict:
    rows, more, cursor = agent_views.page_rows(repo, t.task, hunt_id, after=after, columns=(
        t.task.c.id, t.task.c.kind, t.task.c.state, t.task.c.attempts, t.task.c.outcome, t.task.c.error))
    with repo.engine.connect() as connection:
        states = dict(connection.execute(select(t.task.c.state, func.count()).where(
            t.task.c.hunt_id == hunt_id).group_by(t.task.c.state)).all())
    return {"rows": rows, "more": more, "states": states, "total": sum(states.values()),
            "next_url": hunt_url(hunt_id, "/run", tasks_after=cursor) + "#tasks" if cursor else None,
            "first_url": hunt_url(hunt_id, "/run") + "#tasks" if after else None}
