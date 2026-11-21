"""The mention pool as every renderer shows it: labelled as mentions, in its own lane, with its coverage.

One view feeds the report manifest (and through it Markdown and DOCX), the web list and the agent's tools. An item
carries no entity and no ATT&CK technique of its own: the pattern's tags sit under `pattern.attack` with the label
saying they are the pattern's metadata. The line is untrusted telemetry: an excerpt around the first match, bounded
here, escaped by every renderer.
"""
from __future__ import annotations

from datetime import UTC, datetime

from romulus.evidence.mentions import (
    MENTION_KIND,
    MENTION_LABEL,
    MENTION_LABEL_SHORT,
    MENTION_LANE,
    PATTERN_ATTACK_LABEL,
)
from romulus.evidence.raw_citation import RAW_MENTION_LABEL

# the mentions the report manifest carries (the web list and the agent's tool page through all of them)
MANIFEST_MENTIONS = 200
MANIFEST_LINE_CHARS = 512
# the (pattern, host) pairs whose lines were not kept that the manifest lists (the web pages through all of them)
MANIFEST_LOSSES = 50
LANE_NOTE = ("the mention lane sits between context and lead: a mention in this pool never reaches a reportable lane "
             "on its own. A lead that rests on raw text appears only when the AI agent read the raw record itself "
             "and judged it: such a lead is labelled a mention, has low confidence and no ATT&CK technique. Only "
             "typed evidence makes an action-level finding")
NOT_SCANNED = {"status": "not_scanned", "reasons": ["the mention sweep did not run for this hunt"]}
STATUS_TEXT = {"scanned_every_offered_record": "scanned every offered record", "partial": "partial",
               "not_scanned": "not scanned"}


def _when(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        value = datetime.fromisoformat(value)
    value = value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    return value.isoformat().replace("+00:00", "Z")


def headline(title: str) -> str:
    """How a mention is named everywhere: its pattern's title, marked as a mention, so it never reads as an action."""
    return f"{title} (mention)"


def snippet(line: str, match_offset: int, chars: int) -> tuple[str, int, bool, bool]:
    """At most `chars` characters of an excerpt around its match: (the text, where the match starts in it, whether
    text before it was left out, whether text after it was left out)."""
    if len(line) <= chars:
        return line, match_offset, False, False
    start = max(0, min(match_offset - chars // 4, len(line) - chars))
    return line[start:start + chars], match_offset - start, start > 0, start + chars < len(line)


def mention_item(row: dict, *, line_chars: int = MANIFEST_LINE_CHARS) -> dict:
    """One mention as every renderer shows it: the excerpt around its first match, at most `line_chars` long."""
    line = row["line"] or ""
    match_offset = int(row.get("match_offset") or 0)
    shown, at, before, after = snippet(line, match_offset, line_chars)
    line_offset = int(row.get("line_offset") or 0)
    return {
        "id": row["id"], "rank": row["rank"], "kind": MENTION_KIND, "lane": MENTION_LANE,
        "label": MENTION_LABEL_SHORT, "headline": headline(row["pattern_title"]),
        "pattern": {"id": row["pattern_id"], "title": row["pattern_title"], "strength": row["strength"],
                    "attack": {"techniques": list(row["pattern_attack"] or []), "label": PATTERN_ATTACK_LABEL},
                    "source": row["pattern_source"]},
        # other patterns the same line matches: metadata of this one mention, never mentions of their own
        "also_matched": list(row.get("also_matched") or []),
        "telemetry": row["telemetry"], "telemetry_fit": bool(row.get("telemetry_fit", True)),
        "host": row["host"] or None, "count": row["count"],
        "first_seen": _when(row["first_ts"]), "last_seen": _when(row["last_ts"]),
        "rarity": {"pattern_hosts": row["pattern_hosts"], "pattern_lines": row["pattern_lines"]},
        # the excerpt shown, where the match starts in it, and where the excerpt starts in the whole line
        "line": shown, "match_at": at, "line_from": line_offset + (match_offset - at),
        "line_cut": bool(row["line_cut"]) or before or after or line_offset > 0, "line_chars": row["line_chars"],
        "raw_id": row["raw_id"], "raw_label": RAW_MENTION_LABEL,
        "source_ref": {"target": row["target"], "native_id": row["native_id"]},
        "suspicious_content": bool(row["suspicious_content"]),
    }


def losses_view(repo, hunt_id: str, *, limit: int = MANIFEST_LOSSES) -> dict:
    """The first page of (pattern, host) pairs whose lines the pool did not keep, strongest patterns first."""
    rows = repo.mention_losses(hunt_id, limit=limit + 1)
    return {"items": [{key: row[key] for key in ("pattern_id", "strength", "host", "lines_not_kept")}
                      for row in rows[:limit]],
            "more": len(rows) > limit,
            "note": ("every (pattern, host) whose lines were not kept is stored and paged on the web Mentions tab; "
                     "pairs past the remembered-pair bound are one row per pattern, their hosts not named")}


def mentions_view(repo, hunt_id: str, *, limit: int = MANIFEST_MENTIONS) -> dict:
    """The pool's header, its coverage and its top `limit` mentions in pool order."""
    summary = repo.mention_scan(hunt_id)
    total = repo.mention_count(hunt_id) if summary is not None else 0
    rows = repo.mentions(hunt_id, limit=limit) if total else []
    coverage = summary if summary is not None else NOT_SCANNED
    status = coverage.get("status", "not_scanned")
    return {
        "kind": MENTION_KIND, "lane": MENTION_LANE, "label": MENTION_LABEL, "lane_note": LANE_NOTE,
        "status": status, "status_text": STATUS_TEXT.get(status, status), "coverage": coverage,
        "total": total, "shown": len(rows), "not_shown": total - len(rows),
        "order": "pattern strength, then whether the record's telemetry class is one the pattern names, then "
                 "rarity (the pattern's distinct hosts, then its matching lines, fewest first), then first time",
        "items": [mention_item(row) for row in rows],
        "losses": losses_view(repo, hunt_id, limit=MANIFEST_LOSSES if limit else 0),
    }


def coverage_lines(view: dict) -> list[str]:
    """Plain sentences for a renderer: what the pool covers and what it does not."""
    coverage = view.get("coverage") or {}
    status = view.get("status", "not_scanned")
    patterns = coverage.get("patterns") or {}
    out = [f"Status: {STATUS_TEXT.get(status, status)} (never a statement that there are no mentions)."]
    if status != "not_scanned" or patterns:
        out.append(f"Patterns loaded: {patterns.get('patterns', 0)} from {len(patterns.get('files') or [])} file(s) "
                   f"(pattern set {str(patterns.get('digest') or 'none')[:16]}).")
        not_scanned = coverage.get("not_scanned") or {}
        out.append(f"Records no normalizer read, offered to the scan: {coverage.get('records_offered', 0)}; lines "
                   f"scanned: {coverage.get('lines_scanned', 0)}; lines matched: {coverage.get('lines_matched', 0)}; "
                   f"mentions kept: {view.get('total', 0)}; matching lines not kept: "
                   f"{coverage.get('lines_not_kept', 0)}.")
        unscanned = sum((not_scanned.get("records") or {}).values())
        out.append(f"Not scanned: {unscanned} record(s) without scannable text, "
                   f"{not_scanned.get('chars_past_bound', 0)} character(s) past the scan bound in "
                   f"{not_scanned.get('lines_cut_at_bound', 0)} line(s), "
                   f"{(coverage.get('unscanned_partitions') or {}).get('count', 0)} partition(s) not read in full, "
                   f"{len(coverage.get('left_out_sources') or [])} source(s) the fetch filters leave out.")
        cut_hosts = not_scanned.get("cut_line_hosts") or []
        if cut_hosts:
            out.append("Hosts of lines cut at the scan bound: " + ", ".join(
                f"{item['host']} ({item['lines']})" for item in cut_hosts) + ".")
        if coverage.get("hosts_with_lines_not_kept"):
            out.append(f"Hosts with matching lines not kept: {coverage['hosts_with_lines_not_kept']} (of them, "
                       f"{coverage.get('hosts_with_strong_lines_not_kept', 0)} lost a strong pattern's lines); each "
                       "is listed with its count on the web Mentions tab, except pairs past the remembered-pair "
                       "bound, which are counted together per pattern.")
    out.extend(coverage.get("reasons") or [])
    return out
