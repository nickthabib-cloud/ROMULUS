"""The mention pool as every renderer shows it: labelled as mentions, in its own lane, with its coverage.

One view feeds the report manifest (and through it Markdown and DOCX), the web list and the agent's tools. An item
carries no entity and no ATT&CK technique of its own: the pattern's tags sit under `pattern.attack` with the label
saying they are the pattern's metadata. The line is untrusted telemetry: bounded here, escaped by every renderer.
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
from romulus.evidence.raw_citation import RAW_LABEL

# the mentions the report manifest carries (the web list and the agent's tool page through all of them)
MANIFEST_MENTIONS = 200
MANIFEST_LINE_CHARS = 512
LANE_NOTE = ("the mention lane sits between context and lead: no mention reaches a reportable lane on its own, and "
             "only typed evidence makes an action-level finding")
NOT_SCANNED = {"status": "not_scanned", "reasons": ["the mention sweep did not run for this hunt"]}


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


def mention_item(row: dict, *, line_chars: int = MANIFEST_LINE_CHARS) -> dict:
    """One mention as every renderer shows it."""
    line = row["line"] or ""
    shown = line[:line_chars]
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
        "line": shown, "line_cut": bool(row["line_cut"]) or len(line) > len(shown), "line_chars": row["line_chars"],
        "raw_id": row["raw_id"], "raw_label": RAW_LABEL, "source_ref": {"target": row["target"],
                                                                     "native_id": row["native_id"]},
        "suspicious_content": bool(row["suspicious_content"]),
    }


def mentions_view(repo, hunt_id: str, *, limit: int = MANIFEST_MENTIONS) -> dict:
    """The pool's header, its coverage and its top `limit` mentions in pool order."""
    summary = repo.mention_scan(hunt_id)
    total = repo.mention_count(hunt_id) if summary is not None else 0
    rows = repo.mentions(hunt_id, limit=limit) if total else []
    coverage = summary if summary is not None else NOT_SCANNED
    return {
        "kind": MENTION_KIND, "lane": MENTION_LANE, "label": MENTION_LABEL, "lane_note": LANE_NOTE,
        "status": coverage.get("status", "not_scanned"), "coverage": coverage,
        "total": total, "shown": len(rows), "not_shown": total - len(rows),
        "order": "pattern strength, then whether the record's telemetry class is one the pattern names, then "
                 "rarity (the pattern's distinct hosts, then its matching lines, fewest first), then first time",
        "items": [mention_item(row) for row in rows],
    }


def coverage_lines(view: dict) -> list[str]:
    """Plain sentences for a renderer: what the pool covers and what it does not."""
    coverage = view.get("coverage") or {}
    status = view.get("status", "not_scanned")
    patterns = coverage.get("patterns") or {}
    out = [f"Status: {status}."]
    if status != "not_scanned" or patterns:
        out.append(f"Patterns loaded: {patterns.get('patterns', 0)} from {len(patterns.get('files') or [])} file(s) "
                   f"(pattern set {str(patterns.get('digest') or 'none')[:16]}).")
        not_scanned = coverage.get("not_scanned") or {}
        out.append(f"Records no normalizer read, offered to the scan: {coverage.get('records_offered', 0)}; lines "
                   f"scanned: {coverage.get('lines_scanned', 0)}; lines matched: {coverage.get('lines_matched', 0)}; "
                   f"mentions kept: {view.get('total', 0)}; matching lines not kept at a cap: "
                   f"{coverage.get('lines_not_kept', 0)}.")
        out.append(f"Not scanned: {not_scanned.get('no_text_field', 0)} record(s) without a text field, "
                   f"{not_scanned.get('no_pattern_for_telemetry', 0)} of a telemetry class no pattern reads, "
                   f"{not_scanned.get('chars_past_bound', 0)} character(s) past the scan bound in "
                   f"{not_scanned.get('lines_cut_at_bound', 0)} line(s). "
                   + str(not_scanned.get("records_not_fetched") or ""))
    out.extend(coverage.get("reasons") or [])
    return out
