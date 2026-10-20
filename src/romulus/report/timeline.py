"""Attack-path timeline layout: findings as marks on rows by host, account and IP, over the hunt window.

Pure and deterministic, so the web page (SVG, no scripts) and tests share it. Links keep their provenance:
`observed` (solid), `inferred` (dashed, a hypothesis) and `analyst` (an assertion by an analyst, never shown as
proven). Every filter reports what it hides, and nothing is dropped silently when a page limit is reached.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime

ROW_KINDS = ("host", "account", "ip")
LANES = ("urgent", "high", "lead")
LINK_STYLES = ("observed", "inferred", "analyst")
MAX_ROWS = 60
WIDTH, LEFT, RIGHT, TOP, ROW_H = 1200, 220, 30, 40, 34


def _ts(value) -> datetime:
    dt = value if isinstance(value, datetime) else datetime.fromisoformat(str(value))
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)


def _x(ts: datetime, start: datetime, end: datetime) -> float:
    span = max((end - start).total_seconds(), 1.0)
    frac = min(max((ts - start).total_seconds() / span, 0.0), 1.0)
    return round(LEFT + frac * (WIDTH - LEFT - RIGHT), 1)


def _rows_of(finding: dict) -> list[tuple[str, str]]:
    out = []
    for kind, value, role in finding.get("entities") or []:
        kind = {"account": "account", "host": "host", "ip": "ip"}.get(kind)
        if kind and not (kind == "host" and role == "observer"):       # a sensor saw it; it is not where it ran
            out.append((kind, str(value)))
    return list(dict.fromkeys(out))


def build_timeline(findings: list[dict], edges: list[dict], analyst_links: list[dict], start, end, *,
                   titles: dict[str, str] | None = None, lanes=LANES, kinds=ROW_KINDS, styles=LINK_STYLES) -> dict:
    start, end = _ts(start), _ts(end)
    titles = titles or {}
    lanes, kinds, styles = set(lanes), set(kinds), set(styles)
    reportable = [f for f in findings if f["lane"] in LANES]
    shown = [f for f in reportable if f["lane"] in lanes]
    hidden = {"findings_by_lane": len(reportable) - len(shown), "rows_by_kind": 0, "rows_beyond_page": 0,
              "findings_without_row": 0, "findings_on_hidden_rows": 0, "links_by_style": defaultdict(int), "links_without_both_ends": 0}

    row_items: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for f in sorted(shown, key=lambda f: (_ts(f["observed_at"]), f["id"])):
        rows = _rows_of(f)
        if not rows:
            hidden["findings_without_row"] += 1
        for row in rows:
            row_items[row].append(f)
    all_rows = sorted(row_items, key=lambda r: (ROW_KINDS.index(r[0]), _ts(row_items[r][0]["observed_at"]), r[1]))
    kept = [r for r in all_rows if r[0] in kinds]
    hidden["rows_by_kind"] = len(all_rows) - len(kept)
    hidden["rows_beyond_page"] = max(0, len(kept) - MAX_ROWS)
    kept = kept[:MAX_ROWS]

    rows, primary = [], {}
    for i, (kind, value) in enumerate(kept):
        y = TOP + i * ROW_H + ROW_H // 2
        items = []
        for f in row_items[(kind, value)]:
            x = _x(_ts(f["observed_at"]), start, end)
            primary.setdefault(f["id"], (x, y))
            items.append({"id": f["id"], "x": x, "y": y, "lane": f["lane"], "ts": f["observed_at"],
                          "title": titles.get(f["rule_id"], f["rule_id"]), "claim": f["claim"][:300]})
        rows.append({"kind": kind, "value": value, "y": y, "items": items})

    hidden["findings_on_hidden_rows"] = sum(1 for f in shown if _rows_of(f) and f["id"] not in primary)
    links = []
    candidates = [{"from": e["from"], "to": e["to"], "style": e["style"],
                   "label": e["link_type"].replace("_", " ")} for e in edges]
    candidates += [{"from": a["from_finding"], "to": a["to_finding"], "style": "analyst",
                    "label": f"{a['relation']} (analyst assertion, not proven)"} for a in analyst_links]
    for link in sorted(candidates, key=lambda li: (LINK_STYLES.index(li["style"]), li["from"], li["to"], li["label"])):
        if link["style"] not in styles:
            hidden["links_by_style"][link["style"]] += 1
            continue
        if link["from"] not in primary or link["to"] not in primary:
            hidden["links_without_both_ends"] += 1
            continue
        (x1, y1), (x2, y2) = primary[link["from"]], primary[link["to"]]
        links.append({**link, "x1": x1, "y1": y1, "x2": x2, "y2": y2})

    ticks = []
    for k in range(7):
        frac = k / 6
        ts = start + (end - start) * frac
        ticks.append({"x": round(LEFT + frac * (WIDTH - LEFT - RIGHT), 1), "label": ts.strftime("%m-%d %H:%M")})
    hidden["links_by_style"] = dict(hidden["links_by_style"])
    return {"width": WIDTH, "height": TOP + max(len(rows), 1) * ROW_H + 30, "left": LEFT, "rows": rows,
            "links": links, "ticks": ticks, "hidden": hidden, "shown_findings": len(primary),
            "filters": {"lanes": sorted(lanes), "kinds": sorted(kinds), "styles": sorted(styles)}}
