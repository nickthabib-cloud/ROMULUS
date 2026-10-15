"""Deterministic evaluation for reviewed aggregate behavior definitions.

The aggregate pack is intentionally a closed language.  A record is evaluated
only when its generated ``execution`` block names one of the primitives below
and supplies every field needed by that primitive.  Natural-language research
records never become executable by guessing a threshold or join key here.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
import hashlib
import math
from typing import Any, Iterable

from .analytics import evidence_source_family


MAX_AGGREGATE_EVENTS = 10_000
MAX_GROUPS_PER_RULE = 2_000
MAX_EVIDENCE_IDS = 40
PRIMITIVES = {
    "count", "distinct_count", "fanout", "rate", "transition",
    "volume", "ratio", "duration", "periodicity",
}


def evaluate_aggregates(
    evidence: list[dict[str, Any]],
    definitions: list[dict[str, Any]],
    source_outcomes: list[dict[str, Any]] | None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Evaluate executable aggregate definitions over bounded evidence.

    Missing or incomplete source coverage changes an otherwise negative result
    to ``partial``.  A positive result can still be emitted, but it records its
    incomplete inputs and cannot be customer visible.
    """
    envelopes = sorted(
        (_envelope(row) for row in evidence[:MAX_AGGREGATE_EVENTS]),
        key=lambda row: (row["time"], row["evidence_id"]),
    )
    truncated = len(evidence) > MAX_AGGREGATE_EVENTS
    matches: list[dict[str, Any]] = []
    by_rule: dict[str, dict[str, Any]] = {}

    for definition in definitions:
        identifier = str(definition.get("id") or "")
        execution = definition.get("execution") if isinstance(definition.get("execution"), dict) else {}
        if execution.get("status") != "executable":
            by_rule[identifier] = {
                "state": "reference_only",
                "reason_code": execution.get("reason_code", "missing_executable_translation"),
            }
            continue

        required_sources = list(execution.get("source_families") or
                                sorted({row["source_family"] for row in envelopes}))
        incomplete = _incomplete_sources(required_sources, source_outcomes)
        if truncated:
            incomplete = sorted(set(incomplete + ["event_limit"]))
        selected, metric, group = _match_definition(envelopes, execution)
        if selected:
            candidate = _candidate(definition, selected, metric, group, bool(incomplete))
            matches.append(candidate)
            by_rule[identifier] = {
                "state": "matched_partial" if incomplete else "matched",
                "primitive": execution.get("primitive"),
                "metric": metric,
                "group": list(group),
                "incomplete_sources": incomplete,
                "evidence_ids": candidate["evidence_ids"],
            }
        elif incomplete:
            by_rule[identifier] = {
                "state": "partial",
                "primitive": execution.get("primitive"),
                "incomplete_sources": incomplete,
            }
        else:
            by_rule[identifier] = {
                "state": "no_match",
                "primitive": execution.get("primitive"),
                "incomplete_sources": [],
            }

    coverage = {
        "total": len(definitions),
        "executable": sum(row.get("execution", {}).get("status") == "executable" for row in definitions),
        "reference_only": sum(row.get("execution", {}).get("status") != "executable" for row in definitions),
        "matched": len(matches),
        "evaluated_events": len(envelopes),
        "event_limit_reached": truncated,
        "by_rule": by_rule,
    }
    return sorted(matches, key=lambda row: (-int(row["priority_score"]), row["candidate_id"])), coverage


def _match_definition(
    events: list[dict[str, Any]], execution: dict[str, Any]
) -> tuple[list[dict[str, Any]], float, tuple[str, ...]]:
    primitive = str(execution.get("primitive") or "")
    if primitive not in PRIMITIVES:
        return [], 0.0, ()
    allowed_sources = set(execution.get("source_families") or [])
    eligible = [row for row in events if not allowed_sources or row["source_family"] in allowed_sources]
    if execution.get("filter"):
        eligible = [row for row in eligible if _filter_matches(row, execution["filter"])]
    group_fields = list(execution.get("group_by") or [])
    groups: dict[tuple[str, ...], list[dict[str, Any]]] = defaultdict(list)
    for row in eligible:
        key = tuple(_scalar(row, field) for field in group_fields)
        if group_fields and any(not value for value in key):
            continue
        if key not in groups and len(groups) >= MAX_GROUPS_PER_RULE:
            continue
        groups[key].append(row)
    if not group_fields and () not in groups:
        groups[()] = []

    threshold = execution.get("threshold") or {}
    window_seconds = max(1, int(execution.get("window_minutes") or 60)) * 60
    sample_min = max(1, int(execution.get("sample_min") or 1))
    for group in sorted(groups):
        rows = groups[group]
        for window in _windows(rows, window_seconds):
            if len(window) < sample_min:
                continue
            metric, supporting = _metric(primitive, window, execution)
            if supporting and _compare(metric, threshold):
                return supporting, metric, group
    return [], 0.0, ()


def _windows(rows: list[dict[str, Any]], window_seconds: int) -> Iterable[list[dict[str, Any]]]:
    """Yield deterministic maximal forward windows without quadratic output."""
    if not rows:
        yield []
        return
    end = 0
    for start in range(len(rows)):
        if end < start:
            end = start
        cutoff = rows[start]["time"] + timedelta(seconds=window_seconds)
        while end + 1 < len(rows) and rows[end + 1]["time"] <= cutoff:
            end += 1
        yield rows[start:end + 1]


def _metric(
    primitive: str, rows: list[dict[str, Any]], execution: dict[str, Any]
) -> tuple[float, list[dict[str, Any]]]:
    if primitive == "count":
        return float(len(rows)), rows
    if primitive in {"distinct_count", "fanout"}:
        field = str(execution.get("distinct_field") or "")
        values = {_scalar(row, field) for row in rows} - {""}
        return float(len(values)), rows if values else []
    if primitive == "rate":
        minutes = max(1, int(execution.get("window_minutes") or 60))
        return len(rows) / minutes, rows
    if primitive == "volume":
        field = str(execution.get("measure_field") or "")
        values = [_number(_value(row, field)) for row in rows]
        present = [value for value in values if value is not None]
        return float(sum(present)), rows if present else []
    if primitive == "ratio":
        numerator_filter = execution.get("numerator_filter")
        denominator_filter = execution.get("denominator_filter")
        if isinstance(numerator_filter, dict) and isinstance(denominator_filter, dict):
            numerator = sum(_filter_matches(row, numerator_filter) for row in rows)
            denominator = sum(_filter_matches(row, denominator_filter) for row in rows)
            if denominator <= 0:
                return 0.0, []
            return numerator / denominator, rows
        numerator_field = str(execution.get("numerator_field") or "")
        denominator_field = str(execution.get("denominator_field") or "")
        numerators = [_number(_value(row, numerator_field)) for row in rows]
        denominators = [_number(_value(row, denominator_field)) for row in rows]
        numerator = sum(value for value in numerators if value is not None)
        denominator = sum(value for value in denominators if value is not None)
        if denominator <= 0 or not any(value is not None for value in numerators):
            return 0.0, []
        return numerator / denominator, rows
    if primitive == "duration":
        if len(rows) < 2:
            return 0.0, []
        return (rows[-1]["time"] - rows[0]["time"]).total_seconds(), rows
    if primitive == "periodicity":
        if len(rows) < 3:
            return math.inf, []
        intervals = [(rows[index]["time"] - rows[index - 1]["time"]).total_seconds()
                     for index in range(1, len(rows))]
        mean = sum(intervals) / len(intervals)
        if mean <= 0:
            return math.inf, []
        variance = sum((value - mean) ** 2 for value in intervals) / len(intervals)
        return math.sqrt(variance) / mean, rows
    if primitive == "transition":
        from_filter = execution.get("from_filter") or {}
        to_filter = execution.get("to_filter") or {}
        needed = max(1, int(execution.get("from_count") or 1))
        prior: list[dict[str, Any]] = []
        for row in rows:
            if _filter_matches(row, from_filter):
                prior.append(row)
                continue
            if len(prior) >= needed and _filter_matches(row, to_filter):
                return 1.0, prior[-needed:] + [row]
        return 0.0, []
    return 0.0, []


def _filter_matches(row: dict[str, Any], predicate: dict[str, Any]) -> bool:
    field = str(predicate.get("field") or "")
    operator = str(predicate.get("operator") or "")
    value = _value(row, field)
    values = predicate.get("values") or []
    actual = [str(item).lower() for item in value] if isinstance(value, list) else [str(value).lower()]
    expected = [str(item).lower() for item in values]
    if operator == "exists":
        return value is not None and value != "" and value != []
    if operator in {"equals", "equals_any"}:
        return any(item in expected for item in actual)
    if operator in {"contains", "contains_any"}:
        return any(needle in item for item in actual for needle in expected)
    return False


def _compare(metric: float, threshold: dict[str, Any]) -> bool:
    try:
        value = float(threshold["value"])
    except (KeyError, TypeError, ValueError):
        return False
    operator = threshold.get("operator")
    return {
        "gte": metric >= value,
        "gt": metric > value,
        "lte": metric <= value,
        "lt": metric < value,
        "eq": metric == value,
    }.get(str(operator), False)


def _incomplete_sources(required: list[str], outcomes: list[dict[str, Any]] | None) -> list[str]:
    if outcomes is None:
        return []
    incomplete = []
    for family in required:
        rows = [row for row in outcomes if row.get("source_family") == family]
        healthy = any(row.get("status") == "completed" and not row.get("capped")
                      and not row.get("incomplete") and not row.get("timed_out")
                      and not row.get("shard_failures") for row in rows)
        if not healthy:
            incomplete.append(family)
    return incomplete


def _candidate(
    definition: dict[str, Any], events: list[dict[str, Any]], metric: float,
    group: tuple[str, ...], partial: bool,
) -> dict[str, Any]:
    evidence_ids = list(dict.fromkeys(row["evidence_id"] for row in events if row["evidence_id"]))
    identifier = str(definition["id"])
    digest = hashlib.sha256((identifier + "|" + "|".join(evidence_ids)).encode("utf-8")).hexdigest()[:16].upper()
    score = min(100, int(definition.get("base_score", definition.get("base_priority", 50)))
                + min(10, int(definition.get("specificity", 0)) // 10))
    disposition = "corroborated" if not partial and score >= 70 else "observed"
    assets = sorted({asset for row in events for asset in row["assets"]}) or ["unknown"]
    return {
        "candidate_id": f"AGG-{digest}",
        "kind": "aggregate",
        "analytic_id": identifier,
        "indicator_id": None,
        "title": definition.get("title", identifier),
        "description": definition.get("description", "Aggregate behavior threshold matched."),
        "priority_score": score,
        "priority_tier": "critical" if score >= 90 else "high" if score >= 70 else "medium" if score >= 40 else "low",
        "disposition": disposition,
        "customer_visible": disposition == "corroborated",
        "evidence_ids": evidence_ids[:MAX_EVIDENCE_IDS],
        "evidence_match_count": len(evidence_ids),
        "assets": assets,
        "first_observed": events[0]["time"].isoformat().replace("+00:00", "Z"),
        "last_observed": events[-1]["time"].isoformat().replace("+00:00", "Z"),
        "aggregate_primitive": definition.get("execution", {}).get("primitive"),
        "aggregate_metric": round(metric, 6),
        "aggregate_group": list(group),
        "source_families": sorted({row["source_family"] for row in events}),
        "completeness": "partial" if partial else "complete",
        "score_reasons": ["reviewed aggregate threshold matched", f"measured value {metric:.6g}"],
        "attack_techniques": list(definition.get("attack_techniques") or []),
        "benign_explanations": list(definition.get("benign_explanations") or []),
        "follow_up": list(definition.get("follow_up") or []),
        "follow_ups": [],
        "finding_ids": [],
    }


def _envelope(event: dict[str, Any]) -> dict[str, Any]:
    raw = event.get("raw") if isinstance(event.get("raw"), dict) else {}
    return {
        "evidence_id": str(event.get("evidence_id") or ""),
        "time": _time(event.get("observed_at") or _nested(raw, "@timestamp")),
        "source_family": _source_family(event, raw),
        "assets": _asset_values(event, raw),
        "event": event,
        "raw": raw,
    }


def _value(row: dict[str, Any], path: str) -> Any:
    value = _nested(row["raw"], path)
    if value is None:
        value = _nested(row["event"], path)
    return value


def _scalar(row: dict[str, Any], path: str) -> str:
    value = _value(row, path)
    if isinstance(value, list):
        value = value[0] if value else ""
    return str(value).strip().lower() if value is not None else ""


def _asset_values(event: dict[str, Any], raw: dict[str, Any]) -> set[str]:
    values: set[str] = set()
    for field in ("host.name", "host.hostname", "host.ip", "source.ip"):
        value = _nested(raw, field)
        for item in value if isinstance(value, list) else [value]:
            if item is not None and str(item).strip():
                values.add(str(item).strip().lower())
    if event.get("asset"):
        values.add(str(event["asset"]).strip().lower())
    return values


def _source_family(event: dict[str, Any], raw: dict[str, Any]) -> str:
    return evidence_source_family(event, raw)


def _nested(value: dict[str, Any], path: str) -> Any:
    current: Any = value
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _number(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _time(value: Any) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return datetime.min.replace(tzinfo=timezone.utc)
