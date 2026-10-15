"""Persistent, contamination-aware baseline comparisons for reviewed rules."""
from __future__ import annotations

from collections import defaultdict
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import math
import re
from typing import Any

from .analytics import evidence_source_family


MAX_BASELINE_EVENTS = 10_000
MAX_SCOPES = 10_000
MAX_VALUES_PER_SCOPE = 2_000
MAX_VALUE_SCOPES = 2_000
MAX_EVIDENCE_IDS = 40
PRIMITIVES = {"first_seen", "prevalence", "deviation"}


def evaluate_baselines(
    evidence: list[dict[str, Any]],
    definitions: list[dict[str, Any]],
    states: dict[str, dict[str, Any]],
    source_outcomes: list[dict[str, Any]] | None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Compare current evidence with prior completed-hunt baseline state."""
    events = [_envelope(row) for row in evidence[:MAX_BASELINE_EVENTS]]
    truncated = len(evidence) > MAX_BASELINE_EVENTS
    matches: list[dict[str, Any]] = []
    by_rule: dict[str, dict[str, Any]] = {}
    ready_count = 0

    for definition in definitions:
        identifier = str(definition.get("id") or "")
        execution = definition.get("execution") if isinstance(definition.get("execution"), dict) else {}
        if execution.get("status") != "executable":
            by_rule[identifier] = {"state": "reference_only",
                "reason_code": execution.get("reason_code", "missing_executable_translation")}
            continue
        required_sources = list(execution.get("source_families") or
                                sorted({row["source_family"] for row in events}))
        incomplete = _incomplete_sources(required_sources, source_outcomes)
        if truncated:
            incomplete = sorted(set(incomplete + ["event_limit"]))
        eligible = _eligible(events, execution)
        state = states.get(identifier) if isinstance(states.get(identifier), dict) else {}
        selected, detail, ready = _match(eligible, execution, state)
        if ready:
            ready_count += 1
        if selected:
            candidate = _candidate(definition, selected, detail, bool(incomplete))
            matches.append(candidate)
            by_rule[identifier] = {"state": "matched_partial" if incomplete else "matched",
                "primitive": execution.get("primitive"), "detail": detail,
                "incomplete_sources": incomplete, "evidence_ids": candidate["evidence_ids"]}
        elif incomplete:
            by_rule[identifier] = {"state": "partial", "primitive": execution.get("primitive"),
                "history_ready": ready, "incomplete_sources": incomplete}
        elif not ready:
            by_rule[identifier] = {"state": "warming", "primitive": execution.get("primitive"),
                "observations": int(state.get("observations") or 0), "incomplete_sources": []}
        else:
            by_rule[identifier] = {"state": "no_match", "primitive": execution.get("primitive"),
                "incomplete_sources": []}

    coverage = {
        "total": len(definitions),
        "executable": sum(row.get("execution", {}).get("status") == "executable" for row in definitions),
        "reference_only": sum(row.get("execution", {}).get("status") != "executable" for row in definitions),
        "ready": ready_count,
        "warming": sum(row.get("state") == "warming" for row in by_rule.values()),
        "matched": len(matches),
        "evaluated_events": len(events),
        "event_limit_reached": truncated,
        "by_rule": by_rule,
    }
    return sorted(matches, key=lambda row: (-int(row["priority_score"]), row["candidate_id"])), coverage


def build_baseline_updates(
    evidence: list[dict[str, Any]],
    definitions: list[dict[str, Any]],
    states: dict[str, dict[str, Any]],
    excluded_evidence_ids: set[str] | None = None,
) -> dict[str, dict[str, Any]]:
    """Build next baseline states from clean evidence without writing storage.

    Callers must only persist these states after a completed hunt with complete
    source coverage.  Evidence cited by candidates or findings belongs in
    ``excluded_evidence_ids`` so suspicious activity cannot teach itself into
    the normal baseline.
    """
    excluded = set(excluded_evidence_ids or set())
    events = [_envelope(row) for row in evidence[:MAX_BASELINE_EVENTS]
              if row.get("evidence_id") not in excluded]
    updates: dict[str, dict[str, Any]] = {}
    for definition in definitions:
        identifier = str(definition.get("id") or "")
        execution = definition.get("execution") if isinstance(definition.get("execution"), dict) else {}
        if execution.get("status") != "executable":
            continue
        eligible = _eligible(events, execution)
        state = deepcopy(states.get(identifier)) if isinstance(states.get(identifier), dict) else {}
        state.setdefault("schema_version", 1)
        state.setdefault("observations", 0)
        primitive = execution.get("primitive")
        if primitive in {"first_seen", "prevalence"}:
            scope_values = state.setdefault("scope_values", {})
            value_scopes = state.setdefault("value_scopes", {})
            added = 0
            for row in eligible:
                scope = _key(row, execution.get("scope_fields") or [])
                value = _value_key(row, execution)
                if not scope or not value:
                    continue
                if scope not in scope_values and len(scope_values) >= MAX_SCOPES:
                    continue
                values = scope_values.setdefault(scope, {})
                if value not in values and len(values) >= MAX_VALUES_PER_SCOPE:
                    continue
                values[value] = int(values.get(value, 0)) + 1
                scopes = set(value_scopes.get(value, []))
                if scope in scopes or len(scopes) < MAX_VALUE_SCOPES:
                    scopes.add(scope)
                    value_scopes[value] = sorted(scopes)
                added += 1
            state["observations"] = int(state.get("observations") or 0) + added
        elif primitive == "deviation":
            current = _measurements(eligible, execution)
            metrics = state.setdefault("metrics", {})
            for scope, (metric, _) in current.items():
                summary = metrics.setdefault(scope, {"n": 0, "mean": 0.0, "m2": 0.0})
                n = int(summary.get("n") or 0) + 1
                mean = float(summary.get("mean") or 0.0)
                delta = metric - mean
                mean += delta / n
                m2 = float(summary.get("m2") or 0.0) + delta * (metric - mean)
                summary.update({"n": n, "mean": mean, "m2": m2})
                state["observations"] = int(state.get("observations") or 0) + 1
        updates[identifier] = state
    return updates


def persist_completed_baselines(
    store: Any,
    hunt_id: str,
    hunt_status: str,
    evidence: list[dict[str, Any]],
    definitions: list[dict[str, Any]],
    states: dict[str, dict[str, Any]],
    excluded_evidence_ids: set[str] | None = None,
) -> dict[str, Any]:
    """Persist baseline updates only for a coverage-complete hunt."""
    if hunt_status != "completed":
        return {"status": "skipped_incomplete_hunt", "eligible": 0, "applied": 0}
    updates = build_baseline_updates(evidence, definitions, states, excluded_evidence_ids)
    applied = sum(store.apply_baseline_update(hunt_id, identifier, state,
        version=int(state.get("schema_version") or 1)) for identifier, state in updates.items())
    return {"status": "completed", "eligible": len(updates), "applied": applied,
        "excluded_evidence": len(excluded_evidence_ids or set())}


def _match(
    events: list[dict[str, Any]], execution: dict[str, Any], state: dict[str, Any]
) -> tuple[list[dict[str, Any]], dict[str, Any], bool]:
    primitive = execution.get("primitive")
    warmup = max(1, int(execution.get("warmup_min") or 1))
    observations = int(state.get("observations") or 0)
    if primitive == "first_seen":
        ready = observations >= warmup
        if not ready:
            return [], {}, False
        history = state.get("scope_values") if isinstance(state.get("scope_values"), dict) else {}
        for row in events:
            scope = _key(row, execution.get("scope_fields") or [])
            value = _value_key(row, execution)
            if scope and value and value not in history.get(scope, {}):
                return [row], {"scope": scope, "value": value, "prior_count": 0}, True
        return [], {}, True
    if primitive == "prevalence":
        history = state.get("scope_values") if isinstance(state.get("scope_values"), dict) else {}
        peer_min = max(1, int(execution.get("peer_min_scopes") or warmup))
        ready = observations >= warmup and len(history) >= peer_min
        if not ready:
            return [], {}, False
        value_scopes = state.get("value_scopes") if isinstance(state.get("value_scopes"), dict) else {}
        max_prevalence = float(execution.get("max_prevalence", 0.1))
        for row in events:
            scope = _key(row, execution.get("scope_fields") or [])
            value = _value_key(row, execution)
            if not scope or not value:
                continue
            prevalence = len(value_scopes.get(value, [])) / max(1, len(history))
            if prevalence <= max_prevalence:
                return [row], {"scope": scope, "value": value,
                    "peer_prevalence": round(prevalence, 6), "peer_scopes": len(history)}, True
        return [], {}, True
    if primitive == "deviation":
        metrics = state.get("metrics") if isinstance(state.get("metrics"), dict) else {}
        current = _measurements(events, execution)
        any_ready = False
        for scope in sorted(current):
            metric, rows = current[scope]
            prior = metrics.get(scope) if isinstance(metrics.get(scope), dict) else {}
            n = int(prior.get("n") or 0)
            if n < warmup:
                continue
            any_ready = True
            mean = float(prior.get("mean") or 0.0)
            stddev = math.sqrt(float(prior.get("m2") or 0.0) / max(1, n - 1))
            threshold = max(float(execution.get("minimum") or 0.0),
                            mean * float(execution.get("multiplier") or 1.0),
                            mean + stddev * float(execution.get("zscore") or 3.0))
            if metric >= threshold:
                return rows, {"scope": scope, "value": round(metric, 6),
                    "prior_mean": round(mean, 6), "prior_stddev": round(stddev, 6),
                    "threshold": round(threshold, 6)}, True
        return [], {}, any_ready
    return [], {}, False


def _measurements(
    events: list[dict[str, Any]], execution: dict[str, Any]
) -> dict[str, tuple[float, list[dict[str, Any]]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in events:
        scope = _key(row, execution.get("scope_fields") or [])
        if scope:
            grouped[scope].append(row)
    result = {}
    aggregation = execution.get("aggregation")
    for scope, rows in grouped.items():
        if aggregation == "count":
            metric = float(len(rows))
        elif aggregation == "sum":
            values = [_number(_value(row, str(execution.get("measure_field") or ""))) for row in rows]
            present = [value for value in values if value is not None]
            if not present:
                continue
            metric = float(sum(present))
        elif aggregation == "distinct_count":
            field = str(execution.get("distinct_field") or "")
            values = {_scalar(row, field) for row in rows} - {""}
            if not values:
                continue
            metric = float(len(values))
        elif aggregation == "ratio":
            numerator = sum(_filter_matches(row, execution.get("numerator_filter") or {}) for row in rows)
            denominator = sum(_filter_matches(row, execution.get("denominator_filter") or {}) for row in rows)
            if not denominator:
                continue
            metric = numerator / denominator
        else:
            continue
        result[scope] = (metric, rows)
    return result


def _eligible(events: list[dict[str, Any]], execution: dict[str, Any]) -> list[dict[str, Any]]:
    sources = set(execution.get("source_families") or [])
    return [row for row in events if (not sources or row["source_family"] in sources)
            and (not execution.get("filter") or _filter_matches(row, execution["filter"]))]


def _filter_matches(row: dict[str, Any], predicate: dict[str, Any]) -> bool:
    field = str(predicate.get("field") or "")
    operator = str(predicate.get("operator") or "")
    value = _value(row, field)
    values = [str(item).lower() for item in predicate.get("values") or []]
    actual = [str(item).lower() for item in value] if isinstance(value, list) else [str(value).lower()]
    if operator == "exists":
        return value is not None and value != "" and value != []
    if operator in {"equals", "equals_any"}:
        return any(item in values for item in actual)
    if operator in {"contains", "contains_any"}:
        return any(needle in item for item in actual for needle in values)
    return False


def _value_key(row: dict[str, Any], execution: dict[str, Any]) -> str:
    fields = execution.get("value_fields") or []
    values = [_scalar(row, field) for field in fields]
    if not values or any(not value for value in values):
        return ""
    if execution.get("value_transform") == "command_shape":
        values = [_command_shape(value) for value in values]
    return _join(values)


def _key(row: dict[str, Any], fields: list[str]) -> str:
    values = [_scalar(row, field) for field in fields]
    return _join(values) if values and all(values) else ""


def _join(values: list[str]) -> str:
    return "\u001f".join(values)


def _command_shape(value: str) -> str:
    value = re.sub(r"\b(?:[0-9a-f]{8,}|\d{3,})\b", "#", value.lower())
    value = re.sub(r"\s+", " ", value).strip()
    return value[:500]


def _candidate(
    definition: dict[str, Any], events: list[dict[str, Any]], detail: dict[str, Any], partial: bool,
) -> dict[str, Any]:
    evidence_ids = list(dict.fromkeys(row["evidence_id"] for row in events if row["evidence_id"]))
    identifier = str(definition["id"])
    digest = hashlib.sha256((identifier + "|" + "|".join(evidence_ids)).encode("utf-8")).hexdigest()[:16].upper()
    score = min(100, int(definition.get("base_score", definition.get("base_priority", 25)))
                + min(10, int(definition.get("specificity", 0)) // 10))
    assets = sorted({asset for row in events for asset in row["assets"]}) or ["unknown"]
    return {"candidate_id": f"BASE-{digest}", "kind": "baseline", "analytic_id": identifier,
        "indicator_id": None, "title": definition.get("title", identifier),
        "description": definition.get("description", "Behavior differs from completed-hunt baseline."),
        "priority_score": score,
        "priority_tier": "critical" if score >= 90 else "high" if score >= 70 else "medium" if score >= 40 else "low",
        "disposition": "observed", "customer_visible": False,
        "evidence_ids": evidence_ids[:MAX_EVIDENCE_IDS], "evidence_match_count": len(evidence_ids),
        "assets": assets, "first_observed": events[0]["time"].isoformat().replace("+00:00", "Z"),
        "last_observed": events[-1]["time"].isoformat().replace("+00:00", "Z"),
        "baseline_detail": detail, "source_families": sorted({row["source_family"] for row in events}),
        "completeness": "partial" if partial else "complete",
        "score_reasons": ["reviewed historical baseline condition matched", "baseline-only lead requires follow-up"],
        "attack_techniques": list(definition.get("attack_techniques") or []),
        "benign_explanations": list(definition.get("benign_explanations") or []),
        "follow_up": list(definition.get("follow_up") or []), "follow_ups": [], "finding_ids": []}


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


def _envelope(event: dict[str, Any]) -> dict[str, Any]:
    raw = event.get("raw") if isinstance(event.get("raw"), dict) else {}
    assets = set()
    for field in ("host.name", "host.hostname", "host.ip", "source.ip"):
        value = _nested(raw, field)
        for item in value if isinstance(value, list) else [value]:
            if item is not None and str(item).strip():
                assets.add(str(item).strip().lower())
    if event.get("asset"):
        assets.add(str(event["asset"]).strip().lower())
    return {"evidence_id": str(event.get("evidence_id") or ""),
        "time": _time(event.get("observed_at") or _nested(raw, "@timestamp")),
        "source_family": _source_family(event, raw), "assets": assets, "event": event, "raw": raw}


def _value(row: dict[str, Any], path: str) -> Any:
    value = _nested(row["raw"], path)
    return _nested(row["event"], path) if value is None else value


def _scalar(row: dict[str, Any], path: str) -> str:
    value = _value(row, path)
    if isinstance(value, list):
        value = value[0] if value else ""
    return str(value).strip().lower() if value is not None else ""


def _nested(value: dict[str, Any], path: str) -> Any:
    current: Any = value
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _source_family(event: dict[str, Any], raw: dict[str, Any]) -> str:
    return evidence_source_family(event, raw)


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
