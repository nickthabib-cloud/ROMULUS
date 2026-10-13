"""Offline behavioral analytic and trusted-indicator catalogs.

The catalog is intentionally data driven. Entries refer to semantic roles so
the same analytic can bind to ECS, Sysmon, auditd, Zeek, and unfamiliar data
sets when their fields can be resolved safely.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import re
from pathlib import Path
from typing import Any

from .attack_catalog import load_attack_catalog


BEHAVIOR_CATALOG_PATH = Path(__file__).with_name("behavior_catalog.json")
LOCAL_INDICATORS_PATH = Path(__file__).with_name("local_indicators.json")

ALLOWED_OPERATORS = {
    "contains_any", "equals_any", "ends_with_any", "path_prefix_any",
    "regex", "exists", "lookalike_process",
}
ALLOWED_SOURCES = {"elasticsearch", "aggregate"}
PRIORITIES = {"informational", "low", "medium", "high", "critical"}
NOISE_LEVELS = {"low", "medium", "high"}
_ATTACK_TECHNIQUE_IDS: set[str] | None = None

SEMANTIC_ROLE_ALIASES: dict[str, tuple[str, ...]] = {
    "event.time": ("@timestamp", "timestamp", "event.created", "event.start", "winlog.time_created"),
    "event.action": ("event.action", "event.type", "event.code", "event.id", "winlog.event_id", "action"),
    "host.name": ("host.name", "host.hostname", "hostname", "computer_name", "agent.hostname"),
    "user.name": ("user.name", "account.name", "winlog.event_data.SubjectUserName", "user", "username"),
    "process.name": ("process.name", "process.executable", "winlog.event_data.Image", "exe", "comm"),
    "process.executable": ("process.executable", "winlog.event_data.Image", "process.path", "exe", "image"),
    "process.command_line": (
        "process.command_line", "process.args", "winlog.event_data.CommandLine",
        "audit.command", "cmdline", "command_line", "message", "event.original",
    ),
    "process.parent.name": (
        "process.parent.name", "process.parent.executable",
        "winlog.event_data.ParentImage", "parent_process_name", "ppid_name",
    ),
    "file.path": ("file.path", "file.name", "target.file.path", "winlog.event_data.TargetFilename", "path"),
    "registry.path": ("registry.path", "registry.key", "winlog.event_data.TargetObject"),
    "service.name": ("service.name", "winlog.event_data.ServiceName", "systemd.unit"),
    "source.ip": ("source.ip", "src_ip", "srcIp", "ip.src", "client.ip"),
    "destination.ip": ("destination.ip", "dst_ip", "dstIp", "ip.dst", "server.ip"),
    "destination.port": ("destination.port", "dst_port", "dstPort", "tcp.dstport", "udp.dstport", "port"),
    "network.protocol": ("network.protocol", "network.transport", "network.application", "protocol", "protocols"),
    "network.bytes": ("network.bytes", "source.bytes", "destination.bytes", "bytes", "totBytes"),
    "dns.question": ("dns.question.name", "dns.qry.name", "dns.host", "query", "domain"),
    "dns.rcode": ("dns.response_code", "dns.header.response_code", "dns.flags.rcode", "rcode"),
    "url.full": ("url.full", "url.original", "http.request.uri", "http.uri", "uri"),
    "tls.server_name": ("tls.server.name", "tls.handshake.extensions_server_name", "server_name", "sni"),
    "file.hash.sha256": ("file.hash.sha256", "hash.sha256", "sha256"),
    "file.hash.sha1": ("file.hash.sha1", "hash.sha1", "sha1"),
    "file.hash.md5": ("file.hash.md5", "hash.md5", "md5"),
    "tls.certificate.fingerprint": ("tls.server.hash.sha256", "tls.certificate.fingerprint", "certificate.fingerprint"),
    "aggregate.signal": ("aggregate.signal",),
}


class CatalogValidationError(ValueError):
    """Catalog content is unsafe or structurally invalid."""


def load_behavior_catalog(path: Path = BEHAVIOR_CATALOG_PATH) -> dict[str, Any]:
    value = _read_json(Path(path), "behavior catalog")
    if not isinstance(value, dict):
        raise CatalogValidationError("$: behavior catalog must be an object")
    if not _nonempty_string(value.get("catalog_version")):
        raise CatalogValidationError("catalog_version: expected non-empty string")
    analytics = value.get("analytics")
    if not isinstance(analytics, list):
        raise CatalogValidationError("analytics: expected array")
    seen: set[str] = set()
    for index, analytic in enumerate(analytics):
        _validate_analytic(analytic, index, seen)
    return value


def load_local_indicators(path: Path = LOCAL_INDICATORS_PATH) -> dict[str, Any]:
    value = _read_json(Path(path), "local indicator catalog")
    if not isinstance(value, dict):
        raise CatalogValidationError("$: local indicator catalog must be an object")
    if not _nonempty_string(value.get("catalog_version")):
        raise CatalogValidationError("catalog_version: expected non-empty string")
    indicators = value.get("indicators")
    if not isinstance(indicators, list):
        raise CatalogValidationError("indicators: expected array")
    seen: set[str] = set()
    allowed_types = {"sha256", "sha1", "md5", "domain", "ip", "path", "process", "certificate"}
    for index, item in enumerate(indicators):
        prefix = f"indicators[{index}]"
        if not isinstance(item, dict):
            raise CatalogValidationError(f"{prefix}: expected object")
        identifier = item.get("id")
        if not _nonempty_string(identifier):
            raise CatalogValidationError(f"{prefix}.id: expected non-empty string")
        if identifier in seen:
            raise CatalogValidationError(f"{prefix}.id: duplicate id {identifier}")
        seen.add(identifier)
        if item.get("type") not in allowed_types:
            raise CatalogValidationError(f"{prefix}.type: unsupported indicator type")
        for field in ("value", "source", "created_at"):
            if not _nonempty_string(item.get(field)):
                raise CatalogValidationError(f"{prefix}.{field}: expected non-empty string")
        confidence = item.get("confidence")
        if not isinstance(confidence, int) or isinstance(confidence, bool) or not 0 <= confidence <= 100:
            raise CatalogValidationError(f"{prefix}.confidence: expected integer 0 through 100")
        for field in ("created_at", "expires_at"):
            if item.get(field):
                _parse_time(item[field], f"{prefix}.{field}")
    return value


def resolve_semantic_fields(fields: list[str] | set[str] | tuple[str, ...]) -> dict[str, list[str]]:
    available = {str(field) for field in fields}
    lower = {field.lower(): field for field in available}
    bindings: dict[str, list[str]] = {}
    for role, aliases in SEMANTIC_ROLE_ALIASES.items():
        matches = []
        for alias in aliases:
            if alias in available:
                matches.append(alias)
            elif alias.lower() in lower:
                matches.append(lower[alias.lower()])
        if matches:
            bindings[role] = list(dict.fromkeys(matches))
    return bindings


def applicable_analytics(
    catalog: dict[str, Any], bindings: dict[str, list[str]], source: str
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    applicable: list[dict[str, Any]] = []
    unsupported: list[dict[str, Any]] = []
    for analytic in catalog.get("analytics", []):
        if not analytic.get("enabled", True) or analytic.get("source") != source:
            continue
        missing = [role for role in analytic.get("required_roles", []) if not bindings.get(role)]
        if missing:
            unsupported.append({"id": analytic["id"], "missing_roles": missing})
        else:
            applicable.append(analytic)
    return applicable, unsupported


def _valid_attack_technique_ids() -> set[str]:
    global _ATTACK_TECHNIQUE_IDS
    if _ATTACK_TECHNIQUE_IDS is None:
        _ATTACK_TECHNIQUE_IDS = {
            str(item.get("technique_id"))
            for item in load_attack_catalog().get("techniques", [])
            if isinstance(item, dict) and item.get("technique_id")
        }
        if not _ATTACK_TECHNIQUE_IDS:
            raise CatalogValidationError("attack_catalog.json: pinned ATT&CK catalog is unavailable or invalid")
    return _ATTACK_TECHNIQUE_IDS


def _read_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise CatalogValidationError(f"{path}: {label} file not found") from exc
    except json.JSONDecodeError as exc:
        raise CatalogValidationError(f"{path}:{exc.lineno}:{exc.colno}: invalid JSON") from exc
    except OSError as exc:
        raise CatalogValidationError(f"{path}: unable to read {label}") from exc


def _validate_analytic(item: Any, index: int, seen: set[str]) -> None:
    prefix = f"analytics[{index}]"
    if not isinstance(item, dict):
        raise CatalogValidationError(f"{prefix}: expected object")
    identifier = item.get("id")
    if not _nonempty_string(identifier):
        raise CatalogValidationError(f"{prefix}.id: expected non-empty string")
    if identifier in seen:
        raise CatalogValidationError(f"{prefix}.id: duplicate id {identifier}")
    seen.add(identifier)
    for field in ("title", "description", "review_date"):
        if not _nonempty_string(item.get(field)):
            raise CatalogValidationError(f"{prefix}.{field}: expected non-empty string")
    if not isinstance(item.get("version"), int) or item["version"] < 1:
        raise CatalogValidationError(f"{prefix}.version: expected positive integer")
    if not isinstance(item.get("enabled"), bool):
        raise CatalogValidationError(f"{prefix}.enabled: expected boolean")
    if item.get("source") not in ALLOWED_SOURCES:
        raise CatalogValidationError(f"{prefix}.source: unsupported source")
    for field in (
        "platforms", "categories", "required_roles", "optional_roles",
        "attack_techniques", "benign_explanations", "required_corroboration", "follow_up",
    ):
        values = item.get(field)
        if not isinstance(values, list) or (field not in {"optional_roles", "required_corroboration"} and not values):
            raise CatalogValidationError(f"{prefix}.{field}: expected non-empty array")
        if not all(_nonempty_string(value) for value in values):
            raise CatalogValidationError(f"{prefix}.{field}: expected strings")
    valid_attack_ids = _valid_attack_technique_ids()
    for technique_id in item["attack_techniques"]:
        if technique_id not in valid_attack_ids:
            raise CatalogValidationError(f"{prefix}.attack_techniques: unknown pinned ATT&CK technique {technique_id}")
    known_roles = set(SEMANTIC_ROLE_ALIASES)
    for field in ("required_roles", "optional_roles"):
        for role in item[field]:
            if role not in known_roles:
                raise CatalogValidationError(f"{prefix}.{field}: unsupported semantic role {role}")
    if item.get("priority_tier", "low") not in PRIORITIES:
        raise CatalogValidationError(f"{prefix}.priority_tier: unsupported priority")
    for field in ("base_priority", "specificity"):
        value = item.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 100:
            raise CatalogValidationError(f"{prefix}.{field}: expected integer 0 through 100")
    if item.get("expected_noise") not in NOISE_LEVELS:
        raise CatalogValidationError(f"{prefix}.expected_noise: unsupported noise level")
    provenance = item.get("provenance")
    if not isinstance(provenance, list) or not provenance:
        raise CatalogValidationError(f"{prefix}.provenance: expected non-empty array")
    for number, source in enumerate(provenance):
        if not isinstance(source, dict) or not _nonempty_string(source.get("name")) or not _nonempty_string(source.get("url")):
            raise CatalogValidationError(f"{prefix}.provenance[{number}]: expected name and url")
    match = item.get("match")
    if not isinstance(match, dict):
        raise CatalogValidationError(f"{prefix}.match: expected object")
    if not any(match.get(group) for group in ("all", "any")):
        raise CatalogValidationError(f"{prefix}.match: at least one all or any predicate is required")
    for group in ("all", "any", "none"):
        predicates = match.get(group, [])
        if not isinstance(predicates, list):
            raise CatalogValidationError(f"{prefix}.match.{group}: expected array")
        for number, predicate in enumerate(predicates):
            _validate_predicate(predicate, f"{prefix}.match.{group}[{number}]")


def _validate_predicate(predicate: Any, path: str) -> None:
    if not isinstance(predicate, dict):
        raise CatalogValidationError(f"{path}: expected object")
    role = predicate.get("role")
    if role not in SEMANTIC_ROLE_ALIASES:
        raise CatalogValidationError(f"{path}.role: unsupported semantic role")
    operator = predicate.get("operator")
    if operator not in ALLOWED_OPERATORS:
        raise CatalogValidationError(f"{path}.operator: unsupported operator {operator}")
    values = predicate.get("values", [])
    if operator == "exists":
        if values not in ([], None):
            raise CatalogValidationError(f"{path}.values: exists does not accept values")
    elif not isinstance(values, list) or not values or not all(_nonempty_string(value) for value in values):
        raise CatalogValidationError(f"{path}.values: expected non-empty string array")


def _parse_time(value: str, path: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    except (TypeError, ValueError) as exc:
        raise CatalogValidationError(f"{path}: expected ISO-8601 timestamp") from exc


def _nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def compile_elasticsearch_seed(
    analytic: dict[str, Any],
    bindings: dict[str, list[str]],
    timestamp_field: str,
    time_range: dict[str, str] | None,
) -> dict[str, Any] | None:
    """Compile a catalog entry into a bounded, validator-compatible ES query."""
    match = analytic.get("match", {})
    must = []
    should = []
    must_not = []
    for predicate in match.get("all", []):
        clause = _predicate_query(predicate, bindings)
        if clause is None:
            return None
        must.append(clause)
    for predicate in match.get("any", []):
        clause = _predicate_query(predicate, bindings)
        if clause is not None:
            should.append(clause)
    for predicate in match.get("none", []):
        clause = _predicate_query(predicate, bindings)
        if clause is None:
            return None
        must_not.append(clause)
    if not must and not should:
        return None
    body: dict[str, Any] = {}
    if must:
        body["must"] = must
    if should:
        body["should"] = should
        body["minimum_should_match"] = 1
    if must_not:
        body["must_not"] = must_not
    if time_range:
        body["filter"] = [{"range": {timestamp_field: dict(time_range)}}]
    return {"bool": body}


def build_candidate_queue(
    evidence: list[dict[str, Any]],
    catalog: dict[str, Any],
    indicators: dict[str, Any],
    analytic_summary: dict[str, Any] | None = None,
    now: str | datetime | None = None,
) -> list[dict[str, Any]]:
    """Match evidence and return a stable, explainable candidate queue."""
    events = list(evidence) + _aggregate_events(analytic_summary or {}, evidence)
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    analytics = [item for item in catalog.get("analytics", []) if item.get("enabled", True)]
    for analytic in analytics:
        for event in events:
            if analytic.get("source") == "aggregate" and event.get("source") != "aggregate":
                continue
            if analytic.get("source") == "elasticsearch" and event.get("source") == "aggregate":
                continue
            if _analytic_matches(analytic, event):
                asset = str(event.get("asset") or "unknown")
                grouped.setdefault((analytic["id"], asset), []).append(event)

    candidates: list[dict[str, Any]] = []
    for (analytic_id, asset), rows in grouped.items():
        analytic = next(item for item in analytics if item["id"] == analytic_id)
        score = int(analytic["base_priority"]) + min(10, int(analytic["specificity"]) // 10)
        reasons = [
            f"base analytic priority {analytic['base_priority']}",
            f"specificity contribution {min(10, int(analytic['specificity']) // 10)}",
        ]
        if len(rows) > 1:
            repeat_bonus = min(9, (len(rows) - 1) * 3)
            score += repeat_bonus
            reasons.append(f"repeat observation contribution {repeat_bonus}")
        score = min(100, score)
        candidates.append(_behavior_candidate(analytic, asset, rows, score, "observed", reasons))

    reference_time = _coerce_time(now) if now is not None else datetime.now(timezone.utc)
    for indicator in indicators.get("indicators", []):
        expires = indicator.get("expires_at")
        if expires and _parse_time(expires, f"indicator {indicator.get('id')}.expires_at") <= reference_time:
            continue
        matched = [event for event in evidence if _indicator_matches(indicator, event)]
        if not matched:
            continue
        by_asset: dict[str, list[dict[str, Any]]] = {}
        for event in matched:
            by_asset.setdefault(str(event.get("asset") or "unknown"), []).append(event)
        for asset, rows in by_asset.items():
            score = max(90, min(100, int(indicator.get("confidence", 0))))
            identifier = str(indicator["id"])
            candidate_id = _candidate_id("indicator", identifier, asset)
            follow_up = ["Validate the indicator source and investigate the cited event and adjacent activity."]
            candidates.append({
                "candidate_id": candidate_id,
                "kind": "trusted_indicator", "indicator_id": identifier,
                "analytic_id": None, "title": f"Trusted indicator observed: {identifier}",
                "description": f"An exact {indicator.get('type')} indicator supplied by {indicator.get('source')} was observed.",
                "base_priority_score": score,
                "priority_score": score, "priority_tier": "critical",
                "disposition": "observed", "customer_visible": True,
                "evidence_ids": _evidence_ids(rows), "assets": [asset],
                "first_observed": _observed_bounds(rows)[0], "last_observed": _observed_bounds(rows)[1],
                "score_reasons": [
                    f"trusted exact indicator confidence {indicator.get('confidence')}",
                    "exact value match with current provenance",
                ],
                "attack_techniques": [], "benign_explanations": [],
                "follow_up": follow_up, "follow_ups": _follow_up_records(candidate_id, follow_up),
                "finding_ids": [],
                "indicator_source": indicator.get("source"), "indicator_confidence": indicator.get("confidence"),
                "indicator_type": indicator.get("type"), "indicator_value": indicator.get("value"),
                "indicator_expires_at": indicator.get("expires_at"),
            })
    return sorted(
        candidates,
        key=lambda item: (
            -int(item.get("priority_score", 0)),
            0 if item.get("kind") == "trusted_indicator" else 1,
            str(item.get("candidate_id")),
        ),
    )


def customer_visible_candidates(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [item for item in candidates if item.get("customer_visible")]


def merge_candidate_queue(previous: list[dict[str, Any]], current: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Merge fresh detections without erasing investigation decisions or follow-up history."""
    prior_by_id = {str(item.get("candidate_id")): item for item in previous if item.get("candidate_id")}
    merged = []
    refreshed_ids = set()
    terminal = {"benign_likely", "dismissed", "unresolved"}
    for fresh in current:
        item = dict(fresh)
        prior = prior_by_id.get(str(item.get("candidate_id")))
        refreshed_ids.add(str(item.get("candidate_id")))
        if prior:
            prior_disposition = str(prior.get("disposition") or "observed")
            fresh_disposition = str(item.get("disposition") or "observed")
            # Preserve analyst-owned terminal decisions and an in-progress
            # investigation.  ``corroborated`` is derived from the current
            # evidence relationships, so carrying it across refreshes can
            # leave a candidate promoted after its relationship disappears.
            if prior_disposition in terminal or (
                prior_disposition == "investigating" and fresh_disposition == "observed"
            ):
                item["disposition"] = prior_disposition
            item["evidence_ids"] = sorted(set(prior.get("evidence_ids", [])) | set(item.get("evidence_ids", [])))
            observed = [value for value in (prior.get("first_observed"), item.get("first_observed")) if value]
            item["first_observed"] = min(observed) if observed else None
            observed = [value for value in (prior.get("last_observed"), item.get("last_observed")) if value]
            item["last_observed"] = max(observed) if observed else None
            item["finding_ids"] = list(dict.fromkeys(prior.get("finding_ids", []) + item.get("finding_ids", [])))
            old_follow_ups = {entry.get("follow_up_id"): entry for entry in prior.get("follow_ups", [])}
            preserved = []
            for follow_up in item.get("follow_ups", []):
                old = old_follow_ups.get(follow_up.get("follow_up_id"))
                preserved.append(dict(follow_up, status=old.get("status", follow_up.get("status")),
                    history=list(old.get("history", []))) if old else follow_up)
            refreshed_follow_up_ids = {entry.get("follow_up_id") for entry in preserved}
            preserved.extend(dict(entry, history=list(entry.get("history", [])))
                for entry in prior.get("follow_ups", []) if entry.get("follow_up_id") not in refreshed_follow_up_ids)
            item["follow_ups"] = preserved
            for field in ("disposition_history", "telemetry_gaps"):
                if prior.get(field): item[field] = list(prior[field])
        merged.append(item)
    # A bounded re-analysis may not reproduce a previously observed candidate
    # (for example after context retention or source availability changes).
    # Preserve it until an explicit analyst disposition closes it.
    merged.extend(_retained_candidate_without_derived_corroboration(item) for item in previous
        if str(item.get("candidate_id")) not in refreshed_ids)
    return sorted(merged, key=lambda item: (-int(item.get("priority_score", 0)),
        0 if item.get("kind") == "trusted_indicator" else 1, str(item.get("candidate_id"))))


def _retained_candidate_without_derived_corroboration(candidate: dict[str, Any]) -> dict[str, Any]:
    """Keep investigation history without carrying an unavailable relationship."""
    item = dict(candidate)
    item["follow_ups"] = [dict(entry, history=list(entry.get("history", [])))
        for entry in candidate.get("follow_ups", [])]
    bonus = max(0, min(20, int(item.get("corroboration_bonus", 0) or 0)))
    fallback_base = max(0, int(item.get("priority_score", 0) or 0) - bonus)
    score = max(0, min(100, int(item.get("base_priority_score", fallback_base) or 0)))
    item["base_priority_score"] = score
    item["corroboration_bonus"] = 0
    item["priority_score"] = score
    item["priority_tier"] = "critical" if score >= 90 else (
        "high" if score >= 70 else ("medium" if score >= 40 else "low")
    )
    item["related_candidates"] = []
    item["corroboration_reasons"] = []
    item["score_reasons"] = [str(reason) for reason in item.get("score_reasons", [])
        if not str(reason).startswith("evidence-backed corroboration contribution ")]
    if str(item.get("disposition") or "observed") == "corroborated":
        item["disposition"] = "observed"
    item["customer_visible"] = bool(item.get("kind") == "trusted_indicator")
    return item


def _predicate_query(predicate: dict[str, Any], bindings: dict[str, list[str]]) -> dict[str, Any] | None:
    fields = bindings.get(predicate.get("role"), [])
    if not fields:
        return None
    operator = predicate.get("operator")
    values = predicate.get("values", [])
    clauses = []
    for field in fields[:4]:
        if operator == "exists":
            clauses.append({"exists": {"field": field}})
        elif operator == "equals_any":
            clauses.append({"terms": {field: values[:20]}})
        elif operator == "path_prefix_any":
            clauses.extend({"prefix": {field: value}} for value in values[:12])
        elif operator in {"contains_any", "ends_with_any"}:
            clauses.extend({"match_phrase": {field: value}} for value in values[:12])
        else:
            continue
    if not clauses:
        return None
    return clauses[0] if len(clauses) == 1 else {"bool": {"should": clauses, "minimum_should_match": 1}}


def _analytic_matches(analytic: dict[str, Any], event: dict[str, Any]) -> bool:
    match = analytic.get("match", {})
    all_results = [_predicate_matches(item, event) for item in match.get("all", [])]
    any_results = [_predicate_matches(item, event) for item in match.get("any", [])]
    none_results = [_predicate_matches(item, event) for item in match.get("none", [])]
    return all(all_results) and (any(any_results) if any_results else True) and not any(none_results)


def _predicate_matches(predicate: dict[str, Any], event: dict[str, Any]) -> bool:
    role = str(predicate.get("role"))
    operator = predicate.get("operator")
    values = [str(value).lower() for value in predicate.get("values", [])]
    observed = [value.lower() for value in _role_values(event, role)]
    if operator == "exists":
        return bool(observed)
    if operator == "contains_any":
        return any(needle in value for value in observed for needle in values)
    if operator == "equals_any":
        return any(value == needle for value in observed for needle in values)
    if operator == "ends_with_any":
        return any(value.endswith(needle) for value in observed for needle in values)
    if operator == "path_prefix_any":
        normalized_values = [_normalize_path(value) for value in values]
        return any(_normalize_path(value).startswith(prefix) for value in observed for prefix in normalized_values)
    if operator == "regex":
        for pattern in predicate.get("values", []):
            try:
                if any(re.search(str(pattern), value, flags=re.IGNORECASE) for value in observed):
                    return True
            except re.error:
                return False
        return False
    if operator == "lookalike_process":
        paths = _role_values(event, "process.executable")
        if not paths:
            return False
        for value in observed:
            basename = _basename(value)
            for expected in values:
                if basename != expected and _edit_distance_at_most_one(basename, expected):
                    return any(_basename(path).lower() == basename for path in paths)
        return False
    return False


def _role_values(event: dict[str, Any], role: str) -> list[str]:
    out: list[str] = []
    for field in SEMANTIC_ROLE_ALIASES.get(role, ()):
        value = _nested_value(event.get("raw", {}), field)
        if value is None:
            value = event.get("raw", {}).get(field) if isinstance(event.get("raw"), dict) else None
        if value is None:
            value = _nested_value(event, field)
        for item in value if isinstance(value, list) else [value]:
            if item is not None and str(item).strip() and str(item) not in out:
                out.append(str(item))
    if role == "host.name" and event.get("asset") and str(event["asset"]) not in out:
        out.append(str(event["asset"]))
    return out


def _indicator_matches(indicator: dict[str, Any], event: dict[str, Any]) -> bool:
    expected = _normalize_indicator(str(indicator.get("type")), str(indicator.get("value")))
    if not expected:
        return False
    kind = str(indicator.get("type"))
    values = _flatten_strings({
        "observation": event.get("observation"),
        "asset": event.get("asset"),
        "raw": event.get("raw", {}),
    })
    observed: set[str] = set()
    for value in values:
        observed.update(_extract_indicator_values(kind, value))
    return expected in observed


def _normalize_indicator(kind: str, value: str) -> str:
    value = value.strip().lower()
    if kind == "path":
        return _normalize_path(value)
    if kind == "process":
        return _basename(value)
    if kind == "domain":
        return value.rstrip(".")
    return value


def _extract_indicator_values(kind: str, value: str) -> set[str]:
    text = str(value).strip().lower()
    if not text:
        return set()
    if kind in {"sha256", "sha1", "md5"}:
        lengths = {"sha256": 64, "sha1": 40, "md5": 32}
        return set(re.findall(rf"(?<![0-9a-f])[0-9a-f]{{{lengths[kind]}}}(?![0-9a-f])", text))
    if kind == "ip":
        values = set()
        for token in re.findall(r"(?<![0-9a-f:.])(?:[0-9a-f]*:[0-9a-f:.]+|(?:\d{1,3}\.){3}\d{1,3})(?![0-9a-f:.])", text):
            try:
                values.add(str(ipaddress.ip_address(token)))
            except ValueError:
                pass
        return values
    if kind == "domain":
        return {value.rstrip(".") for value in re.findall(r"(?<![a-z0-9-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?![a-z0-9-])", text)}
    if kind == "path":
        return {_normalize_path(text)}
    if kind == "process":
        return {_basename(text)}
    return {text}


def _behavior_candidate(
    analytic: dict[str, Any],
    asset: str,
    rows: list[dict[str, Any]],
    score: int,
    disposition: str,
    reasons: list[str],
) -> dict[str, Any]:
    tier = "critical" if score >= 90 else ("high" if score >= 70 else ("medium" if score >= 40 else "low"))
    candidate_id = _candidate_id("behavior", analytic["id"], asset)
    follow_up = analytic.get("follow_up", [])
    return {
        "candidate_id": candidate_id,
        "kind": "behavior", "analytic_id": analytic["id"], "indicator_id": None,
        "corroboration_group": str(analytic.get("corroboration_group") or analytic["id"]),
        "analytic_source": analytic.get("source"),
        "title": analytic["title"], "description": analytic["description"],
        "base_priority_score": score,
        "priority_score": score, "priority_tier": tier, "disposition": disposition,
        "customer_visible": bool(score >= 70 and disposition == "corroborated"),
        "evidence_ids": _evidence_ids(rows), "assets": [asset],
        "first_observed": _observed_bounds(rows)[0], "last_observed": _observed_bounds(rows)[1],
        "score_reasons": reasons, "attack_techniques": analytic.get("attack_techniques", []),
        "benign_explanations": analytic.get("benign_explanations", []),
        "follow_up": follow_up, "follow_ups": _follow_up_records(candidate_id, follow_up),
        "finding_ids": [],
    }


def _aggregate_events(
    summary: dict[str, Any], evidence: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    out = []
    evidence_by_id = {
        str(event.get("evidence_id")): event for event in evidence or [] if event.get("evidence_id")
    }
    aggregate_signals = summary.get("aggregate_signals")
    if isinstance(aggregate_signals, dict):
        for signal, rows in aggregate_signals.items():
            for row in rows or []:
                refs = list(row.get("sample_evidence_ids") or [])
                if row.get("sample_evidence_id"):
                    refs.append(row["sample_evidence_id"])
                asset = (row.get("asset") or row.get("source") or row.get("destination")
                    or row.get("user") or "unknown")
                out.append(_aggregate_event(str(signal), asset, *refs, evidence_by_id=evidence_by_id))
        return out
    host_profile = summary.get("host_profile", {})
    for row in host_profile.get("authentication_sequences", []) or []:
        out.append(_aggregate_event("auth_failures_then_success", row.get("source") or row.get("user"),
            row.get("sample_evidence_id"), evidence_by_id=evidence_by_id))
    network = summary.get("network_profile", {})
    for row in network.get("high_fanout", []) or []:
        out.append(_aggregate_event("high_fanout", row.get("source"), *(row.get("sample_evidence_ids") or []),
            evidence_by_id=evidence_by_id))
    for row in network.get("periodic_edge_candidates", []) or []:
        out.append(_aggregate_event("periodic_edge", row.get("source"), *(row.get("sample_evidence_ids") or []),
            evidence_by_id=evidence_by_id))
    for row in network.get("low_frequency_external_destinations", []) or []:
        out.append(_aggregate_event("rare_external_destination", row.get("destination"),
            *(row.get("sample_evidence_ids") or []), evidence_by_id=evidence_by_id))
    return out


def _aggregate_event(
    signal: str,
    asset: Any,
    *evidence_ids: Any,
    evidence_by_id: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    supporting = list(dict.fromkeys(str(value) for value in evidence_ids if value))
    observed = sorted(
        str((evidence_by_id or {}).get(identifier, {}).get("observed_at"))
        for identifier in supporting
        if (evidence_by_id or {}).get(identifier, {}).get("observed_at")
    )
    return {
        "evidence_id": supporting[0] if supporting else f"AGG-{signal}",
        "source": "aggregate", "observed_at": observed[0] if observed else "",
        "supporting_observed_at": observed, "asset": str(asset or "unknown"),
        "observation": signal, "supporting_evidence_ids": supporting,
        "raw": {"aggregate": {"signal": signal, "supporting_evidence_ids": supporting}},
    }


def _candidate_id(kind: str, identifier: str, asset: str) -> str:
    digest = hashlib.sha1(f"{kind}|{identifier}|{asset}".encode("utf-8", errors="replace")).hexdigest()[:12].upper()
    return f"CL-{digest}"


def _follow_up_records(candidate_id: str, intents: list[str]) -> list[dict[str, Any]]:
    out = []
    for intent in intents:
        digest = hashlib.sha1(f"{candidate_id}|{intent}".encode("utf-8", errors="replace")).hexdigest()[:10].upper()
        out.append({"follow_up_id": f"FU-{digest}", "intent": str(intent), "status": "pending", "history": []})
    return out


def _evidence_ids(rows: list[dict[str, Any]]) -> list[str]:
    values = set()
    for row in rows:
        if row.get("evidence_id"):
            values.add(str(row["evidence_id"]))
        values.update(str(value) for value in row.get("supporting_evidence_ids", []) if value)
    return sorted(values)


def _observed_bounds(rows: list[dict[str, Any]]) -> tuple[str | None, str | None]:
    values = sorted(
        str(value)
        for row in rows
        for value in ([row.get("observed_at")] + list(row.get("supporting_observed_at") or []))
        if value
    )
    return (values[0], values[-1]) if values else (None, None)


def _nested_value(value: Any, path: str) -> Any:
    for part in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def _flatten_strings(value: Any, depth: int = 0) -> list[str]:
    if depth > 6:
        return []
    if isinstance(value, dict):
        return [item for child in value.values() for item in _flatten_strings(child, depth + 1)]
    if isinstance(value, list):
        return [item for child in value[:100] for item in _flatten_strings(child, depth + 1)]
    return [str(value)] if value is not None else []


def _normalize_path(value: str) -> str:
    return str(value).strip().lower().replace("\\", "/")


def _basename(value: str) -> str:
    return _normalize_path(value).rsplit("/", 1)[-1]


def _edit_distance_at_most_one(left: str, right: str) -> bool:
    if abs(len(left) - len(right)) > 1:
        return False
    if left == right:
        return True
    if len(left) == len(right):
        return sum(a != b for a, b in zip(left, right)) <= 1
    short, long = (left, right) if len(left) < len(right) else (right, left)
    index = 0
    for position, char in enumerate(long):
        if index < len(short) and short[index] == char:
            index += 1
        elif position - index >= 1:
            return False
    return True


def _coerce_time(value: str | datetime) -> datetime:
    if isinstance(value, datetime):
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
    return _parse_time(value, "now")



def compile_elasticsearch_indicator_seed(
    indicator: dict[str, Any],
    bindings: dict[str, list[str]],
    timestamp_field: str,
    time_range: dict[str, str] | None,
) -> dict[str, Any] | None:
    """Compile a trusted exact indicator into a strict field-bound query."""
    roles_by_type = {
        "domain": ("dns.question", "url.full", "tls.server_name"),
        "ip": ("source.ip", "destination.ip"),
        "path": ("file.path", "process.executable"),
        "process": ("process.name", "process.executable"),
        "sha256": ("file.hash.sha256",),
        "sha1": ("file.hash.sha1",),
        "md5": ("file.hash.md5",),
        "certificate": ("tls.certificate.fingerprint",),
    }
    fields = [
        field
        for role in roles_by_type.get(str(indicator.get("type")), ())
        for field in bindings.get(role, [])
    ]
    if not fields:
        return None
    value = str(indicator.get("value") or "").strip()
    if not value:
        return None
    should = [{"term": {field: value}} for field in list(dict.fromkeys(fields))[:8]]
    body: dict[str, Any] = {"should": should, "minimum_should_match": 1}
    if time_range:
        body["filter"] = [{"range": {timestamp_field: dict(time_range)}}]
    return {"bool": body}
