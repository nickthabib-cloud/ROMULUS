"""Evidence-constrained analyst indicator synthesis and admission.

Models may organize and explain already-reportable evidence.  Deterministic
code owns every selector, artifact, asset, timestamp, classification, and
outcome boundary rendered to an analyst.
"""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import ipaddress
import re
from typing import Any


_DOMAIN_RE = re.compile(
    r"(?<![A-Za-z0-9_-])(?:[A-Za-z0-9_*][A-Za-z0-9_*/-]{0,62}\.)+"
    r"[A-Za-z][A-Za-z0-9-]{1,62}(?![A-Za-z0-9_-])"
)
_IP_RE = re.compile(r"(?<![0-9A-Fa-f:.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9A-Fa-f:.])")
_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_FILE_RE = re.compile(
    r"(?<![A-Za-z0-9_.-])[A-Za-z0-9_][A-Za-z0-9_.-]{0,160}\."
    r"(?:docx?|xlsx?|pptx?|pdf|csv|txt|zip|7z|rar|php|jsp|aspx?|ps1|bat|cmd|sh|py|exe|dll)"
    r"(?![A-Za-z0-9_.-])",
    re.IGNORECASE,
)
_CONFIDENCE = {"low", "moderate", "medium", "high", "critical", "not assessed"}
_OUTCOMES = {"observed", "suspected", "confirmed"}
_TEXT_LIMIT = 1200


def build_indicator_case(state: Mapping[str, Any], report_items: list[dict[str, Any]]) -> dict[str, Any]:
    """Build the bounded canonical case shown to the reporting model."""
    source = state if isinstance(state, Mapping) else {}
    items = [_project_item(row) for row in report_items if isinstance(row, Mapping) and row.get("item_id")]
    owned_ids = {
        value for item in items for value in item.get("evidence_ids", []) if value
    }
    evidence_index = {
        str(row.get("evidence_id")): row
        for section in ("host", "network")
        for row in _rows(source.get(section))
        if row.get("evidence_id") and str(row.get("evidence_id")) in owned_ids
    }
    evidence = [_project_evidence(evidence_index[key]) for key in sorted(evidence_index)]
    visible_ids = {row["evidence_id"] for row in evidence}
    relationships = []
    for raw in _rows(source.get("correlations")):
        left = str(raw.get("host_ref") or raw.get("left_evidence_id") or "")
        right = str(raw.get("network_ref") or raw.get("right_evidence_id") or "")
        relationship_id = str(raw.get("correlation_id") or raw.get("relationship_id") or "")
        if not relationship_id or left not in visible_ids or right not in visible_ids:
            continue
        relationships.append({
            "relationship_id": relationship_id,
            "evidence_ids": [left, right],
            "reason": _text(raw.get("reason") or raw.get("reasons"), 360),
            "score": raw.get("score"),
        })
    coverage = source.get("coverage") if isinstance(source.get("coverage"), Mapping) else {}
    return {
        "version": 1,
        "mission": {
            "hunt_id": _text(source.get("hunt_id"), 100),
            "objective": _text(source.get("objective"), 1200),
            "time_scope": _text(coverage.get("time_scope"), 300),
        },
        "items": items,
        "evidence": evidence,
        "relationships": relationships,
        "coverage": {
            "host": _text(coverage.get("host"), 300),
            "network": _text(coverage.get("network"), 300),
            "termination_reason": _text(source.get("termination_reason"), 100),
            "source_error_count": coverage.get("source_error_count", 0),
        },
    }


def admit_indicator_review(case: Mapping[str, Any], proposal: Mapping[str, Any]) -> dict[str, Any]:
    """Resolve a model proposal against canonical selectors or reject it whole."""
    if not isinstance(case, Mapping) or not isinstance(proposal, Mapping):
        return _rejected(["malformed_proposal"])
    indexes = _indexes(case)
    rejection_codes: set[str] = set()
    admitted_indicators: list[dict[str, Any]] = []
    for raw in _rows(proposal.get("strong_indicators")):
        selectors = _selectors(raw, indexes, rejection_codes, require_item=True)
        if selectors is None:
            continue
        _validate_text_observables(raw, selectors["observable_ids"], indexes, rejection_codes)
        outcome = str(raw.get("outcome") or "suspected").strip().lower()
        if outcome not in _OUTCOMES:
            rejection_codes.add("invalid_outcome")
        if outcome == "confirmed" and not _supports_confirmed_outcome(selectors["evidence_ids"], indexes):
            rejection_codes.add("unsupported_confirmed_outcome")
        if (_asserts_success(raw) and
                _only_failed_http_outcomes(selectors["evidence_ids"], indexes)):
            rejection_codes.add("contradicted_success_claim")
        admitted_indicators.append(_resolve_indicator(raw, selectors, indexes, outcome))

    supporting = []
    for raw in _rows(proposal.get("supporting_context")):
        selectors = _selectors(raw, indexes, rejection_codes, require_item=False)
        if selectors is not None:
            _validate_text_observables(raw, selectors["observable_ids"], indexes, rejection_codes)
            supporting.append(_resolve_context(raw, selectors, indexes))
    noise = []
    for raw in _rows(proposal.get("likely_noise")):
        selectors = _selectors(raw, indexes, rejection_codes, require_item=True)
        if selectors is not None:
            _validate_text_observables(raw, selectors["observable_ids"], indexes, rejection_codes)
            noise.append(_resolve_noise(raw, selectors, indexes))

    narrative_raw = proposal.get("possible_activity_narrative")
    if isinstance(narrative_raw, Mapping):
        _validate_text_observables(narrative_raw, list(indexes["observable"]), indexes, rejection_codes)
    narrative = _resolve_narrative(narrative_raw, indexes, rejection_codes)
    follow_ups = _bounded_list(proposal.get("recommended_follow_ups"), 12, 500)
    _validate_text_observables({"recommended_follow_ups":follow_ups},
        list(indexes["observable"]), indexes, rejection_codes)
    if rejection_codes:
        return _rejected(sorted(rejection_codes))
    return {
        "version": 1,
        "status": "admitted",
        "strong_indicators": _consolidate_indicators(admitted_indicators),
        "supporting_context": supporting[:12],
        "likely_noise": noise[:12],
        "possible_activity_narrative": narrative,
        "recommended_follow_ups": follow_ups,
        "rejection_codes": [],
    }


def deterministic_indicator_review(case: Mapping[str, Any], reason: str) -> dict[str, Any]:
    """Return an analyst-useful briefing when model synthesis is unavailable."""
    indexes = _indexes(case)
    indicators = []
    for item in case.get("items", []) if isinstance(case.get("items"), list) else []:
        if not isinstance(item, Mapping) or not item.get("item_id"):
            continue
        evidence_ids = [value for value in item.get("evidence_ids", []) if value in indexes["evidence"]]
        selectors = {
            "item_ids": [str(item["item_id"])],
            "evidence_ids": evidence_ids,
            "observable_ids": [
                row["observable_id"] for evidence_id in evidence_ids
                for row in indexes["evidence"][evidence_id].get("observables", [])
            ],
            "relationship_ids": [],
        }
        raw = {
            **selectors,
            "title": item.get("title"),
            "assessment": item.get("why_it_matters") or item.get("observation"),
            "limitations": list(item.get("coverage_gaps", [])) + list(item.get("benign_alternatives", [])),
            "recommended_follow_ups": item.get("recommended_actions", []),
            "confidence": item.get("confidence"),
            "outcome": "suspected",
        }
        indicators.append(_resolve_indicator(raw, selectors, indexes, "suspected"))
    return {
        "version": 1,
        "status": "fallback",
        "reason": _text(reason, 300),
        "strong_indicators": indicators,
        "supporting_context": [],
        "likely_noise": [],
        "possible_activity_narrative": {
            "item_ids": [], "relationship_ids": [],
            "summary": "No model-synthesized activity narrative was available.",
            "limitations": [_text(reason, 300)] if reason else [],
        },
        "recommended_follow_ups": list(dict.fromkeys(
            action for item in case.get("items", []) if isinstance(item, Mapping)
            for action in item.get("recommended_actions", []) if action
        ))[:12],
        "rejection_codes": [],
    }


def indicator_review_proposal(review: Mapping[str, Any]) -> dict[str, Any]:
    """Project persisted review state back to the selector-only proposal shape."""
    if not isinstance(review, Mapping):
        return {}

    def selector_entry(raw: Mapping[str, Any]) -> dict[str, Any]:
        return {
            key: raw.get(
                key,
                [] if key.endswith("_ids") or key in {"limitations", "recommended_follow_ups"} else "",
            )
            for key in (
                "item_ids", "evidence_ids", "observable_ids", "relationship_ids", "title",
                "assessment", "summary", "limitations", "recommended_follow_ups", "confidence", "outcome",
            )
        }

    narrative = review.get("possible_activity_narrative")
    return {
        "strong_indicators": [selector_entry(row) for row in _rows(review.get("strong_indicators"))],
        "supporting_context": [selector_entry(row) for row in _rows(review.get("supporting_context"))],
        "likely_noise": [selector_entry(row) for row in _rows(review.get("likely_noise"))],
        "possible_activity_narrative": selector_entry(narrative) if isinstance(narrative, Mapping) else {},
        "recommended_follow_ups": review.get("recommended_follow_ups", []),
    }


def _project_item(raw: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "item_id": _text(raw.get("item_id"), 120),
        "classification": _text(raw.get("classification"), 40),
        "title": _text(raw.get("title"), 180),
        "observation": _text(raw.get("observation"), 600),
        "why_it_matters": _text(raw.get("why_it_matters"), 600),
        "evidence_ids": _bounded_list(raw.get("evidence_ids"), 100, 120),
        "assets": _bounded_list(raw.get("assets"), 40, 160),
        "first_observed": _text(raw.get("first_observed"), 80),
        "last_observed": _text(raw.get("last_observed"), 80),
        "investigation_status": _text(raw.get("investigation_status"), 80),
        "confidence": _text(raw.get("confidence"), 80),
        "attack_techniques": _bounded_list(raw.get("attack_techniques"), 20, 40),
        "benign_alternatives": _bounded_list(raw.get("benign_alternatives"), 12, 300),
        "coverage_gaps": _bounded_list(raw.get("coverage_gaps"), 12, 300),
        "recommended_actions": _bounded_list(raw.get("recommended_actions"), 12, 300),
    }


def _project_evidence(raw: Mapping[str, Any]) -> dict[str, Any]:
    raw_fields = raw.get("raw") if isinstance(raw.get("raw"), Mapping) else {}
    safe_raw = _safe_raw(raw_fields)
    evidence_id = str(raw.get("evidence_id"))
    return {
        "evidence_id": evidence_id,
        "source": _text(raw.get("source"), 80),
        "asset": _text(raw.get("asset"), 160),
        "observed_at": _text(raw.get("observed_at"), 80),
        "observation": _text(raw.get("observation"), 700),
        "retrieval_context": _text(
            (raw.get("provenance") or {}).get("search_id")
            if isinstance(raw.get("provenance"), Mapping) else "",
            120,
        ),
        "facts": safe_raw,
        "observables": _extract_observables(evidence_id, safe_raw, raw.get("observation")),
    }


def _safe_raw(raw: Mapping[str, Any]) -> dict[str, Any]:
    projected = {}
    for key, value in _flatten(raw):
        lowered = key.lower()
        if any(part in lowered for part in ("ground_truth", "scenario", "label", "rule")):
            continue
        if isinstance(value, (str, int, float, bool)) and value is not None:
            projected[key[:160]] = _text(value, 700)
    return dict(list(projected.items())[:80])


def _extract_observables(evidence_id: str, facts: Mapping[str, Any], observation: Any) -> list[dict[str, str]]:
    found: list[tuple[str, str, str]] = []
    for field, raw_value in facts.items():
        value = str(raw_value).strip()
        lowered = field.lower()
        if not value:
            continue
        if lowered.endswith(".ip") or lowered in {"src_ip", "dest_ip", "ip.src", "ip.dst"}:
            for candidate in _IP_RE.findall(value):
                if _valid_ip(candidate): found.append(("ip", candidate, field))
        if lowered.endswith(".port") or lowered in {"src_port", "dest_port", "port"}:
            if value.isdigit() and 0 <= int(value) <= 65535: found.append(("port", value, field))
        if "status" in lowered and value.isdigit():
            found.append(("http_status", value, field))
        if lowered in {"http.uri", "url.path", "http.request.uri"} and value.startswith("/"):
            found.append(("url_path", value, field))
        if "command_line" in lowered or lowered in {"command", "cmd"}:
            found.append(("command", value, field))
        if lowered.endswith("process.name") or lowered == "process.name":
            found.append(("process", value, field))
        if lowered.endswith("user.name") or lowered == "user.name":
            found.append(("account", value, field))
        for candidate in _URL_RE.findall(value): found.append(("url", candidate.rstrip(".,;)"), field))
        if any(token in lowered for token in ("dns", "domain", "hostname", "host.http", "server_name")):
            for candidate in _DOMAIN_RE.findall(value): found.append(("domain", candidate.rstrip("."), field))
        for candidate in _FILE_RE.findall(value): found.append(("file", candidate, field))
    combined = " ".join([str(observation or "")] + [str(value) for value in facts.values()])
    for candidate in _URL_RE.findall(combined): found.append(("url", candidate.rstrip(".,;)"), "text"))
    for candidate in _IP_RE.findall(combined):
        if _valid_ip(candidate): found.append(("ip", candidate, "text"))
    for candidate in _FILE_RE.findall(combined): found.append(("file", candidate, "text"))
    unique = []
    seen = set()
    for observable_type, value, field in found:
        key = (observable_type, value.lower())
        if key in seen:
            continue
        seen.add(key)
        digest = hashlib.sha256(f"{evidence_id}|{observable_type}|{value}".encode("utf-8")).hexdigest()[:16].upper()
        unique.append({
            "observable_id": f"OB-{digest}", "type": observable_type,
            "value": value, "field": field,
        })
    return unique[:80]


def _indexes(case: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    evidence = {str(row.get("evidence_id")): dict(row) for row in _rows(case.get("evidence")) if row.get("evidence_id")}
    observables = {
        str(row.get("observable_id")): dict(row)
        for evidence_row in evidence.values()
        for row in _rows(evidence_row.get("observables"))
        if row.get("observable_id")
    }
    return {
        "item": {str(row.get("item_id")): dict(row) for row in _rows(case.get("items")) if row.get("item_id")},
        "evidence": evidence,
        "observable": observables,
        "relationship": {
            str(row.get("relationship_id")): dict(row)
            for row in _rows(case.get("relationships")) if row.get("relationship_id")
        },
    }


def _selectors(raw, indexes, rejection_codes, require_item):
    previous_rejections = set(rejection_codes)
    item_ids = _bounded_list(raw.get("item_ids"), 30, 120)
    evidence_ids = _bounded_list(raw.get("evidence_ids"), 100, 120)
    observable_ids = _bounded_list(raw.get("observable_ids"), 200, 120)
    relationship_ids = _bounded_list(raw.get("relationship_ids"), 50, 120)
    if require_item and not item_ids:
        rejection_codes.add("missing_item_id")
    for value in item_ids:
        if value not in indexes["item"]: rejection_codes.add("unknown_item_id")
    for value in evidence_ids:
        if value not in indexes["evidence"]: rejection_codes.add("unknown_evidence_id")
    for value in observable_ids:
        if value not in indexes["observable"]: rejection_codes.add("unknown_observable_id")
    for value in relationship_ids:
        if value not in indexes["relationship"]: rejection_codes.add("unknown_relationship_id")
    owned = {
        evidence_id for item_id in item_ids if item_id in indexes["item"]
        for evidence_id in indexes["item"][item_id].get("evidence_ids", [])
    }
    if item_ids and any(value not in owned for value in evidence_ids):
        rejection_codes.add("unowned_evidence_id")
    selected_observable_ids = {
        row.get("observable_id") for evidence_id in evidence_ids if evidence_id in indexes["evidence"]
        for row in indexes["evidence"][evidence_id].get("observables", [])
    }
    if any(value not in selected_observable_ids for value in observable_ids):
        rejection_codes.add("observable_not_in_selected_evidence")
    if rejection_codes != previous_rejections:
        return None
    return {
        "item_ids": item_ids, "evidence_ids": evidence_ids,
        "observable_ids": observable_ids, "relationship_ids": relationship_ids,
    }


def _resolve_indicator(raw, selectors, indexes, outcome):
    items = [indexes["item"][value] for value in selectors["item_ids"]]
    evidence = [indexes["evidence"][value] for value in selectors["evidence_ids"]]
    artifacts = _selected_artifacts(selectors, indexes)
    classification = "malicious" if any(item.get("classification") == "malicious" for item in items) else "suspicious"
    confidence = str(raw.get("confidence") or "not assessed").strip().lower()
    if confidence not in _CONFIDENCE: confidence = "not assessed"
    times = sorted({str(row.get("observed_at")) for row in evidence if row.get("observed_at")})
    assets = list(dict.fromkeys(str(row.get("asset")) for row in evidence if row.get("asset")))
    title = _text(raw.get("title"), 180) or _text(items[0].get("title"), 180)
    return {
        **selectors,
        "indicator_id": _indicator_id(selectors["item_ids"], selectors["evidence_ids"]),
        "classification": classification,
        "title": title or "Evidence-backed indicator",
        "assessment": _text(raw.get("assessment"), _TEXT_LIMIT),
        "limitations": _bounded_list(raw.get("limitations"), 12, 500),
        "recommended_follow_ups": _bounded_list(raw.get("recommended_follow_ups"), 12, 500),
        "confidence": confidence,
        "outcome": outcome if outcome in _OUTCOMES else "suspected",
        "artifacts": artifacts,
        "assets": assets or list(dict.fromkeys(a for item in items for a in item.get("assets", []) if a)),
        "first_observed": times[0] if times else next((item.get("first_observed") for item in items if item.get("first_observed")), ""),
        "last_observed": times[-1] if times else next((item.get("last_observed") for item in items if item.get("last_observed")), ""),
        "attack_techniques": list(dict.fromkeys(
            value for item in items for value in item.get("attack_techniques", []) if value
        )),
    }


def _resolve_context(raw, selectors, indexes):
    return {
        **selectors,
        "summary": _text(raw.get("summary") or raw.get("assessment"), _TEXT_LIMIT),
        "limitations": _bounded_list(raw.get("limitations"), 8, 500),
        "artifacts": _selected_artifacts(selectors, indexes),
    }


def _resolve_noise(raw, selectors, indexes):
    return {
        **selectors,
        "title": _text(raw.get("title"), 180) or "De-prioritized signal",
        "assessment": _text(raw.get("assessment") or raw.get("basis"), _TEXT_LIMIT),
        "limitations": _bounded_list(raw.get("limitations"), 8, 500),
        "recommended_follow_ups": _bounded_list(raw.get("recommended_follow_ups"), 8, 500),
        "artifacts": _selected_artifacts(selectors, indexes),
    }


def _resolve_narrative(raw, indexes, rejection_codes):
    if not isinstance(raw, Mapping):
        rejection_codes.add("malformed_narrative")
        return {"item_ids": [], "relationship_ids": [], "summary": "", "limitations": []}
    selectors = _selectors(raw, indexes, rejection_codes, require_item=False)
    return {
        "item_ids": selectors["item_ids"],
        "relationship_ids": selectors["relationship_ids"],
        "summary": _text(raw.get("summary"), 1800),
        "limitations": _bounded_list(raw.get("limitations"), 12, 500),
    }


def _selected_artifacts(selectors, indexes):
    return [indexes["observable"][value] for value in selectors["observable_ids"] if value in indexes["observable"]]


def _supports_confirmed_outcome(evidence_ids, indexes):
    for evidence_id in evidence_ids:
        evidence = indexes["evidence"].get(evidence_id, {})
        facts = {str(key).lower(): str(value).lower() for key, value in (evidence.get("facts") or {}).items()}
        for key, value in facts.items():
            if ("status" in key and value.isdigit() and int(value) < 400) or (
                key in {"event.outcome", "outcome"} and value in {"success", "successful"}
            ) or ("state" in key and value in {"established", "connected", "completed"}):
                return True
        observation = str(evidence.get("observation") or "").lower()
        if any(token in observation for token in ("successfully ", "connection established", "received shell output")):
            return True
    return False


def _validate_text_observables(raw, observable_ids, indexes, rejection_codes):
    """Reject precise IOC values authored in prose instead of selected canonically."""
    allowed={str(indexes["observable"][value].get("value","")).strip().lower()
        for value in observable_ids if value in indexes["observable"]}
    text=" ".join(str(raw.get(field) or "") for field in (
        "title","assessment","summary","basis","limitations","recommended_follow_ups"
    ))
    candidates=set()
    for pattern in (_URL_RE,_IP_RE,_DOMAIN_RE,_FILE_RE):
        candidates.update(match.rstrip(".,;:)]}").lower() for match in pattern.findall(text))
    for candidate in candidates:
        if not any(candidate == value or candidate in value for value in allowed):
            rejection_codes.add("unsupported_text_observable")
            return


def _asserts_success(raw):
    text=" ".join(str(raw.get(field) or "") for field in ("title","assessment")).lower()
    return bool(re.search(
        r"\b(?:successful(?:ly)?|downloaded|executed|connected|exfiltrated|compromised)\b|"
        r"\b(?:shell|session|connection)\s+(?:opened|established|succeeded)\b", text
    ))


def _only_failed_http_outcomes(evidence_ids, indexes):
    statuses=[]
    for evidence_id in evidence_ids:
        evidence=indexes["evidence"].get(evidence_id,{})
        for key,value in (evidence.get("facts") or {}).items():
            if "status" not in str(key).lower():
                continue
            try: statuses.append(int(str(value)))
            except (TypeError,ValueError): pass
    return bool(statuses) and all(value >= 400 for value in statuses)


def _consolidate_indicators(indicators):
    consolidated = []
    by_items = {}
    for indicator in indicators:
        key = tuple(sorted(indicator.get("item_ids", [])))
        if key not in by_items:
            by_items[key] = indicator
            consolidated.append(indicator)
            continue
        target = by_items[key]
        for field in ("evidence_ids", "observable_ids", "relationship_ids"):
            target[field] = list(dict.fromkeys(target.get(field, []) + indicator.get(field, [])))
        target["artifacts"] = list({row["observable_id"]: row for row in target.get("artifacts", []) + indicator.get("artifacts", [])}.values())
        target["assets"] = list(dict.fromkeys(target.get("assets", []) + indicator.get("assets", [])))
    return consolidated


def _rejected(codes):
    return {
        "version": 1, "status": "rejected", "strong_indicators": [],
        "supporting_context": [], "likely_noise": [],
        "possible_activity_narrative": {"item_ids": [], "relationship_ids": [], "summary": "", "limitations": []},
        "recommended_follow_ups": [], "rejection_codes": list(dict.fromkeys(codes)),
    }


def _indicator_id(item_ids, evidence_ids):
    value = "|".join(sorted(item_ids) + sorted(evidence_ids))
    return "IR-" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:16].upper()


def _flatten(value, prefix=""):
    for key, child in value.items():
        path = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(child, Mapping):
            yield from _flatten(child, path)
        elif isinstance(child, (list, tuple)):
            yield path, " ".join(str(item) for item in child[:40])
        else:
            yield path, child


def _valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _rows(value):
    return [row for row in value if isinstance(row, Mapping)] if isinstance(value, list) else []


def _bounded_list(value, limit, width):
    values = value if isinstance(value, (list, tuple, set)) else ([] if value is None else [value])
    return list(dict.fromkeys(_text(item, width) for item in values if _text(item, width)))[:limit]


def _text(value, limit):
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        value = "; ".join(str(item) for item in value if item is not None)
    return " ".join(str(value).split())[:limit]

