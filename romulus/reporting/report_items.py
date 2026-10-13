"""Normalized evidence-backed report items for both customer deliverables."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ..investigation.classification import reportable_candidates


def build_report_items(state: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Project classified candidates and findings without implicit de-duplication."""
    source = state if isinstance(state, Mapping) else {}
    candidates = reportable_candidates(_rows(source.get("candidate_leads")))
    findings = [dict(row) for row in _rows(source.get("findings")) if row.get("finding_id")]
    evidence = {
        str(row.get("evidence_id")): row
        for row in _rows(source.get("host")) + _rows(source.get("network"))
        if row.get("evidence_id")
    }
    candidates_by_finding: dict[str, list[dict[str, Any]]] = {}
    for candidate in candidates:
        for finding_id in _strings(candidate.get("finding_ids")):
            candidates_by_finding.setdefault(finding_id, []).append(candidate)

    items: list[dict[str, Any]] = []
    represented_candidates: set[str] = set()
    known_finding_ids = {str(row["finding_id"]) for row in findings}
    for finding in findings:
        finding_id = str(finding["finding_id"])
        linked = candidates_by_finding.get(finding_id, [])
        represented_candidates.update(
            str(row.get("candidate_id")) for row in linked if row.get("candidate_id")
        )
        items.append(_project_item(finding_id, linked, finding, evidence, source))

    for candidate in candidates:
        candidate_id = str(candidate.get("candidate_id") or "")
        if not candidate_id or candidate_id in represented_candidates:
            continue
        # A dangling finding reference cannot erase a reportable candidate.
        if candidate.get("finding_ids") and any(
            value in known_finding_ids for value in _strings(candidate.get("finding_ids"))
        ):
            continue
        items.append(_project_item(candidate_id, [candidate], None, evidence, source))

    rank = {"malicious": 0, "suspicious": 1}
    return sorted(items, key=lambda row: (
        rank.get(str(row.get("classification")), 2),
        str(row.get("first_observed") or ""),
        str(row.get("item_id") or ""),
    ))


def _project_item(
    item_id: str,
    candidates: list[dict[str, Any]],
    finding: Mapping[str, Any] | None,
    evidence: Mapping[str, Mapping[str, Any]],
    state: Mapping[str, Any],
) -> dict[str, Any]:
    finding = finding or {}
    classification = "malicious" if any(
        row.get("classification") == "malicious" for row in candidates
    ) else "suspicious"
    evidence_ids = _unique(
        _strings(finding.get("evidence_ids"))
        + [value for row in candidates for value in _strings(row.get("evidence_ids"))]
    )
    evidence_rows = [evidence[value] for value in evidence_ids if value in evidence]
    assets = _unique(
        _strings(finding.get("affected_assets") or finding.get("assets"))
        + [value for row in candidates for value in _strings(row.get("assets"))]
        + [str(row.get("asset")) for row in evidence_rows if row.get("asset")]
    )
    observed_times = sorted({
        str(value)
        for value in (
            [finding.get("first_observed"), finding.get("last_observed")]
            + [row.get("first_observed") for row in candidates]
            + [row.get("last_observed") for row in candidates]
            + [row.get("observed_at") for row in evidence_rows]
        )
        if value
    })
    statuses = [str(row.get("investigation_status") or "new") for row in candidates]
    status = _status(statuses, bool(finding))
    follow_up_results = _unique([
        _follow_up_result(follow_up)
        for candidate in candidates
        for follow_up in _rows(candidate.get("follow_ups"))
    ])
    finding_actions = _strings(finding.get("follow_up"))
    recommended = _unique(
        finding_actions
        + [
            str(follow_up.get("intent"))
            for candidate in candidates
            for follow_up in _rows(candidate.get("follow_ups"))
            if follow_up.get("intent")
        ]
        + ([] if finding_actions else [
            value for row in candidates for value in _strings(row.get("follow_up"))
        ])
    )
    gaps = _unique(
        [value for row in candidates for value in _strings(row.get("telemetry_gaps"))]
        + _state_coverage_gaps(state)
    )
    benign = _unique(
        _strings(finding.get("alternatives"))
        + [value for row in candidates for value in _strings(row.get("benign_explanations"))]
    )
    techniques = _unique(
        _strings([finding.get("technique_id")])
        + _strings(finding.get("attack_techniques"))
        + [value for row in candidates for value in _strings(row.get("attack_techniques"))]
    )
    why = _first(
        finding.get("interpretation"),
        finding.get("confidence_justification"),
        *[row.get("classification_reason") for row in candidates],
        *[row.get("description") for row in candidates],
    )
    observation = _first(
        finding.get("observation"),
        *[row.get("description") for row in candidates],
        *[row.get("title") for row in candidates],
    )
    confidence = _first(
        finding.get("confidence"),
        *[row.get("confidence") for row in candidates],
        *[row.get("indicator_confidence") for row in candidates],
    ) or "not assessed"
    return {
        "item_id": item_id,
        "candidate_ids": _unique([
            str(row.get("candidate_id")) for row in candidates if row.get("candidate_id")
        ]),
        "finding_ids": [str(finding["finding_id"])] if finding.get("finding_id") else [],
        "classification": classification,
        "title": _first(finding.get("title"), *[row.get("title") for row in candidates])
        or "Evidence-backed behavior",
        "observation": observation or "No compact observation was recorded.",
        "why_it_matters": why or "The evidence met a reviewed reportability policy.",
        "evidence_ids": evidence_ids,
        "assets": assets,
        "first_observed": observed_times[0] if observed_times else None,
        "last_observed": observed_times[-1] if observed_times else None,
        "investigation_status": status,
        "follow_up_results": follow_up_results,
        "benign_alternatives": benign,
        "coverage_gaps": gaps,
        "recommended_actions": recommended,
        "confidence": str(confidence),
        "attack_techniques": techniques,
    }


def _follow_up_result(follow_up: Mapping[str, Any]) -> str:
    status = str(follow_up.get("status") or "pending")
    history = [
        f"{row.get('task_id') or row.get('search_id') or 'attempt'}={row.get('status') or 'attempted'}"
        for row in _rows(follow_up.get("history"))
    ]
    return f"{follow_up.get('follow_up_id') or 'follow-up'}: {status}" + (
        f" ({'; '.join(history)})" if history else ""
    )


def _state_coverage_gaps(state: Mapping[str, Any]) -> list[str]:
    coverage = state.get("coverage") if isinstance(state.get("coverage"), Mapping) else {}
    values = []
    for gap in _rows(coverage.get("scheduler_gaps")):
        reason = gap.get("reason") or gap.get("event")
        if reason:
            values.append(str(reason))
    for error in _rows(state.get("source_errors")):
        detail = error.get("reason") or error.get("error") or error.get("error_kind")
        if detail:
            values.append(str(detail))
    return _unique(values)


def _status(statuses: list[str], finding_present: bool) -> str:
    if finding_present or "resolved" in statuses:
        return "resolved"
    if "follow_up_exhausted" in statuses:
        return "follow_up_exhausted"
    if "investigating" in statuses:
        return "investigating"
    return "new"


def _rows(value: Any) -> list[Mapping[str, Any]]:
    return [row for row in value if isinstance(row, Mapping)] if isinstance(value, list) else []


def _strings(value: Any) -> list[str]:
    if value is None:
        return []
    values = value if isinstance(value, (list, tuple, set)) else [value]
    return [str(item).strip() for item in values if item is not None and str(item).strip()]


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


def _first(*values: Any) -> str:
    return next((str(value).strip() for value in values if value is not None and str(value).strip()), "")
