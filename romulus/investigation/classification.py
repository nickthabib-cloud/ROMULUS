"""Evidence-owned candidate classification and independent investigation lifecycle."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from ..models import utc_now


CLASSIFICATIONS = {"anomalous", "suspicious", "malicious"}
INVESTIGATION_STATUSES = {
    "new", "investigating", "follow_up_exhausted", "resolved", "dismissed",
}
_REPORTABLE = {"suspicious", "malicious"}
_TERMINAL_FOLLOW_UP = {
    "completed", "blocked", "closed", "resolved", "failed", "skipped",
    "skipped_due_gap", "budget_limited", "not_applicable", "partial",
}


def apply_classification(
    candidate: Mapping[str, Any], *, relationship_count: int = 0,
) -> dict[str, Any]:
    """Apply reviewed deterministic policy without consulting priority or model output."""
    item = migrate_candidate(candidate)
    policy = item.get("classification_policy")
    if not isinstance(policy, Mapping):
        return refresh_investigation_status(item)

    current = str(item.get("classification") or "anomalous")
    desired = "anomalous"
    rule = "insufficient_reviewed_evidence"
    cited = _owned_evidence_ids(item)
    minimum = policy.get("minimum_owned_evidence")
    if (
        policy.get("default_classification") in {"anomalous", "suspicious"}
        and isinstance(minimum, int)
        and not isinstance(minimum, bool)
        and minimum >= 1
        and len(cited) >= minimum
    ):
        desired = str(policy["default_classification"])
        rule = "reviewed_catalog_policy"

    relationships = [
        row for row in item.get("related_candidates", [])
        if isinstance(row, Mapping)
        and row.get("candidate_id")
        and row.get("candidate_id") != item.get("candidate_id")
        and len({str(value) for value in row.get("evidence_ids", []) if value}) >= 2
    ]
    if (
        desired == "anomalous"
        and policy.get("upgrade_rule") == "independent_typed_entity_within_30m"
        and relationship_count > 0
        and relationships
    ):
        desired = "suspicious"
        rule = "independent_typed_entity_within_30m"
        cited = sorted({
            str(value)
            for row in relationships
            for value in row.get("evidence_ids", [])
            if value
        })

    explicit_benign = sorted({
        str(value) for value in item.get("explicit_benign_evidence_ids", []) if value
    })
    if explicit_benign and policy.get("downgrade_rule") == "explicit_benign_evidence_only":
        desired = "anomalous"
        rule = "explicit_benign_evidence_only"
        cited = explicit_benign

    # A missing current relationship is not negative evidence. Once promoted,
    # classification persists unless the reviewed explicit-benign rule fires.
    if current in _REPORTABLE and desired == "anomalous" and not explicit_benign:
        desired = current

    if current != desired:
        history = [dict(row) for row in item.get("classification_history", []) if isinstance(row, Mapping)]
        history.append({
            "prior": current,
            "new": desired,
            "rule": rule,
            "evidence_ids": cited,
            "timestamp": utc_now(),
        })
        item["classification_history"] = history
        item["classification"] = desired

    item["classification_policy_version"] = policy.get("policy_version")
    item["classification_reason"] = (
        str(policy.get("policy_reason") or "Reviewed deterministic classification policy.")
        if item["classification"] == policy.get("default_classification")
        else _classification_reason(rule)
    )
    return refresh_investigation_status(item)


def migrate_candidate(candidate: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize legacy/compact candidates conservatively without inventing truth."""
    item = dict(candidate) if isinstance(candidate, Mapping) else {}
    classification = item.get("classification")
    if classification == "malicious" and not _trusted_malicious_admission(item):
        classification = "anomalous"
        item["classification_reason"] = (
            "Malicious state lacked the complete strict trusted-indicator admission record and was migrated fail-closed."
        )
    if classification not in CLASSIFICATIONS:
        classification = "anomalous"
        item["classification_reason"] = (
            "Legacy candidate lacked a reviewed classification and was migrated fail-closed."
        )
    item["classification"] = classification
    item["classification_history"] = [
        dict(row) for row in item.get("classification_history", []) if isinstance(row, Mapping)
    ]
    return refresh_investigation_status(item)


def refresh_investigation_status(candidate: Mapping[str, Any]) -> dict[str, Any]:
    """Derive lifecycle solely from analyst disposition, findings, and follow-up work."""
    item = dict(candidate) if isinstance(candidate, Mapping) else {}
    disposition = str(item.get("disposition") or "observed")
    follow_ups = [row for row in item.get("follow_ups", []) if isinstance(row, Mapping)]
    statuses = [str(row.get("status") or "pending") for row in follow_ups]

    prior_status = str(item.get("investigation_status") or "")
    if disposition in {"benign_likely", "dismissed"} or prior_status == "dismissed":
        status = "dismissed"
    elif any(item.get("finding_ids", [])) or prior_status == "resolved":
        status = "resolved"
    elif any(value in {"pending", "in_progress", "scheduled", "running"} for value in statuses):
        status = "investigating"
    elif follow_ups and all(value in _TERMINAL_FOLLOW_UP for value in statuses):
        status = "follow_up_exhausted"
    elif prior_status in INVESTIGATION_STATUSES:
        status = prior_status
    elif disposition == "investigating":
        status = "investigating"
    else:
        status = "new"

    item["investigation_status"] = status
    item["customer_visible"] = bool(
        item.get("classification") in _REPORTABLE and status != "dismissed"
    )
    return item


def reportable_candidates(candidates: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    rows = [migrate_candidate(row) for row in candidates]
    rows = [
        row for row in rows
        if row.get("classification") in _REPORTABLE
        and row.get("investigation_status") != "dismissed"
    ]
    rank = {"malicious": 0, "suspicious": 1}
    return sorted(rows, key=lambda row: (
        rank[str(row["classification"])], str(row.get("candidate_id") or ""),
    ))


def unresolved_anomalous_candidates(
    candidates: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    rows = [migrate_candidate(row) for row in candidates]
    return sorted(
        [
            row for row in rows
            if row.get("classification") == "anomalous"
            and row.get("investigation_status") in {"new", "investigating", "follow_up_exhausted"}
        ],
        key=lambda row: str(row.get("candidate_id") or ""),
    )


def _owned_evidence_ids(candidate: Mapping[str, Any]) -> list[str]:
    return sorted({str(value) for value in candidate.get("evidence_ids", []) if value})


def _trusted_malicious_admission(candidate: Mapping[str, Any]) -> bool:
    confidence = candidate.get("indicator_confidence")
    return bool(
        candidate.get("kind") == "trusted_indicator"
        and isinstance(confidence, int)
        and not isinstance(confidence, bool)
        and confidence >= 90
        and str(candidate.get("indicator_source") or "").strip()
        and str(candidate.get("indicator_type") or "").strip()
        and str(candidate.get("indicator_value") or "").strip()
        and candidate.get("indicator_match_type") == "exact"
        and candidate.get("indicator_current_at_match") is True
        and _owned_evidence_ids(candidate)
    )


def _classification_reason(rule: str) -> str:
    if rule == "independent_typed_entity_within_30m":
        return "Independent typed-entity evidence within 30 minutes satisfied the reviewed upgrade rule."
    if rule == "explicit_benign_evidence_only":
        return "Explicit cited benign evidence satisfied the reviewed downgrade rule."
    return "Reviewed evidence requirements were not satisfied; retained as anomalous."
