"""Pure, fail-closed admission for untrusted investigator and critic output."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import re
from typing import Any

from ..intelligence.knowledge import TECHNIQUES
from .casefile import visible_case_ids


_COLLECTIONS = (
    ("assessments", "assessment"),
    ("new_hypotheses", "new_hypothesis"),
    ("searches", "search"),
    ("findings", "finding"),
)
_ISSUE_CODES = {
    "citation_mismatch",
    "unsupported_causality",
    "ignored_benign_alternative",
    "duplicate_work",
    "missing_discriminating_search",
    "avoidable_search_cost",
    "malformed",
}
_SOURCES = {"elasticsearch", "arkime", "tshark"}
_DIRECTIONS = {"backward", "forward", "cross_source", "validation"}
_ASSESSMENT_STATUS = {"supported", "contradicted", "inconclusive", "not_tested"}
_NATIVE_LANGUAGES = {"none", "elasticsearch_dsl", "arkime", "tshark"}
_ENTITY_FIELDS = (
    "host.name", "host.ip", "user.name", "source.ip", "destination.ip", "dns.host"
)


def admit_reasoning(
    case_file: Mapping[str, Any],
    investigator_output: Mapping[str, Any],
    critic_output: Mapping[str, Any],
    existing_hypotheses: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Validate untrusted structured reasoning without mutating or executing it."""
    case = case_file if isinstance(case_file, Mapping) else {}
    investigator = investigator_output if isinstance(investigator_output, Mapping) else {}
    critic = critic_output if isinstance(critic_output, Mapping) else {}
    rejections: list[dict[str, Any]] = []

    proposals, proposal_kinds, invalid_proposals = _collect_proposals(investigator, rejections)
    approved = _critic_approvals(
        critic, proposals, proposal_kinds, invalid_proposals, rejections
    )

    visible = visible_case_ids(case)
    candidate_rows = {
        identifier: row
        for row in _rows(case.get("candidates"))
        if (identifier := _text(row.get("candidate_id"), 120))
    }
    evidence_rows = {
        identifier: row
        for row in _rows(case.get("evidence"))
        if (identifier := _text(row.get("evidence_id"), 120))
    }
    case_hypotheses = {
        identifier: row
        for row in _rows(case.get("hypotheses"))
        if (identifier := _text(row.get("hypothesis_id"), 120))
    }
    existing_rows = {
        identifier: row
        for row in existing_hypotheses
        if isinstance(row, Mapping) and (identifier := _text(row.get("hypothesis_id"), 120))
    }
    visible_existing_ids = set(case_hypotheses).intersection(existing_rows)
    candidate_evidence = {
        candidate_id: set(_strings(row.get("evidence_ids"), 120, 100))
        for candidate_id, row in candidate_rows.items()
    }
    candidate_follow_ups = {
        candidate_id: {
            _text(item.get("follow_up_id"), 120)
            for item in _rows(row.get("follow_ups"))
            if _text(item.get("follow_up_id"), 120)
        }
        for candidate_id, row in candidate_rows.items()
    }

    search_checks: dict[str, tuple[dict[str, Any] | None, list[str]]] = {}
    for row in _rows(investigator.get("searches")):
        proposal_id = _text(row.get("proposal_id"), 120)
        if not proposal_id or proposal_id not in approved:
            continue
        hypothesis_ref = _text(row.get("hypothesis_ref"), 120)
        hypothesis = case_hypotheses.get(hypothesis_ref, {})
        expected_candidate = _hypothesis_candidate_id(hypothesis)
        allowed_entities = _hypothesis_scope_entities(
            hypothesis, candidate_rows, candidate_evidence, evidence_rows
        ) if hypothesis else set()
        anchor_rows = [evidence_rows[item] for item in
            _strings(row.get("anchor_evidence_ids"), 120, 8) if item in evidence_rows]
        allowed_entities.update(_anchors(anchor_rows)["entities"])
        search_checks[proposal_id] = _validate_search(
            row, visible, candidate_rows, candidate_evidence, candidate_follow_ups,
            expected_candidate_id=expected_candidate,
            allowed_entities=allowed_entities,
        )

    existing_fingerprints: dict[str, str] = {}
    for hypothesis_id, row in existing_rows.items():
        fingerprint = _existing_fingerprint(row)
        if fingerprint:
            existing_fingerprints.setdefault(fingerprint, hypothesis_id)

    new_hypotheses = []
    hypothesis_proposal_map: dict[str, str] = {}
    invalid_new_hypotheses: set[str] = set()
    for row in _rows(investigator.get("new_hypotheses")):
        proposal_id = _text(row.get("proposal_id"), 120)
        if not proposal_id or proposal_id not in approved:
            continue
        normalized, reasons = _validate_new_hypothesis(
            row, candidate_rows, candidate_evidence, evidence_rows
        )
        related_searches = []
        if normalized is not None:
            for search in _rows(investigator.get("searches")):
                search_id = _text(search.get("proposal_id"), 120)
                if search_id not in approved or _text(search.get("hypothesis_ref"), 120) != proposal_id:
                    continue
                checked, search_reasons = search_checks.get(search_id, (None, ["malformed_search"]))
                dependency_reasons = _new_hypothesis_search_reasons(search, normalized)
                if checked is not None and not search_reasons and not dependency_reasons:
                    related_searches.append(search_id)
            if not related_searches:
                reasons.append("missing_approved_discriminating_search")
        if reasons or normalized is None:
            invalid_new_hypotheses.add(proposal_id)
            _reject(rejections, proposal_id, "new_hypothesis", reasons or ["malformed"])
            continue
        fingerprint = _hypothesis_fingerprint(normalized)
        stable_id = _stable_hypothesis_id(fingerprint)
        existing_id = existing_fingerprints.get(fingerprint)
        if existing_id:
            hypothesis_proposal_map[proposal_id] = existing_id
            _reject(rejections, proposal_id, "new_hypothesis", ["duplicate_hypothesis"])
            continue
        normalized["hypothesis_id"] = stable_id
        normalized["proposal_id"] = proposal_id
        new_hypotheses.append(normalized)
        hypothesis_proposal_map[proposal_id] = stable_id
        existing_fingerprints[fingerprint] = stable_id

    searches = []
    for row in _rows(investigator.get("searches")):
        proposal_id = _text(row.get("proposal_id"), 120)
        if not proposal_id or proposal_id not in approved:
            continue
        normalized, reasons = search_checks.get(proposal_id, (None, ["malformed_search"]))
        hypothesis_ref = _text(row.get("hypothesis_ref"), 120)
        if hypothesis_ref in visible_existing_ids:
            hypothesis_id = hypothesis_ref
        elif hypothesis_ref in hypothesis_proposal_map:
            hypothesis_id = hypothesis_proposal_map[hypothesis_ref]
        else:
            hypothesis_id = ""
            reasons = list(reasons) + [
                "invalid_hypothesis_ref" if hypothesis_ref in invalid_new_hypotheses
                else "unknown_hypothesis_ref"
            ]
        if reasons or normalized is None:
            _reject(rejections, proposal_id, "search", reasons or ["malformed"])
            continue
        normalized["hypothesis_id"] = hypothesis_id
        searches.append(normalized)

    assessments = []
    supported_assessments: dict[str, set[str]] = {}
    for row in _rows(investigator.get("assessments")):
        proposal_id = _text(row.get("proposal_id"), 120)
        if not proposal_id or proposal_id not in approved:
            continue
        normalized, reasons = _validate_assessment(
            row, visible_existing_ids, case_hypotheses, candidate_rows,
            candidate_evidence, evidence_rows
        )
        if reasons or normalized is None:
            _reject(rejections, proposal_id, "assessment", reasons or ["malformed"])
            continue
        assessments.append(normalized)
        if normalized["status"] == "supported":
            supported_assessments[normalized["hypothesis_id"]] = set(normalized["evidence_ids"])

    findings = []
    for row in _rows(investigator.get("findings")):
        proposal_id = _text(row.get("proposal_id"), 120)
        if not proposal_id or proposal_id not in approved:
            continue
        normalized, reasons = _validate_finding(
            row, visible_existing_ids, case_hypotheses, existing_rows, evidence_rows,
            supported_assessments,
        )
        if reasons or normalized is None:
            _reject(rejections, proposal_id, "finding", reasons or ["malformed"])
            continue
        findings.append(normalized)

    summary = {
        "proposals_received": len(proposals),
        "critic_reviews_received": len(_rows(critic.get("reviews"))),
        "critic_approved": len(approved),
        "new_hypotheses_admitted": len(new_hypotheses),
        "assessments_admitted": len(assessments),
        "searches_admitted": len(searches),
        "findings_admitted": len(findings),
        "rejections": len(rejections),
    }
    return {
        "new_hypotheses": new_hypotheses,
        "assessments": assessments,
        "searches": searches,
        "findings": findings,
        "rejections": rejections,
        "summary": summary,
    }


def _collect_proposals(
    investigator: Mapping[str, Any], rejections: list[dict[str, Any]]
) -> tuple[dict[str, Mapping[str, Any]], dict[str, str], set[str]]:
    proposals: dict[str, Mapping[str, Any]] = {}
    kinds: dict[str, str] = {}
    invalid: set[str] = set()
    for collection, kind in _COLLECTIONS:
        value = investigator.get(collection, [])
        if not isinstance(value, list):
            _reject(rejections, f"<{collection}>", kind, ["malformed_collection"])
            continue
        for index, row in enumerate(value):
            if not isinstance(row, Mapping):
                _reject(rejections, f"<{collection}:{index}>", kind, ["malformed"])
                continue
            proposal_id = _text(row.get("proposal_id"), 120)
            if not proposal_id:
                _reject(rejections, f"<{collection}:{index}>", kind, ["missing_proposal_id"])
                continue
            if proposal_id in proposals:
                invalid.add(proposal_id)
                _reject(rejections, proposal_id, "proposal", ["duplicate_proposal_id"])
                continue
            proposals[proposal_id] = row
            kinds[proposal_id] = kind
    return proposals, kinds, invalid


def _critic_approvals(
    critic: Mapping[str, Any],
    proposals: Mapping[str, Mapping[str, Any]],
    proposal_kinds: Mapping[str, str],
    invalid_proposals: set[str],
    rejections: list[dict[str, Any]],
) -> set[str]:
    reviews = critic.get("reviews", [])
    if not isinstance(reviews, list):
        reviews = []
        _reject(rejections, "<reviews>", "critic", ["malformed_collection"])
    review_map: dict[str, Mapping[str, Any]] = {}
    duplicate_reviews: set[str] = set()
    for index, review in enumerate(reviews):
        if not isinstance(review, Mapping):
            _reject(rejections, f"<review:{index}>", "critic", ["malformed"])
            continue
        proposal_id = _text(review.get("proposal_id"), 120)
        if not proposal_id or proposal_id not in proposals:
            _reject(rejections, proposal_id or f"<review:{index}>", "critic", ["unknown_critic_reference"])
            continue
        if proposal_id in review_map:
            duplicate_reviews.add(proposal_id)
            _reject(rejections, proposal_id, proposal_kinds.get(proposal_id, "proposal"),
                ["duplicate_critic_review"])
            continue
        review_map[proposal_id] = review

    approved = set()
    for proposal_id in proposals:
        kind = proposal_kinds.get(proposal_id, "proposal")
        if proposal_id in invalid_proposals or proposal_id in duplicate_reviews:
            continue
        review = review_map.get(proposal_id)
        if review is None:
            _reject(rejections, proposal_id, kind, ["unreviewed"])
            continue
        decision = _text(review.get("decision"), 20).lower()
        issues = [item for item in _strings(review.get("issue_codes"), 80, 20) if item in _ISSUE_CODES]
        raw_issues = _strings(review.get("issue_codes"), 80, 20)
        if len(issues) != len(raw_issues) or decision not in {"accept", "reject"}:
            _reject(rejections, proposal_id, kind, ["malformed_critic_review"])
            continue
        if decision == "reject":
            _reject(rejections, proposal_id, kind, ["critic_rejected", *issues])
            continue
        if issues:
            _reject(rejections, proposal_id, kind, ["inconsistent_critic_accept", *issues])
            continue
        approved.add(proposal_id)
    return approved


def _validate_new_hypothesis(
    row: Mapping[str, Any],
    candidate_rows: Mapping[str, Mapping[str, Any]],
    candidate_evidence: Mapping[str, set[str]],
    evidence_rows: Mapping[str, Mapping[str, Any]],
) -> tuple[dict[str, Any] | None, list[str]]:
    reasons = []
    candidate_id = _text(row.get("candidate_id"), 120)
    evidence_ids = _strings(row.get("evidence_ids"), 120, 20)
    candidate = candidate_rows.get(candidate_id)
    if candidate is None:
        reasons.append("unknown_candidate")
    if not evidence_ids:
        reasons.append("missing_evidence_citation")
    unknown = [identifier for identifier in evidence_ids if identifier not in evidence_rows]
    if unknown:
        reasons.append("unknown_evidence")
    if candidate is not None and any(
        identifier in evidence_rows and identifier not in candidate_evidence.get(candidate_id, set())
        for identifier in evidence_ids
    ):
        reasons.append("cross_candidate_citation")

    technique_id = _text(row.get("technique_id"), 60)
    supported = set(_strings(candidate.get("attack_techniques"), 60, 30)) if candidate else set()
    if technique_id != "unmapped" and (
        technique_id not in TECHNIQUES or technique_id not in supported
    ):
        reasons.append("unsupported_attack_mapping")

    expected_host = _strings(row.get("expected_host"), 240, 8)
    expected_network = _strings(row.get("expected_network"), 240, 8)
    falsifying = _strings(row.get("falsifying_observations"), 240, 8)
    benign = _strings(row.get("benign_explanations"), 240, 8)
    title = _text(row.get("title"), 200)
    explanation = _text(row.get("explanation"), 400)
    analytic_goal = _text(row.get("analytic_goal"), 360)
    if not title:
        reasons.append("missing_title")
    if not explanation:
        reasons.append("missing_explanation")
    if not expected_host and not expected_network:
        reasons.append("missing_expected_observation")
    if not falsifying:
        reasons.append("missing_falsifying_observation")
    if not benign:
        reasons.append("missing_benign_alternative")
    if not analytic_goal:
        reasons.append("missing_analytic_goal")

    anchors = _anchors([evidence_rows[item] for item in evidence_ids if item in evidence_rows])
    if not anchors["entities"] and not anchors["time_range"]:
        reasons.append("missing_observed_anchor")
    if reasons:
        return None, _unique(reasons)

    entities = anchors["entities"]
    ips = [value for value in entities if _is_ip(value)]
    hostnames = [value for value in entities if not _is_ip(value)]
    return {
        "title": title,
        "technique_id": technique_id,
        "rationale": explanation,
        "expected_host": expected_host,
        "expected_network": expected_network,
        "falsifying_observations": falsifying,
        "benign_explanations": benign,
        "analytic_goal": analytic_goal,
        "basis": "model_grounded_competing",
        "basis_candidate_ids": [candidate_id],
        "basis_evidence_ids": evidence_ids,
        "candidate_evidence_ids": evidence_ids,
        "evidence_ids": [],
        "candidate_id": candidate_id,
        "candidate_assets": _strings(candidate.get("assets"), 160, 20),
        "anchor_entities": entities,
        "anchor_time_range": anchors["time_range"],
        "ips": ips,
        "hostnames": hostnames,
        "status": "untested",
        "confidence": "not assessed",
    }, []


def _validate_search(
    row: Mapping[str, Any],
    visible: Mapping[str, set[str]],
    candidate_rows: Mapping[str, Mapping[str, Any]],
    candidate_evidence: Mapping[str, set[str]],
    candidate_follow_ups: Mapping[str, set[str]],
    *,
    expected_candidate_id: str = "",
    allowed_entities: set[str] | None = None,
) -> tuple[dict[str, Any] | None, list[str]]:
    reasons = []
    source = _text(row.get("source"), 80).lower()
    direction = _text(row.get("direction"), 40).lower()
    candidate_id = _text(row.get("candidate_id"), 120)
    follow_up_id = _text(row.get("follow_up_id"), 120)
    anchors = _strings(row.get("anchor_evidence_ids"), 120, 4)
    if source not in _SOURCES:
        reasons.append("unsupported_source")
    if direction not in _DIRECTIONS:
        reasons.append("malformed_direction")
    if not _text(row.get("intent"), 300) or not _text(row.get("discriminating_goal"), 300):
        reasons.append("missing_discriminating_search")
    if expected_candidate_id:
        if candidate_id and candidate_id != expected_candidate_id:
            reasons.append("search_candidate_mismatch")
        candidate_id = expected_candidate_id
    if candidate_id and candidate_id not in candidate_rows:
        reasons.append("unknown_candidate")
    if follow_up_id:
        if follow_up_id not in visible.get("follow_up", set()):
            reasons.append("unknown_follow_up")
        elif candidate_id and follow_up_id not in candidate_follow_ups.get(candidate_id, set()):
            reasons.append("cross_candidate_follow_up")
    if any(identifier not in visible.get("evidence", set()) for identifier in anchors):
        reasons.append("unknown_evidence")
    if candidate_id and any(
        identifier in visible.get("evidence", set())
        and identifier not in candidate_evidence.get(candidate_id, set())
        for identifier in anchors
    ):
        reasons.append("cross_candidate_citation")
    explicit_entities = {
        normalized for value in [*_strings(row.get("ips"), 80, 8),
            *_strings(row.get("hostnames"), 255, 8)]
        if (normalized := _normalize_entity(value))
    }
    if explicit_entities and not explicit_entities.issubset(set(allowed_entities or set())):
        reasons.append("search_entity_mismatch")
    native_language = _text(row.get("native_query_language"), 40).lower() or "none"
    native_query = _text(row.get("native_query"), 1600)
    if native_language not in _NATIVE_LANGUAGES:
        reasons.append("malformed_native_query")
    selectors = any((
        _strings(row.get("terms"), 100, 8),
        _strings(row.get("ips"), 80, 8),
        _strings(row.get("hostnames"), 255, 8),
        _numbers(row.get("ports"), 12),
        _strings(row.get("protocols"), 40, 8),
        _numbers(row.get("event_codes"), 12),
        anchors,
        native_query if native_language != "none" else "",
    ))
    if not selectors:
        reasons.append("empty_search_selector")
    if reasons:
        return None, _unique(reasons)
    return {
        "proposal_id": _text(row.get("proposal_id"), 120),
        "source": source,
        "intent": _text(row.get("intent"), 300),
        "direction": direction,
        "discriminating_goal": _text(row.get("discriminating_goal"), 300),
        "candidate_id": candidate_id,
        "follow_up_id": follow_up_id,
        "terms": _strings(row.get("terms"), 100, 8),
        "fields": _strings(row.get("fields"), 180, 16),
        "ips": _strings(row.get("ips"), 80, 8),
        "hostnames": _strings(row.get("hostnames"), 255, 8),
        "ports": _numbers(row.get("ports"), 12),
        "protocols": _strings(row.get("protocols"), 40, 8),
        "event_codes": _numbers(row.get("event_codes"), 12),
        "index_class": _text(row.get("index_class"), 40),
        "anchor_evidence_ids": anchors,
        "native_query_language": native_language,
        "native_query": native_query,
    }, []


def _new_hypothesis_search_reasons(
    search: Mapping[str, Any], hypothesis: Mapping[str, Any]
) -> list[str]:
    reasons = []
    candidate_id = _text(search.get("candidate_id"), 120)
    expected_candidate = hypothesis["candidate_id"]
    if candidate_id != expected_candidate:
        reasons.append("search_candidate_mismatch")
    cited = set(hypothesis["basis_evidence_ids"])
    anchors = set(_strings(search.get("anchor_evidence_ids"), 120, 8))
    if anchors and not anchors.issubset(cited):
        reasons.append("search_anchor_mismatch")
    selectors = {
        normalized for value in [*_strings(search.get("ips"), 80, 8),
            *_strings(search.get("hostnames"), 255, 8)]
        if (normalized := _normalize_entity(value))
    }
    allowed = {_normalize_entity(value) for value in hypothesis.get("anchor_entities", [])}
    allowed.discard("")
    if selectors and not selectors.issubset(allowed):
        reasons.append("search_entity_mismatch")
    return reasons


def _validate_assessment(
    row: Mapping[str, Any],
    visible_existing_ids: set[str],
    case_hypotheses: Mapping[str, Mapping[str, Any]],
    candidate_rows: Mapping[str, Mapping[str, Any]],
    candidate_evidence: Mapping[str, set[str]],
    evidence_rows: Mapping[str, Mapping[str, Any]],
) -> tuple[dict[str, Any] | None, list[str]]:
    reasons = []
    hypothesis_id = _text(row.get("hypothesis_id"), 120)
    evidence_ids = _strings(row.get("evidence_ids"), 120, 20)
    status = _text(row.get("status"), 40).lower()
    if hypothesis_id not in visible_existing_ids:
        reasons.append("unknown_hypothesis_ref")
    if status not in _ASSESSMENT_STATUS:
        reasons.append("malformed_assessment")
    if any(identifier not in evidence_rows for identifier in evidence_ids):
        reasons.append("unknown_evidence")
    hypothesis = case_hypotheses.get(hypothesis_id, {})
    candidate_id = _hypothesis_candidate_id(hypothesis)
    if candidate_id and any(
        identifier in evidence_rows and identifier not in candidate_evidence.get(candidate_id, set())
        for identifier in evidence_ids
    ):
        reasons.append("cross_candidate_citation")
    if status in {"supported", "contradicted"} and not evidence_ids:
        reasons.append("missing_evidence_citation")
    if status in {"supported", "contradicted"} and evidence_ids:
        scope = _hypothesis_scope_entities(
            hypothesis, candidate_rows, candidate_evidence, evidence_rows
        )
        if not scope:
            reasons.append("missing_hypothesis_entity_scope")
        elif any(not scope.intersection(_anchors([evidence_rows[identifier]])["entities"])
                for identifier in evidence_ids if identifier in evidence_rows):
            reasons.append("citation_entity_mismatch")
    if reasons:
        return None, _unique(reasons)
    return {
        "proposal_id": _text(row.get("proposal_id"), 120),
        "hypothesis_id": hypothesis_id,
        "status": status,
        "evidence_ids": evidence_ids,
        "observation": _text(row.get("observation"), 360),
        "interpretation": _text(row.get("interpretation"), 360),
        "benign_alternatives": _strings(row.get("benign_alternatives"), 240, 8),
        "rationale": _text(row.get("rationale"), 300),
    }, []


def _validate_finding(
    row: Mapping[str, Any],
    visible_existing_ids: set[str],
    case_hypotheses: Mapping[str, Mapping[str, Any]],
    existing_rows: Mapping[str, Mapping[str, Any]],
    evidence_rows: Mapping[str, Mapping[str, Any]],
    supported_assessments: Mapping[str, set[str]],
) -> tuple[dict[str, Any] | None, list[str]]:
    reasons = []
    hypothesis_id = _text(row.get("hypothesis_id"), 120)
    evidence_ids = _strings(row.get("evidence_ids"), 120, 20)
    if hypothesis_id not in visible_existing_ids:
        reasons.append("unknown_hypothesis_ref")
    if not evidence_ids:
        reasons.append("missing_evidence_citation")
    if any(identifier not in evidence_rows for identifier in evidence_ids):
        reasons.append("unknown_evidence")
    hypothesis = existing_rows.get(hypothesis_id, case_hypotheses.get(hypothesis_id, {}))
    technique_id = _text(row.get("technique_id"), 60)
    expected_technique = _text(hypothesis.get("technique_id"), 60)
    if (expected_technique == "unmapped" and technique_id != "unmapped") or (
        expected_technique != "unmapped" and (
            expected_technique not in TECHNIQUES or technique_id != expected_technique
        )
    ):
        reasons.append("unsupported_attack_mapping")
    assessment = hypothesis.get("model_assessment") or hypothesis.get("deterministic_assessment")
    prior_supported = _text(hypothesis.get("status"), 40).lower() == "supported"
    if isinstance(assessment, Mapping):
        prior_supported = prior_supported or _text(assessment.get("status"), 40).lower() == "supported"
    cited_support = supported_assessments.get(hypothesis_id)
    if not prior_supported and cited_support is None:
        reasons.append("unsupported_hypothesis")
    if cited_support is not None and not set(evidence_ids).issubset(cited_support):
        reasons.append("citation_mismatch")
    alternatives = _strings(row.get("alternatives"), 240, 8)
    if not alternatives:
        reasons.append("missing_benign_alternative")
    if not _text(row.get("observation"), 360) or not _text(row.get("interpretation"), 360):
        reasons.append("malformed_finding")
    if reasons:
        return None, _unique(reasons)
    return {
        "proposal_id": _text(row.get("proposal_id"), 120),
        "hypothesis_id": hypothesis_id,
        "title": _text(row.get("title"), 200),
        "technique_id": expected_technique,
        "observation": _text(row.get("observation"), 360),
        "interpretation": _text(row.get("interpretation"), 360),
        "evidence_ids": evidence_ids,
        "confidence": _text(row.get("confidence"), 40),
        "confidence_justification": _text(row.get("confidence_justification"), 300),
        "alternatives": alternatives,
        "follow_up": _strings(row.get("follow_up"), 240, 8),
    }, []


def _anchors(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    entities = []
    timestamps: list[tuple[datetime, str]] = []
    for row in rows:
        values = [_text(row.get("asset"), 200)]
        raw = row.get("raw") if isinstance(row.get("raw"), Mapping) else {}
        values.extend(_flatten_text(raw.get(field)) for field in _ENTITY_FIELDS)
        for value in values:
            for text in value if isinstance(value, list) else [value]:
                normalized = _normalize_entity(text)
                if normalized and normalized not in entities:
                    entities.append(normalized)
        timestamp = _text(row.get("observed_at"), 80)
        parsed = _parse_time(timestamp)
        if parsed is not None:
            timestamps.append((parsed, timestamp))
    timestamps.sort(key=lambda item: item[0])
    time_range = {}
    if timestamps:
        time_range = {"start": timestamps[0][1], "end": timestamps[-1][1]}
    return {"entities": entities[:24], "time_range": time_range}


def _hypothesis_scope_entities(
    hypothesis: Mapping[str, Any],
    candidate_rows: Mapping[str, Mapping[str, Any]],
    candidate_evidence: Mapping[str, set[str]],
    evidence_rows: Mapping[str, Mapping[str, Any]],
) -> set[str]:
    entities = {
        normalized for key in ("anchor_entities", "candidate_assets", "ips", "hostnames")
        for value in _strings(hypothesis.get(key), 255, 30)
        if (normalized := _normalize_entity(value))
    }
    candidate_id = _hypothesis_candidate_id(hypothesis)
    candidate = candidate_rows.get(candidate_id, {})
    entities.update(normalized for value in _strings(candidate.get("assets"), 200, 30)
        if (normalized := _normalize_entity(value)))
    evidence_ids = set(candidate_evidence.get(candidate_id, set()))
    evidence_ids.update(_strings(
        hypothesis.get("basis_evidence_ids") or hypothesis.get("evidence_ids"), 120, 30
    ))
    rows = [evidence_rows[item] for item in evidence_ids if item in evidence_rows]
    entities.update(_anchors(rows)["entities"])
    return entities


def _existing_fingerprint(row: Mapping[str, Any]) -> str:
    candidate_id = _hypothesis_candidate_id(row)
    evidence_ids = _strings(
        row.get("basis_evidence_ids") or row.get("candidate_evidence_ids") or row.get("evidence_ids"),
        120, 30,
    )
    expected_host = _strings(row.get("expected_host"), 240, 8)
    expected_network = _strings(row.get("expected_network"), 240, 8)
    falsifying = _strings(row.get("falsifying_observations"), 240, 8)
    if not candidate_id or not evidence_ids or (not expected_host and not expected_network) or not falsifying:
        return ""
    return _hypothesis_fingerprint({
        "candidate_id": candidate_id,
        "technique_id": _text(row.get("technique_id"), 60),
        "basis_evidence_ids": evidence_ids,
        "expected_host": expected_host,
        "expected_network": expected_network,
        "falsifying_observations": falsifying,
    })


def _hypothesis_fingerprint(row: Mapping[str, Any]) -> str:
    payload = {
        "candidate_id": _text(row.get("candidate_id"), 120),
        "technique_id": _text(row.get("technique_id"), 60),
        "evidence_ids": sorted(_strings(row.get("basis_evidence_ids"), 120, 30)),
        "expected_host": _normalized_phrases(row.get("expected_host")),
        "expected_network": _normalized_phrases(row.get("expected_network")),
        "falsifying_observations": _normalized_phrases(row.get("falsifying_observations")),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _stable_hypothesis_id(fingerprint: str) -> str:
    digest = hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()[:16].upper()
    return f"H-AI-{digest}"


def _hypothesis_candidate_id(row: Mapping[str, Any]) -> str:
    candidate_id = _text(row.get("candidate_id"), 120)
    if candidate_id:
        return candidate_id
    candidates = _strings(row.get("basis_candidate_ids"), 120, 4)
    return candidates[0] if candidates else ""


def _normalized_phrases(value: Any) -> list[str]:
    return sorted({re.sub(r"\s+", " ", item).strip().lower()
        for item in _strings(value, 240, 20) if item.strip()})


def _reject(
    rejections: list[dict[str, Any]], proposal_id: str, kind: str, reason_codes: Sequence[str]
) -> None:
    codes = _unique([_text(code, 100) for code in reason_codes if _text(code, 100)])
    if not codes:
        codes = ["malformed"]
    existing = next((row for row in rejections
        if row.get("proposal_id") == proposal_id and row.get("kind") == kind), None)
    if existing is not None:
        existing["reason_codes"] = _unique([*existing.get("reason_codes", []), *codes])
        return
    rejections.append({"proposal_id": proposal_id, "kind": kind, "reason_codes": codes})


def _rows(value: Any) -> list[Mapping[str, Any]]:
    if not isinstance(value, (list, tuple)):
        return []
    return [row for row in value if isinstance(row, Mapping)]


def _strings(value: Any, item_limit: int, count_limit: int) -> list[str]:
    if isinstance(value, (str, int, float, bool)):
        value = [value]
    if not isinstance(value, (list, tuple, set)):
        return []
    result = []
    for item in value:
        text = _text(item, item_limit)
        if text and text not in result:
            result.append(text)
        if len(result) >= count_limit:
            break
    return result


def _numbers(value: Any, count_limit: int) -> list[int]:
    if not isinstance(value, (list, tuple, set)):
        return []
    result = []
    for item in value:
        if isinstance(item, bool):
            continue
        try:
            number = int(item)
        except (TypeError, ValueError):
            continue
        if number not in result:
            result.append(number)
        if len(result) >= count_limit:
            break
    return result


def _text(value: Any, limit: int) -> str:
    if isinstance(value, (str, int, float)) and not isinstance(value, bool):
        return str(value).strip()[:limit]
    return ""


def _flatten_text(value: Any) -> list[str]:
    if isinstance(value, (str, int, float)) and not isinstance(value, bool):
        return [str(value)]
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value[:20]
            if isinstance(item, (str, int, float)) and not isinstance(item, bool)]
    return []


def _normalize_entity(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return re.sub(r"\s+", " ", value).strip().lower()[:255]


def _parse_time(value: str) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _unique(values: Sequence[str]) -> list[str]:
    return list(dict.fromkeys(values))


__all__ = ["admit_reasoning"]
