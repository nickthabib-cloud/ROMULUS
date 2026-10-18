"""Shared deterministic publication for sweep and investigator discoveries."""
from __future__ import annotations

from romulus.decide.policy import decide
from romulus.detect.base import Match, Playbook
from romulus.store.repo import Repo


def publish_match(repo: Repo, hunt_id: str, playbook: Playbook, match: Match,
                  task_id: str | None, raw_sources: dict[str, dict],
                  source_case_id: str | None = None, *, owner_token: str | None = None) -> dict | None:
    """Persist cited evidence and publish a machine-decided candidate once."""
    decision = decide(match, hunt_id)
    repo.save_evidence(hunt_id, match.events, raw_sources, task_id, owner_token=owner_token)
    row = {
        "id": decision.candidate_id,
        "hunt_id": hunt_id,
        "rule_id": match.playbook_id,
        "rule_version": playbook.version,
        "claim": match.claim,
        "claim_type": match.claim_type,
        "event_ids": [event.id for event in match.events],
        "predicate_fields": [
            {"field": predicate.field, "value": predicate.value, "origin": predicate.origin}
            for predicate in match.predicate
        ],
        "entities": [list(entity) for entity in match.entities],
        "ts": match.ts,
        "severity": decision.severity,
        "confidence": decision.confidence,
        "lane": decision.lane,
        "priority": decision.priority,
        "priority_reasons": decision.priority_reasons,
        "gate_results": {**decision.gates, "_notes": decision.notes},
        "benign_alternatives": list(playbook.benign),
        "next_checks": list(playbook.next_checks),
        "source_case_id": source_case_id,
    }
    return row if repo.save_candidate(row, owner_token=owner_token) else None
