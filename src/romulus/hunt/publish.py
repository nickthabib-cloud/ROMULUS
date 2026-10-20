"""Shared deterministic publication for sweep and investigator discoveries."""
from __future__ import annotations

from romulus.decide.policy import LANE_ORDER, decide
from romulus.detect.base import Match, Playbook
from romulus.store.repo import Repo


def publish_match(repo: Repo, hunt_id: str, playbook: Playbook, match: Match,
                  task_id: str | None, raw_sources: dict[str, dict],
                  source_case_id: str | None = None, source_anchor_id: str | None = None,
                  source_link_id: str | None = None, context_reach: dict | None = None,
                  *, owner_token: str | None = None) -> dict | None:
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
        "gate_results": {
            **decision.gates,
            "_notes": decision.notes,
            **({"_context_reaches": [context_reach]} if context_reach else {}),
        },
        "benign_alternatives": list(playbook.benign),
        "next_checks": list(playbook.next_checks),
        "group_key": match.group_key,
        "source_case_id": source_case_id,
        "source_anchor_id": source_anchor_id,
        "source_link_id": source_link_id,
    }
    if repo.save_candidate(row, owner_token=owner_token):
        return row
    if context_reach is None or playbook.kind != "context":
        return None
    existing = repo.candidate(row["id"])
    if existing is None:
        return None
    gates = dict(existing["gate_results"])
    reaches = list(gates.get("_context_reaches", []))
    if context_reach not in reaches:
        reaches.append(context_reach)
    gates["_context_reaches"] = sorted(
        reaches, key=lambda reach: (
            reach["anchor_id"], reach["link_id"], reach["link_type"], reach["strength"],
        ),
    )
    stronger = LANE_ORDER.get(row["lane"], 9) < LANE_ORDER.get(existing["lane"], 9)
    updates = {
        "gate_results": gates,
        "event_ids": sorted(set(existing["event_ids"] + row["event_ids"])),
    }
    if stronger:
        updates.update({
            key: row[key] for key in (
                "claim", "severity", "confidence", "lane", "priority", "priority_reasons",
                "source_anchor_id", "source_link_id",
            )
        })
    repo.update_context_candidate(row["id"], updates, owner_token=owner_token)
    return repo.candidate(row["id"])
