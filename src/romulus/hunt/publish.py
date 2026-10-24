"""Shared deterministic publication for sweep and investigator discoveries."""
from __future__ import annotations

from romulus.decide.policy import decide
from romulus.detect.base import Match, Playbook
from romulus.store.repo import Repo


def subject_event_ids(candidate: dict) -> list[str]:
    """The records a finding is about: its cited records except those cited only to support what its claim states
    (`Match.context_ids`). Expansion and the context pass start from these, so citing more never widens their reach.
    A candidate stored without the field (an older hunt) is about every record it cites."""
    context = set(candidate.get("context_event_ids") or ())
    subject = [event_id for event_id in candidate["event_ids"] if event_id not in context]
    return subject or list(candidate["event_ids"])


def mark_hypothesis_relation(match: Match, *, anchor_id: str, link_type: str,
                             link_id: str, strength: str) -> None:
    """Label a non-observed relation without weakening the finding's own cited claim."""
    if strength == "observed":
        return
    relation = "agent-requested" if strength == "agent_hypothesis" else "inferred"
    match.claim += (f" Its relation to {anchor_id} rests on an {relation} {link_type} reach "
                    f"{link_id} and is a hypothesis; the actor is not proven identical.")
    match.notes.append(
        f"reached through an {relation} {link_type} relation: the relation to the anchor "
        "is a hypothesis, the finding itself is not",
    )


def publish_match(repo: Repo, hunt_id: str, playbook: Playbook, match: Match,
                  task_id: str | None, raw_sources: dict[str, dict],
                  source_case_id: str | None = None, source_anchor_id: str | None = None,
                  source_link_id: str | None = None, context_reach: dict | None = None,
                  *, owner_token: str | None = None) -> dict | None:
    """Persist cited evidence and publish a machine-decided candidate once. Direct (sweep) findings only;
    context findings are published by the single post-expansion pass (romulus.hunt.context.finalize_context)."""
    decision = decide(match, hunt_id)
    if match.raw_copies:
        raw_sources = {**match.raw_copies, **raw_sources}
    repo.save_evidence(hunt_id, match.events, raw_sources, task_id, owner_token=owner_token)
    row = {
        "id": decision.candidate_id,
        "hunt_id": hunt_id,
        "rule_id": match.playbook_id,
        "rule_version": playbook.version,
        "claim": match.claim,
        "claim_type": match.claim_type,
        "event_ids": [event.id for event in match.events],
        "context_event_ids": sorted({event.id for event in match.events} & match.context_ids),
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
    return row if repo.save_candidate(
        row, canonicalize_agent=source_case_id is None, owner_token=owner_token,
    ) else None
