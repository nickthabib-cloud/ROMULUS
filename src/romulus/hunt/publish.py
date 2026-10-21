"""Shared deterministic publication for sweep and investigator discoveries."""
from __future__ import annotations

from romulus.decide.policy import decide
from romulus.detect.base import ContextAnchor, ContextLink, Match, Playbook
from romulus.evidence.typed import TypedEvent
from romulus.store.db import digest
from romulus.store.repo import Repo


def _events_from_ids(repo: Repo, ids: list[str]) -> list[TypedEvent]:
    rows = repo.events_by_ids(ids)
    return [TypedEvent.model_validate(row["event"]) for row in rows]


def _representative_reach(reaches: list[dict]) -> dict | None:
    """Deterministic representative among a candidate's reaches: an observed link beats an inferred one, then
    the lowest (anchor id, link id). Independent of the order reaches were recorded."""
    if not reaches:
        return None
    return min(reaches, key=lambda reach: (
        0 if reach.get("strength") == "observed" else 1,
        reach.get("anchor_id", ""), reach.get("link_id", ""),
    ))


def rebuild_context_candidate(repo: Repo, hunt_id: str, playbook: Playbook, existing: dict,
                              extra_events: list[TypedEvent], reaches: list[dict], reason: str,
                              *, owner_token: str | None = None) -> None:
    """Re-run a context rule's aggregation over the union of the candidate's cited events and `extra_events`,
    with a deterministic representative anchor/link, and set the candidate to the rebuilt match (lane up or
    down). If the union no longer yields a match for this key, withdraw to the context lane, keeping the
    evidence. Every change is audited. The result does not depend on evaluation order."""
    union = {event.id: event for event in _events_from_ids(repo, existing["event_ids"])}
    for event in extra_events:
        union[event.id] = event
    union_ids = sorted(union)
    rep = _representative_reach(reaches)
    gates = dict(existing["gate_results"])
    sorted_reaches = sorted(reaches, key=lambda reach: (
        reach["anchor_id"], reach["link_id"], reach["link_type"], reach["strength"]))
    target = None
    if rep is not None:
        anchor = ContextAnchor(id=rep["anchor_id"], anchor_class=rep.get("anchor_class", "execution"),
                               lane="", claim="", events=[])
        link = ContextLink(id=rep["link_id"], link_type=rep["link_type"], strength=rep["strength"],
                           key={}, evidence_events=[], status="complete")
        matches = playbook.__class__().consume_linked(anchor, link, list(union.values()))
        target = next((m for m in matches if m.group_key == existing["group_key"]), None)

    old_lane, old_claim = existing["lane"], existing["claim"]
    if target is not None:
        decision = decide(target, hunt_id)
        new_gates = {**decision.gates, "_notes": decision.notes, "_context_reaches": sorted_reaches}
        updates = {
            "claim": target.claim,
            "predicate_fields": [{"field": p.field, "value": p.value, "origin": p.origin}
                                 for p in target.predicate],
            "entities": [list(entity) for entity in target.entities],
            "ts": target.ts, "event_ids": union_ids, "lane": decision.lane, "severity": decision.severity,
            "confidence": decision.confidence, "priority": decision.priority,
            "priority_reasons": decision.priority_reasons, "gate_results": new_gates,
            "source_anchor_id": rep["anchor_id"], "source_link_id": rep["link_id"],
        }
        new_claim, new_lane = target.claim, decision.lane
    else:
        gates["_context_reaches"] = sorted_reaches
        gates["_notes"] = [f"withdrawn: {reason}"]
        new_claim = (f"withdrawn: a wider evaluation of the same session no longer supports this finding "
                     f"({reason})")
        new_lane = "context"
        updates = {"claim": new_claim, "lane": new_lane, "severity": "info", "confidence": "low",
                   "priority": 0.0, "event_ids": union_ids, "gate_results": gates}

    repo.update_context_candidate(existing["id"], updates, owner_token=owner_token)
    if new_lane != old_lane or new_claim != old_claim:
        repo.audit("system", "context.rebuild", hunt_id, {
            "candidate_id": existing["id"], "old_lane": old_lane, "new_lane": new_lane,
            "old_claim_digest": digest(old_claim), "new_claim_digest": digest(new_claim),
            "reason": reason, "records": len(union_ids),
        }, owner_token=owner_token)


def refute_context_candidates(repo: Repo, hunt_id: str, window_events: list[TypedEvent],
                              produced: set, context_packs: dict, *, owner_token: str | None = None) -> None:
    """Re-judge existing context candidates whose evidence this window touched but whose key it did not produce
    (for example an entry point the wider window now shows had an internal source). Rebuilds over the union; a
    key that no longer matches is withdrawn to the context lane."""
    window_ids = {event.id for event in window_events}
    for candidate in repo.candidates(hunt_id):
        playbook = context_packs.get(candidate["rule_id"])
        if playbook is None:
            continue
        if (candidate["rule_id"], candidate["group_key"]) in produced:
            continue
        if not (set(candidate["event_ids"]) & window_ids):
            continue
        reaches = list(candidate["gate_results"].get("_context_reaches", []))
        rebuild_context_candidate(repo, hunt_id, playbook, candidate, window_events, reaches,
                                  "rebuilt from the union after a wider evaluation of the same session",
                                  owner_token=owner_token)


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
    # A second evaluation of the same session (a wider window, or a different anchor) adds evidence. Rebuild the
    # candidate from the union of its cited events and the incoming match's, so claim, predicates and lane match
    # the merged evidence regardless of which window or anchor was evaluated first (the lane follows the
    # evidence, up or down).
    reaches = list(existing["gate_results"].get("_context_reaches", []))
    if context_reach not in reaches:
        reaches.append(context_reach)
    rebuild_context_candidate(repo, hunt_id, playbook, existing, list(match.events), reaches,
                              "rebuilt from the union of the merged records", owner_token=owner_token)
    return repo.candidate(row["id"])
