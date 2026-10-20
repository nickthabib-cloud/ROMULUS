"""Evaluate context playbooks and persist anchor/link-scoped coverage truth."""
from __future__ import annotations

from dataclasses import dataclass

from romulus.decide.policy import Decision, decide
from romulus.detect.base import ContextAnchor, ContextLink, Match, Playbook
from romulus.detect.registry import fresh_context_pack
from romulus.store.repo import Repo


@dataclass
class ContextEvaluation:
    playbook: Playbook
    match: Match
    decision: Decision


def evaluate_context(
    repo: Repo, hunt_id: str, anchor: ContextAnchor, link: ContextLink, events,
) -> list[ContextEvaluation]:
    evaluations = []
    for playbook in fresh_context_pack():
        before_eval, before_missing = playbook.evaluated, playbook.missing_required
        matches = playbook.consume_linked(anchor, link, events)
        admitted = []
        for match in matches:
            decision = decide(match, hunt_id)
            if decision.admitted:
                admitted.append(ContextEvaluation(playbook, match, decision))
        evaluations.extend(admitted)
        evaluated = playbook.evaluated - before_eval
        missing = playbook.missing_required - before_missing
        partial = link.status != "complete" or missing > 0
        applicable = (("*" in playbook.anchor_classes or anchor.anchor_class in playbook.anchor_classes)
                      and link.link_type in playbook.link_types)
        if admitted:
            state = "match_on_partial" if partial else "matched"
        elif not applicable:
            state = "not_applicable_no_events"
        elif not playbook.assures_negative:
            state = "positive_only_partial" if partial else "positive_only"
        else:
            state = "evaluated_partial" if partial else "no_match_complete"
        repo.set_rule_cell(
            hunt_id, playbook.id, playbook.version, f"link:{link.link_type}",
            f"anchor:{anchor.id}|link:{link.id}", state, len(admitted), evaluated,
            {"anchor_id": anchor.id, "link_id": link.id, "link_type": link.link_type,
             "strength": link.strength, "missing_required": missing, "reasons": link.reasons},
        )
    return evaluations
