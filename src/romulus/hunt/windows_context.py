"""Publish independent Windows link facts without accumulating hunt-wide auth/session records."""
from __future__ import annotations

from romulus.decide.policy import decide, publishable
from romulus.detect.base import ContextAnchor, ContextLink
from romulus.detect.metadata import hunt_rule_metadata, is_sigma_id
from romulus.detect.registry import anchor_class_for_rule
from romulus.detect.windows_linked import WINDOWS_LINKED_PLAYBOOKS
from romulus.evidence.typed import TypedEvent
from romulus.hunt.context import _publish_context, _write_cell
from romulus.hunt.publish import subject_event_ids


def publish_windows_link_context(repo, hunt_id, candidate, result, events, *, owner_token=None):
    """The caller already persisted every selected record and its raw bodies before evaluating this link.

    One link's bounded retrieval supplies the working set. No records, reaches or findings are kept between calls.
    The shared context publisher preserves stable identities, reach provenance and idempotent revisions.
    """
    if result.link_type not in {"process_session", "kerberos_logon"}:
        return []
    anchors = [TypedEvent.model_validate(row["event"]) for row in
               repo.citation_events(hunt_id, subject_event_ids(candidate))]
    if not anchors:
        return []
    metadata = (hunt_rule_metadata(repo, hunt_id, rule_ids={candidate['rule_id']})
                if is_sigma_id(candidate['rule_id']) else None)
    anchor = ContextAnchor(candidate["id"], anchor_class_for_rule(candidate["rule_id"], metadata=metadata), candidate["lane"],
                           candidate["claim"], anchors, candidate["rule_id"], anchors[0].ts)
    link = ContextLink(result.id, result.link_type, result.strength, result.key, events, result.status,
                       result.reasons, result.window.start, result.window.end)
    out = []
    for cls in WINDOWS_LINKED_PLAYBOOKS:
        playbook = cls()
        applicable = playbook.accepts(anchor, link)
        matched = 0
        for match in playbook.consume_linked(anchor, link, events):
            decision = decide(match, hunt_id)
            matched += 1                    # a positive, published or not, is never this reach's no-match
            if publishable(decision):
                candidate_id = _publish_context(repo, hunt_id, playbook, match, decision, [(anchor, link)],
                                                owner_token=owner_token)
                out.append(repo.candidate(candidate_id))
        _write_cell(repo, hunt_id, playbook, anchor.id, link, playbook.evaluated, playbook.missing_required,
                    matched, applicable, owner_token=owner_token)
    return out
