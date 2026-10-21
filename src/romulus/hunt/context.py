"""Context playbooks: per-link coverage, and one deterministic pass after expansion that aggregates every
reach of a session or lineage into one candidate per (rule, group key)."""
from __future__ import annotations

from dataclasses import dataclass

from romulus.decide.policy import Decision, decide
from romulus.detect.base import ContextAnchor, ContextLink, Match, Playbook
from romulus.detect.registry import anchor_class_for_rule, fresh_context_pack
from romulus.evidence.typed import TypedEvent
from romulus.store.db import digest
from romulus.store.repo import Repo


@dataclass
class ContextEvaluation:
    playbook: Playbook
    match: Match
    decision: Decision


def _cell_state(playbook: Playbook, link_status: str, evaluated: int, missing: int,
                admitted: int, applicable: bool) -> str:
    partial = link_status != "complete" or missing > 0
    if admitted:
        return "match_on_partial" if partial else "matched"
    if not applicable:
        return "not_applicable_no_events"
    if evaluated == 0:
        return "evaluated_partial" if (partial or missing) else "not_applicable_no_events"
    if not playbook.assures_negative:
        return "positive_only_partial" if partial else "positive_only"
    return "evaluated_partial" if partial else "no_match_complete"


def _write_cell(repo: Repo, hunt_id: str, playbook: Playbook, anchor: ContextAnchor, link: ContextLink,
                evaluated: int, missing: int, admitted: int, applicable: bool,
                *, owner_token: str | None = None) -> None:
    state = _cell_state(playbook, link.status, evaluated, missing, admitted, applicable)
    repo.set_rule_cell(
        hunt_id, playbook.id, playbook.version, f"link:{link.link_type}",
        f"anchor:{anchor.id}|link:{link.id}", state, admitted, evaluated,
        {"anchor_id": anchor.id, "link_id": link.id, "link_type": link.link_type,
         "strength": link.strength, "missing_required": missing, "reasons": link.reasons},
        owner_token=owner_token,
    )


def evaluate_context(
    repo: Repo, hunt_id: str, anchor: ContextAnchor, link: ContextLink, events,
    *, owner_token: str | None = None,
) -> list[ContextEvaluation]:
    """Evaluate one reach for coverage and return its admitted matches. Publication of context candidates is
    the single post-expansion pass (`finalize_context`); this writes only the per-(rule, link) coverage cell."""
    evaluations = []
    for playbook in fresh_context_pack():
        before_eval, before_missing = playbook.evaluated, playbook.missing_required
        matches = playbook.consume_linked(anchor, link, events)
        admitted = [ContextEvaluation(playbook, match, decide(match, hunt_id))
                    for match in matches if decide(match, hunt_id).admitted]
        evaluations.extend(admitted)
        _write_cell(repo, hunt_id, playbook, anchor, link,
                    playbook.evaluated - before_eval, playbook.missing_required - before_missing,
                    len(admitted), playbook.accepts(anchor, link), owner_token=owner_token)
    return evaluations


# ------------------------------------------------------------------------------------------------
# The single post-expansion pass.
# ------------------------------------------------------------------------------------------------

def _session_of(event: TypedEvent, anchor: ContextAnchor, link: ContextLink) -> tuple:
    """A record's session identity (host, boot id, audit session), matching the rules' own group key. When no
    session id is typed, the anchor keeps lineages on one host apart."""
    session = event.get("process.session_id") or link.key.get("process.session_id")
    return (event.host, event.get("host.boot.id"), session if session is not None else f"lin:{anchor.id}")


def _representative(pairs: list[tuple]) -> tuple[ContextAnchor, ContextLink]:
    """The deterministic representative reach: an observed link beats inferred, then the lowest (anchor, link)
    id. The merged claim's wording and the candidate's source anchor/link come from it."""
    anchor, link = min(pairs, key=lambda pair: (0 if pair[1].strength == "observed" else 1,
                                                pair[0].id, pair[1].id))
    return anchor, link


def _reach_descriptors(pairs: list[tuple]) -> list[dict]:
    seen = {}
    for anchor, link in pairs:
        reach = {"anchor_id": anchor.id, "link_id": link.id, "link_type": link.link_type,
                 "strength": link.strength}
        seen[(reach["anchor_id"], reach["link_id"], reach["link_type"], reach["strength"])] = reach
    return [seen[key] for key in sorted(seen)]


def _publish_context(repo: Repo, hunt_id: str, playbook: Playbook, match: Match, decision: Decision,
                     pairs: list[tuple], *, owner_token: str | None = None) -> str:
    rep_anchor, rep_link = _representative(pairs)
    reaches = _reach_descriptors(pairs)
    event_ids = sorted({event.id for event in match.events})
    predicate = [{"field": p.field, "value": p.value, "origin": p.origin} for p in match.predicate]
    entities = [list(entity) for entity in match.entities]
    salient = {"claim": match.claim, "lane": decision.lane, "severity": decision.severity,
               "event_ids": event_ids, "predicate": predicate, "entities": entities, "reaches": reaches}
    finalize_digest = digest(salient)
    gate_results = {**decision.gates, "_notes": decision.notes, "_context_reaches": reaches,
                    "_finalize_digest": finalize_digest}
    row = {
        "id": decision.candidate_id, "hunt_id": hunt_id, "rule_id": match.playbook_id,
        "rule_version": playbook.version, "claim": match.claim, "claim_type": match.claim_type,
        "event_ids": event_ids, "predicate_fields": predicate, "entities": entities, "ts": match.ts,
        "severity": decision.severity, "confidence": decision.confidence, "lane": decision.lane,
        "priority": decision.priority, "priority_reasons": decision.priority_reasons,
        "gate_results": gate_results, "benign_alternatives": list(playbook.benign),
        "next_checks": list(playbook.next_checks), "group_key": match.group_key,
        "source_case_id": None, "source_anchor_id": rep_anchor.id, "source_link_id": rep_link.id,
    }
    repo.finalize_context_candidate(
        row, finalize_digest,
        {"candidate_id": row["id"], "new_lane": decision.lane, "new_claim_digest": finalize_digest,
         "records": len(event_ids)},
        owner_token=owner_token,
    )
    return row["id"]


def _finalize_rule(repo: Repo, hunt_id: str, playbook_cls, reaches: list[tuple],
                   *, owner_token: str | None = None) -> set[str]:
    # Records are grouped by session across every accepted reach, so a group's judgement (for example whether a
    # root process's parent is known) sees the whole session, not one window. A reach only ever contributes
    # records of a link type the rule accepts.
    coverage = []                                   # (anchor, link, evaluated, missing, applicable)
    sessions: dict[tuple, dict] = {}                # session key -> {events: {id: ev}, pairs: {(a.id,l.id): (a,l)}}
    for anchor, link, link_events in reaches:
        inst = playbook_cls()
        applicable = inst.accepts(anchor, link)
        eligible = inst.eligible_records(link_events) if applicable else []
        coverage.append((anchor, link, inst.evaluated, inst.missing_required, applicable))
        for event in eligible:
            skey = _session_of(event, anchor, link)
            bucket = sessions.setdefault(skey, {"events": {}, "pairs": {}})
            bucket["events"][event.id] = event
            bucket["pairs"][(anchor.id, link.id)] = (anchor, link)

    # One run per session over the union of its records; collect the admitted matches and which reaches fed them.
    admitted: dict[str, tuple] = {}                 # group key -> (match, decision, contributing pairs)
    contributing_reaches: set[tuple] = set()        # (anchor.id, link.id) that fed an admitted match
    for skey in sorted(sessions, key=lambda key: tuple(str(part) for part in key)):
        bucket = sessions[skey]
        pairs = [bucket["pairs"][key] for key in sorted(bucket["pairs"])]
        rep_anchor, rep_link = _representative(pairs)
        union_events = sorted(bucket["events"].values(), key=lambda event: (event.ts, event.id))
        session_admitted = False
        for match in playbook_cls().consume_linked(rep_anchor, rep_link, union_events):
            decision = decide(match, hunt_id)
            if decision.admitted:
                admitted[match.group_key] = (match, decision, pairs)
                session_admitted = True
        if session_admitted:
            contributing_reaches.update(bucket["pairs"])

    produced_ids = set()
    for _group_key, (match, decision, pairs) in sorted(admitted.items()):
        produced_ids.add(_publish_context(repo, hunt_id, playbook_cls(), match, decision, pairs,
                                          owner_token=owner_token))
    for anchor, link, evaluated, missing, applicable in coverage:
        contributed = (anchor.id, link.id) in contributing_reaches
        _write_cell(repo, hunt_id, playbook_cls(), anchor, link, evaluated, missing,
                    1 if contributed else 0, applicable, owner_token=owner_token)
    return produced_ids


def _withdraw_dropped(repo: Repo, hunt_id: str, rule_ids: set[str], produced_ids: set[str],
                      *, owner_token: str | None = None) -> None:
    claim = "withdrawn: the final evaluation over all linked records no longer supports this finding"
    for cand in repo.context_candidate_ids(hunt_id, rule_ids):
        if cand["id"] in produced_ids:
            continue
        existing = repo.candidate(cand["id"])
        if existing is None:
            continue
        reaches = existing["gate_results"].get("_context_reaches", [])
        event_ids = sorted(existing["event_ids"])
        salient = {"claim": claim, "lane": "context", "severity": "info", "event_ids": event_ids,
                   "predicate": existing["predicate_fields"], "entities": existing["entities"],
                   "reaches": reaches}
        finalize_digest = digest(salient)
        gate_results = {"_context_reaches": reaches, "_notes": ["withdrawn by the final context pass"],
                        "_finalize_digest": finalize_digest}
        row = {**existing, "claim": claim, "lane": "context", "severity": "info",
               "event_ids": event_ids, "gate_results": gate_results}
        repo.finalize_context_candidate(
            row, finalize_digest,
            {"candidate_id": cand["id"], "new_lane": "context", "new_claim_digest": finalize_digest,
             "records": len(event_ids)},
            owner_token=owner_token,
        )


def finalize_context(repo: Repo, hunt_id: str, *, owner_token: str | None = None) -> None:
    """One deterministic pass after expansion ends (and again after a resumed expansion). Every evaluated link
    is a reach; each context rule sees only reaches whose anchor class and link type it accepts, aggregates them
    per group key across reaches, and the result is upserted as one candidate per (rule, group key). A candidate
    a previous pass produced that this pass no longer does is withdrawn to the context lane. Order-independent:
    the output depends only on the set of reaches."""
    link_rows = sorted((row for row in repo.expansion_links(hunt_id) if row["evaluated"]),
                       key=lambda row: (row["anchor_id"], row["id"]))

    def events(ids: list[str]) -> list[TypedEvent]:
        found = [TypedEvent.model_validate(item["event"]) for item in repo.events_by_ids(ids)]
        return sorted(found, key=lambda event: (event.ts, event.id))

    candidates: dict[str, dict | None] = {}
    reaches = []
    for row in link_rows:
        anchor_id = row["anchor_id"]
        if anchor_id not in candidates:
            candidates[anchor_id] = repo.candidate(anchor_id)
        cand = candidates[anchor_id]
        if cand is None:
            continue
        anchor = ContextAnchor(id=cand["id"], anchor_class=anchor_class_for_rule(cand["rule_id"]),
                               lane=cand["lane"], claim=cand["claim"], events=events(cand["event_ids"]))
        link = ContextLink(id=row["id"], link_type=row["link_type"], strength=row["strength"], key=row["key"],
                           evidence_events=events(row["evidence_ids"]), status=row["status"],
                           reasons=row["reasons"])
        reaches.append((anchor, link, events(row["event_ids"])))

    rule_classes = [type(playbook) for playbook in fresh_context_pack()]
    produced_ids: set[str] = set()
    for playbook_cls in rule_classes:
        produced_ids |= _finalize_rule(repo, hunt_id, playbook_cls, reaches, owner_token=owner_token)
    _withdraw_dropped(repo, hunt_id, {cls.id for cls in rule_classes}, produced_ids, owner_token=owner_token)
