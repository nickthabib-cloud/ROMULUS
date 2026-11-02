"""Shared deterministic publication for sweep and investigator discoveries."""
from __future__ import annotations

import hashlib
import json

from romulus.decide.policy import decide
from romulus.detect.base import Match, Playbook
from romulus.detect.observed import pointer_body
from romulus.evidence.normalize import normalize_hits, observed_record
from romulus.evidence.typed import TypedEvent, fv
from romulus.store.repo import Repo

LINEAGE_CITATION_BATCH = 500


class WindowsCitationFetcher:
    """Fetch bounded authentication witnesses by native index and document id, verifying recorded fields."""

    def __init__(self, client):
        self.client = client

    def hydrate(self, match: Match) -> None:
        compact = [event for event in match.events if any(
            note.startswith("Authentication witness body not retrieved") for note in event.caveats)]
        if not compact:
            return
        wanted = {}
        for event in compact:
            for ref in event.raw:
                wanted.setdefault(ref.target, set()).add(ref.native_id)
        hits = {}
        for index, identities in wanted.items():
            ordered = sorted(identities)
            for start in range(0, len(ordered), LINEAGE_CITATION_BATCH):
                batch = ordered[start:start+LINEAGE_CITATION_BATCH]
                try:
                    response = self.client.search(index, {"size": len(batch), "track_total_hits": False,
                        "query": {"bool": {"filter": [{"ids": {"values": batch}},
                                                     {"terms": {"_index": [index]}}]}}})
                except Exception:  # noqa: BLE001, S112 - downstream fixed caveat reports unavailable bodies
                    continue
                for hit in response.get("hits", {}).get("hits", []):
                    if hit.get("_index") == index and hit.get("_id") in identities:
                        hits[(index, hit["_id"])] = hit
        replacements = {}
        for event in compact:
            ref = event.raw[0]
            hit = hits.get((ref.target, ref.native_id))
            if hit is None:
                continue
            events, _skips, errors = normalize_hits([hit])
            actual = next((item for item in events if item.id == event.id), None)
            if errors or actual is None or any(actual.fields.get(name) != value for name, value in event.fields.items()):
                continue
            replacements[event.id] = actual
            match.raw_copies[ref.key] = hit["_source"]
        match.events = [replacements.get(event.id, event) for event in match.events]
        missing = len(compact)-len(replacements)
        if missing:
            note = (f"Authentication witness body not retrieved for {missing} cited records; "
                    "compact recorded fields, native index/document ids and timestamps are retained.")
            match.notes.append(note)
            match.claim += " " + note


def _exec_record(hits: list[dict], boot: list | tuple | None = None) -> TypedEvent | None:
    """Rebuild the one process_exec view from its raw audit records and sweep-assigned boot id."""
    events, _skips, errors = normalize_hits(hits)
    execs = [event for event in events if event.family == "process_exec"]
    if errors or len(execs) != 1:
        return None
    event = execs[0]
    if boot is not None and not event.has("host.boot.id"):
        event.fields["host.boot.id"] = fv(boot[0], boot[1])
    return event


class LineageCitationFetcher:
    """Re-read and verify only the raw records named by lineage citation pointers."""

    def __init__(self, client, contracts: dict):
        self.client = client
        self.contracts = contracts

    def load(self, pointers: dict[str, bytes]) -> tuple[dict, dict[str, dict]]:
        decoded = {
            event_id: body
            for event_id, blob in pointers.items()
            if (body := pointer_body(blob)) is not None and body.get("target") in self.contracts
        }
        wanted: dict[str, dict[str, set[str]]] = {}
        for body in decoded.values():
            target = body["target"]
            for index, native_id in body.get("records", []):
                wanted.setdefault(target, {}).setdefault(str(index), set()).add(str(native_id))
        fetched: dict[tuple[str, str], dict] = {}
        for target, by_index in sorted(wanted.items()):
            for index, native_ids in sorted(by_index.items()):
                ordered = sorted(native_ids)
                for start in range(0, len(ordered), LINEAGE_CITATION_BATCH):
                    batch = ordered[start:start + LINEAGE_CITATION_BATCH]
                    query = {
                        "size": len(batch),
                        "track_total_hits": False,
                        "query": {"bool": {"filter": [
                            {"ids": {"values": batch}},
                            {"terms": {"_index": [index]}},
                        ]}},
                    }
                    try:
                        response = self.client.search(target, query)
                    except Exception:  # noqa: BLE001, S112 - a failed re-read leaves these records uncited
                        continue
                    batch_set = {(index, native_id) for native_id in batch}
                    for hit in response.get("hits", {}).get("hits", []):
                        key = (str(hit.get("_index", "")), str(hit.get("_id", "")))
                        if key in batch_set and isinstance(hit.get("_source"), dict):
                            fetched[key] = hit

        events, raw = {}, {}
        for event_id, body in decoded.items():
            records = [(str(index), str(native_id)) for index, native_id in body.get("records", [])]
            hits = [fetched.get(record) for record in records]
            if not records or any(hit is None for hit in hits):
                continue
            sources = [hit["_source"] for hit in hits]
            encoded = json.dumps(sources, sort_keys=True, separators=(",", ":"), default=str).encode()
            if hashlib.sha256(encoded).hexdigest() != body.get("raw_digest"):
                continue
            event = (
                observed_record(hits[0], body.get("boot"))
                if body["kind"] == "observed"
                else _exec_record(hits, body.get("boot"))
            )
            if event is None or event.id != event_id:
                continue
            events[event_id] = event
            raw.update({f"{index}/{native_id}": hit["_source"]
                        for (index, native_id), hit in zip(records, hits, strict=True)})
        return events, raw


def subject_event_ids(candidate: dict) -> list[str]:
    """The records a finding is about: its cited records except those cited only to support what its claim states
    (`Match.context_ids`). Expansion and the context pass start from these, so citing more never widens their reach.
    A candidate stored without the field (an older hunt) is about every record it cites."""
    context = set(candidate.get("context_event_ids") or ())
    subject = [event_id for event_id in candidate["event_ids"] if event_id not in context]
    return subject or list(candidate["event_ids"])


def expansion_candidate_id(base_id: str, match: Match) -> str:
    """Bind an expansion finding's group identity to the raw records it is actually about.

    Aggregate group keys intentionally collapse records inside one evaluation. Across independent anchor
    evaluations, however, the same key can describe different subject records. Including their raw identity keeps
    those findings separate while allowing two anchors that reached the same records to share one candidate.
    """
    subject = [event for event in match.events if event.id not in match.context_ids] or list(match.events)
    raw_identity = [
        sorted((ref.target, ref.native_id) for ref in event.raw)
        for event in sorted(subject, key=lambda event: event.id)
    ]
    material = json.dumps(raw_identity, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(f"{base_id}|{material}".encode()).hexdigest()[:20]


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


def _view_preference(predicates, view_field):
    quality = [item["value"] for item in predicates if item["field"] == "script.view_quality"
               and isinstance(item["value"], int) and not isinstance(item["value"], bool)]
    if quality:
        return max(quality)
    ranks = {"fragment": 0, "single": 1, "joined": 2}
    return max((ranks.get(item["value"], -1) for item in predicates if item["field"] == view_field), default=-1)


def publish_match(repo: Repo, hunt_id: str, playbook: Playbook, match: Match,
                  task_id: str | None, raw_sources: dict[str, dict],
                  source_case_id: str | None = None, source_anchor_id: str | None = None,
                  source_link_id: str | None = None, context_reach: dict | None = None,
                  *, owner_token: str | None = None) -> dict | None:
    """Persist cited evidence and publish a machine-decided finding once, with stable script-view revisions.
    Context findings are published by the post-expansion pass (romulus.hunt.context.finalize_context)."""
    fetcher = getattr(playbook, "citation_fetcher", None)
    if fetcher is not None:
        fetcher.hydrate(match)
    decision = decide(match, hunt_id)
    if match.raw_copies:
        raw_sources = {**match.raw_copies, **raw_sources}
    repo.save_evidence(hunt_id, match.events, raw_sources, task_id, owner_token=owner_token)
    event_ids = [event.id for event in match.events]
    context_event_ids = sorted({event.id for event in match.events} & match.context_ids)
    candidate_id = decision.candidate_id
    view_field = playbook.evidence_view_field if match.group_key else ""
    existing_view = repo.candidate(candidate_id) if view_field else None
    if source_case_id is None and source_anchor_id is not None and not view_field:
        existing = repo.candidate(candidate_id)
        same_subject = (
            existing is not None
            and repo.candidate_subject_raw_identity(existing)
            == repo.candidate_subject_raw_identity({
                "event_ids": event_ids, "context_event_ids": context_event_ids,
            })
        )
        if not same_subject:
            candidate_id = expansion_candidate_id(candidate_id, match)
    row = {
        "id": candidate_id,
        "hunt_id": hunt_id,
        "rule_id": match.playbook_id,
        "rule_version": playbook.version,
        "claim": match.claim,
        "claim_type": match.claim_type,
        "event_ids": event_ids,
        "context_event_ids": context_event_ids,
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
    if view_field:
        # This is an independently reportable, canonical script block observation, even if discovered by
        # expansion. Preserve its discovery reach without making a new raw-subject-owned expansion candidate.
        origin = ((existing_view or {}).get("gate_results") or {}).get("_evidence_view_origin")
        if origin is None:
            first_discovery = existing_view if existing_view is not None else row
            origin = {name: first_discovery.get(name)
                      for name in ("source_case_id", "source_anchor_id", "source_link_id")}
        row["gate_results"]["_evidence_view_origin"] = origin
        if (existing_view is not None and existing_view.get("source_case_id") is not None
                and source_case_id is None and source_anchor_id is None and source_link_id is None):
            # Sweep rediscovery follows ordinary agent-to-deterministic ownership
            # while keeping the best evidence view and its first discovery origin.
            canonical = {**existing_view, "source_case_id": None, "source_anchor_id": None, "source_link_id": None}
            repo.save_candidate(canonical, canonicalize_agent=True, owner_token=owner_token)
            existing_view = repo.candidate(candidate_id)
        if existing_view is not None:
            # Other investigator views retain the current canonical ownership.
            for name in ("source_case_id", "source_anchor_id", "source_link_id"):
                row[name] = existing_view.get(name)
    if view_field and existing_view is not None:
        # The stable group identifies the same script regardless of which source/pivot supplied its view.
        # Fresh evaluator instances cannot remember the prior view, so compare its persisted predicate.
        old_rank = _view_preference(existing_view["predicate_fields"], view_field)
        new_rank = _view_preference(row["predicate_fields"], view_field)
        if new_rank <= old_rank:
            retained = {**existing_view, "gate_results": {**existing_view["gate_results"],
                "_evidence_view_origin": origin,
                **({"_context_reaches": [context_reach]} if context_reach else {})}}
            repo.revise_candidate(retained, "Additional discovery context for the retained script evidence view",
                                  owner_token=owner_token, evidence_view=True)
            return None
        repo.revise_candidate(row, match.revision_reason or "A preferred evidence view replaces the prior citations",
                              owner_token=owner_token, evidence_view=True)
        return None
    if match.revision_reason and source_case_id is None and source_anchor_id is None:
        # the corrected decision for a direct finding already published under this id: revised in place. A revision
        # is not a new candidate, so it returns None (the sweep's new-candidate count and live callback are
        # unchanged); only a first publication under the id returns the row.
        status = repo.revise_candidate(row, match.revision_reason, owner_token=owner_token)
        return row if status == "inserted" else None
    return row if repo.save_candidate(
        row, canonicalize_agent=source_case_id is None, owner_token=owner_token,
    ) else None
