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
