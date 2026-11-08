"""Shared deterministic publication for sweep and investigator discoveries."""
from __future__ import annotations

import hashlib
import json
from dataclasses import replace

import httpx

from romulus.decide.policy import candidate_group_id, decide
from romulus.detect.base import Match, Playbook
from romulus.detect.observed import pointer_body
from romulus.errors import SourceError
from romulus.evidence.normalize import normalize_hits, observed_record, raw_digest
from romulus.evidence.typed import TypedEvent, fv
from romulus.hunt.citations import COMPACT_CITATION_NOTE
from romulus.store.repo import Repo, raw_id

LINEAGE_CITATION_BATCH = 500
# A group-keyed finding that expansion reaches again absorbs the reach instead of gaining a sibling. Its reaches are
# listed up to this many (the rest are counted), and folds together add at most this many subject records to its
# citations (the first and latest of each reach first): one finding per group stays a bounded row however many
# anchors reach it.
FOLD_REACHES_LISTED = 32
FOLD_CITATIONS_ADDED = 8
_LANE_RANK = {"suppressed": 0, "context": 1, "lead": 2, "high": 3, "urgent": 4}
_SEVERITY_RANK = {"info": 0, "informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}


def bind_aggregate_history(repo: Repo, hunt_id: str, playbook: Playbook) -> None:
    """Restore one bounded published checkpoint on demand, without a hunt-wide cache."""
    def load(group_key):
        existing = repo.candidate(candidate_group_id(playbook.id, group_key, hunt_id))
        summary = ((existing or {}).get('gate_results') or {}).get('aggregate_summary')
        if not summary:
            return None
        events = [TypedEvent.model_validate(row['event']) for row in
                  repo.citation_events(hunt_id, list(existing.get('event_ids') or ())[:4])]
        return {'summary': dict(summary), 'lane': existing['lane'], 'events': events}
    playbook.published_aggregate = load


def _retrieval_note(error):
    message = str(error)
    kind = ("authorization" if "HTTP 401" in message or "HTTP 403" in message else
            "mapping/query" if "HTTP 400" in message else "retrieval")
    return f"Citation {kind} error: {message[:300]}. Citation coverage is partial for this finding."


class SourceCitationFetcher:
    """Hydrate compact staged witnesses without changing their recorded normalized fields."""

    def __init__(self, client):
        self.client = client

    def hydrate(self, match: Match, raw_sources=None):
        compact = [event for event in match.events if COMPACT_CITATION_NOTE in event.caveats]
        if not compact:
            return
        sources = {**match.raw_copies, **(raw_sources or {})}
        wanted = {}
        for event in compact:
            for ref in event.raw:
                if ref.key not in sources:
                    wanted.setdefault(ref.target, set()).add(ref.native_id)
        for index, ids in sorted(wanted.items()) if self.client is not None else ():
            ordered = sorted(ids)
            for start in range(0, len(ordered), LINEAGE_CITATION_BATCH):
                batch = ordered[start:start+LINEAGE_CITATION_BATCH]
                try:
                    response = self.client.search(index, {"size": len(batch), "track_total_hits": False,
                        "query": {"bool": {"filter": [{"ids": {"values": batch}}, {"terms": {"_index": [index]}}]}}})
                except (SourceError, httpx.TransportError, FileNotFoundError) as error:
                    note = _retrieval_note(error)
                    if note not in match.notes:
                        match.notes.append(note)
                        match.claim += " "+note
                    continue
                for hit in response.get("hits", {}).get("hits", []):
                    if hit.get("_index") == index and hit.get("_id") in ids and isinstance(hit.get("_source"), dict):
                        sources[f"{index}/{hit['_id']}"] = hit["_source"]
        missing = []
        replacements = {}
        for event in compact:
            valid = {ref.key: sources[ref.key] for ref in event.raw if ref.key in sources and
                     (not ref.digest or raw_digest(sources[ref.key]) == ref.digest)}
            match.raw_copies.update(valid)
            if len(valid) == len(event.raw):
                replacements[event.id] = event.model_copy(update={"caveats": [
                    note for note in event.caveats if note != COMPACT_CITATION_NOTE]})
            else:
                missing.append(event.id)
        match.events = [replacements.get(event.id, event) for event in match.events]
        if missing:
            note = (f"Citation body not retrieved for {len(missing)} cited records; compact recorded fields, "
                    "native index/document ids and timestamps are retained. Citation coverage is partial for this finding.")
            match.notes.append(note)
            match.claim += " " + note


class WindowsCitationFetcher:
    """Fetch bounded authentication witnesses by native index and document id, verifying recorded fields."""

    def __init__(self, client):
        self.client = client

    def hydrate(self, match: Match, raw_sources=None) -> None:
        SourceCitationFetcher(self.client).hydrate(match, raw_sources)
        compact = [event for event in match.events if any(
            note.startswith("Authentication witness body not retrieved") for note in event.caveats)]
        if not compact:
            return
        wanted = {}
        for event in compact:
            for ref in event.raw:
                wanted.setdefault(ref.target, set()).add(ref.native_id)
        hits = {(ref.target, ref.native_id): {"_index": ref.target, "_id": ref.native_id, "_source": raw_sources[ref.key]}
                for event in compact for ref in event.raw if raw_sources and ref.key in raw_sources}
        for index, identities in sorted(wanted.items()) if self.client is not None else ():
            ordered = sorted(identities)
            for start in range(0, len(ordered), LINEAGE_CITATION_BATCH):
                batch = [identity for identity in ordered[start:start+LINEAGE_CITATION_BATCH]
                         if (index, identity) not in hits]
                if not batch:
                    continue
                try:
                    response = self.client.search(index, {"size": len(batch), "track_total_hits": False,
                        "query": {"bool": {"filter": [{"ids": {"values": batch}},
                                                     {"terms": {"_index": [index]}}]}}})
                except (SourceError, httpx.TransportError, FileNotFoundError) as error:
                    note = _retrieval_note(error)
                    if note not in match.notes:
                        match.notes.append(note)
                        match.claim += " "+note
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
            if body["kind"] == "typed":
                normalized, _skips, errors = normalize_hits(hits)
                event = next((candidate for candidate in normalized if candidate.id == event_id), None) if not errors else None
                if event is not None and body.get("boot") is not None and not event.has("host.boot.id"):
                    event.fields["host.boot.id"] = fv(*body["boot"])
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


def _strongest(values, rank):
    return max(values, key=lambda value: rank.get(str(value), -1))


def _fold_reach(repo: Repo, hunt_id: str, match: Match, decision, existing: dict, context_reach: dict | None,
                *, owner_token: str | None = None, keep_decision: bool = False) -> dict | None:
    """Fold an expansion reach of an already published group (same hunt, rule and group key) into its one candidate.

    The candidate keeps its identity, ownership, citations and claim; the reach adds its anchor and link to the
    candidate's reaches, its matching records to a stated (possibly overlapping) re-read count, and, within
    FOLD_CITATIONS_ADDED, its first and latest records to the citations. The lane, severity, confidence and priority
    are the strongest of the parts: a fold never lowers them. With `keep_decision` (records the sweep evaluated) they
    stay the candidate's own. Revised in place, never retracted. Returns the stored candidate when the fold raised
    its lane into the expanded lanes (so expansion may anchor on it), else None."""
    if keep_decision:
        decision = replace(decision, lane=existing["lane"], severity=existing["severity"],
                           confidence=existing["confidence"], priority=float(existing["priority"] or 0),
                           priority_reasons=existing["priority_reasons"])
    gates = dict(existing.get("gate_results") or {})
    fold = dict(gates.get("_expansion_fold") or {})
    fold.setdefault("base_claim", existing["claim"])
    listed = [dict(item) for item in fold.get("reaches", [])]
    reach = dict(context_reach or {})
    reach_key = (reach.get("anchor_id"), reach.get("link_id"))
    subject = sorted((event for event in match.events if event.id not in match.context_ids),
                     key=lambda event: (event.ts, event.id)) or sorted(match.events, key=lambda e: (e.ts, e.id))
    span = match.aggregate_summary or {}
    first = span.get("first", subject[0].ts.timestamp() if subject else None)
    last = span.get("last", subject[-1].ts.timestamp() if subject else None)
    records = int(span.get("count") or len(subject))
    if any((item.get("anchor_id"), item.get("link_id")) == reach_key for item in listed):
        return None                         # this reach is already folded (a resumed expansion)
    cited = list(existing.get("event_ids") or [])
    # Records of this reach that the finding does not cite yet; a cited one is certainly a repeat.
    beyond = max(0, records - sum(event.id in cited for event in subject))
    fold["reaches_total"] = int(fold.get("reaches_total") or 0) + 1
    if len(listed) < FOLD_REACHES_LISTED:
        listed.append({**reach, "records": records, "first": first, "last": last})
    fold["reaches"] = listed
    fold["records"] = int(fold.get("records") or 0) + beyond
    if beyond:
        starts = [value for value in (fold.get("first"), first) if value is not None]
        ends = [value for value in (fold.get("last"), last) if value is not None]
        fold["first"], fold["last"] = (min(starts) if starts else None), (max(ends) if ends else None)
    added = list(fold.get("added") or [])
    room = max(0, FOLD_CITATIONS_ADDED - len(added))
    order = {event.id: event for event in [*subject[:1], *subject[-1:], *subject[1:-1]]}
    new = [event for event_id, event in order.items() if event_id not in cited][:room]
    added += [event.id for event in new]
    fold["added"] = added
    lane = _strongest([existing["lane"], decision.lane], _LANE_RANK)
    severity = _strongest([existing["severity"], decision.severity], _SEVERITY_RANK)
    confidence = _strongest([existing["confidence"], decision.confidence], _CONFIDENCE_RANK)
    inferred = any(item.get("strength") != "observed" for item in listed)
    # The reached span is kept with the fold (`first`, `last`), not stated: its endpoints need not be cited records.
    if fold["records"]:
        claim = (f"{fold['base_claim']} Expansion also reached this group through {fold['reaches_total']} reach(es) "
                 f"and read {fold['records']} matching record(s) not cited above (they may repeat records already "
                 f"counted)" + (f"; {len(added)} of the {fold['records']} are now cited" if added else "") + ".")
    else:
        claim = (f"{fold['base_claim']} Expansion also reached this group through {fold['reaches_total']} reach(es), "
                 f"and every record they read is already cited.")
    if inferred:
        claim += (" A reach through an inferred link relates this group to its anchor only as a hypothesis; the "
                  "records themselves are observed.")
    if lane != existing["lane"]:
        fold["raised_to"] = lane
    if fold.get("raised_to"):
        claim += f" A reach's own evaluation of its records put the group in the {fold['raised_to']} lane."
    reaches = {(item["anchor_id"], item["link_id"], item["link_type"], item["strength"]): item
               for item in [*gates.get("_context_reaches", []), *([context_reach] if context_reach else [])]}
    gates["_context_reaches"] = [reaches[key] for key in sorted(reaches)]
    gates["_expansion_fold"] = fold
    notes = {str(note) for note in gates.get("_notes", [])}
    notes |= {str(note) for note in decision.notes if str(note).startswith(("reached through an inferred ",
                                                                             "reached through an agent-requested "))}
    # why a reach could not resolve a reader's lineage, for the first few readers (the row stays bounded)
    for note in decision.notes:
        if (str(note).startswith("Lineage for the reader ")
                and sum(item.startswith("Lineage for the reader ") for item in notes) < FOLD_REACHES_LISTED // 4):
            notes.add(str(note))
    gates["_notes"] = sorted(notes)
    if (published := gates.get("aggregate_summary")) and first is not None and last is not None:
        gates["aggregate_summary"] = {**published, "first": min(published["first"], first),
                                      "last": max(published["last"], last)}
    predicate = list(existing.get("predicate_fields") or [])
    new_ids = {event.id for event in new}
    origins = {ref.native_id for event in new for ref in event.raw}
    predicate += [{"field": p.field, "value": p.value, "origin": p.origin} for p in match.predicate
                  if new_ids and p.origin.split(":", 1)[0] in origins]
    entities = [list(entity) for entity in dict.fromkeys(
        [tuple(entity) for entity in existing.get("entities") or []]
        + ([tuple(entity) for entity in match.entities] if new else []))]
    row = {
        "id": existing["id"], "hunt_id": hunt_id, "rule_id": existing["rule_id"],
        "rule_version": existing["rule_version"], "claim": claim, "claim_type": existing["claim_type"],
        "event_ids": [*cited, *(event.id for event in new)],
        "context_event_ids": list(existing.get("context_event_ids") or []),
        "predicate_fields": predicate, "entities": entities, "ts": existing["ts"],
        "severity": severity, "confidence": confidence, "lane": lane,
        "priority": max(float(existing["priority"] or 0), float(decision.priority)),
        "priority_reasons": (decision.priority_reasons if float(decision.priority) > float(existing["priority"] or 0)
                             else existing["priority_reasons"]),
        "gate_results": gates,
        # The revision keeps the stored ownership; these only mark the row as a direct-rule fold.
        "source_case_id": None, "source_anchor_id": None, "source_link_id": None,
    }
    with repo.candidate_publication():
        status = repo.revise_candidate(row, f"Expansion reach {reach_key[1]} from {reach_key[0]} folded into the "
                                            f"group's one finding", owner_token=owner_token, bounded_revision=True)
        if status and (match.fleet_host_count or match.fleet_hosts_complete):
            repo.save_candidate_hosts(existing["id"], hunt_id, match.fleet_hosts, owner_token=owner_token,
                                      replace=False, claim=claim)
    raised = _LANE_RANK.get(lane, 0) > _LANE_RANK.get(existing["lane"], 0) and lane in {"urgent", "high"}
    return repo.candidate(existing["id"]) if status and raised else None


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
                  *, owner_token: str | None = None, zeek_context=None, zeek_context_ids=(),
                  sweep_group: dict | None = None) -> dict | None:
    """Persist cited evidence and publish a machine-decided finding once, with stable script-view revisions.
    Context findings are published by the post-expansion pass (romulus.hunt.context.finalize_context).

    `sweep_group`: the candidate the sweep published for these records, which it evaluated with its whole
    partition. The reach then only folds into that candidate, at the sweep's lane: a re-evaluation with less context
    never overrides the sweep's verdict."""
    if source_case_id is None and source_anchor_id is None:
        bind_aggregate_history(repo, hunt_id, playbook)
    if zeek_context is not None and any(event.get("observer.product")=="zeek" for event in match.events):
        from itertools import islice

        from romulus.hunt.zeek_context import MAX_ROWS, attach
        witnesses=list(zeek_context[:MAX_ROWS+1])
        held={event.id for event in witnesses}
        missing=list(islice((identity for identity in zeek_context_ids if identity not in held),
                            max(0,MAX_ROWS+1-len(witnesses))))
        for start in range(0,len(missing),LINEAGE_CITATION_BATCH):
            witnesses.extend(TypedEvent.model_validate(row["event"]) for row in
                             repo.citation_events(hunt_id,missing[start:start+LINEAGE_CITATION_BATCH]))
        attach(match,witnesses,limited=True)
    compact = [event for event in match.events if COMPACT_CITATION_NOTE in event.caveats or any(
        note.startswith("Authentication witness body not retrieved") for note in event.caveats)]
    if compact:
        refs = {raw_id(ref.target, ref.native_id): ref for event in compact for ref in event.raw
                if ref.key not in raw_sources}
        ids = sorted(refs)
        retained = {}
        for start in range(0, len(ids), LINEAGE_CITATION_BATCH):
            for row in repo.raw_records(ids[start:start+LINEAGE_CITATION_BATCH]):
                ref = refs[row["id"]]
                if not ref.digest or row["digest"] == ref.digest:
                    retained[ref.key] = row["source"]
        raw_sources = {**retained, **raw_sources}
    fetcher = getattr(playbook, "citation_fetcher", None)
    if fetcher is not None:
        fetcher.hydrate(match, raw_sources)
    else:
        SourceCitationFetcher(None).hydrate(match, raw_sources)
    decision = decide(match, hunt_id)
    if match.raw_copies:
        raw_sources = {**match.raw_copies, **raw_sources}
    repo.save_evidence(hunt_id, match.events, raw_sources, task_id, owner_token=owner_token)
    event_ids = [event.id for event in match.events]
    context_event_ids = sorted({event.id for event in match.events} & match.context_ids)
    candidate_id = decision.candidate_id
    if sweep_group is not None:
        return _fold_reach(repo, hunt_id, match, decision, sweep_group, context_reach, owner_token=owner_token,
                           keep_decision=True)
    view_field = playbook.evidence_view_field if match.group_key else ""
    existing_view = repo.candidate(candidate_id) if view_field else None
    if source_case_id is None and source_anchor_id is not None and not view_field and match.group_key:
        # One finding per (hunt, rule, group key) across the sweep and every expansion reach: a reach of a group
        # already published folds into it; the first publication of a group takes the group's own id, so a later
        # reach finds it.
        existing = repo.candidate(candidate_id)
        if (existing is not None and existing.get("source_case_id") is None
                and existing["lane"] != "context" and decision.lane != "context"):
            return _fold_reach(repo, hunt_id, match, decision, existing, context_reach, owner_token=owner_token)
        if existing is not None and existing.get("source_case_id") is None:
            candidate_id = expansion_candidate_id(candidate_id, match)
    elif source_case_id is None and source_anchor_id is not None and not view_field:
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
            **({"_attack": list(match.attack)} if match.attack else {}),
            **({"_citation_unavailable": True} if match.citation_unavailable else {}),
            **({"_fleet_host_count": match.fleet_host_count} if match.fleet_host_count else {}),
            **({"_context_reaches": [context_reach]} if context_reach else {}),
            **({"aggregate_summary": dict(match.aggregate_summary)} if match.aggregate_summary else {}),
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
        with repo.candidate_publication():
            status = repo.revise_candidate(row, match.revision_reason, owner_token=owner_token,
                                           bounded_revision=match.bounded_revision)
            if status and (match.fleet_host_count or match.fleet_hosts_complete):
                row.update(repo.save_candidate_hosts(candidate_id, hunt_id, match.fleet_hosts, owner_token=owner_token,
                           replace=match.fleet_hosts_complete, expected_count=match.fleet_host_count, claim=match.claim))
        return row if status == "inserted" else None
    with repo.candidate_publication():
        saved = repo.save_candidate(row, canonicalize_agent=source_case_id is None, owner_token=owner_token)
        if saved and (match.fleet_host_count or match.fleet_hosts_complete):
            row.update(repo.save_candidate_hosts(candidate_id, hunt_id, match.fleet_hosts, owner_token=owner_token,
                       replace=match.fleet_hosts_complete, expected_count=match.fleet_host_count, claim=match.claim))
    return row if saved else None
