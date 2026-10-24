"""Lineage citation stores keep verified source pointers, never full evidence copies."""
import hashlib
import json
import zlib

import pytest

from romulus.config import Settings
from romulus.detect import host as host_detection
from romulus.detect.correlation import InterpreterExternalConnection
from romulus.detect.host import ExecLineage
from romulus.hunt import publish
from romulus.sources.es import ElasticClient, SourceError
from tests.test_lineage_observations import HOST, T, connect, execd, lab_zmc, normalized, observe
from tests.throughput_fixture import MiniES


def _digest(sources: list[dict]) -> str:
    encoded = json.dumps(sources, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(encoded).hexdigest()


def _payload(blob: bytes) -> dict:
    return json.loads(zlib.decompress(blob))


def test_observed_citation_store_keeps_only_a_compact_verified_source_pointer():
    [event], raw = normalized(observe(T, 10, 400, 1, "/usr/lib/systemd/systemd"))
    lineage = ExecLineage(observing=True)

    lineage.observe_process(event, raw, "host-target")

    [entry] = lineage.observed.peek((HOST, 400))
    blob = lineage.citations.peek(entry.event_id)
    assert len(blob) <= 180
    assert _payload(blob) == {
        "boot": None,
        "kind": "observed",
        "raw_digest": _digest([raw[event.raw[0].key]]),
        "records": [["host-logs-x", "o10"]],
        "target": "host-target",
        "v": 1,
    }


def test_exec_citation_store_keeps_only_a_compact_verified_source_pointer():
    events, raw = normalized(execd(T, 11, 400, 1, "/usr/bin/perl", ["/usr/bin/perl", "-e", "1"]))
    [event] = [item for item in events if item.family == "process_exec"]
    lineage = ExecLineage(citing=True)

    lineage.observe(event, raw, "host-target")

    blob = lineage.exec_records.peek(event.id)
    assert len(blob) <= 200
    assert _payload(blob) == {
        "boot": None,
        "kind": "exec",
        "raw_digest": _digest([raw[ref.key] for ref in event.raw]),
        "records": [[ref.target, ref.native_id] for ref in event.raw],
        "target": "host-target",
        "v": 1,
    }


def test_pointer_stores_use_the_shrunken_one_gib_disk_caps():
    lineage = ExecLineage(observing=True, citing=True)

    assert lineage.citations.disk_budget == 2**30
    assert lineage.exec_records.disk_budget == 2**30


class _Source:
    def __init__(self, hits: list[dict]):
        self.hits = hits
        self.calls: list[tuple[str, dict]] = []

    def search(self, target: str, body: dict) -> dict:
        self.calls.append((target, body))
        filters = body["query"]["bool"]["filter"]
        ids = set(next(item["ids"]["values"] for item in filters if "ids" in item))
        indices = set(next(item["terms"]["_index"] for item in filters if "terms" in item))
        selected = [hit for hit in self.hits if hit["_id"] in ids and hit["_index"] in indices]
        return {"hits": {"hits": selected}}


class _FailingSource:
    def search(self, _target: str, _body: dict) -> dict:
        raise SourceError("citation source unavailable", retryable=True)


def test_verified_loader_batches_exact_ids_and_rebuilds_observed_and_exec_views():
    observed_hits = observe(T, 20, 400, 1, "/usr/lib/systemd/systemd")
    exec_hits = execd(T + 1, 21, 400, 1, "/usr/bin/perl", ["/usr/bin/perl", "-e", "1"])
    events, raw = normalized(observed_hits, exec_hits)
    observed_event = next(item for item in events if item.family == "process_observed")
    exec_event = next(item for item in events if item.family == "process_exec")
    lineage = ExecLineage(observing=True, citing=True)
    lineage.observe_process(observed_event, raw, "host-target")
    lineage.observe(exec_event, raw, "host-target")
    [entry] = lineage.observed.peek((HOST, 400))
    pointers = {
        entry.event_id: lineage.citations.peek(entry.event_id),
        exec_event.id: lineage.exec_records.peek(exec_event.id),
    }
    source = _Source([*observed_hits, *exec_hits])

    rebuilt, copies = publish.LineageCitationFetcher(
        source, {"host-target": object()},
    ).load(pointers)

    assert {event_id: event.model_dump() for event_id, event in rebuilt.items()} == {
        observed_event.id: observed_event.model_dump(),
        exec_event.id: exec_event.model_dump(),
    }
    assert copies == raw
    assert len(source.calls) == 1
    target, body = source.calls[0]
    assert target == "host-target"
    assert body["size"] == 3
    assert body["track_total_hits"] is False


def test_throughput_mini_es_serves_plain_exact_id_citation_refetch():
    hits = observe(T, 22, 402, 1, "/usr/lib/systemd/systemd")
    [event], raw = normalized(hits)
    lineage = ExecLineage(observing=True)
    lineage.observe_process(event, raw, "host-target")
    [entry] = lineage.observed.peek((HOST, 402))
    pointers = {entry.event_id: lineage.citations.peek(entry.event_id)}
    mini_es = MiniES({"host-target": hits}, {"host-target": "@timestamp"})
    client = ElasticClient(Settings(es_url="http://es.invalid"), transport=mini_es.transport())

    rebuilt, copies = publish.LineageCitationFetcher(
        client, {"host-target": object()},
    ).load(pointers)

    assert rebuilt[entry.event_id].model_dump() == event.model_dump()
    assert copies == raw


def test_exact_index_id_pairs_prevent_cross_product_hits_from_displacing_citations():
    hit_a = observe(T, 23, 403, 1, "/usr/lib/systemd/systemd")[0]
    hit_a = {**hit_a, "_index": "host-a", "_id": "wanted-a"}
    decoy = observe(T + 1, 24, 404, 1, "/usr/lib/systemd/systemd")[0]
    decoy = {**decoy, "_index": "host-a", "_id": "wanted-b"}
    hit_b = observe(T + 2, 25, 405, 1, "/usr/lib/systemd/systemd")[0]
    hit_b = {**hit_b, "_index": "host-b", "_id": "wanted-b"}
    events, raw = normalized([hit_a], [hit_b])
    pointers = {}
    for event in events:
        lineage = ExecLineage(observing=True)
        lineage.observe_process(event, raw, "host-target")
        [entry] = lineage.observed.peek((HOST, event.get("process.pid")))
        pointers[entry.event_id] = lineage.citations.peek(entry.event_id)
    mini_es = MiniES({"host-target": [hit_a, decoy, hit_b]}, {"host-target": "@timestamp"})
    client = ElasticClient(Settings(es_url="http://es.invalid"), transport=mini_es.transport())

    rebuilt, _copies = publish.LineageCitationFetcher(
        client, {"host-target": object()},
    ).load(pointers)

    assert set(rebuilt) == set(pointers)


def test_exec_lineage_returns_only_pointer_records_verified_by_its_loader():
    hits = execd(T, 31, 410, 1, "/usr/bin/perl", ["/usr/bin/perl", "-e", "1"])
    events, raw = normalized(hits)
    [event] = [item for item in events if item.family == "process_exec"]
    lineage = ExecLineage(citing=True)
    lineage.observe(event, raw, "host-target")
    source = _Source(hits)
    loader = publish.LineageCitationFetcher(source, {"host-target": object()})
    lineage.bind_citation_loader(loader.load)

    cited, copies = lineage.cited([event.id])

    assert cited[event.id].model_dump() == event.model_dump()
    assert copies == raw


def test_rule_refetches_only_its_named_lineage_records_before_it_builds_the_finding():
    events, raw = lab_zmc()
    hits = [
        {"_index": key.split("/", 1)[0], "_id": key.split("/", 1)[1], "_source": source}
        for key, source in raw.items()
    ]
    source = _Source(hits)
    rule = InterpreterExternalConnection()
    rule.bind_raw(raw, "host-target")
    rule.consume([event for event in events if event.family in rule.families])
    rule.bind_raw({})
    stage = {event.id: event for event in rule.drain_staged()}
    rule.bind_loader(lambda ids: [stage[event_id] for event_id in ids if event_id in stage])
    host_detection.bind_lineage_citation_loader(
        [rule], publish.LineageCitationFetcher(source, {"host-target": object()}).load,
    )

    [match] = rule.finalize()

    assert match.proposed_lane == "lead"
    lineage_events = [event for event in match.events if event.id in match.context_ids]
    assert lineage_events
    assert all(ref.key in match.raw_copies for event in lineage_events for ref in event.raw)
    assert source.calls


def _lineage_match(source_hits: list[dict], source=None):
    events, raw = lab_zmc()
    rule = InterpreterExternalConnection()
    rule.bind_raw(raw, "host-target")
    rule.consume([event for event in events if event.family in rule.families])
    rule.bind_raw({})
    stage = {event.id: event for event in rule.drain_staged()}
    rule.bind_loader(lambda ids: [stage[event_id] for event_id in ids if event_id in stage])
    host_detection.bind_lineage_citation_loader(
        [rule], publish.LineageCitationFetcher(source or _Source(source_hits), {"host-target": object()}).load,
    )
    [match] = rule.finalize()
    return match, events, raw


def _hits(raw: dict[str, dict]) -> list[dict]:
    return [
        {"_index": key.split("/", 1)[0], "_id": key.split("/", 1)[1], "_source": source}
        for key, source in raw.items()
    ]


@pytest.mark.parametrize("failure", ["missing", "digest_mismatch"])
def test_unverified_observed_record_makes_lineage_unknown_and_keeps_the_lane(failure):
    _events, raw = lab_zmc()
    hits = _hits(raw)
    if failure == "missing":
        hits = [hit for hit in hits if hit["_id"] != "s843"]
    else:
        for hit in hits:
            if hit["_id"] == "s843":
                hit["_source"] = {**hit["_source"], "message": "changed after the sweep"}

    match, _events, _raw = _lineage_match(hits)

    assert match.proposed_lane == "high"
    assert "ancestry is not fully recorded" in match.claim
    assert any("could not be read back for citation" in note for note in match.notes)


def test_observed_source_failure_makes_lineage_unknown_and_keeps_the_lane():
    match, _events, _raw = _lineage_match([], _FailingSource())

    assert match.proposed_lane == "high"
    assert "ancestry is not fully recorded" in match.claim
    assert any("could not be read back for citation" in note for note in match.notes)


@pytest.mark.parametrize("failure", ["missing", "digest_mismatch"])
def test_unverified_exec_ancestor_is_not_cited_but_changes_no_verdict(failure):
    events, raw = lab_zmc()
    exec_ids = {ref.native_id for event in events if event.family == "process_exec" for ref in event.raw}
    hits = _hits(raw)
    if failure == "missing":
        hits = [hit for hit in hits if hit["_id"] not in exec_ids]
    else:
        for hit in hits:
            if hit["_id"] in exec_ids:
                hit["_source"] = {**hit["_source"], "message": "changed after the sweep"}

    match, _events, _raw = _lineage_match(hits)

    assert match.proposed_lane == "lead"
    assert "reaches the service manager with no web server" in match.claim
    assert any("exec record(s) it reads were not kept for citation" in note for note in match.notes)


def test_exec_source_failure_drops_the_ancestor_citation_but_changes_no_verdict():
    events, raw = normalized(
        execd(T, 10, 800, 1, "/usr/lib/systemd/systemd-executor",
              ["/usr/lib/systemd/systemd-executor", "--deserialize", "3"]),
        execd(T + 0.002, 11, 800, 1, "/usr/bin/perl", ["/usr/bin/perl", "/usr/sbin/d.pl"]),
        execd(T + 5.5, 21, 801, 800, "/usr/bin/python3", ["python3", "job.py"], "33", "www-data"),
    )
    # This observation continues pid 801's exec state, so the ancestry citation set is exec-only.
    connect_events, connect_raw = normalized(connect(T + 6, 22, 801, 800, "/usr/bin/python3", "python3"))
    events += connect_events
    raw.update(connect_raw)
    rule = InterpreterExternalConnection()
    rule.bind_raw(raw, "host-target")
    rule.consume([event for event in events if event.family in rule.families])
    rule.bind_raw({})
    stage = {event.id: event for event in rule.drain_staged()}
    rule.bind_loader(lambda ids: [stage[event_id] for event_id in ids if event_id in stage])
    host_detection.bind_lineage_citation_loader(
        [rule], publish.LineageCitationFetcher(_FailingSource(), {"host-target": object()}).load,
    )

    [match] = rule.finalize()

    assert match.proposed_lane == "lead"
    assert "reaches the service manager with no web server" in match.claim
    assert any("exec record(s) it reads were not kept for citation" in note for note in match.notes)
