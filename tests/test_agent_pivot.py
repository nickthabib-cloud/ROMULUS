"""Safe pivot execution and shared deterministic candidate publication."""
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

import pytest

from romulus.agent.models import EntityRef
from romulus.agent.tools import (
    AuthActivityArgs,
    AuthActivityRequest,
    EntityTimelineArgs,
    EntityTimelineRequest,
    IdsAlertsArgs,
    IdsAlertsRequest,
    ProcessTreeArgs,
    ProcessTreeRequest,
)
from romulus.detect.host import CredentialStoreRead
from romulus.detect.registry import fresh_direct_pack
from romulus.evidence.typed import Outcome, RawRef, TypedEvent, fv
from romulus.hunt import pivot as pivot_module
from romulus.hunt.pivot import PivotExecutor
from romulus.hunt.publish import publish_match
from romulus.sources.compile import compile_es
from romulus.sources.models import Completeness, SearchOutcome
from romulus.sources.profile import contract_from_types
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo

START = datetime(2024, 11, 18, 14, 0, tzinfo=UTC)
END = START + timedelta(minutes=10)


class FakeClient:
    version = "test"

    class settings:
        es_flavor = "elasticsearch"

    @contextmanager
    def point_in_time(self, _target):
        yield object()


def _repo() -> Repo:
    engine = make_engine(":memory:")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"targets": []}, "digest", "test")
    return repo


def _process_event(argv=None, *, event_id="event-1", ts=START) -> TypedEvent:
    return TypedEvent(
        id=event_id, family="process_exec", ts=ts, host="video", outcome=Outcome.success,
        fields={
            "process.argv": fv(argv or ["cat", "/etc/shadow"], "raw-1:event.original#auditd:EXECVE.a*"),
            "process.pid": fv(123, "raw-1:event.original#auditd:SYSCALL.pid"),
            "process.ppid": fv(100, "raw-1:event.original#auditd:SYSCALL.ppid"),
        },
        raw=[RawRef(target="romulus-host-x", native_id=event_id, digest="d")], normalizer="test@1",
    )


def test_shared_publication_sets_source_case_and_keeps_machine_policy():
    repo = _repo()
    playbook = CredentialStoreRead()
    match = playbook.consume([_process_event()])[0]

    row = publish_match(
        repo, "h1", playbook, match, None,
        {"romulus-host-x/raw-1": {"event": {"dataset": "linux.audit"}}},
        source_case_id="case-1",
    )

    assert row is not None
    stored = repo.candidate(row["id"])
    assert stored["source_case_id"] == "case-1"
    assert stored["claim"] == match.claim
    assert stored["lane"] == "high"


def test_pivot_pack_contains_only_direct_playbooks():
    pack = fresh_direct_pack()

    assert pack
    assert all(playbook.kind == "direct" for playbook in pack)
    assert "host.web_service_spawns_interpreter" not in {playbook.id for playbook in pack}
    assert "net.port_scan" not in {playbook.id for playbook in pack}


def test_ip_timeline_queries_both_network_sides_and_safe_journal_superset(monkeypatch):
    seen = []

    def fake_execute(_client, intent, _contract, *, pit=None):
        seen.append(intent)
        return SearchOutcome(
            target=intent.target, fingerprint="fp", started_at=START, ended_at=START,
            completeness=Completeness.complete, total=0, total_relation="eq", returned=0,
        )

    monkeypatch.setattr(pivot_module, "execute", fake_execute)
    contracts = {
        "romulus-network-x": contract_from_types("romulus-network-x", {
            "@timestamp": "date", "source.ip": "ip", "destination.ip": "ip", "event.dataset": "keyword",
        }),
        "romulus-host-x": contract_from_types("romulus-host-x", {
            "@timestamp": "date", "event.dataset": "keyword", "host.name": "keyword",
        }),
    }
    request = EntityTimelineRequest(tool="entity_timeline", arguments=EntityTimelineArgs(
        entity=EntityRef(kind="ip", value="203.0.113.8", role="src"), start=START, end=END,
    ))

    repo = _repo()
    result = PivotExecutor(repo, FakeClient(), "h1", contracts).run("case-1", request)

    assert result.status == "complete"
    network = next(intent for intent in seen if "network" in intent.target)
    assert [(p.field, p.op, p.value) for p in network.filters] == [
        ("event.dataset", "in", [
            "suricata.eve.alert", "suricata.eve.flow", "suricata.eve.netflow",
            "suricata.eve.dns", "suricata.eve.http", "suricata.eve.fileinfo",
            "suricata.eve.tls", "suricata.eve.ssh",
        ]),
    ]
    assert [[(p.field, p.op, p.value) for p in group] for group in network.any_of] == [
        [("source.ip", "eq", "203.0.113.8")],
        [("destination.ip", "eq", "203.0.113.8")],
    ]
    journal = next(intent for intent in seen if "host" in intent.target)
    assert [(p.field, p.op, p.value) for p in journal.filters] == [
        ("event.dataset", "eq", "systemd.journal"),
    ]


def test_each_tool_compiles_source_filters_for_only_the_families_it_summarizes():
    contracts = {
        "romulus-network-x": contract_from_types("romulus-network-x", {
            "@timestamp": "date", "source.ip": "ip", "destination.ip": "ip",
            "event.dataset": "keyword", "host.name": "keyword",
        }),
        "romulus-host-x": contract_from_types("romulus-host-x", {
            "@timestamp": "date", "event.dataset": "keyword", "host.name": "keyword",
        }),
    }
    executor = PivotExecutor(_repo(), FakeClient(), "h1", contracts)
    requests = [
        EntityTimelineRequest(tool="entity_timeline", arguments=EntityTimelineArgs(
            entity=EntityRef(kind="host", value="video", role="host"), start=START, end=END,
        )),
        AuthActivityRequest(tool="auth_activity", arguments=AuthActivityArgs(
            entity=EntityRef(kind="host", value="video", role="host"), start=START, end=END,
        )),
        ProcessTreeRequest(tool="process_tree", arguments=ProcessTreeArgs(
            host="video", process_id=123, start=START, end=END,
        )),
        IdsAlertsRequest(tool="ids_alerts", arguments=IdsAlertsArgs(
            entity=EntityRef(kind="ip", value="203.0.113.8", role="src"), start=START, end=END,
        )),
    ]

    by_tool = {request.tool: executor._intents(request) for request in requests}

    expected = {
        "entity_timeline": ["linux.audit", "systemd.journal", "apache.access", "apache.error"],
        "auth_activity": "systemd.journal",
        "process_tree": "linux.audit",
        "ids_alerts": "suricata.eve.alert",
    }
    for tool, intents in by_tool.items():
        assert len(intents) == 1
        compiled = compile_es(intents[0], contracts[intents[0].target])
        filters = compiled.body["query"]["bool"]["filter"]
        family_clause = filters[1]
        if isinstance(expected[tool], list):
            assert family_clause == {"terms": {"event.dataset": expected[tool]}}
        else:
            assert family_clause == {"term": {"event.dataset": expected[tool]}}


def test_family_filter_is_required_instead_of_falling_back_to_broad_entity_query(monkeypatch):
    called = False

    def fake_execute(*_args):
        nonlocal called
        called = True
        raise AssertionError("broad source query must not execute")

    monkeypatch.setattr(pivot_module, "execute", fake_execute)
    contracts = {"romulus-network-x": contract_from_types("romulus-network-x", {
        "@timestamp": "date", "source.ip": "ip", "destination.ip": "ip",
    })}
    request = IdsAlertsRequest(tool="ids_alerts", arguments=IdsAlertsArgs(
        entity=EntityRef(kind="ip", value="203.0.113.8", role="src"), start=START, end=END,
    ))

    executor = PivotExecutor(_repo(), FakeClient(), "h1", contracts)
    result = executor.run("case-1", request)

    assert result.status == "unsupported"
    assert called is False


def test_ids_alerts_rejects_host_entity_without_querying_sensor_host_name(monkeypatch):
    called = False

    def fake_execute(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("network host.name identifies the sensor, not the investigated host")

    monkeypatch.setattr(pivot_module, "execute", fake_execute)
    contracts = {"romulus-network-x": contract_from_types("romulus-network-x", {
        "@timestamp": "date", "event.dataset": "keyword", "host.name": "keyword",
        "source.ip": "ip", "destination.ip": "ip",
    })}
    hostile_args = IdsAlertsArgs.model_construct(
        entity=EntityRef(kind="host", value="video", role="host"), start=START, end=END,
    )
    request = IdsAlertsRequest(tool="ids_alerts", arguments=hostile_args)

    executor = PivotExecutor(_repo(), FakeClient(), "h1", contracts)
    result = executor.run("case-1", request)

    assert result.status == "unsupported"
    assert result.reasons == [
        "ids_alerts requires an IP entity; network host.name identifies the observer sensor",
    ]
    assert executor._intents(request) == []
    assert called is False


def test_family_filter_requires_the_exact_contract_operator():
    contracts = {"romulus-host-x": contract_from_types("romulus-host-x", {
        "@timestamp": "date", "event.dataset": "boolean", "host.name": "keyword",
    })}
    request = EntityTimelineRequest(tool="entity_timeline", arguments=EntityTimelineArgs(
        entity=EntityRef(kind="host", value="video", role="host"), start=START, end=END,
    ))

    intents = PivotExecutor(_repo(), FakeClient(), "h1", contracts)._intents(request)

    assert intents == []


def test_pivot_heartbeats_before_and_after_source_execution(monkeypatch):
    calls = []

    def fake_execute(_client, intent, _contract, *, pit=None):
        calls.append("execute")
        return SearchOutcome(
            target=intent.target, fingerprint="fp", started_at=START, ended_at=START,
            completeness=Completeness.complete, total=0, total_relation="eq", returned=0,
        )

    monkeypatch.setattr(pivot_module, "execute", fake_execute)
    contracts = {"romulus-host-x": contract_from_types("romulus-host-x", {
        "@timestamp": "date", "event.dataset": "keyword", "host.name": "keyword",
    })}
    request = EntityTimelineRequest(tool="entity_timeline", arguments=EntityTimelineArgs(
        entity=EntityRef(kind="host", value="video", role="host"), start=START, end=END,
    ))
    executor = PivotExecutor(
        _repo(), FakeClient(), "h1", contracts, heartbeat=lambda: calls.append("heartbeat"),
    )

    result = executor.run("case-1", request)

    assert result.status == "complete"
    assert calls == ["heartbeat", "execute", "heartbeat"]


def test_partial_pivot_retains_events_and_publishes_direct_matches(monkeypatch):
    event = _process_event()

    def fake_execute(_client, intent, _contract, *, pit=None):
        record = {"_id": "raw-1", "_index": intent.target, "_source": {"event": {"dataset": "linux.audit"}}}
        return SearchOutcome(
            target=intent.target, fingerprint="fp", started_at=START, ended_at=END,
            completeness=Completeness.partial, reasons=["shard_failures"], total=2,
            total_relation="eq", returned=1, records=[record],
        )

    monkeypatch.setattr(pivot_module, "execute", fake_execute)
    monkeypatch.setattr(pivot_module, "normalize_hits", lambda _records: ([event], {}, []))
    contracts = {"romulus-host-x": contract_from_types("romulus-host-x", {
        "@timestamp": "date", "event.dataset": "keyword", "host.name": "keyword",
    })}
    request = ProcessTreeRequest(tool="process_tree", arguments=ProcessTreeArgs(
        host="video", process_id=123, start=START, end=END,
    ))
    repo = _repo()

    result = PivotExecutor(repo, FakeClient(), "h1", contracts).run("case-1", request)

    assert result.status == "partial"
    assert result.event_ids == ["event-1"]
    assert len(result.candidate_ids) == 1
    assert repo.candidate(result.candidate_ids[0])["source_case_id"] == "case-1"
    assert repo.tasks("h1")[0]["state"] == "evaluated"
    assert "shard_failures" in result.reasons


def test_displaced_pivot_worker_cannot_write_after_normalization(monkeypatch):
    repo = _repo()
    first = repo.claim_hunt("h1", lease_seconds=60, now=START)
    request = ProcessTreeRequest(tool="process_tree", arguments=ProcessTreeArgs(
        host="video", process_id=123, start=START, end=END,
    ))
    contracts = {"romulus-host-x": contract_from_types("romulus-host-x", {
        "@timestamp": "date", "event.dataset": "keyword", "host.name": "keyword",
    })}

    def fake_execute(_client, intent, _contract, *, pit=None):
        record = {
            "_id": "event-1", "_index": intent.target,
            "_source": {"event": {"dataset": "linux.audit"}},
        }
        return SearchOutcome(
            target=intent.target, fingerprint="fp", started_at=START, ended_at=END,
            completeness=Completeness.complete, total=1, total_relation="eq", returned=1,
            records=[record],
        )

    def displacing_normalize(_records):
        second = repo.claim_hunt(
            "h1", lease_seconds=60, resume=True, now=START + timedelta(seconds=61),
        )
        repo.set_hunt_state("h1", "completed_within_scope", owner_token=second["lease_owner"])
        return [_process_event()], {}, []

    monkeypatch.setattr(pivot_module, "execute", fake_execute)
    monkeypatch.setattr(pivot_module, "normalize_hits", displacing_normalize)
    executor = PivotExecutor(
        repo, FakeClient(), "h1", contracts, owner_token=first["lease_owner"],
    )

    with pytest.raises(RuntimeError, match="lease ownership lost"):
        executor.run("case-1", request)

    assert repo.events_by_ids(["event-1"]) == []
    assert repo.raw_records(["romulus-host-x/event-1"]) == []
    assert repo.candidates("h1") == []
    assert repo.tasks("h1")[0]["state"] == "leased"


def test_capped_dense_pivot_splits_and_late_event_reaches_time_spread_digest(monkeypatch):
    window = EntityTimelineArgs(
        entity=EntityRef(kind="host", value="video", role="host"),
        start=START, end=START + timedelta(minutes=20),
    )
    request = EntityTimelineRequest(tool="entity_timeline", arguments=window)
    calls = []

    def records(prefix, start):
        return [
            {"_id": f"{prefix}-{index}", "_index": "romulus-host-x",
             "_source": {"@timestamp": (start + timedelta(seconds=index)).isoformat(),
                         "event": {"dataset": "linux.audit"}}}
            for index in range(30)
        ]

    def fake_execute(_client, intent, _contract, *, pit=None):
        calls.append(intent.window)
        if intent.window.start == window.start and intent.window.end == window.end:
            parent = records("discarded-parent", window.start)
            return SearchOutcome(
                target=intent.target, fingerprint="parent", started_at=START, ended_at=START,
                completeness=Completeness.partial, reasons=["cap:10000<total:60000"],
                total=60000, total_relation="eq", returned=len(parent), records=parent,
            )
        prefix = "early" if intent.window.start == window.start else "late"
        leaf_records = records(prefix, intent.window.start)
        return SearchOutcome(
            target=intent.target, fingerprint=prefix, started_at=START, ended_at=START,
            completeness=Completeness.complete, total=len(leaf_records), total_relation="eq",
            returned=len(leaf_records), records=leaf_records,
        )

    def fake_normalize(raw_records):
        events = [
            _process_event(
                ["echo"], event_id=record["_id"],
                ts=datetime.fromisoformat(record["_source"]["@timestamp"]),
            )
            for record in raw_records
        ]
        return events, {}, []

    monkeypatch.setattr(pivot_module, "execute", fake_execute)
    monkeypatch.setattr(pivot_module, "normalize_hits", fake_normalize)
    contracts = {"romulus-host-x": contract_from_types("romulus-host-x", {
        "@timestamp": "date", "event.dataset": "keyword", "host.name": "keyword",
    })}
    repo = _repo()

    result = PivotExecutor(repo, FakeClient(), "h1", contracts).run("case-1", request)

    assert [(call.start, call.end) for call in calls] == [
        (window.start, window.end),
        (window.start, window.start + timedelta(minutes=10)),
        (window.start + timedelta(minutes=10), window.end),
    ]
    assert result.status == "complete"
    assert result.matched_event_count == 60
    assert len(result.event_summaries) == 50
    assert result.event_summaries[-1]["id"] == "late-29"
    assert all(not event_id.startswith("discarded-parent") for event_id in result.event_ids)
    assert [segment.model_dump(mode="json") for segment in result.coverage] == [{
        "target": "romulus-host-x", "start": "2024-11-18T14:00:00Z", "end": "2024-11-18T14:20:00Z",
        "status": "complete", "reasons": [], "returned": 60, "total": 60,
        "covered_ranges": [
            {
                "start": "2024-11-18T14:00:00.000000000Z",
                "end": "2024-11-18T14:10:00.000000000Z",
                "start_inclusive": True, "end_inclusive": False,
                "reason": "source retrieval complete",
            },
            {
                "start": "2024-11-18T14:10:00.000000000Z",
                "end": "2024-11-18T14:20:00.000000000Z",
                "start_inclusive": True, "end_inclusive": False,
                "reason": "source retrieval complete",
            },
        ],
        "unresolved_ranges": [],
    }]


def test_unsplittable_partial_pivot_reports_complete_and_unresolved_time_ranges(monkeypatch):
    window = EntityTimelineArgs(
        entity=EntityRef(kind="host", value="video", role="host"),
        start=START, end=START + timedelta(seconds=20),
    )
    request = EntityTimelineRequest(tool="entity_timeline", arguments=window)

    def one_record(identifier, ts):
        return [{"_id": identifier, "_index": "romulus-host-x",
                 "_source": {"@timestamp": ts.isoformat(), "event": {"dataset": "linux.audit"}}}]

    def fake_execute(_client, intent, _contract, *, pit=None):
        if intent.window.start == window.start and intent.window.end == window.end:
            return SearchOutcome(
                target=intent.target, fingerprint="parent", started_at=START, ended_at=START,
                completeness=Completeness.partial, reasons=["cap:10000<total:20001"],
                total=20001, total_relation="eq", returned=1,
                records=one_record("discarded", window.start),
            )
        late = intent.window.start > window.start
        return SearchOutcome(
            target=intent.target, fingerprint="late" if late else "early", started_at=START, ended_at=START,
            completeness=Completeness.partial if late else Completeness.complete,
            reasons=["cap:10000<total:10001"] if late else [], total=10001 if late else 1,
            total_relation="eq", returned=1,
            records=one_record("late-visible" if late else "early-visible", intent.window.start),
        )

    monkeypatch.setattr(pivot_module, "execute", fake_execute)
    monkeypatch.setattr(pivot_module, "normalize_hits", lambda raw_records: (
        [_process_event(["echo"], event_id=record["_id"],
                        ts=datetime.fromisoformat(record["_source"]["@timestamp"]))
         for record in raw_records], {}, [],
    ))
    contracts = {"romulus-host-x": contract_from_types("romulus-host-x", {
        "@timestamp": "date", "event.dataset": "keyword", "host.name": "keyword",
    })}
    repo = _repo()

    result = PivotExecutor(repo, FakeClient(), "h1", contracts).run("case-1", request)

    assert result.status == "partial"
    assert "late-visible" in result.event_ids
    assert [(segment.start, segment.end, segment.status) for segment in result.coverage] == [
        (window.start, window.start + timedelta(seconds=10), "complete"),
        (window.start + timedelta(seconds=10), window.end, "partial"),
    ]
    assert "cap:10000<total:10001" in result.coverage[1].reasons
    stored_coverage = repo.tasks("h1")[0]["outcome"]["coverage"]
    assert stored_coverage[1]["status"] == "partial"
    assert stored_coverage[1]["start"] == "2024-11-18T14:00:10Z"


def test_partition_limited_dense_pivot_reads_tail_and_reports_unresolved_middle(monkeypatch):
    monkeypatch.setattr(pivot_module, "MAX_PIVOT_RECORDS", 1)
    window = EntityTimelineArgs(
        entity=EntityRef(kind="host", value="video", role="host"),
        start=START, end=START + timedelta(seconds=320),
    )
    request = EntityTimelineRequest(tool="entity_timeline", arguments=window)
    calls = []

    def fake_execute(_client, intent, _contract, *, pit=None):
        calls.append((intent.window, intent.order))
        tail = intent.order == "desc"
        ts = intent.window.end - timedelta(microseconds=1) if tail else intent.window.start
        identifier = "window-tail" if tail and intent.window.end == window.end else (
            f"{'tail' if tail else 'head'}-{int(ts.timestamp() * 1_000_000)}"
        )
        record = {
            "_id": identifier,
            "_index": intent.target,
            "_source": {"@timestamp": ts.isoformat(), "event": {"dataset": "linux.audit"}},
        }
        return SearchOutcome(
            target=intent.target, fingerprint=identifier, started_at=START, ended_at=START,
            completeness=Completeness.partial, reasons=["cap:1<total:30000"],
            total=30000, total_relation="eq", returned=1, records=[record],
        )

    monkeypatch.setattr(pivot_module, "execute", fake_execute)
    monkeypatch.setattr(pivot_module, "normalize_hits", lambda raw_records: (
        [_process_event(
            ["echo"], event_id=record["_id"],
            ts=datetime.fromisoformat(record["_source"]["@timestamp"]),
        ) for record in raw_records], {}, [],
    ))
    contracts = {"romulus-host-x": contract_from_types("romulus-host-x", {
        "@timestamp": "date", "event.dataset": "keyword", "host.name": "keyword",
    })}

    repo = _repo()
    result = PivotExecutor(repo, FakeClient(), "h1", contracts).run("case-1", request)

    assert any(order == "desc" and attempted.end == window.end for attempted, order in calls)
    assert result.status == "partial"
    assert result.event_summaries[-1]["id"] == "window-tail"
    assert result.coverage[-1].covered_ranges
    assert result.coverage[-1].unresolved_ranges
    final_suffix = result.coverage[-1].covered_ranges[-1]
    final_gap = result.coverage[-1].unresolved_ranges[-1]
    assert final_suffix.start == "2024-11-18T14:05:19.999999001Z"
    assert final_suffix.end == "2024-11-18T14:05:20.000000000Z"
    assert (final_suffix.start_inclusive, final_suffix.end_inclusive) == (True, False)
    assert final_gap.start == "2024-11-18T14:05:00.000000000Z"
    assert final_gap.end == "2024-11-18T14:05:19.999999001Z"
    assert (final_gap.start_inclusive, final_gap.end_inclusive) == (True, False)
    assert "pivot_partition_limit:16" in result.coverage[-1].reasons
    stored = repo.tasks("h1")[0]["outcome"]["coverage"][-1]
    assert stored["covered_ranges"][-1] == final_suffix.model_dump(mode="json")
    assert stored["unresolved_ranges"][-1] == final_gap.model_dump(mode="json")


def test_terminal_head_tail_share_pit_and_keep_exact_prefix_when_tail_has_shard_failure(monkeypatch):
    monkeypatch.setattr(pivot_module, "MAX_PIVOT_RECORDS", 1)
    window = EntityTimelineArgs(
        entity=EntityRef(kind="host", value="video", role="host"),
        start=START, end=START + timedelta(seconds=10),
    )
    request = EntityTimelineRequest(tool="entity_timeline", arguments=window)
    shared_pits = []

    def record(identifier, source_ts, sort_ts):
        return {
            "_id": identifier, "_index": "romulus-host-x", "_sort": [sort_ts, 1],
            "_source": {"@timestamp": source_ts, "event": {"dataset": "linux.audit"}},
        }

    def fake_execute(_client, intent, _contract, *, pit=None):
        if pit is None:
            records = [record("discarded", START.isoformat(), "2024-11-18T14:00:00.000000000Z")]
            reasons = ["cap:1<total:30000"]
        else:
            shared_pits.append(pit)
            if intent.order == "asc":
                records = [record(
                    "head", "2024-11-18T14:00:01.123456+00:00",
                    "2024-11-18T14:00:01.123456789Z",
                )]
                reasons = ["cap:1<total:30000"]
            else:
                records = [record(
                    "tail", "2024-11-18T14:00:09+00:00",
                    "2024-11-18T14:00:09.000000000Z",
                )]
                reasons = ["cap:1<total:30000", "shard_failures:1"]
        return SearchOutcome(
            target=intent.target, fingerprint="fp", started_at=START, ended_at=START,
            completeness=Completeness.partial, reasons=reasons,
            total=30000, total_relation="eq", returned=1, records=records,
        )

    monkeypatch.setattr(pivot_module, "execute", fake_execute)
    monkeypatch.setattr(pivot_module, "normalize_hits", lambda raw_records: (
        [_process_event(
            ["echo"], event_id=record["_id"],
            ts=datetime.fromisoformat(record["_source"]["@timestamp"]),
        ) for record in raw_records], {}, [],
    ))
    contracts = {"romulus-host-x": contract_from_types("romulus-host-x", {
        "@timestamp": "date", "event.dataset": "keyword", "host.name": "keyword",
    })}

    result = PivotExecutor(_repo(), FakeClient(), "h1", contracts).run("case-1", request)

    assert len(shared_pits) == 2 and shared_pits[0] is shared_pits[1]
    assert result.status == "partial"
    assert result.coverage[0].covered_ranges[0].end == "2024-11-18T14:00:01.123456789Z"
    assert result.coverage[0].unresolved_ranges[0].start == "2024-11-18T14:00:01.123456789Z"
    assert result.coverage[0].unresolved_ranges[0].end == "2024-11-18T14:00:10.000000000Z"


def test_terminal_sample_keeps_exact_suffix_when_head_has_shard_failure(monkeypatch):
    monkeypatch.setattr(pivot_module, "MAX_PIVOT_RECORDS", 1)
    request = EntityTimelineRequest(tool="entity_timeline", arguments=EntityTimelineArgs(
        entity=EntityRef(kind="host", value="video", role="host"),
        start=START, end=START + timedelta(seconds=10),
    ))

    def fake_execute(_client, intent, _contract, *, pit=None):
        tail = intent.order == "desc"
        ts = "2024-11-18T14:00:08.876543211Z" if tail else "2024-11-18T14:00:01.000000000Z"
        record = {
            "_id": "tail" if tail else "head", "_index": intent.target, "_sort": [ts, 1],
            "_source": {"@timestamp": ts, "event": {"dataset": "linux.audit"}},
        }
        reasons = ["cap:1<total:30000"]
        if pit is not None and not tail:
            reasons.append("shard_failures:1")
        return SearchOutcome(
            target=intent.target, fingerprint="fp", started_at=START, ended_at=START,
            completeness=Completeness.partial, reasons=reasons,
            total=30000, total_relation="eq", returned=1, records=[record],
        )

    monkeypatch.setattr(pivot_module, "execute", fake_execute)
    monkeypatch.setattr(pivot_module, "normalize_hits", lambda raw_records: (
        [_process_event(
            ["echo"], event_id=record["_id"],
            ts=datetime.fromisoformat(record["_source"]["@timestamp"]),
        ) for record in raw_records], {}, [],
    ))
    contracts = {"romulus-host-x": contract_from_types("romulus-host-x", {
        "@timestamp": "date", "event.dataset": "keyword", "host.name": "keyword",
    })}

    result = PivotExecutor(_repo(), FakeClient(), "h1", contracts).run("case-1", request)

    assert result.status == "partial"
    assert result.coverage[0].covered_ranges[0].start == "2024-11-18T14:00:08.876543212Z"
    assert result.coverage[0].covered_ranges[0].end == "2024-11-18T14:00:10.000000000Z"
    assert result.coverage[0].unresolved_ranges[0].end == "2024-11-18T14:00:08.876543212Z"


def test_terminal_sample_with_an_unparseable_cutoff_claims_no_coverage(monkeypatch):
    monkeypatch.setattr(pivot_module, "MAX_PIVOT_RECORDS", 2)
    request = EntityTimelineRequest(tool="entity_timeline", arguments=EntityTimelineArgs(
        entity=EntityRef(kind="host", value="video", role="host"),
        start=START, end=START + timedelta(seconds=10),
    ))

    def fake_execute(_client, intent, _contract, *, pit=None):
        records = [{
            "_id": f"{'tail' if intent.order == 'desc' else 'head'}-good",
            "_index": intent.target,
            "_sort": ["2024-11-18T14:00:01.123456789Z", 1],
            "_source": {"@timestamp": START.isoformat(), "event": {"dataset": "linux.audit"}},
        }, {
            "_id": f"{'tail' if intent.order == 'desc' else 'head'}-bad",
            "_index": intent.target,
            "_sort": ["hostile-not-a-time", 2],
            "_source": {"@timestamp": "also-not-a-time", "event": {"dataset": "linux.audit"}},
        }]
        return SearchOutcome(
            target=intent.target, fingerprint="fp", started_at=START, ended_at=START,
            completeness=Completeness.partial, reasons=["cap:2<total:30000"],
            total=30000, total_relation="eq", returned=2, records=records,
        )

    monkeypatch.setattr(pivot_module, "execute", fake_execute)
    monkeypatch.setattr(pivot_module, "normalize_hits", lambda raw_records: (
        [_process_event(["echo"], event_id=record["_id"]) for record in raw_records], {}, [],
    ))
    contracts = {"romulus-host-x": contract_from_types("romulus-host-x", {
        "@timestamp": "date", "event.dataset": "keyword", "host.name": "keyword",
    })}

    result = PivotExecutor(_repo(), FakeClient(), "h1", contracts).run("case-1", request)

    assert result.status == "partial"
    assert result.coverage[0].covered_ranges == []
    assert result.coverage[0].unresolved_ranges[0].start == "2024-11-18T14:00:00.000000000Z"
    assert result.coverage[0].unresolved_ranges[0].end == "2024-11-18T14:00:10.000000000Z"


def test_terminal_short_capped_page_claims_no_coverage(monkeypatch):
    request = EntityTimelineRequest(tool="entity_timeline", arguments=EntityTimelineArgs(
        entity=EntityRef(kind="host", value="video", role="host"),
        start=START, end=START + timedelta(seconds=10),
    ))

    def fake_execute(_client, intent, _contract, *, pit=None):
        ts = intent.window.end - timedelta(seconds=1) if intent.order == "desc" else intent.window.start + timedelta(seconds=1)
        record = {
            "_id": intent.order, "_index": intent.target,
            "_sort": [ts.isoformat(), 1],
            "_source": {"@timestamp": ts.isoformat(), "event": {"dataset": "linux.audit"}},
        }
        return SearchOutcome(
            target=intent.target, fingerprint="fp", started_at=START, ended_at=START,
            completeness=Completeness.partial, reasons=["cap:10000<total:30000"],
            total=30000, total_relation="eq", returned=1, records=[record],
        )

    monkeypatch.setattr(pivot_module, "execute", fake_execute)
    monkeypatch.setattr(pivot_module, "normalize_hits", lambda raw_records: (
        [_process_event(["echo"], event_id=record["_id"]) for record in raw_records], {}, [],
    ))
    contracts = {"romulus-host-x": contract_from_types("romulus-host-x", {
        "@timestamp": "date", "event.dataset": "keyword", "host.name": "keyword",
    })}

    result = PivotExecutor(_repo(), FakeClient(), "h1", contracts).run("case-1", request)

    assert result.coverage[0].covered_ranges == []
    assert len(result.coverage[0].unresolved_ranges) == 1


def test_pivot_coverage_is_rendered_in_utc_for_offset_request_bounds(monkeypatch):
    offset_start = datetime.fromisoformat("2024-11-18T09:00:00-05:00")
    request = EntityTimelineRequest(tool="entity_timeline", arguments=EntityTimelineArgs(
        entity=EntityRef(kind="host", value="video", role="host"),
        start=offset_start, end=offset_start + timedelta(seconds=10),
    ))

    def fake_execute(_client, intent, _contract, *, pit=None):
        record = {
            "_id": "event-offset", "_index": intent.target,
            "_source": {"@timestamp": START.isoformat(), "event": {"dataset": "linux.audit"}},
        }
        return SearchOutcome(
            target=intent.target, fingerprint="fp", started_at=START, ended_at=START,
            completeness=Completeness.complete, total=1, total_relation="eq",
            returned=1, records=[record],
        )

    monkeypatch.setattr(pivot_module, "execute", fake_execute)
    monkeypatch.setattr(pivot_module, "normalize_hits", lambda _records: ([_process_event()], {}, []))
    contracts = {"romulus-host-x": contract_from_types("romulus-host-x", {
        "@timestamp": "date", "event.dataset": "keyword", "host.name": "keyword",
    })}

    result = PivotExecutor(_repo(), FakeClient(), "h1", contracts).run("case-1", request)
    coverage = result.coverage[0].model_dump(mode="json")

    assert coverage["start"] == "2024-11-18T14:00:00Z"
    assert coverage["end"] == "2024-11-18T14:00:10Z"
    assert coverage["covered_ranges"][0]["start"] == "2024-11-18T14:00:00.000000000Z"
    assert coverage["covered_ranges"][0]["end"] == "2024-11-18T14:00:10.000000000Z"


def test_terminal_dense_pivot_reserves_anchor_neighborhood_in_digest(monkeypatch):
    monkeypatch.setattr(pivot_module, "MAX_PIVOT_RECORDS", 64)
    anchor = START + timedelta(seconds=5)
    window = EntityTimelineArgs(
        entity=EntityRef(kind="host", value="video", role="host"),
        start=START, end=START + timedelta(seconds=10),
    )
    request = EntityTimelineRequest(tool="entity_timeline", arguments=window)
    calls = []
    normalized_events = {}

    def records(prefix, timestamps):
        return [{
            "_id": "anchor-event" if prefix == "after" and index == 0 else f"{prefix}-{index}",
            "_index": "romulus-host-x",
            "_sort": [ts.isoformat().replace("+00:00", "Z"), index],
            "_source": {"@timestamp": ts.isoformat(), "event": {"dataset": "linux.audit"}},
        } for index, ts in enumerate(timestamps)]

    def fake_execute(_client, intent, _contract, *, pit=None):
        calls.append((intent.window, intent.order, pit))
        if pit is None:
            batch = records("discarded", [START + timedelta(microseconds=index) for index in range(64)])
        elif intent.window.start == anchor:
            batch = records("after", [anchor + timedelta(milliseconds=index + 1) for index in range(64)])
        elif pit is not None and intent.window.end == anchor:
            batch = records("before", [anchor - timedelta(milliseconds=index + 1) for index in range(64)])
        elif intent.order == "desc":
            batch = records("tail", [intent.window.end - timedelta(milliseconds=index + 1)
                                     for index in range(64)])
        else:
            batch = records("head", [intent.window.start + timedelta(milliseconds=index)
                                     for index in range(64)])
        return SearchOutcome(
            target=intent.target, fingerprint="fp", started_at=START, ended_at=START,
            completeness=Completeness.partial, reasons=["cap:64<total:30000"],
            total=30000, total_relation="eq", returned=64, records=batch,
        )

    monkeypatch.setattr(pivot_module, "execute", fake_execute)
    def fake_normalize(raw_records):
        events = [_process_event(
            ["echo"], event_id=record["_id"],
            ts=datetime.fromisoformat(record["_source"]["@timestamp"]),
        ) for record in raw_records]
        normalized_events.update({event.id: event for event in events})
        return events, {}, []

    monkeypatch.setattr(pivot_module, "normalize_hits", fake_normalize)
    contracts = {"romulus-host-x": contract_from_types("romulus-host-x", {
        "@timestamp": "date", "event.dataset": "keyword", "host.name": "keyword",
    })}

    result = PivotExecutor(_repo(), FakeClient(), "h1", contracts).run(
        "case-1", request, anchor_ts=anchor,
    )

    assert any(attempted.start == anchor and order == "asc" and pit is not None
               for attempted, order, pit in calls)
    assert any(attempted.end == anchor and order == "desc" and pit is not None
               for attempted, order, pit in calls)
    assert result.matched_event_count > 50
    assert len(result.event_summaries) == 50
    assert "anchor-event" not in {
        event.id for event in pivot_module._time_spread(list(normalized_events.values()), 50)
    }
    assert "anchor-event" in {summary["id"] for summary in result.event_summaries}
    assert "anchor-event" in result.anchor_event_ids
