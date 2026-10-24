"""The hunt-layer adapter reuses sweep retrieval without crossing the baseline boundary."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from romulus.hunt import baseline_source as module
from romulus.hunt.baseline_source import HuntHistorySource
from romulus.sources.models import Completeness
from romulus.sources.profile import FieldContract

START = datetime(2026, 1, 1, tzinfo=UTC)


def test_adapter_reuses_partition_planner_execute_and_normalizer(monkeypatch):
    planned = []

    def plan(client, target, contract, window, filters):
        planned.append((client, target, contract, window, filters))
        return [(window, 2)]

    monkeypatch.setattr(module, "plan_partitions", plan)
    source = HuntHistorySource("client", {
        "host-index": FieldContract(target="host-index", fields={}, role="host"),
    })
    result = source.plan("host-index", START, START + timedelta(hours=1), query_budget=5)
    parts = list(result.partitions)
    assert len(parts) == 1 and parts[0].expected_records == 2
    assert result.query_count == 1 and result.completeness == "complete"
    assert planned[0][4][0].field == "event.dataset"

    outcome = SimpleNamespace(
        completeness=Completeness.complete, reasons=[], error=None, total=2,
        total_relation="eq", returned=2, records=[{"_id": "1"}, {"_id": "2"}],
    )
    def one_page(_client, _intent, _contract, *, on_query, **_kwargs):
        assert on_query()
        return outcome

    monkeypatch.setattr(module, "execute", one_page)
    monkeypatch.setattr(module, "normalize_hits", lambda records, boots: (["event"], {}, []))
    fetched = source.fetch(parts[0])
    assert fetched.completeness == "complete"
    assert fetched.events == ("event",) and fetched.record_count == 2 and fetched.query_count == 1


def test_recursive_planning_stops_at_the_physical_query_budget(monkeypatch):
    calls = []

    def oversized(_client, _target, _contract, window, _filters):
        calls.append(window)
        return [(window, module.PARTITION_MAX_DOCS + 1)]

    monkeypatch.setattr(module, "plan_partitions", oversized)
    source = HuntHistorySource("client", {
        "host-index": FieldContract(target="host-index", fields={}, role="host"),
    })

    result = source.plan("host-index", START, START + timedelta(hours=1), query_budget=1)

    assert result.completeness == "partial"
    assert result.query_count == 1 and len(calls) == 1
    assert result.reasons == ("planning query budget exhausted",)


def test_zero_partition_skips_source_and_fetch_reports_physical_spend(monkeypatch):
    called = []
    source = HuntHistorySource("client", {
        "network": FieldContract(target="network", fields={}, role="network"),
    })
    zero = module.HistoryPartition("network", START, START + timedelta(hours=1), 0, "zero")
    monkeypatch.setattr(module, "execute", lambda *_args, **_kwargs: called.append(True))
    assert source.fetch(zero, record_budget=0, query_budget=1).query_count == 0
    assert called == []

    outcome = SimpleNamespace(
        completeness=Completeness.partial, reasons=["source query budget exhausted"], error=None,
        total=4_000, total_relation="eq", returned=2_000, records=[],
    )

    def bounded(_client, _intent, _contract, *, on_query, **_kwargs):
        assert on_query() is True
        assert on_query() is False
        return outcome

    monkeypatch.setattr(module, "execute", bounded)
    part = module.HistoryPartition("network", START, START + timedelta(hours=1), 4_000, "paged")
    fetched = source.fetch(part, record_budget=4_000, query_budget=1)
    assert fetched.query_count == 1 and fetched.completeness == "partial"


def test_adapter_turns_normalization_errors_and_unsupported_records_partial(monkeypatch):
    source = HuntHistorySource("client", {
        "network": FieldContract(target="network", fields={}, role="network"),
    })
    partition = module.HistoryPartition(
        "network", START, START + timedelta(hours=1), 1, "p",
    )
    outcome = SimpleNamespace(
        completeness=Completeness.complete, reasons=[], error=None, total=1,
        total_relation="eq", returned=1,
        records=[{"_id": "1", "_source": {"event": {"dataset": "unknown"}}}],
    )
    monkeypatch.setattr(module, "execute", lambda client, intent, contract, **_kwargs: outcome)
    monkeypatch.setattr(
        module, "normalize_hits",
        lambda records, boots: ([], {"dataset:unknown is not normalized": 1}, [("1", "bad")]),
    )
    fetched = source.fetch(partition)
    assert fetched.completeness == "partial"
    assert "normalization_errors=1" in fetched.reasons
    assert "unsupported_records=1" in fetched.reasons


def _complete_outcome(records=2):
    return SimpleNamespace(
        completeness=Completeness.complete, reasons=[], error=None, total=records,
        total_relation="eq", returned=records, records=[{"_id": str(index)} for index in range(records)],
    )


def test_boot_conflict_in_an_hour_makes_the_hour_partial_and_the_map_is_per_hour(monkeypatch):
    monkeypatch.setattr(module, "plan_partitions", lambda client, target, contract, window, filters: [
        (window, 2)])
    monkeypatch.setattr(module, "execute", lambda *_args, **_kwargs: _complete_outcome())
    maps = []

    def normalize(records, boots):
        maps.append(boots)
        if len(maps) == 1:
            # A later record of the same hour refused a placement made from an earlier one.
            boots.conflicts.setdefault("web01", []).append(("boot-a", 0, 1))
        return ["event"], {}, []

    monkeypatch.setattr(module, "normalize_hits", normalize)
    source = HuntHistorySource("client", {
        "host-index": FieldContract(target="host-index", fields={}, role="host"),
    })
    newest = source.plan("host-index", START + timedelta(hours=1), START + timedelta(hours=2), query_budget=5)
    fetched = source.fetch(newest.partitions[0])
    assert fetched.completeness == "partial"
    assert any("boot placement conflict" in reason and "web01" in reason for reason in fetched.reasons)

    # The next (older) hour gets its own map: its records can never re-place events of the hour above,
    # whose segment may already be written.
    older = source.plan("host-index", START, START + timedelta(hours=1), query_budget=5)
    assert source.fetch(older.partitions[0]).completeness == "complete"
    assert maps[0] is not maps[1] and not maps[1].conflicts


def test_a_process_execs_time_is_the_retrieval_time_field():
    """The parent carry's continuity rests on this: an exec's typed time is the very field history partitions
    retrieve by, so no exec can be typed in one hour and retrieved in another. If exec time ever moved (to the
    audit header, say), the carry's tripwire and horizon would catch only part of it; this test then fails first.
    """
    from romulus.evidence.normalize import normalize_hits
    from romulus.sources.profile import FieldContract

    stamped = "2024-11-18T14:40:00.250Z"            # the shipper's time, minutes after the audit header's
    raws = [
        'type=EXECVE msg=audit(1731940424.829:9001): argc=1 a0="ls"',
        ('type=SYSCALL msg=audit(1731940424.829:9001): arch=c000003e syscall=59 success=yes exit=0 ppid=10 '
         'pid=11 auid=1000 uid=1000 euid=1000 comm="ls" exe="/usr/bin/ls" key=(null)'),
    ]
    hits = [{"_id": f"r{n}", "_index": "host-index", "_source": {
        "@timestamp": stamped, "message": raw, "host": {"name": "video"},
        "event": {"dataset": "linux.audit", "original": raw}}} for n, raw in enumerate(raws)]
    events, _skips, errors = normalize_hits(hits)
    execs = [event for event in events if event.family == "process_exec"]
    assert not errors and len(execs) == 1
    time_field = FieldContract(target="host-index", fields={}).time_field
    assert time_field == "@timestamp"
    assert execs[0].ts == datetime.fromisoformat(hits[0]["_source"][time_field]).astimezone(UTC)


def test_history_filter_uses_contract_role_not_target_name(monkeypatch):
    planned = []
    monkeypatch.setattr(module, "plan_partitions", lambda _client, target, _contract, window, filters: (
        planned.append((target, filters)) or [(window, 0)]
    ))
    source = HuntHistorySource("client", {
        "host-looking-network": FieldContract(target="host-looking-network", fields={}, role="network"),
        "plain-index": FieldContract(target="plain-index", fields={}, role="host"),
    })

    source.plan("host-looking-network", START, START + timedelta(hours=1), query_budget=2)
    source.plan("plain-index", START, START + timedelta(hours=1), query_budget=2)

    assert planned[0] == ("host-looking-network", [])
    assert planned[1][1][0].field == "event.dataset"


def test_fetch_refs_uses_exact_native_ids_and_returns_raw_copies(monkeypatch):
    class Client:
        def __init__(self):
            self.calls = []

        def search(self, target, body):
            self.calls.append((target, body))
            return {"hits": {"hits": [
                {"_index": target, "_id": native_id, "_source": {"message": native_id}}
                for native_id in body["query"]["ids"]["values"]
            ]}}

    client = Client()
    event = SimpleNamespace(id="event", raw=[])
    monkeypatch.setattr(module, "normalize_hits", lambda records, boots: ([event], {}, []))
    source = HuntHistorySource(client, {
        "host-index": FieldContract(target="host-index", fields={}, role="host"),
    })

    events, raw, reasons = source.fetch_refs([
        {"target": "host-index", "native_id": "b"},
        {"target": "host-index", "native_id": "a"},
        {"target": "host-index", "native_id": "a"},
    ])

    assert events == (event,)
    assert client.calls == [("host-index", {
        "size": 2, "query": {"ids": {"values": ["a", "b"]}},
    })]
    assert raw == {"host-index/a": {"message": "a"}, "host-index/b": {"message": "b"}}
    assert reasons == ()
