"""Streaming, bounded baseline key counting."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from romulus.baseline.count import KeyCounter
from romulus.baseline.spec import BASELINE_SPECS, SPEC_BY_ID, BaselineKey, KeyContext
from romulus.detect.correlation import PidTable
from romulus.evidence.typed import Outcome, TypedEvent, fv

T0 = datetime(2026, 1, 2, 12, tzinfo=UTC)


def _event(family: str, event_id: str, ts: datetime = T0, outcome=Outcome.unknown, **fields):
    return TypedEvent(
        id=event_id, family=family, ts=ts, host="web01", outcome=outcome,
        fields={name: fv(value, f"fixture:{name}") for name, value in fields.items()},
        raw=[], normalizer="fixture@1",
    )


def _key(name: str, token: str | None) -> BaselineKey:
    return BaselineKey(
        scope_kind="host", scope="host:web01", key={"name": name},
        key_digest=f"digest-{name}", key_id=f"id-{name}", dedup_token=token,
    )


def test_counter_deduplicates_per_key_and_token_not_token_alone():
    counter = KeyCounter("segment", SPEC_BY_ID["bl.ext_dest"])
    counter.add_keys(T0, [_key("a", "flow-1"), _key("b", "flow-1")])
    counter.add_keys(T0 + timedelta(seconds=1), [_key("a", "flow-1"), _key("b", "flow-1")])

    rows = list(counter.count_rows())

    assert {(row["key_digest"], row["count"]) for row in rows} == {
        ("digest-a", 1), ("digest-b", 1),
    }
    assert next(iter(counter.scope_hour_rows()))["events"] == 2


def test_none_token_counts_each_record_and_scope_hour_once():
    counter = KeyCounter("segment", SPEC_BY_ID["bl.exec_path"])
    counter.add_keys(T0, [_key("a", None), _key("a", None)])
    counter.add_keys(T0 + timedelta(minutes=1), [_key("a", None)])

    assert next(iter(counter.count_rows()))["count"] == 2
    assert list(counter.scope_hour_rows()) == [{
        "segment_id": "segment", "scope_kind": "host", "scope": "host:web01",
        "hour": T0.replace(minute=0), "events": 2,
    }]


def test_token_cap_marks_counter_partial_and_refuses_segment_rows():
    counter = KeyCounter("segment", SPEC_BY_ID["bl.ext_dest"], token_cap=2)
    counter.add_keys(T0, [_key("a", "one")])
    counter.add_keys(T0, [_key("a", "two")])
    counter.add_keys(T0, [_key("a", "three")])

    assert counter.partial is True
    assert counter.reasons == ("dedup token cap 2 exceeded in an open bucket",)
    assert list(counter.count_rows()) == []
    assert list(counter.scope_hour_rows()) == []


def test_count_and_pending_caps_make_oversized_segments_partial():
    rows = KeyCounter("segment", SPEC_BY_ID["bl.exec_path"], row_cap=1)
    rows.add_keys(T0, [_key("a", None)])
    rows.add_keys(T0, [_key("b", None)])
    assert rows.partial and "count row cap 1 exceeded" in rows.reasons

    pendings = KeyCounter("segment", SPEC_BY_ID["bl.exec_pair"], pending_cap=1)
    for index in range(2):
        pendings.consume(_event("process_exec", f"child-{index}", outcome=Outcome.success, **{
            "process.executable": "/bin/sh", "process.ppid": 99,
        }), KeyContext())
    assert pendings.partial and "pending parent cap 1 exceeded" in pendings.reasons


def test_missing_reason_collection_stops_after_the_first_partial_fact():
    counter = KeyCounter("segment", SPEC_BY_ID["bl.exec_path"])
    for index in range(10_000):
        counter.consume(_event("process_exec", f"missing-{index}"), KeyContext())
    assert counter.partial and len(counter.reasons) == 1


def test_shuffle_within_one_bucket_is_deterministic():
    items = [
        (T0 + timedelta(seconds=2), [_key("a", "two")]),
        (T0, [_key("a", "one")]),
        (T0 + timedelta(seconds=1), [_key("a", "one")]),
    ]
    outputs = []
    for ordered in (items, list(reversed(items))):
        counter = KeyCounter("segment", SPEC_BY_ID["bl.ext_dest"])
        for ts, keys in ordered:
            counter.add_keys(ts, keys)
        outputs.append(list(counter.count_rows()))

    assert outputs[0] == outputs[1]


def test_dns_integer_and_string_ids_share_one_dedup_token():
    spec = SPEC_BY_ID["bl.ext_dest"]
    fields = {
        "dns.type": "query", "source.ip": "10.0.0.4", "destination.ip": "10.0.0.53", "source.port": 40000,
        "destination.port": 53, "dns.question.name": "www.example.com", "suricata.flow_id": 77,
    }
    integer = spec.keys(_event("dns_query", "one", **fields, **{"dns.id": 42}), KeyContext())[0]
    string = spec.keys(_event("dns_query", "two", **fields, **{"dns.id": "42"}), KeyContext())[0]

    assert integer.dedup_token == string.dedup_token


def test_every_accepted_spec_runs_through_the_counter():
    parent_table = PidTable()
    parent_table.add(_event(
        "process_exec", "parent", T0 - timedelta(seconds=1), Outcome.success,
        **{"process.pid": 10, "process.ppid": 1, "process.executable": "/sbin/init"},
    ))
    fixtures = {
        "bl.ssh_tuple": _event("auth", "ssh", outcome=Outcome.success, **{
            "auth.service": "sshd", "source.ip": "192.0.2.10", "user.name": "alice",
        }),
        "bl.exec_path": _event("process_exec", "path", outcome=Outcome.success, **{
            "process.executable": "/bin/id", "process.exec_file.path": "/bin/id", "process.user": "svc",
        }),
        "bl.exec_pair": _event("process_exec", "pair", outcome=Outcome.success, **{
            "process.executable": "/bin/id", "process.ppid": 10,
        }),
        "bl.cmd_shape": _event("process_exec", "shape", outcome=Outcome.success, **{
            "process.executable": "/bin/id", "process.argv": ["id"],
        }),
        "bl.ext_dest": _event("net_flow", "flow", **{
            "source.ip": "10.0.0.4", "destination.ip": "198.51.100.8",
        }),
        "bl.svc_exec_rate": _event("process_exec", "rate", **{
            "process.user": "svc", "process.uid": 100,
        }),
    }
    seen = []
    for spec in BASELINE_SPECS:
        counter = KeyCounter("segment", spec)
        counter.consume(fixtures[spec.id], KeyContext(pid_table=parent_table))
        assert not counter.partial
        assert list(counter.count_rows())
        seen.append(spec.id)

    assert seen == [spec.id for spec in BASELINE_SPECS]


def test_million_records_keep_only_current_bucket_tokens():
    counter = KeyCounter("segment", SPEC_BY_ID["bl.ext_dest"], token_cap=16)
    for index in range(1_000_000):
        hour = T0 + timedelta(hours=index // 100_000)
        counter.add_keys(hour, [_key("a", f"token-{index % 4}")])

    assert counter.max_token_entries == 4
    assert counter.token_entries == 4
    assert not counter.partial
