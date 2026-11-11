"""Synthetic eCAR native and indexed timestamps with explicit source provenance.

https://github.com/FiveDirections/OpTC-data/blob/master/ecar.md
https://www.rfc-editor.org/rfc/rfc3339#section-5.6
"""
from datetime import UTC, datetime

import pytest

from romulus.evidence.ecar import normalize_ecar
from romulus.evidence.normalize import normalize_hits


def _hit(**clocks):
    return {"_index": "endpoint", "_id": "clock-1", "_source": {
        "id": "11111111-1111-4111-8111-111111111111", "hostname": "client.example.test",
        "object": "PROCESS", "action": "CREATE", "objectID": "22222222-2222-4222-8222-222222222222",
        "actorID": "33333333-3333-4333-8333-333333333333", "properties": {}, **clocks}}


@pytest.mark.parametrize("clocks,origin,epoch", [
    ({"timestamp_ms": 1735689600123}, "timestamp_ms", 1735689600123),
    ({"timestamp_ms": "1735689600123"}, "timestamp_ms", 1735689600123),
    ({"timestamp": 1735689600123}, "timestamp", 1735689600123),
    ({"timestamp": "1735689600123"}, "timestamp", 1735689600123),
    ({"timestamp": "2025-01-01T00:00:00.123Z"}, "timestamp", None),
    ({"timestamp": "2024-12-31T19:00:00.123-05:00"}, "timestamp", None),
    ({"@timestamp": "2025-01-01T00:00:00.123Z"}, "@timestamp", None),
])
def test_each_supported_clock_reaches_batch_normalization_with_native_origin(clocks, origin, epoch):
    events, skips, errors = normalize_hits([_hit(**clocks)])
    assert errors == [] and not skips and len(events) == 1
    event = events[0]
    assert event.ts == datetime(2025, 1, 1, 0, 0, 0, 123000, tzinfo=UTC)
    assert event.fields["event.created"].origin == "clock-1:" + origin
    assert event.get("event.created") == "2025-01-01T00:00:00.123000+00:00"
    if epoch is None:
        assert not event.has("ecar.timestamp_ms")
    else:
        assert event.get("ecar.timestamp_ms") == epoch
        assert event.fields["ecar.timestamp_ms"].origin == "clock-1:" + origin


@pytest.mark.parametrize("clocks,selected", [
    ({"timestamp_ms": 1735689600123, "@timestamp": "2025-01-02T03:04:05Z"}, "timestamp_ms"),
    ({"timestamp": 1735689600123, "@timestamp": "2025-01-02T03:04:05Z"}, "timestamp"),
    ({"timestamp": "2025-01-01T00:00:00.123Z", "@timestamp": "2025-01-02T03:04:05Z"}, "timestamp"),
])
def test_pipeline_clock_never_overrides_the_source_clock_and_conflict_is_labelled(clocks, selected):
    event = normalize_ecar(_hit(**clocks))
    assert event.ts == datetime(2025, 1, 1, 0, 0, 0, 123000, tzinfo=UTC)
    assert event.fields["event.created"].origin == "clock-1:" + selected
    assert event.get("event.ingested") == "2025-01-02T03:04:05+00:00"
    assert event.fields["event.ingested"].origin == "clock-1:@timestamp"
    assert any("@timestamp" in note and selected in note and "differs" in note for note in event.caveats)


def test_millisecond_field_wins_over_another_native_clock():
    event = normalize_ecar(_hit(timestamp_ms=1735689600123, timestamp=1735689601123))
    assert event.ts == datetime(2025, 1, 1, 0, 0, 0, 123000, tzinfo=UTC)
    assert event.fields["event.created"].origin == "clock-1:timestamp_ms"
    assert event.get("ecar.timestamp_ms") == 1735689600123
    assert any("timestamp" in note and "differs" in note for note in event.caveats)


def test_equivalent_native_and_pipeline_clocks_do_not_claim_a_conflict():
    event = normalize_ecar(_hit(timestamp_ms=1735689600123, timestamp="2025-01-01T00:00:00.123Z",
                               **{"@timestamp": "2024-12-31T19:00:00.123-05:00"}))
    assert not any("differs" in note for note in event.caveats)
    assert event.fields["event.created"].origin == "clock-1:timestamp_ms"


def test_iso_submillisecond_precision_is_not_truncated_into_an_invented_native_epoch():
    event = normalize_ecar(_hit(timestamp="2025-01-01T00:00:00.123456Z"))
    assert event.ts.microsecond == 123456
    assert event.get("event.created") == "2025-01-01T00:00:00.123456+00:00"
    assert not event.has("ecar.timestamp_ms")


@pytest.mark.parametrize("clocks", [
    {}, {"timestamp_ms": True}, {"timestamp_ms": "bad"}, {"timestamp_ms": 1.25},
    {"timestamp_ms": 10 ** 30}, {"timestamp": True}, {"timestamp": "bad"},
    {"timestamp": "2025-01-01T00:00:00"}, {"@timestamp": "bad"},
    {"@timestamp": "2025-01-01T00:00:00"}, {"@timestamp": 1735689600123},
    {"timestamp_ms": "bad", "@timestamp": "2025-01-01T00:00:00Z"},
    {"timestamp": "bad", "@timestamp": "2025-01-01T00:00:00Z"},
    {"timestamp_ms": 1735689600123, "@timestamp": "bad"},
])
def test_malformed_present_clocks_remain_counted_even_when_another_clock_is_valid(clocks):
    events, skips, errors = normalize_hits([_hit(**clocks)])
    assert not events and not skips and len(errors) == 1
    assert errors[0][0] == "clock-1"
    assert errors[0][1].startswith("ecar:") and "timestamp" in errors[0][1]
