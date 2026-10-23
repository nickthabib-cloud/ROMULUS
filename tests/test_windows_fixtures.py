"""The shared Windows fixture factory covers shapes, negatives, and mission volume."""

from __future__ import annotations

from itertools import islice

from romulus.evidence.normalize import normalize_hits
from romulus.evidence.windows_catalog import EVENT_CLASSES
from tests.windows_fixtures import (
    SHAPES,
    all_logical_events,
    benign_admin_events,
    mission_windows_volume,
    semantic_event,
    windows_hit,
)


def test_factory_covers_every_catalog_event_in_every_supported_shipper_shape():
    logical = all_logical_events()
    catalog = {(event.channel, event.provider, event.event_id) for event in EVENT_CLASSES}

    assert {(event.channel, event.provider, event.event_id) for event in logical} == catalog
    for shape in SHAPES:
        events, skips, errors = normalize_hits([windows_hit(event, shape) for event in logical])
        assert len(events) == len(catalog)
        assert skips == {} and errors == []


def test_winlogbeat_shapes_do_not_invent_an_event_dataset():
    """Winlogbeat's documented event fields identify the source by agent.type + winlog.*.

    https://www.elastic.co/guide/en/beats/winlogbeat/current/exported-fields-winlog.html
    """
    logical = all_logical_events()[0]

    for shape in ("winlogbeat_7", "winlogbeat_8"):
        source = windows_hit(logical, shape)["_source"]
        assert source["agent"]["type"] == "winlogbeat"
        assert "event" not in source or "dataset" not in source["event"]


def test_each_logical_event_has_identical_typed_semantics_in_all_three_shapes():
    for logical in all_logical_events():
        normalized = []
        for shape in SHAPES:
            [event], skips, errors = normalize_hits([windows_hit(logical, shape)])
            assert skips == {} and errors == []
            normalized.append(semantic_event(event))
        assert normalized[1:] == normalized[:-1], logical


def test_cross_shipper_copies_are_deduplicated_with_every_raw_reference_retained():
    logical = all_logical_events()[0]
    hits = [windows_hit(logical, shape) for shape in SHAPES]
    for ordinal, hit in enumerate(hits):
        hit["_index"] = f"logs-{ordinal}"
        hit["_id"] = f"copy-{ordinal}"

    events, skips, errors = normalize_hits(hits)

    assert errors == [] and len(events) == 1
    assert len(events[0].raw) == len(SHAPES)
    assert sum(skips.values()) == len(SHAPES) - 1
    assert any("duplicate Windows event copy" in reason for reason in skips)


def test_benign_admin_negatives_are_structured_cataloged_events():
    logical = benign_admin_events()
    events, skips, errors = normalize_hits([windows_hit(event, "elastic_agent") for event in logical])

    assert skips == {} and errors == [] and len(events) == len(logical)
    assert {event.family for event in events} >= {
        "process_exec", "account_change", "service_change", "scheduled_task",
    }
    assert all(event.get("host.os.family") == "windows" for event in events)


def test_mission_volume_generator_is_streaming_deterministic_and_uses_documentation_values():
    generated = mission_windows_volume(20_000, shape="winlogbeat_8", seed=7)
    assert iter(generated) is generated
    first = list(islice(generated, 500))
    again = list(islice(mission_windows_volume(20_000, shape="winlogbeat_8", seed=7), 500))

    assert first == again
    assert len({record["_id"] for record in first}) == 500
    rendered = str(first)
    assert "example.test" in rendered
    assert any(prefix in rendered for prefix in ("192.0.2.", "198.51.100.", "203.0.113."))
