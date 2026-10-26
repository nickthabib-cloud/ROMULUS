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
    windows_xml_hit,
)

_REPRESENTATIVE_FIELDS = {
    "process_exec": ("process.executable",),
    "process_termination": ("process.executable",),
    "net_socket": ("source.ip", "destination.ip"),
    "auth": ("source.ip",),
    "account_change": ("auth.target_account",),
    "service_change": ("service.name",),
    "scheduled_task": ("task.name",),
    "audit_config": ("audit.config.action",),
    "system_state": ("system.event",),
    "file_change": ("file.path",),
    "process_access": ("process.access.mask",),
    "image_load": ("image.path",),
    "remote_thread": ("thread.id",),
    "process_tampering": ("process.tampering.type",),
    "registry_change": ("registry.path",),
    "object_access": ("object.name",),
    "pipe_event": ("pipe.name",),
    "wmi_subscription": ("wmi.name", "wmi.consumer"),
    "dns_lookup": ("dns.question.name",),
    "script_block": ("script.text",),
    "directory_access": ("directory.object.dn",),
    "directory_change": ("directory.object.dn",),
    "share_access": ("share.name",),
    "defender_event": ("defender.threat.name",),
    "remote_access": ("source.ip", "bits.job_id"),
}


def test_factory_covers_every_catalog_event_in_every_supported_shipper_shape():
    logical = all_logical_events()
    catalog = {(event.channel, event.provider, event.event_id) for event in EVENT_CLASSES}

    assert {(event.channel, event.provider, event.event_id) for event in logical} == catalog
    for shape in SHAPES:
        events, skips, errors = normalize_hits([windows_hit(event, shape) for event in logical])
        assert len(events) == len(catalog)
        assert skips == {} and errors == []


def test_every_catalog_fixture_rejects_a_wrong_provider_as_a_hard_negative():
    logical = all_logical_events()
    hits = [windows_hit(event, "elastic_agent") for event in logical]
    for hit in hits:
        winlog = hit["_source"]["winlog"]
        winlog["provider_name"] = str(winlog["provider_name"]) + "-not-cataloged"

    events, skips, errors = normalize_hits(hits)

    assert events == []
    assert errors == []
    assert sum(skips.values()) == len(logical)


def test_every_catalog_fixture_reports_a_malformed_structured_payload_without_crashing():
    logical = all_logical_events()
    hits = [windows_hit(event, "elastic_agent") for event in logical]
    for hit in hits:
        hit["_source"]["winlog"]["event_data"] = "not-an-object"

    events, skips, errors = normalize_hits(hits)

    assert events == []
    assert skips == {}
    assert len(errors) == len(logical)
    assert all("winlog.event_data must be an object" in reason for _native_id, reason in errors)


def test_every_catalog_fixture_has_representative_native_and_typed_family_data():
    event_classes = {(row.channel, row.provider, row.event_id): row for row in EVENT_CLASSES}

    for logical in all_logical_events():
        key = (logical.channel, logical.provider, logical.event_id)
        event_class = event_classes[key]
        assert logical.data, key
        [normalized], skips, errors = normalize_hits([windows_hit(logical, "elastic_agent")])
        assert skips == {} and errors == []
        expected = _REPRESENTATIVE_FIELDS[event_class.family]
        assert any(field in normalized.fields for field in expected), (key, event_class.family, expected)


def test_1102_fixture_uses_the_documented_eventlog_provider_independently_of_catalog():
    """Microsoft's event XML names Microsoft-Windows-Eventlog, not Security-Auditing.

    https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102
    """
    [event] = [event for event in all_logical_events() if event.event_id == 1102]
    assert event.channel == "Security"
    assert event.provider == "Microsoft-Windows-Eventlog"


def test_winlogbeat_shapes_do_not_invent_an_event_dataset():
    """Winlogbeat's documented event fields identify the source by agent.type + winlog.*.

    https://www.elastic.co/guide/en/beats/winlogbeat/current/exported-fields-winlog.html
    """
    logical = all_logical_events()[0]

    for shape in ("winlogbeat_7", "winlogbeat_8"):
        source = windows_hit(logical, shape)["_source"]
        assert source["agent"]["type"] == "winlogbeat"
        assert "event" not in source or "dataset" not in source["event"]


def test_shipper_variants_cover_supported_keyword_and_dataset_differences():
    operational = next(event for event in all_logical_events() if event.channel.endswith("/Operational")
                       and event.provider not in {"Microsoft-Windows-Sysmon"})
    old_beat = windows_hit(operational, "winlogbeat_7")["_source"]
    agent = windows_hit(operational, "elastic_agent")["_source"]

    assert isinstance(old_beat["winlog"]["event_id"], str)
    assert isinstance(old_beat["winlog"]["record_id"], str)
    assert agent["event"]["dataset"] != "system.system"


def test_provider_payload_in_user_data_uses_the_supported_structured_fallback():
    logical = next(event for event in all_logical_events() if event.channel.endswith("/Operational"))
    hit = windows_hit(logical, "elastic_agent")
    hit["_source"]["winlog"]["user_data"] = hit["_source"]["winlog"].pop("event_data")

    [event], skips, errors = normalize_hits([hit])

    assert skips == {} and errors == []
    assert event.get("event.channel") == logical.channel


def test_defender_space_and_agent_underscore_native_names_have_identical_typed_values():
    logical = next(event for event in all_logical_events()
                   if event.provider == "Microsoft-Windows-Windows Defender")
    [beat], _, _ = normalize_hits([windows_hit(logical, "winlogbeat_8")])
    [agent], _, _ = normalize_hits([windows_hit(logical, "elastic_agent")])

    assert beat.get("defender.threat.name") == agent.get("defender.threat.name")
    assert beat.get("defender.recorded_action") == agent.get("defender.recorded_action")
    assert ".Threat Name" in beat.fields["defender.threat.name"].origin
    assert ".Threat_Name" in agent.fields["defender.threat.name"].origin


def test_each_logical_event_has_identical_typed_semantics_in_all_three_shapes():
    for logical in all_logical_events():
        normalized = []
        for shape in SHAPES:
            [event], skips, errors = normalize_hits([windows_hit(logical, shape)])
            assert skips == {} and errors == []
            normalized.append(semantic_event(event))
        assert normalized[1:] == normalized[:-1], logical


def test_one_event_per_channel_normalizes_when_event_data_exists_only_in_original_xml():
    by_channel = {}
    for logical in all_logical_events():
        by_channel.setdefault(logical.channel, logical)
    catalog_channels = {event.channel for event in EVENT_CLASSES}
    assert set(by_channel) == catalog_channels

    events, skips, errors = normalize_hits([windows_xml_hit(logical) for logical in by_channel.values()])

    assert len(events) == len(catalog_channels)
    assert skips == {} and errors == []
    assert {event.get("event.channel") for event in events} == set(by_channel)
    assert all(any("#xml" in field.origin for field in event.fields.values()) for event in events)


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


def test_defender_agent_aliases_and_xml_are_one_native_record_signature():
    logical = next(
        event for event in all_logical_events()
        if event.provider == "Microsoft-Windows-Windows Defender"
    )
    hits = [
        windows_hit(logical, "winlogbeat_8"),
        windows_hit(logical, "elastic_agent"),
        windows_xml_hit(logical, "winlogbeat_8"),
    ]
    for ordinal, hit in enumerate(hits):
        hit["_index"] = f"logs-defender-{ordinal}"
        hit["_id"] = f"defender-copy-{ordinal}"

    events, skips, errors = normalize_hits(hits)

    assert errors == []
    assert len(events) == 1
    assert len(events[0].raw) == 3
    assert skips == {"duplicate Windows event copy (computer/channel/record_id)": 2}


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
