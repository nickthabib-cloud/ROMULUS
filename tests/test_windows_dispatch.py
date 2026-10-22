"""Windows shipper recognition, catalog dispatch, and authoritative structured input."""

from __future__ import annotations

import pytest

from romulus.evidence.normalize import normalize_hits
from romulus.evidence.windows import WindowsInputError, read_windows_event
from romulus.evidence.windows_catalog import lookup_event_class


def _hit(
    native_id: str = "w1",
    *,
    dataset: str = "windows.sysmon_operational",
    agent_type: str = "filebeat",
    channel: str = "Microsoft-Windows-Sysmon/Operational",
    provider: str = "Microsoft-Windows-Sysmon",
    event_id: int | str = 1,
    event_data: dict | None = None,
    original: str | None = None,
    message: str = "rendered text must never be parsed",
):
    winlog = {
        "channel": channel,
        "provider_name": provider,
        "event_id": event_id,
        "computer_name": "WS01.example.test",
        "record_id": 42,
    }
    if event_data is not None:
        winlog["event_data"] = event_data
    source = {
        "@timestamp": "2026-01-02T03:04:05Z",
        "agent": {"type": agent_type},
        "event": {"dataset": dataset},
        "data_stream": {"dataset": dataset},
        "message": message,
        "winlog": winlog,
    }
    if original is not None:
        source["event"]["original"] = original
    return {"_index": "logs-example", "_id": native_id, "_source": source}


def test_catalog_uses_the_complete_channel_provider_event_id_triple():
    known = lookup_event_class(
        "Security", "Microsoft-Windows-Security-Auditing", "4688"
    )
    assert known is not None and known.family == "process_exec"
    assert lookup_event_class("System", known.provider, known.event_id) is None
    assert lookup_event_class(known.channel, "lookalike-provider", known.event_id) is None
    assert lookup_event_class(known.channel, known.provider, 9999) is None


@pytest.mark.parametrize(
    ("dataset", "agent_type"),
    [
        ("windows.sysmon_operational", "filebeat"),
        ("system.security", "filebeat"),
        ("not-a-windows-dataset", "winlogbeat"),
    ],
)
def test_only_shipper_markers_dispatch_windows_records(dataset, agent_type):
    hit = _hit(dataset=dataset, agent_type=agent_type)
    events, skips, errors = normalize_hits([hit])

    assert len(events) == 1
    assert events[0].family == "process_exec"
    assert skips == {} and errors == []


def test_unmarked_lookalike_and_unknown_triple_are_counted_not_guessed():
    lookalike = _hit(dataset="custom.application", agent_type="filebeat")
    unknown = _hit(event_id=9999)

    events, skips, errors = normalize_hits([lookalike, unknown])

    assert events == [] and errors == []
    assert skips["dataset:custom.application is not normalized"] == 1
    reason = next(reason for reason in skips if "Windows event class" in reason)
    assert "9999" in reason and "not normalized" in reason
    assert skips[reason] == 1


def test_message_is_never_parsed_and_structured_fields_win_over_xml():
    xml = _xml(command_line="xml-payload.exe")
    hit = _hit(
        event_data={"Image": r"C:\Windows\safe.exe", "CommandLine": "safe.exe"},
        original=xml,
        message="CommandLine: malicious-from-message.exe",
    )

    record = read_windows_event(hit)

    assert record.value("CommandLine") == "safe.exe"
    assert "message" not in record.origin("CommandLine")
    assert "#xml" not in record.origin("CommandLine")
    assert all("malicious-from-message" not in str(value.value) for value in record.data.values())


def test_event_original_xml_is_used_only_as_the_sole_structured_copy():
    record = read_windows_event(_hit(event_data=None, original=_xml(command_line="from-xml.exe")))

    assert record.value("CommandLine") == "from-xml.exe"
    assert "#xml" in record.origin("CommandLine")


def test_hostile_xml_is_rejected_and_counted_as_malformed_telemetry():
    hostile = '<!DOCTYPE x [<!ENTITY boom "oops">]><Event><EventData/></Event>'
    hit = _hit(event_data=None, original=hostile)

    with pytest.raises(WindowsInputError, match="DOCTYPE|ENTITY"):
        read_windows_event(hit)
    events, skips, errors = normalize_hits([hit])
    assert events == [] and skips == {}
    assert errors and "DOCTYPE" in errors[0][1]


def test_sysmon_hashes_are_split_with_parsed_lineage():
    record = read_windows_event(
        _hit(event_data={"Hashes": "SHA256=ABCDEF,MD5=012345", "Image": "example.exe"})
    )

    assert record.value("Hashes.SHA256") == "abcdef"
    assert record.value("Hashes.MD5") == "012345"
    assert record.origin("Hashes.SHA256").endswith("#parsed:sysmon-hashes")


def _xml(*, command_line: str) -> str:
    return f"""\
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>1</EventID></System>
  <EventData>
    <Data Name="Image">C:\\Windows\\example.exe</Data>
    <Data Name="CommandLine">{command_line}</Data>
  </EventData>
</Event>
"""
