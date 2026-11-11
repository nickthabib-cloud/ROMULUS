"""Synthetic native time copies from Windows Event Schema and Winlogbeat JSON.

https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-timecreated-systempropertiestype-element
https://www.elastic.co/guide/en/beats/winlogbeat/current/exported-fields-winlog.html
"""
from copy import deepcopy

import pytest

from romulus.evidence.normalize import normalize_hits
from romulus.evidence.windows import RecordIdContinuity, windows_record_signature
from romulus.hunt.stage import EventStage
from tests.test_evtx_json import raw_hit, twin
from tests.windows_fixtures import LogicalWindowsEvent, windows_hit


def _copies(native_time, shipped_time):
    native = raw_hit()
    native["_source"]["Event"]["System"]["TimeCreated"]["#attributes"]["SystemTime"] = native_time
    native["_source"]["@timestamp"] = "2030-01-06T09:00:00.123Z"
    shipped = twin(native)
    shipped["_id"] = "shipped-copy"
    shipped["_source"]["winlog"]["time_created"] = shipped_time
    return native, shipped


@pytest.mark.parametrize("native_time, shipped_time", [
    ("2030-01-06T09:00:00.1234567Z", "2030-01-06T09:00:00.123Z"),
    ("2030-01-06T09:00:00.123Z", "2030-01-06T09:00:00.123Z"),
    ("2030-01-06T09:00:00.1234567Z", "2030-01-06T10:00:00.123+01:00"),
    ("2030-01-06T09:00:00.9999999Z", "2030-01-06T09:00:00.999Z"),
    ("2030-01-06T09:00:00.0000001Z", "2030-01-06T09:00:00Z"),
])
def test_native_and_shipped_time_precisions_deduplicate_without_false_log_reuse(native_time, shipped_time):
    records = _copies(native_time, shipped_time)
    events, skips, errors = normalize_hits(list(records))
    assert errors == []
    assert len(events) == 1
    assert {ref.native_id for ref in events[0].raw} == {"raw-1", "shipped-copy"}
    assert skips == {"duplicate Windows event copy (computer/channel/record_id)": 1}
    continuity = RecordIdContinuity()
    try:
        preceding = deepcopy(records[0])
        preceding["_source"]["Event"]["System"]["EventRecordID"] = 18
        assert continuity.observe("windows", [preceding, records[0]]) == []
        assert continuity.observe("windows", [records[1]]) == []
    finally:
        continuity.close()


def test_same_record_id_one_millisecond_later_is_a_distinct_event():
    records = _copies("2030-01-06T09:00:00.1234567Z", "2030-01-06T09:00:00.124Z")
    events, skips, errors = normalize_hits(list(records))
    assert errors == [] and len(events) == 2
    assert len({event.id for event in events}) == 2
    assert skips == {"record_id reused (log cleared or reverted)": 1}


def test_same_instant_with_different_payload_is_not_a_duplicate():
    native, shipped = _copies("2030-01-06T09:00:00.1234567Z", "2030-01-06T09:00:00.123Z")
    shipped["_source"]["winlog"]["event_data"]["CommandLine"] = "cmd.exe /c different"
    events, skips, errors = normalize_hits([native, shipped])
    assert errors == [] and len(events) == 2
    assert skips == {"record_id reused (log cleared or reverted)": 1}


def test_native_payload_time_uses_the_same_millisecond_identity():
    native, shipped = _copies("2030-01-06T09:00:00.1234567Z", "2030-01-06T09:00:00.123Z")
    native["_source"]["Event"]["EventData"]["TimeCreated"] = "2030-01-06T09:00:00.1234567Z"
    shipped["_source"]["winlog"]["event_data"]["TimeCreated"] = "2030-01-06T09:00:00.123Z"
    assert windows_record_signature(native) == windows_record_signature(shipped)
    changed = deepcopy(shipped)
    changed["_source"]["winlog"]["event_data"]["TimeCreated"] = "2030-01-06T09:00:00.124Z"
    assert windows_record_signature(native) != windows_record_signature(changed)


def test_native_and_shipped_copies_in_different_batches_deduplicate_on_disk(tmp_path):
    native, shipped = _copies("2030-01-06T09:00:00.1234567Z", "2030-01-06T09:00:00.123Z")
    first = normalize_hits([native])[0][0]
    duplicate = normalize_hits([shipped])[0][0]
    stage = EventStage(tmp_path)
    try:
        assert stage.unique_windows([first]) == ([first], [])
        fresh, duplicates = stage.unique_windows([duplicate])
        assert fresh == [] and len(duplicates) == 1
        assert first.id == duplicate.id
    finally:
        stage.close()


def _read_time_copy(shape):
    native = raw_hit()
    source = native["_source"]
    system = source["Event"]["System"]
    system["TimeCreated"]["#attributes"]["SystemTime"] = "2030-01-06T09:00:00.1234567Z"
    event = LogicalWindowsEvent(channel=system["Channel"], provider=system["Provider"]["#attributes"]["Name"],
        event_id=system["EventID"], computer=system["Computer"], record_id=system["EventRecordID"],
        timestamp="2030-01-06T09:00:00.123Z", data=source["Event"]["EventData"])
    shipped = windows_hit(event, shape)
    shipped["_source"]["winlog"].pop("time_created", None)
    shipped["_source"].setdefault("event", {})["created"] = "2030-01-06T09:00:01.456Z"
    return native, shipped


@pytest.mark.parametrize("shape", ["winlogbeat_8", "elastic_agent"])
def test_real_shipper_read_time_does_not_split_native_twins(shape):
    native, shipped = _read_time_copy(shape)
    events, skips, errors = normalize_hits([native, shipped])
    assert errors == [] and len(events) == 1
    assert skips == {"duplicate Windows event copy (computer/channel/record_id)": 1}
    continuity = RecordIdContinuity()
    try:
        preceding = deepcopy(native)
        preceding["_source"]["Event"]["System"]["EventRecordID"] = 18
        assert continuity.observe("windows", [preceding, native]) == []
        assert continuity.observe("windows", [shipped]) == []
    finally:
        continuity.close()


@pytest.mark.parametrize("shape", ["winlogbeat_8", "elastic_agent"])
def test_shipper_records_read_together_remain_distinct_one_millisecond_apart(shape):
    _, first = _read_time_copy(shape)
    second = deepcopy(first)
    second["_id"] += "-later"
    second["_source"]["@timestamp"] = "2030-01-06T09:00:00.124Z"
    events, skips, errors = normalize_hits([first, second])
    assert errors == [] and len(events) == 2
    assert skips == {"record_id reused (log cleared or reverted)": 1}
