"""Synthetic Windows XML/EVTX JSON shapes from public renderer and event-schema specifications.

https://github.com/omerbenamram/evtx
https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-systempropertiestype-complextype
https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-eventdatatype-complextype
https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.eventing.reader.standardeventkeywords
https://www.w3.org/TR/REC-xml/#sec-line-ends
https://github.com/elastic/beats/blob/v8.19.12/winlogbeat/sys/strings.go
https://github.com/elastic/beats/blob/v8.19.12/winlogbeat/sys/winevent/winmeta.go
"""
from copy import deepcopy
from datetime import UTC, datetime

import pytest

from romulus.evidence import windows as w
from romulus.evidence.normalize import normalize_hits
from romulus.evidence.typed import Outcome

WHEN = "2024-03-04T12:34:56.1234567Z"
PIPELINE = "2024-03-04T12:35:00.000000Z"
SECURITY = "Microsoft-Windows-Security-Auditing"


def raw_hit(*, event_id=4688, data=None, channel="Security", provider=SECURITY):
    return {"_index": "synthetic-windows", "_id": "raw-1", "_source": {"Event": {
        "#attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"},
        "System": {
            "Provider": {"#attributes": {"Name": provider}}, "EventID": event_id,
            "Version": 2, "Level": 0, "Task": 13312, "Opcode": 0, "Keywords": "0x8020000000000000",
            "TimeCreated": {"#attributes": {"SystemTime": WHEN}}, "EventRecordID": 19,
            "Execution": {"#attributes": {"ProcessID": 4, "ThreadID": 68}},
            "Channel": channel, "Computer": "WS01.example.test", "Security": None,
        },
        "EventData": {"NewProcessName": r"C:\Windows\System32\cmd.exe", "NewProcessId": "0x1234",
                      "CommandLine": "cmd.exe /c echo synthetic", "SubjectUserName": "operator"}
        if data is None else data,
    }}}


def twin(hit):
    src = hit["_source"]
    system = src["Event"]["System"]
    return {**hit, "_source": {
        "@timestamp": src.get("@timestamp", WHEN), "agent": {"type": "winlogbeat"},
        "winlog": {
            "channel": system["Channel"], "provider_name": system["Provider"]["#attributes"]["Name"],
            "event_id": system["EventID"], "computer_name": system["Computer"], "record_id": system["EventRecordID"],
            "time_created": WHEN, "event_data": deepcopy(src["Event"]["EventData"]),
            "keywords": ["Audit Success"],
        },
    }}


def values(event):
    return {key: item.value for key, item in event.fields.items()}


@pytest.mark.parametrize("event_id", [4688, "4688", {"#attributes": {"Qualifiers": 0}, "#text": 4688}])
def test_event_identity_and_semantics_match_winlogbeat(event_id):
    hit = raw_hit(event_id=event_id)
    winlog = twin(raw_hit())
    events, skips, errors = normalize_hits([hit])
    assert skips == {} and errors == [] and len(events) == 1
    actual, expected = events[0], w.normalize_windows(winlog)
    assert (actual.family, actual.host, actual.ts, actual.outcome) == (
        expected.family, expected.host, expected.ts, expected.outcome)
    assert values(actual) == values(expected)
    assert actual.fields["process.executable"].origin == "raw-1:Event.EventData.NewProcessName"
    assert actual.fields["event.provider"].origin == "raw-1:Event.System.Provider.#attributes.Name"
    assert all(":winlog." not in field.origin for field in actual.fields.values())


@pytest.mark.parametrize("event_id", [True, False, "nonsense", "4688.0", 4688.5, None, [], {}])
def test_malformed_event_id_is_counted_without_guessing(event_id):
    hit = raw_hit(event_id=event_id)
    assert w.is_windows_source(hit["_source"])
    events, skips, errors = normalize_hits([hit])
    assert not events and not skips and len(errors) == 1
    assert "EventID" in errors[0][1]


@pytest.mark.parametrize("missing", ["Computer", "Channel", "EventID", "Provider"])
def test_incomplete_envelope_never_claims_an_app_document(missing):
    hit = raw_hit()
    del hit["_source"]["Event"]["System"][missing]
    assert not w.is_evtx_json(hit["_source"])
    events, skips, errors = normalize_hits([hit])
    assert not events and sum(skips.values()) + len(errors) == 1
    with pytest.raises(w.WindowsInputError):
        w.evtx_json_to_winlog(hit["_source"])


@pytest.mark.parametrize("source", [{"Event": "application event"}, {"Event": {"System": {}}},
                                    {"evtx": raw_hit()["_source"]}])
def test_other_event_objects_and_wrappers_are_not_windows(source):
    assert not w.is_windows_source(source)


def test_existing_winlog_dict_wins_over_evtx_shape():
    hit = raw_hit()
    hit["_source"]["winlog"] = {"event_id": "existing"}
    assert not w.is_evtx_json(hit["_source"])
    assert w.windows_view(hit["_source"]) is hit["_source"]


@pytest.mark.parametrize("qualifier_shape", ["object", "split", "flat"])
def test_classic_event_id_qualifiers_and_event_source_name(qualifier_shape):
    hit = raw_hit(event_id=7036, channel="System", provider="Service Control Manager", data={"Data": ["example", "running"]})
    system = hit["_source"]["Event"]["System"]
    system["Provider"]["#attributes"]["EventSourceName"] = "An unrelated lookup name"
    if qualifier_shape == "object":
        system["EventID"] = {"#text": 7036, "#attributes": {"Qualifiers": 16384}}
    elif qualifier_shape == "split":
        system["EventIDQualifiers"] = 16384
    else:
        system["EventID_attributes"] = {"Qualifiers": 16384}
    view = w.evtx_json_to_winlog(hit["_source"])
    assert view["winlog"]["event_id"] == 7036
    assert view["winlog"]["qualifiers"] == 16384
    assert view["winlog"]["event_source_name"] == "An unrelated lookup name"
    assert w.normalize_windows(hit).get("event.provider") == "Service Control Manager"


def test_flat_attributes_keep_all_system_native_values_and_origins():
    hit = raw_hit()
    system = hit["_source"]["Event"]["System"]
    for name in ("Provider", "TimeCreated", "Execution"):
        system[name + "_attributes"] = system.pop(name)["#attributes"]
    system["Execution_attributes"] = {"ProcessID": "4", "ThreadID": "68"}
    system["EventRecordID"] = "19"
    system["Security_attributes"] = {"UserID": "S-1-5-18"}
    system["Correlation_attributes"] = {"ActivityID": "activity", "RelatedActivityID": "related"}
    view = w.evtx_json_to_winlog(hit["_source"])
    winlog = view["winlog"]
    assert winlog["process"] == {"pid": 4, "thread": {"id": 68}}
    assert winlog["user"] == {"identifier": "S-1-5-18"}
    assert winlog["record_id"] == 19
    assert winlog["activity_id"] == "activity" and winlog["related_activity_id"] == "related"
    assert [winlog[key] for key in ("version", "level", "task", "opcode")] == [2, 0, 13312, 0]
    event = w.normalize_windows(hit)
    assert event.fields["event.provider"].origin == "raw-1:Event.System.Provider_attributes.Name"
    assert event.fields["event.created"].origin == "raw-1:Event.System.TimeCreated_attributes.SystemTime"


def test_pipeline_time_and_precise_native_time_are_retained_separately():
    hit = raw_hit()
    hit["_source"]["@timestamp"] = PIPELINE
    view = w.evtx_json_to_winlog(hit["_source"])
    assert view["@timestamp"] == PIPELINE and view["winlog"]["time_created"] == WHEN
    event = w.normalize_windows(hit)
    assert event.ts == datetime(2024, 3, 4, 12, 34, 56, 123456, tzinfo=UTC)
    assert event.get("event.ingested") == "2024-03-04T12:35:00+00:00"
    assert values(event) == values(w.normalize_windows(twin(hit)))


def test_no_timestamp_is_counted_as_error():
    hit = raw_hit()
    del hit["_source"]["Event"]["System"]["TimeCreated"]
    events, skips, errors = normalize_hits([hit])
    assert events == [] and skips == {} and len(errors) == 1
    assert "time" in errors[0][1].lower()


@pytest.mark.parametrize("data", [None, {}, {"Empty": "", "Null": None, "Number": "42", "Repeated": ["a", "b"],
                                           "Name_1": "first", "Name_2": "second", "Binary": "0102"}])
def test_event_data_values_remain_native_without_xml_fallback(data):
    hit = raw_hit()
    hit["_source"]["Event"]["EventData"] = data
    hit["_source"]["event"] = {"original": "<!DOCTYPE injected><bad>"}
    event = w.normalize_windows(hit)
    for name, value in (data or {}).items():
        assert event.get("windows.event_data." + name) == value
        assert event.fields["windows.event_data." + name].origin == "raw-1:Event.EventData." + name


@pytest.mark.parametrize("unnamed, expected", [("value", {"param1": "value"}),
                                             (["one", "two"], {"param1": "one", "param2": "two"})])
def test_unnamed_data_keeps_order(unnamed, expected):
    hit = raw_hit(data={"Data": unnamed})
    view = w.evtx_json_to_winlog(hit["_source"])
    assert view["winlog"]["event_data"] == expected
    event = w.normalize_windows(hit)
    for name, value in expected.items():
        assert event.get("windows.event_data." + name) == value
        assert event.fields["windows.event_data." + name].origin.startswith("raw-1:Event.EventData.Data")


def test_user_data_schema_and_text_are_retained_without_namespace_attributes():
    hit = raw_hit(event_id=1102, provider="Microsoft-Windows-Eventlog")
    event = hit["_source"]["Event"]
    del event["EventData"]
    event["UserData"] = {"LogFileCleared": {"#attributes": {"xmlns": "urn:example"},
                                          "SubjectUserName": "operator", "#text": "native text"}}
    view = w.evtx_json_to_winlog(hit["_source"])
    assert view["winlog"]["user_data"] == {
        "xml_name": "LogFileCleared", "SubjectUserName": "operator", "#text": "native text"}
    normalized = w.normalize_windows(hit)
    assert normalized.family == "audit_config"
    assert normalized.fields["windows.event_data.SubjectUserName"].origin == (
        "raw-1:Event.UserData.LogFileCleared.SubjectUserName")


@pytest.mark.parametrize("mask, names, outcome", [
    ("0x8020000000000000", ["Audit Success"], Outcome.success),
    ("0x8010000000000000", ["Audit Failure"], Outcome.failure),
    ("0x8030000000000000", ["Audit Failure", "Audit Success"], Outcome.unknown),
    ("0x8000000000000000", [], Outcome.success),
])
def test_keyword_mask_drives_the_existing_audit_outcome(mask, names, outcome):
    hit = raw_hit(event_id=4720, data={"TargetUserName": "new-user"})
    hit["_source"]["Event"]["System"]["Keywords"] = mask
    assert w.evtx_json_to_winlog(hit["_source"])["winlog"]["keywords"] == names
    assert w.normalize_windows(hit).outcome == outcome


@pytest.mark.parametrize("location", ["root", "event"])
def test_recovered_record_gets_a_caveat(location):
    hit = raw_hit()
    node = hit["_source"] if location == "root" else hit["_source"]["Event"]
    node["recovered"] = True
    assert "recovered from unallocated log space" in w.normalize_windows(hit).caveats


def test_rendering_message_is_optional_and_does_not_change_semantics():
    hit = raw_hit()
    expected = values(w.normalize_windows(hit))
    hit["_source"]["Event"]["RenderingInfo"] = {"Message": "Rendered process message"}
    assert w.evtx_json_to_winlog(hit["_source"])["message"] == "Rendered process message"
    assert values(w.normalize_windows(hit)) == expected


def test_adapter_never_mutates_source_and_keeps_logical_dedup_identity():
    hit = raw_hit()
    original = deepcopy(hit)
    assert w.windows_record_key(hit) == w.windows_record_key(twin(hit))
    first = w.normalize_windows(hit)
    second = w.normalize_windows({**hit, "_id": "other-copy"})
    assert first.id == second.id
    assert hit == original


@pytest.mark.parametrize("value, expected", [(42, "42"), (2**64 - 1, "18446744073709551615"),
                                           (True, "true"), (False, "false")])
def test_native_numeric_data_is_exact_xml_text_as_in_winlogbeat(value, expected):
    hit = raw_hit(data={"Value": value})
    before = deepcopy(hit)
    event = w.normalize_windows(hit)
    assert event.get("windows.event_data.Value") == expected
    assert event.fields["windows.event_data.Value"].origin == "raw-1:Event.EventData.Value"
    assert hit == before


def test_unnamed_text_array_and_named_complex_data_follow_xml_names():
    hit = raw_hit(data={"Data": {"#text": ["one", "two"]},
                       "ComplexData": {"#attributes": {"Name": "Parameters"}, "#text": "0102"}})
    event = w.normalize_windows(hit)
    assert event.get("windows.event_data.param1") == "one"
    assert event.get("windows.event_data.param2") == "two"
    assert event.get("windows.event_data.Parameters") == "0102"
    assert event.fields["windows.event_data.Parameters"].origin == "raw-1:Event.EventData.ComplexData.#text"


def test_native_rpc_null_channel_uses_only_the_existing_catalog_exception():
    hit = raw_hit(event_id=5, channel=None, provider="Microsoft-Windows-RPC", data={})
    assert w.is_evtx_json(hit["_source"])
    assert w.evtx_json_to_winlog(hit["_source"])["winlog"]["channel"] is None
    assert w.normalize_windows(hit).family == "rpc_call"
    hit["_source"]["Event"]["System"]["Provider"]["#attributes"]["Name"] = SECURITY
    with pytest.raises(w.WindowsNotNormalized):
        w.normalize_windows(hit)


@pytest.mark.parametrize("path, value", [("@timestamp", "2024-03-04T12:30:00"), ("@timestamp", None),
                                       ("@timestamp", True)])
def test_bad_pipeline_time_never_silently_falls_back_to_system_time(path, value):
    hit = raw_hit()
    hit["_source"][path] = value
    events, skips, errors = normalize_hits([hit])
    assert not events and not skips and len(errors) == 1


def test_conflicting_attribute_modes_are_counted_and_not_guessed():
    hit = raw_hit()
    hit["_source"]["Event"]["System"]["Provider_attributes"] = {"Name": "Other Provider"}
    events, skips, errors = normalize_hits([hit])
    assert not events and not skips and len(errors) == 1
    assert "conflicting attributes" in errors[0][1]


@pytest.mark.parametrize("element", ["Data", "ComplexData"])
def test_empty_named_element_cites_the_existing_container(element):
    event = w.normalize_windows(raw_hit(data={element: {"#attributes": {"Name": "Empty"}}}))
    assert event.get("windows.event_data.Empty") == ""
    assert event.fields["windows.event_data.Empty"].origin == f"raw-1:Event.EventData.{element}#empty-element"


@pytest.mark.parametrize("native, expected", [
    ("first\r\nsecond\r\n", "first\nsecond"),
    ("first\rsecond\r", "first\nsecond"),
    ("first\nsecond\n\n", "first\nsecond"),
    ("first \t\nsecond \t", "first \t\nsecond \t"),
])
def test_xml_and_winlogbeat_line_endings_are_applied_without_other_trimming(native, expected):
    hit = raw_hit(data={"CommandLine": native})
    before = deepcopy(hit)
    event = w.normalize_windows(hit)
    assert event.get("process.command_line") == expected
    assert event.get("windows.event_data.CommandLine") == expected
    assert event.fields["process.command_line"].origin == "raw-1:Event.EventData.CommandLine"
    assert hit == before


def test_newline_only_image_never_invents_a_current_directory_path():
    hit = raw_hit(event_id=10, channel="Microsoft-Windows-Sysmon/Operational",
                  provider="Microsoft-Windows-Sysmon", data={"SourceImage": "\r", "TargetImage": "target.exe"})
    event = w.normalize_windows(hit)
    assert event.get("source.executable") is None
    assert event.get("source.executable_key") is None
    assert event.get("windows.event_data.SourceImage") == ""


def test_user_data_scalar_text_uses_the_same_xml_line_endings():
    hit = raw_hit(event_id=1102, provider="Microsoft-Windows-Eventlog")
    hit["_source"]["Event"]["UserData"] = {"LogFileCleared": {"#text": "one\r\ntwo\n"}}
    assert w.evtx_json_to_winlog(hit["_source"])["winlog"]["user_data"]["#text"] == "one\ntwo"


def test_standard_keywords_use_winlogbeat_names_without_guessing_unknown_bits():
    hit = raw_hit()
    hit["_source"]["Event"]["System"]["Keywords"] = "0x00ff000000000001"
    assert w.evtx_json_to_winlog(hit["_source"])["winlog"]["keywords"] == [
        "Response Time", "WDI Diag", "SQM", "Audit Failure", "Audit Success", "Correlation Hint", "Classic"]


def test_native_zero_execution_pid_is_preserved_despite_winlogbeat_omitting_zero():
    hit = raw_hit()
    hit["_source"]["Event"]["System"]["Execution"]["#attributes"] = {"ProcessID": 0, "ThreadID": 0}
    assert w.evtx_json_to_winlog(hit["_source"])["winlog"]["process"] == {"pid": 0, "thread": {"id": 0}}


@pytest.mark.parametrize("control", ["\u009d", "\u0094\u0002"])
def test_native_command_control_character_is_not_replaced_with_escaped_text(control):
    hit = raw_hit(data={"CommandLine": "echo " + control})
    assert w.normalize_windows(hit).get("process.command_line") == "echo " + control


@pytest.mark.parametrize("flat", [False, True])
def test_optional_execution_metadata_remains_native(flat):
    hit = raw_hit()
    attrs = {"ProcessID": 4, "ThreadID": 68, "ProcessorID": "3", "SessionID": "5",
             "KernelTime": "17", "UserTime": "19", "ProcessorTime": "23"}
    system = hit["_source"]["Event"]["System"]
    if flat:
        del system["Execution"]
        system["Execution_attributes"] = attrs
    else:
        system["Execution"] = {"#attributes": attrs}
    view = w.evtx_json_to_winlog(hit["_source"])
    for name, value in {"processor_id": 3, "session_id": 5, "kernel_time": 17,
                        "user_time": 19, "processor_time": 23}.items():
        assert view["winlog"][name] == value
    assert values(w.normalize_windows(hit)) == values(w.normalize_windows(raw_hit()))
