"""Synthetic EVTX JSON mappings follow https://github.com/omerbenamram/evtx.

Keyword multifields and paged inventories follow Elasticsearch's public reference:
https://www.elastic.co/guide/en/elasticsearch/reference/8.19/multi-fields.html
https://www.elastic.co/guide/en/elasticsearch/reference/8.19/search-aggregations-bucket-composite-aggregation.html
"""
from datetime import UTC, datetime

import pytest

from romulus.doctor import check_linux_text_sources
from romulus.hunt import sweep as sweep_module
from romulus.hunt.pivot import _windows_source_groups
from romulus.hunt.sweep import Sweep
from romulus.sources.compile import _pred, compile_es
from romulus.sources.models import Completeness, Predicate, SearchIntent, SearchOutcome, Window
from romulus.sources.profile import (
    build_profile,
    contract_from_types,
    flatten_mapping,
    keyword_subfield_limits,
)
from tests.test_sweep import _repo
from tests.zeek_source_support import matches

WINDOW = Window(start=datetime(2026, 1, 1, tzinfo=UTC), end=datetime(2026, 1, 2, tzinfo=UTC))


def types(*, flat=False, dynamic=False, object_id=False, pipeline_time=True):
    attrs = "_attributes" if flat else ".#attributes"
    fields = {
        "Event.System.Channel": "keyword", "Event.System.Computer": "keyword",
        f"Event.System.Provider{attrs}.Name": "keyword", "Event.System.EventRecordID": "long",
        f"Event.System.TimeCreated{attrs}.SystemTime": "date",
        "Event.EventData.CommandLine": "keyword", "Event.EventData.NewProcessName": "keyword",
        "Event.EventData.SubjectUserName": "keyword", "Event.EventData.SubjectUserSid": "keyword",
    }
    fields["Event.System.EventID.#text" if object_id else "Event.System.EventID"] = "long"
    if pipeline_time:
        fields["@timestamp"] = "date"
    if dynamic:
        for name, kind in list(fields.items()):
            if kind == "keyword":
                fields[name] = "text"
                fields[name + ".keyword"] = "keyword"
    return fields


def mapping(fields):
    properties = {}
    for name, kind in fields.items():
        if name.endswith(".keyword") and fields.get(name.removesuffix(".keyword")) == "text":
            continue
        properties[name] = {"type": kind}
        if kind == "text" and fields.get(name + ".keyword") == "keyword":
            properties[name]["fields"] = {"keyword": {"type": "keyword", "ignore_above": 256}}
    return {"raw": {"mappings": {"properties": properties}}}


def contract(**options):
    fields = types(**options)
    return contract_from_types("raw", fields, keyword_limits=keyword_subfield_limits(mapping(fields)))


@pytest.mark.parametrize("flat", [False, True])
@pytest.mark.parametrize("dynamic", [False, True])
def test_raw_evtx_aliases_compile_native_queries_and_aggregate_exact_fields(flat, dynamic):
    current = contract(flat=flat, dynamic=dynamic)
    attrs = "_attributes" if flat else ".#attributes"
    suffix = ".keyword" if dynamic else ""
    assert current.role == "host" and current.os_family == "windows"
    assert current.fields["process.command_line"].natives == ("Event.EventData.CommandLine",)
    assert current.fields["winlog.record_id"].native == "Event.System.EventRecordID"
    host_query = _pred(Predicate(field="host.name", op="eq", value="ws01.example.test"), current)
    assert host_query["bool"]["should"][0] == {
        "wildcard": {"Event.System.Computer" + suffix: {"value": "ws01", "case_insensitive": True}}}
    query = compile_es(SearchIntent(kind="aggregate", target="raw", window=WINDOW,
        filters=[Predicate(field="event.provider", op="eq", value="Microsoft-Windows-Security-Auditing")],
        group_by=["event.channel", "event.provider", "event.code"]), current).body
    assert query["query"]["bool"]["filter"][-1] == {
        "wildcard": {f"Event.System.Provider{attrs}.Name{suffix}": {
            "value": "Microsoft-Windows-Security-Auditing", "case_insensitive": True}}}
    assert [next(iter(item.values()))["terms"]["field"] for item in query["aggs"]["g"]["composite"]["sources"]] == [
        "Event.System.Channel" + suffix, f"Event.System.Provider{attrs}.Name{suffix}", "Event.System.EventID"]


def test_raw_evtx_time_without_pipeline_timestamp_uses_native_system_time():
    current = contract(pipeline_time=False)
    assert current.time_field == "Event.System.TimeCreated.#attributes.SystemTime"
    body = compile_es(SearchIntent(kind="raw", target="raw", window=WINDOW), current).body
    assert current.time_field in body["query"]["bool"]["filter"][0]["range"]


class ProfileClient:
    settings = type("Settings", (), {"es_flavor": "elasticsearch"})()
    version = "8.19.0"

    def __init__(self, *, flat=False, dynamic=True):
        self.fields = types(flat=flat, dynamic=dynamic)
        self.bodies = []

    def mapping(self, target):
        return mapping(self.fields)

    def resolve(self, pattern):
        return ["raw"]

    def search(self, target, body):
        self.bodies.append(body)
        hosts = body.get("aggs", {}).get("hosts", {}).get("composite", {})
        after = hosts.get("after")
        page = {"buckets": [{"key": {"host": "ws02.example.test" if after else "ws01.example.test"},
                              "doc_count": 1 if after else 2}]}
        if not after:
            page["after_key"] = {"host": "ws01.example.test"}
        return {"hits": {"total": {"value": 3, "relation": "eq"}},
                "aggregations": {"hosts": page, "ds": {"buckets": []},
                    "tmin": {"value_as_string": "2026-01-01T01:00:00Z"},
                    "tmax": {"value_as_string": "2026-01-01T02:00:00Z"}}}


@pytest.mark.parametrize("flat", [False, True])
def test_profile_pages_raw_evtx_computer_keyword_and_doctor_names_shape(flat):
    client = ProfileClient(flat=flat)
    profile, current = build_profile(client, "raw")
    assert profile.os_family == current.os_family == "windows"
    assert profile.hosts == {"ws01.example.test": 2, "ws02.example.test": 1}
    host_queries = [body for body in client.bodies if "hosts" in body.get("aggs", {})]
    assert len(host_queries) == 2
    for body in host_queries:
        assert body["aggs"]["hosts"]["composite"]["sources"] == [
            {"host": {"terms": {"field": "Event.System.Computer.keyword"}}}]
    settings = type("Settings", (), {"es_index_patterns": ["raw"], "home": None})()
    checks = check_linux_text_sources(settings, ProfileClient(flat=flat))
    windows = [check for check in checks if check.name == "es.windows_inventory[raw]"]
    assert len(windows) == 1 and windows[0].status == "ok"
    assert ("evtx_json_flat" if flat else "evtx_json") in windows[0].detail
    assert "3" in windows[0].detail


def test_object_event_id_inventory_is_unavailable_instead_of_guessing_a_scalar(tmp_path):
    current = contract(object_id=True)
    repo = _repo()
    sweep = Sweep(repo, None, "h1", WINDOW, {"raw": current}, stage_dir=tmp_path)
    try:
        sweep._prepare_windows_inventory("raw", current)
        assert sweep._windows_inventory_reasons["raw"] == [
            "event class inventory unavailable: channel/provider/event id fields are not searchable"]
    finally:
        sweep.close_stage()
        repo.engine.dispose()


def test_real_sweep_class_inventory_compiles_raw_keyword_aliases(tmp_path, monkeypatch):
    current = contract(dynamic=True)
    seen = []

    def execute(_client, intent, active):
        seen.append(compile_es(intent, active).body)
        return SearchOutcome(target=intent.target, fingerprint="class", started_at=WINDOW.start,
            ended_at=WINDOW.start, completeness=Completeness.complete,
            buckets=[{"key": {"event.channel": "Security", "event.provider": "Microsoft-Windows-Security-Auditing",
                                "event.code": 4688}, "count": 3}])

    monkeypatch.setattr(sweep_module, "execute", execute)
    repo = _repo()
    sweep = Sweep(repo, None, "h1", WINDOW, {"raw": current}, stage_dir=tmp_path)
    try:
        sweep._prepare_windows_inventory("raw", current)
        assert seen and not sweep._windows_inventory_reasons["raw"]
        assert sum(sweep.stats["windows_inventory"]["raw"]["counts"].values()) == 3
    finally:
        sweep.close_stage()
        repo.engine.dispose()


def test_raw_shape_is_retrieved_when_an_object_event_id_prevents_class_filtering(tmp_path):
    current = contract(object_id=True)
    repo = _repo()
    sweep = Sweep(repo, None, "h1", WINDOW, {"raw": current}, stage_dir=tmp_path)
    try:
        sweep.pack = []
        raw = {"@timestamp": "2026-01-01T01:00:00Z", "Event": {"System": {
            "Channel": "security", "Computer": "WS01", "EventID": {"#text": 7036},
            "Provider": {"#attributes": {"Name": "Service Control Manager"}}}}}
        for groups in (sweep._any_of_for("raw", current), _windows_source_groups(current)):
            query = compile_es(SearchIntent(kind="raw", target="raw", window=WINDOW, any_of=groups), current).body
            assert matches(query["query"], raw)
            assert not matches(query["query"], {"@timestamp": raw["@timestamp"], "Event": {"name": "app"}})
    finally:
        sweep.close_stage()
        repo.engine.dispose()


@pytest.mark.parametrize("other", [{"type": "keyword"}, {"properties": {"#text": {"type": "long"}}}])
def test_conflicting_event_id_mappings_never_advertise_an_aggregate(other):
    raw = mapping(types())
    raw["second"] = {"mappings": {"properties": {"Event.System.EventID": other}}}
    flattened = flatten_mapping(raw)
    current = contract_from_types("raw", flattened)
    assert not current.fields["event.code"].aggregatable


def test_failed_shape_count_is_named_unknown_in_doctor():
    class Incomplete(ProfileClient):
        def search(self, target, body):
            result = super().search(target, body)
            if "aggs" not in body:
                result["timed_out"] = True
            return result

    settings = type("Settings", (), {"es_index_patterns": ["raw"], "home": None})()
    checks = check_linux_text_sources(settings, Incomplete())
    [windows] = [check for check in checks if check.name == "es.windows_inventory[raw]"]
    assert windows.status == "warn" and "unknown" in windows.detail
    assert windows.data["evtx_json"]["records"] is None


@pytest.mark.parametrize("channel_mapped", [False, True])
def test_native_null_channel_rpc_is_selected_and_counted(channel_mapped, tmp_path):
    raw = {"@timestamp": "2026-01-01T01:00:00Z", "Event": {"System": {
        "Channel": None, "Computer": "WS01", "EventID": 5,
        "Provider": {"#attributes": {"Name": "Microsoft-Windows-RPC"}}}}}

    class NullChannelClient(ProfileClient):
        def __init__(self):
            super().__init__(dynamic=False)
            if not channel_mapped:
                self.fields.pop("Event.System.Channel")

        def search(self, target, body):
            if "aggs" not in body:
                return {"hits": {"total": {"value": int(matches(body["query"], raw)), "relation": "eq"}}}
            return super().search(target, body)

    profile, current = build_profile(NullChannelClient(), "raw")
    assert profile.os_family == "windows"
    assert profile.model_dump()["windows_shapes"]["evtx_json"]["records"] == 1
    repo = _repo()
    sweep = Sweep(repo, None, "h1", WINDOW, {"raw": current}, stage_dir=tmp_path)
    try:
        sweep.pack = []
        for groups in (sweep._any_of_for("raw", current), _windows_source_groups(current)):
            body = compile_es(SearchIntent(kind="raw", target="raw", window=WINDOW, any_of=groups), current).body
            assert matches(body["query"], raw)
    finally:
        sweep.close_stage()
        repo.engine.dispose()
