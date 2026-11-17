"""What the agent is told it can search on: the hunt's typed vocabulary, its sources and their own fields.

The typed vocabulary is derived from the hunt's field contracts with the planner's own rules, so every listed field
and op plans on some target and an unlisted field is still refused. The listing tool's definition is fixed text, so
the tool definitions stay byte-identical across a hunt's sessions (and hunts), and a listing is bounded and paged
however wide the contracts are.
"""
from __future__ import annotations

import json
from dataclasses import asdict

import httpx
import pytest

from romulus.agent.admission import AgentAdmission
from romulus.agent.aliases import AliasBook
from romulus.agent.toolbox import SEARCH_FIELD_GROUPS, SEARCH_FIELDS_PAGE_SIZE, Toolbox
from romulus.agent.tools import SEARCH_OPS
from romulus.config import Settings
from romulus.hunt.pivot import PivotExecutor, search_ops, search_vocabulary
from romulus.hunt.run import arkime_profile_fields
from romulus.sources import packets as pk
from romulus.sources.profile import FieldContract, FieldSpec, contract_from_types
from tests.test_agent_search_events import (
    SESSION,
    FakeES,
    _hunt,
    _keyword_contract,
    _request,
    _toolbox,
    _windows_contract_and_record,
)

VALUES = {"eq": "10.0.0.5", "in": "10.0.0.5", "prefix": "abc", "cidr": "10.0.0.0/24", "gte": "5", "lt": "9"}


def _mixed_contract(target: str = "net-a") -> FieldContract:
    return contract_from_types(target, {
        "@timestamp": "date", "event.dataset": "keyword", "source.ip": "ip", "destination.port": "long",
        "event.duration": "double", "event.start": "date", "message": "text", "tls.established": "boolean",
        "url.original": "wildcard", "zeek.dns.@proc": "keyword", "a-b": "keyword", "caf\u00e9.name": "keyword",
        "network.community_id": "keyword:not_indexed",
    }, role="network")


def _typed(toolbox: Toolbox, **arguments) -> dict:
    return toolbox.execute("list_search_fields", arguments)


def _entries(result: dict) -> dict[str, dict]:
    return {item["field"]: item for item in result["data"]["entries"]}


# ---- the vocabulary is the planner's -----------------------------------------------------------------------------

def test_the_vocabulary_has_only_fields_a_search_can_name_with_their_ops_and_scope():
    vocabulary = {item["field"]: item for item in search_vocabulary({
        "net-a": _mixed_contract(), "host-a": _keyword_contract("host-a", role="host"), "gone": None})}
    # the time field, analyzed text, an unindexed field and names no condition can carry are left out
    for name in ("@timestamp", "message", "network.community_id", "zeek.dns.@proc", "a-b", "caf\u00e9.name"):
        assert name not in vocabulary, name
    assert vocabulary["source.ip"]["roles"] == {
        "host": {"targets": 1, "ops": {"eq": 1, "in": 1, "cidr": 1}},
        "network": {"targets": 1, "ops": {"eq": 1, "in": 1, "cidr": 1}}}
    assert vocabulary["destination.port"]["roles"]["network"]["ops"] == {"eq": 1, "in": 1, "gte": 1, "lt": 1}
    assert vocabulary["event.duration"]["roles"]["network"]["ops"] == {"gte": 1, "lt": 1}
    assert vocabulary["event.start"]["roles"] == {"network": {"targets": 1, "ops": {"gte": 1, "lt": 1}}}
    assert vocabulary["tls.established"]["roles"]["network"]["ops"] == {"eq": 1}
    assert vocabulary["url.original"]["roles"]["network"]["ops"] == {"eq": 1, "in": 1, "prefix": 1}
    assert list(vocabulary) == sorted(vocabulary)


def test_a_field_matched_by_a_special_form_is_listed_without_prefix():
    contract, _hit = _windows_contract_and_record()
    assert "prefix" not in search_ops(contract, "host.name")
    assert "prefix" not in search_ops(contract, "auth.target_account")
    assert set(search_ops(contract, "host.name")) >= {"eq", "in"}


def test_every_listed_field_and_op_plans_on_some_target_and_an_unlisted_one_is_refused():
    contracts = {"net-a": _mixed_contract(), "host-a": _keyword_contract("host-a", role="host")}
    windows, _hit = _windows_contract_and_record()
    contracts["win-a"] = windows
    executor = PivotExecutor(_hunt(), FakeES(), "h1", contracts)
    checked = 0
    for entry in search_vocabulary(contracts):
        name = entry["field"]
        for role, cell in entry["roles"].items():
            for op in cell["ops"]:
                spec = next(contract.fields[name] for contract in contracts.values()
                            if contract.role == role and name in contract.fields)
                base = spec.type.split(":", 1)[0]
                value = {"ip": VALUES[op], "date": "2024-11-18T14:05:00+00:00", "boolean": "true"}.get(
                    base, "5" if base in {"long", "integer", "short", "double", "float"} else
                    ("sid:S-1-5-18" if name in {"user.entity_id", "auth.target_account"} else "abcdef"))
                if op == "cidr":
                    value = VALUES["cidr"]
                conditions = [{"field": name, "op": op, "values": [value]}]
                if op in {"gte", "lt"}:
                    conditions.append({"field": "event.dataset", "op": "eq", "values": ["x.y"]})
                plan = executor.plan_search(_request(conditions, scope=role))
                field_problems = [cell.reasons[0] for cell in plan.coverage
                                  if f"field {name} / op {op}" in cell.reasons[0]
                                  and ("not supported" in cell.reasons[0] or "refused" in cell.reasons[0])]
                assert plan.intents and len(field_problems) < len(contracts), (name, op, role, plan.refusal)
                checked += 1
    assert checked > 50
    plan = executor.plan_search(_request([{"field": "file.path", "op": "eq", "values": ["C:\\x"]}], scope="all"))
    assert plan.refusal["reasons"] == ["conditions[].field: unsupported_field"]
    assert "list_search_fields" in plan.refusal["message"]
    assert "file.path" not in {item["field"] for item in search_vocabulary(contracts)}


def test_no_native_name_or_target_name_reaches_the_typed_listing():
    spec = FieldSpec(native="Event.EventData.Image", natives=("Event.EventData.Image", "winlog.event_data.Image"),
                     type="text", ops=["eq", "in", "exists", "missing"], aggregatable=False,
                     exact=("Event.EventData.Image.keyword",), exact_limit=256)
    contract = FieldContract(target="secret-index-name-2024", role="host", os_family="windows", fields={
        "@timestamp": FieldSpec(native="@ts_native", type="date", ops=["gte", "lt"], aggregatable=True),
        "process.executable": spec})
    repo = _hunt()
    toolbox = _toolbox(repo, {"secret-index-name-2024": contract}, FakeES())
    text = json.dumps(_typed(toolbox, scope="all"))
    assert "process.executable" in text
    for native in ("Event.EventData.Image", "winlog.event_data", ".keyword", "@ts_native", "secret-index-name"):
        assert native not in text, native


# ---- the listing tool --------------------------------------------------------------------------------------------

def test_the_listing_gives_typed_fields_by_scope_with_how_many_sources_take_each_op():
    repo = _hunt()
    toolbox = _toolbox(repo, {"net-a": _mixed_contract(), "net-b": _keyword_contract("net-b"),
                              "host-a": _keyword_contract("host-a", role="host")}, FakeES(),
                       packet_sources=("packets behind net-a",))
    network = _typed(toolbox, scope="network")
    assert network["status"] == "complete" and network["more"] is False
    data = network["data"]
    assert data["sources_in_scope"] == 2 and data["not_searchable_by_typed_fields"]["packet_capture_sources"] == 1
    entries = _entries(network)
    assert entries["destination.ip"] == {"field": "destination.ip", "scopes": ["network"], "targets": 1,
                                         "ops": {"eq": 1, "in": 1, "cidr": 1}}
    assert entries["source.ip"]["targets"] == 2 and entries["source.ip"]["ops"]["cidr"] == 2
    every = _entries(_typed(toolbox, scope="all"))
    assert every["source.ip"]["scopes"] == ["host", "network"] and every["source.ip"]["targets"] == 3
    host = _entries(_typed(toolbox, scope="host"))
    assert "url.original" not in host and "url.original" in every
    narrowed = _typed(toolbox, scope="all", prefix="destination.")
    assert set(_entries(narrowed)) == {"destination.ip", "destination.port"}
    empty = _typed(toolbox, prefix="nothing.")
    assert empty["counts"] == {"returned": 0, "total": 0} and "complete" in empty["data"]["statement"]
    assert all(op in SEARCH_OPS for item in every.values() for op in item["ops"])


def test_a_large_vocabulary_is_paged_and_counted_by_group_never_cut_silently():
    names = {f"ns{n % 120:03d}.sub.f{n}": "keyword" for n in range(5_000)}
    contract = contract_from_types("net-a", {"@timestamp": "date", **names}, role="network")
    repo = _hunt()
    toolbox = _toolbox(repo, {"net-a": contract}, FakeES())
    first = _typed(toolbox)
    data = first["data"]
    assert first["counts"] == {"returned": SEARCH_FIELDS_PAGE_SIZE, "total": 5_000} and first["more"] is True
    assert data["pages"] == 50 and data["next"] == "list_search_fields listing=typed_fields scope=all page=2"
    assert len(data["groups"]) == SEARCH_FIELD_GROUPS and data["groups_omitted"] == 120 - SEARCH_FIELD_GROUPS
    assert sum(group["entries"] for group in data["groups"]) < 5_000
    assert len(json.dumps(first)) < 20_000
    seen = []
    for page in range(1, 51):
        seen += [item["field"] for item in _typed(toolbox, page=page)["data"]["entries"]]
    assert sorted(seen) == sorted(names) and len(seen) == len(set(seen))
    last = _typed(toolbox, page=50)
    assert last["more"] is False and last["data"]["next"] is None
    assert _typed(toolbox, page=51)["data"]["error"]["code"] == "page_out_of_range"
    narrowed = _typed(toolbox, prefix="ns007.")
    assert narrowed["counts"]["total"] == len([name for name in names if name.startswith("ns007.")])
    assert narrowed["data"]["pages"] == 1 and "groups" not in narrowed["data"]


def test_sources_and_their_native_fields_with_type_kind_and_index_limit():
    repo = _hunt()
    contract = contract_from_types("win-a", {
        "@timestamp": "date", "winlog.event_data.CommandLine": "text",
        "winlog.event_data.CommandLine.keyword": "keyword", "host.name": "keyword",
        "event.original": "keyword:not_indexed"}, role="host", os_family="linux",
        index_limits={"winlog.event_data.CommandLine.keyword": 1024, "host.name": None})
    arkime = contract_from_types("arkime_sessions3-241118", {
        "firstPacket": "date", "lastPacket": "date", "network.community_id": "keyword", "source.ip": "ip",
        "destination.port": "long"}, role="network")
    assert arkime.time_field == "firstPacket"
    repo.save_profile("h1", {"id": "p1", "target": "win-a", "kind": "es", "field_types": {
        "@timestamp": "date", "winlog.event_data.CommandLine": "text",
        "winlog.event_data.CommandLine.keyword": "keyword", "host.name": "keyword",
        "event.original": "keyword:not_indexed", "labels.raw": "flattened"}})
    repo.save_profile("h1", {"id": "p2", "target": "arkime_sessions3-241118", "kind": "es",
                             "field_types": {"firstPacket": "date"},
                             "arkime_fields": [{"field": "ip.src", "type": "ip", "group": "general",
                                                "db_field": "source.ip"}]})
    toolbox = _toolbox(repo, {"win-a": contract, "arkime_sessions3-241118": arkime}, FakeES())
    sources = {item["source"]: item for item in _typed(toolbox, listing="sources")["data"]["entries"]}
    assert set(sources) == {"win-a", "arkime_sessions3-241118", "arkime:arkime_sessions3-241118"}
    assert sources["arkime:arkime_sessions3-241118"]["kind"] == "arkime_viewer"
    assert sources["win-a"] == {"source": "win-a", "kind": "index", "role": "host", "time_field": "@timestamp",
                                "fields": 6}
    host_only = _typed(toolbox, listing="sources", scope="host")["data"]["entries"]
    assert [item["source"] for item in host_only] == ["win-a"]
    native = _entries(_typed(toolbox, listing="native_fields", source="win-a"))
    assert native["winlog.event_data.CommandLine"]["kind"] == "text"
    assert "ignore_above" not in native["winlog.event_data.CommandLine"]
    assert native["winlog.event_data.CommandLine.keyword"]["ignore_above"] == 1024
    assert native["host.name"]["ignore_above"] == "none" and native["host.name"]["kind"] == "keyword"
    assert native["labels.raw"]["ignore_above"] == "none"
    assert native["event.original"]["indexed"] is False and native["event.original"]["aggregatable"] is False
    viewer = _typed(toolbox, listing="native_fields", source="arkime:arkime_sessions3-241118")
    assert _entries(viewer)["ip.src"]["db_field"] == "source.ip"
    refused = _typed(toolbox, listing="native_fields", source="arkime:win-a")
    assert refused["status"] == "refused" and refused["data"]["error"]["code"] == "unknown_source"
    assert _typed(toolbox, listing="native_fields", source="other-index")["data"]["error"]["code"] == "unknown_source"


def test_an_index_without_a_viewer_field_list_says_why():
    repo = _hunt()
    arkime = contract_from_types("arkime_sessions3-1", {"firstPacket": "date", "lastPacket": "date",
                                                        "network.community_id": "keyword", "source.ip": "ip"},
                                 role="network")
    toolbox = _toolbox(repo, {"arkime_sessions3-1": arkime}, FakeES())
    viewer = _typed(toolbox, listing="native_fields", source="arkime:arkime_sessions3-1")
    assert viewer["counts"]["total"] == 0 and "not profiled" in viewer["data"]["note"]
    # without a stored profile the index's own fields come from its contract
    assert set(_entries(_typed(toolbox, listing="native_fields", source="arkime_sessions3-1"))) == {
        "firstPacket", "lastPacket", "network.community_id", "source.ip"}


def test_without_a_hunt_layer_the_listing_is_unsupported_and_arguments_are_validated():
    toolbox = Toolbox(_hunt(), "h1")
    assert _typed(toolbox)["status"] == "unsupported"
    refused = _typed(toolbox, listing="native_fields")
    assert refused["status"] == "refused" and refused["data"]["error"]["code"] == "invalid_arguments"


# ---- caching -----------------------------------------------------------------------------------------------------

def _definitions(toolbox: Toolbox, tmp_path, session: str) -> str:
    AgentAdmission(Settings(home=tmp_path), toolbox.repo, "h1", session).register(toolbox)
    return json.dumps([asdict(tool) for tool in toolbox.provider_tools()], sort_keys=True)


def test_tool_definitions_are_byte_identical_across_sessions_and_hunts(tmp_path):
    repo = _hunt()
    one = _definitions(_toolbox(repo, {"net-a": _mixed_contract()}, FakeES()), tmp_path, SESSION)
    two = _definitions(Toolbox(repo, "h1", executor=_toolbox(repo, {"net-a": _mixed_contract()}, FakeES()).executor,
                               session_id="as-other"), tmp_path, "as-other")
    names = {f"ns{n}.f{n}": "keyword" for n in range(3_000)}
    wide = contract_from_types("net-z", {"@timestamp": "date", **names}, role="network")
    other_hunt = _definitions(_toolbox(_hunt(), {"net-z": wide}, FakeES()), tmp_path, SESSION)
    without_executor = _definitions(Toolbox(repo, "h1"), tmp_path, SESSION)
    assert one == two == other_hunt == without_executor
    assert "list_search_fields" in one and "ns1.f1" not in one


# ---- the viewer's expression fields, read when a hunt is profiled ------------------------------------------------

def _viewer(**extra) -> Settings:
    return Settings(arkime_url="http://viewer.invalid:8005", arkime_username="hunter", **extra)


def test_the_field_list_endpoint_is_allowlisted_read_only():
    pk.check_arkime_endpoint("GET", "/api/fields")
    for method, path in (("POST", "/api/fields"), ("GET", "/api/fields/../user"), ("GET", "/api/user")):
        with pytest.raises(pk.PacketError):
            pk.check_arkime_endpoint(method, path)


def test_the_viewer_field_list_is_read_bounded_and_sorted():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path, dict(request.url.params)))
        return httpx.Response(200, json=[
            {"exp": "port.dst", "type": "integer", "group": "general", "dbField": "destination.port"},
            {"exp": "ip.src", "type": "ip", "group": "general", "dbField": "source.ip", "help": "x" * 900},
            {"exp": "bad name;drop", "type": "termfield"}, {"friendlyName": "no expression"}, "junk",
        ])

    fields, note = pk.arkime_expression_fields(_viewer(), transport=httpx.MockTransport(handler))
    assert seen == [("GET", "/api/fields", {"array": "true"})]
    assert [item["field"] for item in fields] == ["ip.src", "port.dst"]
    assert fields[0] == {"field": "ip.src", "type": "ip", "group": "general", "db_field": "source.ip"}
    assert note == "3 Arkime field entries without a usable expression name were left out"


def test_the_viewer_field_list_in_its_keyed_form_and_its_failures():
    keyed = httpx.MockTransport(lambda request: httpx.Response(200, json={"tls.ja3": {"type": "termfield"}}))
    fields, note = pk.arkime_expression_fields(_viewer(), transport=keyed)
    assert fields == [{"field": "tls.ja3", "type": "termfield", "group": None, "db_field": None}] and note is None
    for response in (httpx.Response(401), httpx.Response(200, text="<html>"), httpx.Response(200, json=7)):
        fields, note = pk.arkime_expression_fields(
            _viewer(), transport=httpx.MockTransport(lambda request, response=response: response))
        assert fields == [] and note.startswith("Arkime expression fields unavailable")


def test_the_profile_takes_the_viewer_fields_only_for_arkime_targets_and_a_failed_read_never_stops_it(monkeypatch):
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json=[{"exp": "ip.dst", "type": "ip"}]))
    assert arkime_profile_fields(_viewer(), [], transport=transport) == {}

    def broken(*_args, **_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr("romulus.hunt.run.arkime_expression_fields", broken)
    failed = arkime_profile_fields(_viewer(), ["arkime_sessions3-1"], transport=transport)
    assert failed["arkime_sessions3-1"] == {
        "arkime_fields": [], "arkime_fields_note": "Arkime expression fields unavailable: the read failed (RuntimeError)"}
    monkeypatch.undo()
    added = arkime_profile_fields(_viewer(), ["arkime_sessions3-1"], transport=transport)
    assert added["arkime_sessions3-1"]["arkime_fields"][0]["field"] == "ip.dst"
    assert "arkime_fields_note" not in added["arkime_sessions3-1"]
    down = arkime_profile_fields(_viewer(), ["a"], transport=httpx.MockTransport(lambda request: httpx.Response(503)))
    assert down["a"]["arkime_fields"] == [] and "HTTP 503" in down["a"]["arkime_fields_note"]


def test_the_session_tools_reach_the_listing_through_the_hunt_executor():
    repo = _hunt()
    toolbox = _toolbox(repo, {"net-a": _keyword_contract("net-a")}, FakeES())
    anchor = AliasBook(repo, "h1").alias_for("F", "anchor")
    listed = _entries(_typed(toolbox, scope="network"))
    response = toolbox.execute("search_events", {"anchor": anchor, "scope": "network", "conditions": [
        {"field": "dns.question.name", "op": "eq", "values": ["example.test"]}]})
    assert "dns.question.name" in listed and response["status"] in {"complete", "partial"}
