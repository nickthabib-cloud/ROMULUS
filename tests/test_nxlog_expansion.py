"""Deterministic expansion over NXLog's flat Windows records gets the links Winlogbeat's records get.

The intrusion (tests.nxlog_expansion_fixture) is swept and expanded end to end over the in-memory Elasticsearch in
each shipper layout. NXLog's records are mapped three ways: by an index template (keyword fields), by Elasticsearch's
dynamic mapping (a text field with a `.keyword` subfield for every string, what JSON shipped without a template gets),
and as text alone. A Windows alias whose natives are text reads their keyword subfields for equality, so the first
two pivot exactly like Winlogbeat; the third cannot, and every link says which field it could not search.
"""
from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime, timedelta

import pytest

from romulus.evidence.typed import RawRef, TypedEvent, fv
from romulus.hunt.links import NXLOG_MIXED_LINK_REASON, LinkAnchor, LinkFetcher, LinkWindow
from romulus.hunt.pivot import PivotExecutor
from romulus.sources.compile import _pred, build_query, utf16_length
from romulus.sources.models import Predicate, SearchIntent, Window
from romulus.sources.profile import (
    build_profile,
    contract_from_types,
    flatten_mapping,
    keyword_subfield_limits,
)
from tests import nxlog_expansion_fixture as fx

_RUNS: dict = {}


def _run(layout: str, mapping: str = "keyword"):
    """One sweep and expansion per layout and mapping for the whole module (each takes a few seconds)."""
    if (layout, mapping) not in _RUNS:
        _RUNS[(layout, mapping)] = fx.run(layout, mapping=mapping)
    return _RUNS[(layout, mapping)]


def _logical(repo, ids) -> list[tuple]:
    """The linked records by their identity in the event log (channel, record number), whatever the layout."""
    rows = repo.citation_events("h1", list(ids))
    events = [TypedEvent.model_validate(row["event"]) for row in rows]
    return sorted((str(event.get("event.channel")), int(event.get("winlog.record_id"))) for event in events)


def _links(repo) -> list[tuple]:
    """Each link with what it reached: type, window, status, the linked records and the reasons."""
    return sorted((link["link_type"], link["window_label"], link["status"], tuple(_logical(repo, link["event_ids"])),
                   tuple(sorted(link["reasons"]))) for link in repo.expansion_links("h1"))


def _anchors(repo) -> list[tuple]:
    return sorted((row["lane"], row["status"], tuple(sorted(row["reasons"]))) for row in repo.expansion_anchors("h1"))


@pytest.mark.parametrize("mapping", ["keyword", "dynamic"])
def test_nxlog_records_get_the_links_and_source_queries_winlogbeat_records_get(mapping):
    wlb_repo, wlb_summary, wlb_searches = _run("winlogbeat")
    nx_repo, nx_summary, nx_searches = _run("nxlog", mapping)
    # the sweep raises the same high finding in both layouts, so both expand the same anchor
    assert [row["lane"] for row in wlb_repo.expansion_anchors("h1")] == ["high"]
    assert _anchors(nx_repo) == _anchors(wlb_repo)
    # expansion queries the source as often, and every link reaches the same records with the same status
    assert wlb_summary["source_queries"] > 0
    assert nx_summary["source_queries"] == wlb_summary["source_queries"]
    assert sum(nx_searches["expansion"].values()) == sum(wlb_searches["expansion"].values())
    assert _links(nx_repo) == _links(wlb_repo)
    reached = {link[0]: link[3] for link in _links(nx_repo) if link[1] == "anchor ±5 min"}
    assert reached["process_session"] == (("Security", 5001),)          # the network logon of the dumper's session
    assert reached["host_after_anchor"] == (("Microsoft-Windows-Sysmon/Operational", 6002),
                                            ("Microsoft-Windows-Sysmon/Operational", 6003),
                                            ("Security", 5002))
    # the context finding expansion builds on the session link is the same too
    rules = sorted(row["rule_id"] for row in nx_repo.candidates("h1"))
    assert rules == sorted(row["rule_id"] for row in wlb_repo.candidates("h1"))
    assert "win.process_session_link" in rules


def test_records_split_across_a_winlogbeat_and_an_nxlog_target_are_linked_through_both():
    wlb_repo, _summary, _searches = _run("winlogbeat")
    repo, _summary, searches = _run("split", "dynamic")
    assert set(searches["expansion"]) == {fx.WINLOGBEAT_TARGET, fx.NXLOG_TARGET}
    # the same records are reached as when one Winlogbeat target held them all
    assert [link[:4] for link in _links(repo)] == [link[:4] for link in _links(wlb_repo)]
    session = [link for link in _links(repo) if link[0] == "process_session"]
    assert session and all(link[3] == (("Security", 5001),) for link in session)   # the logon is NXLog's record


def test_a_field_a_target_cannot_search_leaves_its_links_unresolved_with_that_reason():
    repo, summary, searches = _run("nxlog", "text")
    assert summary["anchors"] == 1 and not searches["expansion"]
    host_field = (f"pivot_field_unsearchable:host.name:{fx.NXLOG_TARGET} maps Hostname as text with no "
                  "exact-searchable form, so its records cannot be selected by host.name")
    links = {(link["link_type"], link["window_label"]): link for link in repo.expansion_links("h1")}
    for link_type in ("process_lineage", "process_session", "process_activity", "host_after_anchor"):
        link = links[(link_type, "anchor ±5 min")]
        # never complete and never a link without matches: the target's window is unresolved, and says why
        assert link["status"] == "partial" and host_field in link["reasons"], link_type
        cells = [cell for cell in link["coverage"] if cell["target"] == fx.NXLOG_TARGET]
        assert cells and all(cell["unresolved_ranges"] for cell in cells)
    assert any(f"pivot_field_unsearchable:process.guid:{fx.NXLOG_TARGET}" in reason
               for reason in links[("process_activity", "anchor ±5 min")]["reasons"])
    # the link's own reason for planning nothing stays beside the target's
    for link_type in ("process_activity", "host_after_anchor"):
        assert "key not pushable; full-dataset scan refused" in links[(link_type, "anchor ±5 min")]["reasons"]
    [anchor] = repo.expansion_anchors("h1")
    assert anchor["status"] == "expanded_partial" and host_field in anchor["reasons"]


# ---- planning across mixed targets -------------------------------------------------------------------------------

START = fx.T0
WINDOW = LinkWindow(label="anchor ±5 min", start=START - timedelta(minutes=5), end=START + timedelta(minutes=5))
LINUX_TYPES = {"@timestamp": "date", "event.dataset": "keyword", "event.module": "keyword", "host.name": "keyword",
               "source.ip": "ip", "destination.ip": "ip", "process.pid": "long", "process.executable": "keyword",
               "user.name": "keyword", "auditd.data.syscall": "keyword", "message": "text"}


def _nxlog_contract(mapping="dynamic", ignore_above: int | None = 256):
    return fx.nxlog_contract(fx.nxlog_docs(), mapping=mapping, ignore_above=ignore_above)


def _event(event_id: str, os_family: str, **fields) -> TypedEvent:
    return TypedEvent(
        id=event_id, family="auth", ts=START, host="web01" if os_family == "linux" else "ws01",
        fields={"host.os.family": fv(os_family, f"{event_id}:os"),
                **{name.replace("__", "."): fv(value, f"{event_id}:{name}") for name, value in fields.items()}},
        raw=[RawRef(target="t", native_id=event_id, digest="d")],
        normalizer="linux-ecs@1" if os_family == "linux" else "windows-ecs@3",
    )


def _plan(contracts, root: TypedEvent, link_type: str):
    fetcher = LinkFetcher(PivotExecutor(None, None, "h1", contracts), WINDOW.start, WINDOW.end)
    anchor = LinkAnchor(finding_id="f1", ts=root.ts, host=root.host, event_ids=[root.id], events=[root])
    _key, _strength, intents, _retain, _select, reason, coverage = fetcher._plan(anchor, link_type, WINDOW)
    return intents, reason, coverage


def test_a_linux_anchors_address_link_searches_the_nxlog_target_by_its_native_names():
    contracts = {"linux": contract_from_types("linux", LINUX_TYPES), fx.NXLOG_TARGET: _nxlog_contract()}
    assert contracts["linux"].os_family == "linux" and contracts[fx.NXLOG_TARGET].os_family == "windows"
    intents, reason, _coverage = _plan(contracts, _event("ssh", "linux", source__ip="10.20.0.7"), "source_ip")
    assert reason is None and {intent.target for intent in intents} == {"linux", fx.NXLOG_TARGET}
    [windows] = [intent for intent in intents if intent.target == fx.NXLOG_TARGET]
    query = build_query(windows, contracts[fx.NXLOG_TARGET])
    text = str(query)
    assert "'SourceIp.keyword': '10.20.0.7'" in text and "'IpAddress.keyword': '10.20.0.7'" in text


def test_a_windows_anchors_host_link_selects_only_the_windows_target_beside_a_linux_one():
    contracts = {"linux": contract_from_types("linux", LINUX_TYPES), fx.NXLOG_TARGET: _nxlog_contract()}
    root = _event("logon", "windows", process__guid="{00000000-0000-0000-0000-0000000000a3}")
    intents, reason, coverage = _plan(contracts, root, "host_after_anchor")
    assert reason is None and coverage == [] and [intent.target for intent in intents] == [fx.NXLOG_TARGET]
    host = build_query(intents[0], contracts[fx.NXLOG_TARGET])["bool"]["filter"][1]
    assert host["bool"]["should"][0] == {"wildcard": {"Hostname.keyword": {"value": "ws01",
                                                                           "case_insensitive": True}}}


def test_nxlog_records_on_a_linux_target_are_named_unresolved_for_windows_links():
    mixed_types = {**LINUX_TYPES, **fx.nxlog_types(fx.nxlog_docs(), mapping="dynamic")}
    mixed = contract_from_types("mixed", mixed_types)
    assert mixed.os_family == "linux" and mixed.nxlog_mixed
    root = _event("logon", "windows", process__guid="{00000000-0000-0000-0000-0000000000a3}")
    for link_type in ("host_after_anchor", "process_activity"):
        intents, reason, coverage = _plan({"mixed": mixed}, root, link_type)
        assert intents == [] and reason is None, link_type
        assert [cell.reasons for cell in coverage] == [
            [NXLOG_MIXED_LINK_REASON, "key not pushable; full-dataset scan refused"]]


def test_winlogbeat_records_a_text_mapped_target_cannot_select_are_named_unresolved():
    """Template-less Winlogbeat and NXLog records in one index, every string text with a keyword subfield: only
    NXLog's flat shape can be selected there, so Winlogbeat's records are named, never silently left out."""
    docs = fx.nxlog_docs()
    raw = fx.nxlog_mapping(docs, mapping="dynamic")
    keyword = {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}}
    raw[fx.NXLOG_TARGET]["mappings"]["properties"]["winlog"] = {"properties": {
        name: keyword for name in ("channel", "provider_name", "computer_name", "event_id")} | {
        "event_data": {"properties": {"ProcessGuid": keyword, "LogonId": keyword}}}}
    contract = contract_from_types("both", flatten_mapping(raw), hosts=(fx.HOST,),
                                   keyword_limits=keyword_subfield_limits(raw))
    assert contract.os_family == "windows" and contract.fields["host.name"].natives == ("winlog.computer_name",
                                                                                         "Hostname")
    root = _event("logon", "windows", process__guid="{00000000-0000-0000-0000-0000000000a3}")
    for link_type in ("host_after_anchor", "process_activity"):
        intents, reason, coverage = _plan({"both": contract}, root, link_type)
        assert reason is None and intents, link_type
        assert all(group[0].field == "Channel" for intent in intents for group in intent.any_of
                   if group[0].field in {"Channel", "event.channel", "event.dataset"})
        reasons = [reason for cell in coverage for reason in cell.reasons]
        assert any(reason.startswith("windows_source_unselectable:both: its Winlogbeat records (winlog.*)")
                   for reason in reasons), link_type
    # a pure NXLog target records no such gap
    intents, reason, coverage = _plan({fx.NXLOG_TARGET: _nxlog_contract()}, root, "host_after_anchor")
    assert intents and coverage == []


# ---- the contract and the compiled equality -----------------------------------------------------------------------

def test_text_aliases_read_their_keyword_subfields_for_equality_only():
    dynamic, text = _nxlog_contract("dynamic"), _nxlog_contract("text")
    for typed, native in (("host.name", "Hostname"), ("process.guid", "ProcessGuid"),
                          ("auth.session_id", "TargetLogonId"), ("source.ip", "SourceIp")):
        spec = dynamic.fields[typed]
        assert spec.natives[0] == native and spec.exact[0] == f"{native}.keyword" and spec.type == "text"
        assert set(spec.ops) == {"eq", "in", "exists", "missing"} and not spec.aggregatable
        assert text.fields[typed].exact == () and set(text.fields[typed].ops) == {"exists", "missing"}
    # substring and prefix matching would miss values longer than the subfield keeps: never offered
    assert not dynamic.supports("process.command_line", "contains")
    # class selectors stay without equality: the flat records are selected by their shape, which a provider's own
    # Channel data overwriting NXLog's cannot hide
    assert not dynamic.supports("event.channel", "eq") and not dynamic.supports("event.provider", "in")
    assert "exact" not in dynamic.fields["event.code"].model_dump()
    # a Winlogbeat target's contract is unchanged
    winlogbeat = contract_from_types("w", fx.WINLOGBEAT_TYPES)
    assert all(not spec.exact for spec in winlogbeat.fields.values())


def _clauses(query) -> list[tuple[str, str]]:
    """Every (clause kind, field) in a compiled query."""
    out = []
    if isinstance(query, dict):
        for kind, body in query.items():
            if kind in {"term", "terms", "wildcard", "match_phrase", "exists"} and isinstance(body, dict):
                out.extend((kind, field) for field in (body.values() if kind == "exists" else body))
            else:
                out.extend(_clauses(body))
    elif isinstance(query, list):
        for item in query:
            out.extend(_clauses(item))
    return out


def test_the_subfield_limit_is_read_from_the_mapping():
    raw = {"a": {"mappings": {"properties": {
        "Hostname": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 128}}},
        "ProcessGuid": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
        "User": {"type": "text", "fields": {"raw": {"type": "keyword", "ignore_above": 64}}},
        "Image": {"type": "keyword", "ignore_above": 10}}}},
        "b": {"mappings": {"properties": {
            "Hostname": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 512}}}}}}}
    # the smallest limit any index of the target sets; a subfield without one keeps every value
    assert keyword_subfield_limits(raw) == {"Hostname.keyword": 128, "ProcessGuid.keyword": None, "User.raw": 64}
    contract = contract_from_types("t", {**flatten_mapping(raw), "Channel": "text", "EventID": "long"},
                                   keyword_limits=keyword_subfield_limits(raw))
    assert contract.fields["host.name"].exact_limit == 128
    assert contract.fields["process.guid"].exact_limit is None
    assert "exact_limit" not in contract.fields["process.guid"].model_dump()
    assert contract.fields["user.entity_id"].exact == ("User.raw",)
    # without the mapping's limits nothing is assumed: no text alias gains equality
    unknown = contract_from_types("t", {**flatten_mapping(raw), "Channel": "text", "EventID": "long"})
    assert not unknown.fields["host.name"].exact and not unknown.supports("host.name", "eq")


class _ProfileClient:
    settings = type("S", (), {"es_flavor": "elasticsearch"})()
    version = "8.19.0"

    def mapping(self, target):
        return fx.nxlog_mapping(fx.nxlog_docs(), mapping="dynamic", ignore_above=128, target=target)

    def search(self, target, body):
        return {"aggregations": {"hosts": {"buckets": [{"key": {"host": fx.HOST}, "doc_count": 6}]},
                                 "ds": {"buckets": []}}, "hits": {"total": {"value": 6}}}


def test_a_profile_carries_the_subfield_limit_without_changing_its_field_types():
    profile, contract = build_profile(_ProfileClient(), fx.NXLOG_TARGET)
    assert contract.os_family == "windows" and contract.fields["host.name"].exact == ("Hostname.keyword",)
    assert contract.fields["host.name"].exact_limit == 128
    # the profile's field types (part of its id) are what they were: the limit is not among them
    assert profile.field_types == flatten_mapping(_ProfileClient().mapping(fx.NXLOG_TARGET))


def test_a_value_longer_than_the_mappings_limit_is_matched_as_a_phrase():
    contract = _nxlog_contract(ignore_above=128)
    long = "y" * 200
    clauses = _clauses(_pred(Predicate(field="user.entity_id", op="eq", value=f"name:EXAMPLE\\{long}"), contract))
    assert clauses and all(kind == "match_phrase" for kind, _field in clauses)
    assert ("match_phrase", "User") in clauses
    # a 38-character GUID under a 32-character limit: never a term-only query on the subfield
    narrow = _nxlog_contract(ignore_above=32)
    root = _event("proc", "windows", process__guid="00000000-0000-0000-0000-0000000000a3")
    intents, reason, _coverage = _plan({fx.NXLOG_TARGET: narrow}, root, "process_activity")
    assert reason is None and intents
    clauses = [item for intent in intents for item in _clauses(build_query(intent, narrow))]
    assert ("match_phrase", "ProcessGuid") in clauses
    assert not any(field == "ProcessGuid.keyword" for _kind, field in clauses)
    assert ("wildcard", "Hostname.keyword") in clauses           # the short host name still reads the subfield


def test_the_limit_counts_utf16_code_units():
    contract = _nxlog_contract(ignore_above=32)
    astral = "\U0001F600" * 16                                       # 16 characters, 32 code units: kept
    over = "\U0001F600" * 16 + "a"                                   # 17 characters, 33 code units: not kept
    assert len(over) == 17 and utf16_length(astral) == 32 and utf16_length(over) == 33
    assert _pred(Predicate(field="process.guid", op="eq", value=astral), contract) == {
        "term": {"ProcessGuid.keyword": astral}}
    assert _pred(Predicate(field="process.guid", op="eq", value=over), contract) == {
        "match_phrase": {"ProcessGuid": over}}


def test_equality_on_a_subfield_matches_a_value_longer_than_it_keeps_as_a_phrase():
    contract = _nxlog_contract()
    short, long = "4300", "x" * 257
    assert _pred(Predicate(field="process.pid", op="eq", value=short), contract) == {"bool": {"should": [
        {"term": {"ProcessId.keyword": short}}, {"term": {"NewProcessId.keyword": short}}],
        "minimum_should_match": 1}}
    assert _pred(Predicate(field="process.pid", op="in", value=[short, long]), contract) == {"bool": {"should": [
        {"bool": {"should": [{"terms": {"ProcessId.keyword": [short]}}, {"terms": {"NewProcessId.keyword": [short]}}],
                  "minimum_should_match": 1}},
        {"match_phrase": {"ProcessId": long}}, {"match_phrase": {"NewProcessId": long}}],
        "minimum_should_match": 1}}
    # canonical account values keep their native forms on the subfields
    account = _pred(Predicate(field="user.entity_id", op="eq", value="sid:S-1-5-21-1"), contract)
    assert account == {"wildcard": {"SubjectUserSid.keyword": {"value": "S-1-5-21-1", "case_insensitive": True}}}
    query = build_query(SearchIntent(kind="raw", target=fx.NXLOG_TARGET, window=Window(
        start=datetime(2026, 1, 1, tzinfo=UTC), end=datetime(2026, 1, 2, tzinfo=UTC)),
        filters=[Predicate(field="host.name", op="eq", value="WS01.example.test")]), contract)
    assert query["bool"]["filter"][1] == {"bool": {"should": [
        {"wildcard": {"Hostname.keyword": {"value": "WS01", "case_insensitive": True}}},
        {"wildcard": {"Hostname.keyword": {"value": "WS01.*", "case_insensitive": True}}}],
        "minimum_should_match": 1}}


def test_the_fixture_activity_is_typed_alike_in_every_layout():
    """Guards the comparison above: the records the links reach are one set whichever layout carried them."""
    counts = Counter()
    for layout, mapping in (("winlogbeat", "keyword"), ("nxlog", "keyword"), ("nxlog", "dynamic")):
        repo, _summary, _searches = _run(layout, mapping)
        counts[layout, mapping] = len(repo.candidates("h1"))
    assert len(set(counts.values())) == 1
