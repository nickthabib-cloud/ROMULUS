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
from romulus.sources.compile import SUBFIELD_IGNORE_ABOVE, _pred, build_query
from romulus.sources.models import Predicate, SearchIntent, Window
from romulus.sources.profile import contract_from_types
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
    [anchor] = repo.expansion_anchors("h1")
    assert anchor["status"] == "expanded_partial" and host_field in anchor["reasons"]


# ---- planning across mixed targets -------------------------------------------------------------------------------

START = fx.T0
WINDOW = LinkWindow(label="anchor ±5 min", start=START - timedelta(minutes=5), end=START + timedelta(minutes=5))
LINUX_TYPES = {"@timestamp": "date", "event.dataset": "keyword", "event.module": "keyword", "host.name": "keyword",
               "source.ip": "ip", "destination.ip": "ip", "process.pid": "long", "process.executable": "keyword",
               "user.name": "keyword", "auditd.data.syscall": "keyword", "message": "text"}


def _nxlog_contract(mapping="dynamic"):
    return contract_from_types(fx.NXLOG_TARGET, fx.nxlog_types(fx.nxlog_docs(), mapping=mapping), hosts=(fx.HOST,))


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
        assert [cell.reasons for cell in coverage] == [[NXLOG_MIXED_LINK_REASON]]


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


def test_equality_on_a_subfield_matches_a_value_longer_than_it_keeps_as_a_phrase():
    contract = _nxlog_contract()
    short, long = "4300", "x" * (SUBFIELD_IGNORE_ABOVE + 1)
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
