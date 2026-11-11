"""Host query coverage for RFC 3164 and RFC 5424 header-derived identities.

Public formats: https://www.rfc-editor.org/rfc/rfc3164 and
https://www.rfc-editor.org/rfc/rfc5424. Fixtures are synthetic.
"""
from datetime import UTC, datetime, timedelta

import pytest

from romulus.agent.aliases import AliasBook
from romulus.agent.models import EntityRef
from romulus.agent.toolbox import Toolbox
from romulus.agent.tools import (
    AuthActivityArgs,
    AuthActivityRequest,
    EntityTimelineArgs,
    EntityTimelineRequest,
)
from romulus.config import Settings
from romulus.evidence.normalize import normalize_hits
from romulus.hunt.agent_tools import HuntToolExecutor
from romulus.hunt.links import LinkAnchor, LinkFetcher, LinkWindow
from romulus.hunt.pivot import PivotExecutor
from romulus.sources.es import ElasticClient
from romulus.sources.profile import contract_from_types
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo
from tests.throughput_fixture import MiniES

START = datetime(2030, 1, 6, 9, tzinfo=UTC)
END = START + timedelta(minutes=5)
REASON = "text lines may carry their host only in the syslog header"


def _line(number, indexed=None):
    stamp = START + timedelta(seconds=number)
    source = {
        "@timestamp": stamp.isoformat(),
        "message": f"Jan  6 {stamp:%H:%M:%S} app01 sshd[{100 + number}]: "
                   f"Accepted password for root from 192.0.2.9 port {40000 + number} ssh2",
        "log": {"file": {"path": "/var/log/auth.log"}, "offset": number},
    }
    if indexed:
        source["host"] = {"name": indexed}
    return {"_index": "text-host", "_id": f"line-{number}", "_source": source}


@pytest.fixture
def source(tmp_path):
    opened = []

    def build(*, indexed_anchor=False, host_mapped=True, dataset_mapped=True,
              inventory=True, mixed=False):
        rows = [_line(0, "app01" if indexed_anchor else None), _line(1), _line(2, "other01")]
        types = {"@timestamp": "date", "message": "text", "log.file.path": "keyword", "log.offset": "long"}
        if host_mapped:
            types["host.name"] = "keyword"
        if dataset_mapped:
            types.update({"event.dataset": "keyword", "input.type": "keyword"})
        if mixed:
            types.update({"winlog.channel": "keyword", "winlog.event_id": "long",
                          "winlog.computer_name": "keyword", "winlog.provider_name": "keyword"})
        contract = contract_from_types("text-host", types, role="host", os_family="windows" if mixed else "linux")
        if mixed:
            contract = contract.model_copy(update={"linux_text_mixed": True})
        repo = Repo(make_engine(":memory:"))
        migrate(repo.engine)
        repo.create_hunt("h1", {"targets": ["text-host"], "window": {
            "start": START.isoformat(), "end": END.isoformat()}, "pack": {"playbooks": []}}, "digest", "test")
        opened.append(repo)
        client = ElasticClient(Settings(es_url="http://es.invalid"), transport=MiniES(
            {"text-host": rows}, {"text-host": "@timestamp"}).transport())
        executor = PivotExecutor(repo, client, "h1", {"text-host": contract}, stage_dir=tmp_path)
        executor.dataset_inventory = {"text-host": {"linux.text": 3}} if inventory else {}
        events, skips, errors = normalize_hits(rows[:2])
        assert not skips and not errors
        assert [event.host for event in events] == ["app01", "app01"]
        return executor, events, rows

    yield build
    for repo in opened:
        repo.engine.dispose()


def _link(executor, anchor_event):
    anchor = LinkAnchor(finding_id="anchor", ts=anchor_event.ts, host=anchor_event.host,
                        event_ids=[anchor_event.id], events=[anchor_event])
    window = LinkWindow(label="anchor +5 min", start=START, end=END)
    return LinkFetcher(executor, START, END).fetch(anchor, "host_after_anchor", window)


@pytest.mark.parametrize("indexed_anchor", [False, True])
@pytest.mark.parametrize("inventory", [False, True])
def test_host_link_never_completes_when_header_only_lines_are_omitted(source, indexed_anchor, inventory):
    executor, events, _rows = source(indexed_anchor=indexed_anchor, inventory=inventory)
    result = _link(executor, events[0])
    assert events[1].id not in result.event_ids
    assert result.status == "partial", result.reasons
    assert REASON in result.reasons
    gaps = [cell for cell in result.coverage if REASON in cell.reasons]
    assert gaps and all(cell.status == "partial" and cell.unresolved_ranges for cell in gaps)


def test_header_origin_is_enough_when_inventory_omits_text(source):
    executor, events, _rows = source()
    executor.dataset_inventory = {"text-host": {"auditd.log": 1}}
    result = _link(executor, events[0])
    assert result.status == "partial", result.reasons
    assert REASON in result.reasons


@pytest.mark.parametrize("inventory", [False, True])
def test_mixed_text_flag_preserves_gap_for_indexed_anchor(source, inventory):
    executor, events, _rows = source(indexed_anchor=True, inventory=inventory, mixed=True)
    result = _link(executor, events[0])
    assert result.status == "partial", result.reasons
    assert REASON in result.reasons


@pytest.mark.parametrize("host_mapped,dataset_mapped", [(False, True), (True, False)])
def test_unpushable_host_query_remains_unsupported(source, host_mapped, dataset_mapped):
    executor, events, _rows = source(host_mapped=host_mapped, dataset_mapped=dataset_mapped)
    result = _link(executor, events[0])
    assert result.status == "unsupported"
    assert executor.source_queries == 0


@pytest.mark.parametrize("tool", ["entity_timeline", "auth_activity"])
def test_host_pivot_keeps_header_gap_and_retains_indexed_matches(source, tool):
    executor, events, _rows = source(indexed_anchor=True)
    entity = EntityRef(kind="host", value="app01", role="host")
    request = (EntityTimelineRequest(tool=tool, arguments=EntityTimelineArgs(entity=entity, start=START, end=END))
               if tool == "entity_timeline" else AuthActivityRequest(
                   tool=tool, arguments=AuthActivityArgs(entity=entity, start=START, end=END)))
    result = executor.run("session", request)
    assert result.status == "partial", result.reasons
    assert REASON in result.reasons
    assert events[0].id in result.reach_event_ids
    assert events[1].id not in result.reach_event_ids


def test_agent_toolbox_preserves_unresolved_host_pivot(source):
    executor, events, rows = source(indexed_anchor=True)
    repo = executor.repo
    event = events[0]
    repo.save_evidence("h1", [event], {"text-host/line-0": rows[0]["_source"]}, None)
    repo.save_candidate({
        "id": "anchor", "hunt_id": "h1", "rule_id": "host.credential_store_read", "rule_version": "1",
        "claim": "synthetic anchor", "claim_type": "observed_action", "event_ids": [event.id],
        "predicate_fields": [], "entities": [["host", "app01", "host"]], "ts": START,
        "severity": "high", "confidence": "high", "lane": "high", "priority": 1.0,
        "priority_reasons": [], "gate_results": {}, "benign_alternatives": [], "next_checks": [],
        "group_key": "", "source_case_id": None, "source_anchor_id": None, "source_link_id": None,
    })
    aliases = AliasBook(repo, "h1")
    fetcher = LinkFetcher(executor, START, END)
    tools = Toolbox(repo, "h1", executor=HuntToolExecutor(repo, "h1", executor, fetcher, START, END),
                    session_id="session")
    response = tools.execute("entity_timeline", {
        "anchor": aliases.alias_for("F", "anchor"),
        "entity": aliases.alias_for("N", "h1:host:app01"), "start": None, "end": None,
    })
    assert response["status"] == "partial", response
    assert REASON in response["data"]["result"]["reasons"]


def test_unmapped_host_pivot_stays_unsupported(source):
    executor, _events, _rows = source(host_mapped=False)
    request = EntityTimelineRequest(tool="entity_timeline", arguments=EntityTimelineArgs(
        entity=EntityRef(kind="host", value="app01", role="host"), start=START, end=END))
    result = executor.run("session", request)
    assert result.status == "unsupported"
    assert executor.source_queries == 0


def test_inventoried_nontext_sources_keep_complete_planning(source):
    executor, _events, _rows = source(indexed_anchor=True)
    executor.dataset_inventory = {"text-host": {"linux.audit": 3}}
    request = EntityTimelineRequest(tool="entity_timeline", arguments=EntityTimelineArgs(
        entity=EntityRef(kind="host", value="app01", role="host"), start=START, end=END))
    intents, coverage = executor.plan(request)
    assert intents
    assert not any(REASON in cell.reasons for cell in coverage)
