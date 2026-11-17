"""The AI agent's source-query budget is shared out per session and per tool call, from persisted spend."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from romulus.agent.models import EntityRef
from romulus.agent.tools import (
    AuthActivityArgs,
    AuthActivityRequest,
    ProcessTreeArgs,
    ProcessTreeRequest,
    SearchEventsRequest,
)
from romulus.config import load_settings
from romulus.hunt import pivot as pivot_module
from romulus.hunt.agent_tools import (
    CALL_SLICE_FLOOR,
    HuntToolExecutor,
    agent_query_shares,
    build_agent_toolbox,
    packet_span,
)
from romulus.hunt.links import LinkFetcher
from romulus.hunt.pivot import PivotExecutor
from romulus.sources.models import Completeness, SearchOutcome
from romulus.sources.profile import SHARDS_UNANSWERED, contract_from_types
from romulus.store import schema as store_schema
from romulus.store.db import make_engine, migrate, utcnow
from romulus.store.repo import Repo
from tests.test_agent_search_events import ABSENT, FakeES, _hunt, _keyword_contract

START = datetime(2024, 11, 18, 14, 0, tzinfo=UTC)
END = START + timedelta(hours=1)


class _Client:
    version = "test"

    class settings:
        es_flavor = "elasticsearch"


def _repo() -> Repo:
    repo = Repo(make_engine(":memory:"))
    migrate(repo.engine)
    repo.create_hunt("h1", {"window": {"start": START.isoformat(), "end": END.isoformat()}, "targets": ["host-x"]},
                     "digest", "test")
    return repo


def _session(repo: Repo, session_id: str, purpose: str, hypothesis_id: str | None = None) -> None:
    repo.save_agent_session({"id": session_id, "hunt_id": "h1", "hypothesis_id": hypothesis_id, "purpose": purpose,
                             "state": "running", "tool_calls": 0, "summary": "", "started_at": utcnow(),
                             "ended_at": None})


def _settings(total: int):
    return load_settings(environ={"AGENT_MAX_SOURCE_QUERIES": str(total)})


def _linux_contract(target: str = "host-x"):
    return contract_from_types(target, {"@timestamp": "date", "event.dataset": "keyword", "host.name": "keyword"},
                               role="host", os_family="linux")


def _empty(intent, *_args, **_kwargs):
    return SearchOutcome(target=intent.target if hasattr(intent, "target") else "host-x", fingerprint="fp",
                         started_at=START, ended_at=START, completeness=Completeness.complete, total=0,
                         total_relation="eq", returned=0)


def _quiet(monkeypatch):
    monkeypatch.setattr(pivot_module, "execute", lambda _client, intent, *_a, **_k: _empty(intent))


def _executor(repo: Repo, session_id: str, purpose: str, share, call_slice, total: int = 1000) -> PivotExecutor:
    executor = PivotExecutor(repo, _Client(), "h1", {"host-x": _linux_contract()}, source_query_budget=total,
                             source_query_scope="agent")
    executor.source_queries = repo.agent_source_queries("h1")
    executor.configure_agent_shares(session_id=session_id, purpose=purpose, session_share=share,
                                    call_slice=call_slice)
    return executor


def _spend(executor: PivotExecutor, count: int) -> list[str]:
    """Spend up to `count` queries one tool call at a time; return each refusal's reasons."""
    intent = pivot_module.SearchIntent(kind="raw", target="host-x",
                                       window=pivot_module.Window(start=START, end=END), max_records=10)
    refused = []
    for _ in range(count):
        executor.begin_call()
        outcome = executor._execute(intent, executor.contracts["host-x"])
        if outcome.completeness == Completeness.failed:
            refused.extend(outcome.reasons)
    return refused


def _auth_request():
    return AuthActivityRequest(tool="auth_activity", arguments=AuthActivityArgs(
        entity=EntityRef(kind="host", value="web01", role="host"), start=START, end=END))


# ---- the shares ---------------------------------------------------------------------------------------------------

def test_orient_cannot_take_more_than_its_share(monkeypatch):
    _quiet(monkeypatch)
    repo = _repo()
    _session(repo, "orient-1", "orient")
    share, call_slice = agent_query_shares(_settings(100), repo, "h1", repo.agent_session("h1", "orient-1"))
    assert (share, call_slice) == (20, 20)          # 20 % of the total; the slice is never more than the share
    executor = _executor(repo, "orient-1", "orient", share, call_slice, total=100)

    refused = _spend(executor, 30)

    assert repo.agent_source_queries("h1") == 20
    assert refused == ["agent_session_source_query_share:20"] * 10
    caps = [row["detail"] for row in repo.audit_trail("h1", "agent.source_query_cap", limit=50)[0]]
    assert caps and all(item["cap"] == "agent_session_source_query_share" for item in caps)
    # one record per call the cap stopped, counted apart from the other caps for the run page
    assert repo.agent_source_query_caps("h1") == {"agent_session_source_query_share": 10}


def test_a_later_investigate_session_still_gets_queries_after_a_greedy_orient(monkeypatch):
    _quiet(monkeypatch)
    repo = _repo()
    settings = _settings(100)
    _session(repo, "orient-1", "orient")
    orient = _executor(repo, "orient-1", "orient", *agent_query_shares(settings, repo, "h1",
                                                                       repo.agent_session("h1", "orient-1")), total=100)
    _spend(orient, 100)
    assert repo.agent_source_queries("h1") == 20

    monkeypatch.setattr(repo, "agent_hypotheses", lambda _hunt: [
        {"id": "hy-1", "status": "open", "sessions_run": 1}, {"id": "hy-2", "status": "open", "sessions_run": 0},
        {"id": "hy-3", "status": "open", "sessions_run": 4},      # no session left for it
        {"id": "hy-4", "status": "closed", "sessions_run": 0}])
    _session(repo, "inv-1", "investigate", None)
    share, call_slice = agent_query_shares(settings, repo, "h1", {"purpose": "investigate", "hypothesis_id": "hy-1"})
    assert share == 40                                # the 80 left over the two hypotheses still to be worked
    assert call_slice == CALL_SLICE_FLOOR
    investigate = _executor(repo, "inv-1", "investigate", share, call_slice, total=100)

    assert _spend(investigate, 10) == []
    assert repo.agent_source_queries("h1") == 30


def test_an_unused_share_flows_to_the_sessions_after_it(monkeypatch):
    repo = _repo()
    settings = _settings(1000)
    monkeypatch.setattr(repo, "agent_hypotheses", lambda _hunt: [
        {"id": f"hy-{n}", "status": "open", "sessions_run": 0} for n in range(4)])
    first, _ = agent_query_shares(settings, repo, "h1", {"purpose": "investigate", "hypothesis_id": "hy-0"})
    assert first == 250
    # the first session spends 50 of its 250 and its hypothesis is finished: the others share what remains
    _quiet(monkeypatch)
    _session(repo, "inv-0", "investigate")
    _spend(_executor(repo, "inv-0", "investigate", first, 100), 50)
    monkeypatch.setattr(repo, "agent_hypotheses", lambda _hunt: [
        {"id": f"hy-{n}", "status": "open", "sessions_run": 0} for n in range(1, 4)])
    later, _ = agent_query_shares(settings, repo, "h1", {"purpose": "investigate", "hypothesis_id": "hy-1"})
    assert later == 317                               # ceil(950 / 3)


def test_resume_keeps_the_counts_and_never_gets_a_fresh_budget(monkeypatch, tmp_path):
    _quiet(monkeypatch)
    path = tmp_path / "hunt.db"
    repo = Repo(make_engine(path))
    migrate(repo.engine)
    repo.create_hunt("h1", {"window": {"start": START.isoformat(), "end": END.isoformat()}, "targets": []}, "d", "t")
    settings = _settings(100)
    _session(repo, "orient-1", "orient")
    _spend(_executor(repo, "orient-1", "orient", 20, 20, total=100), 12)

    resumed = Repo(make_engine(path))                 # a new process: only what was persisted remains
    _session(resumed, "orient-2", "orient")
    assert resumed.agent_source_queries("h1") == 12
    assert resumed.agent_purpose_source_queries("h1", "orient") == 12
    share, _ = agent_query_shares(settings, resumed, "h1", resumed.agent_session("h1", "orient-2"))
    assert share == 8                                 # orient's 20 less the 12 its interrupted session spent
    executor = _executor(resumed, "orient-2", "orient", share, share, total=100)
    assert executor.source_queries == 12
    assert _spend(executor, 10) == ["agent_session_source_query_share:8"] * 2
    with resumed.engine.connect() as connection:
        details = [row.detail for row in connection.execute(select(store_schema.audit_event).where(
            store_schema.audit_event.c.action == "agent.source_query"))]
    assert [item["session_id"] for item in details] == ["orient-1"] * 12 + ["orient-2"] * 8
    assert {item["purpose"] for item in details} == {"orient"}


def test_the_toolbox_configures_the_session_share_from_its_session_row():
    repo = _repo()
    _session(repo, "orient-1", "orient")
    toolbox = build_agent_toolbox(_settings(2000), repo, "h1", client=object(), contracts={},
                                  session_id="orient-1")
    pivot = toolbox.executor.pivot
    assert (pivot.session_id, pivot.session_purpose) == ("orient-1", "orient")
    assert (pivot.session_share, pivot.call_slice) == (400, 40)


# ---- the call slice ------------------------------------------------------------------------------------------------

def test_a_call_slice_ends_the_call_partial_and_names_what_it_did_not_search(monkeypatch):
    _quiet(monkeypatch)
    repo = _repo()
    _session(repo, "inv-1", "investigate")
    executor = _executor(repo, "inv-1", "investigate", 100, 2)
    executor.begin_call()

    result = executor.run("inv-1", _auth_request(), anchor_ts=START + timedelta(minutes=5))

    # three auth datasets planned, two queries in the slice: the third is named, never zero hits
    assert result.status == "partial"
    assert "agent_call_source_query_slice:2" in result.reasons
    unsearched = [cell for cell in result.coverage if "agent_call_source_query_slice:2" in cell.reasons]
    assert len(unsearched) == 1 and unsearched[0].status == "failed" and unsearched[0].unresolved_ranges
    assert len(result.task_ids) == 2 and len(repo.tasks("h1")) == 2
    assert repo.agent_source_queries("h1") == 2
    # the next call has its own slice
    executor.begin_call()
    assert executor.run("inv-1", _auth_request(), anchor_ts=START).status != "failed"


def test_a_dense_source_keeps_its_capped_records_rather_than_splitting_past_the_slice(monkeypatch):
    calls = []

    def capped(_client, intent, *_args, **_kwargs):
        calls.append(intent)
        return SearchOutcome(target=intent.target, fingerprint="fp", started_at=START, ended_at=START,
                             completeness=Completeness.partial, reasons=["cap:10<total:500"], total=500,
                             total_relation="eq", returned=0)

    monkeypatch.setattr(pivot_module, "execute", capped)
    repo = _repo()
    _session(repo, "inv-1", "investigate")
    executor = _executor(repo, "inv-1", "investigate", 100, 3)
    executor.begin_call()
    request = ProcessTreeRequest(tool="process_tree", arguments=ProcessTreeArgs(
        host="web01", process_id=7, start=START, end=END))

    result = executor.run("inv-1", request, anchor_ts=START + timedelta(minutes=5))

    assert len(calls) <= 3 and repo.agent_source_queries("h1") == len(calls)
    assert result.status == "partial"
    assert "agent_call_source_query_slice:3" in result.reasons
    assert all(cell.status != "complete" for cell in result.coverage)


# ---- nothing left --------------------------------------------------------------------------------------------------

def test_a_pivot_with_nothing_left_creates_no_task_and_says_so_once(monkeypatch):
    _quiet(monkeypatch)
    repo = _repo()
    _session(repo, "inv-1", "investigate")
    executor = _executor(repo, "inv-1", "investigate", 0, 0)
    executor.begin_call()

    result = executor.run("inv-1", _auth_request(), anchor_ts=START)

    assert result.status == "failed"
    assert result.reasons[0] == "agent_session_source_query_share:0"
    assert "nothing was searched" in result.reasons[1] and len(result.reasons) == 2
    assert result.task_ids == [] and repo.tasks("h1") == []
    assert all(cell.status == "failed" and cell.unresolved_ranges for cell in result.coverage)
    assert repo.agent_source_queries("h1") == 0


def test_a_search_with_nothing_left_creates_no_task():
    repo, client = _hunt(), FakeES({"net-a": []})
    pivot = PivotExecutor(repo, client, "h1", {"net-a": _keyword_contract("net-a")}, source_query_budget=50,
                          source_query_scope="agent")
    pivot.configure_agent_shares(session_id="as-search", purpose="investigate", session_share=0, call_slice=0)
    executor = HuntToolExecutor(repo, "h1", pivot, LinkFetcher(pivot, START, END), START, END)
    request = SearchEventsRequest.model_validate({"tool": "search_events", "arguments": {
        "scope": "network", "conditions": ABSENT, "start": START.isoformat(),
        "end": END.isoformat()}})

    result = executor.run("as-search", "anchor", request, anchor_ts=START + timedelta(minutes=30))

    assert result.status == "failed"
    assert "agent_session_source_query_share:0" in result.reasons
    assert client.bodies == [] and repo.tasks("h1") == []


def test_a_followed_link_with_nothing_left_creates_no_task():
    repo, client = _hunt(), FakeES({"net-a": []})
    pivot = PivotExecutor(repo, client, "h1", {"net-a": _keyword_contract("net-a")}, source_query_budget=0,
                          source_query_scope="agent")
    executor = HuntToolExecutor(repo, "h1", pivot, LinkFetcher(pivot, START, END), START, END)

    result = executor.follow_link("as-search", "anchor", "process_lineage", None)

    assert result.status == "failed" and result.reasons[0] == "agent_source_query_budget:0"
    assert client.bodies == [] and repo.tasks("h1") == []


# ---- out-of-window packet sources ----------------------------------------------------------------------------------

def _profile(first: str | None, last: str | None, notes=()) -> dict:
    return {"time_min": first, "time_max": first, "packet_time_max": last, "notes": list(notes)}


def test_a_packet_span_is_known_only_from_both_bounds_of_a_complete_inventory():
    assert packet_span(_profile("2018-01-01T00:00:00.000Z", "2018-01-02T00:00:00.000Z")) == (
        datetime(2018, 1, 1, tzinfo=UTC), datetime(2018, 1, 2, tzinfo=UTC))
    assert packet_span(_profile("2018-01-01T00:00:00.000Z", None)) is None
    assert packet_span(_profile(None, "2018-01-02T00:00:00.000Z")) is None
    assert packet_span(_profile("1514764800000", "2018-01-02T00:00:00Z")) is None
    assert packet_span(_profile("2018-01-01T00:00:00", "2018-01-02T00:00:00")) is None       # no offset
    assert packet_span(_profile("2018-01-01T00:00:00Z", "2018-01-02T00:00:00Z",
                                [f"ds inventory truncated ({SHARDS_UNANSWERED}: x)"])) is None
    assert packet_span(None) is None


class _ProfileClient:
    """A source whose inventory search answers the time bounds it is asked for, and every other search empty."""

    version = "8.19.0"

    class settings:
        es_flavor = "elasticsearch"

    def __init__(self, properties: dict):
        self.properties = properties
        self.bodies: list[dict] = []

    def mapping(self, target):
        return {target: {"mappings": {"properties": self.properties}}}

    def search(self, _target, body):
        self.bodies.append(body)
        stamps = {"tmin": ("2018-01-01T00:00:00.000Z", 1514764800000),
                  "tmax": ("2018-01-01T12:00:00.000Z", 1514808000000),
                  "pmax": ("2018-01-02T00:00:00.000Z", 1514851200000)}
        aggs = {name: {"value": stamps[name][1], "value_as_string": stamps[name][0]}
                for name in (body.get("aggs") or {}) if name in stamps}
        return {"hits": {"total": {"value": 5 if aggs else 0, "relation": "eq"}, "hits": []},
                "aggregations": aggs}


def test_an_arkime_profile_carries_its_packet_span_into_the_agent_toolbox():
    from romulus.sources.profile import build_profile
    arkime = _ProfileClient({name: {"type": kind} for name, kind in (
        ("firstPacket", "date"), ("lastPacket", "date"), ("network.community_id", "keyword"),
        ("source.ip", "ip"), ("destination.ip", "ip"), ("protocol", "keyword"), ("node", "keyword"))})
    profile, contract = build_profile(arkime, "arkime_sessions3-180101")
    assert any("pmax" in (body.get("aggs") or {}) for body in arkime.bodies)
    assert contract.time_field == "firstPacket"
    stored = profile.model_dump(mode="json")
    assert stored["packet_time_max"] == "2018-01-02T00:00:00.000Z"

    host = _ProfileClient({"@timestamp": {"type": "date"}, "event": {"properties": {"dataset": {"type": "keyword"}}},
                           "host": {"properties": {"name": {"type": "keyword"}}}})
    host_profile, _ = build_profile(host, "logs-host")
    assert "packet_time_max" not in host_profile.model_dump(mode="json")
    assert not any("pmax" in (body.get("aggs") or {}) for body in host.bodies)

    repo = _repo()
    repo.save_profile("h1", stored)
    _session(repo, "inv-1", "investigate")
    toolbox = build_agent_toolbox(_settings(2000), repo, "h1", client=object(),
                                  contracts={"arkime_sessions3-180101": contract}, session_id="inv-1")
    label = "packet captures behind arkime_sessions3-180101 (Arkime viewer and TShark)"
    assert toolbox.executor.packet_sources == (label,)
    assert toolbox.executor.packet_spans == {label: (datetime(2018, 1, 1, tzinfo=UTC),
                                                     datetime(2018, 1, 2, tzinfo=UTC))}


def test_out_of_window_packet_sources_are_counted_not_listed_and_unknown_ones_stay_listed():
    repo, client = _hunt(), FakeES({"net-a": []})
    pivot = PivotExecutor(repo, client, "h1", {"net-a": _keyword_contract("net-a")})
    names = {key: f"packet captures behind {key} (Arkime viewer and TShark)"
             for key in ("old", "before", "spanning", "after", "unknown")}
    spans = {
        names["old"]: (datetime(2018, 1, 1, tzinfo=UTC), datetime(2018, 1, 2, tzinfo=UTC)),
        # a session that began before the window but whose last packet is in it: listed
        names["spanning"]: (START - timedelta(days=1), START + timedelta(minutes=1)),
        names["before"]: (START - timedelta(days=1), START - timedelta(seconds=1)),
        names["after"]: (END, END + timedelta(days=1)),          # the window is half-open
    }
    executor = HuntToolExecutor(repo, "h1", pivot, LinkFetcher(pivot, START, END), START, END,
                                packet_sources=tuple(names.values()), packet_spans=spans)
    request = SearchEventsRequest.model_validate({"tool": "search_events", "arguments": {
        "scope": "network", "conditions": ABSENT, "start": START.isoformat(),
        "end": END.isoformat()}})

    result = executor.run("as-search", "anchor", request, anchor_ts=START + timedelta(minutes=30))

    listed = {item.split(":", 1)[0] for item in result.not_searched}
    assert listed == {names["spanning"], names["unknown"]}
    summary = [reason for reason in result.reasons if "not listed as not searched" in reason]
    assert len(summary) == 1 and summary[0].startswith("3 packet source(s)")
    assert result.status == "partial"                  # the two listed sources are still gaps
