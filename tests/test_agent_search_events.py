"""The agent's typed search: validation, honest coverage, literal values at the source, admission and bounds.

Every source here is a fake that answers the compiled query the real compiler produced, so what a model value becomes
on the way to Elasticsearch is the code under test. No test reaches a real model or cluster.
"""
from __future__ import annotations

import json
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

import pytest

from romulus.agent.admission import AgentAdmission, collect_issued_aliases, typed_alias_arguments
from romulus.agent.aliases import AliasBook
from romulus.agent.toolbox import TELEMETRY_RESPONSE_BYTES, Toolbox
from romulus.agent.tools import SearchEventsArgs, SearchEventsRequest, tool_catalog
from romulus.config import Settings
from romulus.evidence.typed import Outcome, RawRef, TypedEvent, fv
from romulus.hunt import pivot as pivot_module
from romulus.hunt.agent_tools import HuntToolExecutor
from romulus.hunt.links import LinkFetcher
from romulus.hunt.pivot import MAX_PIVOT_PARTITIONS, PivotExecutor
from romulus.sources.compile import _escape_wildcard
from romulus.sources.es import SourceBudgetExhausted
from romulus.sources.profile import FieldContract, FieldSpec, contract_from_types
from romulus.store.db import make_engine, migrate, utcnow
from romulus.store.repo import Repo

T = datetime(2024, 11, 18, 14, 0, tzinfo=UTC)
END = T + timedelta(hours=1)
SESSION = "as-search"


# ---- fixtures ----------------------------------------------------------------------------------------------------

def _dns(target: str, number: int, ts: datetime, name: str = "example.test") -> dict:
    """One Suricata DNS record as an Elastic shipper stores it: it normalizes to one dns_query event."""
    body = {"timestamp": ts.isoformat(), "event_type": "dns", "src_ip": "10.0.0.8", "dest_ip": "10.0.0.53",
            "proto": "UDP", "dns": {"type": "query", "rrname": name, "rrtype": "A"}}
    return {"_id": f"{target}-{number}", "_index": target, "_source": {
        "@timestamp": ts.isoformat().replace("+00:00", "Z"), "host": {"name": "sensor"},
        "event": {"dataset": "suricata.eve.dns", "original": json.dumps(body)}}}


def _window(body: dict) -> tuple[datetime, datetime]:
    bounds = body["query"]["bool"]["filter"][0]["range"]["@timestamp"]
    return datetime.fromisoformat(bounds["gte"]), datetime.fromisoformat(bounds["lt"])


class FakeES:
    """Answers each compiled raw query from fixed records (or a generator for mission-scale totals), honouring the
    query's time window, order and record cap, and keeps every body it was sent."""

    version = "8.19.0"

    class settings:
        es_flavor = "elasticsearch"

    def __init__(self, records: dict[str, list[dict]] | None = None, generated: dict[str, int] | None = None):
        self.records = records or {}
        self.generated = generated or {}          # target -> claimed total per query (records made on demand)
        self.bodies: list[tuple[str, dict]] = []
        self.returned = 0

    @contextmanager
    def point_in_time(self, _target):
        yield object()

    def iterate(self, q, max_records, page_size=None, pit=None, on_query=None, deadline=None, clock=None):
        if on_query is not None and not on_query():
            raise SourceBudgetExhausted("source query budget exhausted")
        self.bodies.append((q.target, q.body))
        start, end = _window(q.body)
        descending = q.body["sort"][0]["@timestamp"]["order"] == "desc"
        if q.target in self.generated:
            total = self.generated[q.target]
            span = (end - start) / max(1, max_records)
            moments = [start + span * index for index in range(min(total, max_records))]
            if descending:
                moments = [end - span * (index + 1) for index in range(min(total, max_records))]
            hits = [_dns(q.target, int(moment.timestamp() * 1e6), moment) for moment in moments]
        else:
            matching = [record for record in self.records.get(q.target, [])
                        if start <= datetime.fromisoformat(record["_source"]["@timestamp"]) < end]
            # ties at one instant are ordered by document, as the source's _shard_doc tiebreak does
            matching.sort(key=lambda record: (record["_source"]["@timestamp"], record["_id"]), reverse=descending)
            total = len(matching)
            hits = matching[:max_records]
        hits = [dict(hit) for hit in hits]
        self.returned += len(hits)
        yield hits, {"problems": [], "total": total, "total_relation": "eq", "surrogate_free": True}


def _keyword_contract(target: str, role: str = "network", **extra: str) -> FieldContract:
    return contract_from_types(target, {
        "@timestamp": "date", "event.dataset": "keyword", "dns.question.name": "keyword",
        "destination.ip": "ip", "destination.port": "long", "event.duration": "double", **extra,
    }, role=role, os_family="linux" if role == "host" else None)


def _hunt(path=None) -> Repo:
    repo = Repo(make_engine(path or ":memory:"))
    migrate(repo.engine)
    repo.create_hunt("h1", {"window": {"start": T.isoformat(), "end": END.isoformat()},
                            "targets": ["net-a", "net-b"], "ai_agent": {"requested": True}}, "d", "test")
    repo.set_hunt_state("h1", "running")
    repo.set_hunt_state("h1", "completed_within_scope", detection_result="leads_only", stop_reason="scope")
    anchor = TypedEvent(id="anchor-ev", family="process_exec", ts=T + timedelta(minutes=30), host="web01",
                        outcome=Outcome.success, fields={"process.argv": fv(["id"], "fixture")},
                        raw=[RawRef(target="host-a", native_id="anchor-ev", digest="d")], normalizer="test@1")
    repo.save_evidence("h1", [anchor], {"host-a/anchor-ev": {"message": "anchor"}}, None)
    repo.save_candidate({
        "id": "anchor", "hunt_id": "h1", "rule_id": "host.test", "rule_version": "1",
        "claim": "A process execution was recorded", "claim_type": "observed_action", "event_ids": [anchor.id],
        "context_event_ids": [], "predicate_fields": [], "entities": [["host", "web01", "host"]],
        "ts": anchor.ts, "severity": "high", "confidence": "high", "lane": "high", "priority": 10.0,
        "priority_reasons": [], "gate_results": {}, "benign_alternatives": [], "next_checks": [],
        "group_key": "anchor", "source_case_id": None, "source_anchor_id": None, "source_link_id": None,
    })
    repo.save_agent_session({"id": SESSION, "hunt_id": "h1", "hypothesis_id": None, "purpose": "investigate",
                             "state": "running", "tool_calls": 0, "summary": "", "started_at": utcnow(),
                             "ended_at": None})
    return repo


def _toolbox(repo: Repo, contracts: dict, client: FakeES, *, budget: int | None = None,
             packet_sources: tuple[str, ...] = ()) -> Toolbox:
    pivot = PivotExecutor(repo, client, "h1", contracts, source_query_budget=budget,
                          source_query_scope="agent" if budget is not None else None)
    fetcher = LinkFetcher(pivot, T, END)
    executor = HuntToolExecutor(repo, "h1", pivot, fetcher, T, END, packet_sources=packet_sources)
    return Toolbox(repo, "h1", executor=executor, session_id=SESSION)


def _search(toolbox: Toolbox, conditions, *, scope="network", **extra) -> dict:
    anchor = AliasBook(toolbox.repo, "h1").alias_for("F", "anchor")
    return toolbox.execute("search_events", {"anchor": anchor, "scope": scope, "conditions": conditions, **extra})


DNS = [{"field": "dns.question.name", "op": "eq", "values": ["example.test"]}]


# ---- schema and validation ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("op", ["contains", "not_in", "missing", "exists"])
def test_each_excluded_op_is_refused_before_any_query(op):
    repo, client = _hunt(), FakeES()
    response = _search(_toolbox(repo, {"net-a": _keyword_contract("net-a")}, client),
                       [{"field": "dns.question.name", "op": op, "values": ["x"]}])
    assert response["status"] == "refused"
    assert response["data"]["error"]["code"] == "invalid_arguments"
    assert "conditions[].op: literal_error" in response["data"]["error"]["reasons"]
    assert client.bodies == []


@pytest.mark.parametrize("conditions, why", [
    ([{"field": "event.duration", "op": "gte", "values": ["5"]}], "at least one eq, in, prefix or cidr"),
    ([{"field": "event.duration", "op": "gte", "values": ["5"]},
      {"field": "event.duration", "op": "lt", "values": ["9"]}], "at least one eq, in, prefix or cidr"),
    ([{"field": "dns.question.name", "op": "in", "values": [f"v{n}" for n in range(21)]}], "at most 20"),
    ([{"field": "dns.question.name", "op": "eq", "values": ["x" * 257]}], "at most 256"),
    ([{"field": "dns.question.name", "op": "eq", "values": ["a", "b"]}], "exactly one value"),
    ([{"field": "dns.question.name", "op": "prefix", "values": ["ab"]}], "at least 3"),
    ([{"field": "destination.ip", "op": "cidr", "values": ["0.0.0.0/0"]}], "/8 or narrower"),
    ([{"field": "destination.ip", "op": "cidr", "values": ["10.0.0.300/8"]}], "one IP network"),
    ([{"field": "dns.question.name", "op": "eq", "values": [443]}], "string"),
    (DNS * 5, "at most 4"),
])
def test_the_selectivity_rule_and_value_limits_are_refused(conditions, why):
    repo, client = _hunt(), FakeES()
    response = _search(_toolbox(repo, {"net-a": _keyword_contract("net-a")}, client), conditions)
    assert response["status"] == "refused", why
    assert why.split()[-1] in json.dumps(response["data"]["error"]["details"], default=str), why
    assert client.bodies == []


@pytest.mark.parametrize("field, op, value", [
    ("destination.ip", "eq", "10.0.0.999"),
    ("destination.ip", "in", "not an address"),
    ("destination.port", "eq", "443/tcp"),
    ("destination.port", "eq", "4.5"),
    ("event.duration", "gte", "nan"),
    ("@timestamp", "gte", "2024-11-18T14:00:00Z"),
])
def test_a_value_its_field_type_cannot_hold_is_refused_by_name(field, op, value):
    repo, client = _hunt(), FakeES()
    conditions = [*DNS, {"field": field, "op": op, "values": [value]}]
    response = _search(_toolbox(repo, {"net-a": _keyword_contract("net-a")}, client), conditions)
    assert response["status"] == "refused"
    error = response["data"]["error"]
    assert error["code"] in {"search_unsupported", "invalid_arguments"}
    assert client.bodies == []


def test_a_date_field_takes_only_a_time_with_its_offset():
    contract = _keyword_contract("net-a", **{"event.start": "date"})
    plan = PivotExecutor(_hunt(), FakeES(), "h1", {"net-a": contract}).plan_search(_request([
        *DNS, {"field": "event.start", "op": "gte", "values": ["2024-11-18T14:05:00"]}]))
    assert plan.refusal is not None and "UTC offset" in json.dumps(plan.refusal)
    plan = PivotExecutor(_hunt(), FakeES(), "h1", {"net-a": contract}).plan_search(_request([
        *DNS, {"field": "event.start", "op": "gte", "values": ["2024-11-18T15:05:00+01:00"]}]))
    assert plan.refusal is None
    assert plan.intents[0].filters[1].value == "2024-11-18T14:05:00+00:00"


@pytest.mark.parametrize("window", [
    {"start": (T - timedelta(minutes=1)).isoformat()},
    {"end": (END + timedelta(seconds=1)).isoformat()},
    {"start": (T + timedelta(minutes=5)).isoformat(), "end": (T + timedelta(minutes=5)).isoformat()},
    {"start": "2024-11-18T14:05:00"},
])
def test_the_window_must_lie_inside_the_hunt_window(window):
    repo, client = _hunt(), FakeES()
    response = _search(_toolbox(repo, {"net-a": _keyword_contract("net-a")}, client), DNS, **window)
    assert response["status"] == "refused"
    assert client.bodies == []


def test_a_field_no_target_supports_is_refused_with_bounded_similar_fields():
    repo, client = _hunt(), FakeES()
    contract = contract_from_types("net-a", {"@timestamp": "date", "event.dataset": "keyword",
                                             **{f"zeek.files.f{n}": "keyword" for n in range(500)},
                                             "file.hash.sha256": "keyword", "file.hash.md5": "keyword",
                                             "process.hash.sha256": "keyword"}, role="network")
    response = _search(_toolbox(repo, {"net-a": contract}, client),
                       [{"field": "hash.sha256", "op": "eq", "values": ["ab" * 32]}])
    assert response["status"] == "refused"
    error = response["data"]["error"]
    assert error["code"] == "search_unsupported"
    assert error["reasons"] == ["conditions[].field: unsupported_field"]
    similar = [item["field"] for item in error["conditions"][0]["similar_fields"]]
    assert similar[:2] == ["file.hash.sha256", "process.hash.sha256"]
    assert len(similar) <= pivot_module.SEARCH_SIMILAR_FIELDS
    assert error["conditions"][0]["searchable_field_count"] == 504
    assert client.bodies == []


def test_an_op_the_field_type_does_not_take_is_refused_naming_the_ops_it_does():
    repo, client = _hunt(), FakeES()
    response = _search(_toolbox(repo, {"net-a": _keyword_contract("net-a")}, client),
                       [{"field": "destination.port", "op": "prefix", "values": ["443"]}])
    error = response["data"]["error"]
    assert response["status"] == "refused" and error["code"] == "search_unsupported"
    assert "takes eq, gte, in, lt" in error["targets"][0]["problem"]


def test_a_scope_with_no_source_is_refused():
    repo, client = _hunt(), FakeES()
    response = _search(_toolbox(repo, {"net-a": _keyword_contract("net-a")}, client), DNS, scope="host")
    assert response["status"] == "refused"
    assert response["data"]["error"]["code"] == "scope_has_no_source"


# ---- honest coverage ---------------------------------------------------------------------------------------------

def test_an_unsupported_field_on_one_of_two_targets_is_a_partial_naming_the_unevaluated_target():
    repo = _hunt()
    client = FakeES({"net-a": [_dns("net-a", 1, T + timedelta(minutes=3))]})
    other = contract_from_types("net-b", {"@timestamp": "date", "dns.query.name": "keyword"}, role="network")
    response = _search(_toolbox(repo, {"net-a": _keyword_contract("net-a"), "net-b": other}, client), DNS)
    assert response["status"] == "partial"
    assert [target for target, _body in client.bodies] == ["net-a"]
    reasons = response["data"]["result"]["reasons"]
    assert any(reason.startswith("not evaluated: net-b: field dns.question.name / op eq not supported")
               and "dns.query.name" in reason for reason in reasons)
    cell = next(cell for cell in response["data"]["result"]["coverage"] if cell["target"] == "net-b")
    assert cell["status"] == "partial" and cell["returned"] == 0 and cell["total"] is None
    assert cell["unresolved_ranges"]
    search = response["data"]["result"]["search"]
    assert search["negative"] == "matches_found" and len(response["data"]["result"]["evidence"]) == 1


def test_zero_hits_beside_an_unevaluated_target_is_unresolved_never_no_match():
    repo, client = _hunt(), FakeES()
    other = contract_from_types("net-b", {"@timestamp": "date"}, role="network")
    response = _search(_toolbox(repo, {"net-a": _keyword_contract("net-a"), "net-b": other}, client), DNS)
    assert response["status"] == "partial"
    search = response["data"]["result"]["search"]
    assert search["negative"] == "unresolved"
    assert any("not evaluated: net-b" in why for why in search["unresolved_because"])


def test_zero_hits_under_complete_coverage_is_a_real_no_match():
    repo, client = _hunt(), FakeES({"net-a": [], "net-b": []})
    contracts = {"net-a": _keyword_contract("net-a"), "net-b": _keyword_contract("net-b")}
    response = _search(_toolbox(repo, contracts, client), DNS)
    assert response["status"] == "complete"
    search = response["data"]["result"]["search"]
    assert search["negative"] == "no_match" and search["unresolved_because"] == []
    assert {cell["target"] for cell in response["data"]["result"]["coverage"]} == {"net-a", "net-b"}
    assert all(cell["status"] == "complete" for cell in response["data"]["result"]["coverage"])


def test_packet_captures_are_named_as_not_searched_and_keep_a_zero_unresolved():
    repo, client = _hunt(), FakeES({"net-a": []})
    toolbox = _toolbox(repo, {"net-a": _keyword_contract("net-a")}, client,
                       packet_sources=("packet captures behind arkime-sessions (Arkime viewer and TShark)",))
    response = _search(toolbox, DNS)
    search = response["data"]["result"]["search"]
    assert search["negative"] == "unresolved"
    assert search["not_searched"] == [(
        "packet captures behind arkime-sessions (Arkime viewer and TShark): not searched (scope unsupported for "
        "agent search)")]


def test_records_no_normalizer_reads_are_named_not_dropped():
    repo = _hunt()
    odd = {"_id": "odd", "_index": "net-a", "_source": {"@timestamp": (T + timedelta(minutes=2)).isoformat(),
                                                         "event": {"dataset": "custom.thing"}}}
    client = FakeES({"net-a": [odd]})
    response = _search(_toolbox(repo, {"net-a": _keyword_contract("net-a")}, client), DNS)
    assert response["status"] == "partial"
    assert any(reason.startswith("records_not_normalized:1:dataset:custom.thing")
               for reason in response["data"]["result"]["reasons"])
    assert response["data"]["result"]["search"]["negative"] == "unresolved"


def test_a_spent_query_budget_is_a_partial_unresolved_search():
    repo, client = _hunt(), FakeES({"net-a": []})
    response = _search(_toolbox(repo, {"net-a": _keyword_contract("net-a")}, client, budget=0), DNS)
    assert response["status"] == "partial"
    assert response["data"]["result"]["search"]["negative"] == "unresolved"
    assert "agent_source_query_budget:0" in response["data"]["result"]["reasons"]
    assert client.bodies == []


def test_cap_plus_one_spread_over_the_window_is_resolved_by_partitioning(monkeypatch):
    monkeypatch.setattr(pivot_module, "SEARCH_LEAF_RECORDS", 10)
    records = [_dns("net-a", n, T + timedelta(minutes=5 * n)) for n in range(11)]
    repo, client = _hunt(), FakeES({"net-a": records})
    response = _search(_toolbox(repo, {"net-a": _keyword_contract("net-a")}, client), DNS)
    assert response["status"] == "complete"
    assert response["counts"]["total"] == 11
    assert response["data"]["result"]["search"]["negative"] == "matches_found"


def test_records_past_the_cap_at_one_instant_are_an_honest_partial(monkeypatch):
    monkeypatch.setattr(pivot_module, "SEARCH_LEAF_RECORDS", 10)
    moment = T + timedelta(minutes=7)
    records = [_dns("net-a", n, moment) for n in range(31)]
    repo, client = _hunt(), FakeES({"net-a": records})
    response = _search(_toolbox(repo, {"net-a": _keyword_contract("net-a")}, client), DNS)
    assert response["status"] == "partial"
    reasons = response["data"]["result"]["reasons"]
    assert "cap:10<total:31" in reasons and "pivot_head_tail_sample" in reasons
    assert any(reason.startswith("pivot_min_split:") for reason in reasons)
    assert response["counts"]["total"] == 20                    # head and tail, every one shown, none invented
    partial = [cell for cell in response["data"]["result"]["coverage"] if cell["status"] == "partial"]
    assert partial and all(cell["unresolved_ranges"] for cell in partial)
    assert response["data"]["result"]["search"]["negative"] == "matches_found"


def test_the_partition_limit_is_named_and_zero_unresolved_is_never_claimed(monkeypatch):
    monkeypatch.setattr(pivot_module, "SEARCH_LEAF_RECORDS", 5)
    repo, client = _hunt(), FakeES(generated={"net-a": 1_000_000})
    response = _search(_toolbox(repo, {"net-a": _keyword_contract("net-a")}, client), DNS)
    assert response["status"] == "partial"
    assert f"pivot_partition_limit:{MAX_PIVOT_PARTITIONS}" in response["data"]["result"]["reasons"]
    assert response["data"]["result"]["search"]["negative"] == "matches_found"
    cells = response["data"]["result"]["coverage"]
    assert any(cell["unresolved_ranges"] for cell in cells)


# ---- literal values at the source --------------------------------------------------------------------------------

ADVERSARIAL = [
    'a"b', "a\\b", "a*b", "a?b", "a && b", "a || b", "(a)", "a)", "a\nb", "a\x00b", "x" * 256,
    "pаypal",                      # Cyrillic a
    "ｆｕｌｌ",         # fullwidth letters: never NFKC-folded to "full"
    "* OR 1:1", "field:value", "\\*", "{\"query_string\": 1}",
]


def _leaves(node, path=()):
    if isinstance(node, dict):
        for key, value in node.items():
            yield from _leaves(value, (*path, key))
    elif isinstance(node, list):
        for value in node:
            yield from _leaves(value, (*path, "[]"))
    else:
        yield path, node


def _clause_kinds(node) -> set[str]:
    return {part for path, _value in _leaves(node) for part in path}


def _assert_literal(body: dict, value: str):
    """The value is a JSON value in the body, and no clause that parses query syntax is anywhere in it."""
    assert {"query_string", "simple_query_string", "regexp", "script", "match"}.isdisjoint(_clause_kinds(body))
    assert json.loads(json.dumps(body)) == body
    assert any(leaf == value for _path, leaf in _leaves(body)), value


def test_adversarial_values_reach_the_source_only_as_literal_term_terms_and_prefix_values():
    contract = _keyword_contract("net-a")
    executor = PivotExecutor(_hunt(), FakeES(), "h1", {"net-a": contract})
    for value in ADVERSARIAL:
        for op in ("eq", "prefix"):
            if op == "prefix" and len(value) < 3:
                continue
            plan = executor.plan_search(_request([{"field": "dns.question.name", "op": op, "values": [value]}]))
            assert plan.refusal is None, value
            body = pivot_module.compile_es(plan.intents[0], contract).body
            clause = body["query"]["bool"]["filter"][1]
            assert clause == ({"term": {"dns.question.name": value}} if op == "eq"
                              else {"prefix": {"dns.question.name": {"value": value}}})
            _assert_literal(body, value)
    plan = executor.plan_search(_request([{"field": "dns.question.name", "op": "in", "values": ADVERSARIAL}]))
    clause = pivot_module.compile_es(plan.intents[0], contract).body["query"]["bool"]["filter"][1]
    assert clause == {"terms": {"dns.question.name": sorted(set(ADVERSARIAL))}}


def test_adversarial_values_on_case_insensitive_windows_paths_are_escaped_wildcards_only():
    spec = {"type": "keyword", "ops": ["eq", "in", "prefix", "exists", "missing"], "aggregatable": True}
    contract = FieldContract(target="win-a", os_family="windows", role="host", fields={
        "@timestamp": FieldSpec(native="@timestamp", type="date", ops=["gte", "lt"], aggregatable=True),
        "host.name": FieldSpec(native="winlog.computer_name", natives=("winlog.computer_name",), **spec),
        "event.channel": FieldSpec(native="winlog.channel", natives=("winlog.channel",), **spec),
        "process.command_line": FieldSpec(native="process.command_line", natives=("process.command_line",),
                                          type="text", ops=["eq", "in", "exists", "missing"], aggregatable=False,
                                          exact=("process.command_line.keyword",), exact_limit=64),
    })
    executor = PivotExecutor(_hunt(), FakeES(), "h1", {"win-a": contract})
    for value in ADVERSARIAL:
        plan = executor.plan_search(_request([{"field": "host.name", "op": "eq", "values": [value]},
                                              {"field": "event.channel", "op": "eq", "values": [value]},
                                              {"field": "process.command_line", "op": "eq", "values": [value]}],
                                             scope="host"))
        assert plan.refusal is None, value
        body = pivot_module.compile_es(plan.intents[0], contract).body
        assert {"query_string", "regexp", "script", "match", "simple_query_string"}.isdisjoint(_clause_kinds(body))
        wildcards = [leaf for path, leaf in _leaves(body) if "wildcard" in path and path[-1] == "value"]
        short = _escape_wildcard(value.strip().rstrip(".").split(".", 1)[0])
        assert set(wildcards) <= {_escape_wildcard(value), short, f"{short}.*"}
        for pattern in wildcards:
            # every * and ? the value held is escaped: only the compiler's own trailing ".*" is a wildcard
            unescaped = pattern.replace("\\\\", "").replace("\\*", "").replace("\\?", "")
            assert "?" not in unescaped and unescaped.count("*") <= (1 if pattern.endswith(".*") else 0)
        phrases = [leaf for path, leaf in _leaves(body) if "match_phrase" in path]
        terms = [leaf for path, leaf in _leaves(body) if "term" in path]
        assert (phrases == [value]) if len(value) > 64 else (terms == [value])


def test_an_account_value_without_its_kind_prefix_is_not_evaluated_and_never_reaches_the_source():
    contract = FieldContract(target="win-a", os_family="windows", role="host", fields={
        "@timestamp": FieldSpec(native="@timestamp", type="date", ops=["gte", "lt"], aggregatable=True),
        "user.entity_id": FieldSpec(native="winlog.event_data.TargetUserName",
                                    natives=("winlog.event_data.TargetUserName",), type="keyword",
                                    ops=["eq", "in"], aggregatable=True),
    })
    repo, client = _hunt(), FakeES({"win-a": []})
    response = _search(_toolbox(repo, {"win-a": contract}, client),
                       [{"field": "user.entity_id", "op": "eq", "values": ['ad"min*']}], scope="host")
    assert response["status"] == "refused"
    assert "cannot be compiled exactly" in response["data"]["error"]["targets"][0]["problem"]
    assert client.bodies == []
    response = _search(_toolbox(repo, {"win-a": contract}, client),
                       [{"field": "user.entity_id", "op": "eq", "values": ['name:CORP\\ad"min*']}], scope="host")
    assert response["status"] == "complete"
    (_target, body), = client.bodies
    assert body["query"]["bool"]["filter"][1] == {"wildcard": {"winlog.event_data.TargetUserName": {
        "value": 'ad"min\\*', "case_insensitive": True}}}


def test_a_compiled_clause_outside_the_allow_list_is_never_sent(monkeypatch):
    real = pivot_module.compile_es

    def hostile(intent, contract, flavor="elasticsearch"):
        compiled = real(intent, contract, flavor)
        compiled.body["query"]["bool"]["filter"].append({"query_string": {"query": "*"}})
        return compiled

    monkeypatch.setattr(pivot_module, "compile_es", hostile)
    repo, client = _hunt(), FakeES({"net-a": []})
    response = _search(_toolbox(repo, {"net-a": _keyword_contract("net-a")}, client), DNS)
    assert response["status"] == "refused"
    assert "query_string clause" in response["data"]["error"]["targets"][0]["problem"]
    assert client.bodies == []


def test_values_reach_the_wire_body_unchanged_through_the_real_executor():
    repo = _hunt()
    client = FakeES({"net-a": []})
    _search(_toolbox(repo, {"net-a": _keyword_contract("net-a")}, client),
            [{"field": "dns.question.name", "op": "in", "values": ADVERSARIAL}])
    (_target, body), = client.bodies
    assert body["query"]["bool"]["filter"][1] == {"terms": {"dns.question.name": sorted(set(ADVERSARIAL))}}
    assert "ｆｕｌｌ" in body["query"]["bool"]["filter"][1]["terms"]["dns.question.name"]
    assert "full" not in body["query"]["bool"]["filter"][1]["terms"]["dns.question.name"]


# ---- admission, budgets and dedupe -------------------------------------------------------------------------------

def test_a_finding_citing_search_evidence_is_admitted(tmp_path):
    repo = _hunt(tmp_path / "admit.sqlite")
    client = FakeES({"net-a": [_dns("net-a", 1, T + timedelta(minutes=4), "beacon.example")]})
    toolbox = _toolbox(repo, {"net-a": _keyword_contract("net-a")}, client)
    admission = AgentAdmission(Settings(home=tmp_path), repo, "h1", SESSION)
    admission.register(toolbox)
    anchor = AliasBook(repo, "h1").alias_for("F", "anchor")
    admission.issue_aliases({"finding": anchor})
    arguments = {"anchor": anchor, "scope": "network",
                 "conditions": [{"field": "dns.question.name", "op": "eq", "values": ["beacon.example"]}]}
    assert typed_alias_arguments("search_events", arguments) == {anchor}
    response = toolbox.execute("search_events", arguments)
    assert response["status"] == "complete"
    evidence = response["data"]["result"]["evidence"]
    assert len(evidence) == 1
    assert collect_issued_aliases(response, tool_name="search_events") >= set(evidence)
    admission.issue_aliases(response, tool_name="search_events")
    proposed = toolbox.execute("propose_finding", {
        "claim": "A host resolved a beacon domain found by search", "claim_kind": "network",
        "cites": evidence, "lane": "lead"})
    assert proposed["status"] == "complete", proposed
    links = [row for row in repo.expansion_links("h1") if row["link_type"] == "agent_search_events"]
    assert len(links) == 1 and links[0]["anchor_id"] == "anchor"
    assert links[0]["key"]["search"]["conditions"][0]["values"] == ["beacon.example"]
    assert links[0]["strength"] == "agent_hypothesis"


def test_a_repeated_search_is_deduplicated_and_spends_no_source_query():
    repo = _hunt()
    client = FakeES({"net-a": [_dns("net-a", 1, T + timedelta(minutes=4))]})
    toolbox = _toolbox(repo, {"net-a": _keyword_contract("net-a")}, client, budget=10)
    in_order = [{"field": "dns.question.name", "op": "in", "values": ["b.test", "example.test"]},
                {"field": "destination.port", "op": "eq", "values": ["53"]}]
    reordered = [{"field": "destination.port", "op": "eq", "values": ["53"]},
                 {"field": "dns.question.name", "op": "in", "values": ["example.test", "b.test", "b.test"]}]
    first = _search(toolbox, in_order)
    spent = repo.agent_source_queries("h1")
    again = _search(toolbox, reordered)
    assert spent >= 1 and repo.agent_source_queries("h1") == spent
    assert len(client.bodies) == 1
    assert first["data"]["result"]["cursor"] == again["data"]["result"]["cursor"]
    assert again["data"]["result"]["search"]["repeated"] is True
    assert first["data"]["result"]["search"]["repeated"] is False
    assert again["data"]["result"]["evidence"] == first["data"]["result"]["evidence"]


def test_each_search_spends_the_hunt_source_query_budget():
    repo = _hunt()
    client = FakeES({"net-a": []})
    toolbox = _toolbox(repo, {"net-a": _keyword_contract("net-a")}, client, budget=1)
    first = _search(toolbox, DNS)
    second = _search(toolbox, [{"field": "dns.question.name", "op": "eq", "values": ["other.test"]}])
    assert first["data"]["result"]["search"]["negative"] == "no_match"
    assert second["status"] == "partial"
    assert second["data"]["result"]["search"]["negative"] == "unresolved"
    assert repo.agent_source_queries("h1") == 1


# ---- tool surface ------------------------------------------------------------------------------------------------

def test_search_events_is_a_loose_tool_and_the_strict_grammar_budget_holds(tmp_path):
    from romulus.agent.provider.claude_messages import (
        GRAMMAR_BUDGET,
        strict_schema_problems,
        strict_wire_schema,
    )

    repo = _hunt()
    toolbox = Toolbox(repo, "h1")
    AgentAdmission(Settings(home=tmp_path), repo, "h1", SESSION).register(toolbox)
    tools = {tool.name: tool for tool in toolbox.provider_tools()}
    assert "search_events" in tools and not tools["search_events"].strict
    strict = [tool for tool in tools.values() if tool.strict]
    assert len(strict) <= GRAMMAR_BUDGET["tools"]
    counts: dict = {}
    for tool in strict:
        assert strict_schema_problems(strict_wire_schema(tool.parameters), counts) == []
    for key in ("optional", "union", "properties", "enum"):
        assert counts[key] <= GRAMMAR_BUDGET[key], key
    # the loose schema is still a closed object the strict form of every adapter can carry
    wire = strict_wire_schema(tools["search_events"].parameters)
    assert wire["additionalProperties"] is False
    assert set(wire["properties"]) == {"anchor", "scope", "conditions", "start", "end", "page", "cursor",
                                       "chunk_index"}
    condition = tools["search_events"].parameters["$defs"]["SearchCondition"]
    assert condition["properties"]["op"]["enum"] == ["eq", "in", "prefix", "cidr", "gte", "lt"]
    assert "target" not in json.dumps(tools["search_events"].parameters["properties"])


def test_the_prompt_and_catalog_name_the_tool():
    from importlib import resources

    prompt = resources.files("romulus.agent.prompts").joinpath("investigate.md").read_text(encoding="utf-8")
    assert "search_events" in prompt and "no_match" in prompt
    assert "search_events" in tool_catalog()
    assert "contains" not in tool_catalog()["search_events"]["arguments"]


# ---- bounds at mission scale -------------------------------------------------------------------------------------

def test_a_search_over_many_dense_targets_stays_bounded_and_names_what_it_did_not_evaluate(monkeypatch):
    monkeypatch.setattr(pivot_module, "SEARCH_LEAF_RECORDS", 20)
    monkeypatch.setattr(pivot_module, "MAX_SEARCH_RECORDS", 400)
    targets = [f"net-{n:02d}" for n in range(12)]
    repo = _hunt()
    # every target claims fifty million matching records in the window
    client = FakeES(generated={target: 50_000_000 for target in targets})
    toolbox = _toolbox(repo, {target: _keyword_contract(target) for target in targets}, client)
    response = _search(toolbox, DNS)

    per_target = MAX_PIVOT_PARTITIONS * pivot_module.MAX_SAMPLE_QUERIES * 20
    assert response["status"] == "partial"
    # each query held at most the leaf cap, and one target took at most its splits, leaves and samples
    queries = {}
    for target, _body in client.bodies:
        queries[target] = queries.get(target, 0) + 1
    assert max(queries.values()) <= 2 * MAX_PIVOT_PARTITIONS - 1 + MAX_PIVOT_PARTITIONS * pivot_module.MAX_SAMPLE_QUERIES
    assert client.returned <= 20 * len(client.bodies)
    reasons = response["data"]["result"]["reasons"]
    searched = {target for target, _body in client.bodies}
    unevaluated = {target for target in targets if f"search_record_limit:400: not evaluated: {target}" in reasons}
    assert searched and unevaluated and searched | unevaluated == set(targets) and not searched & unevaluated
    assert len(response["data"]["result"]["evidence"]) <= 50
    assert len(response["data"]["result"]["event_summaries"]) <= 50
    assert len(json.dumps(response["data"]["result"]["event_summaries"]).encode()) <= TELEMETRY_RESPONSE_BYTES * 2
    assert response["more"] is True
    assert response["counts"]["total"] <= 400 + per_target
    links = [row for row in repo.expansion_links("h1") if row["link_type"] == "agent_search_events"]
    assert len(links[0]["event_ids"]) <= 400 + per_target


def test_the_search_bounds_hold_for_the_real_constants():
    assert pivot_module.MAX_SEARCH_TARGET_RECORDS == (
        MAX_PIVOT_PARTITIONS * pivot_module.MAX_SAMPLE_QUERIES * pivot_module.SEARCH_LEAF_RECORDS)
    # one search's rows stay well under the hunt's page-item ceiling
    from romulus.store.repo import AGENT_PAGE_ITEM_LIMIT
    assert pivot_module.MAX_SEARCH_RECORDS + pivot_module.MAX_SEARCH_TARGET_RECORDS < AGENT_PAGE_ITEM_LIMIT // 3


def _request(conditions, *, scope="network") -> SearchEventsRequest:
    return SearchEventsRequest(tool="search_events", arguments=SearchEventsArgs.model_validate({
        "scope": scope, "conditions": conditions, "start": T, "end": END}))


def test_a_tool_without_a_reach_link_type_is_refused_before_any_source_query():
    class Unlisted:
        tool = "unlisted_tool"

    class NoPivot:
        def run(self, *_args, **_kwargs):
            raise AssertionError("an unlisted tool reached the source")

    executor = HuntToolExecutor(_hunt(), "h1", NoPivot(), None, T, END)
    result = executor.run(SESSION, "anchor", Unlisted(), anchor_ts=T)
    assert result.status == "unsupported"
    assert result.reasons == ["tool unlisted_tool has no agent reach link type"]
