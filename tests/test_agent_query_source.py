"""The AI agent's own source queries (query_source): the boundary that decides what reaches a source.

Every refusal is checked on what the fake source received (nothing), every accepted query on the exact body and
target it received. No test reaches a real cluster, viewer or model.
"""
from __future__ import annotations

import json
from datetime import timedelta

import httpx
import pytest

from romulus.agent.admission import AgentAdmission, collect_issued_aliases, typed_alias_arguments
from romulus.agent.aliases import AliasBook
from romulus.agent.toolbox import QUERY_CHUNK_BYTES, Toolbox
from romulus.config import Settings
from romulus.hunt.agent_tools import HuntToolExecutor
from romulus.hunt.links import LinkFetcher
from romulus.hunt.pivot import PivotExecutor
from romulus.sources import agent_query as aq
from romulus.sources.es import ElasticClient, SourceError
from romulus.sources.packets import ArkimeSessionHits, ArkimeSessionSearch
from romulus.sources.profile import contract_from_types
from tests.test_agent_search_events import END, SESSION, T, _dns, _hunt, _keyword_contract

SECRET = "s3cret-Pa55word-value"
ES_400 = ('HTTP 400 POST /net-a/_search: {"error":{"root_cause":[{"type":"parsing_exception","reason":"unknown query '
          '[wildcardd]","line":1,"col":62}],"type":"parsing_exception","reason":"unknown query [wildcardd]"},'
          '"status":400}')


class QueryES:
    """A source that records each search it receives and answers with a fixed response (or raises)."""

    version = "8.19.0"

    class settings:
        es_flavor = "elasticsearch"

    def __init__(self, response: dict | None = None, error: Exception | None = None):
        self.response = response if response is not None else _response([])
        self.error = error
        self.calls: list[tuple[str, dict]] = []

    def search(self, target, body):
        self.calls.append((target, json.loads(json.dumps(body))))
        if self.error is not None:
            raise self.error
        return self.response


class FakeViewer:
    def __init__(self, hits: ArkimeSessionHits):
        self.hits = hits
        self.calls = []

    def search(self, expression, start, end, length):
        self.calls.append((expression, start, end, length))
        return self.hits


def _response(hits: list[dict], total: int | None = None, **extra) -> dict:
    return {"hits": {"total": {"value": len(hits) if total is None else total, "relation": "eq"}, "hits": hits},
            **extra}


def _arkime_contract(target="arkime-a"):
    return contract_from_types(target, {"firstPacket": "date", "lastPacket": "date",
                                        "network.community_id": "keyword", "source.ip": "ip"}, role="network")


def _box(client, *, contracts=None, settings=None, viewer=None, budget=None, repo=None) -> Toolbox:
    repo = repo or _hunt()
    contracts = contracts or {"net-a": _keyword_contract("net-a"), "host-a": _keyword_contract("host-a", "host")}
    pivot = PivotExecutor(repo, client, "h1", contracts, source_query_budget=budget,
                          source_query_scope="agent" if budget is not None else None)
    executor = HuntToolExecutor(repo, "h1", pivot, LinkFetcher(pivot, T, END), T, END, settings=settings,
                                arkime_search=viewer)
    return Toolbox(repo, "h1", executor=executor, session_id=SESSION)


def _query(toolbox: Toolbox, **arguments) -> dict:
    anchor = AliasBook(toolbox.repo, "h1").alias_for("F", "anchor")
    return toolbox.execute("query_source", {"anchor": anchor, "source": "net-a", **arguments})


def _nest(clause: dict, depth: int) -> dict:
    for _ in range(depth):
        clause = {"bool": {"filter": [clause]}}
    return clause


TERM = {"term": {"dns.question.name": "example.test"}}

# ---- refusals: nothing reaches the source ------------------------------------------------------------------------

FORBIDDEN_QUERIES = [
    {"script": {"script": {"source": "doc['a'].value > 1"}}},
    _nest({"script": {"script": "1"}}, 12),
    {"script_score": {"query": TERM, "script": {"source": "1"}}},
    {"function_score": {"query": TERM, "functions": []}},
    {"percolate": {"field": "q", "document": {}}},
    {"wrapper": {"query": "eyJtYXRjaF9hbGwiOnt9fQ=="}},
    {"more_like_this": {"fields": ["a"], "like": [{"_index": "other", "_id": "1"}]}},
    {"terms": {"user.name": {"index": "other-index", "id": "1", "path": "names"}}},
    _nest({"terms": {"user.name": {"index": "other-index", "id": "1", "path": "names"}}}, 6),
    {"geo_shape": {"location": {"indexed_shape": {"index": "shapes", "id": "1", "path": "s"}}}},
    {"knn": {"field": "v", "query_vector": [1], "k": 1}},
    {"has_child": {"type": "c", "query": TERM}},
    {"semantic": {"field": "a", "query": "b"}},
    {"bool": {"filter": [TERM], "should": [{"match": {"a": {"query": "x", "params": {}}}}]}},
    {"intervals": {"a": {"match": {"query": "x"}}}},
    {"bool": {"must": TERM, "extra_key": 1}},
    {"term": {"a": "x", "b": "y"}},
    {"match_all": {}, "term": {"a": "b"}},
    {"query_string": {"query": "a:b", "fields": ["a"], "script": "x"}},
    {"term": {"a": "\x00x"}},
    {"term": {"a": "x" * (aq.MAX_TEXT_CHARS + 1)}},
    _nest(TERM, aq.MAX_QUERY_DEPTH),
]


@pytest.mark.parametrize("query", FORBIDDEN_QUERIES, ids=range(len(FORBIDDEN_QUERIES)))
def test_a_forbidden_query_construct_is_refused_and_never_sent(query):
    client = QueryES()
    result = _query(_box(client), query=query)
    assert result["status"] == "refused", result
    assert result["data"]["error"]["code"] == "query_refused"
    assert client.calls == []


FORBIDDEN_AGGS = [
    {"all": {"global": {}, "aggs": {"n": {"value_count": {"field": "a"}}}}},
    {"c": {"children": {"type": "answer"}}},
    {"p": {"parent": {"type": "question"}}},
    {"s": {"significant_terms": {"field": "a"}}},
    {"m": {"scripted_metric": {"map_script": "x"}}},
    {"t": {"terms": {"field": "a"}, "aggs": {"b": {"bucket_script": {"script": "1"}}}}},
    {"t": {"terms": {"field": "a", "min_doc_count": 0}}},
    {"t": {"terms": {"field": "a", "size": 101}}},
    {"t": {"terms": {"field": "a", "size": "100000"}}},
    {"t": {"terms": {"field": "a", "size": 10.0}}},
    {"t": {"terms": {"field": "a", "size": True}}},
    {"t": {"terms": {"field": "a", "script": {"source": "1"}}}},
    {"t": {"terms": {"field": "a", "size": 100}, "aggs": {"u": {"terms": {"field": "b", "size": 100}, "aggs": {
        "v": {"terms": {"field": "c", "size": 2}}}}}}},
    {"t": {"terms": {"field": "a"}, "aggs": {"u": {"terms": {"field": "b"}, "aggs": {"v": {"terms": {
        "field": "c"}, "aggs": {"w": {"terms": {"field": "d"}}}}}}}}},
    {f"a{n}": {"value_count": {"field": "a"}} for n in range(aq.MAX_AGGREGATIONS + 1)},
    {"h": {"date_histogram": {"field": "@timestamp", "fixed_interval": "1s"}}},
    {"h": {"date_histogram": {"field": "@timestamp", "fixed_interval": "1h", "extended_bounds": {
        "min": "2000-01-01", "max": "2030-01-01"}}}},
    {"h": {"histogram": {"field": "destination.port", "interval": 1}}},
    {"r": {"rare_terms": {"field": "a"}}},
    {"x": {"top_hits": {"size": 11}}},
    {"t": {"terms": {"field": "a", "size": 100}, "aggs": {"u": {"terms": {"field": "b", "size": 100}, "aggs": {
        "x": {"top_hits": {"size": 10}}}}}}},
    {"t": {"terms": {"field": "a", "size": 20}, "aggs": {"x": {"top_hits": {"size": 10}}}}},
    {"x": {"top_hits": {"script_fields": {"a": {"script": "1"}}}}},
    {"x": {"top_hits": {"docvalue_fields": ["a"]}}},
    {"bad name": {"value_count": {"field": "a"}}},
    {"f": {"filter": {"script": {"script": "1"}}}},
]


@pytest.mark.parametrize("aggs", FORBIDDEN_AGGS, ids=range(len(FORBIDDEN_AGGS)))
def test_a_forbidden_or_unbounded_aggregation_is_refused_and_never_sent(aggs):
    client = QueryES()
    result = _query(_box(client), aggs=aggs, size=0)
    assert result["status"] == "refused", result
    assert client.calls == []


@pytest.mark.parametrize("arguments", [
    {"sort": [{"_script": {"type": "number", "script": "1"}}]},
    {"sort": [{"a": {"order": "sideways"}}]},
    {"sort": [{"a": {"nested": {"path": "x"}}}]},
    {"source_fields": ["a b"]},
    {"query": TERM, "size": 101},
    {"source": "other-index", "query": TERM},
    {"source": "net-a,other", "query": TERM},
    {"source": "_all", "query": TERM},
    {"source": "net-a/_delete_by_query", "query": TERM},
    {"source": "arkime:net-a", "expression": "ip.src == 10.0.0.1"},
    {"expression": "ip.src == 10.0.0.1"},
    {},
])
def test_a_query_outside_the_source_or_its_shape_is_refused_and_never_sent(arguments):
    client = QueryES()
    result = _query(_box(client), **arguments)
    assert result["status"] == "refused", result
    assert client.calls == []


# ---- what is sent ------------------------------------------------------------------------------------------------

def test_the_query_is_anded_with_the_window_on_the_named_source_only_with_its_caps():
    client = QueryES()
    query = {"wildcard": {"dns.question.name": {"value": "*.example.test"}}}
    aggs = {"top": {"terms": {"field": "dns.question.name", "size": 50}}}
    result = _query(_box(client), query=query, aggs=aggs, size=7, sort=[{"@timestamp": "desc"}],
                    start=(T - timedelta(days=3)).isoformat(), end=(END + timedelta(days=3)).isoformat())
    assert result["status"] == "complete"
    [(target, body)] = client.calls
    assert target == "net-a"
    window, sent = body["query"]["bool"]["filter"]
    assert sent == query and set(body["query"]) == {"bool"} and set(body["query"]["bool"]) == {"filter"}
    assert window == {"range": {"@timestamp": {"gte": T.isoformat(), "lt": END.isoformat(),
                                               "format": "strict_date_optional_time"}}}
    assert body["size"] == 7 and body["aggs"] == aggs and body["sort"] == [{"@timestamp": "desc"}]
    assert body["timeout"] == aq.QUERY_TIMEOUT and body["terminate_after"] == aq.TERMINATE_AFTER
    assert body["track_total_hits"] == aq.TRACK_TOTAL_HITS
    assert set(body) == {"query", "size", "timeout", "terminate_after", "track_total_hits", "sort", "aggs"}
    assert result["data"]["result"]["search"]["window_clamped"] is True


def test_the_real_client_sends_only_a_search_of_the_named_index():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path, dict(request.url.params), json.loads(request.content)))
        return httpx.Response(200, json=_response([]))

    client = ElasticClient(Settings(es_url="http://es.invalid"), transport=httpx.MockTransport(handler))
    result = _query(_box(client), query=TERM)
    assert result["data"]["result"]["search"]["negative"] == "unresolved"
    [(method, path, params, body)] = seen
    assert (method, path) == ("POST", "/net-a/_search")
    assert params["allow_partial_search_results"] == "false"
    assert body["query"]["bool"]["filter"][1] == TERM


def test_a_window_outside_the_hunt_is_refused():
    client = QueryES()
    result = _query(_box(client), query=TERM, start=(END + timedelta(hours=1)).isoformat())
    assert result["status"] == "refused" and result["data"]["error"]["code"] == "outside_hunt_window"
    assert client.calls == []


# ---- results -----------------------------------------------------------------------------------------------------

def test_zero_hits_is_unresolved_never_an_absence():
    result = _query(_box(QueryES(_response([]))), query=TERM)
    search = result["data"]["result"]["search"]
    assert search["negative"] == "unresolved"
    assert search["statement"] == "nothing matched this query in this source; this is not a confirmed absence"
    counts_only = _query(_box(QueryES(_response([], total=12, aggregations={"n": {"value": 12}}))),
                         aggs={"n": {"value_count": {"field": "dns.question.name"}}}, size=0)
    assert counts_only["data"]["result"]["search"]["negative"] == "matches_found"


def test_returned_records_are_citable_evidence_and_rows_past_the_size_are_named():
    hits = [_dns("net-a", n, T + timedelta(minutes=n)) for n in range(3)]
    toolbox = _box(QueryES(_response(hits, total=40)))
    result = _query(toolbox, query=TERM, size=3)
    assert result["status"] == "partial"
    evidence = result["data"]["result"]["evidence"]
    assert len(evidence) == 3 and all(alias.startswith("E") for alias in evidence)
    ids = [AliasBook(toolbox.repo, "h1").resolve(alias, {"E"}) for alias in evidence]
    assert len(toolbox.repo.citation_events("h1", ids)) == 3
    search = result["data"]["result"]["search"]
    assert search["negative"] == "matches_found" and search["total"] == {"value": 40, "relation": "eq"}
    assert any("40 records matched; the first 3 were returned" in reason for reason in search["gaps_and_caveats"])
    rows = json.loads(search["rows_and_aggregations"]["text"])["rows"]
    assert {row["id"] for row in rows} == {hit["_id"] for hit in hits} and all(row["citable"] for row in rows)
    assert "event_ids" not in json.dumps(rows)


def test_a_source_error_round_trips_as_refusal_text_and_a_repeat_is_not_sent_again():
    client = QueryES(error=SourceError(ES_400, status=400))
    toolbox = _box(client)
    first = _query(toolbox, query=TERM)
    assert first["status"] == "refused" and first["data"]["error"]["code"] == "source_query_error"
    assert "unknown query [wildcardd]" in first["data"]["error"]["message"]
    assert first["errors"] and "unknown query" in first["errors"][0]
    again = _query(toolbox, query=TERM)
    assert again["status"] == "refused" and again["data"]["result"]["search"]["repeated"] is True
    assert len(client.calls) == 1


@pytest.mark.parametrize("error", [SourceError("timeout POST /net-a/_search", retryable=True),
                                   SourceError("HTTP 403 POST /net-a/_search: no read", status=403),
                                   SourceError("HTTP 404 POST /net-a/_search: no such index", status=404),
                                   SourceError("HTTP 503 POST /net-a/_search: busy", retryable=True, status=503),
                                   SourceError("HTTP 429 POST /net-a/_search: too many", retryable=True, status=429)])
def test_a_timeout_or_source_failure_is_unresolved_not_a_query_to_correct(error):
    result = _query(_box(QueryES(error=error)), query=TERM)
    assert result["status"] == "failed"
    search = result["data"]["result"]["search"]
    assert search["negative"] == "unresolved" and search["query_error"] is None


def test_a_timed_out_or_early_stopped_answer_is_partial_and_says_so():
    response = _response([], timed_out=True, terminated_early=True)
    result = _query(_box(QueryES(response)), query=TERM)
    reasons = " ".join(result["data"]["result"]["search"]["gaps_and_caveats"])
    assert result["status"] == "partial" and "timed out" in reasons and "stopped early" in reasons
    assert result["data"]["result"]["search"]["negative"] == "unresolved"


def test_a_large_aggregation_answer_is_bounded_and_counted():
    buckets = [{"key": f"host-{n}", "doc_count": 1} for n in range(5_000)]
    toolbox = _box(QueryES(_response([], total=5_000, aggregations={"top": {"buckets": buckets}})))
    result = _query(toolbox, aggs={"top": {"terms": {"field": "dns.question.name", "size": 100}}}, size=0)
    search = result["data"]["result"]["search"]
    assert result["status"] == "partial"
    chunk = search["rows_and_aggregations"]
    text = "".join(_query(toolbox, aggs={"top": {"terms": {"field": "dns.question.name", "size": 100}}}, size=0,
                          chunk_index=index)["data"]["result"]["search"]["rows_and_aggregations"]["text"]
                   for index in range(1, chunk["chunk_count"] + 1))
    shown = json.loads(text)["aggregations"]["top"]
    assert len(shown["buckets"]) == aq.MAX_BUCKETS_SHOWN and shown["buckets_not_shown"] == 4_900
    assert len(chunk["text"].encode("utf-8")) <= QUERY_CHUNK_BYTES
    assert any("4900 aggregation bucket(s) not shown" in reason for reason in search["gaps_and_caveats"])


def test_secrets_are_redacted_from_what_is_stored_and_shown():
    settings = Settings(es_password=SECRET)
    hit = _dns("net-a", 1, T + timedelta(minutes=1))
    hit["_source"]["note"] = f"password={SECRET}"
    toolbox = _box(QueryES(_response([hit], aggregations={"a": {"buckets": [{"key": SECRET, "doc_count": 1}]}})),
                   settings=settings)
    result = _query(toolbox, query=TERM, aggs={"a": {"terms": {"field": "note"}}})
    cursor = result["data"]["result"]["cursor"]
    stored = json.dumps(toolbox.repo.agent_page_plan("h1", cursor)["summary"])
    assert SECRET not in stored and "<redacted>" in stored
    assert SECRET not in json.dumps(result)
    failing = _box(QueryES(error=SourceError(f"HTTP 400 POST /net-a/_search: bad value {SECRET}", status=400)),
                   settings=settings)
    refused = _query(failing, query=TERM)
    assert SECRET not in json.dumps(refused) and "<redacted>" in refused["data"]["error"]["message"]


# ---- budget ------------------------------------------------------------------------------------------------------

def test_each_query_spends_the_agent_budget_once_and_a_repeat_spends_nothing():
    client = QueryES()
    toolbox = _box(client, budget=5)
    _query(toolbox, query=TERM)
    assert toolbox.repo.agent_source_queries("h1") == 1
    _query(toolbox, query=TERM)
    assert toolbox.repo.agent_source_queries("h1") == 1 and len(client.calls) == 1
    _query(toolbox, query={"term": {"dns.question.name": "other.test"}})
    assert toolbox.repo.agent_source_queries("h1") == 2


def test_a_spent_budget_queries_nothing_and_is_unresolved():
    client = QueryES()
    toolbox = _box(client, budget=1)
    _query(toolbox, query=TERM)
    result = _query(toolbox, query={"term": {"dns.question.name": "other.test"}})
    assert result["status"] == "failed" and len(client.calls) == 1
    assert result["data"]["result"]["search"]["negative"] == "unresolved"


# ---- Arkime --------------------------------------------------------------------------------------------------------

def _arkime_hit(sid: str) -> dict:
    return {"_index": "arkime-a", "_id": sid, "_source": {
        "firstPacket": int((T + timedelta(minutes=2)).timestamp() * 1000),
        "lastPacket": int((T + timedelta(minutes=3)).timestamp() * 1000),
        "source": {"ip": "10.0.0.8", "port": 5555}, "destination": {"ip": "10.0.0.9", "port": 445},
        "network": {"community_id": "1:x"}, "ipProtocol": 6, "protocol": ["tcp", "smb"]}}


def test_an_arkime_expression_is_run_by_the_viewer_and_its_sessions_read_from_the_index_in_the_window():
    viewer = FakeViewer(ArkimeSessionHits(ids=["241118-AbCdEfGhIj", "241118-ZzZzZzZzZz", "bad id"], matched=7))
    client = QueryES(_response([_arkime_hit("241118-AbCdEfGhIj")]))
    toolbox = _box(client, contracts={"arkime-a": _arkime_contract()}, viewer=viewer, budget=10)
    result = _query(toolbox, source="arkime:arkime-a", expression="ip.dst == 10.0.0.9 && port.dst == 445")
    [(expression, start, end, length)] = viewer.calls
    assert expression == "ip.dst == 10.0.0.9 && port.dst == 445" and (start, end) == (T, END) and length == 100
    [(target, body)] = client.calls
    assert target == "arkime-a"
    window, ids = body["query"]["bool"]["filter"]
    assert "firstPacket" in window["range"] and ids == {"ids": {"values": ["241118-AbCdEfGhIj",
                                                                           "241118-ZzZzZzZzZz"]}}
    reasons = " ".join(result["data"]["result"]["search"]["gaps_and_caveats"])
    assert "matched 7 sessions" in reasons and "without a usable session id" in reasons
    assert "1 viewer session(s) are not records of this source in the window" in reasons
    assert toolbox.repo.agent_source_queries("h1") == 2


def test_an_arkime_expression_error_is_refusal_text_and_nothing_else_is_queried():
    viewer = FakeViewer(ArkimeSessionHits(query_error="Unknown field ip.dts"))
    client = QueryES()
    toolbox = _box(client, contracts={"arkime-a": _arkime_contract()}, viewer=viewer)
    result = _query(toolbox, source="arkime:arkime-a", expression="ip.dts == 1.2.3.4")
    assert result["status"] == "refused" and "Unknown field ip.dts" in result["data"]["error"]["message"]
    assert client.calls == []
    refused = _query(toolbox, source="arkime:arkime-a", query=TERM)
    assert refused["status"] == "refused" and len(viewer.calls) == 1


def test_the_viewer_search_sends_only_the_allowlisted_read_with_the_window():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path, dict(request.url.params)))
        return httpx.Response(200, json={"recordsTotal": 99, "recordsFiltered": 2,
                                         "data": [{"id": "241118-AbCdEfGhIj"}, {"id": "241118-ZzZzZzZzZz"}]})

    viewer = ArkimeSessionSearch(Settings(arkime_url="http://viewer.invalid"), transport=httpx.MockTransport(handler))
    found = viewer.search("ip.src == 10.0.0.1", T, END + timedelta(milliseconds=1), 100)
    assert found.ids == ["241118-AbCdEfGhIj", "241118-ZzZzZzZzZz"] and found.matched == 2
    [(method, path, params)] = seen
    assert (method, path) == ("GET", "/api/sessions")
    assert params == {"expression": "ip.src == 10.0.0.1", "startTime": str(int(T.timestamp())),
                      "stopTime": str(int(END.timestamp()) + 1), "bounding": "first", "length": "100",
                      "order": "firstPacket:asc"}
    for response, attribute in ((httpx.Response(400, text="bad expression"), "query_error"),
                                (httpx.Response(200, json={"bsqErr": "Unknown field"}), "query_error"),
                                (httpx.Response(500), "error"), (httpx.Response(200, json=[]), "error")):
        result = ArkimeSessionSearch(Settings(), transport=httpx.MockTransport(
            lambda request, response=response: response)).search("a == 1", T, END, 10)
        assert getattr(result, attribute) and not result.ids


def test_the_query_source_tool_is_loose_and_its_definition_is_fixed_text():
    toolbox = Toolbox(_hunt(), "h1")
    tool = next(item for item in toolbox.provider_tools() if item.name == "query_source")
    assert tool.strict is False
    assert set(tool.parameters["properties"]) == {"anchor", "source", "query", "expression", "aggs", "sort",
                                                  "size", "source_fields", "start", "end", "page", "cursor",
                                                  "chunk_index"}
    assert _query(toolbox, query=TERM)["status"] in {"unsupported", "refused"}


def test_a_small_top_hits_under_one_bucket_level_is_accepted():
    client = QueryES()
    result = _query(_box(client), size=0, aggs={"t": {"terms": {"field": "a", "size": 10}, "aggs": {
        "x": {"top_hits": {"size": 10, "_source": ["a", "b.*"], "sort": [{"@timestamp": "desc"}]}}}}})
    assert result["status"] == "complete" and len(client.calls) == 1


def test_a_finding_citing_query_evidence_is_admitted(tmp_path):
    repo = _hunt(tmp_path / "admit.sqlite")
    toolbox = _box(QueryES(_response([_dns("net-a", 1, T + timedelta(minutes=4), "beacon.example")])), repo=repo)
    admission = AgentAdmission(Settings(home=tmp_path), repo, "h1", SESSION)
    admission.register(toolbox)
    anchor = AliasBook(repo, "h1").alias_for("F", "anchor")
    admission.issue_aliases({"finding": anchor})
    arguments = {"anchor": anchor, "source": "net-a",
                 "query": {"wildcard": {"dns.question.name": {"value": "beacon.*"}}}}
    assert typed_alias_arguments("query_source", arguments) == {anchor}
    response = toolbox.execute("query_source", arguments)
    evidence = response["data"]["result"]["evidence"]
    assert response["status"] == "complete" and len(evidence) == 1
    assert collect_issued_aliases(response, tool_name="query_source") >= set(evidence)
    admission.issue_aliases(response, tool_name="query_source")
    proposed = toolbox.execute("propose_finding", {
        "claim": "A host resolved a beacon domain found by a query", "claim_kind": "network",
        "cites": evidence, "lane": "lead"})
    assert proposed["status"] == "complete", proposed
    links = [row for row in repo.expansion_links("h1") if row["link_type"] == "agent_query_source"]
    assert len(links) == 1 and links[0]["strength"] == "agent_hypothesis"
    assert links[0]["key"]["query"]["source"] == "net-a"


def test_the_session_share_bounds_the_agent_queries():
    client = QueryES()
    toolbox = _box(client, budget=50)
    toolbox.executor.pivot.configure_agent_shares(session_id=SESSION, purpose="investigate", session_share=1,
                                                  call_slice=1)
    assert _query(toolbox, query=TERM)["status"] == "complete"
    second = _query(toolbox, query={"term": {"dns.question.name": "other.test"}})
    assert second["status"] == "failed" and len(client.calls) == 1
    assert second["data"]["result"]["search"]["negative"] == "unresolved"
    assert toolbox.repo.agent_source_queries("h1") == 1
