"""ES adapter safety, compiler strictness, and completeness accounting."""
import json
from datetime import UTC, datetime

import httpx
import pytest

from romulus.config import Settings
from romulus.sources.compile import CompileError, compile_es
from romulus.sources.es import (
    FIELD_CAPS_FILTER_PATH,
    MAPPING_FILTER_PATH,
    PIT_CLOSE_FILTER_PATH,
    PIT_OPEN_FILTER_PATH,
    SEARCH_FILTER_PATH,
    ElasticClient,
    WriteAttemptBlocked,
    check_allowed,
)
from romulus.sources.execute import execute
from romulus.sources.models import Completeness, Predicate, SearchIntent, Window
from romulus.sources.profile import contract_from_types

W = Window(start=datetime(2024, 11, 18, 14, tzinfo=UTC), end=datetime(2024, 11, 18, 15, tzinfo=UTC))
TYPES = {"@timestamp": "date", "event.dataset": "keyword", "process.command_line": "wildcard",
         "message": "text", "source.ip": "ip", "destination.port": "long", "host.name": "keyword"}
C = contract_from_types("idx", TYPES)


@pytest.mark.parametrize("method,path", [
    ("PUT", "/idx/_doc/1"), ("POST", "/idx/_doc"), ("POST", "/_bulk"), ("POST", "/idx/_update/1"),
    ("POST", "/idx/_delete_by_query"), ("POST", "/idx/_update_by_query"), ("DELETE", "/idx"),
    ("PUT", "/idx/_mapping"), ("PUT", "/_cluster/settings"), ("POST", "/_reindex"),
    ("PUT", "/_security/user/x"), ("POST", "/_snapshot/r/s"), ("GET", "/_cat/indices"),
])
def test_write_capable_requests_are_refused(method, path):
    with pytest.raises(WriteAttemptBlocked):
        check_allowed(method, path)


def test_refusal_happens_before_any_network_io():
    calls = []
    transport = httpx.MockTransport(lambda r: calls.append(r) or httpx.Response(200, json={}))
    client = ElasticClient(Settings(es_url="http://es"), transport=transport)
    with pytest.raises(WriteAttemptBlocked):
        client.request("DELETE", "/idx")
    with pytest.raises(WriteAttemptBlocked):
        client.request("POST", "/idx/_search", {"query": {"script": {"script": "x"}}})
    assert calls == []


def test_compiler_rejects_unknown_field_and_unsafe_ops():
    with pytest.raises(CompileError):
        compile_es(SearchIntent(kind="raw", target="idx", window=W,
                                filters=[Predicate(field="nope.field", op="eq", value=1)]), C)
    # text fields are analyzed; 'contains' would not be a retrieval superset
    with pytest.raises(CompileError):
        compile_es(SearchIntent(kind="raw", target="idx", window=W,
                                filters=[Predicate(field="message", op="contains", value="x")]), C)
    with pytest.raises(CompileError):
        compile_es(SearchIntent(kind="aggregate", target="idx", window=W, group_by=["message"]), C)


def test_predicate_field_names_cannot_inject():
    with pytest.raises(ValueError):
        Predicate(field='a"}},{"script', op="eq", value=1)


def test_contains_escapes_wildcard_metacharacters():
    q = compile_es(SearchIntent(kind="raw", target="idx", window=W,
                                filters=[Predicate(field="process.command_line", op="contains", value="a*b?")]), C)
    wc = q.body["query"]["bool"]["filter"][1]["wildcard"]["process.command_line"]
    assert wc["value"] == r"*a\*b\?*" and wc["case_insensitive"] is True


def test_window_is_half_open_utc():
    q = compile_es(SearchIntent(kind="raw", target="idx", window=W), C)
    rng = q.body["query"]["bool"]["filter"][0]["range"]["@timestamp"]
    assert set(rng) >= {"gte", "lt"} and "lte" not in rng and "gt" not in rng
    with pytest.raises(ValueError):
        Window(start=datetime(2024, 1, 2, tzinfo=UTC), end=datetime(2024, 1, 1, tzinfo=UTC))


def test_raw_retrieval_order_is_typed_and_compiled():
    q = compile_es(SearchIntent(kind="raw", target="idx", window=W, order="desc"), C)

    assert q.body["sort"] == [
        {"@timestamp": {"order": "desc", "format": "strict_date_optional_time_nanos"}},
        {"_shard_doc": "desc"},
    ]


def test_pit_retrieval_preserves_compiled_descending_order():
    seen = []

    def handler(req: httpx.Request):
        if req.url.path.endswith("/_pit") and req.method == "POST":
            return httpx.Response(200, json={"id": "pit1"})
        if req.url.path == "/_pit":
            return httpx.Response(200, json={"succeeded": True})
        if req.url.path == "/":
            return httpx.Response(200, json={"version": {"number": "9.5.5"}})
        seen.append(json.loads(req.content))
        return httpx.Response(200, json={
            "pit_id": "pit1", "timed_out": False, "_shards": {"failed": 0},
            "hits": {"total": {"value": 0, "relation": "eq"}, "hits": []},
        })

    client = ElasticClient(Settings(es_url="http://es"), transport=httpx.MockTransport(handler))
    execute(client, SearchIntent(kind="raw", target="idx", window=W, order="desc"), C)

    assert seen[0]["sort"] == [
        {"@timestamp": {"order": "desc", "format": "strict_date_optional_time_nanos"}},
        {"_shard_doc": "desc"},
    ]


def test_execute_calls_can_share_one_rotating_pit_session():
    opened = []
    searched_pits = []
    deleted = []

    def handler(req: httpx.Request):
        body = json.loads(req.content) if req.content else {}
        if req.url.path == "/idx/_pit" and req.method == "POST":
            opened.append(req.url.path)
            return httpx.Response(200, json={"id": "pit1"})
        if req.url.path == "/_search":
            searched_pits.append(body["pit"]["id"])
            next_pit = "pit2" if len(searched_pits) == 1 else "pit3"
            return httpx.Response(200, json={
                "pit_id": next_pit,
                "timed_out": False,
                "_shards": {"failed": 0},
                "hits": {"total": {"value": 0, "relation": "eq"}, "hits": []},
            })
        if req.url.path == "/_pit" and req.method == "DELETE":
            deleted.append(body["id"])
            return httpx.Response(200, json={"succeeded": True})
        if req.url.path == "/":
            return httpx.Response(200, json={"version": {"number": "9.5.5"}})
        raise AssertionError(f"unexpected request {req.method} {req.url.path}")

    client = ElasticClient(Settings(es_url="http://es"), transport=httpx.MockTransport(handler))
    intent = SearchIntent(kind="raw", target="idx", window=W)

    with client.point_in_time("idx") as pit:
        first = execute(client, intent, C, pit=pit)
        second = execute(client, intent, C, pit=pit)

    assert first.completeness == second.completeness == Completeness.complete
    assert opened == ["/idx/_pit"]
    assert searched_pits == ["pit1", "pit2"]
    assert deleted == ["pit3"]


def test_raw_search_limits_source_and_every_transport_envelope():
    requests = []

    def handler(req: httpx.Request):
        requests.append(req)
        if req.url.path == "/idx/_mapping":
            return httpx.Response(200, json={"idx": {"mappings": {"properties": {}}}})
        if req.url.path == "/idx/_field_caps":
            return httpx.Response(200, json={"fields": {"@timestamp": {"date": {"type": "date"}}}})
        if req.url.path == "/idx/_pit" and req.method == "POST":
            return httpx.Response(200, json={"id": "pit1"})
        if req.url.path == "/_search":
            return httpx.Response(200, json={
                "pit_id": "pit1", "timed_out": False, "_shards": {"failed": 0},
                "hits": {"total": {"value": 0, "relation": "eq"}, "hits": []},
            })
        if req.url.path == "/_pit" and req.method == "DELETE":
            return httpx.Response(200, json={"succeeded": True})
        raise AssertionError(f"unexpected request {req.method} {req.url.path}")

    client = ElasticClient(Settings(es_url="http://es"), transport=httpx.MockTransport(handler))
    assert "idx" in client.mapping("idx")
    assert "@timestamp" in client.field_caps("idx")["fields"]
    query = compile_es(SearchIntent(kind="raw", target="idx", window=W), C)
    assert list(client.iterate(query, max_records=10)) == [([], {
        "problems": [], "total": 0, "total_relation": "eq",
    })]

    by_path = {(request.method, request.url.path): request for request in requests}
    assert by_path[("GET", "/idx/_mapping")].url.params["filter_path"] == MAPPING_FILTER_PATH
    field_caps = by_path[("GET", "/idx/_field_caps")]
    assert field_caps.url.params["filter_path"] == FIELD_CAPS_FILTER_PATH
    assert field_caps.url.params["fields"] == "*"
    pit_open = by_path[("POST", "/idx/_pit")]
    assert pit_open.url.params["filter_path"] == PIT_OPEN_FILTER_PATH
    search = by_path[("POST", "/_search")]
    assert search.url.params["filter_path"] == SEARCH_FILTER_PATH
    # the raw copy and its digest are the whole _source: trimming it would change citation identity
    assert "_source" not in json.loads(search.content)
    assert by_path[("DELETE", "/_pit")].url.params["filter_path"] == PIT_CLOSE_FILTER_PATH


def _pit_transport(pages, total, relation="eq", shard_fail=False):
    state = {"i": 0}

    def handler(req: httpx.Request):
        if req.url.path.endswith("/_pit") and req.method == "POST":
            return httpx.Response(200, json={"id": "pit1"})
        if req.url.path == "/_pit":
            return httpx.Response(200, json={"succeeded": True})
        if req.url.path == "/":
            return httpx.Response(200, json={"version": {"number": "9.5.5"}})
        page = pages[state["i"]] if state["i"] < len(pages) else []
        state["i"] += 1
        hits = [{"_id": f"d{n}", "_index": "idx", "_source": {"n": n}, "sort": [n, n]} for n in page]
        body = {"pit_id": "pit1", "timed_out": False, "_shards": {"failed": 1 if shard_fail else 0},
                "hits": {"total": {"value": total, "relation": relation}, "hits": hits}}
        return httpx.Response(200, json=body)
    return httpx.MockTransport(handler)


def test_raw_retrieval_complete_only_when_everything_fetched():
    client = ElasticClient(Settings(es_url="http://es"), transport=_pit_transport([[1, 2], [3]], 3))
    out = execute(client, SearchIntent(kind="raw", target="idx", window=W, max_records=2), C)
    # max_records=2 caps below total=3 -> partial with explicit reason
    assert out.completeness == Completeness.partial
    assert any(r.startswith("cap:") for r in out.reasons)


def test_raw_retrieval_stops_at_physical_page_and_deadline_budgets():
    client = ElasticClient(
        Settings(es_url="http://es"), transport=_pit_transport([list(range(2000)), [2000]], 2001),
    )
    spent = 0

    def reserve():
        nonlocal spent
        if spent >= 1:
            return False
        spent += 1
        return True

    out = execute(
        client, SearchIntent(kind="raw", target="idx", window=W, max_records=3000), C,
        on_query=reserve,
    )
    assert spent == 1 and out.returned == 2000
    assert out.completeness == Completeness.partial
    assert "source query budget exhausted" in out.reasons

    ticks = iter((0.0, 11.0))
    timed = execute(
        ElasticClient(Settings(es_url="http://es"), transport=_pit_transport([[1]], 1)),
        SearchIntent(kind="raw", target="idx", window=W, max_records=1), C,
        deadline=10.0, clock=lambda: next(ticks),
    )
    assert timed.completeness == Completeness.partial
    assert "source wall-clock budget exhausted" in timed.reasons


def test_shard_failure_and_lower_bound_totals_are_partial():
    client = ElasticClient(Settings(es_url="http://es"), transport=_pit_transport([[1]], 1, shard_fail=True))
    out = execute(client, SearchIntent(kind="raw", target="idx", window=W), C)
    assert out.completeness == Completeness.partial and any("shard" in r for r in out.reasons)
    client = ElasticClient(Settings(es_url="http://es"), transport=_pit_transport([[1]], 10000, relation="gte"))
    out = execute(client, SearchIntent(kind="raw", target="idx", window=W), C)
    assert out.completeness == Completeness.partial


def _resolve_client(payload):
    transport = httpx.MockTransport(lambda r: httpx.Response(200, json=payload))
    return ElasticClient(Settings(es_url="http://es"), transport=transport)


def test_resolve_includes_data_streams_without_double_counting_backing_indices():
    c = _resolve_client({"indices": [{"name": ".ds-logs-a-000001"}, {"name": "plain-idx"}],
                         "aliases": [{"name": "alias-x"}],
                         "data_streams": [{"name": "logs-a", "backing_indices": [".ds-logs-a-000001"]}]})
    assert c.resolve("*") == ["logs-a", "plain-idx"]


def test_resolve_empty_pattern_is_empty_and_hunt_creation_refuses(tmp_path, monkeypatch):
    from romulus.hunt import run as hr
    assert _resolve_client({"indices": [], "aliases": [], "data_streams": []}).resolve("nothing-*") == []
    monkeypatch.setattr(hr.ElasticClient, "resolve", lambda self, p: [])
    s = Settings(home=tmp_path, es_index_patterns=["nothing-*"])
    with pytest.raises(ValueError, match="resolves to no index"):
        hr.create_hunt(s, W.start, W.end, created_by="t")
    assert hr.open_repo(s).list_hunts() == []
