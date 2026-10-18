"""ES adapter safety, compiler strictness, and completeness accounting."""
from datetime import UTC, datetime

import httpx
import pytest

from romulus.config import Settings
from romulus.sources.compile import CompileError, compile_es
from romulus.sources.es import ElasticClient, WriteAttemptBlocked, check_allowed
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


def test_shard_failure_and_lower_bound_totals_are_partial():
    client = ElasticClient(Settings(es_url="http://es"), transport=_pit_transport([[1]], 1, shard_fail=True))
    out = execute(client, SearchIntent(kind="raw", target="idx", window=W), C)
    assert out.completeness == Completeness.partial and any("shard" in r for r in out.reasons)
    client = ElasticClient(Settings(es_url="http://es"), transport=_pit_transport([[1]], 10000, relation="gte"))
    out = execute(client, SearchIntent(kind="raw", target="idx", window=W), C)
    assert out.completeness == Completeness.partial
