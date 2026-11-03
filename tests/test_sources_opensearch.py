"""OpenSearch flavor: request table, flavor and version detection, point in time, and paging by whole tie groups.

The recorded responses in tests/data/opensearch_responses.json are synthetic values in the shapes OpenSearch
documents:
- `GET /`: https://docs.opensearch.org/latest/api-reference/cluster-api/info/ (`version.distribution`).
- Point in time (2.4+): https://docs.opensearch.org/latest/api-reference/search-apis/point-in-time-api/
  (create answers `pit_id`; delete takes `{"pit_id": [...]}` and answers `{"pits": [{"successful", "pit_id"}]}`).
- `_resolve/index`: https://docs.opensearch.org/latest/api-reference/index-apis/resolve-index/;
  `_field_caps`: https://docs.opensearch.org/latest/api-reference/search-apis/field-caps/.
- authinfo: opensearch-project/security SecurityInfoAction.java; no handler: OpenSearch RestController (HTTP 400,
  "no handler found for uri [...] and method [...]").
- `_shard_doc` tie-breaking only from 3.3.0 (opensearch-project/OpenSearch#18924, release notes 3.3.0).
"""
import json
import re
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from romulus.config import Settings
from romulus.sources import es as es_module
from romulus.sources.es import (
    ALLOWLIST,
    ALLOWLISTS,
    OPENSEARCH_ALLOWLIST,
    OPENSEARCH_PIT_CLOSE_FILTER_PATH,
    OPENSEARCH_PIT_OPEN_FILTER_PATH,
    BackendRefused,
    ElasticClient,
    SourceError,
    WriteAttemptBlocked,
    backend_refusal,
    check_allowed,
    detect_backend,
)
from romulus.sources.execute import execute
from romulus.sources.models import CompiledQuery, Completeness, SearchIntent, Window
from romulus.sources.profile import contract_from_types

RESPONSES = json.loads((Path(__file__).parent / "data" / "opensearch_responses.json").read_text(encoding="utf-8"))
TARGET = "arkime_sessions3-241118"
WINDOW = Window(start=datetime(2024, 11, 18, 14, tzinfo=UTC), end=datetime(2024, 11, 18, 15, tzinfo=UTC))


def recorded(name: str) -> httpx.Response:
    entry = RESPONSES[name]
    if "body" in entry:
        return httpx.Response(entry["status"], json=entry["body"], headers=entry.get("headers"))
    return httpx.Response(entry["status"], text=entry["text"], headers=entry.get("headers"))


class FakeOpenSearch:
    """Answers each allowlisted OpenSearch request with a recorded response and fails the test on any request that
    the OpenSearch table would refuse (the client must never send one)."""

    def __init__(self, root="root_opensearch_2.11.1", authinfo="authinfo_read_only_roles", pages=None):
        self.root, self.authinfo = root, authinfo
        self.pages = list(pages or [RESPONSES["pit_search_page"]["body"]])
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        method, path = request.method, request.url.path
        check_allowed(method, path, "opensearch")
        if path == "/":
            return recorded(self.root)
        if path == "/_plugins/_security/authinfo":
            return recorded(self.authinfo)
        if path.startswith("/_resolve/index/"):
            return recorded("resolve_index")
        if path.endswith("/_field_caps"):
            return recorded("field_caps")
        if path.endswith("/_search/point_in_time") and method == "POST":
            return recorded("pit_open")
        if path == "/_search/point_in_time" and method == "DELETE":
            return recorded("pit_close")
        if path == "/_search":
            body = self.pages.pop(0) if self.pages else {
                "pit_id": "c3ludGhldGljLXBpdC0x", "timed_out": False, "_shards": {"failed": 0},
                "hits": {"total": {"value": 2, "relation": "eq"}, "hits": []}}
            return httpx.Response(200, json=body)
        raise AssertionError(f"unexpected request {method} {path}")

    def sent(self) -> list[str]:
        return [f"{r.method} {r.url.path}" for r in self.requests]


def os_client(fake, **settings) -> ElasticClient:
    return ElasticClient(Settings(es_url="http://os.invalid", es_flavor="opensearch", **settings),
                         transport=httpx.MockTransport(fake))


def query(order: str = "asc") -> CompiledQuery:
    body = {"query": {"match_all": {}},
            "sort": [{"@timestamp": {"order": order, "format": "strict_date_optional_time_nanos"}},
                     {"_shard_doc": order}]}
    return CompiledQuery(backend="opensearch", target=TARGET, body=body, fingerprint="f")


# ---- request tables ---------------------------------------------------------------------------------------------

WRITE_SHAPED = [
    ("PUT", "/idx/_doc/1"), ("POST", "/idx/_doc"), ("POST", "/_bulk"), ("POST", "/idx/_bulk"),
    ("POST", "/idx/_update/1"), ("POST", "/idx/_delete_by_query"), ("POST", "/idx/_update_by_query"),
    ("DELETE", "/idx"), ("DELETE", "/idx/_doc/1"), ("PUT", "/idx"), ("PUT", "/idx/_mapping"),
    ("PUT", "/_cluster/settings"), ("POST", "/_reindex"), ("POST", "/_snapshot/r/s"), ("GET", "/_cat/indices"),
    ("POST", "/idx/_close"), ("POST", "/idx/_open"), ("POST", "/_aliases"), ("PUT", "/_index_template/t"),
    ("PUT", "/_ingest/pipeline/p"), ("POST", "/_scripts/s"), ("POST", "/_search/scroll"), ("DELETE", "/_search/scroll"),
    ("GET", "/_search/point_in_time/_all"), ("DELETE", "/_search/point_in_time/_all"),
    ("PUT", "/_plugins/_security/api/internalusers/x"), ("PATCH", "/_plugins/_security/api/rolesmapping"),
    ("DELETE", "/_plugins/_security/api/roles/x"), ("PUT", "/_plugins/_security/api/roles/x"),
    ("POST", "/_plugins/_security/authinfo"), ("POST", "/_plugins/_ism/add/idx"), ("POST", "/_plugins/_sql"),
    ("POST", "/_plugins/_ppl"), ("POST", "/_plugins/_asynchronous_search"), ("DELETE", "/_plugins/_ism/policies/p"),
    ("GET", "/idx/_search"), ("PUT", "/idx/_search"), ("DELETE", "/idx/_search/point_in_time"),
    ("POST", "/_search/point_in_time"), ("GET", "/idx/_doc/1"), ("POST", "/idx/_msearch"),
    ("POST", "/idx/_search/template"), ("POST", "/_render/template"), ("POST", "/idx/_forcemerge"),
    ("POST", "/idx/_refresh"), ("POST", "/_nodes/reload_secure_settings"), ("POST", "/_cluster/reroute"),
    ("DELETE", "/_pit"), ("POST", "/idx/_pit"),
]


@pytest.mark.parametrize("method,path", WRITE_SHAPED)
def test_opensearch_table_refuses_everything_but_its_reads(method, path):
    with pytest.raises(WriteAttemptBlocked):
        check_allowed(method, path, "opensearch")


@pytest.mark.parametrize("method,path", [
    ("DELETE", "/_search/point_in_time"), ("POST", "/idx/_search/point_in_time"),
    ("GET", "/_plugins/_security/authinfo"), ("PUT", "/idx/_doc/1"), ("POST", "/_bulk"),
])
def test_elasticsearch_table_refuses_opensearch_paths_and_writes(method, path):
    with pytest.raises(WriteAttemptBlocked):
        check_allowed(method, path, "elasticsearch")


@pytest.mark.parametrize("method,path", [
    ("GET", "/_security/_authenticate"), ("POST", "/_security/user/_has_privileges"),
])
def test_opensearch_table_refuses_elasticsearch_security_paths(method, path):
    with pytest.raises(WriteAttemptBlocked):
        check_allowed(method, path, "opensearch")


def test_unknown_flavor_refuses_everything():
    with pytest.raises(WriteAttemptBlocked):
        check_allowed("GET", "/", "solr")


def test_the_only_delete_in_either_table_releases_one_point_in_time():
    deletes = {flavor: [rx.pattern for method, rx in table if method == "DELETE"]
               for flavor, table in ALLOWLISTS.items()}
    assert deletes == {"elasticsearch": [r"^/_pit$"], "opensearch": [r"^/_search/point_in_time$"]}
    # no write verb at all, in either table
    assert {method for table in (ALLOWLIST, OPENSEARCH_ALLOWLIST) for method, _rx in table} == {"GET", "POST", "DELETE"}


def test_every_post_in_the_opensearch_table_is_a_read():
    posts = sorted(rx.pattern for method, rx in OPENSEARCH_ALLOWLIST if method == "POST")
    assert all(re.search(r"/(_search|_count|_search/point_in_time)\$$", p) for p in posts), posts


@pytest.mark.parametrize("key", sorted(es_module.FORBIDDEN_QUERY_KEYS))
def test_opensearch_client_refuses_forbidden_body_keys_before_any_io(key):
    fake = FakeOpenSearch()
    client = os_client(fake)
    with pytest.raises(WriteAttemptBlocked):
        client.request("POST", f"/{TARGET}/_search", {"query": {"bool": {"filter": [{key: {"x": 1}}]}}})
    with pytest.raises(WriteAttemptBlocked):
        client.request("DELETE", f"/{TARGET}")
    assert fake.requests == []


def test_every_request_of_a_full_opensearch_read_is_on_the_opensearch_table():
    fake = FakeOpenSearch()
    client = os_client(fake)
    client.resolve("arkime_sessions3-*")
    client.field_caps(TARGET)
    client.authinfo()
    list(client.iterate(query(), max_records=10))
    # FakeOpenSearch checked each request against the table as it arrived
    assert fake.sent() == ["GET /", "GET /_resolve/index/arkime_sessions3-*", f"GET /{TARGET}/_field_caps",
                           "GET /_plugins/_security/authinfo", f"POST /{TARGET}/_search/point_in_time",
                           "POST /_search", "DELETE /_search/point_in_time"]


# ---- flavor and version ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("name,distribution,version", [
    ("root_opensearch_2.3.0", "opensearch", (2, 3, 0)),
    ("root_opensearch_2.11.1", "opensearch", (2, 11, 1)),
    ("root_opensearch_3.3.0", "opensearch", (3, 3, 0)),
    ("root_opensearch_compat_7.10.2", "opensearch", (7, 10, 2)),
    ("root_elasticsearch_8.15.0", "elasticsearch", (8, 15, 0)),
    ("root_elasticsearch_7.17.0", "elasticsearch", (7, 17, 0)),
])
def test_distribution_and_version_come_from_get_root(name, distribution, version):
    backend = detect_backend(RESPONSES[name]["body"])
    assert (backend.distribution, backend.version) == (distribution, version)


def test_unreadable_version_is_none():
    assert detect_backend({}).version is None and detect_backend({}).distribution == "elasticsearch"
    assert detect_backend({"version": {"distribution": "opensearch", "number": "x"}}).version is None
    assert detect_backend({"version": "2.11"}).distribution == "elasticsearch"


@pytest.mark.parametrize("flavor,name,refused", [
    ("opensearch", "root_opensearch_2.3.0", "no point-in-time search"),
    ("opensearch", "root_opensearch_compat_7.10.2", "Elasticsearch-compatible version"),
    ("opensearch", "root_elasticsearch_8.15.0", "ES_FLAVOR=opensearch, but the cluster reports elasticsearch"),
    ("elasticsearch", "root_opensearch_2.11.1", "ES_FLAVOR=elasticsearch, but the cluster reports opensearch"),
    ("opensearch", "root_opensearch_2.11.1", None),
    ("opensearch", "root_opensearch_3.3.0", None),
    ("elasticsearch", "root_elasticsearch_8.15.0", None),
])
def test_backend_refusal(flavor, name, refused):
    reason = backend_refusal(flavor, detect_backend(RESPONSES[name]["body"]))
    assert (reason is None) if refused is None else (refused in reason)


@pytest.mark.parametrize("root", ["root_opensearch_2.3.0", "root_elasticsearch_8.15.0",
                                  "root_opensearch_compat_7.10.2"])
def test_opensearch_client_refuses_to_run_before_any_data_request(root):
    fake = FakeOpenSearch(root=root)
    client = os_client(fake)
    with pytest.raises(BackendRefused):
        client.resolve("arkime_sessions3-*")
    with pytest.raises(BackendRefused):
        list(client.iterate(query(), max_records=10))
    assert fake.sent() == ["GET /"]                 # nothing but the flavor check ever left the process


def test_opensearch_below_2_4_is_a_failed_search_never_a_paged_one():
    fake = FakeOpenSearch(root="root_opensearch_2.3.0")
    contract = contract_from_types(TARGET, {"@timestamp": "date"})
    out = execute(os_client(fake), SearchIntent(kind="raw", target=TARGET, window=WINDOW), contract)
    assert out.completeness == Completeness.failed and "no point-in-time search" in out.error
    assert fake.sent() == ["GET /"]


def test_elasticsearch_client_latches_a_refusal_when_get_root_names_opensearch():
    calls = []

    def handler(request):
        calls.append(request.url.path)
        return recorded("root_opensearch_2.11.1") if request.url.path == "/" else httpx.Response(200, json={})

    client = ElasticClient(Settings(es_url="http://es.invalid"), transport=httpx.MockTransport(handler))
    with pytest.raises(BackendRefused, match="ES_FLAVOR=elasticsearch"):
        client.info()
    assert client.version == "2.11.1"               # known, so an outcome can still name it
    with pytest.raises(BackendRefused):
        client.mapping(TARGET)
    assert calls == ["/"]


def test_probe_reports_without_raising():
    fake = FakeOpenSearch(root="root_opensearch_2.3.0")
    client = os_client(fake)
    info, backend, refusal = client.probe()
    assert info["cluster_name"] == "example-cluster" and backend.version == (2, 3, 0)
    assert "OpenSearch 2.4 or later" in refusal and client.refusal == refusal


# ---- point in time ---------------------------------------------------------------------------------------------

def test_opensearch_point_in_time_open_search_and_close_follow_the_documented_shapes():
    fake = FakeOpenSearch()
    pages = list(os_client(fake).iterate(query(), max_records=10))
    assert [h["_id"] for hits, _meta in pages for h in hits] == ["r1", "r2"]
    opened, search, closed = fake.requests[1], fake.requests[2], fake.requests[-1]
    assert (opened.method, opened.url.path) == ("POST", f"/{TARGET}/_search/point_in_time")
    assert dict(opened.url.params) == {"keep_alive": "2m", "allow_partial_pit_creation": "false",
                                       "filter_path": OPENSEARCH_PIT_OPEN_FILTER_PATH}
    assert opened.content == b""
    body = json.loads(search.content)
    assert (search.method, search.url.path) == ("POST", "/_search")       # no index beside a PIT
    assert body["pit"] == {"id": "c3ludGhldGljLXBpdC0x", "keep_alive": "2m"} and body["track_total_hits"] is True
    assert (closed.method, closed.url.path) == ("DELETE", "/_search/point_in_time")
    assert json.loads(closed.content) == {"pit_id": ["c3ludGhldGljLXBpdC0x"]}
    assert closed.url.params["filter_path"] == OPENSEARCH_PIT_CLOSE_FILTER_PATH


def test_opensearch_3_3_pages_with_the_shard_doc_tiebreaker_like_elasticsearch():
    fake = FakeOpenSearch(root="root_opensearch_3.3.0")
    list(os_client(fake).iterate(query("desc"), max_records=10))
    body = json.loads(fake.requests[2].content)
    assert body["sort"] == query("desc").body["sort"]


def test_a_shared_opensearch_point_in_time_is_opened_and_released_once():
    fake = FakeOpenSearch(root="root_opensearch_3.3.0", pages=[])
    client = os_client(fake)
    with client.point_in_time(TARGET) as pit:
        list(client.iterate(query(), max_records=10, pit=pit))
        list(client.iterate(query(), max_records=10, pit=pit))
    assert fake.sent().count(f"POST /{TARGET}/_search/point_in_time") == 1
    assert fake.sent().count("DELETE /_search/point_in_time") == 1


# ---- paging by whole tie groups (OpenSearch before 3.3) ----------------------------------------------------------

class TieSearch:
    """An OpenSearch-before-3.3 search over one point in time: `search_after` continues strictly after the sort
    values (records tied on them are skipped, as Lucene does), `_shard_doc` does not exist, and from/size pages a
    query in a fixed order. Records carry many identical times so ties fall on page boundaries."""

    def __init__(self, times: list[str], root="root_opensearch_2.11.1"):
        # (time, shard order) per record; ties are kept in a fixed per-PIT order
        self.docs = [{"_index": TARGET, "_id": f"d{i:04d}", "_source": {"n": i}, "time": t, "doc": (i * 7919) % 1000}
                     for i, t in enumerate(times)]
        self.root = root
        self.requests: list[dict] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        check_allowed(request.method, path, "opensearch")
        if path == "/":
            return recorded(self.root)
        if path.endswith("/_search/point_in_time"):
            return recorded("pit_open") if request.method == "POST" else recorded("pit_close")
        body = json.loads(request.content)
        self.requests.append(body)
        assert "_shard_doc" not in json.dumps(body["sort"]), "OpenSearch before 3.3 has no _shard_doc"
        (field, spec), = body["sort"][0].items()
        assert field == "@timestamp"
        desc = spec["order"] == "desc"
        matching = self.docs
        exact = _exact_time(body["query"])
        if exact is not None:
            matching = [d for d in matching if d["time"] == exact]
        total = len(matching)
        ordered = sorted(matching, key=lambda d: (d["time"], d["doc"]), reverse=desc)
        if "search_after" in body:
            after = body["search_after"][0]
            ordered = [d for d in ordered if (d["time"] < after if desc else d["time"] > after)]
        start = body.get("from", 0)
        page = ordered[start:start + body["size"]]
        with_doc = len(body["sort"]) > 1
        hits = [{"_index": d["_index"], "_id": d["_id"], "_source": d["_source"],
                 "sort": [d["time"], d["doc"]] if with_doc else [d["time"]]} for d in page]
        return httpx.Response(200, json={"pit_id": "c3ludGhldGljLXBpdC0x", "timed_out": False, "_shards": {"failed": 0},
                                         "hits": {"total": {"value": total, "relation": "eq"}, "hits": hits}})


def _exact_time(q: dict):
    for clause in (q.get("bool") or {}).get("filter", []):
        rng = (clause.get("range") or {}).get("@timestamp")
        if rng and rng.get("gte") == rng.get("lte"):
            return rng["gte"]
    return None


def _times(counts: list[int]) -> list[str]:
    return [f"2024-11-18T14:00:{second:02d}.000Z" for second, n in enumerate(counts) for _ in range(n)]


@pytest.mark.parametrize("order", ["asc", "desc"])
@pytest.mark.parametrize("counts,page_size", [
    ([3, 4, 1, 5, 2, 7, 1], 4),          # groups straddle almost every page boundary
    ([10, 1, 1], 4),                     # a whole page (and more) of one time
    ([1] * 9, 3),                        # no ties at all
    ([4, 4, 4], 4),                      # groups exactly fill pages
    ([2, 9, 2, 11, 1], 5),
])
def test_tie_groups_read_every_record_exactly_once(order, counts, page_size):
    search = TieSearch(_times(counts))
    client = ElasticClient(Settings(es_url="http://os.invalid", es_flavor="opensearch"),
                           transport=httpx.MockTransport(search))
    pages = list(client.iterate(query(order), max_records=10_000, page_size=page_size))
    ids = [h["_id"] for hits, _meta in pages for h in hits]
    assert sorted(ids) == sorted(d["_id"] for d in search.docs) and len(ids) == len(set(ids))
    times = [search.docs[int(i[1:])]["time"] for i in ids]
    assert times == sorted(times, reverse=order == "desc")
    assert all(meta["total"] == len(search.docs) and meta["problems"] == [] for _hits, meta in pages)


def test_a_search_after_on_time_alone_would_skip_tied_records():
    """Why tie groups are read whole: the same backend, paged naively, loses records at page boundaries."""
    search = TieSearch(_times([3, 4, 1, 5]))
    seen, after = [], None
    while True:
        body = {"query": {"match_all": {}}, "size": 4,
                "sort": [{"@timestamp": {"order": "asc", "format": "strict_date_optional_time_nanos"}}]}
        if after is not None:
            body["search_after"] = [after]
        hits = json.loads(search(httpx.Request("POST", "http://os.invalid/_search", json=body)).content)["hits"]["hits"]
        seen += hits
        if len(hits) < 4:
            break
        after = hits[-1]["sort"][0]
    assert len(seen) < len(search.docs)


def test_a_tie_group_beyond_the_result_window_is_read_in_part_and_says_so(monkeypatch):
    monkeypatch.setattr(es_module, "TIE_GROUP_WINDOW", 6)
    search = TieSearch(_times([2, 9, 1]))
    client = ElasticClient(Settings(es_url="http://os.invalid", es_flavor="opensearch"),
                           transport=httpx.MockTransport(search))
    pages = list(client.iterate(query(), max_records=10_000, page_size=4))
    ids = [h["_id"] for hits, _meta in pages for h in hits]
    problems = [p for _hits, meta in pages for p in meta["problems"]]
    assert problems == ["tie_group_window:@timestamp=2024-11-18T14:00:01.000Z:6<total:9"]
    assert len(ids) == len(set(ids)) == 2 + 6 + 1      # 3 records of the large group were not read, and it says so
    assert pages[-1][1]["total"] == 12


def test_tie_group_requests_count_against_the_query_budget():
    search = TieSearch(_times([3, 4, 1, 5]))
    client = ElasticClient(Settings(es_url="http://os.invalid", es_flavor="opensearch"),
                           transport=httpx.MockTransport(search))
    spent = 0

    def reserve():
        nonlocal spent
        spent += 1
        return True

    list(client.iterate(query(), max_records=10_000, page_size=4, on_query=reserve))
    assert spent == len(search.requests) + 2        # every search, plus the PIT open and close


def test_tie_paging_refuses_an_order_it_cannot_page_by_groups():
    search = TieSearch(_times([2, 2]))
    client = ElasticClient(Settings(es_url="http://os.invalid", es_flavor="opensearch"),
                           transport=httpx.MockTransport(search))
    q = CompiledQuery(backend="opensearch", target=TARGET, fingerprint="f",
                      body={"query": {"match_all": {}}, "sort": [{"host.name": "asc"}, {"@timestamp": "asc"}]})
    with pytest.raises(SourceError, match="no _shard_doc tiebreaker"):
        list(client.iterate(q, max_records=10))
