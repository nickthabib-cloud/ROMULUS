"""OpenSearch flavor: request table, flavor and version detection, point in time, and paging by whole tie groups.

The recorded responses in tests/data/opensearch_responses.json are synthetic values in the shapes OpenSearch
documents:
- `GET /`: https://docs.opensearch.org/latest/api-reference/cluster-api/info/ (`version.distribution`); in
  compatibility mode the distribution is omitted and 7.10.2 reported, the tagline unchanged (server
  org/opensearch/action/main/MainResponse.java).
- Point in time (2.4+): https://docs.opensearch.org/latest/api-reference/search-apis/point-in-time-api/
  (create answers `pit_id`; delete takes `{"pit_id": [...]}` and answers `{"pits": [{"successful", "pit_id"}]}`).
- `_resolve/index`: https://docs.opensearch.org/latest/api-reference/index-apis/resolve-index/;
  `_field_caps`: https://docs.opensearch.org/latest/api-reference/search-apis/field-caps/.
- authinfo: opensearch-project/security SecurityInfoAction.java; no handler: OpenSearch RestController (HTTP 400,
  "no handler found for uri [...] and method [...]").
- Field sorts: server org/opensearch/search/sort/FieldSortBuilder.java (2.4 through 3.3) parses only order, missing,
  mode, unmapped_type, numeric_type, nested_path, nested_filter and nested, and refuses any other key; with no
  `format`, a date sort value is the field's epoch number (ms for `date`, ns for `date_nanos`).
- `_shard_doc` tie-breaking only from 3.3.0 (opensearch-project/OpenSearch#18924, release notes 3.3.0).

The simulated searches below enforce those rules, so a request OpenSearch would refuse fails here too.
"""
import json
import random
import re
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from romulus.config import Settings
from romulus.sources import es as es_module
from romulus.sources.compile import compile_es
from romulus.sources.es import (
    ALLOWLIST,
    ALLOWLISTS,
    OPENSEARCH_ALLOWLIST,
    OPENSEARCH_FIELD_SORT_KEYS,
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
BASE_SECOND = 1731938400                       # 2024-11-18T14:00:00Z
PER_SECOND = {"ms": 1_000, "ns": 1_000_000_000}


def recorded(name: str) -> httpx.Response:
    entry = RESPONSES[name]
    if "body" in entry:
        return httpx.Response(entry["status"], json=entry["body"], headers=entry.get("headers"))
    return httpx.Response(entry["status"], text=entry["text"], headers=entry.get("headers"))


def _version(root: str) -> tuple[int, ...]:
    return tuple(int(p) for p in RESPONSES[root]["body"]["version"]["number"].split("."))


def sort_refusal(body: dict, version: tuple[int, ...]) -> httpx.Response | None:
    """OpenSearch's answer to a sort it does not accept, or None."""
    for key in body.get("sort", []):
        for name, spec in (key.items() if isinstance(key, dict) else [(key, None)]):
            if name == "_shard_doc" and version < (3, 3):
                return httpx.Response(400, json={"error": {"type": "query_shard_exception", "reason":
                                                           "No mapping found for [_shard_doc] in order to sort on"}})
            if isinstance(spec, dict):
                unknown = sorted(set(spec) - OPENSEARCH_FIELD_SORT_KEYS)
                if unknown:
                    return httpx.Response(400, json={"error": {"type": "x_content_parse_exception",
                                                               "reason": f"[field_sort] unknown field [{unknown[0]}]"}})
    return None


class FakeOpenSearch:
    """Answers each allowlisted OpenSearch request with a recorded response and fails the test on any request that
    the OpenSearch table would refuse (the client must never send one); refuses sorts as OpenSearch does."""

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
            refused = sort_refusal(json.loads(request.content), _version(self.root))
            if refused is not None:
                return refused
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


def query(order: str = "asc", unit: str = "ms") -> CompiledQuery:
    """A raw retrieval as the compiler writes it for OpenSearch."""
    body = {"query": {"match_all": {}}, "sort": [{"@timestamp": {"order": order}}, {"_shard_doc": order}]}
    return CompiledQuery(backend="opensearch", target=TARGET, body=body, fingerprint="f", time_unit=unit)


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


# Paths that look allowed to a pattern but would reach another path: dot segments, line breaks, query strings.
EDGE_PATHS = [
    ("POST", "/../_search", None, None), ("POST", "/./_count", None, None),
    ("POST", "/a,b,-c/_search", "ALLOWED", "ALLOWED"), ("POST", "/_all/_search", "ALLOWED", "ALLOWED"),
    ("POST", "/*/_search/point_in_time", "ALLOWED", None), ("POST", "/../_search/point_in_time", None, None),
    ("GET", "/../_mapping", None, None), ("DELETE", "/_search/point_in_time\n", None, None),
    ("POST", "/idx/_search\n", None, None), ("POST", "/idx%2F_bulk/_search", None, None),
    ("DELETE", "/_search/point_in_time/_all", None, None), ("DELETE", "/_search/point_in_time?x=1", None, None),
    ("delete", "/_search/point_in_time", "ALLOWED", None), ("POST", "/_search/point_in_time", None, None),
    ("GET", "/_resolve/index/..", None, None), ("GET", "/_resolve/index/.", None, None),
    ("POST", "/idx/_search\r", None, None), ("POST", "/idx\t/_search", None, None),
    ("DELETE", "/_pit\n", None, None), ("POST", "/idx/../_count", None, None), ("GET", "/idx/./_mapping", None, None),
    ("POST", "/.security/_search", "ALLOWED", "ALLOWED"),
]


@pytest.mark.parametrize("method,path,opensearch,elasticsearch", EDGE_PATHS)
def test_edge_paths_on_both_tables(method, path, opensearch, elasticsearch):
    for flavor, expected in (("opensearch", opensearch), ("elasticsearch", elasticsearch)):
        if expected == "ALLOWED":
            check_allowed(method, path, flavor)
        else:
            with pytest.raises(WriteAttemptBlocked):
                check_allowed(method, path, flavor)


@pytest.mark.parametrize("method,path", [
    ("GET", "/"), ("GET", "/_security/_authenticate"), ("POST", "/_security/user/_has_privileges"),
    ("GET", "/_resolve/index/logs-*"), ("GET", "/logs-a/_mapping"), ("GET", "/logs-a/_field_caps"),
    ("POST", "/logs-a/_search"), ("POST", "/logs-a/_count"), ("POST", "/logs-a/_pit"), ("POST", "/_search"),
    ("DELETE", "/_pit"), ("POST", "/.ds-logs-a-2024.11.18-000001/_search"),
])
def test_every_elasticsearch_request_romulus_sends_is_still_allowed(method, path):
    check_allowed(method, path, "elasticsearch")


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

@pytest.mark.parametrize("name,distribution,version,compatibility", [
    ("root_opensearch_2.3.0", "opensearch", (2, 3, 0), False),
    ("root_opensearch_2.11.1", "opensearch", (2, 11, 1), False),
    ("root_opensearch_3.3.0", "opensearch", (3, 3, 0), False),
    ("root_opensearch_compatibility_mode", "opensearch", (7, 10, 2), True),
    ("root_elasticsearch_8.15.0", "elasticsearch", (8, 15, 0), False),
    ("root_elasticsearch_7.17.0", "elasticsearch", (7, 17, 0), False),
])
def test_distribution_and_version_come_from_get_root(name, distribution, version, compatibility):
    backend = detect_backend(RESPONSES[name]["body"])
    assert (backend.distribution, backend.version, backend.compatibility_mode) == (distribution, version,
                                                                                   compatibility)


def test_unreadable_version_is_none():
    assert detect_backend({}).version is None and detect_backend({}).distribution == "elasticsearch"
    assert detect_backend({"version": {"distribution": "opensearch", "number": "x"}}).version is None
    assert detect_backend({"version": "2.11"}).distribution == "elasticsearch"


COMPATIBILITY = "compatibility mode"


@pytest.mark.parametrize("flavor,name,refused", [
    ("opensearch", "root_opensearch_2.3.0", "no point-in-time search"),
    ("opensearch", "root_opensearch_compatibility_mode", COMPATIBILITY),
    ("elasticsearch", "root_opensearch_compatibility_mode", COMPATIBILITY),
    ("opensearch", "root_elasticsearch_8.15.0", "ES_FLAVOR=opensearch, but the cluster reports elasticsearch"),
    ("elasticsearch", "root_opensearch_2.11.1", "ES_FLAVOR=elasticsearch, but the cluster reports opensearch"),
    ("opensearch", "root_opensearch_2.11.1", None),
    ("opensearch", "root_opensearch_3.3.0", None),
    ("elasticsearch", "root_elasticsearch_8.15.0", None),
])
def test_backend_refusal(flavor, name, refused):
    reason = backend_refusal(flavor, detect_backend(RESPONSES[name]["body"]))
    assert (reason is None) if refused is None else (refused in reason)
    if refused == COMPATIBILITY:
        # the fix is on the cluster, not in ES_FLAVOR
        assert "turn off compatibility.override_main_response_version" in reason and "ES_FLAVOR" not in reason


@pytest.mark.parametrize("root", ["root_opensearch_2.3.0", "root_elasticsearch_8.15.0",
                                  "root_opensearch_compatibility_mode"])
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


# ---- sorts OpenSearch accepts -------------------------------------------------------------------------------------

@pytest.mark.parametrize("field_type,unit", [("date", "ms"), ("date_nanos", "ns")])
def test_the_compiler_writes_no_sort_format_for_opensearch_and_names_the_time_resolution(field_type, unit):
    contract = contract_from_types(TARGET, {"@timestamp": field_type})
    intent = SearchIntent(kind="raw", target=TARGET, window=WINDOW, order="desc")
    os_query = compile_es(intent, contract, "opensearch")
    assert os_query.body["sort"] == [{"@timestamp": {"order": "desc"}}, {"_shard_doc": "desc"}]
    assert os_query.time_unit == unit
    es_query = compile_es(intent, contract)
    assert es_query.body["sort"][0] == {"@timestamp": {"order": "desc", "format": "strict_date_optional_time_nanos"}}


@pytest.mark.parametrize("root", ["root_opensearch_2.11.1", "root_opensearch_3.3.0"])
def test_a_formatted_sort_is_never_sent_to_opensearch(root):
    """A body carrying Elasticsearch's sort format (iterate's default, or an Elasticsearch-compiled query) reaches
    OpenSearch without it; the fake refuses an unknown sort key exactly as OpenSearch's parser does."""
    page = RESPONSES["pit_search_page"]["body"]
    fake = FakeOpenSearch(root=root, pages=[page, page])
    formatted = CompiledQuery(backend="opensearch", target=TARGET, fingerprint="f", body={
        "query": {"match_all": {}},
        "sort": [{"@timestamp": {"order": "asc", "format": "strict_date_optional_time_nanos"}}, {"_shard_doc": "asc"}]})
    unsorted = CompiledQuery(backend="opensearch", target=TARGET, fingerprint="f", body={"query": {"match_all": {}}})
    for q in (formatted, unsorted):
        assert [h["_id"] for hits, _meta in os_client(fake).iterate(q, max_records=10) for h in hits] == ["r1", "r2"]
    assert all("format" not in json.dumps(json.loads(r.content).get("sort"))
               for r in fake.requests if r.url.path == "/_search")


def test_the_fake_refuses_what_opensearch_refuses():
    assert sort_refusal({"sort": [{"@timestamp": {"order": "asc", "format": "x"}}]}, (3, 3)).status_code == 400
    assert sort_refusal({"sort": [{"_shard_doc": "asc"}]}, (2, 11)).status_code == 400
    assert sort_refusal({"sort": [{"@timestamp": {"order": "asc"}}, {"_shard_doc": "asc"}]}, (3, 3)) is None


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


def test_opensearch_3_3_pages_with_the_shard_doc_tiebreaker():
    fake = FakeOpenSearch(root="root_opensearch_3.3.0")
    list(os_client(fake).iterate(query("desc"), max_records=10))
    body = json.loads(fake.requests[2].content)
    assert body["sort"] == [{"@timestamp": {"order": "desc"}}, {"_shard_doc": "desc"}]


def test_a_shared_opensearch_point_in_time_is_opened_and_released_once():
    fake = FakeOpenSearch(root="root_opensearch_3.3.0", pages=[])
    client = os_client(fake)
    with client.point_in_time(TARGET) as pit:
        list(client.iterate(query(), max_records=10, pit=pit))
        list(client.iterate(query(), max_records=10, pit=pit))
    assert fake.sent().count(f"POST /{TARGET}/_search/point_in_time") == 1
    assert fake.sent().count("DELETE /_search/point_in_time") == 1


@pytest.mark.parametrize("flavor", ["opensearch", "elasticsearch"])
@pytest.mark.parametrize("pit_id", ["_all", "someone-elses-pit", ""])
def test_only_a_point_in_time_this_client_holds_is_ever_released(flavor, pit_id):
    sent = []
    client = ElasticClient(Settings(es_url="http://x.invalid", es_flavor=flavor),
                           transport=httpx.MockTransport(lambda r: sent.append(r) or httpx.Response(200, json={})))
    with pytest.raises(WriteAttemptBlocked):
        client._close_pit(pit_id)
    assert sent == []


class RotatingPits:
    """A cluster that hands back a new PIT id with every search response; one response names `_all`."""

    def __init__(self, root):
        self.root, self.searches, self.closed = root, 0, []

    def __call__(self, request):
        path = request.url.path
        if path == "/":
            return recorded(self.root)
        if request.method == "DELETE":
            self.closed.append(json.loads(request.content))
            return httpx.Response(200, json={"succeeded": True, "pits": [{"successful": True}]})
        if path.endswith(("/_pit", "/_search/point_in_time")):
            return httpx.Response(200, json={"id": "pit-0", "pit_id": "pit-0"})
        self.searches += 1
        pit_id = "_all" if self.searches == 2 else f"pit-{self.searches}"
        hits = [{"_index": TARGET, "_id": f"d{self.searches}", "_source": {}, "sort": [self.searches, self.searches]}]
        return httpx.Response(200, json={"pit_id": pit_id, "timed_out": False, "_shards": {"failed": 0},
                                         "hits": {"total": {"value": 3, "relation": "eq"},
                                                  "hits": hits if self.searches <= 3 else []}})


@pytest.mark.parametrize("flavor,root", [("opensearch", "root_opensearch_3.3.0"),
                                         ("elasticsearch", "root_elasticsearch_8.15.0")])
def test_the_released_id_is_the_last_usable_one_the_cluster_handed_back(flavor, root):
    cluster = RotatingPits(root)
    client = ElasticClient(Settings(es_url="http://x.invalid", es_flavor=flavor), transport=httpx.MockTransport(cluster))
    body = {"query": {"match_all": {}}, "sort": [{"@timestamp": {"order": "asc"}}, {"_shard_doc": "asc"}]}
    q = CompiledQuery(backend=flavor, target=TARGET, body=body, fingerprint="f")
    assert len([h for hits, _meta in client.iterate(q, max_records=10, page_size=1) for h in hits]) == 3
    # the response naming `_all` was not taken as the session's id; the last id handed back is the one released
    assert cluster.closed == [{"pit_id": ["pit-4"]} if flavor == "opensearch" else {"id": "pit-4"}]
    with pytest.raises(WriteAttemptBlocked):
        client._close_pit("pit-1")                  # superseded, and no longer this client's to release


# ---- simulated OpenSearch search over one point in time ----------------------------------------------------------

_ISO = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?(Z|[+-]\d\d:\d\d)?$")


def iso_ns(text: str) -> int:
    m = _ISO.match(text)
    assert m, text
    zone = m.group(3) or "Z"
    base = datetime.fromisoformat(m.group(1) + ("+00:00" if zone == "Z" else zone))
    return int(base.timestamp()) * 1_000_000_000 + int((m.group(2) or "0").ljust(9, "0"))


class SimSearch:
    """OpenSearch search over one point in time, for a `date` (ms) or `date_nanos` (ns) time field:
    - sorts are checked as OpenSearch's parser checks them (`sort_refusal`): no `format`, no `_shard_doc` before 3.3;
    - a date sort value is the field's epoch number, in its own resolution;
    - the merged order of tied values is (shard, doc), fixed for the point in time, as Lucene's merge orders them;
    - `search_after` continues strictly after the sort values: records tied on all of them are skipped;
    - a multi-valued time field sorts by its smallest value ascending and its largest descending, and a range
      matches when any value is in it;
    - from/size page the merged order."""

    def __init__(self, docs: list[dict], unit: str = "ms", root: str = "root_opensearch_2.11.1"):
        self.docs, self.unit, self.root, self.version = docs, unit, root, _version(root)
        self.searches: list[dict] = []

    @classmethod
    def from_counts(cls, counts: list[int], unit="ms", root="root_opensearch_2.11.1", step=None):
        """`counts[k]` records at the k-th time. Times are `step` apart in the field's unit (ns fields default to
        microsecond steps, so several distinct times share one millisecond)."""
        step = step or (1000 if unit == "ns" else 1)
        base = BASE_SECOND * PER_SECOND[unit]
        docs, n = [], 0
        for k, count in enumerate(counts):
            for _ in range(count):
                docs.append({"id": f"d{n:04d}", "t": [base + k * step], "shard": n % 3, "doc": (n * 7919) % 1000})
                n += 1
        return cls(docs, unit, root)

    def _ns(self, value: int) -> int:
        return value * (1_000_000 if self.unit == "ms" else 1)

    def _matches(self, query: dict, doc: dict) -> bool:
        if not query or "match_all" in query:
            return True
        if "bool" in query:
            return all(self._matches(clause, doc) for clause in query["bool"].get("filter", []))
        if "range" in query:
            (field, bounds), = query["range"].items()
            assert field == "@timestamp", field

            def within(t: int) -> bool:
                ns = self._ns(t)
                return all(op not in bounds or test(ns, iso_ns(bounds[op])) for op, test in (
                    ("gte", lambda a, b: a >= b), ("gt", lambda a, b: a > b),
                    ("lte", lambda a, b: a <= b), ("lt", lambda a, b: a < b)))
            return any(within(t) for t in doc["t"])
        raise AssertionError(f"query the simulator does not evaluate: {query}")

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        check_allowed(request.method, path, "opensearch")
        if path == "/":
            return recorded(self.root)
        if path.endswith("/_search/point_in_time"):
            return recorded("pit_open") if request.method == "POST" else recorded("pit_close")
        body = json.loads(request.content)
        refused = sort_refusal(body, self.version)
        if refused is not None:
            return refused
        self.searches.append(body)
        (field, spec), *rest = [next(iter(k.items())) for k in body["sort"]]
        assert field == "@timestamp"
        desc = spec["order"] == "desc"
        tiebreak = rest[0][0] if rest else None

        def key(doc):
            t = max(doc["t"]) if desc else min(doc["t"])
            return t, doc["shard"], doc["doc"]

        def values(doc):
            t = key(doc)[0]
            if tiebreak == "_shard_doc":
                return [t, (doc["shard"] << 32) + doc["doc"]]
            return [t, doc["doc"]] if tiebreak == "_doc" else [t]

        matching = [d for d in self.docs if self._matches(body.get("query", {}), d)]
        ordered = sorted(matching, key=key, reverse=desc)
        if "search_after" in body:
            after = body["search_after"]
            ordered = [d for d in ordered if (values(d)[:len(after)] < after if desc else values(d)[:len(after)] > after)]
        start = body.get("from", 0)
        page = ordered[start:start + body["size"]]
        hits = [{"_index": TARGET, "_id": d["id"], "_source": {}, "sort": values(d)} for d in page]
        return httpx.Response(200, json={"pit_id": "c3ludGhldGljLXBpdC0x", "timed_out": False, "_shards": {"failed": 0},
                                         "hits": {"total": {"value": len(matching), "relation": "eq"}, "hits": hits}})


def sim_client(sim: SimSearch) -> ElasticClient:
    return ElasticClient(Settings(es_url="http://os.invalid", es_flavor="opensearch"), transport=httpx.MockTransport(sim))


def read_all(sim: SimSearch, q: CompiledQuery, page_size: int, max_records: int = 10_000):
    pages = list(sim_client(sim).iterate(q, max_records=max_records, page_size=page_size))
    return [h["_id"] for hits, _meta in pages for h in hits], pages


@pytest.mark.parametrize("root", ["root_opensearch_2.11.1", "root_opensearch_3.3.0"])
@pytest.mark.parametrize("field_type,unit", [("date", "ms"), ("date_nanos", "ns")])
@pytest.mark.parametrize("order", ["asc", "desc"])
def test_compiled_retrieval_reads_every_record_once_for_both_resolutions_and_both_paths(root, field_type, unit,
                                                                                         order):
    sim = SimSearch.from_counts([3, 4, 1, 5, 2, 7, 1, 1, 6], unit, root)
    contract = contract_from_types(TARGET, {"@timestamp": field_type})
    q = compile_es(SearchIntent(kind="raw", target=TARGET, window=WINDOW, order=order), contract, "opensearch")
    ids, pages = read_all(sim, q, page_size=4)
    assert sorted(ids) == sorted(d["id"] for d in sim.docs) and len(ids) == len(set(ids))
    times = [min(sim.docs[int(i[1:])]["t"]) for i in ids]
    assert times == sorted(times, reverse=order == "desc")
    assert all(meta["problems"] == [] and meta["total"] == len(sim.docs) for _hits, meta in pages)
    uses_groups = root == "root_opensearch_2.11.1"
    assert any("from" in s for s in sim.searches) == uses_groups
    if uses_groups:
        # each tie group's exact range names its time in the field's own resolution
        exact = [c["range"]["@timestamp"] for s in sim.searches if "from" in s for c in s["query"]["bool"]["filter"]
                 if "range" in c and c["range"]["@timestamp"].get("gte") == c["range"]["@timestamp"].get("lte")]
        assert exact and all(e["format"] == "strict_date_optional_time_nanos" for e in exact)
        stamps = {iso_ns(e["gte"]) for e in exact}
        assert stamps <= {sim._ns(t) for d in sim.docs for t in d["t"]}


def test_nanosecond_times_inside_one_millisecond_stay_distinct_groups():
    """Times 1 microsecond apart: read as milliseconds they would collapse into one group."""
    sim = SimSearch.from_counts([2, 3, 2, 3], "ns", step=1_000)
    ids, _pages = read_all(sim, query(unit="ns"), page_size=3)
    assert sorted(ids) == sorted(d["id"] for d in sim.docs) and len(ids) == len(set(ids))
    group_queries = [s for s in sim.searches if "from" in s]
    assert len({json.dumps(s["query"]) for s in group_queries}) >= 2


def test_a_resolution_that_does_not_match_the_mapping_is_an_error_never_a_skip():
    """Sort values in nanoseconds read as milliseconds would name another time: the group comes back short."""
    sim = SimSearch.from_counts([2, 3, 2], "ns")
    with pytest.raises(SourceError):
        read_all(sim, query(unit="ms"), page_size=3)
    sim = SimSearch.from_counts([2, 3, 2], "ms")
    with pytest.raises(SourceError, match="could not be read back as a group"):
        read_all(sim, query(unit="ns"), page_size=3)


@pytest.mark.parametrize("order", ["asc", "desc"])
@pytest.mark.parametrize("counts,page_size", [
    ([3, 4, 1, 5, 2, 7, 1], 4),          # groups straddle almost every page boundary
    ([10, 1, 1], 4),                     # a whole page (and more) of one time
    ([1] * 9, 3),                        # no ties at all
    ([4, 4, 4], 4),                      # groups exactly fill pages
    ([2, 9, 2, 11, 1], 5),
])
def test_tie_groups_read_every_record_exactly_once(order, counts, page_size):
    sim = SimSearch.from_counts(counts)
    ids, pages = read_all(sim, query(order), page_size)
    assert sorted(ids) == sorted(d["id"] for d in sim.docs) and len(ids) == len(set(ids))
    times = [sim.docs[int(i[1:])]["t"][0] for i in ids]
    assert times == sorted(times, reverse=order == "desc")
    assert all(meta["total"] == len(sim.docs) and meta["problems"] == [] for _hits, meta in pages)


def test_a_search_after_on_time_alone_would_skip_tied_records():
    """Why tie groups are read whole: the same backend, paged naively, loses records at page boundaries."""
    sim = SimSearch.from_counts([3, 4, 1, 5])
    seen, after = [], None
    while True:
        body = {"query": {"match_all": {}}, "size": 4, "sort": [{"@timestamp": {"order": "asc"}}]}
        if after is not None:
            body["search_after"] = [after]
        hits = json.loads(sim(httpx.Request("POST", "http://os.invalid/_search", json=body)).content)["hits"]["hits"]
        seen += hits
        if len(hits) < 4:
            break
        after = hits[-1]["sort"][0]
    assert len(seen) < len(sim.docs)


def test_a_tie_group_beyond_the_result_window_is_read_in_part_and_says_so(monkeypatch):
    monkeypatch.setattr(es_module, "TIE_GROUP_WINDOW", 6)
    sim = SimSearch.from_counts([2, 9, 1])
    ids, pages = read_all(sim, query(), page_size=4)
    problems = [p for _hits, meta in pages for p in meta["problems"]]
    assert problems == [f"tie_group_window:@timestamp={BASE_SECOND * 1000 + 1}:6<total:9"]
    assert len(ids) == len(set(ids)) == 2 + 6 + 1      # 3 records of the large group were not read, and it says so
    assert pages[-1][1]["total"] == 12


def test_tie_group_requests_count_against_the_query_budget():
    sim = SimSearch.from_counts([3, 4, 1, 5])
    spent = 0

    def reserve():
        nonlocal spent
        spent += 1
        return True

    list(sim_client(sim).iterate(query(), max_records=10_000, page_size=4, on_query=reserve))
    assert spent == len(sim.searches) + 2           # every search, plus the PIT open and close


def test_tie_paging_refuses_an_order_it_cannot_page_by_groups():
    sim = SimSearch.from_counts([2, 2])
    q = CompiledQuery(backend="opensearch", target=TARGET, fingerprint="f",
                      body={"query": {"match_all": {}}, "sort": [{"host.name": "asc"}, {"@timestamp": "asc"}]})
    with pytest.raises(SourceError, match="no _shard_doc tiebreaker"):
        list(sim_client(sim).iterate(q, max_records=10))


def test_tie_paging_fuzz_exactly_once_and_honest_about_what_it_did_not_read(monkeypatch):
    """Random record sets (ties, multi-valued times, both orders, small pages, caps and result windows) through
    execute(): never a duplicate; complete only when every record was read; anything unread is a stated reason; and
    with no cap and no result window in reach, every record is read."""
    rng = random.Random(7)
    contract = contract_from_types(TARGET, {"@timestamp": "date"})
    defects = []
    for trial in range(400):
        n, distinct = rng.randint(0, 80), rng.randint(1, 10)
        docs = []
        for i in range(n):
            times = [(BASE_SECOND + rng.randrange(distinct)) * 1000]
            if rng.random() < 0.15:
                times.append((BASE_SECOND + rng.randrange(distinct)) * 1000)
            docs.append({"id": f"d{i}", "t": times, "shard": rng.randrange(3), "doc": rng.randrange(10_000)})
        sim = SimSearch(docs)
        client = sim_client(sim)
        page = rng.choice([1, 2, 3, 5, 8, 50])
        client.iterate = lambda q, max_records, _c=client, _p=page, **kw: ElasticClient.iterate(
            _c, q, max_records, page_size=_p, **kw)
        window = rng.choice([10_000, 4, 9])
        monkeypatch.setattr(es_module, "TIE_GROUP_WINDOW", window)
        intent = SearchIntent(kind="raw", target=TARGET, window=WINDOW, order=rng.choice(["asc", "desc"]),
                              max_records=rng.choice([10_000, 7, 1, 25]))
        out = execute(client, intent, contract)
        ids = [r["_id"] for r in out.records]
        lost = n - len(set(ids))
        unbounded = intent.max_records == 10_000 and window == 10_000
        if (len(ids) != len(set(ids)) or (out.completeness == Completeness.complete and lost)
                or (out.completeness != Completeness.complete and not out.reasons)
                or (unbounded and (lost or out.completeness != Completeness.complete))):
            defects.append((trial, n, page, out.completeness, out.reasons))
    assert defects == []
