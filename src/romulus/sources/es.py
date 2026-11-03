"""Read-only Elasticsearch/OpenSearch adapter with an HTTP allowlist that blocks write APIs.

Each flavor has its own request table; a request on neither is refused before it leaves the process. The flavor is
configured (ES_FLAVOR) and confirmed from the cluster's own `GET /`: a cluster of the other flavor, or an OpenSearch
without point-in-time search, makes the client refuse every further request.

OpenSearch facts this module relies on (OpenSearch documentation and source):
- `GET /` names the distribution in `version.distribution` ("opensearch"); Elasticsearch writes no such field.
  https://docs.opensearch.org/latest/api-reference/cluster-api/info/. In compatibility mode
  (`compatibility.override_main_response_version`) OpenSearch omits the distribution and reports 7.10.2; its
  tagline still names OpenSearch (server org/opensearch/action/main/MainResponse.java).
- A field sort takes only order, missing, mode, unmapped_type, numeric_type, nested_path, nested_filter and nested,
  and refuses anything else (server org/opensearch/search/sort/FieldSortBuilder.java, 2.4 through 3.3): no
  `format`, so a date sort value comes back as the field's own epoch number (milliseconds for `date`, nanoseconds
  for `date_nanos`).
- Point in time, introduced in 2.4: `POST /<index>/_search/point_in_time?keep_alive=...` answers `{"pit_id": ...}`;
  a PIT search is `/_search` with no index and `"pit": {"id", "keep_alive"}` in the body; `DELETE
  /_search/point_in_time` takes `{"pit_id": [...]}`. `DELETE /_search/point_in_time/_all` also exists and deletes
  every PIT in the cluster, other users' included, so it is not on the table.
  https://docs.opensearch.org/latest/api-reference/search-apis/point-in-time-api/
- `_shard_doc` as a sort tiebreaker exists only from 3.3.0 ("Add support for search tie-breaking by _shard_doc",
  opensearch-project/OpenSearch#18924; release-notes/opensearch.release-notes-3.3.0.md). Before it, `search_after`
  over sort values that tie skips the tied records, and sorting on `_id` loads every id into heap and is deprecated
  (https://docs.opensearch.org/latest/mappings/metadata-fields/id/), so `iterate` reads every tie group whole.
- `POST /<index>/_search` and `POST /_search` with `from`, `size`, `sort`, `search_after`, `track_total_hits` and
  `pit` in the body: https://docs.opensearch.org/latest/api-reference/search-apis/search/; `POST /<index>/_count`:
  https://docs.opensearch.org/latest/api-reference/search-apis/count/; `GET /<index>/_mapping`:
  https://docs.opensearch.org/latest/api-reference/index-apis/get-mapping/; `_resolve/index` (since 1.0):
  https://docs.opensearch.org/latest/api-reference/index-apis/resolve-index/; `_field_caps`:
  https://docs.opensearch.org/latest/api-reference/search-apis/field-caps/; `filter_path`:
  https://docs.opensearch.org/latest/api-reference/common-parameters/.
- `GET /_plugins/_security/authinfo` (security plugin; fields user_name, backend_roles, roles, ...):
  opensearch-project/security, src/main/java/org/opensearch/security/rest/SecurityInfoAction.java. Without the
  plugin no handler answers: OpenSearch's RestController replies 400 "no handler found for uri [...]".
"""
from __future__ import annotations

import re
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from romulus.config import Settings, redact_text
from romulus.sources.models import CompiledQuery, Completeness, SearchOutcome


class WriteAttemptBlocked(RuntimeError):
    """Raised before any request that is not on the read-only allowlist leaves the process."""


class SourceError(RuntimeError):
    def __init__(self, message: str, retryable: bool = False, status: int | None = None):
        super().__init__(message)
        self.retryable = retryable
        self.status = status


class SourceBudgetExhausted(SourceError):
    """A caller-supplied physical page or deadline budget stopped retrieval."""


class BackendRefused(SourceError):
    """The cluster is not one this client may run against: another flavor than configured, or an OpenSearch
    without point-in-time search. Every request after `GET /` is refused."""


@dataclass
class PitSession:
    id: str             # the id this session last carried; release it through the client that opened it


_IDX = r"[A-Za-z0-9_.*,\-]+"
# (method, path regex) per flavor. Everything else is refused. The only DELETE releases one search context.
ALLOWLIST: list[tuple[str, re.Pattern]] = [
    ("GET", re.compile(r"^/$")),
    ("GET", re.compile(r"^/_security/_authenticate$")),
    ("POST", re.compile(r"^/_security/user/_has_privileges$")),
    ("GET", re.compile(rf"^/_resolve/index/{_IDX}$")),
    ("GET", re.compile(rf"^/{_IDX}/_mapping$")),
    ("GET", re.compile(rf"^/{_IDX}/_field_caps$")),
    ("POST", re.compile(rf"^/{_IDX}/_search$")),
    ("POST", re.compile(rf"^/{_IDX}/_count$")),
    ("POST", re.compile(rf"^/{_IDX}/_pit$")),
    ("POST", re.compile(r"^/_search$")),            # PIT searches (index comes from the PIT)
    ("DELETE", re.compile(r"^/_pit$")),
]
OPENSEARCH_ALLOWLIST: list[tuple[str, re.Pattern]] = [
    ("GET", re.compile(r"^/$")),
    ("GET", re.compile(r"^/_plugins/_security/authinfo$")),
    ("GET", re.compile(rf"^/_resolve/index/{_IDX}$")),
    ("GET", re.compile(rf"^/{_IDX}/_mapping$")),
    ("GET", re.compile(rf"^/{_IDX}/_field_caps$")),
    ("POST", re.compile(rf"^/{_IDX}/_search$")),
    ("POST", re.compile(rf"^/{_IDX}/_count$")),
    ("POST", re.compile(rf"^/{_IDX}/_search/point_in_time$")),
    ("POST", re.compile(r"^/_search$")),            # PIT searches (index comes from the PIT)
    ("DELETE", re.compile(r"^/_search/point_in_time$")),
]
ALLOWLISTS = {"elasticsearch": ALLOWLIST, "opensearch": OPENSEARCH_ALLOWLIST}
FORBIDDEN_QUERY_KEYS = {"script", "script_fields", "runtime_mappings", "stored_fields"}

SEARCH_FILTER_PATH = (
    "pit_id,timed_out,terminated_early,_shards.failed,hits.total.value,hits.total.relation,"
    "hits.hits._id,hits.hits._index,hits.hits._source,hits.hits.sort,aggregations"
)
MAPPING_FILTER_PATH = "*.mappings.properties"
FIELD_CAPS_FILTER_PATH = "fields.*.*"
PIT_OPEN_FILTER_PATH = "id"
PIT_CLOSE_FILTER_PATH = "succeeded,num_freed"
OPENSEARCH_PIT_OPEN_FILTER_PATH = "pit_id"
OPENSEARCH_PIT_CLOSE_FILTER_PATH = "pits.successful"
PAGE_SIZE = 2000
PIT_KEEP_ALIVE = "2m"
# OpenSearch versions: point in time from 2.4; the _shard_doc tiebreaker from 3.3.
OPENSEARCH_MIN_PIT = (2, 4)
OPENSEARCH_SHARD_DOC = (3, 3)
ELASTICSEARCH_MIN = (8, 0)
# A tie group is read by from/size inside the PIT; from + size may not pass the index's max_result_window, whose
# default is 10,000. A larger group is read in part and says so.
TIE_GROUP_WINDOW = 10_000
# Elasticsearch privileges that can change data, indices or cluster configuration (the write-capable entries of
# https://www.elastic.co/docs/reference/elasticsearch/security-privileges that exist from 8.0 on). `romulus doctor`
# asks `_has_privileges` for each; any one held means the account is not read-only.
ES_INDEX_WRITE_PRIVILEGES = (
    "all", "auto_configure", "create", "create_doc", "create_index", "delete", "delete_index", "index",
    "maintenance", "manage", "manage_follow_index", "manage_ilm", "manage_leader_index", "write",
)
ES_CLUSTER_WRITE_PRIVILEGES = (
    "all", "create_snapshot", "delegate_pki", "grant_api_key", "manage", "manage_api_key", "manage_autoscaling",
    "manage_ccr", "manage_enrich", "manage_ilm", "manage_index_templates", "manage_ingest_pipelines",
    "manage_logstash_pipelines", "manage_ml", "manage_oidc", "manage_own_api_key", "manage_pipeline",
    "manage_rollup", "manage_saml", "manage_security", "manage_slm", "manage_token", "manage_transform",
    "manage_watcher",
)
# OpenSearch's field sort takes only these keys and refuses any other (FieldSortBuilder's strict parser), `format`
# included: its date sort values are the field's own epoch numbers.
OPENSEARCH_FIELD_SORT_KEYS = frozenset({"order", "missing", "mode", "unmapped_type", "numeric_type", "nested_path",
                                        "nested_filter", "nested"})


def fetch_limit(max_records: int, page_size: int = PAGE_SIZE) -> int:
    """The most hits `iterate` returns for `max_records`: it reads whole pages until it has at least that many."""
    size = min(page_size, max_records)
    return -(-max_records // size) * size


def _path_refused(path: str) -> bool:
    """A path no table admits whatever its patterns say: a control character (a line break would end the request
    line), or a "." or ".." segment, which a server or proxy may resolve to another path."""
    return any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in path) or any(seg in (".", "..") for seg in path.split("/"))


def check_allowed(method: str, path: str, flavor: str = "elasticsearch") -> None:
    method = method.upper()
    if not _path_refused(path):
        for m, rx in ALLOWLISTS.get(flavor, ()):
            if m == method and rx.fullmatch(path):
                return
    raise WriteAttemptBlocked(f"refused non-allowlisted request {method} {path!r}")


# OpenSearch's root response always carries this tagline (server MainResponse.TAGLINE); Elasticsearch's differs.
OPENSEARCH_TAGLINE = "The OpenSearch Project: https://opensearch.org/"


@dataclass(frozen=True)
class Backend:
    """What a cluster's `GET /` says it is."""
    distribution: str                     # "elasticsearch", "opensearch", or the distribution named
    number: str                           # version.number as written
    version: tuple[int, int, int] | None  # parsed major.minor.patch; None when unreadable
    compatibility_mode: bool = False      # OpenSearch answering with an Elasticsearch-compatible version number

    def label(self) -> str:
        return f"{self.distribution} {self.number or '(no version)'}"


_VERSION = re.compile(r"^(\d+)\.(\d+)(?:\.(\d+))?")


def detect_backend(info: dict) -> Backend:
    """Elasticsearch writes no `version.distribution`; OpenSearch writes "opensearch", except in compatibility mode
    (`compatibility.override_main_response_version`), where it omits the distribution and reports 7.10.2 in place
    of its own version. Its tagline names OpenSearch in every mode (server MainResponse.toXContent)."""
    version = info.get("version") if isinstance(info.get("version"), dict) else {}
    distribution = version.get("distribution")
    number = version.get("number") if isinstance(version.get("number"), str) else ""
    m = _VERSION.match(number)
    parsed = (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)) if m else None
    if distribution is None and info.get("tagline") == OPENSEARCH_TAGLINE:
        return Backend("opensearch", number, parsed, compatibility_mode=True)
    name = "elasticsearch" if distribution is None else str(distribution).strip().lower() or "elasticsearch"
    return Backend(name, number, parsed)


def backend_refusal(flavor: str, backend: Backend) -> str | None:
    """Why this client must not run against `backend`, or None. Only what makes retrieval wrong is refused here:
    another flavor (its request table does not fit), and an OpenSearch whose point-in-time search cannot be shown
    (paging without one is not a consistent view)."""
    if backend.compatibility_mode:
        return (f"the cluster is OpenSearch in compatibility mode, which reports {backend.number or 'no version'} in "
                f"place of its own version, so its point-in-time support cannot be read: turn off "
                f"compatibility.override_main_response_version on the cluster")
    if backend.distribution != flavor:
        return (f"ES_FLAVOR={flavor}, but the cluster reports {backend.label()}: ROMULUS runs only against the "
                f"configured flavor; set ES_FLAVOR to match the cluster")
    if flavor == "opensearch":
        if backend.version is None:
            return f"the cluster reports {backend.label()}: its point-in-time support cannot be read"
        if backend.version[:2] < OPENSEARCH_MIN_PIT:
            return (f"{backend.label()} has no point-in-time search (OpenSearch 2.4 or later): ROMULUS does not page "
                    f"through records without a consistent view")
    return None


def _shard_doc_supported(flavor: str, backend: Backend | None) -> bool:
    if flavor != "opensearch":
        return True
    return backend is not None and backend.version is not None and backend.version[:2] >= OPENSEARCH_SHARD_DOC


def _scan_body(obj: Any) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in FORBIDDEN_QUERY_KEYS:
                raise WriteAttemptBlocked(f"refused query containing {k!r}")
            _scan_body(v)
    elif isinstance(obj, list):
        for v in obj:
            _scan_body(v)


class ElasticClient:
    def __init__(self, settings: Settings, transport: httpx.BaseTransport | None = None):
        self.settings = settings
        auth = None
        headers = {"Content-Type": "application/json"}
        if not settings.es_compression:
            # uncompressed responses: no decompression cost here, more bytes on the wire
            headers["Accept-Encoding"] = "identity"
        if settings.es_api_key.get_secret_value():
            headers["Authorization"] = "ApiKey " + settings.es_api_key.get_secret_value()
        elif settings.es_username:
            auth = (settings.es_username, settings.es_password.get_secret_value())
        verify: bool | str = settings.es_verify_tls
        if settings.es_ca_cert:
            verify = settings.es_ca_cert
        self._http = httpx.Client(base_url=settings.es_url.rstrip("/"), auth=auth, headers=headers,
                                  verify=verify, timeout=60.0, transport=transport)
        self.flavor = settings.es_flavor
        self._version: str | None = None
        self.backend: Backend | None = None
        self.refusal: str | None = None
        # the current id of every point in time this client opened and has not released (one per open session)
        self._pit_ids: set[str] = set()

    # -- transport -------------------------------------------------------------------------
    def request(self, method: str, path: str, body: dict | None = None, params: dict | None = None) -> dict:
        check_allowed(method, path, self.flavor)
        if body is not None:
            _scan_body(body)
        if path != "/":
            if self.refusal is not None:
                raise BackendRefused(self.refusal)
            if self.flavor == "opensearch" and self.backend is None:
                # the OpenSearch table and its point-in-time calls depend on the version: confirm it first
                self.info()
        try:
            r = self._http.request(method, path, json=body, params=params)
        except httpx.TimeoutException as e:
            raise SourceError(f"timeout {method} {path}", retryable=True) from e
        except httpx.HTTPError as e:
            raise SourceError(redact_text(f"transport error {method} {path}: {e}", self.settings),
                              retryable=True) from e
        if r.status_code >= 400:
            retry = r.status_code in (429, 502, 503, 504)
            raise SourceError(redact_text(f"HTTP {r.status_code} {method} {path}: {r.text[:300]}", self.settings),
                              retryable=retry, status=r.status_code)
        return r.json() if r.content else {}

    # -- metadata --------------------------------------------------------------------------
    def probe(self) -> tuple[dict, Backend, str | None]:
        """`GET /`, what it says the cluster is, and why this client refuses to run against it (None: it does
        not). Never raises for a refusal, so the doctor can report it; every later request is refused."""
        d = self.request("GET", "/")
        self.backend = detect_backend(d)
        self._version = self.backend.number
        self.refusal = backend_refusal(self.flavor, self.backend)
        return d, self.backend, self.refusal

    def info(self) -> dict:
        d, _backend, refusal = self.probe()
        if refusal is not None:
            raise BackendRefused(refusal)
        return d

    @property
    def version(self) -> str:
        if self._version is None:
            self.info()
        return self._version or ""

    def authenticate(self) -> dict:
        return self.request("GET", "/_security/_authenticate")

    def authinfo(self) -> dict:
        """OpenSearch security plugin: the account's name, backend roles and mapped security roles."""
        return self.request("GET", "/_plugins/_security/authinfo")

    def has_privileges(self, indices: list[str]) -> dict:
        body = {
            "cluster": [*ES_CLUSTER_WRITE_PRIVILEGES, "monitor"],
            "index": [{"names": indices, "privileges": ["read", *ES_INDEX_WRITE_PRIVILEGES]}],
        }
        return self.request("POST", "/_security/user/_has_privileges", body)

    def resolve(self, pattern: str) -> list[str]:
        """Concrete searchable targets for a pattern: indices plus data streams (searched by stream
        name; backing indices are excluded so nothing is counted twice). Aliases are used only when
        the pattern matches nothing else, for the same reason."""
        d = self.request("GET", f"/_resolve/index/{pattern}")
        streams = [s["name"] for s in d.get("data_streams", [])]
        backing = {b for s in d.get("data_streams", []) for b in s.get("backing_indices", [])}
        indices = [i["name"] for i in d.get("indices", []) if i["name"] not in backing]
        names = indices + streams
        if not names:
            names = [a["name"] for a in d.get("aliases", [])]
        return sorted(set(names))

    def mapping(self, index: str) -> dict:
        return self.request("GET", f"/{index}/_mapping", params={"filter_path": MAPPING_FILTER_PATH})

    def field_caps(self, index: str, fields: str = "*") -> dict:
        return self.request("GET", f"/{index}/_field_caps", params={
            "fields": fields, "filter_path": FIELD_CAPS_FILTER_PATH,
        })

    def search(self, target: str | None, body: dict) -> dict:
        path = f"/{target}/_search" if target is not None else "/_search"
        return self.request("POST", path, body, params={"filter_path": SEARCH_FILTER_PATH})

    def _open_pit(self, target: str) -> str:
        if self.flavor == "opensearch":
            # a PIT missing some shards would search those shards silently never: refuse to create one
            pit_id = self.request("POST", f"/{target}/_search/point_in_time", params={
                "keep_alive": PIT_KEEP_ALIVE, "allow_partial_pit_creation": "false",
                "filter_path": OPENSEARCH_PIT_OPEN_FILTER_PATH,
            })["pit_id"]
        else:
            pit_id = self.request("POST", f"/{target}/_pit", params={
                "keep_alive": "2m", "filter_path": PIT_OPEN_FILTER_PATH,
            })["id"]
        if not _usable_pit_id(pit_id):
            raise SourceError("the cluster opened a point in time without a usable id")
        self._pit_ids.add(pit_id)
        return pit_id

    def _carry_pit(self, session: PitSession, d: dict) -> None:
        """A search response may hand back a new id for its point in time; the session carries it from then on."""
        pit_id = d.get("pit_id")
        if _usable_pit_id(pit_id) and pit_id != session.id:
            self._pit_ids.discard(session.id)
            self._pit_ids.add(pit_id)
            session.id = pit_id

    def _close_pit(self, pit_id: str) -> None:
        """Release one point in time this client opened, by the id it last carried. `_all` (every PIT in the
        cluster, other users' included) and any id this client did not open or receive are refused unsent."""
        if not _usable_pit_id(pit_id) or pit_id not in self._pit_ids:
            raise WriteAttemptBlocked("refused to release a point in time this client did not open")
        try:
            if self.flavor == "opensearch":
                self.request("DELETE", "/_search/point_in_time", {"pit_id": [pit_id]},
                             params={"filter_path": OPENSEARCH_PIT_CLOSE_FILTER_PATH})
                return
            self.request("DELETE", "/_pit", {"id": pit_id}, params={"filter_path": PIT_CLOSE_FILTER_PATH})
        finally:
            self._pit_ids.discard(pit_id)

    @contextmanager
    def point_in_time(self, target: str):
        session = PitSession(self._open_pit(target))
        try:
            yield session
        finally:
            try:
                self._close_pit(session.id)
            except SourceError:
                pass

    # -- search ----------------------------------------------------------------------------
    def run(self, q: CompiledQuery) -> tuple[SearchOutcome, dict | None]:
        """Execute a single-request (aggregate/histogram) query. Returns (outcome shell, response)."""
        started = datetime.now(UTC)
        try:
            d = self.search(q.target, q.body)
        except SourceError as e:
            return SearchOutcome(target=q.target, fingerprint=q.fingerprint, started_at=started,
                                 ended_at=datetime.now(UTC), completeness=Completeness.failed,
                                 reasons=["source_error"], error=str(e)), None
        reasons = _response_problems(d)
        total = d.get("hits", {}).get("total", {})
        return SearchOutcome(target=q.target, fingerprint=q.fingerprint, started_at=started,
                             ended_at=datetime.now(UTC), backend_version=self.version,
                             completeness=Completeness.partial if reasons else Completeness.complete,
                             reasons=reasons, total=total.get("value"),
                             total_relation=total.get("relation", "unknown")), d

    def iterate(self, q: CompiledQuery, max_records: int, page_size: int = PAGE_SIZE,
                pit: PitSession | None = None,
                on_query: Callable[[], bool] | None = None,
                deadline: float | None = None,
                clock: Callable[[], float] = time.monotonic,
                ) -> Iterator[tuple[list[dict], dict]]:
        """Exhaustive raw retrieval with PIT + search_after. Yields (hits, page_meta).

        Raises SourceError on failure; the caller records partial coverage.
        """
        owned = pit is None
        # Opening and closing an owned PIT are physical requests too. Both are reserved before the open, so the
        # close that must follow is always inside the caller's budget.
        if owned and on_query is not None and not (on_query() and on_query()):
            raise SourceBudgetExhausted("source query budget exhausted")
        session = pit or PitSession(self._open_pit(q.target))
        try:
            body = dict(q.body)
            body["size"] = min(page_size, max_records)
            body["pit"] = {"id": session.id, "keep_alive": "2m"}
            body.setdefault(
                "sort",
                [{"@timestamp": {"order": "asc", "format": "strict_date_optional_time_nanos"}},
                 {"_shard_doc": "asc"}],
            )
            body["track_total_hits"] = True
            if self.flavor == "opensearch":
                body["sort"] = _opensearch_sort(body["sort"])
                if not _shard_doc_supported(self.flavor, self.backend):
                    yield from self._pages_by_tie_group(body, session, max_records, q.time_unit, on_query,
                                                        deadline, clock)
                    return
            fetched = 0
            while True:
                if deadline is not None and clock() >= deadline:
                    raise SourceBudgetExhausted("source wall-clock budget exhausted")
                if on_query is not None and not on_query():
                    raise SourceBudgetExhausted("source query budget exhausted")
                d = self.search(None, body)
                if deadline is not None and clock() >= deadline:
                    raise SourceBudgetExhausted("source wall-clock budget exhausted")
                self._carry_pit(session, d)
                body["pit"]["id"] = session.id
                hits = d.get("hits", {}).get("hits", [])
                meta = {
                    "problems": _response_problems(d),
                    "total": d.get("hits", {}).get("total", {}).get("value"),
                    "total_relation": d.get("hits", {}).get("total", {}).get("relation", "unknown"),
                }
                if not hits:
                    yield [], meta
                    return
                fetched += len(hits)
                # read the cursor before the hits are handed over: the consumer may take them as they are
                last = hits[-1]
                after, has_after = last.get("sort"), "sort" in last
                yield hits, meta
                if fetched >= max_records or len(hits) < body["size"]:
                    return
                if not has_after:
                    raise KeyError("sort")
                body["search_after"] = after
        finally:
            if owned:
                try:
                    self._close_pit(session.id)
                except SourceError:
                    pass

    def _budgeted_search(self, body: dict, on_query: Callable[[], bool] | None, deadline: float | None,
                         clock: Callable[[], float]) -> dict:
        if deadline is not None and clock() >= deadline:
            raise SourceBudgetExhausted("source wall-clock budget exhausted")
        if on_query is not None and not on_query():
            raise SourceBudgetExhausted("source query budget exhausted")
        d = self.search(None, body)
        if deadline is not None and clock() >= deadline:
            raise SourceBudgetExhausted("source wall-clock budget exhausted")
        return d

    def _pages_by_tie_group(self, body: dict, session: PitSession, max_records: int, time_unit: str,
                            on_query: Callable[[], bool] | None, deadline: float | None,
                            clock: Callable[[], float]) -> Iterator[tuple[list[dict], dict]]:
        """Paging without a unique tiebreaker (OpenSearch before 3.3 has no `_shard_doc`).

        `search_after` continues strictly after the last sort values, so records tied on them at a page boundary
        would be skipped. Pages therefore sort on time alone, and stop short of their final time: every record at
        that time (its tie group) is read whole, by from/size inside the same point in time, before the next page
        continues strictly after it. Each record is read exactly once. A tie group larger than TIE_GROUP_WINDOW is
        read in part, and the page says how much of it was read. A group is read whole even past `max_records`, so
        one call returns at most max_records + one page + TIE_GROUP_WINDOW records; the caller's cap accounting
        compares what it received with the total, as for any page.

        OpenSearch returns a date sort value as the field's own epoch number (`time_unit`: milliseconds for `date`,
        nanoseconds for `date_nanos`); the tie group's exact range is written from it in that resolution."""
        field, spec = _time_sort(body.get("sort"))
        pit = {"id": session.id, "keep_alive": PIT_KEEP_ALIVE}
        page = {**body, "sort": [{field: spec}], "pit": pit}
        size = page["size"]
        fetched = 0
        while True:
            d = self._budgeted_search(page, on_query, deadline, clock)
            self._carry_pit(session, d)
            pit["id"] = session.id
            hits = d.get("hits", {}).get("hits", [])
            total = d.get("hits", {}).get("total", {})
            meta = {"problems": _response_problems(d), "total": total.get("value"),
                    "total_relation": total.get("relation", "unknown")}
            if len(hits) < size:
                # the rest of the result: no record after it can share its final time
                yield hits, meta
                return
            boundary = _sort_value(hits[-1])
            head = [hit for hit in hits if _sort_value(hit) != boundary]
            fetched += len(head)
            yield head, meta
            for group, problems in self._tie_group(page, field, spec, boundary, len(hits) - len(head), time_unit,
                                                   session, pit, on_query, deadline, clock):
                fetched += len(group)
                yield group, {**meta, "problems": problems}
            if fetched >= max_records:
                return
            page["search_after"] = [boundary]

    def _tie_group(self, page: dict, field: str, spec, boundary, seen: int, time_unit: str, session: PitSession,
                   pit: dict, on_query: Callable[[], bool] | None, deadline: float | None,
                   clock: Callable[[], float]) -> Iterator[tuple[list[dict], list[str]]]:
        """Every record of the page query whose time sort value is `boundary`, in pages of the page size. `seen`
        records at that value were on the page: a group query that finds fewer was written in the wrong resolution,
        and is an error rather than a skip."""
        clauses = [page["query"]] if "query" in page else []
        group = {key: value for key, value in page.items() if key not in ("search_after", "query", "sort", "size")}
        group["query"] = {"bool": {"filter": [*clauses, {"range": {field: _exact_time(boundary, time_unit)}}]}}
        # time first, so each hit returns its own sort value (a multi-valued time field may match the range by
        # another value); _doc orders the group the same way on every page of one point in time
        group["sort"] = [{field: spec}, {"_doc": "asc"}]
        group["track_total_hits"] = True
        offset, total = 0, None
        while True:
            step = min(page["size"], TIE_GROUP_WINDOW - offset)
            if step <= 0:
                yield [], [f"tie_group_window:{field}={boundary}:{offset}<total:{total}"]
                return
            d = self._budgeted_search({**group, "from": offset, "size": step}, on_query, deadline, clock)
            self._carry_pit(session, d)
            pit["id"] = session.id
            hits = d.get("hits", {}).get("hits", [])
            total = d.get("hits", {}).get("total", {}).get("value")
            if offset == 0 and not (isinstance(total, int) and total >= seen):
                raise SourceError(f"the records at one {field} value ({boundary}) could not be read back as a "
                                  f"group: the page held {seen}, the group query found {total}")
            offset += len(hits)
            yield [hit for hit in hits if _sort_value(hit) == boundary], _response_problems(d)
            if len(hits) < step or offset >= total:
                return

    def search_raw(self, q: CompiledQuery) -> dict:
        return self.search(q.target, q.body)


def _usable_pit_id(value) -> bool:
    """A point-in-time id this client may carry and release: a non-empty string, never `_all`."""
    return isinstance(value, str) and bool(value) and value != "_all"


def _opensearch_sort(sort) -> list:
    """The retrieval order as OpenSearch takes it: field sorts without `format`, which its parser refuses."""
    out = []
    for key in sort if isinstance(sort, list) else [sort]:
        if isinstance(key, dict):
            key = {name: ({k: v for k, v in spec.items() if k != "format"} if isinstance(spec, dict) else spec)
                   for name, spec in key.items()}
        out.append(key)
    return out


_PER_SECOND = {"ms": 1_000, "ns": 1_000_000_000}


def _exact_time(value, time_unit: str) -> dict:
    """A range matching exactly one time: an OpenSearch date sort value (epoch milliseconds for a `date` field,
    nanoseconds for `date_nanos`), written as ISO-8601 text with nine fraction digits, which names either exactly."""
    per_second = _PER_SECOND.get(time_unit)
    if per_second is None or isinstance(value, bool) or not isinstance(value, int):
        raise SourceError(f"a time sort value is not an epoch number in a known resolution: {value!r} ({time_unit})")
    seconds, fraction = divmod(value, per_second)
    try:
        moment = datetime(1970, 1, 1, tzinfo=UTC) + timedelta(seconds=seconds)
    except OverflowError as e:
        raise SourceError(f"a time sort value is out of range for {time_unit}: {value}") from e
    text = f"{moment:%Y-%m-%dT%H:%M:%S}.{fraction * (1_000_000_000 // per_second):09d}Z"
    return {"gte": text, "lte": text, "format": "strict_date_optional_time_nanos"}


def _time_sort(sort) -> tuple[str, Any]:
    """The time key of a retrieval order that ends in the `_shard_doc` tiebreaker (the compiler's and iterate's
    default), for paging by tie group where `_shard_doc` does not exist."""
    keys = list(sort) if isinstance(sort, list) else []
    if keys and keys[-1] in ({"_shard_doc": "asc"}, {"_shard_doc": "desc"}):
        keys = keys[:-1]
    if len(keys) != 1 or not isinstance(keys[0], dict) or len(keys[0]) != 1:
        raise SourceError("this OpenSearch has no _shard_doc tiebreaker (3.3 or later), and the retrieval order is "
                          "not a single time key that ROMULUS can page through by whole tie groups")
    (field, spec), = keys[0].items()
    return field, spec


def _sort_value(hit: dict):
    values = hit.get("sort")
    if not isinstance(values, list) or not values:
        raise SourceError("a search hit came back without its sort values")
    return values[0]


def _response_problems(d: dict) -> list[str]:
    problems = []
    if d.get("timed_out"):
        problems.append("timed_out")
    shards = d.get("_shards", {})
    if shards.get("failed"):
        problems.append(f"shard_failures:{shards.get('failed')}")
    if d.get("terminated_early"):
        problems.append("terminated_early")
    return problems
