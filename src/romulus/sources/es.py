"""Read-only Elasticsearch/OpenSearch adapter with an HTTP allowlist that blocks write APIs."""
from __future__ import annotations

import re
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import httpx

from romulus.config import Settings, redact_text
from romulus.sources.models import CompiledQuery, Completeness, SearchOutcome


class WriteAttemptBlocked(RuntimeError):
    """Raised before any request that is not on the read-only allowlist leaves the process."""


class SourceError(RuntimeError):
    def __init__(self, message: str, retryable: bool = False):
        super().__init__(message)
        self.retryable = retryable


@dataclass
class PitSession:
    id: str


_IDX = r"[A-Za-z0-9_.*,\-]+"
# (method, path regex). Everything else is refused. DELETE /_pit only releases a search context.
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
FORBIDDEN_QUERY_KEYS = {"script", "script_fields", "runtime_mappings", "stored_fields"}


def check_allowed(method: str, path: str) -> None:
    method = method.upper()
    for m, rx in ALLOWLIST:
        if m == method and rx.match(path):
            return
    raise WriteAttemptBlocked(f"refused non-allowlisted request {method} {path}")


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
        if settings.es_api_key.get_secret_value():
            headers["Authorization"] = "ApiKey " + settings.es_api_key.get_secret_value()
        elif settings.es_username:
            auth = (settings.es_username, settings.es_password.get_secret_value())
        verify: bool | str = settings.es_verify_tls
        if settings.es_ca_cert:
            verify = settings.es_ca_cert
        self._http = httpx.Client(base_url=settings.es_url.rstrip("/"), auth=auth, headers=headers,
                                  verify=verify, timeout=60.0, transport=transport)
        self._version: str | None = None

    # -- transport -------------------------------------------------------------------------
    def request(self, method: str, path: str, body: dict | None = None, params: dict | None = None) -> dict:
        check_allowed(method, path)
        if body is not None:
            _scan_body(body)
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
                              retryable=retry)
        return r.json() if r.content else {}

    # -- metadata --------------------------------------------------------------------------
    def info(self) -> dict:
        d = self.request("GET", "/")
        self._version = d.get("version", {}).get("number", "")
        return d

    @property
    def version(self) -> str:
        if self._version is None:
            self.info()
        return self._version or ""

    def authenticate(self) -> dict:
        return self.request("GET", "/_security/_authenticate")

    def has_privileges(self, indices: list[str]) -> dict:
        body = {
            "cluster": ["all", "manage", "monitor", "manage_security"],
            "index": [{"names": indices, "privileges": ["read", "write", "index", "delete", "manage",
                                                        "create", "delete_index"]}],
        }
        return self.request("POST", "/_security/user/_has_privileges", body)

    def resolve(self, pattern: str) -> list[str]:
        d = self.request("GET", f"/_resolve/index/{pattern}")
        names = [i["name"] for i in d.get("indices", [])]
        names += [a["name"] for a in d.get("aliases", [])]
        return sorted(set(names))

    def mapping(self, index: str) -> dict:
        return self.request("GET", f"/{index}/_mapping")

    @contextmanager
    def point_in_time(self, target: str):
        session = PitSession(
            self.request("POST", f"/{target}/_pit", params={"keep_alive": "2m"})["id"],
        )
        try:
            yield session
        finally:
            try:
                self.request("DELETE", "/_pit", {"id": session.id})
            except SourceError:
                pass

    # -- search ----------------------------------------------------------------------------
    def run(self, q: CompiledQuery) -> tuple[SearchOutcome, dict | None]:
        """Execute a single-request (aggregate/histogram) query. Returns (outcome shell, response)."""
        started = datetime.now(UTC)
        try:
            d = self.request("POST", f"/{q.target}/_search", q.body)
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

    def iterate(self, q: CompiledQuery, max_records: int, page_size: int = 2000,
                pit: PitSession | None = None,
                ) -> Iterator[tuple[list[dict], dict]]:
        """Exhaustive raw retrieval with PIT + search_after. Yields (hits, page_meta).

        Raises SourceError on failure; the caller records partial coverage.
        """
        owned = pit is None
        session = pit or PitSession(
            self.request("POST", f"/{q.target}/_pit", params={"keep_alive": "2m"})["id"],
        )
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
            fetched = 0
            while True:
                d = self.request("POST", "/_search", body)
                session.id = d.get("pit_id", session.id)
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
                yield hits, meta
                if fetched >= max_records or len(hits) < body["size"]:
                    return
                body["search_after"] = hits[-1]["sort"]
        finally:
            if owned:
                try:
                    self.request("DELETE", "/_pit", {"id": session.id})
                except SourceError:
                    pass

    def search_raw(self, q: CompiledQuery) -> dict:
        return self.request("POST", f"/{q.target}/_search", q.body)


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
