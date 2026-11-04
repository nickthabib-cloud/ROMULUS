"""Malformed backend JSON must preserve computed positives and name incomplete retrieval."""
import json
from datetime import timedelta

import httpx
import pytest

from romulus.config import Settings
from romulus.detect.windows_auth_events import WindowsBruteForce
from romulus.hunt.publish import SourceCitationFetcher, WindowsCitationFetcher, publish_match
from romulus.sources.es import ElasticClient
from romulus.sources.execute import execute
from romulus.sources.models import Completeness, SearchIntent, Window
from romulus.sources.profile import contract_from_types
from tests.test_sweep import _repo
from tests.test_windows_c_burst_review import START, failure
from tests.test_windows_c_round4 import dns
from tests.test_windows_c_round5 import _feed, _native_sweep

_SHAPES = [[], "private login message", None, False, 42, {"hits": []}, {"hits": None},
           {"hits": {"hits": {}}}, {"hits": {"hits": None}}, {"hits": {"hits": "private login message"}}]


def shape_client(payload, *, metadata=False):
    def respond(request):
        if metadata and request.url.path == "/":
            return httpx.Response(200, json={"version": {"number": "8.19.0"}})
        if request.url.path.endswith("/_pit"):
            return httpx.Response(200, json={"id": "test-pit"})
        return httpx.Response(200, content=json.dumps(payload), headers={"content-type": "application/json"})
    return ElasticClient(Settings(es_url="http://es.invalid"), transport=httpx.MockTransport(respond))


@pytest.mark.parametrize("payload", _SHAPES)
def test_wrong_shape_citation_json_retains_every_native_positive(tmp_path, monkeypatch, payload):
    rule, sweep = _native_sweep(tmp_path, monkeypatch)
    pairs = [dns(1, "first.c2.test"), dns(2, "second.c2.test")]
    _feed(sweep, pairs, monkeypatch)
    sweep._event_stage()._compact_cache([pairs[0][0]], (sweep._stage_owner_accounts[rule.id],), drop_raw=True)
    rule.citation_fetcher = SourceCitationFetcher(shape_client(payload))
    try:
        sweep.finalize()
        rows = sweep.repo.candidates("h1")
        assert len(rows) == 2 and all(row["lane"] == "high" for row in rows)
        assert all("invalid JSON response shape" in row["claim"] and "partial" in row["claim"] for row in rows)
        assert all("private login message" not in row["claim"] for row in rows)
    finally:
        sweep.close_stage()


@pytest.mark.parametrize("kind", ["raw", "aggregate", "histogram"])
@pytest.mark.parametrize("payload", _SHAPES)
def test_wrong_shape_search_json_names_incomplete_query(kind, payload):
    intent = SearchIntent(target="logs", kind=kind, group_by=["host.name"] if kind == "aggregate" else [],
                          window=Window(start=START, end=START+timedelta(hours=1)))
    contract = contract_from_types("logs", {"@timestamp": "date", "host.name": "keyword"})
    outcome = execute(shape_client(payload, metadata=True), intent, contract)
    assert outcome.completeness != Completeness.complete
    assert outcome.reasons == ["source_error"] and "invalid JSON response shape" in outcome.error
    assert "private login message" not in outcome.error


@pytest.mark.parametrize("payload", _SHAPES)
def test_wrong_shape_metadata_json_names_incomplete_query(payload):
    intent = SearchIntent(target="logs", kind="raw", window=Window(start=START, end=START+timedelta(hours=1)))
    outcome = execute(shape_client(payload), intent, contract_from_types("logs", {"@timestamp": "date"}))
    assert outcome.completeness != Completeness.complete
    assert outcome.reasons == ["source_error"] and "invalid JSON response shape" in outcome.error


@pytest.mark.parametrize("payload", [[], {"hits": []}, {"hits": {"hits": "private login message"}}])
def test_wrong_shape_auth_hydration_preserves_computed_burst(payload):
    rule, repo = WindowsBruteForce(), _repo()
    rule.citation_fetcher = WindowsCitationFetcher(shape_client(payload))
    try:
        matches = rule.consume([failure(n, account="service") for n in range(25)])
        assert matches
        for match in matches:
            publish_match(repo, "h1", rule, match, None, {})
        rows = repo.candidates("h1")
        assert rows and all("invalid JSON response shape" in row["claim"] for row in rows)
    finally:
        rule.release_state()
