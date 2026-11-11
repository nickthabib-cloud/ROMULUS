"""A single bounded preflight count governs header-host retrieval coverage."""
import re

import pytest

from romulus.errors import SourceError
from romulus.hunt.pivot import _text_host_coverage
from romulus.sources.models import Predicate, SearchIntent, Window
from romulus.sources.profile import build_profile
from tests.test_linux_text_reporting import FIELDS, ProfileClient, _sample
from tests.test_syslog_host_queries import END, REASON, START, _line
from tests.zeek_source_support import matches, value


def _count_matches(query, source):
    # The preflight's bounded whitespace character class has identical full-term
    # semantics in this synthetic evaluator and Lucene's regexp query.
    if "regexp" in query:
        field, spec = next(iter(query["regexp"].items()))
        actual = value(source, field)
        return isinstance(actual, str) and re.fullmatch(spec["value"], actual) is not None
    if "bool" in query:
        spec = query["bool"]
        return (all(_count_matches(q, source) for q in spec.get("filter", []))
                and not any(_count_matches(q, source) for q in spec.get("must_not", []))
                and sum(_count_matches(q, source) for q in spec.get("should", []))
                >= spec.get("minimum_should_match", 1 if spec.get("should") else 0))
    return matches(query, source)


class HostCountClient(ProfileClient):
    def __init__(self, rows, *, count=None, failure=None, dataset="system.syslog", datasetless=False):
        fields = {**FIELDS, "log.file.path": "keyword"} if datasetless else FIELDS
        samples = [_sample([], "", total=0)] if datasetless else []
        if datasetless:
            samples[0]["hits"]["total"]["relation"] = "gte"
        elif dataset not in {"system.syslog", "system.auth"}:
            samples = [_sample([], dataset, total=len(rows))]
        super().__init__({dataset: len(rows)} if dataset else {}, samples=samples, fields=fields)
        self.rows, self.count, self.failure = rows, count, failure

    def search(self, target, body):
        if "text_missing_host" not in body.get("aggs", {}):
            return super().search(target, body)
        self.bodies.append(body)
        if self.failure == "error":
            raise SourceError("synthetic count failure")
        query = body["aggs"]["text_missing_host"]["filter"]
        count = self.count if self.count is not None else sum(_count_matches(query, row["_source"]) for row in self.rows)
        return {"aggregations": {"text_missing_host": {"doc_count": count}},
                **({"timed_out": True} if self.failure == "timeout" else {}),
                **({"_shards": {"failed": 1}} if self.failure == "shards" else {})}


def _rows(dataset, indexed):
    rows = [_line(0, "app01"), _line(1, "app01" if indexed else None)]
    for row in rows:
        row["_source"]["event"] = {"dataset": dataset}
    return rows


def _gaps(contract, inventory, dataset="linux.syslog"):
    intent = SearchIntent(kind="raw", target="logs", window=Window(start=START, end=END), filters=[
        Predicate(field="host.name", op="eq", value="app01"),
        Predicate(field="event.dataset", op="eq", value=dataset)])
    return _text_host_coverage({"logs": contract}, {"logs": inventory}, [intent])


@pytest.mark.parametrize("dataset", ["system.syslog", "system.auth", "custom.auth"])
@pytest.mark.parametrize("indexed", [False, True])
def test_preflight_count_distinguishes_indexed_and_header_only_syslog(dataset, indexed):
    client = HostCountClient(_rows(dataset, indexed), dataset=dataset)
    profile, contract = build_profile(client, "logs")
    assert contract.text_missing_host_records == (0 if indexed else 1)
    assert bool(_gaps(contract, profile.datasets, "linux.text" if dataset == "custom.auth" else "linux.syslog")) \
        is (not indexed)
    queries = [body for body in client.bodies if "text_missing_host" in body.get("aggs", {})]
    assert len(queries) == 1 and queries[0]["size"] == 0


@pytest.mark.parametrize("failure", ["error", "timeout", "shards"])
def test_failed_count_stays_unknown_and_syslog_coverage_partial(failure):
    profile, contract = build_profile(HostCountClient(_rows("system.syslog", True), failure=failure), "logs")
    assert contract.text_missing_host_records is None
    assert _gaps(contract, profile.datasets)[0].reasons == [REASON]


def test_unknown_datasetless_count_cannot_silence_the_header_gap():
    client = HostCountClient([_line(0)], dataset="", datasetless=True, failure="error")
    profile, contract = build_profile(client, "logs")
    assert "linux.text" not in profile.datasets
    assert contract.text_missing_host_records is None
    assert _gaps(contract, profile.datasets, "linux.text")


def test_very_large_count_uses_one_scalar_filter_aggregation():
    client = HostCountClient([], count=500_000_000)
    _, contract = build_profile(client, "logs")
    assert contract.text_missing_host_records == 500_000_000
    [body] = [body for body in client.bodies if "text_missing_host" in body.get("aggs", {})]
    assert set(body["aggs"]) == {"text_missing_host"}
    assert set(body["aggs"]["text_missing_host"]) == {"filter"}


@pytest.mark.parametrize("host", ["", " ", "\t\n", "\u00a0", "\u2003", "\x1c", "\u3000"])
def test_indexed_blank_hosts_cannot_hide_header_only_records(host):
    from romulus.evidence.normalize import normalize_hits
    rows = _rows("system.syslog", True)
    rows[1]["_source"]["host"]["name"] = host
    events, skips, errors = normalize_hits(rows)
    assert not skips and not errors and {e.host for e in events} == {"app01"}
    profile, contract = build_profile(HostCountClient(rows), "logs")
    assert contract.text_missing_host_records == 1
    assert _gaps(contract, profile.datasets)


def test_analyzed_host_without_exact_field_cannot_prove_no_blank_hosts():
    from romulus.sources.profile import _text_missing_host_count, contract_from_types
    contract = contract_from_types("logs", {**FIELDS, "host.name": "text"})
    assert _text_missing_host_count(HostCountClient(_rows("system.syslog", True)), "logs", contract) is None
