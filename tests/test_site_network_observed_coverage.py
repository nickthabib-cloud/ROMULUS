"""Observed network endpoints must reveal omissions without redefining the site."""
from collections import Counter
from copy import deepcopy
from datetime import UTC, datetime, timedelta

import pytest

from romulus.config import Settings
from romulus.detect.netdef import SiteNetworks
from romulus.doctor import check_site_networks
from romulus.hunt import run as hunt_run
from romulus.report import markdown
from romulus.report.manifest import build_manifest as build_report
from romulus.sources.models import Window
from romulus.sources.profile import SourceProfile, contract_from_types

START = datetime(2024, 5, 1, tzinfo=UTC)
WINDOW = Window(start=START, end=START + timedelta(hours=1))
TYPES = {"@timestamp": "date", "source.ip": "ip", "destination.ip": "ip"}
SITE = SiteNetworks.from_lists(["10.1.0.0/16"])


class EndpointSource:
    """Evaluate the fixed aggregation boundary against synthetic rows, including the time predicate."""

    def __init__(self, rows, types=None, response_patch=None, fail=False):
        self.rows = rows
        self.types = types or {name: TYPES for name in rows}
        self.requests = []
        self.response_patch = response_patch
        self.fail = fail

    def resolve(self, pattern):
        return list(self.rows)

    def mapping(self, target):
        return {target: {"mappings": {"properties": {
            name: {"type": kind} for name, kind in self.types[target].items()}}}}

    def search(self, target, body):
        from romulus.errors import SourceError
        self.requests.append((target, deepcopy(body)))
        if self.fail:
            raise SourceError("synthetic source unavailable")
        assert body["size"] == 0
        assert body["track_total_hits"] is False
        rows = self.rows[target]
        for clause in body.get("query", {}).get("bool", {}).get("filter", []):
            if "range" in clause:
                field, bounds = next(iter(clause["range"].items()))
                rows = [row for row in rows if bounds["gte"] <= row[field] < bounds["lt"]]
        aggs = {}
        for label, agg in body["aggs"].items():
            terms = agg["terms"]
            assert terms["size"] <= 1000
            assert terms["order"] == {"_key": "asc"}
            values = Counter()
            for row in rows:
                raw = row.get(terms["field"], [])
                values.update(set(raw if isinstance(raw, list) else [raw]))
            keys = sorted(values)
            size = terms["size"]
            aggs[label] = {"buckets": [{"key": key, "doc_count": values[key]} for key in keys[:size]],
                           "sum_other_doc_count": sum(values[key] for key in keys[size:]),
                           "doc_count_error_upper_bound": 0}
        result = {"timed_out": False, "_shards": {"total": 1, "successful": 1, "failed": 0},
                  "aggregations": aggs}
        if self.response_patch:
            self.response_patch(result)
        return result


def row(src, dst="198.51.100.10", at=START, clock="@timestamp"):
    return {"source.ip": src, "destination.ip": dst, clock: at.isoformat()}


def _check(source, definition=SITE, window=WINDOW):
    from romulus.sources.network_coverage import check_network_addresses
    contracts = {name: contract_from_types(name, source.types[name]) for name in source.rows}
    return check_network_addresses(source, contracts, definition, window)


def test_doctor_warns_on_observed_private_network_gap_before_hunting(tmp_path):
    source = EndpointSource({"wire": [row("10.2.0.8"), row("10.1.0.9")]})
    result = check_site_networks(Settings(home=tmp_path, es_index_patterns=["wire"],
                                          internal_networks=["10.1.0.0/16"]), source)
    assert result.status == "warn"
    assert "50.0%" in result.detail and "10.2.0.0/16" in result.detail
    assert result.data["coverage"]["outside_share"] == .5
    assert len(source.requests) == 1


def test_distinct_union_counts_addresses_once_across_sides_targets_and_repeated_rows():
    source = EndpointSource({"a": [row("10.2.0.8", "10.1.0.9")] * 500,
                             "b": [row("10.1.0.9", "10.2.0.8"), row("100.64.1.3", "fdab:1234:5678::4")]})
    result = _check(source)
    assert (result["private_addresses"], result["outside"], result["outside_share"]) == (4, 3, .75)
    assert result["status"] == "uncovered" and result["warn"]
    assert result["prefixes"] == ["10.2.0.0/16", "100.64.0.0/16", "fdab:1234:5678::/48"]
    assert len(source.requests) == 2


def test_hunt_window_applies_to_arkime_native_clock_and_ignores_out_of_scope_addresses():
    types = {"firstPacket": "date", "lastPacket": "date", "network.community_id": "keyword",
             "source.ip": "ip", "destination.ip": "ip"}
    source = EndpointSource({"sessions": [row("10.1.0.9", clock="firstPacket"),
                                          row("10.2.0.8", at=WINDOW.end, clock="firstPacket")]},
                            {"sessions": types})
    result = _check(source)
    assert result["status"] == "covered" and result["outside"] == 0
    assert result["arkime"]["status"] == "checked"
    assert len(source.requests) == 1
    bounds = source.requests[0][1]["query"]["bool"]["filter"][0]["range"]["firstPacket"]
    assert bounds == {"gte": START.isoformat(), "lt": WINDOW.end.isoformat()}


@pytest.mark.parametrize("addresses", [["198.51.100.5", "203.0.113.6"], ["127.0.0.1", "fe80::1"], []])
def test_no_private_endpoints_is_not_a_missing_rfc1918_declaration(addresses):
    source = EndpointSource({"wire": [row(address) for address in addresses]})
    result = _check(source, SiteNetworks.from_lists(["198.51.100.0/24"]))
    assert result["status"] == "no_private_observed"
    assert result["private_addresses"] == 0 and result["outside_share"] is None and not result["warn"]


def test_no_network_targets_is_not_claimed_covered():
    source = EndpointSource({"host": []}, {"host": {"@timestamp": "date", "host.ip": "ip"}})
    result = _check(source)
    assert result["status"] == "not_applicable" and not source.requests
    assert result["arkime"]["status"] == "unknown"


@pytest.mark.parametrize("patch", [
    lambda result: result.update(timed_out=True),
    lambda result: result["_shards"].update(failed=1),
    lambda result: result.update(terminated_early=True),
    lambda result: result["aggregations"]["source"].update(sum_other_doc_count=3),
    lambda result: result["aggregations"]["destination"].update(doc_count_error_upper_bound=1),
    lambda result: result["aggregations"].pop("source"),
])
def test_capped_partial_and_malformed_answers_never_claim_covered(patch):
    result = _check(EndpointSource({"wire": [row("10.1.0.8")]}, response_patch=patch))
    assert result["status"] == "unknown" and result["at_least"] and result["warn"]
    assert result["reasons"]


def test_query_failure_is_unknown_but_other_targets_retained():
    result = _check(EndpointSource({"wire": [row("10.1.0.8")]}, fail=True))
    assert result["status"] == "unknown" and result["outside_share"] is None
    assert result["reasons"] and result["warn"]


def test_global_distinct_cap_is_honest_and_retains_known_uncovered(monkeypatch):
    from romulus.sources import network_coverage
    monkeypatch.setattr(network_coverage, "DISTINCT_CAP", 2)
    source = EndpointSource({"a": [row("10.2.0.1"), row("10.2.0.2")], "b": [row("10.2.0.3")]})
    result = _check(source)
    assert result["status"] == "unknown" and result["private_addresses"] == 2 and result["outside"] == 2
    assert "10.2.0.0/16" in result["prefixes"]


def test_invalid_address_is_counted_unresolved_instead_of_silently_complete():
    result = _check(EndpointSource({"wire": [row("not an address")]}))
    assert result["status"] == "unknown" and result["invalid_addresses"] == 1


def test_ipv4_mapped_values_canonicalize_and_reserved_ranges_do_not_count_as_private():
    result = _check(EndpointSource({"wire": [row("::ffff:10.2.0.8", "10.2.0.8"),
                                             row("192.0.2.1", "2001:db8::1")]}))
    assert result["private_addresses"] == result["outside"] == 1
    assert result["prefixes"] == ["10.2.0.0/16"]


def test_an_intentional_carve_out_is_visible_but_network_definition_is_unchanged():
    definition = SiteNetworks.from_lists(["10.0.0.0/8"], ["10.9.0.0/16"])
    before = definition.record()
    result = _check(EndpointSource({"wire": [row("10.9.0.8")]}), definition)
    assert result["outside"] == 1 and "carve-out" in result["summary"]
    assert definition.record() == before


def test_small_uncovered_share_is_reported_without_threshold_warning():
    result = _check(EndpointSource({"wire": [row(f"10.1.0.{n}") for n in range(1, 20)] + [row("10.2.0.8")]}))
    assert result["outside_share"] == .05 and result["outside"] == 1
    assert result["status"] == "uncovered" and not result["warn"]
    assert "10.2.0.0/16" in result["summary"]


def test_create_hunt_freezes_window_coverage_and_reports_it(tmp_path, monkeypatch):
    source = EndpointSource({"wire": [row("10.2.0.8"), row("10.3.0.8", at=WINDOW.end)]})
    settings = Settings(home=tmp_path, es_index_patterns=["wire"], internal_networks=["10.1.0.0/16"])
    profile = SourceProfile(id="synthetic", target="wire", kind="lab_ecs", role="network", os_family="unknown",
        backend="elasticsearch", backend_version="8", captured_at=START, field_types=TYPES, doc_count=2)
    contract = contract_from_types("wire", TYPES)
    monkeypatch.setattr(hunt_run, "ElasticClient", lambda _settings: source)
    monkeypatch.setattr(hunt_run, "build_profile", lambda *_args, **_kwargs: (profile, contract))
    monkeypatch.setattr(hunt_run, "ai_agent_entry", lambda *_args: {"requested": False})
    hunt_id = hunt_run.create_hunt(settings, START, WINDOW.end, "analyst")
    repo = hunt_run.open_repo(settings)
    try:
        manifest = repo.get_hunt(hunt_id)["manifest"]
        coverage = manifest["internal_networks"]["coverage"]
        assert coverage["outside"] == 1 and coverage["prefixes"] == ["10.2.0.0/16"]
        assert coverage["window"] == {"start": START.isoformat(), "end": WINDOW.end.isoformat(), "semantics": "[start,end)"}
        assert len(source.requests) == 1
        repo.audit("system", "hunt.sweep_summary", hunt_id, {"internal_networks": {
            "warning": "Synthetic host-address warning", "outside": 1}})
        report = build_report(repo, hunt_id, "analyst")
        assert report["coverage"]["internal_networks"] == coverage
        assert report["internal_networks"]["coverage"] == coverage
        text = markdown.render({**report, "revision": {"number": 1, "id": "r1", "supersedes": None}})
        section = text.split("## Coverage", 1)[1]
        assert "10.2.0.0/16" in section and "100.0%" in section
        assert "10.3.0.0/16" not in section
        assert "Synthetic host-address warning" in report["internal_networks"]["warning"]
        from xml.etree import ElementTree
        from zipfile import ZipFile

        from romulus.report import executive
        document = tmp_path / "executive.docx"
        executive.write({**report, "revision": {"number": 1}}, document, "technical.md")
        with ZipFile(document) as archive:
            xml = ElementTree.fromstring(archive.read("word/document.xml"))
        doc_text = " ".join(xml.itertext())
        assert "Internal-network coverage" in doc_text and "10.2.0.0/16" in doc_text
        assert "100.0%" in doc_text
    finally:
        repo.engine.dispose()

def test_arkime_integer_millisecond_clock_uses_exact_hunt_bounds():
    types = {"firstPacket": "long", "lastPacket": "long", "network.community_id": "keyword",
             "source.ip": "ip", "destination.ip": "ip"}
    begin = int(START.timestamp() * 1000)
    end = int(WINDOW.end.timestamp() * 1000)
    source = EndpointSource({"sessions": [dict(row("10.1.0.9"), firstPacket=begin),
                                          dict(row("10.2.0.8"), firstPacket=end)]}, {"sessions": types})
    result = _check(source)
    assert result["status"] == "covered" and result["outside"] == 0
    assert len(source.requests) == 1
    bounds = source.requests[0][1]["query"]["bool"]["filter"][0]["range"]["firstPacket"]
    assert bounds == {"gte": 1714521600000, "lt": 1714525200000}


def test_late_uncovered_address_remains_visible_when_private_address_cap_is_full(monkeypatch):
    from romulus.sources import network_coverage
    monkeypatch.setattr(network_coverage, "DISTINCT_CAP", 2)
    source = EndpointSource({"a": [row("10.1.0.1"), row("10.1.0.2")], "z": [row("10.9.0.1")]})
    result = _check(source)
    assert result["status"] == "unknown" and result["outside"] == 1
    assert "10.9.0.0/16" in result["prefixes"]


def test_query_count_and_target_details_are_bounded_and_remaining_targets_named_as_unchecked(monkeypatch):
    from romulus.sources import network_coverage
    monkeypatch.setattr(network_coverage, "TARGET_LIMIT", 2, raising=False)
    result = _check(source := EndpointSource({f"wire-{n}": [row("10.1.0.9")] for n in range(5)}))
    assert len(source.requests) == 2
    assert result["status"] == "unknown" and result["targets_omitted"] == 3
    assert len(result["checked_targets"]) == 2


def test_declared_plain_zeek_uses_native_addresses_and_epoch_seconds():
    from romulus.sources.network_coverage import check_network_addresses
    types = {"ts": "double", "id.orig_h": "ip", "id.resp_h": "ip"}
    source = EndpointSource({"plain": [{"ts": START.timestamp(), "id.orig_h": "10.2.0.9", "id.resp_h": "10.1.0.8"},
                                       {"ts": WINDOW.end.timestamp(), "id.orig_h": "10.3.0.9"}]}, {"plain": types})
    contract = contract_from_types("plain", types, role="network").model_copy(
        update={"time_field": "ts", "zeek_sensor": "test-sensor", "zeek_log": "conn"})
    result = check_network_addresses(source, {"plain": contract}, SITE, WINDOW)
    assert result["outside"] == 1 and result["outside_share"] == .5
    assert result["prefixes"] == ["10.2.0.0/16"]


def test_absent_one_endpoint_mapping_is_unknown_not_false_complete():
    types = {"@timestamp": "date", "source.ip": "ip", "event.dataset": "keyword"}
    from romulus.sources.network_coverage import check_network_addresses
    source = EndpointSource({"wire": []}, {"wire": types})
    result = check_network_addresses(source, {"wire": contract_from_types("wire", types, role="network")}, SITE, WINDOW)
    assert result["status"] == "unknown" and result["unchecked_targets"] and not source.requests

def test_incomplete_shard_accounting_and_missing_timeout_flag_are_unknown():
    for patch in (lambda response: response["_shards"].update(total=2, successful=1),
                  lambda response: response.pop("timed_out")):
        result = _check(EndpointSource({"wire": [row("10.1.0.8")]}, response_patch=patch))
        assert result["status"] == "unknown"


def test_doctor_failed_mapping_explicitly_reports_unknown_network_coverage(tmp_path):
    from romulus.errors import SourceError
    source = EndpointSource({"wire": []})
    source.mapping = lambda target: (_ for _ in ()).throw(SourceError("unavailable"))
    result = check_site_networks(Settings(home=tmp_path, es_index_patterns=["wire"],
                                          internal_networks=["10.1.0.0/16"]), source)
    assert result.status == "warn"
    assert result.data["coverage"]["status"] == "unknown"


def test_arkime_failed_query_does_not_claim_arkime_was_checked():
    types = {"firstPacket": "date", "lastPacket": "date", "network.community_id": "keyword",
             "source.ip": "ip", "destination.ip": "ip"}
    result = _check(EndpointSource({"sessions": []}, {"sessions": types}, fail=True))
    assert result["status"] == "unknown" and result["arkime"]["status"] == "unknown"

def test_doctor_declared_plain_source_with_wrong_clock_is_unknown_not_a_crash(tmp_path):
    (tmp_path / "site").mkdir()
    (tmp_path / "site" / "collection.yaml").write_text(
        "schema: romulus-site-collection@1\nzeek:\n  plain_sources:\n    wire:\n      sensor: synthetic\n", encoding="utf-8")
    source = EndpointSource({"wire": []})
    result = check_site_networks(Settings(home=tmp_path, es_index_patterns=["wire"],
                                          internal_networks=["10.1.0.0/16"]), source)
    assert result.status == "warn" and result.data["coverage"]["status"] == "unknown"
