"""Observed network endpoints must reveal omissions without redefining the site."""
import ipaddress
import json
from collections import Counter
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from functools import cache

import httpx
import pytest

from romulus.config import Settings
from romulus.detect.netdef import SiteNetworks
from romulus.doctor import check_site_networks
from romulus.hunt import run as hunt_run
from romulus.report import markdown
from romulus.report.manifest import build_manifest as build_report
from romulus.sources.es import SEARCH_FILTER_PATH, ElasticClient
from romulus.sources.models import Window
from romulus.sources.profile import SourceProfile, contract_from_types

START = datetime(2024, 5, 1, tzinfo=UTC)
WINDOW = Window(start=START, end=START + timedelta(hours=1))
TYPES = {"@timestamp": "date", "source.ip": "ip", "destination.ip": "ip"}
LISTED = {"@timestamp": "date", "source.ip": "keyword", "destination.ip": "keyword"}
SITE = SiteNetworks.from_lists(["10.1.0.0/16"])


@cache
def _address(value):
    """An ip field's value as the cluster holds it: an IPv4-mapped IPv6 address is the IPv4 address."""
    address = ipaddress.ip_address(value)
    return address.ipv4_mapped or address if address.version == 6 else address


@cache
def _network(value):
    return ipaddress.ip_network(value)


def _values(row, field, kind):
    raw = row.get(field, [])
    values = raw if isinstance(raw, list) else [raw]
    return [str(_address(value)) for value in values] if kind == "ip" else values


def _matches(row, clause, types):
    """The query DSL the check sends, evaluated per document the way the cluster evaluates it."""
    if "bool" in clause:
        parts = clause["bool"]
        if any(_matches(row, part, types) for part in parts.get("must_not", [])):
            return False
        if not all(_matches(row, part, types) for part in parts.get("filter", [])):
            return False
        should = parts.get("should", [])
        return not should or sum(_matches(row, part, types) for part in should) >= parts["minimum_should_match"]
    if "range" in clause:
        ((field, bounds),) = clause["range"].items()
        if field not in row:
            return False
        read = datetime.fromisoformat if types[field] == "date" else (lambda value: value)
        return read(bounds["gte"]) <= read(row[field]) < read(bounds["lt"])
    if "terms" in clause:
        ((field, wanted),) = clause["terms"].items()
        assert types[field] == "ip", "address ranges select only from an ip field"
        return any(address.version == network.version and address in network
                   for address in map(_address, _values(row, field, "ip")) for network in map(_network, wanted))
    raise AssertionError(f"unexpected clause {clause}")


def _aggregate(rows, aggs, types):
    out = {}
    for name, agg in aggs.items():
        if "filter" in agg:
            kept = [row for row in rows if _matches(row, agg["filter"], types)]
            out[name] = {"doc_count": len(kept), **_aggregate(kept, agg.get("aggs", {}), types)}
            continue
        ((kind, spec),) = agg.items()
        field = spec["field"]
        values = Counter()
        for row in rows:
            values.update(set(_values(row, field, types.get(field))))
        if kind == "terms":
            assert spec["size"] <= 1000
            assert spec["order"] == {"_key": "asc"}
            # an ip field orders by address, IPv4 among the IPv4-mapped IPv6 addresses; a keyword by its text
            order = ((lambda key: int(ipaddress.IPv6Address(f"::ffff:{key}" if ":" not in key else key)))
                     if types.get(field) == "ip" else str)
            keys = sorted(values, key=order)
            out[name] = {"doc_count_error_upper_bound": 0,
                         "sum_other_doc_count": sum(values[key] for key in keys[spec["size"]:]),
                         "buckets": [{"key": key, "doc_count": values[key]} for key in keys[:spec["size"]]]}
        elif kind == "cardinality":
            assert spec["precision_threshold"] <= 40_000
            out[name] = {"value": len(values)}
        elif kind == "max":
            if not values:
                out[name] = {"value": None}
            elif types[field] == "date":
                newest = max(map(datetime.fromisoformat, values))
                out[name] = {"value": newest.timestamp() * 1000, "value_as_string": newest.isoformat()}
            else:
                out[name] = {"value": max(values)}
        else:
            raise AssertionError(f"unexpected aggregation {agg}")
    return out


def _only(node, paths):
    """What a response keeps under a filter path: the fields it names and nothing else."""
    if isinstance(node, list):
        return [kept for item in node if (kept := _only(item, paths))]
    if not isinstance(node, dict):
        return None
    kept = {}
    for key, value in node.items():
        below = [path[1:] for path in paths if path[0] == key]
        if any(not rest for rest in below):
            kept[key] = value
        elif below and (inner := _only(value, below)):
            kept[key] = inner
    return kept


class EndpointSource:
    """A cluster of synthetic rows that evaluates the check's queries and aggregations, time predicate included.

    Called directly it stands for the client; as an `httpx.MockTransport` handler it stands for the cluster behind
    the real client. Either way a search answer carries only the fields the request's filter path names."""

    def __init__(self, rows, types=None, response_patch=None, fail=False):
        self.rows = rows
        self.types = types or {name: TYPES for name in rows}
        self.requests = []
        self.answers = []
        self.response_patch = response_patch
        self.fail = fail

    def resolve(self, pattern):
        return list(self.rows)

    def mapping(self, target):
        return {target: {"mappings": {"properties": {
            name: {"type": kind} for name, kind in self.types[target].items()}}}}

    def search(self, target, body):
        from romulus.errors import SourceError
        if self.fail:
            self.requests.append((target, deepcopy(body)))
            raise SourceError("synthetic source unavailable")
        return self._answer(target, body, SEARCH_FILTER_PATH)

    def _answer(self, target, body, filter_path):
        self.requests.append((target, deepcopy(body)))
        assert body["size"] == 0
        assert body["track_total_hits"] is False
        types = self.types[target]
        rows = [row for row in self.rows[target] if _matches(row, body.get("query", {"bool": {}}), types)]
        answer = {"took": 1, "timed_out": False,
                  "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0},
                  "hits": {"max_score": None, "hits": []}, "aggregations": _aggregate(rows, body["aggs"], types)}
        if self.response_patch and "newest" not in body["aggs"]:
            self.response_patch(answer)
        answer = _only(answer, [path.split(".") for path in filter_path.split(",")])
        self.answers.append(answer)
        return answer

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/":
            return httpx.Response(200, json={"version": {"number": "8.17.0"}})
        if path.startswith("/_resolve/index/"):
            return httpx.Response(200, json={"indices": [{"name": name} for name in sorted(self.rows)]})
        target, _, action = path.strip("/").partition("/")
        if action == "_mapping":
            props: dict = {}
            for name, kind in self.types[target].items():
                node = props
                *parents, leaf = name.split(".")
                for part in parents:
                    node = node.setdefault(part, {"properties": {}})["properties"]
                node[leaf] = {"type": kind}
            return httpx.Response(200, json={target: {"mappings": {"properties": props}}})
        assert action == "_search"
        if self.fail:
            return httpx.Response(503, text="synthetic source unavailable")
        return httpx.Response(200, json=self._answer(target, json.loads(request.content),
                                                     request.url.params["filter_path"]))


def _client(source, **settings) -> ElasticClient:
    """The real client, with `source` as the cluster behind its transport."""
    return ElasticClient(Settings(es_url="http://es.invalid", es_index_patterns=list(source.rows), **settings),
                         transport=httpx.MockTransport(source))


def row(src, dst="198.51.100.10", at=START, clock="@timestamp"):
    return {"source.ip": src, "destination.ip": dst, clock: at.isoformat()}


def _check(source, definition=SITE, window=WINDOW, client=None):
    from romulus.sources.network_coverage import check_network_addresses
    contracts = {name: contract_from_types(name, source.types[name]) for name in source.rows}
    return check_network_addresses(client or source, contracts, definition, window)


def test_doctor_warns_on_observed_private_network_gap_before_hunting(tmp_path):
    source = EndpointSource({"wire": [row("10.2.0.8"), row("10.1.0.9"),
                                      row("10.3.0.8", at=START - timedelta(days=7, seconds=1))]})
    result = check_site_networks(Settings(home=tmp_path, es_index_patterns=["wire"],
                                          internal_networks=["10.1.0.0/16"]), source)
    assert result.status == "warn"
    assert "50.0%" in result.detail and "10.2.0.0/16" in result.detail
    assert result.data["coverage"]["outside_share"] == .5
    # one request finds the target's newest record; the one coverage request reads the week ending at it
    (_, newest), (_, coverage) = source.requests
    assert set(newest["aggs"]) == {"newest"}
    assert coverage["query"]["bool"]["filter"][0]["range"]["@timestamp"] == {
        "gte": (START - timedelta(days=7)).isoformat(), "lt": (START + timedelta(milliseconds=1)).isoformat()}
    assert result.data["coverage"]["window"] == "last 7 days of each target"
    assert "10.3.0.0/16" not in result.detail


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
    lambda result: result["aggregations"]["source"]["outside"]["addresses"].update(sum_other_doc_count=3),
    lambda result: result["aggregations"]["destination"]["outside"]["addresses"].update(
        doc_count_error_upper_bound=1),
    lambda result: result["aggregations"].pop("source"),
    lambda result: result["aggregations"]["source"].pop("covered"),
    lambda result: result["aggregations"]["destination"]["outside"].pop("addresses"),
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
    assert result["status"] == "uncovered" and result["at_least"] and result["warn"]
    assert result["private_addresses"] == 2 and result["outside"] == 2
    assert "10.2.0.0/16" in result["prefixes"]


def test_invalid_address_is_counted_unresolved_instead_of_silently_complete():
    result = _check(EndpointSource({"wire": [row("not an address")]}, {"wire": LISTED}))
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
    source = EndpointSource({"a": [row("10.1.0.1"), row("10.1.0.2"), row("10.1.0.3")], "z": [row("10.9.0.1")]},
                            {"a": LISTED, "z": LISTED})
    result = _check(source)
    assert result["status"] == "uncovered" and result["at_least"] and result["warn"] and result["outside"] == 1
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
    for patch in (lambda response: response.pop("_shards"),
                  lambda response: response["_shards"].update(failed=None),
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


# ---- the real client: a search answer carries only what its filter path names ------------------------------

def test_real_client_answer_is_complete_for_a_fully_covered_site(tmp_path):
    source = EndpointSource({"wire": [row("10.1.0.8"), row("10.1.0.9")]})
    result = _check(source, client=_client(source))
    assert result["status"] == "covered" and not result["warn"] and result["reasons"] == []
    assert (result["private_addresses"], result["outside"]) == (2, 0)
    # the cluster was asked for, and returned, the failed shard count alone
    assert source.answers[-1]["_shards"] == {"failed": 0} and "took" not in source.answers[-1]
    check = check_site_networks(Settings(home=tmp_path, es_url="http://es.invalid", es_index_patterns=["wire"],
                                         internal_networks=["10.1.0.0/16"]), _client(source))
    assert check.status == "ok" and check.data["coverage"]["status"] == "covered"
    assert "shard" not in check.detail


@pytest.mark.parametrize("patch", [
    lambda answer: answer["_shards"].update(failed=1),
    lambda answer: answer.update(timed_out=True),
    lambda answer: answer.update(terminated_early=True),
])
def test_real_client_failed_shards_and_cut_short_answers_stay_unknown(patch):
    source = EndpointSource({"wire": [row("10.1.0.8")]}, response_patch=patch)
    result = _check(source, client=_client(source))
    assert result["status"] == "unknown" and result["warn"] and result["reasons"]


def test_real_client_source_failure_is_unknown_and_names_no_backend_text():
    source = EndpointSource({"wire": [row("10.1.0.8")]}, fail=True)
    result = _check(source, client=_client(source))
    assert result["status"] == "unknown" and result["reasons"] == ["wire: network-address query failed"]


# ---- private ranges are selected in the cluster, before anything is listed ---------------------------------

def _peers(count):
    """Internet addresses, many of them just outside the edges of a private range."""
    edges = ("9.255", "11.0", "100.63", "100.128", "172.15", "172.32", "192.167", "192.169")
    return [f"{edges[n % 8]}.{n // 8 // 250}.{n // 8 % 250 + 1}" for n in range(count)]


def _site_rows(hosts, peers):
    """Every host opens a session to a peer, and every peer opens one to a host."""
    return ([row(host, peers[n % len(peers)]) for n, host in enumerate(hosts)]
            + [row(peer, hosts[n % len(hosts)]) for n, peer in enumerate(peers)])


def test_an_undeclared_private_range_is_named_however_many_internet_peers_were_seen():
    undeclared = [f"172.20.{n // 200}.{n % 200 + 1}" for n in range(400)]
    declared = [f"192.168.4.{n}" for n in range(1, 101)]
    source = EndpointSource({"wire": _site_rows(undeclared + declared, _peers(5000))})
    result = _check(source, SiteNetworks.from_lists(["192.168.0.0/16"]))
    assert result["status"] == "uncovered" and result["warn"] and not result["at_least"]
    assert (result["outside"], result["covered"], result["private_addresses"]) == (400, 100, 500)
    assert result["outside_share"] == .8 and result["prefixes"] == ["172.20.0.0/16"]
    assert "172.20.0.0/16" in result["summary"] and "80.0%" in result["summary"]
    assert len(source.requests) == 1


def test_the_one_request_selects_private_addresses_and_lists_only_possible_outsiders():
    from romulus.sources.network_coverage import PRIVATE_RANGES, outside_candidates
    definition = SiteNetworks.from_lists(["10.0.0.0/8"], ["10.9.0.0/16"])
    source = EndpointSource({"wire": [row("10.1.0.8")]})
    _check(source, definition)
    ((_, body),) = source.requests
    for side in ("source", "destination"):
        field = f"{side}.ip"
        agg = body["aggs"][side]
        assert agg["filter"] == {"terms": {field: [str(network) for network in PRIVATE_RANGES]}}
        candidates = outside_candidates(field, definition)
        assert candidates["bool"]["should"][1] == {"terms": {field: ["10.9.0.0/16"]}}       # the carve-out
        assert agg["aggs"]["outside"]["filter"] == candidates
        assert agg["aggs"]["outside"]["aggs"]["addresses"]["terms"] == {
            "field": field, "size": 1000, "order": {"_key": "asc"}}
        assert agg["aggs"]["outside"]["aggs"]["distinct"]["cardinality"]["field"] == field
        assert agg["aggs"]["covered"]["filter"] == {"bool": {"must_not": [candidates]}}
        assert agg["aggs"]["covered"]["aggs"]["distinct"]["cardinality"]["field"] == field


@pytest.mark.parametrize("hosts, status", [([], "no_private_observed"),
                                           ([f"192.168.4.{n}" for n in range(1, 101)], "covered")])
def test_a_sensor_facing_the_internet_never_warns_for_its_peers(hosts, status):
    peers = _peers(5000)
    rows = _site_rows(hosts, peers) if hosts else [row(peer, peers[-n - 1]) for n, peer in enumerate(peers)]
    result = _check(EndpointSource({"wire": rows}), SiteNetworks.from_lists(["192.168.0.0/16"]))
    assert result["status"] == status and not result["warn"] and result["reasons"] == []
    assert (result["outside"], result["covered"], result["prefixes"]) == (0, len(hosts), [])


def test_an_undeclared_ipv6_unique_local_range_is_named_past_thousands_of_global_peers():
    undeclared = [f"fd12:3456:789a:{n // 100:x}::{n % 100 + 1:x}" for n in range(400)]
    declared = [f"fd00:aaaa::{n:x}" for n in range(1, 51)]
    peers = [f"2001:db8:{n:x}::1" for n in range(5000)]
    source = EndpointSource({"wire": _site_rows(undeclared + declared, peers)})
    result = _check(source, SiteNetworks.from_lists(["192.168.0.0/16", "fd00:aaaa::/32"]))
    assert result["status"] == "uncovered" and result["warn"] and not result["at_least"]
    assert (result["outside"], result["covered"]) == (400, 50)
    assert result["prefixes"] == ["fd12:3456:789a::/48"]


def test_carrier_grade_nat_space_counts_as_private_and_its_public_neighbours_do_not():
    rows = _site_rows(["100.64.0.1", "100.127.255.254", "10.1.0.9"], ["100.63.255.255", "100.128.0.1"])
    result = _check(EndpointSource({"wire": rows}), SiteNetworks.from_lists(["10.0.0.0/8"]))
    assert (result["outside"], result["covered"]) == (2, 1) and result["status"] == "uncovered"
    assert result["prefixes"] == ["100.64.0.0/16", "100.127.0.0/16"]
    declared = _check(EndpointSource({"wire": rows}), SiteNetworks.from_lists(["10.0.0.0/8", "100.64.0.0/10"]))
    assert declared["status"] == "covered" and (declared["outside"], declared["covered"]) == (0, 3)


def test_a_site_that_declares_public_addresses_is_judged_on_its_private_ones_only():
    definition = SiteNetworks.from_lists(["198.51.100.0/24"])
    own = [f"198.51.100.{n}" for n in range(1, 201)]
    public_only = _check(EndpointSource({"wire": _site_rows(own, _peers(5000))}), definition)
    assert public_only["status"] == "no_private_observed" and not public_only["warn"]
    assert public_only["private_addresses"] == 0
    lab = [f"10.20.0.{n}" for n in range(1, 31)]
    result = _check(EndpointSource({"wire": _site_rows(own + lab, _peers(5000))}), definition)
    assert result["status"] == "uncovered" and result["warn"]
    assert (result["outside"], result["covered"], result["outside_share"]) == (30, 0, 1.0)
    assert result["prefixes"] == ["10.20.0.0/16"]


def test_more_uncovered_addresses_than_one_listing_holds_are_an_honest_lower_bound():
    undeclared = [f"172.{16 + n // 750}.{n % 750 // 250}.{n % 250 + 1}" for n in range(1500)]
    source = EndpointSource({"wire": _site_rows(undeclared, _peers(5000))})
    result = _check(source, SiteNetworks.from_lists(["192.168.0.0/16"]))
    assert result["status"] == "uncovered" and result["at_least"] and result["warn"]
    assert result["outside"] == 1000 and result["outside_estimate"] == 1500
    # the listing is lowest first: all of 172.16.0.0/16 and the start of 172.17.0.0/16 were seen and are named
    assert result["prefixes"] == ["172.16.0.0/16", "172.17.0.0/16"]
    assert "at least 1000 of" in result["summary"] and "terms capped" in result["summary"]
    assert "one address field alone holds about 1,500 that may be outside" in result["summary"]
    assert "Coverage unknown" not in result["summary"] and "observation is incomplete" in result["summary"]
    assert len(source.requests) == 1


def test_a_range_inside_a_carve_out_is_counted_as_covered_and_the_carve_out_as_outside():
    definition = SiteNetworks.from_lists(["10.0.0.0/8", "10.9.1.0/24"], ["10.9.0.0/16"])
    result = _check(EndpointSource({"wire": [row("10.1.0.5"), row("10.9.0.8"), row("10.9.1.7")]}), definition)
    assert (result["outside"], result["covered"], result["private_addresses"]) == (1, 2, 3)
    assert result["status"] == "uncovered" and result["prefixes"] == ["10.9.0.0/16"]


def test_keyword_address_fields_are_listed_unselected_and_judged_here():
    rows = [row("10.2.0.8", "10.1.0.9"), row("10.1.0.9", "10.2.0.8"), row("10.1.0.7"), row("::ffff:10.1.0.7")]
    source = EndpointSource({"wire": rows}, {"wire": LISTED})
    result = _check(source)
    assert (result["status"], result["outside"], result["covered"]) == ("uncovered", 1, 2)
    ((_, body),) = source.requests
    assert set(body["aggs"]["source"]) == {"terms"}              # no address range can select from a keyword
    # more values than the listing holds: an uncovered address that was listed is still a finding, a lower bound;
    # with none listed the question stays open
    crowded = _check(EndpointSource({"wire": _site_rows(["172.20.0.9"], _peers(5000))}, {"wire": LISTED}))
    assert (crowded["status"], crowded["outside"], crowded["at_least"], crowded["warn"]) == ("uncovered", 1, True, True)
    unseen = _check(EndpointSource({"wire": _site_rows(["10.1.0.9"], _peers(5000))}, {"wire": LISTED}))
    assert (unseen["status"], unseen["outside"], unseen["warn"]) == ("unknown", 0, True)


# ---- doctor's lookback, and a diagnostic that cannot stop a hunt -------------------------------------------

def test_doctor_lookback_is_read_on_each_target_clock():
    from romulus.sources.network_coverage import check_network_addresses
    arkime = {"firstPacket": "long", "lastPacket": "long", "network.community_id": "keyword",
              "source.ip": "ip", "destination.ip": "ip"}
    plain = {"ts": "double", "id.orig_h": "ip", "id.resp_h": "ip"}
    newest_ms, week = int(START.timestamp() * 1000), 7 * 86_400
    source = EndpointSource(
        {"sessions": [dict(row("10.2.0.8"), firstPacket=newest_ms),
                      dict(row("10.3.0.8"), firstPacket=newest_ms - week * 1000 - 1)],
         "plain": [{"ts": START.timestamp(), "id.orig_h": "10.4.0.9", "id.resp_h": "10.1.0.8"},
                   {"ts": START.timestamp() - week - 1, "id.orig_h": "10.5.0.9"}]},
        {"sessions": arkime, "plain": plain})
    contracts = {"sessions": contract_from_types("sessions", arkime),
                 "plain": contract_from_types("plain", plain, role="network").model_copy(
                     update={"time_field": "ts", "zeek_sensor": "test-sensor", "zeek_log": "conn"})}
    result = check_network_addresses(source, contracts, SITE, None)
    assert result["status"] == "uncovered" and result["prefixes"] == ["10.2.0.0/16", "10.4.0.0/16"]
    assert result["window"] == "last 7 days of each target"
    bodies = {target: body for target, body in source.requests if "newest" not in body["aggs"]}
    assert len(source.requests) == 4 and set(bodies) == {"sessions", "plain"}
    assert bodies["sessions"]["query"]["bool"]["filter"][0]["range"]["firstPacket"] == {
        "gte": newest_ms - week * 1000, "lt": newest_ms + 1}
    assert bodies["plain"]["query"]["bool"]["filter"][0]["range"]["ts"] == pytest.approx(
        {"gte": START.timestamp() - week, "lt": START.timestamp() + .001})


def test_doctor_on_a_target_with_no_record_asks_nothing_more_and_does_not_warn():
    source = EndpointSource({"wire": []})
    result = _check(source, window=None)
    assert result["status"] == "no_private_observed" and not result["warn"]
    assert len(source.requests) == 1 and set(source.requests[0][1]["aggs"]) == {"newest"}


def test_doctor_newest_record_answer_that_is_not_complete_is_unknown():
    source = EndpointSource({"wire": [row("10.1.0.8")]})
    answer = source.search
    source.search = lambda target, body: {**answer(target, body), "timed_out": True}
    result = _check(source, window=None)
    assert result["status"] == "unknown" and result["reasons"] == ["wire: newest record time unknown"]


def test_create_hunt_records_unknown_coverage_when_the_diagnostic_raises(tmp_path, monkeypatch):
    source = EndpointSource({"wire": [row("10.2.0.8")]})
    settings = Settings(home=tmp_path, es_index_patterns=["wire"], internal_networks=["10.1.0.0/16"])
    profile = SourceProfile(id="synthetic", target="wire", kind="lab_ecs", role="network", os_family="unknown",
        backend="elasticsearch", backend_version="8", captured_at=START, field_types=TYPES, doc_count=1)
    monkeypatch.setattr(hunt_run, "ElasticClient", lambda _settings: source)
    monkeypatch.setattr(hunt_run, "build_profile",
                        lambda *_args, **_kwargs: (profile, contract_from_types("wire", TYPES)))
    monkeypatch.setattr(hunt_run, "ai_agent_entry", lambda *_args: {"requested": False})

    def broken(*_args, **_kwargs):
        raise RuntimeError("transport error http://user:secret@es.invalid")

    monkeypatch.setattr(hunt_run, "check_network_addresses", broken)
    hunt_id = hunt_run.create_hunt(settings, START, WINDOW.end, "analyst")
    repo = hunt_run.open_repo(settings)
    try:
        coverage = repo.get_hunt(hunt_id)["manifest"]["internal_networks"]["coverage"]
    finally:
        repo.engine.dispose()
    assert coverage["status"] == "unknown" and coverage["warn"] and coverage["outside"] == 0
    assert coverage["reasons"] == ["the network-address coverage check failed (RuntimeError)"]
    assert "secret" not in json.dumps(coverage) and "Coverage unknown" in coverage["summary"]
    assert coverage["window"]["start"] == START.isoformat()
