"""Misconfiguration warning: host telemetry comes from the site's own assets, so a host address outside the
internal-network definition is evidence that the definition is wrong for this site. Reported by doctor and in
the hunt's sweep summary as a warning naming the setting, never a failure. When the hunt's own telemetry
contradicts the definition, the direction-dependent rules' negatives are partial. Documentation ranges only."""
import ipaddress
import json
import random
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from romulus.config import Settings
from romulus.detect.netdef import SiteNetworks
from romulus.detect.registry import ALL_PLAYBOOKS
from romulus.doctor import check_site_networks
from romulus.hunt import run as hunt_run
from romulus.hunt import site_networks as sn
from romulus.sources.es import ElasticClient
from romulus.sources.models import Window
from romulus.sources.profile import contract_from_types

SITE = {"internal_networks": ["198.51.100.0/24", "10.0.0.0/8"], "external_networks": ["10.50.0.0/16"]}
HOST, NETWORK, ARKIME = "logs-host-x", "logs-network-x", "arkime_sessions3-x"
HOST_TYPES = {"@timestamp": "date", "host.name": "keyword", "host.ip": "ip", "event.dataset": "keyword"}
WINDOW = Window(start=datetime(2024, 11, 18, 10, tzinfo=UTC), end=datetime(2024, 11, 18, 11, tzinfo=UTC))
NEWEST = datetime(2024, 11, 18, 17, 0, tzinfo=UTC)
DIRECTION_RULES = sorted(pb.id for pb in ALL_PLAYBOOKS if pb.direction_dependent)


def _matches(address: str, clause: dict) -> bool:
    """The subset of the query DSL the check sends, evaluated the way Elasticsearch evaluates an ip field."""
    if "bool" in clause:
        b = clause["bool"]
        if any(_matches(address, c) for c in b.get("must_not", [])):
            return False
        if not all(_matches(address, c) for c in b.get("filter", []) + b.get("must", [])):
            return False
        should = b.get("should", [])
        return not should or sum(_matches(address, c) for c in should) >= b.get("minimum_should_match", 1)
    if "terms" in clause:
        ((_field, values),) = clause["terms"].items()
        ip = ipaddress.ip_address(address)
        ip = ip.ipv4_mapped or ip if ip.version == 6 else ip
        return any(ip.version == n.version and ip in n for n in map(ipaddress.ip_network, values))
    raise AssertionError(f"unexpected clause {clause}")


class FakeES:
    """Answers resolve, mapping, the newest-record query and the one host-address query per target."""

    def __init__(self, addresses: dict[str, list[str]], types: dict | None = None):
        self.addresses, self.types = addresses, types or {}
        self.bodies: list[dict] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/":
            return httpx.Response(200, json={"version": {"number": "8.17.0"}})
        if path.startswith("/_resolve/index/"):
            return httpx.Response(200, json={"indices": [{"name": name} for name in sorted(self.addresses)]})
        target, _, action = path.strip("/").partition("/")
        if action == "_mapping":
            props: dict = {}
            for name, kind in self.types.get(target, HOST_TYPES).items():
                node = props
                *parents, leaf = name.split(".")
                for part in parents:
                    node = node.setdefault(part, {"properties": {}})["properties"]
                node[leaf] = {"type": kind}
            return httpx.Response(200, json={target: {"mappings": {"properties": props}}})
        body = json.loads(request.content)
        self.bodies.append(body)
        if "newest" in body["aggs"]:
            return httpx.Response(200, json={"aggregations": {"newest": {
                "value": NEWEST.timestamp() * 1000, "value_as_string": NEWEST.isoformat()}}})
        agg = body["aggs"]["outside"]
        values = sorted(self.addresses[target])
        candidates = [v for v in values if _matches(v, agg["filter"])]
        size = agg["aggs"]["addresses"]["terms"]["size"]
        return httpx.Response(200, json={"timed_out": False, "_shards": {"failed": 0}, "aggregations": {
            "present": {"value": 2 * len(values)},
            "outside": {"doc_count": 2 * len(candidates),
                        "addresses": {"buckets": [{"key": v, "doc_count": 2} for v in candidates[:size]],
                                      "sum_other_doc_count": 2 * len(candidates[size:])},
                        "distinct": {"value": len(candidates)}}}})


def _client(fake: FakeES, **settings) -> ElasticClient:
    return ElasticClient(Settings(es_url="http://es.invalid", es_index_patterns=["logs-*"], **settings),
                         transport=httpx.MockTransport(fake))


def _contracts(fake: FakeES) -> dict:
    return {t: contract_from_types(t, fake.types.get(t, HOST_TYPES)) for t in fake.addresses}


def _site(**override) -> SiteNetworks:
    lists = {**SITE, **override}
    return SiteNetworks.from_lists(lists["internal_networks"], lists["external_networks"])


HOST_ADDRESSES = ["198.51.100.10", "198.51.100.11", "10.0.0.5", "10.50.0.7", "192.0.2.7", "fe80::1", "127.0.0.1",
                  "2001:db8::5"]


def test_host_addresses_outside_the_configured_site_are_counted_with_examples():
    fake = FakeES({HOST: HOST_ADDRESSES})
    beats = []
    result = sn.check_host_addresses(_client(fake), _contracts(fake), _site(), WINDOW, heartbeat=lambda: beats.append(1))
    # the partner carve-out, a documentation address and an IPv6 address are outside; link-local and loopback never
    assert result["outside"] == 3 and result["examples"] == ["10.50.0.7", "192.0.2.7", "2001:db8::5"]
    assert result["values_present"] == 16 and result["at_least"] is False and result["checked_targets"] == [HOST]
    assert "ROMULUS_INTERNAL_NETWORKS" in result["warning"] and "3 distinct host.ip" in result["warning"]
    # one query per target, bounded by the hunt's own window, with a heartbeat per target
    assert len(fake.bodies) == 1 and beats
    assert fake.bodies[0]["query"]["bool"]["filter"][0]["range"]["@timestamp"]["gte"] == WINDOW.start.isoformat()


def test_the_query_filter_returns_every_address_the_definition_reads_as_outside():
    definition = SiteNetworks.from_lists(["10.0.0.0/8", "10.50.1.0/24", "198.51.100.0/24", "2001:db8::/32"],
                                         ["10.50.0.0/16", "2001:db8:ff::/48"])
    query = sn.outside_candidates("host.ip", definition)
    rng = random.Random(7)
    pools = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "10.50.0.0/16", "10.50.1.0/24", "198.51.100.0/24",
                                               "203.0.113.0/24", "127.0.0.0/8", "2001:db8::/32", "2001:db8:ff::/48")]
    for _ in range(4000):
        net = rng.choice(pools)
        address = str(net.network_address + rng.randrange(net.num_addresses))
        if not definition.is_internal(ipaddress.ip_address(address)):
            assert _matches(address, query), address                  # the query is a superset of "outside"


def test_under_the_default_a_site_in_public_space_is_flagged():
    fake = FakeES({HOST: ["198.51.100.10", "198.51.100.11", "10.0.0.5"]})
    result = sn.check_host_addresses(_client(fake), _contracts(fake), SiteNetworks.default(), WINDOW)
    assert result["outside"] == 2 and result["examples"] == ["198.51.100.10", "198.51.100.11"]
    assert "default (RFC 1918 and reserved ranges)" in result["warning"]


def test_network_and_session_targets_are_not_host_telemetry_and_a_host_target_without_host_ip_is_named():
    fake = FakeES({HOST: ["10.0.0.5"], NETWORK: ["203.0.113.1"], ARKIME: ["203.0.113.2"], "logs-web-x": []},
                  types={ARKIME: {"firstPacket": "date", "lastPacket": "date", "network.community_id": "keyword",
                                  "host.ip": "ip"},
                         "logs-web-x": {"@timestamp": "date", "host.name": "keyword"}})
    result = sn.check_host_addresses(_client(fake), _contracts(fake), SiteNetworks.default(), WINDOW)
    assert result["checked_targets"] == [HOST] and result["outside"] == 0 and result["warning"] is None
    assert result["unchecked_targets"] == {"logs-web-x": "no aggregatable host.ip field"}


def test_a_capped_answer_makes_the_count_a_lower_bound(monkeypatch):
    monkeypatch.setattr(sn, "TERMS_SIZE", 4)
    fake = FakeES({HOST: [f"192.0.2.{i}" for i in range(1, 16)]})
    result = sn.check_host_addresses(_client(fake), _contracts(fake), SiteNetworks.default(), WINDOW)
    assert result["at_least"] is True and result["outside"] == 4 and result["distinct_estimate"] == 15
    assert "at least 4 distinct host.ip" in result["warning"]


def test_the_distinct_set_across_targets_is_capped(monkeypatch):
    monkeypatch.setattr(sn, "DISTINCT_CAP", 3)
    fake = FakeES({HOST: [f"192.0.2.{i}" for i in range(1, 6)], "logs-host-y": [f"203.0.113.{i}" for i in range(9)]})
    result = sn.check_host_addresses(_client(fake), _contracts(fake), SiteNetworks.default(), WINDOW)
    assert result["at_least"] is True and result["outside"] == 3


def test_examples_are_limited_to_ten():
    fake = FakeES({HOST: [f"192.0.2.{i}" for i in range(1, 16)]})
    result = sn.check_host_addresses(_client(fake), _contracts(fake), SiteNetworks.default(), WINDOW)
    assert result["outside"] == 15 and len(result["examples"]) == 10 and result["examples"][0] == "192.0.2.1"


@pytest.mark.parametrize("broad", ["0.0.0.0/0", "::/0", "8.0.0.0/7", "2000::/15"])
def test_an_over_broad_definition_is_warned(broad):
    definition = SiteNetworks.from_lists([broad, "198.51.100.0/24"], [])
    assert definition.broad_ranges() == [broad]
    fake = FakeES({HOST: ["198.51.100.10"]})
    result = sn.check_host_addresses(_client(fake), _contracts(fake), definition, WINDOW)
    assert result["broad_ranges"] == [broad] and broad in result["warning"]
    assert result["outside"] == 0


def test_the_default_and_ordinary_ranges_are_not_broad():
    assert SiteNetworks.default().broad_ranges() == []                 # fc00::/7 is reserved, not a site's choice
    assert _site(internal_networks=["10.0.0.0/8", "2001::/16"]).broad_ranges() == []


def test_the_report_line_lists_the_ranges_bounded_to_twenty():
    definition = SiteNetworks.from_lists([f"10.{i}.0.0/16" for i in range(25)], ["10.3.4.0/24"])
    line = definition.line()
    assert line.startswith("Internal networks: configured (25 ranges, 1 carve-out). Ranges: 10.0.0.0/16, ")
    assert "10.19.0.0/16 and 5 more; carve-outs: 10.3.4.0/24" in line and "10.20.0.0/16" not in line


# ---- doctor ------------------------------------------------------------------------------------------------

def test_doctor_checks_the_week_ending_at_the_newest_record():
    fake = FakeES({HOST: HOST_ADDRESSES})
    check_site_networks(Settings(es_url="http://es.invalid", es_index_patterns=["logs-*"], **SITE),
                        _client(fake, **SITE))
    newest, query = fake.bodies
    assert newest["size"] == 0 and "newest" in newest["aggs"]
    bounds = query["query"]["bool"]["filter"][0]["range"]["@timestamp"]
    assert bounds["gte"] == (NEWEST - sn.DOCTOR_LOOKBACK).isoformat() and bounds["lte"] == NEWEST.isoformat()


def test_doctor_warns_naming_the_setting_with_the_count_and_examples():
    fake = FakeES({HOST: HOST_ADDRESSES})
    check = check_site_networks(Settings(es_url="http://es.invalid", es_index_patterns=["logs-*"], **SITE),
                                _client(fake, **SITE))
    assert check.name == "site.internal_networks" and check.status == "warn"
    assert "3 distinct host.ip" in check.detail and "ROMULUS_INTERNAL_NETWORKS" in check.detail
    assert "192.0.2.7" in check.detail and check.data["outside"] == 3


def test_doctor_warns_on_an_over_broad_definition():
    fake = FakeES({HOST: ["198.51.100.10"]})
    lists = {"internal_networks": ["0.0.0.0/0"], "external_networks": []}
    check = check_site_networks(Settings(es_url="http://es.invalid", es_index_patterns=["logs-*"], **lists),
                                _client(fake, **lists))
    assert check.status == "warn" and "0.0.0.0/0" in check.detail


def test_doctor_is_ok_for_a_configured_site_whose_hosts_are_all_inside():
    fake = FakeES({HOST: ["198.51.100.10", "10.0.0.5", "fe80::1"]})
    check = check_site_networks(Settings(es_url="http://es.invalid", es_index_patterns=["logs-*"], **SITE),
                                _client(fake, **SITE))
    assert check.status == "ok" and "configured (2 ranges, 1 carve-out)" in check.detail


def test_doctor_warns_when_the_setting_is_unset_even_with_no_host_addresses():
    fake = FakeES({HOST: []})
    check = check_site_networks(Settings(es_url="http://es.invalid", es_index_patterns=["logs-*"]), _client(fake))
    assert check.status == "warn" and "ROMULUS_INTERNAL_NETWORKS is not set" in check.detail
    assert "no host.ip value" in check.detail


def test_doctor_reports_an_unreachable_source_as_a_warning_not_a_failure():
    def down(request):
        return httpx.Response(503, text="unavailable")
    client = ElasticClient(Settings(es_url="http://es.invalid", es_index_patterns=["logs-*"]),
                           transport=httpx.MockTransport(down))
    check = check_site_networks(Settings(es_url="http://es.invalid", es_index_patterns=["logs-*"], **SITE), client)
    assert check.status == "warn" and "could not be checked" in check.detail


# ---- the hunt's sweep summary and its effect on direction-dependent negatives ------------------------------

class _Sweep:
    """Writes complete window cells for every direction-dependent rule, as a clean sweep would."""

    def __init__(self, repo, _client, hunt_id, *_args, **_kwargs):
        self.repo, self.hunt_id = repo, hunt_id
        self.partial_reasons, self.stats = [], {"partitions": 0}

    def run_target(self, _target):
        raise AssertionError("no targets")

    def finalize(self):
        for pb in ALL_PLAYBOOKS:
            if pb.direction_dependent:
                state = "matched" if pb.id == "net.beaconing" else "no_match_complete"
                self.repo.set_rule_cell(self.hunt_id, pb.id, pb.version, "*", "window", state,
                                        1 if state == "matched" else 0, 10, {"reasons": []})
        self.repo.set_rule_cell(self.hunt_id, "net.port_scan", "1", "*", "window", "no_match_complete", 0, 10,
                                {"reasons": []})


def _run(tmp_path, monkeypatch, fake, **settings):
    s = Settings(home=tmp_path, agent_mode="off", **settings)
    repo = hunt_run.open_repo(s)
    start = datetime(2024, 11, 18, 10, tzinfo=UTC)
    repo.create_hunt("h1", {"window": {"start": start.isoformat(), "end": (start + timedelta(hours=1)).isoformat()},
                            "targets": [], "source_profiles": {}, "expansion": {"enabled": False},
                            "internal_networks": SiteNetworks.from_settings(s).record()}, "digest", "test")
    monkeypatch.setattr(hunt_run, "Sweep", _Sweep)
    monkeypatch.setattr(hunt_run, "_contracts", lambda *_a, **_k: _contracts(fake))
    monkeypatch.setattr(hunt_run, "ElasticClient", lambda _s: _client(fake))
    monkeypatch.setattr(hunt_run, "_packet_stage", lambda *_a, **_k: {"status": "skipped", "finished": True})
    result = hunt_run.run_hunt(s, "h1")
    return repo, result, repo.latest_audit("h1", "hunt.sweep_summary")["detail"]


def _windows(repo) -> dict:
    return {c["rule_id"]: c for c in repo.rule_cells("h1") if c["partition"] == "window"}


def test_the_sweep_summary_carries_the_check_for_the_hunt_window(tmp_path, monkeypatch):
    fake = FakeES({HOST: HOST_ADDRESSES})
    _repo, _result, summary = _run(tmp_path, monkeypatch, fake, **SITE)
    check = summary["internal_networks"]
    assert check["outside"] == 3 and "ROMULUS_INTERNAL_NETWORKS" in check["warning"]
    assert check["definition"] == "Internal networks: configured (2 ranges, 1 carve-out)"
    assert fake.bodies[0]["query"]["bool"]["filter"][0]["range"]["@timestamp"]["gte"] == "2024-11-18T10:00:00+00:00"


def test_a_configured_definition_the_hosts_contradict_leaves_no_complete_direction_negative(tmp_path, monkeypatch):
    # configured 10/8, but the site's own hosts are in 198.51.100.0/24
    lists = {"internal_networks": ["10.0.0.0/8"], "external_networks": []}
    repo, result, summary = _run(tmp_path, monkeypatch, FakeES({HOST: ["198.51.100.10", "198.51.100.11"]}), **lists)
    cells = _windows(repo)
    assert cells["net.beaconing"]["state"] == "match_on_partial"
    for rule_id in DIRECTION_RULES:
        if rule_id != "net.beaconing":
            assert cells[rule_id]["state"] == "evaluated_partial", rule_id
        reason = cells[rule_id]["detail"]["reasons"][-1]
        assert "2 distinct host.ip" in reason and "198.51.100.10, 198.51.100.11" in reason, reason
    assert cells["net.port_scan"]["state"] == "no_match_complete"         # direction plays no part there
    assert result["execution_state"] == "partial" and not summary["complete"]
    assert any("198.51.100.10" in r for r in summary["partial_reasons"])


def test_a_failed_check_leaves_no_complete_direction_negative_and_never_stops_the_hunt(tmp_path, monkeypatch):
    monkeypatch.setattr(hunt_run, "check_host_addresses",
                        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("aggregation refused")))
    repo, result, summary = _run(tmp_path, monkeypatch, FakeES({HOST: HOST_ADDRESSES}), **SITE)
    assert summary["finished"] and "aggregation refused" in summary["internal_networks"]["error"]
    assert _windows(repo)["net.long_external_connection"]["state"] == "evaluated_partial"
    assert result["execution_state"] == "partial"


def test_a_confirmed_definition_leaves_the_negatives_complete(tmp_path, monkeypatch):
    repo, _result, summary = _run(tmp_path, monkeypatch, FakeES({HOST: ["198.51.100.10", "10.0.0.5"]}), **SITE)
    assert _windows(repo)["net.long_external_connection"]["state"] == "no_match_complete"
    assert summary["complete"] and summary["internal_networks"]["outside"] == 0


def test_no_host_address_at_all_changes_nothing(tmp_path, monkeypatch):
    repo, _result, summary = _run(tmp_path, monkeypatch, FakeES({HOST: []}), **SITE)
    assert _windows(repo)["net.long_external_connection"]["state"] == "no_match_complete"
    assert summary["complete"]


def test_the_report_shows_the_warning_from_the_sweep_summary(tmp_path, monkeypatch):
    from romulus.report import markdown
    from romulus.report.manifest import build_manifest
    from tests.test_report import _repo_with_finding
    _repo, _result, summary = _run(tmp_path, monkeypatch, FakeES({HOST: HOST_ADDRESSES}), **SITE)
    repo, _cid = _repo_with_finding()
    repo.audit("system", "hunt.sweep_summary", "h1", summary)
    manifest = build_manifest(repo, "h1", "test")
    assert manifest["internal_networks"]["warning"].startswith("3 distinct host.ip")
    assert manifest["internal_networks"]["host_address_check"]["examples"] == ["10.50.0.7", "192.0.2.7",
                                                                              "2001:db8::5"]
    text = markdown.render({**manifest, "revision": {"number": 1, "id": "r1", "supersedes": None}})
    assert "> **Internal networks:** 3 distinct host.ip" in text


def test_the_web_hunt_page_shows_the_warning(tmp_path, monkeypatch):
    import secrets

    from fastapi.testclient import TestClient

    from romulus.web.app import create_app
    from romulus.web.auth import create_user
    _run(tmp_path, monkeypatch, FakeES({HOST: HOST_ADDRESSES}), **SITE)
    settings = Settings(home=tmp_path, secret_key=secrets.token_urlsafe(32), **SITE)
    app = create_app(settings)
    password = secrets.token_urlsafe(18)
    create_user(hunt_run.open_repo(settings).engine, "analyst1", password, "analyst")
    client = TestClient(app)
    client.post("/login", data={"username": "analyst1", "password": password})
    page = client.get("/hunts/h1")
    assert page.status_code == 200
    assert "<b>Internal networks:</b> 3 distinct host.ip address(es)" in page.text
    assert "Ranges: 10.0.0.0/8, 198.51.100.0/24; carve-outs: 10.50.0.0/16" in page.text


@pytest.fixture(autouse=True)
def _no_real_network(monkeypatch):
    """A test that forgets to route the client through FakeES fails instead of reaching a real host."""
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request",
                        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("real network")))
