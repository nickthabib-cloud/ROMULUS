"""Misconfiguration warning: host telemetry comes from the site's own assets, so a host address outside the
internal-network definition is evidence that the definition is wrong for this site. Reported by doctor and in
the hunt's sweep summary as a warning naming the setting, never a failure. Documentation ranges only."""
import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from romulus.config import Settings
from romulus.detect.netdef import SiteNetworks
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


class FakeES:
    """Answers resolve, mapping and composite aggregations over `host.ip`, a page at a time."""

    def __init__(self, addresses: dict[str, list[str]], page: int = 2, types: dict | None = None):
        self.addresses, self.page, self.types = addresses, page, types or {}
        self.bodies: list[dict] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/":
            return httpx.Response(200, json={"version": {"number": "8.17.0"}})
        if path.startswith("/_resolve/index/"):
            return httpx.Response(200, json={"indices": [{"name": name} for name in sorted(self.addresses)]})
        target, _, action = path.strip("/").partition("/")
        if action == "_mapping":
            types = self.types.get(target, HOST_TYPES)
            props: dict = {}
            for name, kind in types.items():
                node = props
                *parents, leaf = name.split(".")
                for part in parents:
                    node = node.setdefault(part, {"properties": {}})["properties"]
                node[leaf] = {"type": kind}
            return httpx.Response(200, json={target: {"mappings": {"properties": props}}})
        body = json.loads(request.content)
        self.bodies.append(body)
        composite = body["aggs"]["addresses"]["composite"]
        values = sorted(self.addresses[target])
        start = values.index(composite["after"]["ip"]) + 1 if "after" in composite else 0
        chunk = values[start:start + composite["size"] if self.page is None else start + self.page]
        agg = {"buckets": [{"key": {"ip": v}, "doc_count": 3} for v in chunk]}
        if chunk:
            agg["after_key"] = {"ip": chunk[-1]}
        return httpx.Response(200, json={"timed_out": False, "_shards": {"failed": 0}, "aggregations": {"addresses": agg}})


def _client(fake: FakeES, **settings) -> ElasticClient:
    return ElasticClient(Settings(es_url="http://es.invalid", es_index_patterns=["logs-*"], **settings),
                         transport=httpx.MockTransport(fake))


def _contracts(fake: FakeES) -> dict:
    return {t: contract_from_types(t, fake.types.get(t, HOST_TYPES)) for t in fake.addresses}


HOST_ADDRESSES = ["198.51.100.10", "198.51.100.11", "10.0.0.5", "10.50.0.7", "192.0.2.7", "fe80::1", "127.0.0.1",
                  "2001:db8::5"]


def test_host_addresses_outside_the_configured_site_are_counted_with_examples():
    fake = FakeES({HOST: HOST_ADDRESSES})
    result = sn.check_host_addresses(_client(fake), _contracts(fake),
                                     SiteNetworks.from_lists(SITE["internal_networks"], SITE["external_networks"]),
                                     WINDOW)
    # the partner carve-out, a documentation address and an IPv6 address are outside; link-local and loopback never
    assert result["outside"] == 3 and result["examples"] == ["10.50.0.7", "192.0.2.7", "2001:db8::5"]
    assert result["addresses"] == 8 and result["at_least"] is False and result["checked_targets"] == [HOST]
    assert "ROMULUS_INTERNAL_NETWORKS" in result["warning"] and "3 distinct host.ip" in result["warning"]
    # the hunt's own window bounds the aggregation; pages are followed to the end
    assert all(b["query"]["bool"]["filter"][0]["range"]["@timestamp"]["gte"] == WINDOW.start.isoformat()
               for b in fake.bodies)
    assert len(fake.bodies) == 5


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


def test_the_distinct_sets_are_capped_and_the_count_becomes_at_least(monkeypatch):
    monkeypatch.setattr(sn, "DISTINCT_CAP", 4)
    addresses = [f"192.0.2.{i}" for i in range(1, 16)]
    fake = FakeES({HOST: addresses}, page=5)
    result = sn.check_host_addresses(_client(fake), _contracts(fake), SiteNetworks.default(), WINDOW)
    assert result["at_least"] is True and result["outside"] == 4 and result["addresses"] == 4
    assert "at least 4 distinct host.ip" in result["warning"]
    assert len(result["examples"]) <= sn.EXAMPLES


def test_examples_are_limited_to_ten():
    fake = FakeES({HOST: [f"192.0.2.{i}" for i in range(1, 16)]}, page=100)
    result = sn.check_host_addresses(_client(fake), _contracts(fake), SiteNetworks.default(), WINDOW)
    assert result["outside"] == 15 and len(result["examples"]) == 10 and result["examples"][0] == "192.0.2.1"


def test_a_page_cap_makes_the_count_a_lower_bound(monkeypatch):
    monkeypatch.setattr(sn, "MAX_PAGES", 2)
    fake = FakeES({HOST: [f"192.0.2.{i}" for i in range(1, 16)]}, page=2)
    result = sn.check_host_addresses(_client(fake), _contracts(fake), SiteNetworks.default(), WINDOW)
    assert result["at_least"] is True and result["outside"] == 4 and result["reasons"]


# ---- doctor ------------------------------------------------------------------------------------------------

def test_doctor_warns_naming_the_setting_with_the_count_and_examples():
    fake = FakeES({HOST: HOST_ADDRESSES})
    check = check_site_networks(Settings(es_url="http://es.invalid", es_index_patterns=["logs-*"], **SITE),
                                _client(fake, **SITE))
    assert check.name == "site.internal_networks" and check.status == "warn"
    assert "3 distinct host.ip" in check.detail and "ROMULUS_INTERNAL_NETWORKS" in check.detail
    assert "192.0.2.7" in check.detail and check.data["outside"] == 3


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


# ---- the hunt's sweep summary ------------------------------------------------------------------------------

class _Sweep:
    def __init__(self, *_args, **_kwargs):
        self.partial_reasons, self.stats = [], {"partitions": 0}

    def run_target(self, _target):
        raise AssertionError("no targets")

    def finalize(self):
        return None


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
    hunt_run.run_hunt(s, "h1")
    return repo.latest_audit("h1", "hunt.sweep_summary")["detail"]


def test_the_sweep_summary_carries_the_check_for_the_hunt_window(tmp_path, monkeypatch):
    fake = FakeES({HOST: HOST_ADDRESSES})
    summary = _run(tmp_path, monkeypatch, fake, **SITE)
    check = summary["internal_networks"]
    assert check["outside"] == 3 and "ROMULUS_INTERNAL_NETWORKS" in check["warning"]
    assert check["definition"] == "Internal networks: configured (2 ranges, 1 carve-out)"
    assert fake.bodies[0]["query"]["bool"]["filter"][0]["range"]["@timestamp"]["gte"] == "2024-11-18T10:00:00+00:00"


def test_a_failed_check_is_recorded_and_never_stops_the_hunt(tmp_path, monkeypatch):
    fake = FakeES({HOST: HOST_ADDRESSES})
    monkeypatch.setattr(hunt_run, "check_host_addresses",
                        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("aggregation refused")))
    summary = _run(tmp_path, monkeypatch, fake)
    assert summary["finished"] and "aggregation refused" in summary["internal_networks"]["error"]


def test_the_report_shows_the_warning_from_the_sweep_summary(tmp_path, monkeypatch):
    from romulus.report import markdown
    from romulus.report.manifest import build_manifest
    from tests.test_report import _repo_with_finding
    summary = _run(tmp_path, monkeypatch, FakeES({HOST: HOST_ADDRESSES}), **SITE)
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


@pytest.fixture(autouse=True)
def _no_real_network(monkeypatch):
    """A test that forgets to route the client through FakeES fails instead of reaching a real host."""
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request",
                        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("real network")))
