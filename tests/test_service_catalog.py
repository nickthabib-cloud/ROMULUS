"""Service names are typed observations, with exact source membership on disk."""
import gzip
import importlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from romulus.detect.bounded import StateBudget
from romulus.detect.netdef import SiteNetworks, current, install
from romulus.evidence.typed import RawRef, TypedEvent, fv

ROOT = Path(__file__).resolve().parents[1]
NAMES = {
    "anydesk": "relay-xxx.net.anydesk.com", "teamviewer": "router.teamviewer.com",
    "screenconnect": "tenant.screenconnect.com", "netsupport": "netsupportmanager.com",
    "atera": "agent-api.atera.com", "splashtop": "relay.splashtop.com",
    "rustdesk": "rs-ny.rustdesk.com", "kaseya": "tenant.kaseya.net",
    "simplehelp": "site.simple-help.com", "action1": "server.na-2.action1.com",
    "remote-utilities": "remoteutilities.com", "goto": "fastsupport.com",
    "zoho-assist": "gateway.zohoassist.com", "ngrok": "abc123.ngrok-free.app",
    "cloudflare-tunnel": "x.trycloudflare.com", "localtonet": "localtonet.com",
    "serveo": "test.serveo.net", "localhost-run": "a1b.lhr.life",
    "pinggy": "pinggy.io", "playit": "playit.gg", "tailscale": "controlplane.tailscale.com",
    "zerotier": "my.zerotier.com", "visual-studio-tunnels": "x.devtunnels.ms",
    "interactsh": "token.oast.pro", "burp-collaborator": "token.oastify.com",
    "dnslog": "dnslog.org", "webhook-site": "webhook.site", "request-catcher": "x.requestcatcher.com",
    "transfer-sh": "transfer.sh", "temp-sh": "temp.sh", "gofile": "gofile.io",
    "mega": "mega.nz", "file-io": "file.io",
}


def module():
    return importlib.import_module("romulus.detect.service_catalog")


def event(name="abc123.ngrok-free.app", *, field="dns.question.name", source="10.0.0.1", n=0, extra=None):
    fields = {"source.ip": fv(source, "native.client"), field: fv(name, "native.name")}
    fields.update({k: fv(v, "native.extra") for k, v in (extra or {}).items()})
    family = {"dns.question.name": "dns_query", "http.hostname": "http_tx",
              "tls.client.server_name": "tls_session"}.get(field, "http_tx")
    return TypedEvent(id=f"event-{n}", family=family, ts=datetime(2025, 1, 1, tzinfo=UTC)+timedelta(seconds=n),
                      host="observer-only", fields=fields, raw=[RawRef(target="synthetic", native_id=str(n))],
                      normalizer="synthetic@1")


@pytest.fixture(autouse=True)
def networks():
    previous = current()
    install(SiteNetworks.from_lists(["10.0.0.0/8"]))
    yield
    install(previous)


@pytest.fixture
def rule():
    instance = module().ServiceCatalog()
    yield instance
    instance.close_spill()


def final(rule, events):
    found = {m.group_key: m for m in rule.consume(events)}
    for match in rule.finalize():
        match.fleet_hosts = tuple(match.fleet_hosts)
        found[match.group_key] = match
    return list(found.values())


@pytest.mark.parametrize("slug,name", NAMES.items())
def test_every_required_service_has_a_sourced_presence_lead(rule, slug, name):
    matches = list(rule.consume([event(name)]))
    assert len(matches) == 1, "presence must be publishable before finalize"
    match = matches[0]
    assert match.group_key == f"{slug}|source|10.0.0.1"
    assert match.proposed_lane == "lead"
    assert "observed" in match.claim and " ran" not in match.claim
    assert match.events[0].raw[0].native_id == "0"
    assert {p.origin for p in match.predicate} == {"native.client", "native.name"}


@pytest.mark.parametrize("field", ["dns.question.name", "tls.client.server_name", "http.hostname"])
def test_three_typed_name_fields_and_native_origins(rule, field):
    [match] = list(rule.consume([event("RELAY-X.NET.ANYDESK.COM.", field=field)]))
    assert match.severity == "high"
    assert any(p.field == field for p in match.predicate)


@pytest.mark.parametrize("name", ["notanydesk.com", "anydesk.com.invalid", "badngrok-free.app", "ngrok-free.app.invalid"])
def test_label_boundary_negatives(rule, name):
    assert final(rule, [event(name)]) == []
    assert rule.evaluated == 1


@pytest.mark.parametrize("field,value", [
    ("url.original", "/search?q=anydesk.com"),
    ("http.request.body.content", "SIEM query: anydesk.com OR ngrok-free.app"),
    ("dns.answers.data", "anydesk.com"), ("dns.answers", [{"type": "TXT", "data": "anydesk.com"}]),
])
def test_uri_body_and_txt_never_supply_a_name(rule, field, value):
    assert final(rule, [event("search.internal", extra={field: value})]) == []
    absent = event(None, extra={field: value})
    assert final(rule, [absent]) == []
    assert rule.evaluated == 1 and rule.missing_required == 1


@pytest.mark.parametrize("name", [None, "", [], {}, 42, "https://ngrok-free.app/", "x..ngrok-free.app", "*.ngrok-free.app"])
def test_missing_or_malformed_names_are_not_clean_evaluations(rule, name):
    assert final(rule, [event(name)]) == []
    assert rule.evaluated == 0 and rule.missing_required == 1


def test_unicode_idna_and_ascii_case_agree():
    trie = module().NameTrie([("bücher.example", "books"), ("ngrok-free.app", "ngrok")])
    assert trie.lookup("X.BÜCHER.EXAMPLE.") == ("books",)
    assert trie.lookup("x.xn--bcher-kva.example") == ("books",)
    assert trie.lookup("notbücher.example") == ()
    assert trie.lookup("bücher.example.invalid") == ()


def test_list_names_do_not_become_multiple_transactions(rule):
    rows = final(rule, [event(["x.ngrok-free.app", "y.ngrok-free.app", "file.io", "x..invalid"])])
    assert rule.evaluated == 1 and rule.missing_required == 1
    assert len(rows) == 4  # two source groups and their two fleet summaries
    assert all(m.aggregate_summary["source_host_count"] == 1 for m in rows)


def test_source_is_canonical_internal_address_not_observer(rule):
    rows = final(rule, [event(source="::ffff:10.0.0.1"), event(source="10.0.0.1", n=1),
                        event(source="203.0.113.4", n=2)])
    assert len(rows) == 2 and all(m.aggregate_summary["source_host_count"] == 1 for m in rows)
    assert all("observer-only" not in m.group_key for m in rows)
    assert rows[-1].fleet_hosts == (("10.0.0.1", ""),)
    assert rule.evaluated == 2


def test_missing_or_ambiguous_source_is_unresolved(rule):
    assert final(rule, [event(source=None), event(source=["10.0.0.1", "10.0.0.2"])]) == []
    assert rule.missing_required == 2 and rule.evaluated == 0


def test_approved_services_are_notes_only(rule):
    rule.site_facts = SimpleNamespace(approved_remote_access=("anydesk",))
    rows = final(rule, [event(NAMES["anydesk"])])
    assert all(m.proposed_lane == "lead" and m.severity == "high" for m in rows)
    assert all(any("site-approved" in note for note in m.notes) for m in rows)


def test_exact_folding_fleet_counts_bounded_citations_and_rare_first(rule):
    events = [event(NAMES["anydesk"], source=f"10.0.0.{i}", n=i) for i in range(1, 5)]
    events += [event(NAMES["ngrok"], n=20), event(NAMES["ngrok"], n=5), event(NAMES["ngrok"], n=30)]
    list(rule.consume(events + events))
    final_stream = rule.finalize()
    assert not isinstance(final_stream, (list, tuple))
    rows = []
    for match in final_stream:
        if "|fleet" in match.group_key:
            assert not isinstance(match.fleet_hosts, (list, tuple, set))
        match.fleet_hosts = tuple(match.fleet_hosts)
        rows.append(match)
    assert len(rows) == 7
    assert rows[0].group_key.startswith("ngrok|")
    ngrok = next(m for m in rows if m.group_key == "ngrok|source|10.0.0.1")
    assert [e.id for e in ngrok.events] == ["event-5", "event-30"]
    fleet = next(m for m in rows if m.group_key == "anydesk|fleet")
    assert fleet.fleet_host_count == 4 and len(fleet.fleet_hosts) == 4
    assert all(len(m.events) <= 2 and len(m.entities) <= 2 for m in rows)
    assert fleet.fleet_hosts_complete


def test_default_network_definition_is_explicit_assumption(rule):
    install(SiteNetworks.default())
    [match] = list(rule.consume([event()]))
    assert rule.direction_assumed == 1
    assert any("direction assumed" in note for note in match.notes)


def test_disk_cap_never_becomes_no_match_or_full_fleet_count(rule, tmp_path):
    rule.spill_dir = tmp_path
    rule.budget = StateBudget(tmp_path, disk_total=8192, reserve=0)
    list(rule.consume([event(n=i, source=f"10.0.{i // 250}.{i % 250 + 1}") for i in range(500)]))
    assert rule.capped > 0 and rule.limits
    assert rule.evaluated + rule.capped == 500
    for match in rule.finalize():
        assert not match.fleet_hosts_complete
        assert any("lower bound" in note for note in match.notes)


def test_shipped_catalog_is_versioned_sourced_and_attack_ids_exist():
    path = ROOT / "content/network/services.json"
    body = json.loads(path.read_text(encoding="utf-8"))
    assert body["schema"] == "romulus.network-services@1" and body["version"]
    assert set(NAMES) <= {entry["id"] for entry in body["entries"]}
    with gzip.open(ROOT / "content/attack/enterprise-attack-20.0.json.gz", "rt", encoding="utf-8") as source:
        attack = json.load(source)
    valid = {ref["external_id"] for obj in attack["objects"]
             if obj["type"] == "attack-pattern" and not obj.get("revoked") and not obj.get("x_mitre_deprecated")
             for ref in obj.get("external_references", []) if ref.get("source_name") == "mitre-attack"}
    for entry in body["entries"]:
        assert entry["attack"] and set(entry["attack"]) <= valid
        assert entry["sources"] and all(s["url"].startswith("https://") and s["license"] for s in entry["sources"])
        assert entry["suffixes"]
    assert module().load_catalog().version == body["version"]


def test_source_findings_do_not_claim_to_retain_the_fleet_membership(rule):
    rows = final(rule, [event(source="10.0.0.1"), event(source="10.0.0.2", n=1)])
    for match in rows:
        if "|source|" in match.group_key:
            assert match.fleet_host_count == 0 and not match.fleet_hosts_complete
            assert match.aggregate_summary["source_host_count"] == 2


def test_oversized_citation_never_drops_service_presence(rule):
    huge = event()
    huge.raw[0].native_id = "x" * 1_000_000
    [match] = list(rule.consume([huge]))
    assert match.citation_unavailable and not match.events
    assert rule.evaluated == 1 and not rule.capped
    assert "service_citations" in rule.limits
    assert len(list(rule.finalize())) == 2


def test_fleet_witnesses_bound_time_across_sources(rule):
    rows = final(rule, [event(source="10.0.0.1", n=100), event(source="10.0.0.2", n=10),
                        event(source="10.0.0.3", n=50)])
    fleet = next(m for m in rows if m.group_key.endswith("|fleet"))
    assert [e.id for e in fleet.events] == ["event-10", "event-100"]
    assert fleet.ts == event(n=100).ts


def test_catalog_anchor_is_network_observation(rule):
    assert rule.anchor_class == "network_observation"


def test_hostless_normalized_service_rollup_keeps_policy_lead(rule):
    from romulus.decide.policy import decide
    from romulus.evidence.normalize import normalize_hits
    eve = {"timestamp": "2025-01-01T00:00:00Z", "event_type": "dns", "src_ip": "10.0.0.1",
           "dest_ip": "10.0.0.53", "dns": {"type": "query", "rrname": "a.ngrok-free.app", "rrtype": "A"}}
    hit = {"_index": "synthetic", "_id": "hostless-dns", "_source": {"@timestamp": eve["timestamp"],
           "event": {"dataset": "suricata.eve", "original": json.dumps(eve)}}}
    events, skips, errors = normalize_hits([hit])
    assert len(events) == 1 and events[0].host is None and not skips and not errors
    rule.site_facts = SimpleNamespace(approved_remote_access=("ngrok",))
    for match in final(rule, events):
        decision = decide(match, "synthetic")
        assert decision.admitted and decision.lane == "lead"
        assert 0 < len(match.entities) <= 2


def test_known_presence_survives_tiny_retention_budget(rule, tmp_path):
    from romulus.decide.policy import decide
    rule.spill_dir = tmp_path
    rule.budget = StateBudget(tmp_path, disk_total=1024, reserve=0)
    matches = list(rule.consume([event()]))
    assert len(matches) == 1
    [match] = matches
    assert match.group_key == "ngrok|source|10.0.0.1"
    assert decide(match, "synthetic").lane == "lead"
    assert rule.capped == 1 and not rule.evaluated
    assert any("lower bound" in note for note in match.notes)
    assert not match.fleet_hosts_complete
