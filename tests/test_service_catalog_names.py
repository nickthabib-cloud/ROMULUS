"""Real typed name shapes and bounded, suffix-only service matching."""
import json

import pytest

from romulus.evidence.normalize import normalize_hits
from tests.test_service_catalog import event, final, module, networks  # noqa: F401


@pytest.fixture
def rule():
    instance = module().ServiceCatalog()
    yield instance
    instance.close_spill()


@pytest.mark.parametrize("field,name,entry", [
    ("dns.question.names", ["a.example.com", "x.ngrok-free.app", "file.io"], "ngrok"),
    ("http.hostname", "X.NGROK-FREE.APP.:8080", "ngrok"),
    ("dns.question.name", "svc_app.c1abc.oast.fun", "interactsh"),
    ("dns.question.name", "svc!app.c1abc.oast.fun", "interactsh"),
    ("dns.question.name", "xn--bcher-kva.ngrok-free.app", "ngrok"),
])
def test_real_name_shapes_retain_service_presence(rule, field, name, entry):
    rows = final(rule, [event(name, field=field)])
    assert any(row.group_key == f"{entry}|source|10.0.0.1" for row in rows)
    assert rule.evaluated == 1 and rule.missing_required == 0
    assert any(p.field == field for row in rows for p in row.predicate)


@pytest.mark.parametrize("name", ["a..ngrok.io", "a" * 300 + ".ngrok.io", "a.ngrok.io.."])
def test_malformed_envelope_is_counted_without_suffix_match(rule, name):
    assert final(rule, [event(name)]) == []
    assert rule.missing_required == 1 and rule.evaluated == 0


@pytest.mark.parametrize("name", ["127.0.0.1:443", "[::1]:443", "[2001:db8::1]", "192.0.2.1"])
def test_ip_host_authorities_are_not_service_names(rule, name):
    assert final(rule, [event(name, field="http.hostname")]) == []


def test_port_is_only_accepted_in_host_field(rule):
    assert final(rule, [event("x.ngrok-free.app:443")]) == []
    assert rule.missing_required == 1


def test_arkime_plural_questions_reach_rule(rule):
    hit = {"_index": "arkime_sessions3-x", "_id": "s1", "_source": {
        "firstPacket": 1735689600000, "lastPacket": 1735689601000,
        "source": {"ip": "10.0.0.5", "port": 5353},
        "destination": {"ip": "10.0.0.53", "port": 53}, "ipProtocol": 17,
        "protocol": ["udp", "dns"], "node": "n1",
        "dns": [{"host": ["a.example.com"], "qt": ["A"]},
                {"host": ["x.ngrok-free.app"], "qt": ["A"]}]}}
    events, skips, errors = normalize_hits([hit])
    assert len(events) == 1 and not skips and not errors
    assert events[0].get("dns.question.name") is None
    assert any(row.group_key == "ngrok|source|10.0.0.5" for row in final(rule, events))


def test_suricata_v3_plural_questions_reach_rule(rule):
    eve = {"timestamp": "2025-01-01T00:00:00Z", "event_type": "dns", "src_ip": "10.0.0.5",
           "dest_ip": "10.0.0.53", "dns": {"version": 3, "type": "request",
           "queries": [{"rrname": "a.example.com", "rrtype": "A"},
                       {"rrname": "x.ngrok-free.app", "rrtype": "A"}]}}
    hit = {"_index": "synthetic", "_id": "dns3", "_source": {"@timestamp": eve["timestamp"],
           "event": {"dataset": "suricata.eve", "original": json.dumps(eve)}}}
    events, skips, errors = normalize_hits([hit])
    assert len(events) == 1 and not skips and not errors
    assert events[0].get("dns.question.name") is None
    assert any(row.group_key == "ngrok|source|10.0.0.5" for row in final(rule, events))


def test_ten_thousand_names_have_bounded_work_and_honest_partial_result(rule):
    # A matching first name survives; a service only beyond the bound is not
    # silently described as absent or as a fully evaluated source membership.
    names = ["x.ngrok-free.app"] + [f"x{i}.example.com" for i in range(9998)] + ["file.io"]
    rows = final(rule, [event(names, field="dns.question.names")])
    assert {row.group_key.split("|")[0] for row in rows} == {"ngrok"}
    assert rule.capped == 1 and rule.evaluated == 0
    assert "service_names" in rule.limits
    assert any("name" in note.casefold() and "evaluat" in note.casefold() for row in rows for note in row.notes)
    assert all(not row.fleet_hosts_complete for row in rows)


def test_catalog_suffixes_still_require_dns_hostname_labels():
    with pytest.raises(ValueError, match="full DNS name"):
        module().NameTrie([("bad_suffix.example", "bad")])
