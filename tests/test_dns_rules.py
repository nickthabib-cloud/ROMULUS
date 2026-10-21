"""Fixtures for the DNS reconnaissance and DNS channel-shape rules: positives, hard benign lookalikes, missing
fields, time boundaries and order independence. Internal addresses are RFC 1918; external ones are documentation
ranges, which the internal-range list does not include."""
import json
import random
from datetime import UTC, datetime, timedelta

import pytest

from romulus.detect import dns, network
from romulus.detect.registry import ALL_PLAYBOOKS, fresh_pack
from romulus.evidence.normalize import normalize_hits
from romulus.evidence.typed import RawRef, TypedEvent, fv

T0 = datetime(2024, 11, 18, 14, 30, tzinfo=UTC)
CLIENT, RESOLVER, AUTH = "10.20.0.15", "10.20.0.53", "10.20.0.2"
OUTSIDE, OUTSIDE2 = "203.0.113.77", "198.51.100.9"
_n = 0


def rec(dns_type="query", client=CLIENT, server=RESOLVER, name="www.example.test", qtype="A", rcode=None,
        ts=None, flow=None, transport="udp", **extra):
    """One dns_query record. A query flows client -> server; an answer server -> client."""
    global _n
    _n += 1
    src, dst = (server, client) if dns_type == "answer" else (client, server)
    fields = {"source.ip": src, "destination.ip": dst, "dns.type": dns_type, "dns.question.name": name,
              "dns.question.type": qtype, "dns.response_code": rcode, "network.transport": transport,
              "suricata.flow_id": flow if flow is not None else _n}
    fields.update(extra)
    return TypedEvent(id=f"d{_n:06d}", family="dns_query", ts=ts or T0, host="sensor",
                      fields={k: fv(v, f"fixture:{k}") for k, v in fields.items() if v is not None},
                      raw=[RawRef(target="fx", native_id=f"r{_n}")], normalizer="fixture")


def pair(client=CLIENT, server=RESOLVER, name="www.example.test", qtype="A", rcode="NOERROR", ts=None):
    """A query and its answer on the same flow."""
    q = rec("query", client, server, name, qtype, ts=ts)
    a = rec("answer", client, server, name, qtype, rcode=rcode, ts=(ts or T0) + timedelta(milliseconds=3),
            flow=q.get("suricata.flow_id"))
    return [q, a]


def run(cls, *batches):
    pb = cls()
    out = []
    for batch in batches:
        out += pb.consume(batch)
    return pb, out + pb.finalize()


def signature(matches):
    return [(m.playbook_id, m.group_key, m.claim, m.proposed_lane, m.severity, [e.id for e in m.events])
            for m in matches]


# ================================================================ registry and helpers
def test_dns_rules_are_registered_aggregates_with_cards_and_verified_attack():
    import gzip
    import hashlib
    from pathlib import Path
    with gzip.open(Path(__file__).parents[1] / "content/attack/enterprise-attack-20.0.json.gz") as handle:
        raw = handle.read()
    assert hashlib.sha256(raw).hexdigest() == "81113ba98afa2928f3dcff62022539f7ce30c315c32e14422f11ff95ce534352"
    live = set()
    for obj in json.loads(raw)["objects"]:
        if obj.get("type") == "attack-pattern" and not obj.get("revoked") and not obj.get("x_mitre_deprecated"):
            live |= {r["external_id"] for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"}
    ids = {cls.id for cls in ALL_PLAYBOOKS}
    for cls in dns.DNS_PLAYBOOKS + [network.DnsSubdomainEnumeration]:
        assert cls.id in ids and cls.kind == "aggregate" and cls.assures_negative
        assert {"behavior", "telemetry", "fidelity", "benign_and_cost", "query_cost", "next_pivot", "adds",
                "research_basis", "retrieval"} <= set(cls.card)
        assert set(cls.attack) <= live, cls.attack
        assert cls.lane == "lead"
    assert {type(pb).id for pb in fresh_pack()} >= {cls.id for cls in dns.DNS_PLAYBOOKS}


def test_network_targets_are_retrieved_without_field_filters():
    """Retrieval superset: a network target's sweep query carries no field filter, so every record any of these
    evaluators reads is retrieved."""
    from romulus.hunt.sweep import Sweep
    assert Sweep._filters_for(None, "suricata-net") == []


@pytest.mark.parametrize("raw, expected", [
    ("AXFR", "AXFR"), ("axfr", "AXFR"), (252, "AXFR"), ("252", "AXFR"), ("TYPE252", "AXFR"), (251, "IXFR"),
    ("ANY", "ANY"), (255, "ANY"), ("*", "ANY"), ("PTR", "PTR"), (10, "NULL"), (65399, "TYPE65399"),
    (None, None), (True, None), ("", None), (["AXFR"], None), (70000, None),
])
def test_question_type_canonical_form(raw, expected):
    assert dns.qtype(raw) == expected


@pytest.mark.parametrize("name, expected", [
    ("a.b.example.com", "example.com"), ("x.attacker.co.uk", "attacker.co.uk"), ("co.uk", "co.uk"),
    ("deep.x.y.example.com.au", "example.com.au"), ("example", "example"),
])
def test_registered_domain(name, expected):
    assert dns.registered_domain(name) == expected


@pytest.mark.parametrize("name, address", [
    ("4.3.2.10.in-addr.arpa", "10.2.3.4"),
    ("3.2.10.in-addr.arpa", None),                 # a zone, not an address
    ("256.3.2.10.in-addr.arpa", None),
    ("4.03.2.10.in-addr.arpa", None),               # not a canonical octet
    ("4.x.2.10.in-addr.arpa", None),
    ("in-addr.arpa", None),
    (".".join("1" + "0" * 30 + "2") + ".ip6.arpa", "2000::1"),
])
def test_reverse_address(name, address):
    got = dns.reverse_address(name)
    assert (str(got) if got else None) == address


def test_reverse_tree_is_label_exact():
    assert dns.reverse_zone("4.3.2.1.in-addr.arpa.evil.test") is None
    assert dns.reverse_zone("x.my-in-addr.arpa") is None
    assert dns.reverse_zone("1.0.0.10.in-addr.arpa") == "in-addr.arpa"


# ================================================================ zone transfer and ANY
def test_internal_axfr_request_without_answer_is_a_lead_that_claims_only_a_request():
    pb, out = run(dns.DnsZoneTransferOrAnyRequest, [rec(name="corp.example.test", qtype="AXFR", server=AUTH,
                                                        transport="tcp")])
    assert len(out) == 1
    m = out[0]
    assert m.proposed_lane == "lead" and m.severity == "medium"
    assert f"{CLIENT} sent 1 DNS question record(s) (AXFR x1) for zone 'corp.example.test' to {AUTH}" in m.claim
    assert "whether the server answered is not established" in m.claim
    assert "transferred" not in m.claim
    assert pb.missing_required == 0 and pb.evaluated == 1


def test_external_axfr_answered_noerror_by_internal_server_is_high():
    q, a = pair(client=OUTSIDE, server=AUTH, name="corp.example.test", qtype="AXFR", rcode="NOERROR")
    _pb, out = run(dns.DnsZoneTransferOrAnyRequest, [q, a])
    m = out[0]
    assert m.proposed_lane == "high" and m.severity == "high"
    assert "AXFR NOERROR x1" in m.claim and "do not show how many zone records were sent" in m.claim
    assert "transferred" not in m.claim
    assert {e.id for e in m.events} == {q.id, a.id}


@pytest.mark.parametrize("code", ["REFUSED", "NOTAUTH", None])
def test_external_axfr_refused_or_unanswered_stays_lead(code):
    events = pair(client=OUTSIDE, server=AUTH, name="corp.example.test", qtype="AXFR", rcode=code)
    if code is None:
        events = events[:1]
    _pb, out = run(dns.DnsZoneTransferOrAnyRequest, events)
    assert [m.proposed_lane for m in out] == ["lead"]
    if code:
        assert "refused or did not implement" in out[0].claim


def test_answer_without_rcode_is_reported_as_not_recorded_never_answered():
    events = pair(client=OUTSIDE, server=AUTH, name="corp.example.test", qtype="AXFR", rcode=None)
    _pb, out = run(dns.DnsZoneTransferOrAnyRequest, events)
    assert "AXFR not recorded x1" in out[0].claim and out[0].proposed_lane == "lead"


def test_answer_only_capture_still_reports_the_request_shape():
    a = pair(client=OUTSIDE, server=AUTH, name="corp.example.test", qtype="AXFR", rcode="NOERROR")[1]
    _pb, out = run(dns.DnsZoneTransferOrAnyRequest, [a])
    assert "the question records themselves were not retrieved" in out[0].claim
    assert out[0].proposed_lane == "high"


@pytest.mark.parametrize("raw", [252, "252", "TYPE252", "axfr"])
def test_numeric_and_textual_axfr_forms_match(raw):
    _pb, out = run(dns.DnsZoneTransferOrAnyRequest, [rec(name="corp.example.test", qtype=raw)])
    assert len(out) == 1 and "(AXFR x1)" in out[0].claim


def test_external_udp_any_is_a_lead_with_a_spoofing_note():
    _pb, out = run(dns.DnsZoneTransferOrAnyRequest, [rec(client=OUTSIDE, server=AUTH, name="example.test",
                                                        qtype="ANY")])
    m = out[0]
    assert m.proposed_lane == "lead" and "for 1 distinct name(s) ('example.test')" in m.claim
    assert "for zone" not in m.claim and m.group_key == f"{OUTSIDE}|{AUTH}|ANY"
    assert any("spoofed" in note for note in m.notes)


def test_any_questions_for_many_names_are_one_finding_per_client_and_server():
    events = [rec(name=f"recipient{i}.example.test", qtype="ANY", server=AUTH) for i in range(40)]
    events += [rec(name="corp.example.test", qtype="AXFR", server=AUTH)]
    _pb, out = run(dns.DnsZoneTransferOrAnyRequest, events)
    assert sorted(m.group_key for m in out) == [f"{CLIENT}|{AUTH}|ANY", f"{CLIENT}|{AUTH}|corp.example.test"]
    any_claim = next(m.claim for m in out if m.group_key.endswith("|ANY"))
    assert "40 distinct name(s)" in any_claim and "and 35 more" in any_claim


def test_transfer_words_in_names_or_other_fields_are_not_requests():
    events = [rec(name="axfr.example.test", qtype="A"), rec(name="any.example.test", qtype="TXT"),
              rec(name="AXFR", qtype="AAAA"), rec(name="zone.example.test", qtype="A", dns__note="AXFR")]
    pb, out = run(dns.DnsZoneTransferOrAnyRequest, events)
    assert out == [] and pb.evaluated == 4 and pb.missing_required == 0


def test_missing_question_type_or_address_is_partial_not_a_clean_negative():
    events = [rec(name="corp.example.test", qtype=None), rec(client=None, qtype="AXFR"),
              rec(dns_type="weird", qtype="AXFR")]
    pb, out = run(dns.DnsZoneTransferOrAnyRequest, events)
    assert out == [] and pb.missing_required == 3 and pb.evaluated == 0


def test_question_and_answer_in_different_partitions_join_into_one_group():
    q, a = pair(client=OUTSIDE, server=AUTH, name="corp.example.test", qtype="AXFR", rcode="NOERROR",
                ts=T0 + timedelta(minutes=59, seconds=59, milliseconds=999))
    _pb, out = run(dns.DnsZoneTransferOrAnyRequest, [q], [a])
    assert len(out) == 1 and out[0].proposed_lane == "high"


# ================================================================ reverse-lookup sweep
def ptr(client, address, **kw):
    return rec(client=client, name=".".join(reversed(address.split("."))) + ".in-addr.arpa", qtype="PTR", **kw)


def test_reverse_sweep_of_an_internal_block_is_reported_with_its_range():
    events = [ptr(CLIENT, f"10.30.4.{i}") for i in range(256)]
    _pb, out = run(dns.DnsReverseLookupSweep, events)
    assert len(out) == 1
    m = out[0]
    assert m.proposed_lane == "lead" and m.severity == "medium" and m.group_key == CLIENT
    assert "256 distinct reverse-lookup name(s)" in m.claim
    assert "10.30.4.0/24 (256 address(es), 10.30.4.0 – 10.30.4.255)" in m.claim
    assert "shape of a reverse-DNS sweep" in m.claim and "do not show whether names were returned" in m.claim
    assert "T1018" in m.notes[0]


def test_dense_partial_block_reports_and_small_counts_do_not():
    _pb, out = run(dns.DnsReverseLookupSweep, [ptr(CLIENT, f"10.30.4.{i}") for i in range(32)])
    assert len(out) == 1
    _pb, out = run(dns.DnsReverseLookupSweep, [ptr(CLIENT, f"10.30.4.{i}") for i in range(31)]
                   + [ptr("10.20.0.16", f"10.30.5.{i}") for i in range(8)])
    assert out == []


def test_scattered_reverse_lookups_at_the_enumeration_threshold_are_still_reported():
    """Everything the enumeration rule reported for reverse trees (100 distinct names) is reported here."""
    events = [ptr("10.20.0.25", f"198.51.{i}.{i % 200 + 1}") for i in range(100)]
    _pb, out = run(dns.DnsReverseLookupSweep, events)
    assert len(out) == 1 and out[0].proposed_lane == "lead"
    assert "IPv4 addresses span 198.51.0.1 – 198.51.99.100." in out[0].claim
    assert "No block holds 32 or more" in out[0].claim and "0 of the 100 addresses are in internal ranges" in out[0].claim


def test_enumeration_no_longer_reports_reverse_trees_but_sweep_does_at_the_same_lane():
    reverse = [ptr(CLIENT, f"10.30.4.{i}", dns__type="query") for i in range(150)]
    forward = [rec(client=CLIENT, name=f"h{i}.target.example.test") for i in range(120)]
    enum = network.DnsSubdomainEnumeration()
    enum.consume(reverse + forward)
    found = enum.finalize()
    assert [m.group_key for m in found] == [f"{CLIENT}|example.test"]
    assert enum.evaluated == 270 and enum.missing_required == 0
    _pb, sweep = run(dns.DnsReverseLookupSweep, reverse + forward)
    assert len(sweep) == 1 and sweep[0].proposed_lane == found[0].proposed_lane == "lead"
    assert sweep[0].severity == found[0].severity


def test_reverse_lookalikes_are_not_reverse_names():
    events = [rec(name=f"4.3.2.{i}.in-addr.arpa.example.test") for i in range(150)]
    events += [rec(name=f"host{i}.example.test", qtype="PTR") for i in range(150)]
    _pb, out = run(dns.DnsReverseLookupSweep, events)
    assert out == []


def test_zone_names_are_counted_as_names_not_addresses():
    events = [rec(name=f"{i}.168.192.in-addr.arpa", qtype="SOA") for i in range(100)]
    _pb, out = run(dns.DnsReverseLookupSweep, events)
    assert len(out) == 1 and "100 name a reverse zone rather than one address" in out[0].claim


def test_ipv6_reverse_names_map_to_a_64():
    names = []
    for i in range(40):
        addr = f"20010db8000000010000000000{i:06x}"
        names.append(rec(name=".".join(reversed(addr)) + ".ip6.arpa", qtype="PTR"))
    _pb, out = run(dns.DnsReverseLookupSweep, names)
    assert len(out) == 1 and "2001:db8:0:1::/64 (40 address(es)" in out[0].claim


def test_answers_of_retrieved_questions_are_not_double_counted_and_orphan_answers_are_partial():
    events = []
    for i in range(40):
        events += pair(name=f"{i}.4.30.10.in-addr.arpa", qtype="PTR", rcode="NXDOMAIN")
    pb, out = run(dns.DnsReverseLookupSweep, events)
    assert pb.missing_required == 0 and pb.evaluated == 40
    assert "40 distinct" in out[0].claim and "sent 40 DNS question record(s)" in out[0].claim
    orphan = [rec("answer", name=f"{i}.4.30.10.in-addr.arpa", qtype="PTR", rcode="NOERROR") for i in range(40)]
    pb, out = run(dns.DnsReverseLookupSweep, orphan)
    assert out == [] and pb.missing_required == 40 and pb.evaluated == 0


def test_reverse_sweep_missing_name_or_client_is_partial():
    pb, out = run(dns.DnsReverseLookupSweep, [rec(name=None), rec(client=None, name="1.4.30.10.in-addr.arpa"),
                                             rec(name=["1.4.30.10.in-addr.arpa"])])
    assert out == [] and pb.missing_required == 3


def test_reverse_sweep_split_across_partitions_reaches_the_threshold():
    first = [ptr(CLIENT, f"10.30.4.{i}", ts=T0 + timedelta(seconds=i)) for i in range(20)]
    second = [ptr(CLIENT, f"10.30.4.{i}", ts=T0 + timedelta(hours=1, seconds=i)) for i in range(20, 40)]
    _pb, out = run(dns.DnsReverseLookupSweep, first, second)
    assert len(out) == 1 and "10.30.4.0/24 (40 address(es)" in out[0].claim


# ================================================================ NXDOMAIN burst
def nx_answers(count, client=CLIENT, step=timedelta(seconds=5), start=T0, names=None, code="NXDOMAIN"):
    out = []
    for i in range(count):
        name = names(i) if names else f"q{i:04d}xkvj{i * 7919 % 9973}.example.test"
        out.append(rec("answer", client=client, server=RESOLVER, name=name, rcode=code, ts=start + i * step))
    return out


def test_nxdomain_burst_is_keyed_on_the_answer_destination():
    events = nx_answers(60) + nx_answers(40, code="NOERROR", start=T0 + timedelta(hours=1))
    pb, out = run(dns.DnsNxdomainBurst, events)
    assert len(out) == 1
    m = out[0]
    assert m.group_key == CLIENT and m.proposed_lane == "lead" and m.severity == "high"
    assert f"{CLIENT} was sent 60 NXDOMAIN answer(s) (60% of the 100 answer record(s)" in m.claim
    assert "at most 60 of them fell within one ten-minute interval" in m.claim
    assert f"Answering server(s): {RESOLVER} x60" in m.claim
    assert "60 distinct name(s)" in m.claim
    assert pb.evaluated == 100 and pb.missing_required == 0


def test_nxdomain_burst_window_is_half_open():
    step = timedelta(seconds=12)
    base = nx_answers(49, step=step)
    _pb, out = run(dns.DnsNxdomainBurst, base + nx_answers(1, start=T0 + timedelta(minutes=10)))
    assert out == []                                     # 49 + the one at exactly t0 + 10 min: never 50 inside
    _pb, out = run(dns.DnsNxdomainBurst, base + nx_answers(1, start=T0 + timedelta(minutes=10) - timedelta(microseconds=1)))
    assert len(out) == 1 and "at most 50 of them" in out[0].claim


def test_nxdomain_burst_across_partitions_counts_together():
    events = nx_answers(60, step=timedelta(seconds=2), start=T0 - timedelta(seconds=60))
    _pb, out = run(dns.DnsNxdomainBurst, events[:30], events[30:])
    assert len(out) == 1


def test_slow_nxdomain_drip_is_not_a_burst():
    _pb, out = run(dns.DnsNxdomainBurst, nx_answers(200, step=timedelta(minutes=2)))
    assert out == []


def test_repeated_single_name_burst_is_reported_with_restrained_wording():
    _pb, out = run(dns.DnsNxdomainBurst, nx_answers(80, names=lambda i: "oldhost.corp.example.test"))
    assert len(out) == 1 and "1 distinct name(s)" in out[0].claim and "retrying a name" in out[0].claim


def test_noerror_volume_and_names_mentioning_nxdomain_are_not_bursts():
    events = nx_answers(300, code="NOERROR", names=lambda i: f"nxdomain-{i}.example.test", step=timedelta(seconds=1))
    _pb, out = run(dns.DnsNxdomainBurst, events)
    assert out == []


def test_query_records_carrying_an_rcode_are_not_answers():
    events = [rec("query", name=f"n{i}.example.test", rcode="NXDOMAIN") for i in range(80)]
    events += nx_answers(1, code="NOERROR")
    pb, out = run(dns.DnsNxdomainBurst, events)
    assert out == [] and pb.missing_required == 0


def test_questions_without_any_answers_and_answers_without_rcode_are_partial():
    pb, out = run(dns.DnsNxdomainBurst, [rec("query", name=f"n{i}.example.test") for i in range(80)])
    assert out == [] and pb.missing_required == 80 and pb.evaluated == 0
    pb, out = run(dns.DnsNxdomainBurst, nx_answers(80, code=None))
    assert out == [] and pb.missing_required == 80
    pb, out = run(dns.DnsNxdomainBurst, [rec("answer", client=None, rcode="NXDOMAIN")])
    assert out == [] and pb.missing_required == 1


def test_resolver_is_not_blamed_for_its_clients_failures():
    """The resolver sends the answers; only the client the answers go to is reported."""
    events = nx_answers(60)
    _pb, out = run(dns.DnsNxdomainBurst, events)
    assert [m.group_key for m in out] == [CLIENT]


def test_numeric_rcode_is_understood():
    _pb, out = run(dns.DnsNxdomainBurst, nx_answers(55, code=3))
    assert len(out) == 1


# ================================================================ tunnel shape
HEX = "0123456789abcdef"
B32 = "abcdefghijklmnopqrstuvwxyz234567"


def blob(rng, alphabet, length):
    return "".join(rng.choice(alphabet) for _ in range(length))


def tunnel(count, domain="tun.example.test", types=("TXT", "CNAME", "MX"), alphabet=HEX, label=60, client=CLIENT,
           seed=1, start=T0):
    rng = random.Random(seed)
    out = []
    for i in range(count):
        name = f"{blob(rng, alphabet, label)}.{blob(rng, alphabet, label // 2)}.{domain}"
        out.append(rec(client=client, name=name, qtype=types[i % len(types)], ts=start + timedelta(seconds=i)))
    return out


def test_dnscat_like_txt_cname_mx_tunnel_is_high():
    _pb, out = run(dns.DnsTunnelShape, tunnel(400))
    assert len(out) == 1
    m = out[0]
    assert m.group_key == f"{CLIENT}|example.test" and m.proposed_lane == "high" and m.severity == "high"
    assert "Indicators met: long names, high entropy, unusual question types, volume" in m.claim
    assert "deviation, not proof" in m.claim


def test_iodine_like_null_tunnel_is_high():
    _pb, out = run(dns.DnsTunnelShape, tunnel(350, types=("NULL",), alphabet=B32))
    assert [m.proposed_lane for m in out] == ["high"]


def test_private_use_type_counts_as_unusual():
    _pb, out = run(dns.DnsTunnelShape, tunnel(350, types=(65399,), alphabet=B32))
    assert [m.proposed_lane for m in out] == ["high"]


def test_a_record_tunnel_with_long_random_labels_is_a_lead():
    _pb, out = run(dns.DnsTunnelShape, tunnel(80, types=("A",), alphabet=B32))
    assert len(out) == 1 and out[0].proposed_lane == "lead"
    assert "Indicators met: long names, high entropy." in out[0].claim


def test_hash_reputation_lookups_have_the_shape_but_stay_lead():
    """Anti-virus (A) and hash-reputation (TXT) services encode hashes: same shape, never high."""
    av = tunnel(500, domain="avlookup.test", types=("A",), label=40)
    rep = tunnel(500, domain="hashrep.test", types=("TXT",), label=40, seed=2)
    _pb, out = run(dns.DnsTunnelShape, av + rep)
    assert sorted(m.proposed_lane for m in out) == ["lead", "lead"]


def test_benign_lookalikes_do_not_match():
    rng = random.Random(7)
    events = [rec(name=f"e{rng.randint(1000, 9999)}.dscb.cdn.example.test") for _ in range(400)]       # CDN
    events += [rec(name=f"ec2-10-0-{i // 250}-{i % 250}.compute-1.cloud.example.test") for i in range(400)]
    events += [rec(name=f"s{i}._domainkey.mail.example.test", qtype="TXT") for i in range(5)]           # DKIM
    events += [rec(name="_dmarc.mail.example.test", qtype="TXT") for _ in range(50)]
    events += [rec(name="_acme-challenge.www.example.test", qtype="TXT") for _ in range(60)]
    events += [rec(name="metadata.google.internal") for _ in range(100)]
    events += [rec(name=f"{blob(rng, HEX, 40)}._googlecast._tcp.local", qtype="PTR") for _ in range(100)]  # mDNS
    events += [ptr(CLIENT, f"10.30.{i // 256}.{i % 256}") for i in range(400)]                         # reverse
    events += [rec(name=f"{i}.4.3.2.zen.dnsbl.example.test") for i in range(400)]                      # DNSBL
    _pb, out = run(dns.DnsTunnelShape, events)
    assert out == []


def test_long_names_only_in_another_field_do_not_count():
    rng = random.Random(3)
    events = [rec(name="www.example.test", qtype="TXT", http__hostname=f"{blob(rng, HEX, 60)}.tun.example.test")
              for _ in range(400)]
    _pb, out = run(dns.DnsTunnelShape, events)
    assert out == []


def test_missing_question_type_is_partial_but_still_reports_the_name_shape():
    events = tunnel(80, types=(None,), alphabet=B32)
    pb, out = run(dns.DnsTunnelShape, events)
    assert pb.missing_required == 80 and len(out) == 1 and out[0].proposed_lane == "lead"
    assert "80 question record(s) carry no question type" in out[0].claim


def test_country_suffix_domains_are_not_merged():
    a = tunnel(30, domain="one.co.uk", types=("A",), alphabet=B32, seed=4)
    b = tunnel(30, domain="two.co.uk", types=("A",), alphabet=B32, seed=5)
    _pb, out = run(dns.DnsTunnelShape, a + b)
    assert out == []                                    # each registered domain holds only 30 distinct names


def test_tunnel_split_across_partitions_reaches_the_threshold():
    events = tunnel(60, types=("A",), alphabet=B32, start=T0 - timedelta(seconds=30))
    _pb, out = run(dns.DnsTunnelShape, events[:30], events[30:])
    assert len(out) == 1


def test_tunnel_missing_name_is_partial():
    pb, out = run(dns.DnsTunnelShape, [rec(name=None), rec(name="")])
    assert out == [] and pb.missing_required == 2


# ================================================================ all rules: order independence, normalizer path
def _mixed_events():
    events = [rec(name="corp.example.test", qtype="AXFR", server=AUTH)]
    events += pair(client=OUTSIDE, server=AUTH, name="corp.example.test", qtype="AXFR", rcode="NOERROR")
    events += [ptr(CLIENT, f"10.30.4.{i}") for i in range(64)]
    events += nx_answers(70, client="10.20.0.31")
    events += tunnel(320, client="10.20.0.40")
    return events


@pytest.mark.parametrize("cls", dns.DNS_PLAYBOOKS)
def test_output_is_identical_whatever_the_record_order(cls):
    events = _mixed_events()
    shuffled = events[:]
    random.Random(11).shuffle(shuffled)
    _pb, first = run(cls, events)
    _pb, second = run(cls, shuffled)
    assert signature(first) == signature(second)


def _eve(i, eve):
    return {"_id": f"s{i}", "_index": "net",
            "_source": {"@timestamp": eve["timestamp"], "host": {"name": "sensor"},
                        "event": {"dataset": "suricata.eve.dns", "original": json.dumps(eve)}}}


def test_suricata_eve_v2_records_flow_through_the_normalizer():
    hits = []
    stamp = "2024-11-18T14:30:{:02d}.000000+00:00"
    hits.append(_eve(0, {"timestamp": stamp.format(0), "event_type": "dns", "flow_id": 9001, "src_ip": OUTSIDE,
                         "src_port": 51000, "dest_ip": AUTH, "dest_port": 53, "proto": "TCP",
                         "dns": {"version": 2, "type": "query", "id": 7, "rrname": "corp.example.test",
                                 "rrtype": "AXFR", "tx_id": 0}}))
    hits.append(_eve(1, {"timestamp": stamp.format(1), "event_type": "dns", "flow_id": 9001, "src_ip": AUTH,
                         "src_port": 53, "dest_ip": OUTSIDE, "dest_port": 51000, "proto": "TCP",
                         "dns": {"version": 2, "type": "answer", "id": 7, "flags": "8400", "qr": True,
                                 "rrname": "corp.example.test", "rrtype": "AXFR", "rcode": "NOERROR"}}))
    for i in range(55):
        hits.append(_eve(10 + i, {"timestamp": stamp.format(2 + i % 50), "event_type": "dns", "flow_id": 100 + i,
                                  "src_ip": RESOLVER, "src_port": 53, "dest_ip": CLIENT, "dest_port": 40000 + i,
                                  "proto": "UDP",
                                  "dns": {"version": 2, "type": "answer", "id": i, "flags": "8183", "qr": True,
                                          "rrname": f"gen{i}xq.example.test", "rrtype": "A",
                                          "rcode": "NXDOMAIN"}}))
    events, skips, errors = normalize_hits(hits)
    assert not errors and not skips and len(events) == 57
    _pb, zone = run(dns.DnsZoneTransferOrAnyRequest, events)
    assert [(m.group_key, m.proposed_lane) for m in zone] == [(f"{OUTSIDE}|{AUTH}|corp.example.test", "high")]
    pb, nx = run(dns.DnsNxdomainBurst, events)
    assert [m.group_key for m in nx] == [CLIENT] and pb.missing_required == 0
