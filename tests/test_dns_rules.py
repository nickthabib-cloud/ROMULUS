"""Fixtures for the DNS reconnaissance and DNS channel-shape rules: positives, hard benign lookalikes, missing
fields, time boundaries and order independence. Internal addresses are RFC 1918; external ones are documentation
ranges, which the internal-range list does not include."""
import json
import random
from collections import Counter
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
    src, dst = (server, client) if dns_type in ("answer", "response") else (client, server)
    fields = {"source.ip": src, "destination.ip": dst, "dns.type": dns_type, "dns.question.name": name,
              "dns.question.type": qtype, "dns.response_code": rcode, "network.transport": transport,
              "suricata.flow_id": flow if flow is not None else _n}
    fields.update({k.replace("__", "."): v for k, v in extra.items()})
    return TypedEvent(id=f"d{_n:06d}", family="dns_query", ts=ts or T0, host="sensor",
                      fields={k: fv(v, f"fixture:{k}") for k, v in fields.items() if v is not None},
                      raw=[RawRef(target="fx", native_id=f"r{_n}")], normalizer="fixture")


def pair(client=CLIENT, server=RESOLVER, name="www.example.test", qtype="A", rcode="NOERROR", ts=None,
         transport="udp", roles=("query", "answer")):
    """A query and its answer on the same flow."""
    q = rec(roles[0], client, server, name, qtype, ts=ts, transport=transport)
    a = rec(roles[1], client, server, name, qtype, rcode=rcode, ts=(ts or T0) + timedelta(milliseconds=3),
            flow=q.get("suricata.flow_id"), transport=transport)
    return [q, a]


def run(cls, *batches):
    pb = cls()
    stage = {}
    out = []
    for batch in batches:
        out += pb.consume(batch)
        if pb.staged:
            stage.update({event.id: event for event in pb.drain_staged()})
    if pb.staged:
        pb.bind_loader(lambda ids: [stage[event_id] for event_id in ids if event_id in stage])
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


def test_dns_examples_stage_whole_events_and_release_compact_state():
    rule = dns.DnsReverseLookupSweep()
    event = rec(name="1.0.0.10.in-addr.arpa", qtype="PTR")

    rule.consume([event])

    assert rule.staged is True
    assert rule.retained_events() == []
    # kept as an example, and held as the record bounding the span, the address range and its block's range
    assert {e.id for e in rule.drain_staged()} == {event.id}
    held, released = rule.drain_bounds()
    assert set(held) == {event.id} and released == []
    assert all(isinstance(event_id, str) for store in rule.examples.values() for event_id in store.ids())
    rule.release_state()
    assert rule.examples == {}
    assert rule.names == {}
    assert rule._pending == {}


@pytest.mark.parametrize("shuffled", [False, True])
def test_dns_staging_grows_with_cite_limits_not_with_dns_volume(shuffled):
    """A long hunt sends millions of questions per (client, domain); only records that can still be cited are
    staged, so the stage is bounded by the groups' cite limits whatever the volume or arrival order."""
    import random
    volume = 20_000
    events = [rec(name=f"q{i:05d}.example.test", ts=T0 + timedelta(seconds=i)) for i in range(volume)]
    if shuffled:
        random.Random(7).shuffle(events)
    rule = dns.DnsTunnelShape()
    kept, holds = set(), Counter()
    for start in range(0, volume, 1000):
        rule.consume(events[start:start + 1000])
        drained = rule.drain_staged()
        held, released = rule.drain_bounds()
        holds.update(held)
        holds.subtract(released)
        copies = Counter(event.id for event in drained)
        kept |= {event_id for event_id, n in copies.items() if n > held.count(event_id)}
        # what the stage holds now: the kept examples, the span's two bounds and the example names' records
        live = kept | {event_id for event_id, n in holds.items() if n > 0}
        assert len(live) <= (dns.EXAMPLE_LIMIT if not shuffled else dns.EXAMPLE_LIMIT * 12) + 2 + 6
    earliest = {event.id for event in sorted(events, key=lambda e: (e.ts, e.id))[:dns.EXAMPLE_LIMIT]}
    assert earliest <= kept
    # in time order exactly the cite limit; in random order each record enters with probability limit/rank
    assert len(kept) <= (dns.EXAMPLE_LIMIT if not shuffled else dns.EXAMPLE_LIMIT * 12)


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
    q, a = pair(client=OUTSIDE, server=AUTH, name="corp.example.test", qtype="AXFR", rcode="NOERROR",
                transport="tcp")
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
    a = pair(client=OUTSIDE, server=AUTH, name="corp.example.test", qtype="AXFR", rcode="NOERROR",
             transport="tcp")[1]
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
                ts=T0 + timedelta(minutes=59, seconds=59, milliseconds=999), transport="tcp")
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


def test_scattered_reverse_lookups_at_the_enumeration_threshold_are_reported():
    """A client with the enumeration rule's count (100 distinct names) of reverse names is reported here."""
    events = [ptr("10.20.0.25", f"198.51.{i}.{i % 200 + 1}") for i in range(100)]
    _pb, out = run(dns.DnsReverseLookupSweep, events)
    assert len(out) == 1 and out[0].proposed_lane == "lead"
    assert "IPv4 addresses span 198.51.0.1 – 198.51.99.100." in out[0].claim
    assert "No block holds 32 or more" in out[0].claim and "0 of the 100 addresses are in internal ranges" in out[0].claim


def test_enumeration_leaves_reverse_trees_to_the_sweep_at_the_same_lane():
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


RESOLVER_SAYS = "it acts as a DNS server for other addresses"


def forwarded(count, clients, step=timedelta(seconds=5), start=T0):
    """A resolver forwarding failed lookups: the upstream server's NXDOMAIN answers to the resolver, then the
    resolver's own NXDOMAIN answers to the client that asked, round-robin over `clients`."""
    out = []
    for i in range(count):
        ts = start + i * step
        name = f"host{i:04d}.corp.example.test"
        out.append(rec("answer", client=RESOLVER, server=OUTSIDE, name=name, rcode="NXDOMAIN", ts=ts))
        out.append(rec("answer", client=clients[i % len(clients)], server=RESOLVER, name=name, rcode="NXDOMAIN",
                       ts=ts + timedelta(milliseconds=2)))
    return out


def test_resolver_burst_from_mixed_clients_says_so_and_names_the_clients_that_asked():
    clients = [f"10.20.1.{i}" for i in range(1, 7)]
    events = forwarded(60, clients) + pair(client="10.20.1.9", server=RESOLVER)
    _pb, out = run(dns.DnsNxdomainBurst, events)
    assert [m.group_key for m in out] == [RESOLVER]          # no single client reached the threshold
    m = out[0]
    assert m.proposed_lane == "lead" and m.severity == "high"
    assert f"{RESOLVER} was sent 60 NXDOMAIN answer(s)" in m.claim and f"Answering server(s): {OUTSIDE} x60" in m.claim
    assert RESOLVER_SAYS in m.claim
    assert "it sent 61 DNS answer record(s) to 7 other address(es)" in m.claim
    # the clients it answered are counted, not named: their answer records are not among this finding's citations
    assert ("In the peak interval it sent 60 NXDOMAIN answer(s) to 6 client(s) (counted from answer records that are "
            "not cited).") in m.claim
    assert not any(c in m.claim for c in clients)
    assert "No client it answered reached the burst threshold on its own." in m.claim


def test_workstation_dga_behind_a_resolver_keeps_its_own_finding_and_the_resolver_points_to_it():
    workstation = "10.20.1.77"
    events = forwarded(300, [workstation], step=timedelta(seconds=1))
    _pb, out = run(dns.DnsNxdomainBurst, events)
    by_key = {m.group_key: m for m in out}
    assert set(by_key) == {RESOLVER, workstation}
    ws = by_key[workstation]
    assert ws.proposed_lane == "lead" and ws.severity == "high" and RESOLVER_SAYS not in ws.claim
    assert "at most 300 of them fell within one ten-minute interval" in ws.claim
    assert "1 of those clients have their own finding" in by_key[RESOLVER].claim


def test_an_address_that_only_asks_is_not_called_a_resolver():
    _pb, out = run(dns.DnsNxdomainBurst, nx_answers(60))
    assert len(out) == 1 and RESOLVER_SAYS not in out[0].claim


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
    assert "80 question(s) carry no question type" in out[0].claim


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


# ================================================================ zone-transfer high lane: deciding record, transport
def _axfr(code, ts, transport="tcp", client=OUTSIDE, server=AUTH):
    return pair(client=client, server=server, name="corp.example.test", qtype="AXFR", rcode=code, ts=ts,
                transport=transport)


def test_high_lane_cites_the_deciding_noerror_answer_and_its_query():
    events = []
    for i in range(25):
        events += _axfr("REFUSED", T0 + timedelta(seconds=i))
    deciding_q, deciding_a = _axfr("NOERROR", T0 + timedelta(minutes=5))
    _pb, out = run(dns.DnsZoneTransferOrAnyRequest, events + [deciding_q, deciding_a])
    m = out[0]
    assert m.proposed_lane == "high"
    ids = [e.id for e in m.events]
    assert deciding_a.id in ids and deciding_q.id in ids and len(ids) <= 20
    codes = [p.value for p in m.predicate if p.field == "dns.response_code"]
    assert codes and codes[0] == "NOERROR"
    assert deciding_a.ts.isoformat() in m.claim


@pytest.mark.parametrize("transport", ["udp", None])
def test_noerror_axfr_over_udp_or_unknown_transport_stays_lead(transport):
    _pb, out = run(dns.DnsZoneTransferOrAnyRequest, _axfr("NOERROR", T0, transport=transport))
    assert [m.proposed_lane for m in out] == ["lead"]
    assert "TCP" in out[0].claim


@pytest.mark.parametrize("client, server", [(CLIENT, AUTH), (CLIENT, OUTSIDE2), (OUTSIDE, OUTSIDE2)])
def test_noerror_tcp_axfr_without_outside_client_and_inside_server_stays_lead(client, server):
    _pb, out = run(dns.DnsZoneTransferOrAnyRequest, _axfr("NOERROR", T0, client=client, server=server))
    assert [m.proposed_lane for m in out] == ["lead"]


def test_suricata_v3_request_and_response_roles_are_queries_and_answers():
    events = pair(client=OUTSIDE, server=AUTH, name="corp.example.test", qtype="AXFR", rcode="NOERROR",
                  transport="tcp", roles=("request", "response"))
    pb, out = run(dns.DnsZoneTransferOrAnyRequest, events)
    assert pb.missing_required == 0 and [m.proposed_lane for m in out] == ["high"]
    assert out[0].group_key == f"{OUTSIDE}|{AUTH}|corp.example.test"


# ================================================================ answer-to-question matching
def test_answer_matches_its_query_from_the_previous_batch_only():
    q, a = pair(name="1.4.30.10.in-addr.arpa", qtype="PTR")
    pb, _out = run(dns.DnsReverseLookupSweep, [q], [a])
    assert pb.missing_required == 0
    pb, _out = run(dns.DnsReverseLookupSweep, [q], [], [a])
    assert pb.missing_required == 1


def test_answer_on_a_reused_flow_for_another_question_is_missing():
    q, _a = pair(name="1.4.30.10.in-addr.arpa", qtype="PTR")
    other = rec("answer", name="2.4.30.10.in-addr.arpa", qtype="PTR", rcode="NOERROR",
                flow=q.get("suricata.flow_id"))
    pb, _out = run(dns.DnsReverseLookupSweep, [q, other])
    assert pb.missing_required == 1


def test_answer_with_a_different_transaction_id_is_missing():
    q = rec(name="1.4.30.10.in-addr.arpa", qtype="PTR", dns__id=7)
    a = rec("answer", name="1.4.30.10.in-addr.arpa", qtype="PTR", rcode="NOERROR", flow=q.get("suricata.flow_id"),
            dns__id=8)
    pb, _out = run(dns.DnsReverseLookupSweep, [q, a])
    assert pb.missing_required == 1


def test_suricata_v3_response_records_are_answers_for_the_question_rules():
    events = []
    for i in range(40):
        events += pair(name=f"{i}.4.30.10.in-addr.arpa", qtype="PTR", rcode="NOERROR", roles=("request", "response"))
    pb, out = run(dns.DnsReverseLookupSweep, events)
    assert pb.missing_required == 0 and pb.evaluated == 40 and len(out) == 1
    pb, out = run(dns.DnsNxdomainBurst, [rec("response", name=f"g{i}.example.test", rcode="NXDOMAIN")
                                        for i in range(60)])
    assert [m.group_key for m in out] == [CLIENT] and pb.missing_required == 0


def test_enumeration_rule_reads_suricata_v3_requests():
    enum = network.DnsSubdomainEnumeration()
    enum.consume([rec("request", name=f"h{i}.target.example.test") for i in range(120)]
                 + [rec("response", name="h1.target.example.test", rcode="NOERROR")])
    assert [m.group_key for m in enum.finalize()] == [f"{CLIENT}|example.test"]
    assert enum.evaluated == 120 and enum.missing_required == 1


# ================================================================ multi-question records
def test_multi_question_transaction_records_are_evaluated_per_name():
    events = [rec(None, name=None, qtype="PTR",
                  dns__question__names=sorted(f"{i}.{j}.30.10.in-addr.arpa" for j in (4, 5)))
              for i in range(40)]
    pb, out = run(dns.DnsReverseLookupSweep, events)
    assert pb.missing_required == 0 and pb.evaluated == 40
    assert "80 distinct reverse-lookup name(s)" in out[0].claim


def test_scalar_name_is_used_when_the_names_list_is_absent():
    pb, out = run(dns.DnsReverseLookupSweep, [ptr(CLIENT, f"10.30.4.{i}", dns_type=None) for i in range(40)])
    assert pb.missing_required == 0 and len(out) == 1


# ================================================================ citations from the deciding part of a group
def test_nxdomain_citations_come_from_the_peak_window():
    early = nx_answers(30, step=timedelta(minutes=7))                      # a slow drip first
    burst_start = T0 + timedelta(hours=5)
    burst = nx_answers(60, step=timedelta(seconds=3), start=burst_start)
    _pb, out = run(dns.DnsNxdomainBurst, early + burst)
    m = out[0]
    # the peak's earliest 20 records, beside the records bounding the span and those the names and servers come from
    inside = [e for e in m.events if burst_start <= e.ts < burst_start + timedelta(minutes=10)]
    assert len(inside) >= 20 and len(m.events) <= 20 + 2 + 5 + 5


def test_nxdomain_peak_citations_when_the_window_straddles_buckets():
    bucket = T0 + timedelta(hours=2)                                       # a ten-minute boundary (14:30 + 2h)
    start = bucket + timedelta(minutes=8)
    burst = nx_answers(60, step=timedelta(seconds=9), start=start)
    before = nx_answers(10, step=timedelta(seconds=1), start=bucket)        # same bucket, before the peak
    _pb, out = run(dns.DnsNxdomainBurst, nx_answers(25, step=timedelta(minutes=3)) + before + burst)
    m = out[0]
    assert len([e for e in m.events if start <= e.ts < start + timedelta(minutes=10)]) >= 20


def test_reverse_sweep_cites_the_densest_block():
    scattered = [ptr(CLIENT, f"198.51.{i}.7", ts=T0 + timedelta(seconds=i)) for i in range(30)]
    dense = [ptr(CLIENT, f"10.30.4.{i}", ts=T0 + timedelta(hours=1, seconds=i)) for i in range(64)]
    _pb, out = run(dns.DnsReverseLookupSweep, scattered + dense)
    names = [e.get("dns.question.name") for e in out[0].events]
    assert sum(1 for n in names if n.endswith(".4.30.10.in-addr.arpa")) >= 10


# ================================================================ tunnel high gate and prevalence
def test_strong_types_on_the_bare_domain_do_not_raise_a_txt_shape_to_high():
    events = tunnel(400, domain="hashrep.test", types=("TXT",), label=40)
    events += [rec(name="hashrep.test", qtype="MX", ts=T0 + timedelta(seconds=i)) for i in range(20)]
    events += [rec(name=f"mail{i}.hashrep.test", qtype="MX") for i in range(20)]
    _pb, out = run(dns.DnsTunnelShape, events)
    assert [m.proposed_lane for m in out] == ["lead"]


def test_mixed_txt_and_strong_type_long_names_are_high_and_cite_strong_questions():
    events = tunnel(380, types=("TXT",), seed=8) + tunnel(40, types=("MX",), seed=9, start=T0 + timedelta(hours=2))
    _pb, out = run(dns.DnsTunnelShape, events)
    m = out[0]
    assert m.proposed_lane == "high"
    assert any(e.get("dns.question.type") == "MX" for e in m.events)
    assert "40 questions for long names are NULL, CNAME, MX or private-use types" in m.claim


def _md5_lookups(client, seed):
    return tunnel(60, domain="avvendor.test", types=("A",), label=32, client=client, seed=seed)


def test_shape_shared_by_many_clients_is_one_finding_per_domain():
    events = []
    for i in range(30):
        events += _md5_lookups(f"10.20.1.{i + 1}", seed=100 + i)
    events += [rec(client="10.20.2.1", name="www.avvendor.test")]           # queried, without the shape
    _pb, out = run(dns.DnsTunnelShape, events)
    assert len(out) == 1
    m = out[0]
    assert m.group_key == "*|avvendor.test" and m.proposed_lane == "lead"
    assert "30 of the 31 clients" in m.claim
    assert {e.get("source.ip") for e in m.events} == {f"10.20.1.{i + 1}" for i in range(30)}
    assert any("10.20.1.30" in note for note in m.notes)


def test_two_clients_with_the_shape_stay_separate_findings():
    events = _md5_lookups("10.20.1.1", 1) + _md5_lookups("10.20.1.2", 2)
    _pb, out = run(dns.DnsTunnelShape, events)
    assert sorted(m.group_key for m in out) == ["10.20.1.1|avvendor.test", "10.20.1.2|avvendor.test"]


def test_grouped_domain_keeps_the_highest_member_lane():
    events = _md5_lookups("10.20.1.1", 1) + _md5_lookups("10.20.1.2", 2)
    events += tunnel(400, domain="avvendor.test", types=("NULL",), alphabet=B32, client="10.20.1.3", seed=3)
    _pb, out = run(dns.DnsTunnelShape, events)
    assert [(m.group_key, m.proposed_lane) for m in out] == [("*|avvendor.test", "high")]
    assert "10.20.1.3" in out[0].claim


@pytest.mark.parametrize("seed", range(40))
def test_nxdomain_citations_always_fill_from_inside_the_peak(seed):
    rng = random.Random(seed)
    offsets = sorted(rng.uniform(0, 3600) for _ in range(rng.randint(60, 400)))
    events = [rec("answer", name=f"r{i}.example.test", rcode="NXDOMAIN", ts=T0 + timedelta(seconds=s))
              for i, s in enumerate(offsets)]
    pb = dns.DnsNxdomainBurst()
    pb.consume(events)
    staged = {event.id: event for event in pb.drain_staged()}
    pb.bind_loader(lambda ids: [staged[event_id] for event_id in ids if event_id in staged])
    peak, start = pb._peak(list(pb.times[CLIENT]))
    out = pb.finalize()
    if peak < pb.MIN_BURST:
        assert out == []
        return
    window = pb.WINDOW // timedelta(microseconds=1)
    cited = [dns._micros(e.ts) for e in out[0].events]
    assert len([c for c in cited if start <= c < start + window]) >= 20
