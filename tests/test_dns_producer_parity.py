"""Every rule that reads `dns_query`, on the same DNS behaviour as Zeek, Suricata EVE and dnsmasq record it.

Each behaviour is built once as DNS transactions (tests/test_zeek_twins.py `dns_transaction`) and written three ways:
Zeek's dns.log row, Suricata's query and answer records, and the lines dnsmasq writes for the same lookup (src/cache.c
`log_query`: the query line, the forwarded line, then one reply line per answer record, so an answer with two
addresses is two lines), both without and with `--log-queries=extra` (a serial and the requester on every line).

A rule must report the same items (group key, lane, severity) on every producer, or a case states exactly why a
producer cannot show the behaviour. The rule's counts must count one client query once, whatever number of lines
dnsmasq wrote for it. All names and addresses are synthetic; tool volumes follow the tools' public descriptions
(iodine: NULL questions with labels filled toward 63 characters; dnscat2: hex-encoded TXT/CNAME/MX questions;
DNSteal: A questions carrying hex-encoded file data in several long labels).
"""
from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime, timedelta

import pytest

from romulus.detect.dns import (
    DnsNxdomainBurst,
    DnsReverseLookupSweep,
    DnsTunnelShape,
    DnsZoneTransferOrAnyRequest,
)
from romulus.detect.indicators import IndicatorMatch
from romulus.detect.network import DnsSubdomainEnumeration
from romulus.evidence.normalize import normalize_hits
from tests.test_zeek_twins import (
    CLIENT,
    LISTED,
    PUBLIC,
    RESOLVER,
    dns_transaction,
    dns_twins,
    items,
    run_rule,
)

DNS_HOST = "dns1"
UPSTREAM = "192.0.2.53"
PRODUCERS = ("zeek", "suricata", "dnsmasq", "dnsmasq-extra")


def dnsmasq_lines(transactions, extra: bool) -> list[tuple[float, str]]:
    """(time, message) of the lines dnsmasq writes for each transaction, in order."""
    out = []
    for serial, (row, _pair) in enumerate(transactions, start=1):
        z = row.zeek
        name, qtype, rcode = z["query"], z["qtype_name"], z["rcode_name"]
        client, port = z["id.orig_h"], z["id.orig_p"]
        prefix = f"{serial} {client}/{port} " if extra else ""
        lines = [f"query[{qtype}] {name} from {client}", f"forwarded {name} to {UPSTREAM}"]
        if rcode == "NOERROR":
            # one line per answer record: two addresses are two lines of one reply
            lines += [f"reply {name} is 203.0.113.{k}" for k in (1, 2)]
        else:
            lines.append(f"reply {name} is {rcode}")
        out += [(row.ts, prefix + line) for line in lines]
    return out


def dnsmasq_hits(lines, host=DNS_HOST, dataset="dnsmasq.log"):
    hits = []
    for n, (ts, message) in enumerate(lines):
        when = datetime(1970, 1, 1, tzinfo=UTC) + timedelta(seconds=ts)
        hits.append({"_index": "logs-dnsmasq", "_id": f"m{n}", "_source": {
            "@timestamp": when.isoformat().replace("+00:00", "Z"),
            "message": f"{when.strftime('%b %d %H:%M:%S')} dnsmasq[812]: {message}",
            "event": {"dataset": dataset}, "host": {"name": host}, "input": {"type": "log"}}})
    return hits


def dnsmasq_events(transactions, extra: bool):
    events, skips, errors = normalize_hits(dnsmasq_hits(dnsmasq_lines(transactions, extra)))
    assert not errors and not skips, (skips, errors)
    return events


def produced(transactions) -> dict[str, list]:
    zeek, suricata = dns_twins(transactions, "malcolm")
    return {"zeek": zeek, "suricata": suricata, "dnsmasq": dnsmasq_events(transactions, False),
            "dnsmasq-extra": dnsmasq_events(transactions, True)}


def evaluate(rule_factory, events):
    rule = rule_factory()
    return rule, run_rule(rule, events)


# ---- behaviours ------------------------------------------------------------------------------------------------------

def enumeration():
    return [dns_transaction(i, f"w{i:03d}.corp-example.test", rcode="NXDOMAIN") for i in range(120)]


def reverse_sweep():
    return [dns_transaction(i, f"{i}.1.168.192.in-addr.arpa", "PTR", "NXDOMAIN") for i in range(1, 121)]


def nxdomain_burst():
    return [dns_transaction(i, f"q{hashlib.md5(str(i).encode()).hexdigest()[:12]}.example.org", rcode="NXDOMAIN")
            for i in range(80)]


def b32(seed: str, length: int) -> str:
    return base64.b32encode(hashlib.sha512(seed.encode()).digest()).decode().lower().rstrip("=")[:length]


def iodine_like(count=2000):
    """NULL questions, base32 data filled toward the 63-character label limit, under one delegated zone."""
    return [dns_transaction(i, f"{b32(f'iodine-{i}', 60)}.{b32(f'iodine-b-{i}', 40)}.t.iodine-example.net", "NULL",
                            server=PUBLIC, seconds=0.05)
            for i in range(count)]


def dnscat_like(count=1000):
    """Hex-encoded session data in TXT, CNAME and MX questions."""
    kinds = ("TXT", "CNAME", "MX")
    return [dns_transaction(i, f"{hashlib.sha256(f'dnscat-{i}'.encode()).hexdigest()[:62]}.c2-example.org",
                            kinds[i % 3], server=PUBLIC, seconds=0.2)
            for i in range(count)]


def dnsteal_like(count=500):
    """Hex file data split over several long labels in A questions (the tool's default query shape)."""
    names = []
    for i in range(count):
        data = hashlib.sha512(f"dnsteal-{i}".encode()).hexdigest()
        names.append(f"{data[:57]}.{data[57:114]}.{i:05d}.exfil-example.com")
    return [dns_transaction(i, name, rcode="NOERROR", server=PUBLIC, seconds=0.5) for i, name in enumerate(names)]


def zone_requests():
    return [dns_transaction(1, "corp-example.test", "AXFR", "REFUSED"),
            dns_transaction(2, "corp-example.test", "ANY", "NOERROR")]


SENSOR_ITEMS = {
    "enumeration": [("net.dns_subdomain_enumeration", f"{CLIENT}|corp-example.test", "lead", "medium")],
    "reverse": [("net.dns_reverse_lookup_sweep", CLIENT, "lead", "medium")],
    "nxdomain": [("net.dns_nxdomain_burst", CLIENT, "lead", "high")],
}
CASES = {"enumeration": (DnsSubdomainEnumeration, enumeration), "reverse": (DnsReverseLookupSweep, reverse_sweep),
         "nxdomain": (DnsNxdomainBurst, nxdomain_burst)}


@pytest.mark.parametrize("behaviour", sorted(CASES))
@pytest.mark.parametrize("producer", PRODUCERS)
def test_question_and_reply_rules_report_the_same_items_on_every_producer(behaviour, producer):
    rule_factory, build = CASES[behaviour]
    rule, found = evaluate(rule_factory, produced(build())[producer])
    if behaviour == "nxdomain" and producer == "dnsmasq":
        # Without log-queries=extra a reply line names no requester and no port tells the roles: the rule cannot
        # attribute an answer to a client, so every reply line is counted missing (partial, never a negative).
        assert found == [] and rule.evaluated == 0 and rule.missing_required == 80
        assert rule.partition_coverage_notes() == [DnsNxdomainBurst.WHY["unoriented"]]
        assert rule.coverage_notes() == [DnsNxdomainBurst.WHY["unoriented"]]
        return
    assert items(found) == SENSOR_ITEMS[behaviour]


TUNNELS = {"iodine": (iodine_like, "iodine-example.net", 2000, "high"),
           "dnscat2": (dnscat_like, "c2-example.org", 1000, "high"),
           "dnsteal": (dnsteal_like, "exfil-example.com", 500, "lead")}


@pytest.mark.parametrize("tool", sorted(TUNNELS))
def test_tool_volume_tunnels_fire_alike_and_count_each_question_once(tool):
    build, domain, count, lane = TUNNELS[tool]
    transactions = build()
    claims = {}
    for producer, events in produced(transactions).items():
        _rule, found = evaluate(DnsTunnelShape, events)
        assert items(found) == [("net.dns_tunnel_shape", f"{CLIENT}|{domain}", lane, "high")], producer
        claims[producer] = found[0].claim
        # one question per client query: the forwarded and reply lines dnsmasq writes for it are not questions
        assert f"sent {count} DNS question(s) for {count} distinct subdomain(s)" in found[0].claim, producer
    assert "volume" in claims["dnsmasq"] and "volume" in claims["zeek"]


def test_zone_transfer_and_any_on_dnsmasq_name_the_logging_host_as_the_server():
    by_producer = {producer: evaluate(DnsZoneTransferOrAnyRequest, events)
                   for producer, events in produced(zone_requests()).items()}
    sensor = sorted(("net.dns_zone_transfer_or_any_request", f"{CLIENT}|{RESOLVER}|{zone}", "lead", "medium")
                    for zone in ("ANY", "corp-example.test"))
    assert items(by_producer["zeek"][1]) == items(by_producer["suricata"][1]) == sensor
    # dnsmasq's log names no address of its own: the server is its host, which never takes the high lane (that
    # needs an internal server address)
    host = sorted(("net.dns_zone_transfer_or_any_request", f"{CLIENT}|host {DNS_HOST}|{zone}", "lead", "medium")
                  for zone in ("ANY", "corp-example.test"))
    for producer in ("dnsmasq", "dnsmasq-extra"):
        rule, found = by_producer[producer]
        assert items(found) == host
        transfer = next(m for m in found if m.group_key.endswith("corp-example.test"))
        assert "sent 1 DNS question record(s) (AXFR x1)" in transfer.claim
        # dnsmasq's own log file has no syslog header: the host that shipped it is the server, and the claim says so
        assert "The server is the host that shipped the log" in transfer.claim
        assert "was retrieved" not in transfer.claim
        # the forwarded and reply lines (no question type) are counted missing, not read as questions, and say why
        assert rule.evaluated == 2
        why = DnsZoneTransferOrAnyRequest.WHY
        assert set(rule.partition_coverage_notes()) == {
            why["forwarded"], why["untyped_answer"] if producer == "dnsmasq-extra" else why["unoriented"]}


@pytest.mark.parametrize("line,server,words", [
    # a syslog-wrapped line: its header names the resolver host, not the collector that shipped it
    ("Nov 18 14:00:01 dns1 dnsmasq[812]: query[AXFR] corp-example.test from 10.20.0.15", "host dns1",
     "the host named in the log line's syslog header"),
    # dnsmasq's own file names no host: the collector that shipped it is all the record says
    ("Nov 18 14:00:01 dnsmasq[812]: query[AXFR] corp-example.test from 10.20.0.15", "host log-collector-01",
     "the host that shipped the log"),
])
def test_a_collector_shipped_resolver_log_names_the_server_from_the_line_header(line, server, words):
    hit = {"_index": "i", "_id": "c1", "_source": {
        "@timestamp": "2024-11-18T14:00:01Z", "message": line, "event": {"dataset": "dnsmasq.log"},
        "host": {"name": "log-collector-01"}, "input": {"type": "log"}}}
    events, skips, errors = normalize_hits([hit])
    assert not skips and not errors
    _rule, [match] = evaluate(DnsZoneTransferOrAnyRequest, events)
    assert match.group_key == f"{CLIENT}|{server}|corp-example.test"
    assert f"to {server} " in match.claim and f"The server is {words}" in match.claim
    assert match.proposed_lane == "lead"


def test_an_external_axfr_logged_by_dnsmasq_stays_a_lead():
    row, _hits = dns_transaction(1, "corp-example.test", "AXFR", "NOERROR", client=PUBLIC)
    for extra in (False, True):
        _rule, [match] = evaluate(DnsZoneTransferOrAnyRequest, dnsmasq_events([(row, None)], extra))
        assert match.proposed_lane == "lead" and match.group_key == f"{PUBLIC}|host {DNS_HOST}|corp-example.test"


def test_nxdomain_counts_one_answer_per_query_and_states_unrecorded_rcodes():
    """80 NXDOMAIN and 20 NOERROR lookups (each NOERROR reply is two address lines). Zeek counts 100 answers with an
    rcode; dnsmasq's NXDOMAIN lines are one per query (80), and its address lines carry no reply code, so they are
    counted missing rather than read as 40 more answers."""
    transactions = [dns_transaction(i, f"n{i:03d}.example.org", rcode="NXDOMAIN" if i < 80 else "NOERROR")
                    for i in range(100)]
    events = produced(transactions)
    _rule, zeek = evaluate(DnsNxdomainBurst, events["zeek"])
    rule, extra = evaluate(DnsNxdomainBurst, events["dnsmasq-extra"])
    assert items(zeek) == items(extra) == SENSOR_ITEMS["nxdomain"]
    assert "was sent 80 NXDOMAIN answer(s) (80% of the 100" in zeek[0].claim
    assert "was sent 80 NXDOMAIN answer(s) (100% of the 80" in extra[0].claim
    assert (rule.evaluated, rule.missing_required) == (80, 40)


def test_nxdomain_reads_the_requester_only_from_answer_lines():
    """A forwarded line in extra mode names the requester, but it is dnsmasq's own upstream question: never a
    second question from that client."""
    [forward] = [e for e in dnsmasq_events(nxdomain_burst()[:1], True) if e.get("destination.ip") == UPSTREAM]
    assert forward.get("client.ip") is None and forward.get("dnsmasq.requester.ip") == CLIENT
    _rule, found = evaluate(DnsSubdomainEnumeration, dnsmasq_events(enumeration(), True))
    assert f"{CLIENT} issued 120 DNS queries" in found[0].claim


def test_service_catalog_reports_the_same_items_on_every_producer():
    from romulus.detect.netdef import SiteNetworks, current, install
    from romulus.detect.service_catalog import ServiceCatalog

    previous = current()
    install(SiteNetworks.from_lists(["10.0.0.0/8"]))
    try:
        found = {}
        for producer, events in produced([dns_transaction(1, "abc.ngrok-free.app", server=PUBLIC)]).items():
            rule = ServiceCatalog()
            found[producer] = (tuple(items([*rule.consume(events), *rule.finalize()])), rule.evaluated)
            rule.release_state()
    finally:
        install(previous)
    assert len({matches for matches, _n in found.values()}) == 1 and found["zeek"][0]
    # one question record each, except Suricata's query and answer (both carry the client and the name)
    assert {producer: n for producer, (_m, n) in found.items()} == {"zeek": 1, "suricata": 2, "dnsmasq": 1,
                                                                    "dnsmasq-extra": 1}


def test_indicator_matches_count_records_as_each_producer_writes_them():
    row, hits = dns_transaction(1, "www.listed-example.net", answers=(("A", "192.0.2.9", 60),))
    groups = {}
    for producer, events in produced([(row, hits)]).items():
        _rule, [match] = evaluate(lambda: IndicatorMatch(LISTED), events)
        indicator, kind, _observer, value = match.group_key.split("|")
        groups[producer] = ((indicator, kind, value), match.proposed_lane, match.claim.split(" ")[0])
    # one Zeek row, Suricata's query and answer, dnsmasq's query, forwarded and two reply lines
    assert {p: g[2] for p, g in groups.items()} == {"zeek": "1", "suricata": "2", "dnsmasq": "4", "dnsmasq-extra": "4"}
    assert len({(g[0], g[1]) for g in groups.values()}) == 1


# ---- the dnsmasq grammar: lookalikes, reverse answers, authoritative questions, DHCP and named skips -----------------

def typed(lines, dataset="dnsmasq.log", program="dnsmasq"):
    hits = [{"_index": "i", "_id": f"r{n}", "_source": {
        "@timestamp": "2024-11-18T14:00:00Z",
        "message": line if line.startswith("Nov ") else f"Nov 18 14:00:00 {program}[812]: {line}",
        "event": {"dataset": dataset}, "host": {"name": DNS_HOST}, "input": {"type": "log"}}}
        for n, line in enumerate(lines)]
    events, skips, errors = normalize_hits(hits)
    assert not errors
    return events, skips


@pytest.mark.parametrize("line", [
    # an analyst searching the resolver log: the search is the action
    "Nov 18 14:00:05 analyst1 bash[812]: grep 'query[AXFR]' /var/log/dnsmasq.log",
    # a dnsmasq line echoed through logger by another program: a mention, not the resolver's record
    "Nov 18 14:00:05 web1 logger: dnsmasq[812]: query[AXFR] corp-example.test from 203.0.113.77",
    # the documented format quoted in a SIEM query
    "Nov 18 14:00:05 siem1 kibana[77]: message:\"query[ANY]\" AND message:\"from 10.20.0.15\"",
])
def test_dnsmasq_mentions_are_never_dns_questions(line):
    events, _skips = typed([line], dataset="custom.log")
    assert not [event for event in events if event.family == "dns_query"]


def test_a_reverse_answer_names_the_reverse_lookup_name_never_the_address():
    events, skips = typed(["reply 10.0.0.5 is host5.lan", "cached 10.0.0.6 is NXDOMAIN",
                           "77 10.20.0.15/40001 DHCP 10.0.0.31 is laptop.lan"])
    assert not skips
    first, second, third = events
    assert first.get("dns.question.name") == "5.0.0.10.in-addr.arpa"
    assert first.get("dns.answers") == [{"name": "5.0.0.10.in-addr.arpa", "type": "PTR", "ttl": None,
                                         "data": "host5.lan"}]
    assert second.get("dns.question.name") == "6.0.0.10.in-addr.arpa"
    assert second.get("dns.response_code") == "NXDOMAIN"
    assert third.get("client.ip") == CLIENT and third.get("dns.question.name") == "31.0.0.10.in-addr.arpa"
    assert all(any("Reverse-lookup answer" in c for c in e.caveats) for e in events)


def test_numeric_rcode_and_authoritative_questions():
    events, skips = typed(["reply odd.example is 9", "auth[AXFR] corp-example.test from 203.0.113.77"])
    assert not skips
    assert events[0].get("dns.response_code") == "NOTAUTH"
    assert events[1].get("dns.question.type") == "AXFR" and events[1].get("dnsmasq.authoritative") is True
    assert events[1].get("dns.server_logged") is True


def test_dnsmasq_dhcpack_is_an_address_assignment_and_other_dhcp_lines_are_named_skips():
    events, skips = typed(["DHCPACK(eth0) 10.0.0.31 52:54:00:ab:cd:ef laptop",
                           "1234567 DHCPACK(eth0) 10.0.0.32 52:54:00:ab:cd:f0",
                           "DHCPREQUEST(eth0) 10.0.0.31 52:54:00:ab:cd:ef",
                           "DHCPDISCOVER(eth0) 52:54:00:ab:cd:ef",
                           "1234567 client provides name: laptop"], program="dnsmasq-dhcp")
    assert [e.family for e in events] == ["address_assignment", "address_assignment"]
    first, second = events
    assert {k: first.get(k) for k in ("dhcp.client_address", "dhcp.client_mac", "dhcp.hostname",
                                      "dhcp.message_type", "dhcp.interface")} == {
        "dhcp.client_address": "10.0.0.31", "dhcp.client_mac": "52:54:00:ab:cd:ef", "dhcp.hostname": "laptop",
        "dhcp.message_type": "DHCPACK", "dhcp.interface": "eth0"}
    assert second.get("dhcp.transaction_id") == 1234567 and second.get("dhcp.hostname") is None
    assert any("DHCPINFORM" in caveat for caveat in first.caveats)
    assert skips == {
        "text format application, program 'dnsmasq-dhcp' (dnsmasq DHCP packet line other than an IPv4 DHCPACK "
        "with a hardware address) is not normalized: dnsmasq.log": 2,
        "text format application, program 'dnsmasq-dhcp' (dnsmasq lifecycle, configuration or DHCP option detail "
        "line) is not normalized: dnsmasq.log": 1}


def test_a_syslog_wrapped_dhcpack_is_typed_without_a_writer_mismatch():
    hit = {"_index": "i", "_id": "s1", "_source": {
        "@timestamp": "2024-11-18T14:00:00Z", "event": {"dataset": "custom.syslog"}, "host": {"name": DNS_HOST},
        "message": "Nov 18 14:00:00 dns1 dnsmasq-dhcp[812]: DHCPACK(eth0) 10.0.0.31 52:54:00:ab:cd:ef laptop",
        "journald": {"process": {"name": "dnsmasq"}}, "input": {"type": "log"}}}
    [event], skips, errors = normalize_hits([hit])
    assert not skips and not errors and event.family == "address_assignment"
    assert event.get("dhcp.client_address") == "10.0.0.31"
    assert not any("Writer identity" in caveat for caveat in event.caveats)


@pytest.mark.parametrize("line,reason", [
    ("started, version 2.90 cachesize 150", "dnsmasq lifecycle, configuration or DHCP option detail line"),
    ("compile time options: IPv6 GNU-getopt DBus", "dnsmasq lifecycle, configuration or DHCP option detail line"),
    ("using nameserver 192.0.2.53#53", "dnsmasq lifecycle, configuration or DHCP option detail line"),
    ("read /etc/hosts - 7 names", "dnsmasq lifecycle, configuration or DHCP option detail line"),
    ("cache size 150, 0/1234 cache insertions re-used unexpired cache entries.",
     "dnsmasq statistics or resource line"),
    ("queries forwarded 1234, queries answered locally 567", "dnsmasq statistics or resource line"),
    ("Maximum number of concurrent DNS queries reached (max: 150)", "dnsmasq statistics or resource line"),
    ("validation example.com is SECURE", "dnsmasq DNSSEC, ipset or opcode line"),
    ("12 10.20.0.15/40001 dnssec-query[DS] example.com to 192.0.2.53", "dnsmasq DNSSEC, ipset or opcode line"),
    ("possible DNS-rebind attack detected: rebind.example", "dnsmasq resolver notice (no client address is logged)"),
])
def test_dnsmasq_non_query_lines_are_counted_skips_with_precise_reasons(line, reason):
    events, skips = typed([line])
    assert not events
    assert skips == {f"text format application, program 'dnsmasq' ({reason}) is not normalized: dnsmasq.log": 1}


def test_an_unknown_dnsmasq_message_keeps_the_generic_reason():
    events, skips = typed(["something new in a later release"])
    assert not events and skips == {"text format application, program 'dnsmasq' is not normalized: dnsmasq.log": 1}


# ---- through the sweep ----------------------------------------------------------------------------------------------

def test_dnsmasq_extra_lines_reach_every_dns_rule_through_the_sweep(tmp_path, monkeypatch):
    """Extra-mode lines on a Linux host target: the NXDOMAIN, zone-transfer, enumeration and tunnel rules report
    from them, with the host's partition cell partial (forwarded and address-reply lines are counted missing), and a
    line at the window end is outside the half-open window."""
    from tests import throughput_fixture as tf
    from tests.test_dataset_reconciliation import FILEBEAT_TYPES, _profile

    builder = tf.Builder(17)
    server = "web1"             # a host the fixture knows
    transactions = (nxdomain_burst() + zone_requests()
                    + [dns_transaction(1000 + i, f"{b32(f'sweep-{i}', 60)}.t.iodine-example.net", "NULL",
                                       server=PUBLIC) for i in range(60)])
    lines = dnsmasq_lines(transactions, True)
    for n, (_ts, message) in enumerate(lines):
        when = tf.T0 + timedelta(seconds=n)
        builder._doc(server, when, "dnsmasq.log", None, input={"type": "log"},
                     message=f"{when.strftime('%b %d %H:%M:%S')} dnsmasq[812]: {message}",
                     log={"file": {"path": "/var/log/dnsmasq.log"}})
    builder._doc(server, tf.WINDOW_END, "dnsmasq.log", None, input={"type": "log"},
                 message="Nov 18 17:30:00 dnsmasq[812]: 9999 10.20.0.15/40001 query[AXFR] late.example from 10.20.0.15",
                 log={"file": {"path": "/var/log/dnsmasq.log"}})
    docs = {tf.HOST_TARGET: builder.host, tf.NETWORK_TARGET: [], tf.ARKIME_TARGET: []}
    in_window = [row["_source"]["message"] for row in builder.host
                 if row["_source"]["@timestamp"] != tf._iso(tf.WINDOW_END)]
    with monkeypatch.context() as patch:
        tf.patched_sizes(patch)
        patch.setattr(tf, "HOST_TYPES", FILEBEAT_TYPES)
        snapshot = tf.run_stack(tmp_path, docs=docs,
                                profiles={tf.HOST_TARGET: _profile(FILEBEAT_TYPES, {"dnsmasq.log": in_window})})
    found = {(row["rule_id"], row["group_key"]) for row in snapshot["candidates"]}
    assert {("net.dns_nxdomain_burst", CLIENT),
            ("net.dns_zone_transfer_or_any_request", f"{CLIENT}|host {server}|corp-example.test"),
            ("net.dns_zone_transfer_or_any_request", f"{CLIENT}|host {server}|ANY"),
            ("net.dns_tunnel_shape", f"{CLIENT}|iodine-example.net")} <= found
    assert not any("late.example" in row["claim"] for row in snapshot["candidates"])
    cells = [row for row in snapshot["rule_cells"]
             if row["target"] == tf.HOST_TARGET and row["rule_id"].startswith("net.dns_")]
    # every partition cell is partial: forwarded and address-reply lines are counted missing, never a clean negative
    assert cells and all(row["state"] == "evaluated_partial" for row in cells)
    evaluated = {}
    for row in cells:
        evaluated[row["rule_id"]] = evaluated.get(row["rule_id"], 0) + row["evaluated"]
    # NXDOMAIN reads 80 NXDOMAIN lines and the REFUSED reply to the AXFR question; question rules read each of the
    # 142 query lines once
    assert evaluated["net.dns_nxdomain_burst"] == 81
    assert {rule: n for rule, n in evaluated.items() if rule != "net.dns_nxdomain_burst"} == dict.fromkeys(
        ("net.dns_subdomain_enumeration", "net.dns_zone_transfer_or_any_request", "net.dns_reverse_lookup_sweep",
         "net.dns_tunnel_shape"), 142)
