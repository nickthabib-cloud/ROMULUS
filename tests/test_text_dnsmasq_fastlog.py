"""dnsmasq query logs and Suricata fast.log alerts as typed `dns_query` and `net_alert` records.

Formats follow the public sources: dnsmasq src/cache.c `log_query` and the `--log-queries` man page section
(https://github.com/imp/dnsmasq/blob/master/src/cache.c, https://thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html), and
Suricata src/alert-fastlog.c `AlertFastLogger` (https://github.com/OISF/suricata/blob/master/src/alert-fastlog.c).
Every line below is synthetic.
"""
from __future__ import annotations

from datetime import timedelta

import pytest

from romulus.evidence.linux_service_text import identify_service, parse_service
from romulus.evidence.linux_text import classify, inline_time
from romulus.evidence.normalize import normalize_hits
from tests import throughput_fixture as tf
from tests.test_dataset_reconciliation import FILEBEAT_TYPES, _profile

FAST = ("11/18/2024-14:00:03.123456  [**] [1:2010935:3] ET POLICY Suspicious inbound to MSSQL port 1433 [**] "
        "[Classification: Potentially Bad Traffic] [Priority: 2] {TCP} 203.0.113.9:4444 -> 10.0.0.10:1433")


def _fast(**parts):
    values = {"time": "11/18/2024-14:00:03.123456", "action": "", "sig": "1:2010935:3", "msg": "ET TEST alert",
              "cls": "Attempted Administrator Privilege Gain", "prio": "1", "proto": "TCP",
              "src": "203.0.113.9:4444", "dst": "10.0.0.10:80", **parts}
    return (f"{values['time']}  {values['action']}[**] [{values['sig']}] {values['msg']} [**] "
            f"[Classification: {values['cls']}] [Priority: {values['prio']}] {{{values['proto']}}} "
            f"{values['src']} -> {values['dst']}")


def _typed(line, dataset="suricata-fast.log"):
    hit = {"_index": "i", "_id": "r1", "_source": {"@timestamp": "2024-11-18T14:00:00Z", "message": line,
                                                   "event": {"dataset": dataset}, "host": {"name": "ids1"},
                                                   "input": {"type": "log"}}}
    events, skips, errors = normalize_hits([hit])
    assert not errors
    return events, skips


# ------------------------------------------------------------------------------------------------ fast.log contract
def test_fast_line_types_every_alert_field_the_alert_rules_read():
    [event], skips = _typed(FAST)
    assert not skips and event.family == "net_alert"
    values = {name: field.value for name, field in event.fields.items()}
    assert {key: values[key] for key in (
        "alert.signature", "alert.signature_id", "alert.gid", "alert.rev", "alert.category", "alert.severity",
        "alert.action", "source.ip", "source.port", "destination.ip", "destination.port", "network.transport")} == {
        "alert.signature": "ET POLICY Suspicious inbound to MSSQL port 1433", "alert.signature_id": 2010935,
        "alert.gid": 1, "alert.rev": 3, "alert.category": "Potentially Bad Traffic", "alert.severity": 2,
        "alert.action": "allowed", "source.ip": "203.0.113.9", "source.port": 4444, "destination.ip": "10.0.0.10",
        "destination.port": 1433, "network.transport": "tcp"}
    # integers exactly as EVE types them: the correlation tests `type(severity) is int`
    assert type(values["alert.severity"]) is int and type(values["alert.signature_id"]) is int
    assert values["network.community_id"].startswith("1:")
    assert event.fields["network.community_id"].origin.endswith("#computed:community_id_v1")
    assert "alert.provider" not in values          # the Suricata alert rules read it; Zeek's set it
    assert values["log.inline_timestamp"] == "11/18/2024-14:00:03.123456"
    assert event.ts.isoformat() == "2024-11-18T14:00:00+00:00"       # the indexed time stays the event time
    assert any("fast.log alert line" in caveat for caveat in event.caveats)
    assert ("host", "ids1", "observer") in event.entities()       # the sensor is an observer, never an endpoint


def test_fast_alert_equals_the_eve_alert_on_every_field_the_alert_rules_read():
    import json

    eve = {"timestamp": "2024-11-18T14:00:03.123456+0000", "event_type": "alert", "src_ip": "203.0.113.9",
           "src_port": 4444, "dest_ip": "10.0.0.10", "dest_port": 1433, "proto": "TCP",
           "alert": {"action": "allowed", "gid": 1, "signature_id": 2010935, "rev": 3,
                     "signature": "ET POLICY Suspicious inbound to MSSQL port 1433",
                     "category": "Potentially Bad Traffic", "severity": 2}}
    hit = {"_index": "i", "_id": "e1", "_source": {"@timestamp": "2024-11-18T14:00:03Z", "message": json.dumps(eve),
                                                   "event": {"dataset": "suricata.eve.alert"}}}
    [from_eve], skips, errors = normalize_hits([hit])
    assert not skips and not errors and from_eve.family == "net_alert"
    [from_fast], _skips = _typed(FAST)
    read = ("alert.signature", "alert.signature_id", "alert.category", "alert.severity", "alert.action",
            "source.ip", "source.port", "destination.ip", "destination.port", "network.transport",
            "network.community_id")
    assert {name: from_fast.get(name) for name in read} == {name: from_eve.get(name) for name in read}


@pytest.mark.parametrize("parts,expected", [
    ({"action": "[Drop] "}, {"alert.action": "blocked"}),
    ({"action": "[wDrop] "}, {"alert.action": "allowed"}),
    ({"proto": "UDP", "dst": "10.0.0.10:53"}, {"network.transport": "udp", "destination.port": 53}),
    ({"proto": "ICMP", "src": "203.0.113.9:8", "dst": "10.0.0.10:0"},
     {"network.transport": "icmp", "icmp.type": 8, "icmp.code": 0}),
    # util-proto-name.c names protocol 58 "IPv6-ICMP"; PrintInetIPv6 writes the full, uncompressed form
    ({"proto": "IPv6-ICMP", "src": "2001:0db8:0000:0000:0000:0000:0000:0009:128",
      "dst": "2001:0db8:0000:0000:0000:0000:0000:0010:0"},
     {"source.ip": "2001:db8::9", "destination.ip": "2001:db8::10", "icmp.type": 128,
      "network.transport": "ipv6-icmp"}),
    ({"src": "2001:db8::9:4444", "dst": "2001:db8::10:443"},
     {"source.ip": "2001:db8::9", "source.port": 4444, "destination.port": 443}),
    ({"proto": "PROTO:047", "src": "203.0.113.9:0", "dst": "10.0.0.10:0"}, {"network.iana_number": "47"}),
    ({"msg": "ET MALWARE odd [**] text [Classification: x] in msg"},
     {"alert.signature": "ET MALWARE odd [**] text [Classification: x] in msg"}),
])
def test_fast_line_forms(parts, expected):
    parsed = parse_service(*identify_service(_fast(**parts)))
    assert parsed is not None and parsed.family == "net_alert"
    assert {key: parsed.fields.get(key) for key in expected} == expected
    if parts.get("proto") in ("ICMP", "IPv6-ICMP", "PROTO:047"):
        assert "network.community_id" not in parsed.fields and (
            "source.port" not in parsed.fields or parts["proto"] == "PROTO:047")


def test_missing_classification_is_absent_not_invented():
    parsed = parse_service(*identify_service(_fast(cls="(null)")))
    assert "alert.category" not in parsed.fields and parsed.fields["alert.severity"] == 1


@pytest.mark.parametrize("line", [
    _fast(src="999.1.1.1:4444"),                  # not an address
    _fast(dst="10.0.0.10:70000"),                 # not a port
    _fast(msg=""),                                # no message
])
def test_malformed_fast_lines_are_counted_skips_with_a_reason(line):
    events, skips = _typed(line)
    assert not events
    assert skips == {"text format application, program 'suricata-fastlog' is not normalized: suricata-fast.log": 1}


def test_decoder_event_line_without_addresses_is_an_unknown_line_skip():
    line = ("11/18/2024-14:00:03.123456  [**] [1:2200003:2] SURICATA IPv4 truncated packet [**] "
            "[Classification: Generic Protocol Command Decode] [Priority: 3] [**] [Raw pkt: 45 00 00 ]")
    events, skips = _typed(line)
    assert not events and skips == {"text line in no recognized format: suricata-fast.log": 1}


@pytest.mark.parametrize("line", [
    # an analyst grepping the alert log: the grep is the action, not an alert
    "Nov 18 14:00:05 analyst1 bash[812]: grep '[**] [1:2010935:3]' /var/log/suricata/fast.log",
    # an alert line echoed into another program's syslog record: a mention, not the sensor's alert
    "Nov 18 14:00:05 web1 logger: " + FAST,
    # the documented format quoted in prose
    "Nov 18 14:00:05 web1 docs[9]: fast.log lines look like [**] [gid:sid:rev] msg [**] [Priority: N]",
])
def test_fast_line_mentions_are_never_alerts(line):
    events, _skips = _typed(line, dataset="custom.log")
    assert not [event for event in events if event.family == "net_alert"]


def test_fast_time_is_a_diagnostic_inline_time():
    parsed = classify(FAST)
    assert parsed.format == "application" and parsed.program == "suricata-fastlog"
    assert parsed.timestamp == "11/18/2024-14:00:03.123456"
    from datetime import UTC, datetime
    clock = inline_time(parsed.timestamp, datetime(2024, 11, 18, 14, 0, tzinfo=UTC))
    assert clock == datetime(2024, 11, 18, 14, 0, 3, 123456, tzinfo=UTC)


# ------------------------------------------------------------------------------------------------ dnsmasq contract
@pytest.mark.parametrize("message,expected", [
    ("query[A] update.example from 10.0.0.5",
     {"dns.type": "query", "dns.question.type": "A", "source.ip": "10.0.0.5"}),
    ("query[type=65] update.example from 10.0.0.5", {"dns.question.type": "TYPE65"}),
    ("77 10.0.0.5/53111 query[A] update.example from 10.0.0.5",
     {"dnsmasq.serial": 77, "source.ip": "10.0.0.5", "source.port": 53111}),
    ("TCP 78 10.0.0.5/53112 query[TXT] t.example from 10.0.0.5",
     {"dnsmasq.serial": 78, "network.transport": "tcp", "dns.question.type": "TXT"}),
    ("77 10.0.0.5/53111 forwarded update.example to 192.0.2.53#5353",
     {"dns.type": "query", "destination.ip": "192.0.2.53", "destination.port": 5353, "client.ip": None,
      "dnsmasq.requester.ip": "10.0.0.5"}),
    ("77 10.0.0.5/53111 reply update.example is 203.0.113.9",
     {"dns.type": "answer", "client.ip": "10.0.0.5", "client.port": 53111}),
    ("reply update.example is NODATA-IPv4", {"dns.response_code": "NOERROR"}),
    ("reply update.example is NODATA-IPv6", {"dns.response_code": "NOERROR"}),
    ("reply update.example is not implemented", {"dns.response_code": "NOTIMP"}),
    ("reply update.example is SERVFAIL (EDE: DNSSEC bogus)", {"dns.response_code": "SERVFAIL"}),
    ("reply update.example is <SRV>", {"dns.type": "answer"}),
    ("cached-stale update.example is 192.0.2.7", {"dns.type": "answer"}),
    ("/etc/hosts printer.lan is 10.0.0.30", {"dns.type": "answer"}),
    ("DHCP laptop.lan is 10.0.0.31", {"dns.type": "answer"}),
])
def test_dnsmasq_lines(message, expected):
    parsed = parse_service("dnsmasq", message)
    assert parsed is not None and parsed.family == "dns_query"
    assert {key: parsed.fields.get(key) for key in expected} == expected


@pytest.mark.parametrize("message", [
    "77 not-an-ip/53111 query[A] update.example from 10.0.0.5",      # malformed requester
    "query[A] update.example from somewhere",                         # client is not an address
    "reply update.example is something-else",                         # not a documented answer
    "started, version 2.90 cachesize 150",                            # a lifecycle line, no query
    "using nameserver 192.0.2.53#53",
])
def test_dnsmasq_other_lines_are_not_typed(message):
    assert parse_service("dnsmasq", message) is None


# ------------------------------------------------------------------------------------------------ end to end
def _e2e_docs():
    builder = tf.Builder(11)
    n = 0

    def add(dataset, line, when=None):
        nonlocal n
        n += 1
        builder._doc("fw1" if dataset == "suricata-fast.log" else "web1", when or tf.T0 + timedelta(seconds=n),
                     dataset, None, message=line, input={"type": "log"},
                     log={"file": {"path": f"/var/log/{dataset}"}})

    for port in (4444, 4445, 4446):
        add("suricata-fast.log", _fast(src=f"203.0.113.9:{port}", dst="10.0.0.10:80", prio="1"))
    # half-open window: an alert at the window end is outside it, one at the window start inside it
    add("suricata-fast.log", _fast(msg="ET TEST at the end", dst="10.0.0.20:80"), when=tf.WINDOW_END)
    add("suricata-fast.log", _fast(msg="ET TEST at the start", dst="10.0.0.20:80"), when=tf.WINDOW_START)
    for octet in range(1, 40):
        add("dnsmasq.log", f"Nov 18 14:00:00 dnsmasq[123]: query[PTR] {octet}.0.0.10.in-addr.arpa from 10.0.0.5")
    add("dnsmasq.log", "Nov 18 14:00:00 dnsmasq[123]: reply 1.0.0.10.in-addr.arpa is NXDOMAIN")
    add("dnsmasq.log", "Nov 18 14:00:00 dnsmasq[123]: forwarded 1.0.0.10.in-addr.arpa to 192.0.2.53")
    # a wordlist run against one domain from one client: the subdomain enumeration rule's positive
    for index in range(120):
        add("dnsmasq.log", f"Nov 18 14:00:01 dnsmasq[123]: query[A] w{index:03d}.target.example from 10.0.0.6")
    return {tf.HOST_TARGET: builder.host, tf.NETWORK_TARGET: [], tf.ARKIME_TARGET: []}


def test_fast_and_dnsmasq_records_reach_the_alert_and_dns_rules_through_the_sweep(tmp_path, monkeypatch):
    docs = _e2e_docs()
    in_window = [row for row in docs[tf.HOST_TARGET]
                 if row["_source"]["@timestamp"] != tf._iso(tf.WINDOW_END)]
    lines: dict[str, list[str]] = {}
    for row in in_window:
        lines.setdefault(row["_source"]["event"]["dataset"], []).append(row["_source"]["message"])
    with monkeypatch.context() as patch:
        tf.patched_sizes(patch)
        patch.setattr(tf, "HOST_TYPES", FILEBEAT_TYPES)
        snapshot = tf.run_stack(tmp_path, docs=docs, profiles={tf.HOST_TARGET: _profile(FILEBEAT_TYPES, lines)})
    stats = snapshot["stats"]
    assert stats["records"] == len(in_window)                   # the window-end alert is outside the window
    assert stats["linux_shapes"][tf.HOST_TARGET] == {"linux.text:dnsmasq.log": 161,
                                                     "linux.text:suricata-fast.log": 4}
    # Per DNS rule on dnsmasq lines (the host target's partition cell): question rules read every query line
    # (client and name); the forwarded line (dnsmasq's own upstream query) and the reply line (no client by port,
    # no flow) are counted missing, never a clean negative. The zone-transfer rule reads the logging host as the
    # server of each query line. Without log-queries=extra a reply line names no requester, so the NXDOMAIN rule
    # cannot attribute it to a client.
    host = {row["rule_id"]: row for row in snapshot["rule_cells"]
            if row["target"] == tf.HOST_TARGET and row["rule_id"].startswith("net.dns_")}
    expected = {"net.dns_reverse_lookup_sweep": (159, 2), "net.dns_tunnel_shape": (159, 2),
                "net.dns_zone_transfer_or_any_request": (159, 2), "net.dns_nxdomain_burst": (0, 1)}
    from romulus.detect.dns import DnsNxdomainBurst
    assert DnsNxdomainBurst.WHY["unoriented"] in host["net.dns_nxdomain_burst"]["detail"]["reasons"]
    for rule, (evaluated, missing) in expected.items():
        assert host[rule]["state"] == "evaluated_partial"
        assert (host[rule]["evaluated"], host[rule]["detail"]["missing_required"]) == (evaluated, missing)
    found = {row["rule_id"] for row in snapshot["candidates"]}
    assert {"net.dns_subdomain_enumeration", "net.dns_reverse_lookup_sweep"} <= found
    enumeration = next(row for row in snapshot["candidates"] if row["rule_id"] == "net.dns_subdomain_enumeration")
    assert "10.0.0.6" in enumeration["claim"] and "target.example" in enumeration["claim"]
    assert not stats["skips"] and "dataset_reconciliation" not in stats
    alerts = [row for row in snapshot["candidates"] if row["rule_id"] == "net.suricata_alert_stack"]
    assert {(row["lane"]) for row in alerts} == {"high"}               # priority 1 alerts, as from EVE
    claims = " ".join(row["claim"] for row in alerts)
    assert "203.0.113.9 to 10.0.0.10" in claims and "ET TEST at the start" in claims
    assert "ET TEST at the end" not in claims
    cells = {(row["rule_id"], row["target"]): row for row in snapshot["rule_cells"] if row["partition"] == "window"}
    assert cells[("net.dns_reverse_lookup_sweep", "*")]["evaluated"] == 159  # every question line; reply and forward are not
    assert cells[("corr.alert_then_host_execution", "*")]["state"] != "not_applicable_no_events"
