"""The existing DNS, TLS, SSH, HTTP, indicator and alert-stack rules, called directly, read Zeek analyzer records as they
read the Suricata EVE records of the same traffic.

Each case builds the same transactions twice: as Zeek rows (in a shipper layout) and as their Suricata EVE twins
(a DNS transaction is one Zeek row and a query plus an answer record in EVE). Both sensors are given one name, so a
rule must report the same items (group key, lane, severity) and say the same thing in them, apart from the record-kind
words. Where a rule reads the two differently because of something the rules or a record link must change, a case
asserts that divergence exactly and names the change, so the change cannot land unnoticed and an unrelated failure
cannot hide behind it.
"""
import base64
import hashlib
import json
import re
from datetime import UTC, datetime, timedelta

import pytest

from romulus.detect.dns import (
    DnsNxdomainBurst,
    DnsReverseLookupSweep,
    DnsTunnelShape,
    DnsZoneTransferOrAnyRequest,
)
from romulus.detect.indicators import Indicator, IndicatorMatch, IndicatorSet
from romulus.detect.network import DnsSubdomainEnumeration, SuricataAlertStack, ToolUserAgentHttp
from romulus.detect.sessions import RareClientFingerprint
from romulus.detect.tls import SelfSignedCertificateOutbound, ShortLivedOrNewCertificateOutbound
from romulus.evidence.normalize import normalize_hits
from romulus.evidence.zeek import ZEEK_NORMALIZER
from tests.fixtures import zeek_logs as zl

SENSOR = zl.SENSOR
CLIENT, RESOLVER, PUBLIC = "10.20.0.15", "10.20.0.53", "203.0.113.77"
SHAPES = ("malcolm", "elastic", "security_onion", "plain")
QTYPES = {"A": 1, "PTR": 12, "TXT": 16, "AXFR": 252, "ANY": 255, "CNAME": 5, "NULL": 10}
RCODES = {"NOERROR": 0, "NXDOMAIN": 3, "REFUSED": 5}

CERTIFICATE_LINK_GAP = ("ssl.log names the server certificate but not its validity or fingerprint, which are on the "
                        "x509 row: a link from the ssl row to its certificate row (by fingerprint) must attach them "
                        "before the short-lived rule can judge a Zeek session")
CERTIFICATE_IDENTITY_GAP = ("detect/tls.py identifies a certificate by SHA-1, else by its names as written: Suricata "
                            "writes the subject in RFC 4514 order with a SHA-1, Zeek in RFC 2253 order with a SHA-256, "
                            "so one certificate seen by both sensors is two groups (a detect change)")


def iso(ts: float) -> str:
    when = datetime(1970, 1, 1, tzinfo=UTC) + timedelta(microseconds=round(ts * 1e6))
    return when.strftime("%Y-%m-%dT%H:%M:%S.%f") + "+0000"


def eve(nid: str, record: dict) -> dict:
    return {"_id": nid, "_index": "logs-suricata.eve-default", "_source": {
        "@timestamp": iso(record["_ts"]), "host": {"name": SENSOR},
        "event": {"dataset": f"suricata.eve.{record['event_type']}",
                  "original": json.dumps({k: v for k, v in record.items() if k != "_ts"})}}}


def eve_base(row: zl.Row, event_type: str, flow_id: int, proto: str = "TCP") -> dict:
    z = row.zeek
    return {"_ts": row.ts, "timestamp": iso(row.ts), "flow_id": flow_id, "event_type": event_type,
            "src_ip": z["id.orig_h"], "src_port": z["id.orig_p"], "dest_ip": z["id.resp_h"],
            "dest_port": z["id.resp_p"], "proto": proto}


def normalized(hits: list[dict], plain: bool = False) -> list:
    if plain:
        from romulus.evidence.zeek import normalize_plain_zeek
        return [normalize_plain_zeek(h, sensor=SENSOR) for h in hits]
    events, skips, errors = normalize_hits(hits)
    assert (skips, errors) == ({}, []), (skips, errors)
    return events


def zeek_events(rows: list[zl.Row], shape: str) -> list:
    events = normalized([zl.WRITERS[shape](row, f"z{i}") for i, row in enumerate(rows)], plain=shape == "plain")
    assert len(events) == len(rows) and all(e.normalizer == ZEEK_NORMALIZER for e in events)
    return events


def run_rule(rule, events):
    stage = {}
    out = rule.consume(events)
    stage.update({e.id: e for e in rule.drain_staged()})
    rule.bind_loader(lambda ids: [stage[i] for i in ids if i in stage])
    return out + rule.finalize()


def items(matches) -> list[tuple]:
    return sorted((m.playbook_id, m.group_key, m.proposed_lane, m.severity) for m in matches)


_RECORD_WORDS = re.compile(r"\b(?:query|answer|transaction) records?\b")


def claim_text(match) -> str:
    return _RECORD_WORDS.sub("<records>", match.claim)


def assert_twins(rule_factory, zeek: list, suricata: list, expected: int = 1):
    from_zeek, from_suricata = run_rule(rule_factory(), zeek), run_rule(rule_factory(), suricata)
    assert len(from_suricata) == expected, [m.claim for m in from_suricata]
    assert items(from_zeek) == items(from_suricata)
    assert sorted(claim_text(m) for m in from_zeek) == sorted(claim_text(m) for m in from_suricata)
    return from_zeek


# ---- DNS -----------------------------------------------------------------------------------------------------------

def dns_transaction(i: int, name: str, qtype: str = "A", rcode: str = "NOERROR",
                    answers: tuple[tuple[str, str, int], ...] = (), client: str = CLIENT, server: str = RESOLVER,
                    seconds: float = 1.0) -> tuple[zl.Row, list[dict]]:
    """One DNS transaction: the Zeek dns.log row and Suricata's query and answer records of the same flow. Zeek's
    row carries the question's time; Suricata's answer is given the same time here (in traffic it arrives one round
    trip later), so the two readings compare word for word."""
    row = zl.Row("dns", {"uid": f"Cdns{i:013d}", "id.orig_h": client, "id.orig_p": 40000 + i, "id.resp_h": server,
                         "id.resp_p": 53, "proto": "udp", "trans_id": i % 65536, "rtt": 0.004, "query": name,
                         "qclass": 1, "qclass_name": "C_INTERNET", "qtype": QTYPES[qtype], "qtype_name": qtype,
                         "rcode": RCODES[rcode], "rcode_name": rcode, "AA": False, "TC": False, "RD": True,
                         "RA": True, "Z": 0, "rejected": False,
                         **({"answers": [a[1] for a in answers], "TTLs": [float(a[2]) for a in answers]}
                            if answers else {})},
                 ts=zl.T0 + i * seconds)
    query = {**eve_base(row, "dns", 10**9 + i, "UDP"),
             "dns": {"version": 2, "type": "query", "id": i % 65536, "rrname": name, "rrtype": qtype, "tx_id": 0}}
    answer = {**eve_base(row, "dns", 10**9 + i, "UDP"),
              "dns": {"version": 2, "type": "answer", "id": i % 65536, "rrname": name, "rrtype": qtype,
                      "rcode": rcode, **({"answers": [{"rrname": name, "rrtype": t, "ttl": ttl, "rdata": data}
                                                      for t, data, ttl in answers]} if answers else {})}}
    return row, [eve(f"q{i}", query), eve(f"a{i}", answer)]


def dns_twins(transactions, shape: str):
    rows = [row for row, _ in transactions]
    hits = [h for _, pair in transactions for h in pair]
    return zeek_events(rows, shape), normalized(hits)


@pytest.mark.parametrize("shape", SHAPES)
def test_subdomain_enumeration(shape):
    zeek, suricata = dns_twins([dns_transaction(i, f"host{i:03d}.corp-example.test", rcode="NXDOMAIN")
                                for i in range(120)], shape)
    [match] = assert_twins(DnsSubdomainEnumeration, zeek, suricata)
    assert match.group_key == f"{CLIENT}|corp-example.test" and "120 distinct names" in match.claim


@pytest.mark.parametrize("shape", SHAPES)
def test_nxdomain_burst(shape):
    zeek, suricata = dns_twins([dns_transaction(i, f"x{i:04d}qz.example.org", rcode="NXDOMAIN")
                                for i in range(80)], shape)
    [match] = assert_twins(DnsNxdomainBurst, zeek, suricata)
    assert CLIENT in match.group_key


@pytest.mark.parametrize("shape", SHAPES)
def test_reverse_lookup_sweep(shape):
    zeek, suricata = dns_twins([dns_transaction(i, f"{i}.1.168.192.in-addr.arpa", "PTR", "NXDOMAIN")
                                for i in range(1, 121)], shape)
    [match] = assert_twins(DnsReverseLookupSweep, zeek, suricata)
    assert CLIENT in match.group_key


@pytest.mark.parametrize("shape", SHAPES)
def test_tunnel_shape(shape):
    labels = [base64.b32encode(hashlib.sha256(f"chunk-{i}".encode()).digest()).decode().lower()[:52]
              for i in range(80)]
    zeek, suricata = dns_twins([dns_transaction(i, f"{labels[i]}.t.tunnel-example.net", "TXT",
                                                answers=(("TXT", "TXT 4 data", 0),), server=PUBLIC)
                                for i in range(80)], shape)
    [match] = assert_twins(DnsTunnelShape, zeek, suricata)
    assert "tunnel-example.net" in match.group_key


@pytest.mark.parametrize("shape", SHAPES)
def test_zone_transfer_or_any_request_reports_the_same_items(shape):
    zeek, suricata = dns_twins([dns_transaction(1, "corp-example.test", "AXFR", "REFUSED"),
                                dns_transaction(2, "corp-example.test", "ANY", "NOERROR")], shape)
    from_zeek = run_rule(DnsZoneTransferOrAnyRequest(), zeek)
    from_suricata = run_rule(DnsZoneTransferOrAnyRequest(), suricata)
    assert len(from_suricata) == 2 and items(from_zeek) == items(from_suricata)
    assert {m.group_key for m in from_zeek} == {f"{CLIENT}|{RESOLVER}|corp-example.test",
                                                f"{CLIENT}|{RESOLVER}|ANY"}


def test_zone_transfer_counts_a_transaction_record_once():
    """A Zeek row is the question and its answer in one record: the rule's record total counts it once, so its one
    record is cited in full, as Suricata's two records are."""
    zeek, suricata = dns_twins([dns_transaction(1, "corp-example.test", "AXFR", "REFUSED")], "malcolm")
    [z], [s] = run_rule(DnsZoneTransferOrAnyRequest(), zeek), run_rule(DnsZoneTransferOrAnyRequest(), suricata)
    assert (z.group_key, z.proposed_lane) == (s.group_key, s.proposed_lane)
    assert "of the 2 records" not in z.claim and "All 2 records are cited" in s.claim
    assert "record is cited" in z.claim or "The one record" in z.claim or "the one record" in z.claim, z.claim


# ---- HTTP ------------------------------------------------------------------------------------------------------------

def http_transaction(i: int, user_agent: str, uri: str) -> tuple[zl.Row, dict]:
    row = zl.Row("http", {"uid": f"Chttp{i:012d}", "id.orig_h": CLIENT, "id.orig_p": 50000 + i,
                          "id.resp_h": PUBLIC, "id.resp_p": 80, "trans_depth": 1, "method": "GET",
                          "host": "files.example.net", "uri": uri, "version": "1.1", "user_agent": user_agent,
                          "request_body_len": 0, "response_body_len": 2048, "status_code": 200,
                          "status_msg": "OK"}, ts=zl.T0 + i)
    record = {**eve_base(row, "http", 2 * 10**9 + i),
              "http": {"hostname": "files.example.net", "url": uri, "http_user_agent": user_agent,
                       "http_method": "GET", "protocol": "HTTP/1.1", "status": 200, "length": 2048}}
    return row, eve(f"h{i}", record)


@pytest.mark.parametrize("shape", SHAPES)
def test_tool_user_agent(shape):
    pairs = [http_transaction(i, "curl/8.4.0", f"/drop/{i}.bin") for i in range(4)]
    zeek = zeek_events([row for row, _ in pairs], shape)
    suricata = normalized([h for _, h in pairs])
    [match] = assert_twins(ToolUserAgentHttp, zeek, suricata)
    assert match.group_key == f"{CLIENT}|{PUBLIC}|curl/8.4.0"


# ---- TLS and SSH -----------------------------------------------------------------------------------------------------

SELF_SIGNED = "CN=c2.example.net,O=Example C2,C=US"


def tls_session(i: int, *, subject: str = SELF_SIGNED, issuer: str = SELF_SIGNED, ja3: str = "ab" * 16,
                suricata_subject: str | None = None, suricata_issuer: str | None = None,
                certificate: dict | None = None) -> tuple[zl.Row, dict]:
    row = zl.Row("ssl", {"uid": f"Cssl{i:013d}", "id.orig_h": CLIENT, "id.orig_p": 51000 + i, "id.resp_h": PUBLIC,
                         "id.resp_p": 443, "version": "TLSv12", "cipher": "TLS_AES_128_GCM_SHA256",
                         "server_name": "c2.example.net", "resumed": False, "established": True,
                         "subject": subject, "issuer": issuer, "ja3": ja3, "cert_chain_fps": ["3c" * 32]},
                 ts=zl.T0 + i)
    tls = {"sni": "c2.example.net", "version": "TLS 1.2", "subject": suricata_subject or subject,
           "issuerdn": suricata_issuer or issuer, "ja3": {"hash": ja3}, **(certificate or {})}
    return row, eve(f"t{i}", {**eve_base(row, "tls", 3 * 10**9 + i), "tls": tls})


def tls_twins(sessions, shape):
    return zeek_events([row for row, _ in sessions], shape), normalized([h for _, h in sessions])


@pytest.mark.parametrize("shape", SHAPES)
def test_self_signed_certificate(shape):
    zeek, suricata = tls_twins([tls_session(i) for i in range(3)], shape)
    [match] = assert_twins(SelfSignedCertificateOutbound, zeek, suricata)
    assert match.group_key.endswith(f"|{PUBLIC}") and "Compared by distinguished name" in match.claim


@pytest.mark.parametrize("shape", SHAPES)
def test_rare_ja3_client_fingerprint(shape):
    zeek, suricata = tls_twins([tls_session(i, subject="CN=www.example.net", issuer="CN=Example CA")
                                for i in range(2)], shape)
    [match] = assert_twins(RareClientFingerprint, zeek, suricata)
    assert match.group_key == f"JA3|{'ab' * 16}"


def ssh_session(i: int) -> tuple[zl.Row, dict]:
    row = zl.Row("ssh", {"uid": f"Cssh{i:013d}", "id.orig_h": CLIENT, "id.orig_p": 52000 + i, "id.resp_h": PUBLIC,
                         "id.resp_p": 22, "version": 2, "auth_attempts": 1, "direction": "OUTBOUND",
                         "client": "SSH-2.0-paramiko_3.4.0", "server": "SSH-2.0-OpenSSH_9.6",
                         "hassh": "cd" * 16, "hasshServer": "ef" * 16}, ts=zl.T0 + i)
    ssh = {"client": {"proto_version": "2.0", "software_version": "paramiko_3.4.0", "hassh": {"hash": "cd" * 16}},
           "server": {"proto_version": "2.0", "software_version": "OpenSSH_9.6", "hassh": {"hash": "ef" * 16}}}
    return row, eve(f"s{i}", {**eve_base(row, "ssh", 4 * 10**9 + i), "ssh": ssh})


@pytest.mark.parametrize("shape", SHAPES)
def test_rare_hassh_and_ssh_client_software(shape):
    sessions = [ssh_session(i) for i in range(2)]
    zeek = zeek_events([row for row, _ in sessions], shape)
    suricata = normalized([h for _, h in sessions])
    matches = assert_twins(RareClientFingerprint, zeek, suricata, expected=2)
    assert {m.group_key for m in matches} == {f"HASSH|{'cd' * 16}", "SSH client software|paramiko_3.4.0"}


def test_gap_short_lived_certificate_needs_the_x509_link():
    """Suricata's tls record carries the server certificate's validity; Zeek's ssl row does not. The short-lived rule
    finds the Suricata session and counts the Zeek one as missing (never a negative), until the link lands."""
    validity = {"notbefore": "2024-11-18T12:00:00", "notafter": "2024-11-25T12:00:00"}
    zeek, suricata = tls_twins([tls_session(1, subject="CN=fresh.example.net", issuer="CN=Example CA",
                                            certificate=validity)], "malcolm")
    rule = ShortLivedOrNewCertificateOutbound()
    assert run_rule(rule, zeek) == [] and rule.missing_required == 1, CERTIFICATE_LINK_GAP
    assert len(run_rule(ShortLivedOrNewCertificateOutbound(), suricata)) == 1


def test_gap_one_certificate_from_both_sensors_is_two_groups():
    zeek, suricata = tls_twins([tls_session(1, suricata_subject="C=US, O=Example C2, CN=c2.example.net",
                                            suricata_issuer="C=US, O=Example C2, CN=c2.example.net",
                                            certificate={"fingerprint": "aa:bb:cc:dd"})], "malcolm")
    [z], [s] = run_rule(SelfSignedCertificateOutbound(), zeek), run_rule(SelfSignedCertificateOutbound(), suricata)
    assert z.proposed_lane == s.proposed_lane
    assert z.group_key != s.group_key and s.group_key.startswith("aa:bb:cc:dd|"), CERTIFICATE_IDENTITY_GAP


# ---- indicators ------------------------------------------------------------------------------------------------------

def indicators(*items: tuple[str, str, str]) -> IndicatorSet:
    return IndicatorSet([Indicator(iid, kind, (value,), f"synthetic {kind}", "medium", "lead", (), "synthetic.yaml")
                         for iid, kind, value in items], "synthetic", ["synthetic.yaml"])


LISTED = indicators(("ind-ip", "ip", PUBLIC), ("ind-domain", "domain", "listed-example.net"),
                    ("ind-ja3", "ja3", "ab" * 16), ("ind-hassh", "hassh", "cd" * 16))


def http_listed(i: int, host: str) -> tuple[zl.Row, dict]:
    row, hit = http_transaction(i, "ExampleAgent/2.0", "/index.html")
    record = json.loads(hit["_source"]["event"]["original"])
    record["http"]["hostname"] = host
    hit["_source"]["event"]["original"] = json.dumps(record)
    return row.with_(host=host), hit


def tls_sni(i: int, sni: str) -> tuple[zl.Row, dict]:
    row, hit = tls_session(i, subject="CN=www.example.net", issuer="CN=Example CA")
    record = json.loads(hit["_source"]["event"]["original"])
    record["tls"]["sni"] = sni
    hit["_source"]["event"]["original"] = json.dumps(record)
    return row.with_(server_name=sni), hit


@pytest.mark.parametrize("shape", SHAPES)
def test_indicators_on_addresses_host_names_sni_and_fingerprints(shape):
    pairs = [http_transaction(2, "ExampleAgent/2.0", "/index.html"), http_listed(5, "cdn.listed-example.net"),
             tls_session(3, subject="CN=www.example.net", issuer="CN=Example CA"),
             tls_sni(6, "api.listed-example.net"), ssh_session(4)]
    zeek = zeek_events([row for row, _ in pairs], shape)
    suricata = normalized([hit for _, hit in pairs])
    matches = assert_twins(lambda: IndicatorMatch(LISTED), zeek, suricata, expected=5)
    assert {m.group_key.split("|")[1] for m in matches} == {"address:destination", "domain", "sni", "ja3",
                                                              "hassh"}


@pytest.mark.parametrize("shape", SHAPES)
def test_indicators_on_a_dns_question_count_records_as_each_sensor_writes_them(shape):
    """The same group and lane; the record count is each sensor's own: Zeek's one transaction row, Suricata's
    question and answer records (both name the domain)."""
    row, hits = dns_transaction(1, "www.listed-example.net", answers=(("A", "192.0.2.9", 60),))
    zeek, suricata = zeek_events([row], shape), normalized(hits)
    [z], [s] = run_rule(IndicatorMatch(LISTED), zeek), run_rule(IndicatorMatch(LISTED), suricata)
    assert (z.group_key, z.proposed_lane, z.severity) == (s.group_key, s.proposed_lane, s.severity)
    assert z.claim.startswith("1 dns_query record(s)") and s.claim.startswith("2 dns_query record(s)")


def test_a_listed_name_behind_a_cname_answer():
    """Zeek writes no answer type: answer data that is not an address is matched as a name, as Suricata's typed
    CNAME answer is."""
    row, hits = dns_transaction(1, "www.example.org", answers=(("CNAME", "edge.listed-example.net", 60),))
    zeek, suricata = zeek_events([row], "malcolm"), normalized(hits)
    from_suricata = run_rule(IndicatorMatch(LISTED), suricata)
    from_zeek = run_rule(IndicatorMatch(LISTED), zeek)
    assert zeek[0].get("dns.answers")[0]["type"] is None
    assert [m.group_key.split("|")[1] for m in from_suricata] == ["dns_answer"]
    assert [m.group_key for m in from_zeek] == [m.group_key for m in from_suricata]


def test_an_untyped_answer_address_is_never_matched_as_a_name():
    listed = indicators(("ind-domain", "domain", "listed-example.net"), ("ind-ip", "ip", "192.0.2.99"))
    row, _hits = dns_transaction(1, "www.example.org", answers=(("A", "192.0.2.10", 60),))
    assert run_rule(IndicatorMatch(listed), zeek_events([row], "malcolm")) == []


# ---- hard negatives --------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("shape", SHAPES)
def test_benign_lookalikes_are_evaluated_in_full_and_reported_by_neither_sensor(shape):
    """Ordinary lookups with answers under several domains, a browser's requests, a CA-issued certificate and one
    JA3 shared by two internal clients: every rule evaluates every Zeek record (a complete search, no record
    missing) and reports nothing, as it reports nothing on the Suricata twins."""
    lookups = [dns_transaction(i, f"www{i % 4}.site{i % 7}.example.com", answers=(("A", "192.0.2.10", 300),))
               for i in range(40)]
    browser = [http_transaction(100 + i, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Gecko/20100101 Firefox/131.0",
                                f"/page/{i}") for i in range(5)]
    issued = [tls_session(200 + i, subject="CN=www.example.net,O=Example,C=US", issuer="CN=Example CA,O=Example,C=US")
              for i in range(2)]
    shared = [(row.with_(**{"id.orig_h": "10.20.0.16", "uid": "CsslSharedJa30001"}), hit)
              for row, hit in [tls_session(300, subject="CN=www.example.net", issuer="CN=Example CA")]]
    record = json.loads(shared[0][1]["_source"]["event"]["original"])
    record["src_ip"] = "10.20.0.16"
    shared[0][1]["_source"]["event"]["original"] = json.dumps(record)
    cases = [((DnsSubdomainEnumeration, DnsNxdomainBurst, DnsTunnelShape, DnsReverseLookupSweep,
               DnsZoneTransferOrAnyRequest), dns_twins(lookups, shape)),
             ((ToolUserAgentHttp,), (zeek_events([r for r, _ in browser], shape), normalized([h for _, h in browser]))),
             ((SelfSignedCertificateOutbound, RareClientFingerprint),
              tls_twins([*issued, *shared], shape))]
    for rules, (zeek, suricata) in cases:
        for rule_class in rules:
            rule = rule_class()
            assert run_rule(rule, zeek) == [] and run_rule(rule_class(), suricata) == [], rule_class.id
            assert rule.evaluated > 0 and rule.missing_required == 0, (rule_class.id, rule.missing_required)


# ---- the IDS alert stack ---------------------------------------------------------------------------------------------

def test_zeek_alerts_are_left_to_their_own_rule_by_the_suricata_alert_stack():
    """A Zeek notice and the Suricata alert of the same traffic: the alert stack reports the alert and neither
    evaluates nor counts missing the Zeek alerts, which net.zeek_alert reads."""
    zeek = zeek_events([zl.NOTICE, zl.SIGNATURES, zl.WEIRD, zl.INTEL], "malcolm")
    alert = {"_ts": zl.T0, "timestamp": iso(zl.T0), "event_type": "alert", "src_ip": zl.CLIENT, "src_port": 51040,
             "dest_ip": zl.SERVER, "dest_port": 443, "proto": "TCP",
             "alert": {"signature": "SURICATA TLS invalid certificate", "signature_id": 2230002, "severity": 2,
                       "category": "Generic Protocol Command Decode", "action": "allowed"}}
    suricata = normalized([eve("alert-1", alert)])
    rule = SuricataAlertStack()
    assert run_rule(rule, zeek) == [] and (rule.missing_required, rule.evaluated) == (0, 0)
    assert rule.scope_partition(zeek) == []
    both = SuricataAlertStack()
    [match] = run_rule(both, zeek + suricata)
    assert match.claim.startswith("Suricata raised") and (both.evaluated, both.missing_required) == (1, 0)
    [alone] = run_rule(SuricataAlertStack(), suricata)
    assert alone.claim == match.claim
