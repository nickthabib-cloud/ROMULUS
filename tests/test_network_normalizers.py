"""Suricata EVE tls/ssh/dns and Arkime 6.x list-shaped blocks into one typed handshake contract."""
import json
from datetime import UTC, datetime

import pytest

from romulus.evidence.normalize import normalize_hits

T0 = datetime(2024, 11, 18, 14, 26, 40, tzinfo=UTC)
MS = int(T0.timestamp() * 1000)
DAY_MS = 86_400_000
INDEX = "arkime_sessions3-241118"


def arkime(_id="s1", **blocks):
    src = {"firstPacket": MS, "lastPacket": MS + 2000, "ipProtocol": 6, "node": "server",
           "network": {"community_id": "1:abc="},
           "source": {"ip": "172.17.100.121", "port": 51000, "bytes": 900, "packets": 9},
           "destination": {"ip": "192.0.2.174", "port": 443, "bytes": 4000, "packets": 8},
           "protocol": ["tcp", "tls"]}
    src.update(blocks)
    return {"_id": _id, "_index": INDEX, "_source": src}


def eve(_id, record, ts="2024-11-18T14:26:40.100Z"):
    record = {"timestamp": "2024-11-18T14:26:40.100000+0000", "flow_id": 1234, "src_ip": "172.17.100.121",
              "src_port": 51000, "dest_ip": "192.0.2.174", "dest_port": 443, "proto": "TCP",
              "community_id": "1:abc=", **record}
    return {"_id": _id, "_index": "romulus-network-logs", "_source": {
        "@timestamp": ts, "host": {"name": "inetfw"},
        "event": {"dataset": f"suricata.eve.{record['event_type']}", "original": json.dumps(record)}}}


def one(hit):
    events, skips, errors = normalize_hits([hit])
    assert errors == [] and skips == {}, (errors, skips)
    assert len(events) == 1
    return events[0]


SELF_SIGNED = {"hash": "AA:BB:CC", "subjectCN": ["c2.example"], "subjectON": ["Acme"], "issuerCN": ["c2.example"],
               "issuerON": ["Acme"], "notBefore": MS - DAY_MS, "notAfter": MS + 29 * DAY_MS, "validDays": 30,
               "serial": "0A1B", "alt": ["c2.example", "www.c2.example"], "altCnt": 2,
               "publicAlgorithm": "rsaEncryption"}
LEAF = {"hash": "11:22", "subjectCN": ["shop.example"], "subjectON": [], "issuerCN": ["Example CA R1"],
        "issuerON": ["Example Trust"], "notBefore": MS - 40 * DAY_MS, "notAfter": MS + 50 * DAY_MS,
        "validDays": 90}
INTERMEDIATE = {"hash": "33:44", "subjectCN": ["Example CA R1"], "subjectON": ["Example Trust"],
                "issuerCN": ["Example Root"], "issuerON": ["Example Trust"], "notBefore": MS - 900 * DAY_MS,
                "notAfter": MS + 900 * DAY_MS}
ROOT = {"hash": "55:66", "subjectCN": ["Example Root"], "subjectON": ["Example Trust"],
        "issuerCN": ["Example Root"], "issuerON": ["Example Trust"], "notBefore": MS - 5000 * DAY_MS,
        "notAfter": MS + 5000 * DAY_MS}


# ---- Arkime certificates ---------------------------------------------------------------------------------------

def test_arkime_single_certificate_list_is_typed_with_derived_names():
    e = one(arkime(cert=[SELF_SIGNED], certCnt=1))
    [c] = e.get("tls.server.certificates")
    assert c["subject_cn"] == ["c2.example"] and c["issuer_on"] == ["Acme"]
    assert c["not_before"] == "2024-11-17T14:26:40+00:00" and c["not_after"] == "2024-12-17T14:26:40+00:00"
    assert (c["valid_days"], c["sha1"], c["serial"]) == (30, "aa:bb:cc", "0a1b")
    assert c["alt_names"] == ["c2.example", "www.c2.example"]
    assert c["self_issued"] is True and c["issues_other"] is False and c["names_compared"] == "CN and O"
    # one presented certificate issues no other: it is the server's own, so the flat fields are set
    assert e.get("tls.server.subject_cn") == ["c2.example"] and e.get("tls.server.hash_sha1") == "aa:bb:cc"
    assert e.get("tls.server.not_after") == "2024-12-17T14:26:40+00:00"
    assert e.fields["tls.server.certificates"].origin == "s1:cert"


def test_arkime_chain_in_hash_order_marks_the_issuers_and_keeps_the_leaf():
    e = one(arkime(cert=[ROOT, LEAF, INTERMEDIATE]))
    certs = {c["sha1"]: c for c in e.get("tls.server.certificates")}
    assert certs["55:66"]["self_issued"] is True and certs["55:66"]["issues_other"] is True
    assert certs["33:44"]["issues_other"] is True and certs["33:44"]["self_issued"] is False
    assert certs["11:22"]["issues_other"] is False
    assert e.get("tls.server.subject_cn") == ["shop.example"]
    # sorted, so the source's (hash table) order does not change the typed value
    assert one(arkime(cert=[LEAF, INTERMEDIATE, ROOT])).get("tls.server.certificates") == \
        e.get("tls.server.certificates")


def test_arkime_two_unrelated_certificates_leave_the_server_certificate_ambiguous():
    other = {**LEAF, "hash": "77:88", "subjectCN": ["other.example"]}
    e = one(arkime(cert=[LEAF, other]))
    assert len(e.get("tls.server.certificates")) == 2
    assert e.get("tls.server.subject_cn") is None and e.get("tls.server.hash_sha1") is None
    assert any("ambiguous" in c for c in e.caveats)


def test_arkime_certificate_as_a_single_object_is_one_entry():
    assert len(one(arkime(cert=SELF_SIGNED)).get("tls.server.certificates")) == 1


@pytest.mark.parametrize("bad", ["not-a-list", [1, 2], [{"notBefore": "yesterday"}], [{"subjectCN": 7}]])
def test_arkime_malformed_certificate_is_dropped_and_recorded(bad):
    e = one(arkime(cert=bad))
    assert e.get("source.ip") == "172.17.100.121"          # the rest of the session survives
    malformed = e.get("parse.malformed")
    assert malformed and all(p.startswith("cert") for p in malformed)
    if not isinstance(bad, list) or not all(isinstance(x, dict) for x in bad):
        assert e.get("tls.server.certificates") is None


def test_arkime_certificate_with_bad_time_keeps_its_names_but_not_the_time():
    e = one(arkime(cert=[{**SELF_SIGNED, "notAfter": "soon"}]))
    [c] = e.get("tls.server.certificates")
    assert c["not_after"] is None and c["not_before"] is not None and c["self_issued"] is True
    assert e.get("parse.malformed") == ["cert[0].notAfter"]


def test_arkime_certificate_without_names_is_not_judged_self_issued():
    [c] = one(arkime(cert=[{"hash": "aa", "notBefore": MS, "notAfter": MS + DAY_MS}])).get("tls.server.certificates")
    assert c["self_issued"] is None and c["issues_other"] is False


# ---- Arkime fingerprints, flags, tags ------------------------------------------------------------------------

def test_arkime_fingerprints_are_lists_whatever_the_stored_shape():
    e = one(arkime(tls={"ja3": "E7D705A3286E19EA42F587B344EE6865", "ja3s": ["b", "a", "b"], "ja4": ["t13d_x"],
                        "version": ["TLSv1.3"]},
                   ssh={"hassh": ["H1"], "hasshServer": "s1", "version": ["ssh-2.0-openssh_9.6", "ssh-2.0-go"]}))
    assert e.get("tls.ja3") == ["e7d705a3286e19ea42f587b344ee6865"]
    assert e.get("tls.ja3s") == ["a", "b"] and e.get("tls.ja4") == ["t13d_x"]
    assert e.get("ssh.hassh") == ["h1"] and e.get("ssh.hassh_server") == ["s1"]
    assert e.get("ssh.version") == ["ssh-2.0-go", "ssh-2.0-openssh_9.6"]
    assert e.get("ssh.client.software") is None              # Arkime banners are not attributed to a side
    assert e.get("tls.version") == ["TLSv1.3"]


def test_arkime_fingerprint_of_wrong_type_is_malformed_not_stringified():
    e = one(arkime(tls={"ja3": [{"hash": "x"}], "ja4": 5}))
    assert e.get("tls.ja3") is None and e.get("tls.ja4") is None
    assert e.get("parse.malformed") == ["tls.ja3", "tls.ja4"]


def test_arkime_tcp_flags_root_id_body_magic_and_tags():
    e = one(arkime(_id="241118-b", rootId="241118-a",
                   tcpflags={"syn": 1, "syn-ack": 1, "ack": 12, "psh": 3, "fin": 2, "rst": 0, "urg": 0,
                             "srcZero": 0, "dstZero": 0},
                   http={"bodyMagic": ["application/x-dosexec"]}, tags=["ssh-reverse-shell"]))
    assert (e.get("tcp.flags.syn"), e.get("tcp.flags.syn_ack"), e.get("tcp.flags.fin"), e.get("tcp.flags.rst")) == \
        (1, 1, 2, 0)
    assert e.get("arkime.root_id") == "241118-a" and e.get("arkime.continuation") is True
    assert e.get("http.body_magic") == ["application/x-dosexec"]
    assert e.get("arkime.tags") == ["ssh-reverse-shell"]
    first = one(arkime(_id="241118-a", rootId="241118-a"))
    assert first.get("arkime.continuation") is False
    assert one(arkime()).get("arkime.continuation") is None


def test_arkime_bad_tcp_flag_counter_is_malformed():
    e = one(arkime(tcpflags={"syn": "one", "fin": 1}))
    assert e.get("tcp.flags.syn") is None and e.get("tcp.flags.fin") == 1
    assert e.get("parse.malformed") == ["tcpflags.syn"]


# ---- Arkime DNS ------------------------------------------------------------------------------------------------

def dns_obj(host, qt="A", status="NOERROR", answers=None):
    return {"opcode": "QUERY", "qc": "IN", "qt": qt, "host": host, "hostCnt": 1, "status": status,
            "answers": answers or [], "answersCnt": len(answers or [])}


def test_arkime_dns_list_with_one_question_sets_the_scalar_names():
    ans = [{"type": "A", "class": "IN", "ttl": 300, "name": "update.example", "ip": "198.51.100.7"},
           {"type": "CNAME", "class": "IN", "ttl": 60, "name": "update.example", "cname": "cdn.example"}]
    e = one(arkime(protocol=["udp", "dns"], dns=[dns_obj(["update.example"], answers=ans)]))
    assert e.get("dns.question.name") == "update.example" and e.get("dns.question.names") == ["update.example"]
    assert e.get("dns.question.type") == "A" and e.get("dns.response_code") == "NOERROR"
    # a whole transaction: no dns.type, and the client is the session's source (Arkime's initiator)
    assert e.get("dns.type") is None and e.get("source.ip") == "172.17.100.121"
    assert e.get("dns.answers") == [
        {"name": "update.example", "type": "A", "ttl": 300, "data": "198.51.100.7"},
        {"name": "update.example", "type": "CNAME", "ttl": 60, "data": "cdn.example"}]
    assert ("domain", "update.example", "subject") in e.entities()


def test_arkime_dns_with_several_questions_never_picks_one():
    e = one(arkime(dns=[dns_obj(["b.example"]), dns_obj("a.example", qt="AAAA", status="NXDOMAIN")]))
    assert e.get("dns.question.names") == ["a.example", "b.example"]
    assert e.get("dns.question.name") is None and e.get("dns.question.type") is None
    assert e.get("dns.question.types") == ["A", "AAAA"] and e.get("dns.response_codes") == ["NOERROR", "NXDOMAIN"]
    assert not [x for x in e.entities() if x[0] == "domain"]


def test_arkime_pre_object_dns_shape_still_reads():
    e = one(arkime(dns={"host": ["x.example"], "qt": ["A"], "status": ["NOERROR"]}))
    assert e.get("dns.question.name") == "x.example" and e.get("dns.response_code") == "NOERROR"


@pytest.mark.parametrize("bad", ["x.example", [1], [{"host": [3]}], [{"host": ["a"], "answers": "1.2.3.4"}]])
def test_arkime_malformed_dns_is_recorded(bad):
    e = one(arkime(dns=bad))
    assert e.get("parse.malformed") and all(p.startswith("dns") for p in e.get("parse.malformed"))


# ---- Suricata TLS ----------------------------------------------------------------------------------------------

SURI_TLS = {"event_type": "tls", "tls": {
    "subject": "CN=c2.example, O=Acme", "issuerdn": "CN=c2.example, O=Acme", "serial": "0A:1B",
    "fingerprint": "AA:BB:CC", "sni": "c2.example", "version": "TLS 1.2",
    "notbefore": "2024-11-17T14:26:40", "notafter": "2024-12-17T14:26:40",
    "ja3": {"hash": "E7D705A3286E19EA42F587B344EE6865", "string": "771,..."},
    "ja3s": {"hash": "f4febc55ea12b31ae17cfb7e614afda8", "string": "771,..."}}}


def test_suricata_tls_carries_the_handshake_and_server_certificate():
    e = one(eve("t1", SURI_TLS))
    assert e.family == "tls_session"
    assert e.get("tls.client.server_name") == "c2.example" and e.get("tls.version") == ["TLSv1.2"]
    assert e.get("tls.ja3") == ["e7d705a3286e19ea42f587b344ee6865"]
    assert e.get("tls.ja3s") == ["f4febc55ea12b31ae17cfb7e614afda8"]
    [c] = e.get("tls.server.certificates")
    assert c["subject_dn"] == "CN=c2.example, O=Acme" and c["subject_cn"] == ["c2.example"]
    assert c["subject_on"] == ["Acme"] and c["names_compared"] == "distinguished name"
    assert c["not_before"] == "2024-11-17T14:26:40+00:00" and c["self_issued"] is True
    assert (c["sha1"], c["serial"]) == ("aa:bb:cc", "0a1b")
    assert e.get("tls.server.hash_sha1") == "aa:bb:cc"
    assert e.fields["tls.ja3"].origin == "t1:event.original#eve.tls.ja3.hash"


def test_suricata_dn_differing_only_in_ou_is_not_self_issued():
    rec = {"event_type": "tls", "tls": {"subject": "CN=svc, O=Acme, OU=Web", "issuerdn": "CN=svc, O=Acme, OU=CA"}}
    [c] = one(eve("t2", rec)).get("tls.server.certificates")
    assert c["self_issued"] is False


def test_suricata_dn_with_escaped_comma_in_a_value():
    rec = {"event_type": "tls", "tls": {"subject": "CN=a.example, O=Acme\\, Inc.", "issuerdn": "CN=R3, O=Let's Encrypt"}}
    [c] = one(eve("t3", rec)).get("tls.server.certificates")
    assert c["subject_on"] == ["Acme\\, Inc."] and c["self_issued"] is False


def test_suricata_tls13_without_certificate_has_no_certificate_fields():
    e = one(eve("t4", {"event_type": "tls", "tls": {"sni": "x.example", "version": "TLS 1.3",
                                                    "ja4": "t13d1516h2_8daaf6152771_02713d6af862"}}))
    assert e.get("tls.server.certificates") is None and e.get("tls.ja4") == ["t13d1516h2_8daaf6152771_02713d6af862"]
    assert e.get("tls.version") == ["TLSv1.3"] and e.get("parse.malformed") is None


def test_suricata_tls_with_wrong_types_keeps_the_record():
    e = one(eve("t5", {"event_type": "tls", "tls": {"sni": 5, "ja3": 7, "notafter": "never", "subject": "CN=x"}}))
    assert e.get("tls.client.server_name") is None and e.get("tls.ja3") is None
    assert e.get("parse.malformed") == ["tls.ja3", "tls.notafter", "tls.sni"]
    [c] = e.get("tls.server.certificates")
    assert c["not_after"] is None and c["subject_cn"] == ["x"]


def test_suricata_resumed_session_is_marked():
    assert one(eve("t6", {"event_type": "tls", "tls": {"session_resumed": True}})).get("tls.resumed") is True


@pytest.mark.parametrize("event_type", ["tls", "ssh"])
def test_suricata_app_block_of_wrong_type_is_an_error(event_type):
    _, _, errors = normalize_hits([eve("bad", {"event_type": event_type, event_type: "x"})])
    assert len(errors) == 1


# ---- Suricata SSH and DNS --------------------------------------------------------------------------------------

def test_suricata_ssh_software_is_attributed_by_direction():
    e = one(eve("h1", {"event_type": "ssh", "dest_port": 22, "ssh": {
        "client": {"proto_version": "2.0", "software_version": "paramiko_3.4.0",
                   "hassh": {"hash": "ABC", "string": "x"}},
        "server": {"proto_version": "2.0", "software_version": "OpenSSH_9.6p1 Ubuntu-3ubuntu13.5"}}}))
    assert e.family == "ssh_session"
    assert e.get("ssh.client.software") == "paramiko_3.4.0" and e.get("ssh.client.proto_version") == "2.0"
    assert e.get("ssh.server.software") == "OpenSSH_9.6p1 Ubuntu-3ubuntu13.5"
    assert e.get("ssh.hassh") == ["abc"] and e.get("ssh.hassh_server") is None


def test_suricata_ssh_without_client_block_has_no_client_software():
    e = one(eve("h2", {"event_type": "ssh", "ssh": {"server": {"software_version": "OpenSSH_9.6"}}}))
    assert e.get("ssh.client.software") is None and e.get("ssh.server.software") == "OpenSSH_9.6"


def test_suricata_dns_v2_answer_keeps_answers_and_authorities():
    e = one(eve("d1", {"event_type": "dns", "src_ip": "10.0.0.53", "dest_ip": "10.0.0.9", "dns": {
        "version": 2, "type": "answer", "id": 1, "rrname": "bad.example", "rrtype": "A", "rcode": "NOERROR",
        "answers": [{"rrname": "bad.example", "rrtype": "A", "ttl": 30, "rdata": "203.0.113.9"}],
        "authorities": [{"rrname": "example", "rrtype": "SOA", "ttl": 600, "soa": {"mname": "ns.example"}}]}}))
    assert e.get("dns.question.name") == "bad.example" and e.get("dns.question.names") == ["bad.example"]
    assert e.get("dns.answers") == [{"name": "bad.example", "type": "A", "ttl": 30, "data": "203.0.113.9"}]
    assert e.get("dns.authorities") == [{"name": "example", "type": "SOA", "ttl": 600, "data": None}]
    assert e.get("dns.response_code") == "NOERROR" and e.get("dns.type") == "answer"


def test_suricata_dns_grouped_answers_are_read():
    e = one(eve("d2", {"event_type": "dns", "dns": {"version": 2, "type": "answer", "rrname": "g.example", "rrtype": "A",
                                                    "grouped": {"A": ["192.0.2.1", "192.0.2.2"]}}}))
    assert e.get("dns.answers") == [{"name": None, "type": "A", "ttl": None, "data": "192.0.2.1"},
                                    {"name": None, "type": "A", "ttl": None, "data": "192.0.2.2"}]


def test_suricata_dns_v1_answer_record_is_an_answer_never_the_question():
    """EVE v1 logs each answer resource record on its own; a CNAME target must not read as a question name."""
    e = one(eve("v1", {"event_type": "dns", "dns": {"type": "answer", "id": 7, "rrname": "cdn.example",
                                                    "rrtype": "A", "ttl": 20, "rdata": "203.0.113.5",
                                                    "rcode": "NOERROR"}}))
    assert e.get("dns.type") == "answer"
    assert e.get("dns.question.name") is None and e.get("dns.question.names") is None
    assert e.get("dns.question.type") is None and e.get("dns.response_code") == "NOERROR"
    assert e.get("dns.answers") == [{"name": "cdn.example", "type": "A", "ttl": 20, "data": "203.0.113.5"}]
    assert not [x for x in e.entities() if x[0] == "domain"]


def test_suricata_dns_v1_answer_without_rdata_still_names_no_question():
    e = one(eve("v1n", {"event_type": "dns", "dns": {"type": "answer", "rrname": "gone.example",
                                                     "rcode": "NXDOMAIN"}}))
    assert e.get("dns.question.name") is None and e.get("dns.response_code") == "NXDOMAIN"


def test_suricata_dns_v3_queries_list():
    e = one(eve("d3", {"event_type": "dns", "dns": {"version": 3, "type": "request",
                                                    "queries": [{"rrname": "q.example", "rrtype": "TXT"}]}}))
    assert e.get("dns.question.name") == "q.example" and e.get("dns.question.type") == "TXT"


def test_suricata_dns_query_record_is_unchanged_in_shape():
    e = one(eve("d4", {"event_type": "dns", "dns": {"type": "query", "rrname": "q.example", "rrtype": "A"}}))
    assert e.get("dns.question.name") == "q.example" and e.get("dns.answers") is None


def test_suricata_alert_with_tls_metadata_types_the_handshake():
    e = one(eve("a1", {"event_type": "alert", "alert": {"signature": "x", "signature_id": 1, "severity": 2},
                       "tls": {"sni": "c2.example", "ja3": {"hash": "abc"}}}))
    assert e.family == "net_alert" and e.get("tls.ja3") == ["abc"]


def test_normalization_is_deterministic():
    hits = [arkime(cert=[ROOT, LEAF, INTERMEDIATE], dns=[dns_obj(["a"]), dns_obj(["b"])]), eve("t1", SURI_TLS)]
    a, _, _ = normalize_hits(hits)
    b, _, _ = normalize_hits(json.loads(json.dumps(hits)))
    assert [e.model_dump() for e in a] == [e.model_dump() for e in b]
