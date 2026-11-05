"""Zeek analyzer logs (dns, http, ssl, x509, files, pe, ssh, notice, weird, signatures, intel and the application logs)
in every shipper shape normalize to the typed contracts their families share.

Fixtures are synthetic records in the published layouts (tests/fixtures/zeek_logs.py names the sources). Equality
across shapes is over everything a rule reads: family, time, sensor, caveats and every typed value; origins differ by
design. A shape is compared with Zeek's own record less the columns the catalog says that shape does not index, so a
column a shipper drops is never expected from it, and every column it keeps must type exactly as Zeek's does.
"""
import copy
import json

import pytest

from romulus.evidence.normalize import normalize_hits
from romulus.evidence.typed import NETWORK_OBSERVER_FAMILIES
from romulus.evidence.zeek import (
    ZEEK_ARGUMENT_WITHHELD,
    ZEEK_DUPLICATE,
    ZEEK_FIRST_HOST_ONLY,
    ZEEK_NORMALIZER,
    ZEEK_TIMEDOUT_FILE,
    ZEEK_X509_NAME_PARTS,
    normalize_plain_zeek,
    zeek_record,
)
from romulus.evidence.zeek_catalog import ANALYZER_LOGS, HEALTH_LOGS, SHAPES, lookup_log
from tests.fixtures import zeek_logs as zl

# These shared shape/field/secret checks apply to health records too; they remain
# separate from analyzer content in the production catalog.
LOGS = {log.name: log for log in (*ANALYZER_LOGS, *HEALTH_LOGS)}
# Natives a log's own step reads in a shape outside its catalog table (Security Onion writes both files layouts'
# identifiers to log.id.uid and Zeek 5.0's first hosts to source.ip and destination.ip)
STEP_READ = {("files", "security_onion"): {"uid", "conn_uids", "tx_hosts", "rx_hosts"}}
# A Community ID some shippers compute for a log whose record names no transport, and the list of logs Malcolm names on
# an smb_cmd row that carries its referenced file: compared on their own
NOT_COMPARED = {"network.community_id", "zeek.datasets"}


def normalize(h, *, sensor=zl.SENSOR, expect_clean=True):
    if h["_index"] == zl.INDEX["plain"]:
        return normalize_plain_zeek(h, sensor=sensor)
    events, skips, errors = normalize_hits([h])
    if expect_clean:
        assert (skips, errors) == ({}, []), (skips, errors)
        assert len(events) == 1
    return events[0]


def view(event) -> dict:
    """What a rule reads, less the caveat on a shipper's own loss (its test is below)."""
    caveats = [c for c in event.caveats if c != ZEEK_FIRST_HOST_ONLY]
    return {"family": event.family, "ts": event.ts, "host": event.host, "caveats": caveats,
            "normalizer": event.normalizer,
            "fields": {k: v.value for k, v in event.fields.items() if k not in NOT_COMPARED}}


def unwritten(log, shape: str) -> set[str]:
    """Zeek columns the shape does not index for this log, by the catalog."""
    written = {spec.native for spec in log.fields if shape in spec.paths}
    return {spec.native for spec in log.fields} - written - STEP_READ.get((log.name, shape), set())


def assert_same_across_shapes(row: zl.Row) -> dict:
    log = LOGS[row.log]
    typed = {shape: normalize(h) for shape, h in zl.in_every_shape(row).items()}
    for shape, event in typed.items():
        expected = normalize(zl.plain(row.without(*unwritten(log, shape)), f"ref-{shape}"))
        assert view(event) == view(expected), shape
    return typed


# ---- shape equality --------------------------------------------------------------------------------------------

LOGICAL = {**zl.ROWS, "files-zeek-5.0": zl.FILES_50,
           "ssl-zeek-4": zl.SSL.without("cert_chain_fps").with_(cert_chain_fuids=["Fcert000000000001",
                                                                                  "Fcert000000000002"]),
           "x509-zeek-4": zl.X509.without("fingerprint", "host_cert", "client_cert").with_(id="Fcert000000000001"),
           "dns-nxdomain": zl.DNS.with_(rcode=3, rcode_name="NXDOMAIN", answers=None, TTLs=None),
           "dns-no-reply": zl.DNS.without("rcode", "rcode_name", "answers", "TTLs", "rtt"),
           "ssl-resumed": zl.SSL.without("subject", "issuer", "cert_chain_fps").with_(resumed=True),
           "http-post": zl.HTTP.with_(method="POST", request_body_len=512, orig_fuids=["Fpost000000000001"],
                                      orig_mime_types=["application/octet-stream"], orig_filenames=["data.bin"]),
           "snmp-v3": zl.SNMP.with_(version="3", community="snmpuser")}


@pytest.mark.parametrize("name", sorted(LOGICAL))
def test_one_logical_record_types_the_same_in_every_shape(name):
    row = LOGICAL[name]
    log = LOGS[row.log]
    typed = assert_same_across_shapes(row)
    assert set(typed) == set(log.names)
    for event in typed.values():
        assert event.family == log.family and event.normalizer == ZEEK_NORMALIZER
        assert event.host == zl.SENSOR and event.get("observer.name") == zl.SENSOR
        assert event.get("observer.product") == "zeek" and event.get("zeek.log") == log.name
        assert event.family in NETWORK_OBSERVER_FAMILIES
        assert event.get("zeek.ts") == "2024-11-18T14:00:00.123000+00:00"
        assert ("host", zl.SENSOR, "observer") in event.entities()


@pytest.mark.parametrize("name", sorted(zl.ROWS))
def test_every_catalogued_path_of_a_full_record_is_read(name):
    """Each shape types every field it writes, from one of its own catalogued paths."""
    log = LOGS[name]
    for shape, h in zl.in_every_shape(zl.ROWS[name]).items():
        event = normalize(h)
        for spec in log.fields:
            if shape not in spec.paths or spec.typed.startswith("zeek.") or spec.native not in zl.ROWS[name].zeek:
                continue
            if spec.typed in ("app.arg", "irc.addl") and event.get("auth.cleartext_credentials_present"):
                continue
            assert event.has(spec.typed), (shape, spec.typed)
            origin = event.fields[spec.typed].origin.split(":", 1)[1].split("#")[0].split("+")[0]
            readable = {p.replace("original:", "event.original") for p in spec.paths[shape]}
            assert origin in readable or origin == "event.original", (shape, spec.typed, origin)


def test_shipper_variants_type_the_same():
    """Malcolm's text-log values, Filebeat's module field, a shipper that expanded Zeek's dotted keys, and a Security
    Onion record that did not pass its common pipeline."""
    for name, row in zl.ROWS.items():
        log = LOGS[name]
        reference = view(normalize(zl.malcolm(row, f"mc-{name}")))
        assert view(normalize(zl.malcolm(row, f"mc-text-{name}", text=True))) == reference, name
        if "elastic" in log.names:
            assert view(normalize(zl.elastic(row, f"fb-{name}", filebeat=True))) == \
                view(normalize(zl.elastic(row, f"el-{name}"))), name
        assert view(normalize(zl.plain(row, f"pl-x-{name}", expanded=True))) == \
            view(normalize(zl.plain(row, f"pl-{name}"))), name
        if "security_onion" in log.names:
            assert view(normalize(zl.security_onion(row, f"so-bare-{name}", bare=True))) == \
                view(normalize(zl.security_onion(row, f"so-{name}"))), name


def test_the_community_id_is_the_shippers_or_computed_from_the_records_own_transport():
    for name, row in zl.ROWS.items():
        log = LOGS[name]
        z = row.zeek
        transport = z.get("proto") or log.transport
        for shape, h in zl.in_every_shape(row).items():
            event = normalize(h)
            if not event.has("network.community_id"):
                assert transport is None or "id.orig_h" not in z or shape == "security_onion", (name, shape)
                continue
            origin = event.fields["network.community_id"].origin
            if shape == "plain":
                assert origin.endswith("#computed:community_id_v1"), name
            shipper_transport = transport or zl.SHIPPER_TRANSPORT.get(shape, {}).get(name)
            assert event.get("network.community_id") == zl.community_id(
                z["id.orig_h"], z["id.orig_p"], z["id.resp_h"], z["id.resp_p"], shipper_transport), (name, shape)


def test_a_transport_comes_from_zeeks_proto_or_from_an_analyzer_that_reads_only_one():
    dns = normalize(zl.plain(zl.DNS))
    assert dns.get("network.transport") == "udp" and dns.fields["network.transport"].origin == "pl-1:proto"
    http = normalize(zl.plain(zl.HTTP))
    assert http.get("network.transport") == "tcp"
    assert http.fields["network.transport"].origin.endswith("#derived:analyzer-transport")
    # ssl.log carries TLS over TCP, DTLS over UDP and QUIC's handshakes: only DTLS says which
    assert not normalize(zl.plain(zl.SSL)).has("network.transport")
    dtls = normalize(zl.plain(zl.SSL.with_(version="DTLSv12")))
    assert dtls.get("network.transport") == "udp" and dtls.get("tls.version") == ["DTLSv1.2"]
    # a shipper's constant (Elastic sets tcp on every http document) is never read as Zeek's
    assert "network.transport" not in json.dumps([spec.paths for spec in LOGS["http"].fields])


# ---- dns ---------------------------------------------------------------------------------------------------------

def test_a_dns_row_is_a_transaction_with_the_shared_question_answer_and_code_fields():
    for shape, h in zl.in_every_shape(zl.DNS).items():
        event = normalize(h)
        assert not event.has("dns.type"), shape          # Elastic's and Malcolm's own dns.type are never read
        assert (event.get("dns.question.name"), event.get("dns.question.names")) == \
            ("www.example.test", ["www.example.test"]), shape
        assert (event.get("dns.question.type"), event.get("dns.question.types")) == ("A", ["A"]), shape
        assert (event.get("dns.response_code"), event.get("dns.response_codes")) == ("NOERROR", ["NOERROR"])
        assert event.get("dns.answers") == [{"name": None, "type": None, "ttl": 300, "data": "www-cdn.example.test"},
                                            {"name": None, "type": None, "ttl": 60, "data": "192.0.2.80"}], shape
        assert event.get("dns.ttls") == [300, 60] and event.get("dns.id") == 4242, shape
        assert event.get("dns.header_flags") == ["RD", "RA"] and event.get("dns.rejected") is False, shape
        assert event.get("dns.question.class") == "INTERNET", shape


def test_dns_codes_without_a_mnemonic_take_the_generic_form():
    event = normalize(zl.plain(zl.DNS.with_(qtype=65399, qtype_name="query-65399", rcode=23,
                                            rcode_name="rcode-23")))
    assert event.get("dns.question.type") == "TYPE65399" and event.get("dns.response_code") == "RCODE23"
    assert event.fields["dns.question.type"].origin.endswith("qtype#derived:generic-mnemonic")
    no_name = normalize(zl.plain(zl.DNS.without("qtype_name")))
    assert no_name.get("dns.question.type") == "TYPE1"          # only the number: never a guessed mnemonic


def test_dns_answers_pair_with_ttls_only_when_zeek_wrote_one_for_each():
    event = normalize(zl.plain(zl.DNS.with_(TTLs=[300.0])))
    assert [a["ttl"] for a in event.get("dns.answers")] == [None, None] and event.get("dns.ttls") == [300]
    assert not normalize(zl.plain(zl.DNS.without("RA"))).has("dns.header_flags")   # one flag unknown: no list


# ---- http --------------------------------------------------------------------------------------------------------

def test_http_types_the_shared_request_fields_and_zeeks_entity_lists():
    for shape, h in zl.in_every_shape(zl.HTTP).items():
        event = normalize(h)
        assert (event.get("http.hostname"), event.get("url.original")) == \
            ("www.example.test", "/download/report.pdf?id=7"), shape
        assert (event.get("user_agent.original"), event.get("http.request.method")) == ("ExampleAgent/2.0", "GET")
        assert event.get("http.response.status_code") == 200 and event.get("http.trans_depth") == 1, shape
        assert event.get("http.response.body.bytes") == 48213, shape
        assert event.get("http.resp_mime_types") == ["application/pdf"], shape
        assert event.get("http.resp_fuids") == [zl.FUID_HTTP], shape
        assert not event.has("auth.cleartext_credentials_present"), shape


def test_malcolms_own_url_fields_are_never_read():
    """Malcolm's url.original is "http://" + host + uri and its url.full carries the password: only Zeek's columns
    are read."""
    h = zl.malcolm(zl.HTTP)
    assert h["_source"]["url"]["original"].startswith("http://")
    event = normalize(h)
    assert event.get("url.original") == "/download/report.pdf?id=7"
    assert event.fields["url.original"].origin.endswith(":zeek.http.uri")


# ---- ssl and x509 ------------------------------------------------------------------------------------------------

def test_ssl_types_the_shared_tls_contract_and_the_chain_fingerprints():
    for shape, h in zl.in_every_shape(zl.SSL).items():
        event = normalize(h)
        assert event.get("tls.version") == ["TLSv1.2"] and event.get("tls.client.server_name") == "www.example.test"
        assert event.get("tls.ja3") == ["0123456789abcdef0123456789abcdef"], shape
        assert event.get("tls.ja4") == ["t13d1516h2_8daaf6152771_b186095e22b6"], shape
        assert event.get("tls.server.cert_chain_fps") == [zl.FP_LEAF, zl.FP_CA], shape
        assert (event.get("tls.resumed"), event.get("tls.established")) == (False, True), shape
        [cert] = event.get("tls.server.certificates")
        assert cert["subject_cn"] == ["www.example.test"] and cert["issuer_on"] == ["Example Org"], shape
        assert cert["self_issued"] is False and cert["names_compared"] == "distinguished name", shape
        # ssl.log carries no validity or SHA-1: those are the x509 row's, joined by fingerprint later
        assert cert["not_before"] is None and cert["sha1"] is None, shape
        assert event.get("tls.server.subject_cn") == ["www.example.test"], shape


def test_ssl_before_zeek_4_2_names_its_chain_by_file_id():
    row = LOGICAL["ssl-zeek-4"]
    for shape, h in zl.in_every_shape(row).items():
        event = normalize(h)
        assert event.get("tls.server.cert_chain_fuids") == ["Fcert000000000001", "Fcert000000000002"], shape
        assert not event.has("tls.server.cert_chain_fps"), shape


def test_x509_rows_are_their_own_records_keyed_by_fingerprint():
    for shape, h in zl.in_every_shape(zl.X509).items():
        event = normalize(h)
        assert event.family == "x509_certificate" and event.get("x509.fingerprint") == zl.FP_LEAF, shape
        assert event.get("x509.not_before") == "2024-11-01T00:00:00+00:00", shape
        assert event.get("x509.not_after") == "2025-02-01T00:00:00+00:00", shape
        cert = event.get("x509.certificate")
        assert cert["subject_dn"] == "CN=www.example.test,O=Example Org,C=US" and cert["serial"] == "0a1b2c3d4e5f"
        assert cert["alt_names"] == ["www.example.test", "example.test"] and cert["self_issued"] is False, shape
        assert event.get("x509.self_issued") is False and event.get("x509.key_length") == 2048, shape
    old = normalize(zl.plain(LOGICAL["x509-zeek-4"]))
    assert old.get("file.fuid") == "Fcert000000000001" and not old.has("x509.fingerprint")
    selfsigned = normalize(zl.plain(zl.X509.with_(**{"certificate.issuer": zl.X509.zeek["certificate.subject"]})))
    assert selfsigned.get("x509.self_issued") is True


def test_an_ssl_row_whose_certificate_row_is_elsewhere_states_only_what_it_carries():
    """Zeek logs a certificate to x509.log once a day per sensor (relog_known_certificates_after), so the row of a
    session's certificate is often outside the hunt's window: the ssl row types its chain fingerprints and says
    nothing about the certificate row."""
    events, skips, errors = normalize_hits([zl.malcolm(zl.SSL, "ssl-alone")])
    assert (skips, errors) == ({}, []) and events[0].caveats == []
    assert events[0].get("tls.server.cert_chain_fps")[0] == zl.FP_LEAF


def test_x509_rows_never_feed_the_tls_session_rules():
    """An x509 row names no connection: as a tls_session it would count as an unjudged TLS record in every hunt."""
    assert LOGS["x509"].family == "x509_certificate" and LOGS["ssl"].family == "tls_session"
    assert "x509_certificate" in NETWORK_OBSERVER_FAMILIES


def test_shipper_rewrites_of_an_escaped_comma_in_a_name_are_their_own():
    """Zeek escapes a comma inside a name value ("O=Acme\\, Inc."); Elastic's gsub removes the escape with the comma,
    Malcolm's kv decoding turns it into a plain comma. The names typed are those the shipper kept."""
    row = zl.SSL.with_(subject="CN=a.example.test,O=Acme\\, Inc.,C=US")
    plain = normalize(zl.plain(row)).get("tls.server.subject")
    elastic = normalize(zl.elastic(row)).get("tls.server.subject")
    assert plain == "CN=a.example.test,O=Acme\\, Inc.,C=US" and elastic == "CN=a.example.test,O=Acme Inc.,C=US"


# ---- files and pe ------------------------------------------------------------------------------------------------

def test_files_rows_of_zeek_5_1_name_their_connection_and_of_5_0_their_hosts():
    for shape, h in zl.in_every_shape(zl.FILES).items():
        event = normalize(h)
        assert event.get("zeek.uid") == zl.UID_HTTP and event.get("source.ip") == zl.CLIENT, shape
        assert not event.has("file.conn_uids") and not event.has("file.tx_hosts"), shape
    for shape, h in zl.in_every_shape(zl.FILES_50).items():
        event = normalize(h)
        assert event.get("file.conn_uids") == [zl.UID_HTTP], shape
        assert event.get("file.tx_hosts") == [zl.SERVER] and event.get("file.rx_hosts") == [zl.CLIENT], shape
        assert not event.has("zeek.uid") and not event.has("source.ip"), shape
        assert (ZEEK_FIRST_HOST_ONLY in event.caveats) is (shape in ("elastic", "security_onion")), shape


def test_files_type_hashes_sizes_and_the_analyzer_that_carried_them():
    for shape, h in zl.in_every_shape(zl.FILES).items():
        event = normalize(h)
        assert event.get("file.fuid") == zl.FUID_HTTP and event.get("file.source") == "HTTP", shape
        assert event.get("file.mime_type") == "application/x-dosexec" and event.get("file.name") == "update.exe"
        assert (event.get("file.seen_bytes"), event.get("file.total_bytes")) == (48213, 48213), shape
        assert event.get("file.hash.md5") == "0c" * 16 and event.get("file.is_orig") is False, shape
        assert event.get("file.analyzers") == ["MD5", "PE", "SHA1", "SHA256"], shape
        assert event.caveats == [], shape
    for native, canonical in (("SSL", "TLS"), ("FTP_DATA", "FTP"), ("SPICY_LDAP_TCP", "LDAP"), ("SMB", "SMB")):
        for shape, h in zl.in_every_shape(zl.FILES.with_(source=native)).items():
            assert normalize(h).get("file.source") == canonical, (native, shape)


def test_missing_overflow_and_timed_out_file_bytes_are_truncation_caveats():
    row = zl.FILES.with_(missing_bytes=4096, overflow_bytes=512, timedout=True, seen_bytes=40000)
    for shape, h in zl.in_every_shape(row).items():
        caveats = normalize(h).caveats
        assert any(c.startswith("Zeek did not see 4096 bytes") for c in caveats), shape
        assert any(c.startswith("512 bytes of this file arrived beyond") for c in caveats), shape
        assert ZEEK_TIMEDOUT_FILE in caveats, shape


def test_pe_rows_type_the_header_flags_and_the_compile_time():
    for shape, h in zl.in_every_shape(zl.PE).items():
        event = normalize(h)
        assert event.family == "file_transfer" and event.get("file.fuid") == zl.FUID_HTTP, shape
        assert event.get("pe.is_exe") is True and event.get("pe.uses_code_integrity") is False, shape
        assert event.get("pe.compile_ts") == "2023-11-14T22:13:20+00:00", shape
        assert event.get("pe.section_names")[0] == ".text", shape


# ---- ssh ---------------------------------------------------------------------------------------------------------

def test_ssh_banners_give_the_shared_software_and_protocol_fields():
    for shape, h in zl.in_every_shape(zl.SSH).items():
        event = normalize(h)
        assert (event.get("ssh.client.software"), event.get("ssh.client.proto_version")) == ("OpenSSH_9.6", "2.0")
        assert event.get("ssh.server.software") == "OpenSSH_8.9p1", shape        # comments after the space dropped
        assert event.get("ssh.server.banner") == "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6", shape
        assert event.get("ssh.hassh") == ["aa11bb22cc33dd44ee55ff6600778899"], shape
        assert (event.get("ssh.auth_success"), event.get("ssh.auth_attempts")) == (False, 3), shape
        assert event.get("ssh.direction") == "OUTBOUND", shape
    assert not normalize(zl.plain(zl.SSH.with_(client="not a banner"))).has("ssh.client.software")


# ---- alerts ------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("name,kind,signature", [("notice", "notice", "SSL::Invalid_Server_Cert"),
                                                 ("weird", "weird", "bad_TCP_checksum"),
                                                 ("signatures", "signature", "synthetic-sig-1"),
                                                 ("intel", "intel", None)])
def test_notice_weird_signatures_and_intel_are_zeek_alerts(name, kind, signature):
    for shape, h in zl.in_every_shape(zl.ROWS[name]).items():
        event = normalize(h)
        assert event.family == "net_alert" and event.get("alert.provider") == "zeek", shape
        assert event.get("alert.kind") == kind and event.get("alert.signature") == signature, shape
        assert not event.has("alert.severity") and not event.has("alert.category"), shape   # Zeek writes neither
    intel = normalize(zl.plain(zl.INTEL))
    assert (intel.get("intel.indicator"), intel.get("intel.seen_where")) == ("listed.example.test",
                                                                            "SSL::IN_SERVER_NAME")


def test_a_notice_without_a_connection_takes_its_addresses_from_src_dst_and_p():
    row = zl.NOTICE.without("uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p")
    for shape in ("malcolm", "elastic", "plain"):
        event = normalize(zl.WRITERS[shape](row, f"nc-{shape}"))
        assert (event.get("source.ip"), event.get("destination.ip"), event.get("destination.port")) == \
            (zl.CLIENT, zl.SERVER, 443), shape


def test_malcolms_reading_of_a_notice_message_is_not_typed_as_an_address():
    """Malcolm fills source.ip of a notice without a connection from its message text: only Zeek's src is read."""
    h = zl.malcolm(zl.NOTICE.without("uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "src", "dst"),
                   "nc-msg")
    h["_source"]["source"] = {"ip": "192.0.2.200"}
    event = normalize(h)
    assert not event.has("source.ip") and not event.has("destination.ip")


# ---- application transactions ---------------------------------------------------------------------------------------

def test_application_logs_type_command_argument_and_reply_as_app_tx():
    expected = {"ftp": ("RETR", "ftp://203.0.113.10/pub/tool.bin", "Transfer complete."),
                "mysql": ("query", "SELECT 1", "OK"), "tds": ("SQLBatch", None, None),
                "postgresql": ("simple_query", "SELECT 1", "command_complete"),
                "redis": ("GET", "session:42", "cached"), "irc": ("USER", "synth", None),
                "sip": ("INVITE", "sip:bob@example.net", "OK"), "tunnel": ("DISCOVER", None, None),
                "smtp": (None, None, "250 2.0.0 Ok: queued"), "socks": (None, None, "succeeded"),
                "radius": (None, None, "Welcome"), "snmp": (None, None, None)}
    for name, (command, arg, reply) in expected.items():
        for shape, h in zl.in_every_shape(zl.ROWS[name]).items():
            event = normalize(h)
            assert event.family == "app_tx" and event.get("app.protocol") == name, (name, shape)
            assert (event.get("app.command"), event.get("app.arg"), event.get("app.reply")) == \
                (command, arg, reply), (name, shape)
    assert normalize(zl.plain(zl.RADIUS)).get("app.success") is True
    assert normalize(zl.plain(zl.RADIUS.with_(result="failed"))).get("app.success") is False
    assert normalize(zl.plain(zl.TUNNEL)).get("tunnel.type") == "IP"


def test_zeeks_unknown_ftp_user_is_no_user():
    assert not normalize(zl.plain(zl.FTP.with_(user="<unknown>"))).has("user.name")
    assert normalize(zl.plain(zl.FTP)).get("user.name") == "ftpuser1"


def test_an_snmp_community_is_a_credential_whatever_the_sessions_version_column_says():
    """Zeek writes the community only from an SNMPv1 or v2c message's header, and the version column from the
    session's first message: a session that began with SNMPv3 can still carry a v2c community."""
    for name in ("snmp", "snmp-v3"):
        row = LOGICAL.get(name, zl.SNMP)
        for shape, h in zl.in_every_shape(row).items():
            event = normalize(h)
            assert event.get("auth.cleartext_credentials_present") is True, (name, shape)
            assert not event.has("user.name") and "snmpuser" not in event.model_dump_json(), (name, shape)


def test_malcolm_drops_a_rows_count_of_zero():
    row = zl.MYSQL.with_(rows=0)
    assert normalize(zl.plain(row)).get("app.rows") == 0
    assert not normalize(zl.malcolm(row)).has("app.rows")


# ---- malformed rows ------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("name,h,outcome", zl.malformed_rows(), ids=[r[0] for r in zl.malformed_rows()])
def test_malformed_rows_are_errors_skips_or_listed_fields_never_crashes(name, h, outcome):
    if h["_index"] == zl.INDEX["plain"]:
        try:
            events, skips, errors = [normalize_plain_zeek(h, sensor=zl.SENSOR)], {}, []
        except (ValueError, TypeError) as e:
            events, skips, errors = [], {}, [(h["_id"], str(e))]
    else:
        events, skips, errors = normalize_hits([h])
    if outcome == "error":
        assert events == [] and skips == {} and len(errors) == 1
    elif outcome == "skip":
        assert events == [] and errors == [] and sum(skips.values()) == 1
    elif outcome == "absent":
        assert errors == [] and len(events) == 1 and not events[0].has("parse.malformed")
        for typed in ("user_agent.original", "http.resp_mime_types", "http.response.status_message"):
            assert not events[0].has(typed), typed
    else:
        assert errors == [] and len(events) == 1
        assert outcome in events[0].get("parse.malformed"), events[0].get("parse.malformed")
        assert events[0].has("zeek.ts") and events[0].has("zeek.log")        # the rest of the record is kept


# ---- identity and duplicates ---------------------------------------------------------------------------------------

def test_copies_of_one_row_merge_and_rows_sharing_a_connection_stay_apart():
    a, b = zl.plain(zl.DNS, "copy-a"), {**zl.plain(zl.DNS, "copy-b"), "_index": "zeek-json-other"}
    one, two = normalize_plain_zeek(a, sensor=zl.SENSOR), normalize_plain_zeek(b, sensor=zl.SENSOR)
    assert one.id == two.id and one.raw != two.raw
    events, skips, errors = normalize_hits([zl.malcolm(zl.HTTP, "m-a"), {**zl.malcolm(zl.HTTP, "m-b"),
                                                                          "_index": "arkime_sessions3-x"}])
    assert errors == [] and skips == {ZEEK_DUPLICATE: 1} and len(events) == 1
    assert sorted(r.native_id for r in events[0].raw) == ["m-a", "m-b"]
    # the same connection's next transaction (its own trans_depth / trans_id) is another record
    second = normalize(zl.plain(zl.HTTP.with_(trans_depth=2, uri="/next"), "second"))
    assert second.id != normalize(zl.plain(zl.HTTP, "first")).id
    retry = normalize(zl.plain(zl.DNS.with_(trans_id=4243), "retry"))
    assert retry.id != one.id
    # one sensor's copy is not another sensor's
    assert normalize(zl.plain(zl.DNS, "s2"), sensor="sensor-zeek-02").id != one.id


def test_files_and_x509_rows_are_keyed_by_their_file_and_certificate():
    later = zl.Row("x509", zl.X509.zeek, ts=zl.T0 + 3600)
    assert normalize(zl.plain(later)).id != normalize(zl.plain(zl.X509)).id          # relogged later: its own row
    events, skips, _ = normalize_hits([zl.malcolm(zl.X509, "x-a"), {**zl.malcolm(zl.X509, "x-b"),
                                                                     "_index": "arkime_sessions3-x"}])
    assert len(events) == 1 and skips == {ZEEK_DUPLICATE: 1}
    events, skips, _ = normalize_hits([zl.malcolm(zl.FILES, "f-a"), zl.malcolm(zl.FILES.with_(fuid="Fother"), "f-b")])
    assert len(events) == 2 and skips == {}


def test_duplicates_are_merged_within_one_batch_only():
    """A batch's duplicate map holds that batch's records alone (bounded by the batch size); copies in different
    batches keep one event id each, and the store keeps one row per id."""
    first, _, _ = normalize_hits([zl.malcolm(zl.DNS, "b1")])
    second, _, _ = normalize_hits([zl.malcolm(zl.DNS, "b2")])
    assert first[0].id == second[0].id


# ---- secrets -------------------------------------------------------------------------------------------------------

CREDENTIAL_LOGS = {"http", "ftp", "socks", "snmp", "irc", "redis", "mysql", "postgresql", "ldap", "ldap_search",
                   "software"}
# credential-bearing rows whose column the shipper does not index (its Zeek line is kept whole, never parsed)
NOT_INDEXED = {"ldap.61-security_onion": "Security Onion indexes Zeek 7's singular ldap columns only",
               "software-security_onion": "Security Onion indexes no software url"}


@pytest.mark.parametrize("name,h", zl.secret_rows(), ids=[r[0] for r in zl.secret_rows()])
def test_no_password_value_reaches_a_typed_event_caveat_error_or_skip(name, h):
    log = name.split("-")[0].split(".")[0]
    if h["_index"] == zl.INDEX["plain"]:
        events, skips, errors = [normalize_plain_zeek(h, sensor=zl.SENSOR)], {}, []
    else:
        events, skips, errors = normalize_hits([h])
    assert errors == [] and len(events) == 1
    [event] = events
    assert zl.SECRET not in event.model_dump_json()
    assert zl.SECRET not in json.dumps([skips, errors, event.caveats])
    # the column is found where the shape keeps it as a column; a Zeek line kept whole (Security Onion's message) is
    # never parsed, so nothing is found there (and Elastic's line is read only for the columns it alone carries; its
    # known_* pipelines keep no column they do not rename)
    found = name.endswith(("-malcolm-column", "-plain-column")) or (
        name.endswith("-elastic-column") and "elastic" in LOGS[log].log_objects) or (
        log in CREDENTIAL_LOGS and not name.endswith("-column") and name not in NOT_INDEXED)
    if found:
        assert event.get("auth.cleartext_credentials_present") is True, name
        assert event.fields["auth.cleartext_credentials_present"].origin.endswith("#present")
    # a record that cannot be read names the path, never the value
    broken = copy.deepcopy(h)
    broken["_id"] = f"{h['_id']}-broken"
    if broken["_index"] == zl.INDEX["plain"]:
        broken["_source"]["ts"] = zl.SECRET
        with pytest.raises(ValueError) as caught:
            normalize_plain_zeek(broken, sensor=zl.SENSOR)
        assert zl.SECRET not in str(caught.value)
    else:
        broken["_source"]["@timestamp"] = zl.SECRET
        broken["_source"].pop("firstPacket", None)
        events, skips, errors = normalize_hits([broken])
        assert events == [] and len(errors) == 1 and zl.SECRET not in json.dumps([skips, errors])


def test_every_log_and_shape_has_a_secret_row():
    names = {name for name, _ in zl.secret_rows()}
    for log in ANALYZER_LOGS:
        for shape in log.names:
            assert f"{log.name}-{shape}-column" in names, (log.name, shape)
    for log in CREDENTIAL_LOGS:
        assert {f"{log}-{shape}" for shape in zl.shapes_of(log)} <= names, log


# The commands whose argument is a credential (or may hold one), from the protocols' own definitions:
# (log, Zeek's command column, the command, the columns the credential travels in, what is typed: present/unknown)
S = zl.SECRET
COMMAND_CASES = [
    # RFC 959 PASS and ACCT, RFC 2228 ADAT
    ("ftp", "command", "PASS", {"arg": S}, "present"),
    ("ftp", "command", "ACCT", {"arg": S}, "present"),
    ("ftp", "command", "ADAT", {"arg": S}, "present"),
    # RFC 2812 PASS, OPER <name> <password>, JOIN <channel> <key> (Zeek writes the key to addl), IRCv3 SASL
    ("irc", "command", "PASS", {"value": S}, "present"),
    ("irc", "command", "OPER", {"value": f"admin {S}", "addl": S}, "present"),
    ("irc", "command", "JOIN", {"value": "#ops", "addl": f" with channel key: '{S}'"}, "present"),
    ("irc", "command", "AUTHENTICATE", {"value": S}, "present"),
    ("irc", "command", "NICKSERV", {"value": "IDENTIFY", "addl": S}, "present"),
    ("irc", "command", "PRIVMSG", {"value": "NickServ", "addl": f"IDENTIFY {S}"}, "unknown"),
    # AUTH [username] password; HELLO 3 AUTH user pass; MIGRATE ... AUTH; CONFIG SET requirepass; ACL SETUSER >pass
    ("redis", "cmd.name", "AUTH", {"cmd.key": S}, "present"),
    ("redis", "cmd.name", "HELLO", {"cmd.key": S}, "unknown"),
    ("redis", "cmd.name", "MIGRATE", {"cmd.key": S}, "unknown"),
    ("redis", "cmd.name", "CONFIG", {"cmd.key": S}, "unknown"),
    ("redis", "cmd.name", "ACL", {"cmd.key": S}, "unknown"),
    # COM_CHANGE_USER's raw authentication data; SQL that assigns a password
    ("mysql", "cmd", "change_user", {"arg": S}, "unknown"),
    ("mysql", "cmd", "query", {"arg": f"ALTER USER 'app'@'%' IDENTIFIED BY '{S}'"}, "present"),
    ("mysql", "cmd", "query", {"arg": f"SET PASSWORD FOR 'app'@'%' = '{S}'"}, "present"),
    ("mysql", "cmd", "query", {"arg": f"CHANGE MASTER TO MASTER_PASSWORD='{S}'"}, "present"),
    ("postgresql", "frontend", "simple_query", {"frontend_arg": f"ALTER ROLE app WITH PASSWORD '{S}'"}, "present"),
    ("postgresql", "frontend", "simple_query", {"frontend_arg": f"CREATE USER app PASSWORD '{S}'"}, "present"),
]
# how a command column can arrive: as Zeek wrote it, lowercased, padded, or not readable as one command at all
SPELLINGS = {"as-written": lambda c: c, "lower": str.lower, "leading-space": lambda c: f" {c}",
             "trailing-space": lambda c: f"{c} ", "list": lambda c: [c], "missing": lambda c: None,
             "number": lambda c: 7}


def _command_hits(log: str, column: str, command, values: dict) -> dict[str, dict]:
    row = zl.ROWS[log].with_(**values)
    row = row.without(column) if command is None else row.with_(**{column: command})
    return zl.in_every_shape(row, f"cmd-{log}-")


@pytest.mark.parametrize("case", COMMAND_CASES, ids=[f"{c[0]}-{c[2]}-{c[4]}" for c in COMMAND_CASES])
@pytest.mark.parametrize("spelling", sorted(SPELLINGS))
def test_a_credential_command_never_keeps_its_argument_in_any_shape_or_spelling(case, spelling):
    log, column, command, values, kind = case
    for shape, h in _command_hits(log, column, SPELLINGS[spelling](command), values).items():
        events, skips, errors = normalize_hits([h]) if shape != "plain" else (
            [normalize_plain_zeek(h, sensor=zl.SENSOR)], {}, [])
        assert errors == [] and len(events) == 1, (shape, errors)
        [event] = events
        assert S not in event.model_dump_json() and S not in json.dumps([skips, event.caveats]), (shape, spelling)
        readable = spelling in ("as-written", "lower", "leading-space", "trailing-space")
        flag = "auth.cleartext_credentials_present" if readable and kind == "present" else \
            "auth.cleartext_credentials_unknown"
        assert event.get(flag) is True, (shape, spelling, flag)
        if not readable:                    # fail closed: no argument of an unreadable command is kept
            assert not event.has("app.arg") and not event.has("irc.addl"), (shape, spelling)
            assert ZEEK_ARGUMENT_WITHHELD in event.caveats


def test_other_commands_keep_their_arguments():
    for log, column, command, values in (("ftp", "command", "RETR", {"arg": "ftp://203.0.113.10/pub/tool.bin"}),
                                         ("irc", "command", "PRIVMSG", {"value": "#ops", "addl": "hello"}),
                                         ("redis", "cmd.name", "GET", {"cmd.key": "session:42"}),
                                         ("mysql", "cmd", "query", {"arg": "SELECT password FROM users"}),
                                         ("postgresql", "frontend", "simple_query", {"frontend_arg": "SELECT 1"})):
        for shape, h in _command_hits(log, column, command, values).items():
            event = normalize(h)
            assert event.has("app.arg"), (log, shape)
            assert not event.has("auth.cleartext_credentials_present"), (log, shape)
            assert not event.has("auth.cleartext_credentials_unknown"), (log, shape)


def test_a_credential_command_without_its_argument_still_says_one_was_sent():
    for shape, h in zl.in_every_shape(zl.REDIS.with_(**{"cmd.name": "AUTH"}).without("cmd.key")).items():
        event = normalize(h)
        assert event.get("auth.cleartext_credentials_present") is True, shape
        assert event.fields["auth.cleartext_credentials_present"].origin.endswith("#auth-command#present"), shape


USERINFO_CASES = [
    ("http", {"uri": f"http://alice:{S}@proxy.example.test/x"}, "url.original", "http://proxy.example.test/x"),
    ("http", {"referrer": f"https://alice:{S}@www.example.test/"}, "http.request.referrer",
     "https://www.example.test/"),
    ("http", {"host": f"alice:{S}@www.example.test"}, "http.hostname", "www.example.test"),
    ("ftp", {"command": "RETR", "arg": f"ftp://alice:{S}@203.0.113.10/pub/tool.bin"}, "app.arg",
     "ftp://203.0.113.10/pub/tool.bin"),
    ("sip", {"uri": f"sip:bob:{S}@example.net"}, "app.arg", "sip:bob@example.net"),
    ("sip", {"request_from": f"<sip:alice:{S}@example.test>"}, "sip.request_from", "<sip:alice@example.test>"),
    ("intel", {"seen.indicator": f"http://alice:{S}@listed.example.test/"}, "intel.indicator",
     "http://listed.example.test/"),
]


@pytest.mark.parametrize("log,values,typed,expected", USERINFO_CASES, ids=[f"{c[0]}-{c[2]}" for c in USERINFO_CASES])
def test_a_uris_userinfo_is_removed_and_its_credential_flagged(log, values, typed, expected):
    for shape, h in zl.in_every_shape(zl.ROWS[log].with_(**values), "ui-").items():
        event = normalize(h)
        assert S not in event.model_dump_json(), (shape, typed)
        assert event.get(typed) == expected, (shape, event.get(typed))
        assert event.get("auth.cleartext_credentials_present") is True, shape
        assert "#derived:" in event.fields[typed].origin, shape


def test_a_user_alone_in_a_uri_is_removed_and_flagged_as_possibly_a_credential():
    event = normalize(zl.plain(zl.HTTP.with_(referrer="https://ghp_token0123@git.example.test/repo")))
    assert event.get("http.request.referrer") == "https://git.example.test/repo"
    assert event.get("auth.cleartext_credentials_unknown") is True and "ghp_token" not in event.model_dump_json()


def test_rows_differing_only_in_a_withheld_credential_stay_apart_and_copies_of_one_document_merge():
    # Zeek logs an AUTH row with no key (its parser types a key only for commands that have one): five attempts in
    # one connection and one millisecond are five identical rows, and each is its own document
    keyless = zl.REDIS.without("cmd.key").with_(**{"cmd.name": "AUTH", "success": False,
                                                   "reply.value": "WRONGPASS invalid username-password pair"})
    for shape in zl.shapes_of("redis"):
        attempts = [zl.WRITERS[shape](keyless, f"auth-{shape}-{i}") for i in range(5)]
        events = [normalize(h) for h in attempts]
        assert len({e.id for e in events}) == 5, shape
        assert all(e.get("auth.cleartext_credentials_present") is True for e in events), shape
    attempts = [zl.malcolm(zl.REDIS.with_(**{"cmd.name": "AUTH", "cmd.key": f"guess-{i}", "success": False,
                                              "reply.value": "WRONGPASS"}), f"auth-{i}") for i in range(5)]
    events, skips, errors = normalize_hits(attempts)
    assert errors == [] and skips == {} and len(events) == 5
    assert len({e.id for e in events}) == 5 and all(len(e.raw) == 1 for e in events)
    tries = [zl.plain(zl.FTP.with_(command="PASS", arg=f"guess-{i}", reply_code=530), f"pass-{i}") for i in range(5)]
    assert len({normalize_plain_zeek(h, sensor=zl.SENSOR).id for h in tries}) == 5
    # the same document read twice (overlapping pages) is one record
    events, skips, _ = normalize_hits([attempts[0], attempts[0]])
    assert len(events) == 1 and skips == {ZEEK_DUPLICATE: 1}
    # rows that withheld nothing keep their logical identity: copies in two indices merge
    events, skips, _ = normalize_hits([zl.malcolm(zl.REDIS, "get-a"), {**zl.malcolm(zl.REDIS, "get-b"),
                                                                        "_index": "arkime_sessions3-x"}])
    assert len(events) == 1 and skips == {ZEEK_DUPLICATE: 1}


def test_elastic_x509_rows_without_their_zeek_line_type_names_from_the_attribute_split():
    for original in (True, False):
        event = normalize(zl.elastic(zl.X509, f"x509-{original}", original=original))
        cert = event.get("x509.certificate")
        assert cert["subject_cn"] == ["www.example.test"] and cert["issuer_on"] == ["Example Org"], original
        assert cert["self_issued"] is False, original
        if original:
            assert cert["subject_dn"] == "CN=www.example.test,O=Example Org,C=US"
            assert ZEEK_X509_NAME_PARTS not in event.caveats
        else:
            assert cert["subject_dn"] is None and cert["names_compared"] == "CN and O"
            assert ZEEK_X509_NAME_PARTS in event.caveats and not event.has("x509.subject")
    selfsigned = zl.X509.with_(**{"certificate.issuer": zl.X509.zeek["certificate.subject"]})
    assert normalize(zl.elastic(selfsigned, "x509-self", original=False)).get("x509.self_issued") is True


def test_credential_paths_are_never_catalogued_as_typed_values():
    """The columns that carry a credential are only ever checked for presence."""
    for log in ANALYZER_LOGS:
        for spec in log.fields:
            assert "password" not in spec.native, (log.name, spec.typed)
            for shape, paths in spec.paths.items():
                assert not any("password" in path or path == "url.full" for path in paths), (log.name, shape)
                assert not set(paths) & set(log.secrets.get(shape, ())), (log.name, spec.typed, shape)


# ---- recognition ---------------------------------------------------------------------------------------------------

def test_each_shipper_name_of_a_log_is_recognized_in_its_own_shape():
    assert lookup_log("elastic", "signature") is LOGS["signatures"] and lookup_log("elastic", "signatures") is None
    assert lookup_log("security_onion", "file") is LOGS["files"] and lookup_log("malcolm", "file") is None
    for name in ("tds", "postgresql", "redis"):
        assert lookup_log("elastic", name) is None
    for name in ("postgresql", "redis"):
        assert lookup_log("security_onion", name) is None
    for name, row in zl.ROWS.items():
        for shape, h in zl.in_every_shape(row).items():
            if shape == "plain":
                continue
            record = zeek_record(h["_source"])
            assert (record.shape, record.log) == (shape, LOGS[name]), (name, shape)
    assert set(SHAPES) == set(zl.SHAPES)
