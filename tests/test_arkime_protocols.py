"""Synthetic Arkime SPI fields defined by official parser registrations.

https://github.com/arkime/arkime/blob/main/capture/parsers/smb.c
https://github.com/arkime/arkime/blob/main/capture/parsers/krb5.c
https://github.com/arkime/arkime/blob/main/capture/parsers/ldap.c
https://github.com/arkime/arkime/blob/main/capture/parsers/tls.c
https://github.com/arkime/arkime/blob/main/capture/parsers/http.c
Sessions contain independent sets; fixtures never imply tuple pairing or transaction counts.
"""
import pytest

from romulus.evidence.normalize import normalize_hits
from tests.test_arkime_sessions import session


@pytest.mark.parametrize("provider", [None, "arkime", "suricata"])
@pytest.mark.parametrize("filename", ["filename", "fn"])
def test_session_keeps_unpaired_protocol_lists_in_one_aggregate(provider, filename):
    raw = session("spi")
    src = raw["_source"]
    src.update(smb={"share": [r"\\DC01\DATA"], filename: ["b.txt", "a.txt"],
                    "user": ["alice", "bob"], "host": ["WS01"], "domain": ["EXAMPLE"]},
               krb5={"cname": ["alice", "bob"], "sname": ["cifs/server"], "realm": ["EXAMPLE.TEST"]},
               ldap={"authtype": ["simple", "sasl"], "bindname": ["CN=reader"]})
    if provider:
        src["event"] = {"provider": provider}
    events, skips, errors = normalize_hits([raw])
    assert not skips and not errors and len(events) == 1
    e = events[0]
    assert e.family == "net_session" and e.normalizer == "arkime@1"
    assert e.get("smb.name") == ["a.txt", "b.txt"]
    assert e.get("smb.share") == ["DATA"]
    assert e.get("ntlm.username") == ["alice", "bob"]
    assert e.get("ntlm.hostname") == ["WS01"]
    assert e.get("smb.host") == ["DC01"]
    assert e.get("kerberos.client_name") == ["alice", "bob"]
    assert e.get("kerberos.service") == ["cifs/server"]
    assert e.get("ldap.bind_type") == ["sasl", "simple"]
    assert e.get("ldap.objects") == ["CN=reader"]
    assert not e.has("smb.action") and not e.has("auth.encryption_type")
    assert not e.has("auth.target_account")
    assert any("unpaired" in c for c in e.caveats)


@pytest.mark.parametrize("protocol,expected", [(["tcp", "tls"], ["server.example.test"]),
                                                (["tcp", "http", "tls"], None), (["tcp", "http"], None)])
def test_sni_shared_storage_only_attributable_on_tls_only_session(protocol, expected):
    raw = session("tls")
    raw["_source"].update(protocol=protocol, http={"host": ["server.example.test"]})
    events, skips, errors = normalize_hits([raw])
    assert not skips and not errors
    assert events[0].get("tls.client.server_name") == expected
    assert events[0].get("http.hostname") == ["server.example.test"]
    if "http" in protocol and "tls" in protocol:
        assert any("SNI" in c and "ambiguous" in c for c in events[0].caveats)


def test_http_header_names_do_not_pair_with_values_or_become_observed_body_size():
    raw = session("http")
    raw["_source"].update(http={"request-referer": ["https://example.test/"],
        "request-origin": ["https://example.test"], "request-content-length": [100],
        "requestHeader": ["authorization", "content-length"], "requestHeaderValue": ["secret", "100"]})
    events, skips, errors = normalize_hits([raw])
    assert not skips and not errors
    e = events[0]
    assert e.get("http.request.referrer") == ["https://example.test/"]
    assert e.get("http.request.origin") == ["https://example.test"]
    assert not e.has("http.request.body.bytes")
    assert "secret" not in repr(e.fields)
    assert any("size" in c for c in e.caveats)


def test_malformed_protocol_value_is_explicit_and_not_a_plausible_list():
    raw = session("bad")
    raw["_source"]["smb"] = {"filename": ["ok", 5]}
    events, skips, errors = normalize_hits([raw])
    assert not skips and not errors
    assert events[0].get("parse.malformed") == ["smb.filename"]
    assert not events[0].has("smb.name")


@pytest.mark.parametrize("secret_path", ["request-referer", "request-authorization", "requestHeaderValue"])
def test_arkime_credentials_masked_in_stored_raw_without_changing_unrelated_values(secret_path):
    import hashlib
    import json

    from romulus.evidence.raw_scrub import clean_source
    raw = session("credentials")
    value = "https://alice:credential-secret@example.test/" if secret_path == "request-referer" else "credential-secret"
    raw["_source"]["http"] = {secret_path: [value], "requestHeader": ["authorization"], "statuscode": [200]}
    events, skips, errors = normalize_hits([raw])
    assert not skips and not errors
    clean = clean_source(raw["_source"])
    assert "credential-secret" not in json.dumps(clean)
    assert clean["http"]["statuscode"] == [200]
    assert "credential-secret" in json.dumps(raw["_source"])
    digest = hashlib.sha256(json.dumps(clean, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    assert events[0].raw[0].digest == digest


@pytest.mark.parametrize("password", [False, True])
def test_uri_userinfo_presence_certainty_matches_shared_zeek_contract(password):
    raw = session("userinfo")
    userinfo = "alice:secret" if password else "token"
    raw["_source"]["http"] = {"request-referer": [f"https://{userinfo}@example.test/"]}
    events, skips, errors = normalize_hits([raw])
    assert not skips and not errors
    e = events[0]
    assert e.get("auth.cleartext_credentials_present") is (True if password else None)
    assert e.get("auth.cleartext_credentials_unknown") is (None if password else True)


@pytest.mark.parametrize("case", ["smb", "ntlm", "kerberos", "ldap", "http", "tls"])
def test_arkime_shared_values_equal_zeek_without_pairing_or_transaction_fanout(case):
    from romulus.evidence.zeek import normalize_plain_zeek
    from tests.fixtures import zeek_logs as zl
    raw = session("parity")
    if case == "smb":
        raw["_source"]["smb"] = {"share": [zl.SHARE], "filename": [zl.SMB_FILES.zeek["name"]]}
        row, keys = zl.SMB_FILES, {"smb.path", "smb.host", "smb.share", "smb.name"}
    elif case == "ntlm":
        raw["_source"]["smb"] = {"user": ["alice"], "domain": ["EXAMPLE"], "host": ["WS01"]}
        row, keys = zl.NTLM, {"ntlm.username", "ntlm.domain", "ntlm.hostname"}
    elif case == "kerberos":
        raw["_source"]["krb5"] = {"cname": ["alice"], "sname": ["cifs/server"], "realm": ["EXAMPLE.TEST"]}
        row, keys = zl.KERBEROS.with_(service="cifs/server"), {"kerberos.client_name", "kerberos.service"}
    elif case == "ldap":
        raw["_source"]["ldap"] = {"authtype": ["sasl"], "bindname": [zl.LDAP.zeek["object"]]}
        row, keys = zl.LDAP, {"ldap.bind_type", "ldap.objects"}
    elif case == "http":
        raw["_source"]["http"] = {"request-referer": ["https://example.test/"], "request-origin": ["https://example.test"]}
        row, keys = zl.HTTP.with_(referrer="https://example.test/", origin="https://example.test"), {
            "http.request.referrer", "http.request.origin"}
    else:
        raw["_source"].update(protocol=["tcp", "tls"], http={"host": ["server.example.test"]})
        row, keys = zl.SSL.with_(server_name="server.example.test"), {"tls.client.server_name"}
    z = normalize_plain_zeek(zl.plain(row), sensor=zl.SENSOR)
    events, skips, errors = normalize_hits([raw])
    assert not skips and not errors and len(events) == 1
    assert events[0].family == "net_session"
    for key in keys:
        expected = z.get(key)
        assert expected is not None
        assert events[0].get(key) == (expected if isinstance(expected, list) else [expected])
