"""Zeek's Windows-protocol logs (smb_files, smb_mapping, smb_cmd, dce_rpc, kerberos, ntlm, rdp, rfb, ldap, ldap_search,
dhcp, software and the known_* logs) in every shipper shape, as the sensor's view of each exchange.

Fixtures are synthetic records in the published layouts (tests/fixtures/zeek_logs.py names the sources); equality of
one logical record across shapes is checked with the other analyzer logs (tests/test_zeek_analyzers.py). Here: the
values each family types, the names it shares with the Windows auth events and those it keeps its own, the values a
shipper rewrites, what each shipper does not index, credentials, identity at volume, and linear time on adversarial
values.
"""
import json
import time

import pytest

from romulus.evidence.normalize import normalize_hits
from romulus.evidence.typed import NETWORK_OBSERVER_FAMILIES, Outcome, event_os_family
from romulus.evidence.zeek import ZEEK_ARGUMENT_WITHHELD, ZEEK_DUPLICATE, normalize_plain_zeek
from romulus.evidence.zeek_catalog import (
    KERBEROS_ERRORS,
    KERBEROS_ETYPES,
    WINDOWS_PROTOCOL_LOGS,
    kerberos_etype,
    lookup_log,
)
from romulus.evidence.zeek_credentials import LDAP_FILTER_WITHHELD
from tests.fixtures import zeek_logs as zl

FAMILIES = {"smb_tx", "rpc_tx", "kerberos_tx", "ntlm_tx", "remote_session", "ldap_tx", "address_assignment",
            "asset_observed"}


def normalize(h, *, sensor=zl.SENSOR):
    if h["_index"] == zl.INDEX["plain"]:
        return normalize_plain_zeek(h, sensor=sensor)
    events, skips, errors = normalize_hits([h])
    assert (skips, errors) == ({}, []), (skips, errors)
    [event] = events
    return event


def every_shape(row: zl.Row) -> dict:
    return {shape: normalize(h) for shape, h in zl.in_every_shape(row).items()}


# ---- families --------------------------------------------------------------------------------------------------------

def test_the_new_families_are_network_observed_and_their_host_is_the_sensor():
    assert FAMILIES <= NETWORK_OBSERVER_FAMILIES
    assert {log.family for log in WINDOWS_PROTOCOL_LOGS} == FAMILIES
    for row in zl.WINDOWS_ROWS:
        for shape, event in every_shape(row).items():
            assert event.family in FAMILIES and event.host == zl.SENSOR, (row.log, shape)
            assert ("host", zl.SENSOR, "observer") in event.entities(), (row.log, shape)
            assert event_os_family(event) == "unknown", (row.log, shape)


def test_each_shipper_writes_the_logs_it_has_a_pipeline_for():
    assert lookup_log("security_onion", "smb_cmd") is None and lookup_log("elastic", "smb_cmd") is not None
    assert lookup_log("elastic", "ldap") is None and lookup_log("elastic", "ldap_search") is None
    for name in ("known_hosts", "known_services", "known_certs"):
        assert lookup_log("security_onion", name) is None and lookup_log("malcolm", name) is not None
    for log in WINDOWS_PROTOCOL_LOGS:
        assert set(log.names) | set(log.absent_shapes) == {"malcolm", "elastic", "security_onion", "plain"}


# ---- smb -------------------------------------------------------------------------------------------------------------

def test_smb_files_type_the_action_share_and_file_in_one_form_in_every_shape():
    for shape, event in every_shape(zl.SMB_FILES).items():
        assert event.family == "smb_tx" and event.get("smb.action") == "FILE_OPEN", shape
        assert event.get("smb.path") == "\\\\DC01\\ADMIN$", shape
        assert (event.get("smb.host"), event.get("smb.share")) == ("DC01", "ADMIN$"), shape
        assert event.get("smb.name") == "Temp\\svc-update.exe" and event.get("file.size") == 73802, shape
        assert event.get("file.fuid") == zl.FUID_SMB and event.get("zeek.uid") == zl.UID_SMB, shape
        assert event.get("file.mtime") == "2024-11-18T13:58:20.500000+00:00", shape
        assert event.get("network.transport") == "tcp", shape


def test_a_shippers_rewrite_of_an_smb_value_is_given_zeeks_form_with_its_derivation():
    """Malcolm removes the "SMB::" prefix and makes each doubled backslash single, which turns a JSON row's leading
    "\\\\" into one; every shape types Zeek's share path and the bare action."""
    h = zl.malcolm(zl.SMB_FILES)
    assert h["_source"]["zeek"]["smb_files"]["path"] == "\\DC01\\ADMIN$"
    assert h["_source"]["zeek"]["smb_files"]["action"] == "FILE_OPEN"
    event = normalize(h)
    assert event.get("smb.path") == "\\\\DC01\\ADMIN$"
    assert event.fields["smb.path"].origin.endswith(":zeek.smb_files.path#derived:unc-path")
    assert event.fields["smb.action"].origin.endswith(":zeek.smb_files.action")
    plain = normalize(zl.plain(zl.SMB_FILES))
    assert plain.fields["smb.action"].origin.endswith(":action#derived:zeek-enum-name")
    assert plain.fields["smb.path"].origin.endswith(":path")              # already Zeek's form: not derived
    assert not normalize(zl.plain(zl.SMB_FILES.with_(path="<unknown>"))).has("smb.share")


def test_smb_mapping_types_the_share_and_its_type():
    for shape, event in every_shape(zl.SMB_MAPPING).items():
        assert (event.get("smb.share"), event.get("smb.share_type")) == ("ADMIN$", "DISK"), shape
        assert event.get("smb.native_file_system") == "NTFS", shape
        # Malcolm's JSON rows merge the resource type into network.protocol: it is not read there
        assert event.get("smb.service") == (None if shape == "malcolm" else "A:"), shape


def test_smb_cmd_types_the_command_and_its_referenced_file_in_every_shape():
    for shape, event in every_shape(zl.SMB_CMD).items():
        assert (event.get("smb.command"), event.get("smb.status"), event.get("smb.version")) == \
            ("CREATE", "SUCCESS", "SMB2"), shape
        assert event.get("smb.tree") == "\\\\DC01\\ADMIN$" and event.get("smb.share") == "ADMIN$", shape
        assert event.get("smb.rtt_s") == pytest.approx(0.000412), shape
        assert (event.get("smb.action"), event.get("smb.name")) == ("FILE_OPEN", "Temp\\svc-update.exe"), shape
        assert event.get("file.fuid") == zl.FUID_SMB and event.get("zeek.uid") == zl.UID_SMB, shape
    # Elastic keeps the file's fuid and size only in its Zeek line
    bare = normalize(zl.elastic(zl.SMB_CMD, "no-original", original=False))
    assert bare.get("smb.action") == "FILE_OPEN" and not bare.has("file.fuid") and not bare.has("file.size")


def test_malcolms_smb_cmd_row_with_its_referenced_file_is_the_command_row():
    """Malcolm moves the referenced file to zeek.smb_files and names both logs: the row is smb_cmd's."""
    for text in (False, True):
        h = zl.malcolm(zl.SMB_CMD, f"mc-{text}", text=text)
        assert h["_source"]["event"]["dataset"] == ["smb_files", "smb_cmd"]
        event = normalize(h)
        assert event.get("zeek.log") == "smb_cmd" and event.get("zeek.datasets") == ["smb_files", "smb_cmd"]
        assert event.get("smb.action") == "FILE_OPEN" and event.get("file.fuid") == zl.FUID_SMB, text
        assert event.get("zeek.uid") == zl.UID_SMB, text                # merged into a one-element list
    alone = normalize(zl.malcolm(zl.SMB_CMD_NO_FILE))
    assert alone.get("zeek.log") == "smb_cmd" and not alone.has("smb.action")


def test_a_long_smb_cmd_burst_keeps_every_command_and_takes_linear_time():
    """A burst of one connection's commands, a millisecond apart (the shippers' resolution), is one record each."""
    def burst(n: int, shape: str) -> list[dict]:
        rows = [zl.SMB_CMD.with_(rtt=0.0001 + (i % 50) * 1e-6, command=("READ", "WRITE", "QUERY_INFO")[i % 3])
                for i in range(n)]
        return [zl.WRITERS[shape](zl.Row("smb_cmd", row.zeek, ts=zl.T0 + i * 0.001), f"burst-{shape}-{i}")
                for i, row in enumerate(rows)]

    for shape in ("malcolm", "elastic"):
        events, skips, errors = normalize_hits(burst(5000, shape))
        assert (skips, errors) == ({}, []) and len({e.id for e in events}) == 5000, shape
    timings = []
    for n in (2000, 8000):
        hits = burst(n, "malcolm")
        start = time.perf_counter()
        normalize_hits(hits)
        timings.append(time.perf_counter() - start)
    assert timings[1] <= 8 * timings[0], timings              # linear is 4x; quadratic would be 16x
    # the same burst shipped twice merges copy by copy, keeping both raw records
    hits = burst(200, "malcolm")
    events, skips, _ = normalize_hits(hits + [{**h, "_index": "arkime_sessions3-x"} for h in hits])
    assert len(events) == 200 and skips == {ZEEK_DUPLICATE: 200} and all(len(e.raw) == 2 for e in events)


# ---- dce_rpc ---------------------------------------------------------------------------------------------------------

def test_dce_rpc_types_the_call_and_its_class_from_the_one_rpc_table():
    for shape, event in every_shape(zl.DCE_RPC).items():
        assert event.family == "rpc_tx", shape
        assert (event.get("rpc.endpoint"), event.get("rpc.operation")) == ("svcctl", "CreateServiceW"), shape
        assert event.get("rpc.op_class") == "service_create" and event.get("rpc.opnum") == 12, shape
        assert event.get("rpc.interface_uuid") == "367abb81-9844-35f1-ad32-98f038001003", shape
        assert event.get("rpc.named_pipe") == "\\PIPE\\ntsvcs" and event.get("rpc.rtt_s") == 0.000512, shape
        assert event.fields["rpc.op_class"].origin.endswith("#derived:rpc-catalog"), shape


@pytest.mark.parametrize("endpoint,operation,op_class,uuid,opnum", [
    ("efsrpc2", "EfsRpcOpenFileRaw", "coercion", "c681d488-d850-11d0-8c52-00c04fd90f7e", 0),
    ("drsuapi", "DRSGetNCChanges", "replication", "e3514235-4b06-11d1-ab04-00c04fc2dcd2", 3),
    ("ITaskSchedulerService", "unknown-19", "task_register", "86d35949-83c9-4044-b424-db363231fd0c", 19),
    ("unknown-df1941c5-fe89-4e79-bf10-463657acf44d", "unknown-4", "coercion",
     "df1941c5-fe89-4e79-bf10-463657acf44d", 4),
    ("epmapper", "ept_map", "other", None, None),
    ("unknown-12345678-90ab-cdef-1234-567890abcdef", "unknown-7", "other", "12345678-90ab-cdef-1234-567890abcdef",
     7),
])
def test_every_call_has_a_class_and_an_unknown_one_is_other(endpoint, operation, op_class, uuid, opnum):
    event = normalize(zl.plain(zl.DCE_RPC.with_(endpoint=endpoint, operation=operation)))
    assert event.get("rpc.op_class") == op_class
    assert (event.get("rpc.interface_uuid"), event.get("rpc.opnum")) == (uuid, opnum)


# ---- kerberos --------------------------------------------------------------------------------------------------------

def test_kerberos_types_the_ticket_and_shares_the_windows_auth_names_where_they_mean_the_same():
    for shape, event in every_shape(zl.KERBEROS).items():
        assert event.family == "kerberos_tx" and event.outcome == Outcome.success, shape
        assert (event.get("kerberos.request_type"), event.get("kerberos.cipher")) == ("TGS", "rc4-hmac"), shape
        assert event.get("auth.encryption_type") == 23, shape       # a Windows 4769's TicketEncryptionType 0x17
        assert event.get("auth.target_account") == "name:example.test\\alice", shape
        assert (event.get("kerberos.client_name"), event.get("kerberos.client_realm")) == ("alice", "EXAMPLE.TEST")
        assert event.get("kerberos.service") == "MSSQLSvc/sql01.example.test:1433", shape
        assert event.get("kerberos.till") == "2037-09-13T02:48:05+00:00", shape
        assert (event.get("kerberos.forwardable"), event.get("kerberos.renewable")) == (True, True), shape
        assert event.get("kerberos.client_cert_fuids") == ["FkrbCert000000001"], shape
        assert ("account", "name:example.test\\alice", "subject") in event.entities(), shape
        # what Zeek's record cannot say, or says with another meaning, is never typed under the Windows names
        for name in ("auth.service_name", "auth.ticket_options", "auth.preauth_type", "auth.status"):
            assert not event.has(name), (shape, name)


def test_a_krb_error_types_its_code_only_when_zeek_wrote_the_codes_name():
    failed = normalize(zl.plain(zl.KERBEROS.with_(success=False, error_msg="KDC_ERR_PREAUTH_FAILED", cipher=None,
                                                  request_type="AS", client="bob/EXAMPLE.TEST")))
    assert failed.outcome == Outcome.failure and failed.get("auth.status") == 24
    assert failed.fields["auth.status"].origin.endswith("#derived:kerberos-error-code")
    text = normalize(zl.plain(zl.KERBEROS.with_(success=False, error_msg="NEEDED_PREAUTH")))
    assert not text.has("auth.status") and text.get("kerberos.error_msg") == "NEEDED_PREAUTH"
    # a KRB-ERROR that names no client: Zeek writes the realm alone
    realm = normalize(zl.plain(zl.KERBEROS.with_(client="EXAMPLE.TEST")))
    assert realm.get("kerberos.client_realm") == "EXAMPLE.TEST" and not realm.has("auth.target_account")
    assert not normalize(zl.plain(zl.KERBEROS.with_(client="/EXAMPLE.TEST"))).has("auth.target_account")


@pytest.mark.parametrize("request_type", [None, "", "AP"])
def test_a_kerberos_error_with_no_kdc_request_is_an_application_servers_never_the_accounts(request_type):
    """Zeek's Kerberos analyzer also reads the AP exchange inside GSSAPI (an SMB or HTTP session's authentication):
    its KRB-ERROR is the application server's. It names no account failure and is not the event's outcome."""
    zeek = {k: v for k, v in zl.KERBEROS.zeek.items() if k not in (
        "request_type", "service", "from", "till", "cipher", "forwardable", "renewable", "client_cert_subject",
        "client_cert_fuid", "server_cert_subject", "server_cert_fuid")}
    zeek.update({"id.resp_p": 445, "success": False, "error_msg": "KRB_AP_ERR_MODIFIED"})
    if request_type is not None:
        zeek["request_type"] = request_type
    for shape, h in zl.in_every_shape(zl.Row("kerberos", zeek), "ap-").items():
        event = normalize(h)
        assert (event.get("kerberos.error_code"), event.get("kerberos.error_source")) == (41, "application_server")
        for name in ("auth.status", "auth.target_account", "user.name", "user.domain"):
            assert not event.has(name), (shape, name)
        assert event.outcome == Outcome.unknown and event.get("kerberos.client_name") == "alice", shape
        assert any("application server" in caveat for caveat in event.caveats), shape
    # the KDC's own error for an AS request is the account's
    kdc = normalize(zl.plain(zl.Row("kerberos", {**zeek, "request_type": "AS", "error_msg": "KDC_ERR_PREAUTH_FAILED"})))
    assert (kdc.get("auth.status"), kdc.get("kerberos.error_code"), kdc.outcome) == (24, 24, Outcome.failure)
    assert kdc.get("auth.target_account") == "name:example.test\\alice" and not kdc.has("kerberos.error_source")


def test_the_account_is_also_typed_bare_for_a_join_across_sources():
    """auth.target_account is built as the Windows events build a key from a name, but a Windows event keys the same
    account by its SID where it has one, and Kerberos writes a realm where Windows writes a NetBIOS domain: a join
    reads the bare, casefolded user.name and user.domain."""
    for row, domain in ((zl.KERBEROS, "example.test"), (zl.NTLM, "example")):
        for shape, event in every_shape(row).items():
            assert (event.get("user.name"), event.get("user.domain")) == ("alice", domain), (row.log, shape)
    upper = normalize(zl.plain(zl.NTLM.with_(username="Alice", domainname="EXAMPLE")))
    assert (upper.get("user.name"), upper.get("user.domain")) == ("alice", "example")
    assert not normalize(zl.plain(zl.NTLM.with_(domainname="-"))).has("user.domain")
    machine = normalize(zl.plain(zl.KERBEROS.with_(client="host/ws01.example.test/EXAMPLE.TEST")))
    assert machine.get("user.name") == "host/ws01.example.test" and machine.get("user.domain") == "example.test"


def test_kerberos_encryption_type_names_and_numbers():
    """Zeek's cipher names (KRB::cipher_name) and the IANA Kerberos Encryption Type Numbers they denote."""
    assert KERBEROS_ETYPES == {
        "des-cbc-crc": 1, "des-cbc-md4": 2, "des-cbc-md5": 3, "des3-cbc-md5": 5, "des3-cbc-sha1": 7,
        "dsaWithSHA1-CmsOID": 9, "md5WithRSAEncryption-CmsOID": 10, "sha1WithRSAEncryption-CmsOID": 11,
        "rc2CBC-EnvOID": 12, "rsaEncryption-EnvOID": 13, "rsaES-OAEP-ENV-OID": 14, "des-ede3-cbc-Env-OID": 15,
        "des3-cbc-sha1-kd": 16, "aes128-cts-hmac-sha1-96": 17, "aes256-cts-hmac-sha1-96": 18,
        "aes128-cts-hmac-sha256-128": 19, "aes256-cts-hmac-sha384-192": 20, "rc4-hmac": 23, "rc4-hmac-exp": 24,
        "camellia128-cts-cmac": 25, "camellia256-cts-cmac": 26, "subkey-keymaterial": 65}
    numbers = {number: name for name, number in KERBEROS_ETYPES.items()}
    assert len(numbers) == len(KERBEROS_ETYPES)               # one name per number: names <-> numbers both ways
    for name, number in KERBEROS_ETYPES.items():
        assert kerberos_etype(name) == number and numbers[number] == name
        assert kerberos_etype(f"unknown-{number}") == number
    for junk in ("RC4-HMAC ", "rc4", "unknown-", "unknown-x", "unknown--1", "unknown-" + "9" * 11,
                 f"unknown-{2**31}", None, 23, "unknown-२३"):
        expected = 23 if junk == "RC4-HMAC " else None
        assert kerberos_etype(junk) in (None, expected), junk
    assert kerberos_etype("unknown-20") == 20                 # RFC 8009, which Zeek has no name for


def test_kerberos_error_names_and_codes():
    assert len(set(KERBEROS_ERRORS.values())) == len(KERBEROS_ERRORS)
    assert {KERBEROS_ERRORS[name] for name in ("KDC_ERR_C_PRINCIPAL_UNKNOWN", "KDC_ERR_CLIENT_REVOKED",
                                               "KDC_ERR_KEY_EXPIRED", "KDC_ERR_PREAUTH_FAILED",
                                               "KDC_ERR_PREAUTH_REQUIRED", "KRB_AP_ERR_SKEW")} == {6, 18, 23, 24, 25, 37}


def test_elastics_kerberos_community_id_is_computed_from_its_constant_tcp_and_not_read():
    h = zl.elastic(zl.KERBEROS)
    assert h["_source"]["network"]["transport"] == "tcp" and "community_id" in h["_source"]["network"]
    assert not normalize(h).has("network.community_id")


# ---- ntlm ------------------------------------------------------------------------------------------------------------

def test_ntlm_types_the_account_and_the_workstation_as_the_windows_auth_events_do():
    for shape, event in every_shape(zl.NTLM).items():
        assert event.family == "ntlm_tx" and event.outcome == Outcome.success, shape
        assert event.get("auth.target_account") == "name:example\\alice", shape
        assert event.get("source.hostname") == "ws01" and event.get("ntlm.hostname") == "WS01", shape
        assert event.get("ntlm.server_dns_computer_name") == "dc01.example.test", shape
        # Security Onion writes the workstation to host.name: the event's host stays the sensor
        assert event.host == zl.SENSOR, shape
    no_domain = normalize(zl.plain(zl.NTLM.without("domainname")))
    assert no_domain.get("auth.target_account") == "name:alice"
    assert normalize(zl.plain(zl.NTLM.with_(success=False))).outcome == Outcome.failure
    assert normalize(zl.plain(zl.NTLM.without("success"))).outcome == Outcome.unknown


# ---- rdp and rfb -----------------------------------------------------------------------------------------------------

def test_rdp_and_vnc_are_remote_sessions():
    for shape, event in every_shape(zl.RDP).items():
        assert event.family == "remote_session" and event.get("remote.protocol") == "rdp", shape
        assert (event.get("rdp.cookie"), event.get("rdp.result")) == ("alice", "Success"), shape
        assert event.get("rdp.client_build") == "8.1", shape           # Malcolm's form, given every shape
        assert event.get("rdp.desktop_width") == 1920 and event.get("rdp.cert_count") == 1, shape
        # rdp.log records no authentication result in any Zeek release: none is typed
        assert not any(name.startswith("rdp.auth") for name in event.fields), shape
        assert event.outcome == Outcome.unknown, shape
    for shape, event in every_shape(zl.RFB).items():
        assert event.get("remote.protocol") == "vnc" and event.get("rfb.auth_success") is True, shape
        assert event.outcome == Outcome.success and event.get("rfb.authentication_method") == "VNC", shape


# ---- ldap ------------------------------------------------------------------------------------------------------------

def test_ldap_types_the_operation_and_its_result_in_both_zeek_layouts():
    for row in (zl.LDAP, zl.LDAP_61):
        for shape, event in every_shape(row).items():
            if row is zl.LDAP_61 and shape == "security_onion":
                continue                    # Security Onion indexes the singular columns only
            assert event.family == "ldap_tx", shape
            assert (event.get("ldap.operation"), event.get("ldap.result")) == ("bind SASL", "success"), shape
            assert event.get("ldap.operations") == ["bind SASL"], shape
            assert event.get("ldap.object") == "CN=svc-app,OU=Service,DC=example,DC=test", shape
            assert event.get("ldap.argument") == "GSS-SPNEGO", shape     # a SASL bind's mechanism is kept
            assert event.get("ldap.message_id") == 1 and event.get("ldap.bind_type") == "sasl", shape
            assert not event.has("auth.cleartext_credentials_present"), shape


@pytest.mark.parametrize("operation,kind", [("bind simple", "simple"), ("bind SASL", "sasl"),
                                            ("sicily_negotiate", "sicily_negotiate"),
                                            ("sicily_response", "sicily_response"), ("bind", None),
                                            ("search", None), ("modify", None)])
def test_a_binds_kind_is_typed_from_its_operation(operation, kind):
    event = normalize(zl.plain(zl.LDAP.with_(opcode=operation, argument=None)))
    assert event.get("ldap.bind_type") == kind
    assert not normalize(zl.plain(zl.LDAP_SEARCH)).has("ldap.bind_type")


def test_ldap_search_types_the_search_and_every_requested_attribute():
    for row in (zl.LDAP_SEARCH, zl.LDAP_SEARCH_61):
        for shape, event in every_shape(row).items():
            if row is zl.LDAP_SEARCH_61 and shape == "security_onion":
                continue
            assert event.get("ldap.operation") == "search", shape
            assert (event.get("ldap.scope"), event.get("ldap.base_object")) == ("tree", "DC=example,DC=test"), shape
            assert event.get("ldap.filter") == "(&(objectclass=user)(servicePrincipalName=*))", shape
            assert event.get("ldap.result_count") == 3, shape
    # a long list of attributes is typed whole, never cut
    many = [f"attribute{i}" for i in range(20000)]
    assert normalize(zl.plain(zl.LDAP_SEARCH.with_(attributes=many))).get("ldap.attributes") == many


S = zl.SECRET
OPERATION_SPELLINGS = {"as-written": "bind simple", "upper": "BIND SIMPLE", "padded": " bind simple ",
                       "list": ["bind simple"], "with-other": ["bind simple", "unbind"]}


@pytest.mark.parametrize("spelling", sorted(OPERATION_SPELLINGS))
def test_a_simple_binds_argument_is_never_typed_in_any_shape_or_spelling(spelling):
    row = zl.LDAP.with_(opcode=OPERATION_SPELLINGS[spelling], argument=S)
    for shape, h in zl.in_every_shape(row, "bind-").items():
        if shape == "security_onion" and isinstance(OPERATION_SPELLINGS[spelling], list):
            continue                        # Security Onion's ldap.opcode is Zeek 7's one string
        event = normalize(h)
        assert S not in event.model_dump_json(), (shape, spelling)
        assert not event.has("ldap.argument") and not event.has("ldap.arguments"), (shape, spelling)
        assert event.get("auth.cleartext_credentials_present") is True, (shape, spelling)


@pytest.mark.parametrize("operation", [None, 7, "", "bind", " BIND ", "modify", "extended"])
def test_an_argument_whose_operation_cannot_be_read_is_withheld(operation):
    row = zl.LDAP.with_(argument=S)
    row = row.without("opcode") if operation is None else row.with_(opcode=operation)
    event = normalize(zl.plain(row))
    assert S not in event.model_dump_json() and not event.has("ldap.argument")
    assert event.get("auth.cleartext_credentials_unknown") is True and ZEEK_ARGUMENT_WITHHELD in event.caveats


def test_zeeks_own_redaction_and_an_anonymous_bind():
    redacted = normalize(zl.plain(zl.LDAP.with_(opcode="bind simple", argument="REDACTED")))
    assert redacted.get("auth.cleartext_credentials_present") is True and not redacted.has("ldap.argument")
    anonymous = normalize(zl.plain(zl.LDAP.with_(opcode="bind simple", object=None, argument=None)))
    assert not anonymous.has("auth.cleartext_credentials_present")
    plain_sasl = normalize(zl.plain(zl.LDAP.with_(argument="PLAIN")))
    assert plain_sasl.get("ldap.argument") == "PLAIN"
    assert plain_sasl.fields["auth.cleartext_credentials_present"].origin.endswith(
        "#sasl-cleartext-mechanism#present")


@pytest.mark.parametrize("search,withheld", [
    (f"(userPassword={S})", True), (f"(&(uid=alice)(USERPASSWORD;binary={S}))", True),
    (f"(unicodePwd~={S})", True), (f"(userPassword>={S})", True), (f"(userPassword=a*{S}*)", True),
    (f"(1.2.840.113556.1.4.803:userPassword:={S})", True), (f"(2.5.4.35={S})", True),
    (f"(ms-Mcs-AdmPwd={S})", True), (f"(OID.2.5.4.35={S})", True), (f"(oid.1.2.840.113556.1.4.90={S})", True),
    (f"(unixUserPassword={S})", True), (f"(msSFU30Password={S})", True), (f"(userPassword ={S})", True),
    (f"(userPassword = {S})", True), (f"(userPassword ~= {S})", True), (f"(userPassword:2.5.13.17:={S})", True),
    (f"({S}:userPassword:=)", True), (f"(userPassword=*){S})", True), (f"(userPassword=*{S})", True),
    (f"(userPassword={S}*)", True), (f"(&(cn=a)(userPassword=*){S}))", True),
    ("(ms-Mcs-AdmPwd=*)", False), ("(&(objectClass=computer)(ms-Mcs-AdmPwd=*))", False),
    ("(!(userPassword=*))", False), ("(|(userPassword=*)(unicodePwd=*))", False), ("(userPassword = * )", False),
    ("(&(objectCategory=computer)(ms-Mcs-AdmPwdExpirationTime>=0))", False),
    ("(description=reset the userPassword policy)", False), ("(servicePrincipalName=*)", False),
    ("(userPasswordHint=x)", False), ("(cn=passwords)", False),
])
def test_a_filter_comparing_a_password_attribute_with_a_value_is_withheld(search, withheld):
    for shape, h in zl.in_every_shape(zl.LDAP_SEARCH.with_(filter=search), "filter-").items():
        event = normalize(h)
        assert S not in event.model_dump_json(), shape
        assert event.has("ldap.filter") is not withheld, shape
        assert (event.get("auth.cleartext_credentials_present") is True) is withheld, shape
        assert (LDAP_FILTER_WITHHELD in event.caveats) is withheld, shape


# ---- dhcp ------------------------------------------------------------------------------------------------------------

def test_dhcp_types_the_lease_that_joins_an_address_to_a_host():
    for shape, event in every_shape(zl.DHCP).items():
        assert event.family == "address_assignment", shape
        assert (event.get("dhcp.assigned_ip"), event.get("dhcp.client_mac")) == (zl.WS, "00:00:5e:00:53:05"), shape
        assert (event.get("dhcp.hostname"), event.get("dhcp.domain")) == ("WS01", "example.test"), shape
        assert event.get("dhcp.server_address") == "10.0.0.1" and event.get("dhcp.lease_s") == 86400.0, shape
        assert event.get("dhcp.message_types") == ["REQUEST", "ACK"], shape
        assert event.get("zeek.uids") == ["CdhcpConn00000001", "CdhcpConn00000002"], shape
        # one transaction over several connections: the shippers' ports (68, 67) and Community ID are their own
        for name in ("source.port", "destination.port", "network.community_id", "source.ip", "zeek.uid"):
            assert not event.has(name), (shape, name)
        assert event.get("dhcp.client_fqdn") == (None if shape == "security_onion" else "ws01.example.test")


def test_dhcp_message_types_are_typed_in_zeeks_order_with_repeats():
    """Zeek writes each message of the transaction; Malcolm keeps each type once (its own loss)."""
    row = zl.DHCP.with_(msg_types=["DISCOVER", "OFFER", "REQUEST", "REQUEST", "ACK"])
    assert normalize(zl.plain(row)).get("dhcp.message_types") == ["DISCOVER", "OFFER", "REQUEST", "REQUEST", "ACK"]
    assert normalize(zl.malcolm(row)).get("dhcp.message_types") == ["DISCOVER", "OFFER", "REQUEST", "ACK"]


# ---- asset logs ------------------------------------------------------------------------------------------------------

def test_the_asset_logs_type_what_zeek_saw_as_context():
    for shape, event in every_shape(zl.SOFTWARE).items():
        assert event.family == "asset_observed" and event.get("asset.kind") == "software", shape
        assert (event.get("asset.ip"), event.get("asset.port")) == (zl.DC, 22), shape
        assert (event.get("software.name"), event.get("software.version.major")) == ("OpenSSH", 8), shape
        assert event.get("software.version.unparsed") == "OpenSSH_8.9p1 Ubuntu-3ubuntu0.6", shape
    for shape, event in every_shape(zl.KNOWN_SERVICES).items():
        assert event.get("asset.kind") == "service" and event.get("asset.services") == ["krb"], shape
        assert (event.get("asset.ip"), event.get("asset.port"), event.get("asset.transport")) == (zl.DC, 88, "tcp")
    for shape, event in every_shape(zl.KNOWN_CERTS).items():
        assert event.get("x509.subject") == "CN=dc01.example.test" and event.get("x509.serial") == "0a1b2c3d4e5f6071"
    for shape, event in every_shape(zl.KNOWN_HOSTS).items():
        assert event.get("asset.ip") == zl.WS and event.get("asset.kind") == "host", shape
        assert not any(kind == "ip" for kind, _value, _role in event.entities()), shape   # no connection named


@pytest.mark.parametrize("row", [zl.SOFTWARE, zl.KNOWN_HOSTS, zl.KNOWN_SERVICES, zl.KNOWN_CERTS],
                         ids=lambda row: row.log)
def test_elastics_host_ip_is_never_read_as_the_asset(row):
    """Elastic renames the asset's address into host.ip, where Elastic Agent writes the shipper's own addresses: the
    address is read from the Zeek line, and without it is not typed."""
    h = zl.elastic(row, "sensor-ip")
    h["_source"]["host"]["ip"] = ["192.0.2.250"]            # the shipper's address
    h["_source"].setdefault("server", {})["ip"] = ["192.0.2.250"]
    event = normalize(h)
    assert event.get("asset.ip") == row.zeek["host"]
    assert event.fields["asset.ip"].origin.endswith(":event.original#original.host")
    bare = zl.elastic(row, "sensor-ip-bare", original=False)
    bare["_source"]["host"]["ip"] = ["192.0.2.250"]
    assert not normalize(bare).has("asset.ip")


def test_a_software_urls_userinfo_is_removed_and_flagged():
    event = normalize(zl.plain(zl.SOFTWARE.with_(url=f"http://alice:{S}@www.example.test/plugin")))
    assert event.get("software.url") == "http://www.example.test/plugin" and S not in event.model_dump_json()
    assert event.get("auth.cleartext_credentials_present") is True


# ---- odd values ------------------------------------------------------------------------------------------------------

def test_text_a_sensor_could_not_decode_is_typed_as_written():
    """Zeek writes bytes that are not UTF-8 as "\\xNN" escapes; a shipper that decodes them writes U+FFFD."""
    for value in ("\\xff\\xfeadmin", "admin�"):
        event = normalize(zl.plain(zl.NTLM.with_(username=value)))
        assert event.get("ntlm.username") == value and json.loads(event.model_dump_json())


# ---- linear time on adversarial values -------------------------------------------------------------------------------

N = 256 * 1024


def _fields():
    """(row, columns) of a 256 KB adversarial value in every typed column the Windows-protocol steps scan."""
    yield zl.SMB_FILES, {"path": "\\" * N}
    yield zl.SMB_FILES, {"path": "\\\\" + "a\\\\" * (N // 3), "name": "\\\\" * (N // 2)}
    yield zl.SMB_CMD, {"tree": "\\a" * (N // 2), "version": "9" * N, "command": "SMB::" * (N // 5)}
    yield zl.DCE_RPC, {"endpoint": "unknown-" + "a" * N, "operation": "unknown-" + "1" * N}
    yield zl.DCE_RPC, {"endpoint": "unknown-" + "-" * N, "operation": "x" * N}
    yield zl.KERBEROS, {"client": "/" * N, "cipher": "unknown-" + "9" * N, "error_msg": "KDC_ERR_" * (N // 8)}
    yield zl.KERBEROS, {"client": "a/" * (N // 2), "service": "b/" * (N // 2)}
    yield zl.NTLM, {"hostname": "." * N, "username": "a\\" * (N // 2), "domainname": "." * N}
    yield zl.RDP, {"client_build": "RDP " * (N // 4), "client_channels": ["c"] * (N // 8)}
    yield zl.LDAP, {"opcode": "bind simple" * (N // 11), "argument": "a" * N}
    yield zl.LDAP_61, {"opcodes": ["bind sasl"] * (N // 10), "arguments": ["PLAIN"] * (N // 6)}
    for search in ("(userpassword" * (N // 13), "pass" * (N // 4), "(userPassword=" + "a" * N,
                   "userpassword;" * (N // 13), "(" * N, "1.2.840.113556.1.4." * (N // 19), "unicodepwd" * (N // 10),
                   ";" * N, "(userPassword=*" * (N // 15)):
        yield zl.LDAP_SEARCH, {"filter": search}
    yield zl.LDAP_SEARCH, {"attributes": ["a"] * (N // 4)}
    yield zl.DHCP, {"msg_types": ["ACK"] * (N // 4), "msg_orig": ["10.0.0.1"] * (N // 16)}
    yield zl.KNOWN_SERVICES, {"service": ["SPICY_KRB_TCP"] * (N // 16)}


def _time(fn) -> float:
    best = float("inf")
    for _ in range(3):
        start = time.perf_counter()
        fn()
        best = min(best, time.perf_counter() - start)
        if best < 0.05:
            break
    return best


@pytest.mark.parametrize("row,columns", list(_fields()),
                         ids=[f"{row.log}-{i}" for i, (row, _) in enumerate(_fields())])
def test_an_adversarial_256_kb_value_is_normalized_in_linear_time(row, columns):
    h = zl.plain(row.with_(**columns), "big")
    event = normalize_plain_zeek(h, sensor=zl.SENSOR)
    assert json.dumps(event.model_dump(mode="json"))
    # the 50 ms the other analyzer logs are given, scaled for the lists' own typing (a list of 65,536 items is typed
    # item by item, linearly)
    limit = 0.1 if any(isinstance(value, list) for value in columns.values()) else 0.05
    assert _time(lambda: normalize_plain_zeek(h, sensor=zl.SENSOR)) < limit, (row.log, list(columns))
