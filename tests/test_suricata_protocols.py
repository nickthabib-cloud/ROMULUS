"""Synthetic protocol records from the public Suricata 8 EVE specification.

https://docs.suricata.io/en/suricata-8.0.0/output/eve/eve-json-format.html
https://github.com/OISF/suricata/tree/suricata-8.0.0/rust/src
No upstream traffic or fixtures are copied. Shared-field parity uses Zeek's public catalog.
"""
import copy
import json

import pytest

from romulus.evidence.normalize import normalize_hits
from tests.test_elastic_suricata import shipped
from tests.test_malcolm_suricata import _malcolm_base, filebeat_hit, malcolm_hit

BASE = {"timestamp": "2024-11-18T14:00:00.123000+0000", "src_ip": "10.0.0.5",
        "src_port": 51000, "dest_ip": "10.0.0.10", "dest_port": 445, "proto": "TCP", "flow_id": 1234}
UUID = "367abb81-9844-35f1-ad32-98f038001003"
CASES = {
    "dcerpc": ({"request": "REQUEST", "req": {"opnum": 12}, "interfaces": [{"uuid": UUID}]},
               "rpc_tx", {"rpc.interface_uuid": UUID, "rpc.opnum": 12, "rpc.op_class": "service_create"}),
    "smb": ({"command": "SMB2_COMMAND_SET_INFO", "share": r"\\DC01\DATA",
             "rename": {"from": r"dir\old.txt", "to": r"dir\old.locked"}},
            "smb_tx", {"smb.action": "FILE_RENAME", "smb.prev_name": r"dir\old.txt",
                       "smb.name": r"dir\old.locked", "smb.share": "DATA"}),
    "krb5": ({"msg_type": "KRB_TGS_REP", "cname": "alice", "sname": "cifs/server",
              "realm": "EXAMPLE.TEST", "encryption": "aes256-cts-hmac-sha1-96",
              "ticket_encryption": "aes256-cts-hmac-sha1-96"},
             "kerberos_tx", {"kerberos.request_type": "TGS", "kerberos.client": "alice",
                             "kerberos.service": "cifs/server", "auth.encryption_type": 18}),
    "rdp": ({"event_type": "connect_request", "channel": ["cliprdr", "rdpdr"],
             "client": {"build": "RDP 8.1", "client_name": "WS01"}},
            "remote_session", {"remote.protocol": "rdp", "rdp.client_build": "8.1",
                               "rdp.client_channels": ["cliprdr", "rdpdr"]}),
    "ldap": ({"request": {"message_id": 2, "operation": "search_request", "search_request": {
                  "base_object": "DC=example,DC=test", "scope": 2, "filter": {"type": "present", "value": "cn"},
                  "attributes": ["cn", "memberOf"]}}, "responses": [
                  {"operation": "search_result_done", "search_result_done": {"result_code": "success"}}]},
             "ldap_tx", {"ldap.operation": "search", "ldap.scope": "tree", "ldap.filter": "(cn=*)",
                         "ldap.attributes": ["cn", "memberOf"], "ldap.result": "success"}),
    "smtp": ({"helo": "mail.example.test", "mail_from": "a@example.test", "rcpt_to": ["b@example.test"]},
             "app_tx", {"app.protocol": "smtp", "smtp.helo": "mail.example.test",
                        "smtp.mail_from": "a@example.test", "smtp.rcpt_to": ["b@example.test"]}),
    "ftp": ({"command": "RETR", "command_data": "report.txt", "completion_code": ["226"], "reply": ["done"]},
            "app_tx", {"app.protocol": "ftp", "app.command": "RETR", "app.arg": "report.txt", "app.reply_code": 226}),
    "ftp_data": ({"command": "RETR", "filename": "report.txt"}, "app_tx",
                 {"app.protocol": "ftp", "app.command": "RETR", "app.arg": "report.txt"}),
    "dhcp": ({"dhcp_type": "ack", "assigned_ip": "10.0.0.5", "client_mac": "00:00:5e:00:53:05", "lease_time": 60},
             "address_assignment", {"dhcp.assigned_ip": "10.0.0.5", "dhcp.client_mac": "00:00:5e:00:53:05",
                                    "dhcp.lease_s": 60.0, "dhcp.message_types": ["ACK"]}),
    "snmp": ({"version": 2, "pdu_type": "get_request", "community": "secret"}, "app_tx",
             {"app.protocol": "snmp", "snmp.version": "2c"}),
    "tftp": ({"packet": "read", "file": "boot.bin", "mode": "octet"}, "app_tx",
             {"app.protocol": "tftp", "app.command": "read", "app.arg": "boot.bin"}),
}


def hit(et, block=None, shape="original", nid="row-1"):
    eve = {**BASE, "event_type": et, et: copy.deepcopy(CASES[et][0] if block is None else block)}
    if shape in ("filebeat", "agent"):
        return shipped(eve, shape, nid)
    if shape == "malcolm":
        return malcolm_hit(_malcolm_base(et, eve["timestamp"], {et: eve[et]},
            source={"ip": eve["src_ip"], "port": eve["src_port"]},
            destination={"ip": eve["dest_ip"], "port": eve["dest_port"]},
            network={"transport": "tcp", "protocol": [et]}), nid)
    result = filebeat_hit(eve, nid)
    if shape == "message":
        result["_source"]["message"] = result["_source"]["event"].pop("original")
    return result


@pytest.mark.parametrize("shape", ["original", "message", "filebeat", "agent", "malcolm"])
@pytest.mark.parametrize("et", CASES)
def test_protocol_fields_survive_every_supported_shipper(et, shape):
    events, skips, errors = normalize_hits([hit(et, shape=shape)])
    assert not skips and not errors
    assert len(events) == 1
    event = events[0]
    assert event.family == CASES[et][1]
    assert event.normalizer == "suricata-eve@2"
    for key, expected in CASES[et][2].items():
        assert event.get(key) == expected, key
        assert event.fields[key].origin.startswith("row-1:")
    assert "secret" not in json.dumps({k: v.value for k, v in event.fields.items()})


def test_smb_auth_and_rpc_children_have_distinct_identity_and_verifiable_raw_reference():
    block = {**CASES["smb"][0], "ntlmssp": {"user": "alice", "domain": "EXAMPLE", "host": "WS01"},
             "dcerpc": {"request": "REQUEST", "opnum": 12, "interfaces": [{"uuid": UUID}]}}
    events, skips, errors = normalize_hits([hit("smb", block)])
    assert not skips and not errors
    assert {e.family for e in events} == {"smb_tx", "ntlm_tx", "rpc_tx"}
    assert len({e.id for e in events}) == 3
    assert all(e.raw == events[0].raw for e in events)
    ntlm = next(e for e in events if e.family == "ntlm_tx")
    assert ntlm.get("ntlm.username") == "alice"
    assert ntlm.get("user.domain") == "example"


@pytest.mark.parametrize("et,block", [
    ("smb", {"command": "SMB2_COMMAND_CREATE", "ntlmssp": ["bad"]}),
    ("dcerpc", {"request": "REQUEST", "req": {"opnum": "bad"}, "interfaces": [{"uuid": UUID}]}),
    ("ldap", {"request": {"operation": "invented"}}),
    ("rdp", {"event_type": "invented"}),
    ("smtp", {"rcpt_to": [3]}),
])
def test_malformed_recognized_subrecord_is_counted_without_partial_typed_parent(et, block):
    events, skips, errors = normalize_hits([hit(et, block)])
    assert events == [] and not skips
    assert len(errors) == 1


@pytest.mark.parametrize("et", ["anomaly", "quic", "http2", "sip", "mqtt", "ike", "pgsql", "nfs", "rfb"])
def test_unsupported_protocol_stays_counted(et):
    events, skips, errors = normalize_hits([hit(et, {})])
    assert not events and not errors and sum(skips.values()) == 1


@pytest.mark.parametrize("et", CASES)
def test_missing_protocol_identity_is_malformed(et):
    events, skips, errors = normalize_hits([hit(et, {})])
    assert not events and not skips and len(errors) == 1


@pytest.mark.parametrize("key,value", [("src_ip", ["10.0.0.5"]), ("src_port", True),
    ("dest_port", "445"), ("proto", ["TCP"]), ("dest_ip", "bad")])
def test_new_protocol_invalid_common_fields_are_counted(key, value):
    raw = hit("smb")
    eve = json.loads(raw["_source"]["event"]["original"])
    eve[key] = value
    raw["_source"]["event"]["original"] = json.dumps(eve)
    events, skips, errors = normalize_hits([raw])
    assert not events and not skips and len(errors) == 1


@pytest.mark.parametrize("shape", ["original", "message", "filebeat", "agent", "malcolm"])
@pytest.mark.parametrize("et,block,key", [("ftp", {"command": "PASS", "command_data": "credential-secret"},
    "command_data"), ("snmp", {"version": 2, "pdu_type": "get_request", "community": "credential-secret"},
    "community")])
def test_credentials_are_presence_only_and_clean_raw_digest_matches(shape, et, block, key):
    import hashlib

    from romulus.evidence.raw_scrub import clean_source
    raw = hit(et, block, shape)
    events, skips, errors = normalize_hits([raw])
    assert not skips and not errors and len(events) == 1
    assert events[0].get("auth.cleartext_credentials_present") is True
    assert "credential-secret" not in repr(events[0].fields)
    clean = clean_source(raw["_source"])
    assert "credential-secret" not in json.dumps(clean)
    digest = hashlib.sha256(json.dumps(clean, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    assert events[0].raw[0].digest == digest


def test_reply_cipher_is_not_the_ticket_cipher_and_request_offers_do_not_become_ticket():
    block = {**CASES["krb5"][0], "encryption": "rc4-hmac", "ticket_encryption": "aes256-cts-hmac-sha1-96"}
    events, skips, errors = normalize_hits([hit("krb5", block)])
    assert not skips and not errors and events[0].get("auth.encryption_type") == 18
    block.pop("ticket_encryption")
    events, skips, errors = normalize_hits([hit("krb5", block)])
    assert not skips and not errors and not events[0].has("auth.encryption_type")
    assert any("ticket cipher" in c for c in events[0].caveats)


def test_open_if_does_not_assert_file_creation_or_ntlm_success():
    block = {"command": "SMB2_COMMAND_CREATE", "disposition": "FILE_OPEN_IF", "status": "STATUS_SUCCESS",
             "ntlmssp": {"user": "alice", "domain": "EXAMPLE"}}
    events, skips, errors = normalize_hits([hit("smb", block)])
    assert not skips and not errors
    assert not events[0].has("smb.action")
    assert all(not e.has("ntlm.success") and e.outcome == "unknown" for e in events)


@pytest.mark.parametrize("case", ["rpc", "smb", "ntlm", "kerberos", "rdp", "ldap", "dhcp", "smtp", "ftp", "ftp_data", "snmp"])
def test_shared_protocol_fields_equal_zeek_public_spec_twin(case):
    from romulus.evidence.zeek import normalize_plain_zeek
    from tests.fixtures import zeek_logs as zl
    if case == "rpc":
        et, block, row = "dcerpc", CASES["dcerpc"][0], zl.DCE_RPC
        keys = {"rpc.interface_uuid", "rpc.opnum", "rpc.op_class"}
    elif case == "smb":
        et, block = "smb", CASES["smb"][0]
        row = zl.SMB_FILES.with_(action="SMB::FILE_RENAME", path=block["share"], name=block["rename"]["to"],
                                prev_name=block["rename"]["from"])
        keys = {"smb.action", "smb.name", "smb.prev_name", "smb.path", "smb.host", "smb.share"}
    elif case == "ntlm":
        et, block, row = "smb", {"command": "SMB2_COMMAND_SESSION_SETUP", "ntlmssp": {
            "user": "alice", "domain": "EXAMPLE", "host": "WS01"}}, zl.NTLM
        keys = {"ntlm.username", "ntlm.domain", "ntlm.hostname", "source.hostname", "user.name", "user.domain",
                "auth.target_account"}
    elif case == "kerberos":
        et, block = "krb5", CASES["krb5"][0]
        row = zl.KERBEROS.with_(client="alice/EXAMPLE.TEST", service="cifs/server", cipher="aes256-cts-hmac-sha1-96")
        keys = {"kerberos.request_type", "kerberos.client_name", "kerberos.service", "auth.encryption_type", "kerberos.cipher"}
    elif case == "rdp":
        et, block = "rdp", CASES["rdp"][0]
        row = zl.RDP.with_(client_channels=["cliprdr", "rdpdr"])
        keys = {"remote.protocol", "rdp.client_channels", "rdp.client_build", "rdp.client_name"}
    elif case == "ldap":
        et, block = "ldap", CASES["ldap"][0]
        row = zl.LDAP_SEARCH.with_(filter="(cn=*)", attributes=["cn", "memberOf"])
        keys = {"ldap.operation", "ldap.operations", "ldap.scope", "ldap.scopes", "ldap.base_object",
                "ldap.base_objects", "ldap.filter", "ldap.attributes", "ldap.result", "ldap.results"}
    elif case == "dhcp":
        et, block = "dhcp", CASES["dhcp"][0]
        row = zl.DHCP.with_(assigned_addr="10.0.0.5", lease_time=60.0, msg_types=["ACK"])
        keys = {"dhcp.assigned_ip", "dhcp.client_mac", "dhcp.lease_s", "dhcp.message_types"}
    elif case == "smtp":
        et, block = "smtp", CASES["smtp"][0]
        row = zl.SMTP.with_(mailfrom="a@example.test", rcptto=["b@example.test"])
        keys = {"app.protocol", "smtp.helo", "smtp.mail_from", "smtp.rcpt_to"}
    elif case in ("ftp", "ftp_data"):
        et, block = case, CASES[case][0]
        row = zl.FTP.with_(command="RETR", arg="report.txt", reply_code=226, reply_msg="done")
        keys = {"app.protocol", "app.command", "app.arg"}
        if case == "ftp":
            keys |= {"app.reply", "app.reply_code"}
    else:
        et, block, row = "snmp", CASES["snmp"][0], zl.SNMP
        keys = {"app.protocol", "snmp.version", "auth.cleartext_credentials_present"}
    zeek = normalize_plain_zeek(zl.plain(row), sensor=zl.SENSOR)
    events, skips, errors = normalize_hits([hit(et, block)])
    assert not skips and not errors
    eve = next(e for e in events if e.family == zeek.family)
    assert keys <= set(eve.fields) and keys <= set(zeek.fields)
    assert {k: eve.get(k) for k in keys} == {k: zeek.get(k) for k in keys}


@pytest.mark.parametrize("shape", ["original", "message", "filebeat", "agent", "malcolm"])
def test_rdp_product_id_is_numeric_but_digital_product_id_is_native_id(shape):
    block = {"event_type": "connect_request", "client": {"product_id": 1,
        "id": "00000-00000-00000-AA000", "color_depth": 32, "desktop_width": 1920, "desktop_height": 1080}}
    events, skips, errors = normalize_hits([hit("rdp", block, shape)])
    assert not skips and not errors
    assert events[0].get("rdp.client_dig_product_id") == block["client"]["id"]
    assert events[0].get("rdp.requested_color_depth") == "32bit"


def test_dataset_suffix_raw_credential_copy_is_masked_too():
    from romulus.evidence.raw_scrub import clean_source
    raw = hit("ftp", {"command": "PASS", "command_data": "credential-secret"})
    raw["_source"]["event"]["dataset"] = "suricata.eve.ftp"
    events, skips, errors = normalize_hits([raw])
    assert len(events) == 1 and not skips and not errors
    assert "credential-secret" not in json.dumps(clean_source(raw["_source"]))


def test_ldap_missing_serialized_filter_is_explicit_and_unknown_subrecord_is_counted():
    block = copy.deepcopy(CASES["ldap"][0])
    block["request"]["search_request"].pop("filter")
    events, skips, errors = normalize_hits([hit("ldap", block)])
    assert not skips and not errors and not events[0].has("ldap.filter")
    assert any("filter is unknown" in c for c in events[0].caveats)
    block["responses"].append({"operation": "future_extension"})
    events, skips, errors = normalize_hits([hit("ldap", block)])
    assert not events and not skips and len(errors) == 1


@pytest.mark.parametrize("detail", [None, {"base_object": "CN=a", "attributes": [7]}])
def test_ldap_malformed_response_entry_fails_the_whole_transaction(detail):
    block = copy.deepcopy(CASES["ldap"][0])
    response = {"operation": "search_result_entry"}
    if detail is not None:
        response["search_result_entry"] = detail
    block["responses"].insert(0, response)
    events, skips, errors = normalize_hits([hit("ldap", block)])
    assert not events and not skips and len(errors) == 1


def test_ldap_password_attribute_and_sasl_reply_credentials_are_masked():
    from romulus.evidence.raw_scrub import clean_source
    block = copy.deepcopy(CASES["ldap"][0])
    block["responses"].insert(0, {"operation": "search_result_entry", "search_result_entry": {
        "base_object": "CN=a", "attributes": [{"type": "userPassword", "values": ["credential-secret"]},
                                               {"type": "cn", "values": ["Alice"]}]}})
    raw = hit("ldap", block)
    events, skips, errors = normalize_hits([raw])
    assert not skips and not errors
    assert events[0].get("auth.cleartext_credentials_present") is True
    clean = clean_source(raw["_source"])
    assert "credential-secret" not in json.dumps(clean) and "Alice" in json.dumps(clean)


@pytest.mark.parametrize("et", CASES)
def test_new_elastic_protocol_inventory_keeps_bounded_native_event_type(et):
    shapes = {}
    events, skips, errors = normalize_hits([hit(et, shape="agent")], shapes=shapes)
    assert events and not skips and not errors
    assert shapes == {"suricata.eve.elastic:" + et: 1}


def test_message_only_protocol_field_origins_name_the_actual_payload():
    events, skips, errors = normalize_hits([hit("smb", shape="message")])
    assert not skips and not errors
    assert events[0].fields["smb.name"].origin.startswith("row-1:message#eve.smb.")
    assert events[0].fields["source.ip"].origin == "row-1:message#eve.src_ip"


@pytest.mark.parametrize("shape", ["original", "message", "filebeat", "agent", "malcolm"])
def test_smb_embedded_rpc_opnum_is_beside_request_fragment_metadata(shape):
    # Official rust/src/smb/log.rs: opnum is beside req, whose fields are fragment metadata.
    block = {"command": "SMB2_COMMAND_WRITE", "dcerpc": {"request": "REQUEST", "opnum": 12,
        "req": {"frag_cnt": 1, "stub_data_size": 80}, "interfaces": [{"uuid": UUID}]}}
    events, skips, errors = normalize_hits([hit("smb", block, shape)])
    assert not skips and not errors
    rpc = next(e for e in events if e.family == "rpc_tx")
    assert rpc.get("rpc.opnum") == 12 and rpc.get("rpc.op_class") == "service_create"
    assert rpc.fields["rpc.opnum"].origin.endswith(".smb.dcerpc.opnum")


@pytest.mark.parametrize("nested,parent", [(12, 13), ("bad", 12), (12, "bad")])
def test_rpc_duplicate_opnum_disagreement_or_malformed_value_rejects_raw_record(nested, parent):
    block = {"request": "REQUEST", "opnum": parent, "req": {"opnum": nested}, "interfaces": [{"uuid": UUID}]}
    events, skips, errors = normalize_hits([hit("dcerpc", block)])
    assert not events and not skips and len(errors) == 1


@pytest.mark.parametrize("shape", ["original", "message", "filebeat", "agent", "malcolm"])
@pytest.mark.parametrize("attribute", ["userPassword", "unicodePwd;binary", "OID.2.5.4.35"])
def test_ldap_add_request_named_password_attribute_is_masked_with_verifiable_digest(shape, attribute):
    import hashlib

    from romulus.evidence.raw_scrub import clean_source
    # Official rust/src/ldap/logger.rs log_add_request uses `name`, not the search entry's `type`.
    block = {"request": {"message_id": 3, "operation": "add_request", "add_request": {
        "entry": "CN=synthetic,DC=example,DC=test", "attributes": [
            {"name": attribute, "values": ["synthetic-add-secret"]}, {"name": "cn", "values": ["synthetic"]}]}}}
    raw = hit("ldap", block, shape)
    events, skips, errors = normalize_hits([raw])
    assert not skips and not errors and len(events) == 1
    assert events[0].get("auth.cleartext_credentials_present") is True
    clean = clean_source(raw["_source"])
    assert "synthetic-add-secret" not in json.dumps(clean)
    assert "synthetic-add-secret" in json.dumps(raw["_source"])
    assert "synthetic" in json.dumps(clean)
    digest = hashlib.sha256(json.dumps(clean, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    assert events[0].raw[0].digest == digest


@pytest.mark.parametrize("shape", ["original", "message", "filebeat", "agent", "malcolm"])
def test_ldap_password_modify_extension_masks_request_and_unnamed_response(shape):
    # RFC3062 section2: requestValue may hold passwords; responseName is absent, responseValue may be generated password.
    # https://www.rfc-editor.org/rfc/rfc3062
    import hashlib

    from romulus.evidence.raw_scrub import clean_source
    block = {"request": {"operation": "extended_request", "extended_request": {
        "name": "1.3.6.1.4.1.4203.1.11.1", "value": "synthetic-old-new-secret"}},
        "responses": [{"operation": "extended_response", "extended_response": {
            "result_code": "success", "value": "synthetic-generated-secret"}}]}
    raw = hit("ldap", block, shape)
    events, skips, errors = normalize_hits([raw])
    assert not skips and not errors
    assert events[0].get("auth.cleartext_credentials_unknown") is True
    assert events[0].get("auth.cleartext_credentials_present") is True
    clean = clean_source(raw["_source"])
    assert "synthetic-old-new-secret" not in json.dumps(clean)
    assert "synthetic-generated-secret" not in json.dumps(clean)
    assert events[0].raw[0].digest == hashlib.sha256(json.dumps(
        clean, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    assert "synthetic-old-new-secret" in json.dumps(raw["_source"])


@pytest.mark.parametrize("request_block", [
    {"operation": "add_request", "add_request": {"entry": "CN=test", "attributes": [7]}},
    {"operation": "modify_request", "modify_request": {"object": "CN=test", "changes": ["bad"]}},
    {"operation": "bind_request"},
    {"operation": "compare_request", "compare_request": {"entry": "CN=test", "attribute_value_assertion": []}},
    {"operation": "mod_dn_request", "mod_dn_request": {"entry": "CN=test", "new_rdn": "CN=new", "delete_old_rdn": "yes"}},
    {"operation": "extended_request", "extended_request": {"name": "1.2.3", "value": [7]}},
    {"operation": "del_request", "del_request": {"dn": []}},
    {"operation": "unbind_request", "controls": [7]},
])
def test_ldap_all_present_request_structures_validate_atomically(request_block):
    events, skips, errors = normalize_hits([hit("ldap", {"request": request_block})])
    assert not events and not skips and len(errors) == 1


def test_every_ftp_completion_code_validates_even_when_no_scalar_reply_is_selected():
    events, skips, errors = normalize_hits([hit("ftp", {"command": "RETR", "completion_code": ["226", "bad"]})])
    assert not events and not skips and len(errors) == 1


@pytest.mark.parametrize("operation,detail", [
    ("compare_request", {"entry": "CN=test", "attribute_value_assertion": {
        "description": "unicodePwd;binary", "value": "synthetic-attribute-secret"}}),
    ("modify_request", {"object": "CN=test", "changes": [{"operation": "replace", "modification": {
        "attribute_type": "userPassword", "attribute_values": ["synthetic-attribute-secret"]}}]}),
])
def test_other_official_ldap_password_attribute_value_positions_are_masked(operation, detail):
    from romulus.evidence.raw_scrub import clean_source
    raw = hit("ldap", {"request": {"operation": operation, operation: detail}})
    events, skips, errors = normalize_hits([raw])
    assert not skips and not errors
    assert events[0].get("auth.cleartext_credentials_present") is True
    assert "synthetic-attribute-secret" not in json.dumps(clean_source(raw["_source"]))


def test_other_extended_operation_values_are_preserved():
    from romulus.evidence.raw_scrub import clean_source
    block = {"request": {"operation": "extended_request", "extended_request": {
        "name": "1.2.3.4", "value": "public-request"}}, "responses": [
        {"operation": "extended_response", "extended_response": {"result_code": "success", "value": "public-response"}}]}
    raw = hit("ldap", block)
    events, skips, errors = normalize_hits([raw])
    assert not skips and not errors
    assert not events[0].has("auth.cleartext_credentials_present")
    assert clean_source(raw["_source"]) is raw["_source"]


@pytest.mark.parametrize("shape", ["original", "message", "filebeat", "agent", "malcolm"])
@pytest.mark.parametrize("command", ["PASS", " PASS ", "\tAcCt\r\n", "adat"])
@pytest.mark.parametrize("event_type,argument", [("ftp", "command_data"), ("ftp_data", "filename")])
def test_ftp_credential_classification_matches_raw_mask_in_both_formats(shape, command, event_type, argument):
    import hashlib

    from romulus.evidence.raw_scrub import clean_source
    raw = hit(event_type, {"command": command, argument: "synthetic-ftp-secret", "reply": ["synthetic-ftp-secret"]}, shape)
    events, skips, errors = normalize_hits([raw])
    assert not skips
    clean = clean_source(raw["_source"])
    assert "synthetic-ftp-secret" not in json.dumps(clean)
    assert "synthetic-ftp-secret" in json.dumps(raw["_source"])
    if event_type == "ftp_data":
        assert not events and len(errors) == 1
    else:
        assert not errors and len(events) == 1
        assert events[0].get("app.command") == command.strip().upper()
        assert not events[0].has("app.arg") and not events[0].has("app.reply")
        assert events[0].get("auth.cleartext_credentials_present") is True
        assert "synthetic-ftp-secret" not in repr(events[0].fields)
        assert events[0].raw[0].digest == hashlib.sha256(json.dumps(
            clean, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@pytest.mark.parametrize("event_type,argument", [("ftp", "command_data"), ("ftp_data", "filename")])
@pytest.mark.parametrize("command", ["PASS", " PASS ", "ACCT", "ADAT", "RETR"])
@pytest.mark.parametrize("bad", [["synthetic-malformed-secret"], {"value": "synthetic-malformed-secret"}, 7, True])
def test_ftp_present_argument_type_is_validated_before_withholding(event_type, argument, command, bad):
    raw = hit(event_type, {"command": command, argument: bad})
    events, skips, errors = normalize_hits([raw])
    assert not events and not skips and len(errors) == 1


@pytest.mark.parametrize("event_type,argument", [("ftp", "command_data"), ("ftp_data", "filename")])
def test_ftp_safe_argument_and_raw_payload_remain_unchanged(event_type, argument):
    from romulus.evidence.raw_scrub import clean_source
    raw = hit(event_type, {"command": "RETR", argument: "public-report.txt"})
    events, skips, errors = normalize_hits([raw])
    assert not skips and not errors and events[0].get("app.arg") == "public-report.txt"
    assert clean_source(raw["_source"]) is raw["_source"]
