"""Suricata EVE application records using the Zeek typed field vocabulary.

One request/response transaction is one event, not one event per candidate RPC interface,
LDAP response entry, or FTP reply. SMB authentication and embedded RPC have separate
families and retain the enclosing raw record. Unknown or malformed recognized subrecords
raise ValueError atomically. Optional fields are never fabricated.

Format: https://docs.suricata.io/en/suricata-8.0.0/output/eve/eve-json-format.html
Serializer details: https://github.com/OISF/suricata/tree/suricata-8.0.0/rust/src
"""
from __future__ import annotations

import copy
import ipaddress
import json
import re
from dataclasses import dataclass, field
from uuid import UUID

from romulus.evidence.rpc_catalog import lookup_call
from romulus.evidence.typed import FieldValue, Outcome, fv
from romulus.evidence.zeek_catalog import KERBEROS_ERRORS, KERBEROS_ETYPES
from romulus.evidence.zeek_credentials import LDAP_PASSWORD_ATTRIBUTES

SURICATA_NORMALIZER = "suricata-eve@1"
SURICATA_PROTOCOL_FAMILIES = {
    "dcerpc": frozenset({"rpc_tx"}), "smb": frozenset({"smb_tx", "ntlm_tx", "rpc_tx"}),
    "krb5": frozenset({"kerberos_tx"}), "rdp": frozenset({"remote_session"}),
    "ldap": frozenset({"ldap_tx"}), "dhcp": frozenset({"address_assignment"}),
    **{name: frozenset({"app_tx"}) for name in ("smtp", "ftp", "ftp_data", "snmp", "tftp")},
}
# RFC3961 section8 / RFC3962 / RFC4120 section7.5.9 / RFC4757 / RFC8009.
# https://www.rfc-editor.org/rfc/rfc3961
# https://www.rfc-editor.org/rfc/rfc4120
# https://www.rfc-editor.org/rfc/rfc8009
# The shared IANA table also covers CMS, Camellia and historical encryption names.
EVE_ETYPES = {name.casefold().replace("_", "-"): number for name, number in KERBEROS_ETYPES.items()}
EVE_ETYPES.update({"rc4-hmac-md5": 23, "rc4-hmac-md5-exp": 24})


@dataclass
class ProtocolRecord:
    family: str
    fields: dict[str, FieldValue] = field(default_factory=dict)
    caveats: list[str] = field(default_factory=list)
    outcome: Outcome = Outcome.unknown


class Reader:
    def __init__(self, obj: object, path: str):
        if not isinstance(obj, dict):
            raise TypeError(f"{path}: expected object")
        self.obj, self.path = obj, path

    def origin(self, key):
        return f"{self.path}.{key}"

    def value(self, key, kind="text"):
        if key not in self.obj:
            return None
        value = self.obj[key]
        good = False
        if kind == "text":
            good = isinstance(value, str)
        elif kind == "count":
            good = type(value) is int and 0 <= value < 2**64
        elif kind == "names":
            good = isinstance(value, list) and all(isinstance(x, str) for x in value)
        elif kind == "flag":
            good = isinstance(value, bool)
        elif kind == "ip":
            try:
                good = isinstance(value, str) and bool(ipaddress.ip_address(value))
            except ValueError:
                pass
        if not good:
            raise ValueError(f"{self.origin(key)}: expected {kind}")
        return value

    def copy(self, fields, typed, key, kind="text"):
        value = self.value(key, kind)
        if value is not None:
            fields[typed] = fv(value, self.origin(key))
        return value

    def child(self, key):
        return Reader(self.obj[key], self.origin(key)) if key in self.obj else None


def _backslashes(text):
    return re.sub(r"\\+", lambda _m: "\\", text)


# MS-ERREF NTSTATUS values; only explicit logon failures, not generic SMB errors.
# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55
_NTLM_LOGON_FAILURES = frozenset({
    "STATUS_LOGON_FAILURE", "STATUS_ACCOUNT_LOCKED_OUT", "STATUS_PASSWORD_EXPIRED",
    "STATUS_ACCOUNT_DISABLED", "STATUS_ACCOUNT_RESTRICTION", "STATUS_INVALID_LOGON_HOURS",
    "STATUS_INVALID_WORKSTATION", "STATUS_ACCOUNT_EXPIRED", "STATUS_PASSWORD_MUST_CHANGE",
    "STATUS_NO_SUCH_USER", "STATUS_WRONG_PASSWORD", "STATUS_LOGON_TYPE_NOT_GRANTED",
})


def _smb(reader):
    result = ProtocolRecord("smb_tx")
    f = result.fields
    command = reader.value("command")
    if not command:
        raise ValueError(f"{reader.path}: missing SMB command")
    if command:
        match = re.fullmatch(r"SMB([12])_COMMAND_(.+)", command)
        f["smb.command"] = fv(match[2] if match else command, reader.origin("command"))
        if match:
            f["smb.version"] = fv("SMB" + match[1], reader.origin("command"))
    reader.copy(f, "smb.status", "status")
    for key in ("filename", "directory"):
        value = reader.value(key)
        if value is not None:
            f["smb.name"] = fv(_backslashes(value), reader.origin(key))
    share = reader.value("share")
    if share is not None:
        path = ("\\\\" if share.startswith("\\") else "") + _backslashes(share.lstrip("\\"))
        f["smb.path"] = fv(path, reader.origin("share"))
        if path.startswith("\\\\"):
            host, _, rest = path[2:].partition("\\")
            if host:
                f["smb.host"] = fv(host, reader.origin("share") + "#derived:unc-host")
            if rest:
                f["smb.share"] = fv(rest.partition("\\")[0], reader.origin("share") + "#derived:unc-share")
        elif path:
            f["smb.share"] = fv(path, reader.origin("share"))
    reader.copy(f, "file.size", "size", "count")
    reader.copy(f, "file.fuid", "fuid")
    rename = reader.child("rename")
    if rename:
        before, after = rename.value("from"), rename.value("to")
        if before is None or after is None:
            raise ValueError(f"{rename.path}: rename requires from and to")
        f["smb.prev_name"] = fv(_backslashes(before), rename.origin("from"))
        f["smb.name"] = fv(_backslashes(after), rename.origin("to"))
        f["smb.action"] = fv("FILE_RENAME", rename.path + "#derived:rename")
    elif command == "SMB1_COMMAND_DELETE":
        f["smb.action"] = fv("FILE_DELETE", reader.origin("command"))
    elif command in {"SMB2_COMMAND_CREATE", "SMB2_COMMAND_SET_INFO"} and reader.value("access") == "delete on close":
        f["smb.action"] = fv("FILE_DELETE", reader.origin("access"))
        result.caveats.append("SMB delete-on-close records requested deletion, not its success")
    elif reader.value("disposition") == "FILE_CREATE":
        f["smb.action"] = fv("FILE_CREATE", reader.origin("disposition"))
        result.caveats.append("SMB create disposition records the requested operation, not its success")
    rows = [result]
    ntlm = reader.child("ntlmssp")
    if ntlm:
        auth = ProtocolRecord("ntlm_tx")
        # Suricata SMB log.rs emits this transaction's status and NTLM child;
        # output-json-smb.c uses flow orientation, not the triggering packet.
        if command in {"SMB1_COMMAND_SESSION_SETUP_ANDX", "SMB2_COMMAND_SESSION_SETUP"}:
            status = reader.value("status")
            if status == "STATUS_SUCCESS" or status in _NTLM_LOGON_FAILURES:
                success = status == "STATUS_SUCCESS"
                auth.fields["ntlm.success"] = fv(success, reader.origin("status") + "#derived:session-setup")
                auth.outcome = Outcome.success if success else Outcome.failure
        user = ntlm.copy(auth.fields, "ntlm.username", "user")
        domain = ntlm.copy(auth.fields, "ntlm.domain", "domain")
        host = ntlm.copy(auth.fields, "ntlm.hostname", "host")
        if host:
            auth.fields["source.hostname"] = fv(host.strip().rstrip(".").casefold(), ntlm.origin("host"))
        if user:
            auth.fields["user.name"] = fv(user.strip().casefold(), ntlm.origin("user"))
            if domain:
                auth.fields["user.domain"] = fv(domain.strip().casefold(), ntlm.origin("domain"))
            account = (domain.strip() + "\\" if domain and domain not in ("-", ".") else "") + user.strip()
            auth.fields["auth.target_account"] = fv("name:" + account.casefold(), ntlm.path + "#derived:account")
        rows.append(auth)
    rpc = reader.child("dcerpc")
    if rpc:
        rows.append(_rpc(rpc))
    return rows


def _rpc(reader):
    result = ProtocolRecord("rpc_tx")
    f = result.fields
    request = reader.value("request")
    response = reader.value("response")
    if not request and not response:
        raise ValueError(f"{reader.path}: missing RPC request/response type")
    req = reader.child("req")
    nested_opnum = req.value("opnum", "count") if req else None
    parent_opnum = reader.value("opnum", "count")
    if nested_opnum is not None and parent_opnum is not None and nested_opnum != parent_opnum:
        raise ValueError(f"{reader.path}: conflicting RPC opnums")
    opnum = nested_opnum if nested_opnum is not None else parent_opnum
    opnum_reader = req if nested_opnum is not None else reader
    if opnum is not None:
        if opnum > 65535:
            raise ValueError(f"{reader.path}: invalid RPC opnum")
        f["rpc.opnum"] = fv(opnum, opnum_reader.origin("opnum"))
    interfaces = reader.obj.get("interfaces", [])
    if not isinstance(interfaces, list):
        raise TypeError(f"{reader.path}.interfaces: expected array")
    candidates = []
    for i, obj in enumerate(interfaces):
        part = Reader(obj, f"{reader.path}.interfaces[{i}]")
        raw = part.value("uuid")
        if raw is None:
            raise ValueError(f"{part.path}: missing UUID")
        uuid = str(UUID(raw))
        ack = part.value("ack_result", "count")
        if ack in (None, 0):
            candidates.append((uuid, part.origin("uuid")))
    unique = {uuid for uuid, _ in candidates}
    if len(unique) == 1:
        uuid, origin = candidates[0]
        f["rpc.interface_uuid"] = fv(uuid, origin)
        if opnum is not None and request == "REQUEST":
            f["rpc.op_class"] = fv(lookup_call(uuid, opnum).op_class, origin + "#derived:rpc-catalog")
    elif len(unique) > 1:
        result.caveats.append("RPC interface candidates are unpaired with the request context; call class unresolved")
    return result


def _etype(value, path):
    if type(value) is int and 0 <= value < 2**31:
        return value
    if isinstance(value, str):
        name = value.casefold().replace("_", "-")
        if name in EVE_ETYPES:
            return EVE_ETYPES[name]
        match = re.fullmatch(r"(?:unknown-|encryptiontype\()([0-9]{1,10})\)?", name)
        if match and int(match[1]) < 2**31:
            return int(match[1])
    raise ValueError(f"{path}: unknown encryption type")


def _kerberos(reader, common):
    result = ProtocolRecord("kerberos_tx")
    f = result.fields
    # Suricata 8 registers krb5 with JsonGenericDirPacketLogger. Keep that
    # tuple intact and derive endpoint roles only from one unambiguous KDC port.
    source_kdc = common.value("src_port", "count") == 88
    destination_kdc = common.value("dest_port", "count") == 88
    if source_kdc != destination_kdc:
        for role, key in (("kdc", "src_ip" if source_kdc else "dest_ip"),
                          ("client", "dest_ip" if source_kdc else "src_ip")):
            address = common.value(key, "ip")
            if address is not None:
                f["kerberos." + role + "_ip"] = fv(address, common.origin(key) + "#derived:port-88")
            else:
                result.caveats.append(f"Kerberos {role} address is absent from the observed tuple")
    else:
        result.caveats.append("Kerberos endpoint roles are unresolved: exactly one tuple end must use port 88")
    msg = reader.value("msg_type")
    failed = reader.value("failed_request")
    request = failed if msg == "KRB_ERROR" else msg
    if request in ("KRB_AS_REQ", "KRB_AS_REP", "KRB_TGS_REQ", "KRB_TGS_REP"):
        f["kerberos.request_type"] = fv("AS" if "_AS_" in request else "TGS",
                                       reader.origin("failed_request" if msg == "KRB_ERROR" else "msg_type"))
    elif msg not in ("KRB_ERROR", "KRB_AP_REQ", "KRB_AP_REP", "KRB_SAFE", "KRB_PRIV", "KRB_CRED"):
        raise ValueError(f"{reader.path}: unknown Kerberos message type")
    for typed, key in (("kerberos.client", "cname"), ("kerberos.service", "sname")):
        value = reader.value(key)
        if value is not None and value != "<empty>":
            f[typed] = fv(value, reader.origin(key))
    client = f.get("kerberos.client")
    if client:
        # Suricata's cname is a principal without its realm; realm here is the server realm.
        f["kerberos.client_name"] = client
    if "ticket_encryption" in reader.obj:
        number = _etype(reader.obj["ticket_encryption"], reader.origin("ticket_encryption"))
        if msg in ("KRB_AS_REP", "KRB_TGS_REP"):
            f["auth.encryption_type"] = fv(number, reader.origin("ticket_encryption") + "#derived:kerberos-etype")
            f["kerberos.cipher"] = fv(next((k for k, v in KERBEROS_ETYPES.items() if v == number),
                                          f"unknown-{number}"), reader.origin("ticket_encryption"))
    encryption = reader.obj.get("encryption")
    if encryption not in (None, "<none>"):
        try:
            _etype(encryption, reader.origin("encryption"))
        except ValueError:
            result.caveats.append("Unknown Kerberos response encrypted-part cipher; ticket facts remain independent")
        if "ticket_encryption" not in reader.obj:
            result.caveats.append("Kerberos response encrypted-part cipher does not establish the issued ticket cipher")
    error = reader.value("error_code")
    if error is not None:
        number = KERBEROS_ERRORS.get(error)
        if number is None:
            match = re.fullmatch(r"(?:ErrorCode\(|unknown-)([0-9]{1,10})\)?", error)
            number = int(match[1]) if match and int(match[1]) < 2**31 else None
        if number is None:
            raise ValueError(f"{reader.path}: unknown Kerberos error code")
        f["kerberos.error_msg"] = fv(error, reader.origin("error_code"))
        f["kerberos.error_code"] = fv(number, reader.origin("error_code"))
        if failed in ("KRB_AS_REQ", "KRB_TGS_REQ"):
            f["kerberos.error_source"] = fv("kdc", reader.origin("failed_request"))
            f["auth.status"] = fv(number, reader.origin("error_code"))
            result.outcome = Outcome.failure if number else Outcome.success
    elif msg in ("KRB_AS_REP", "KRB_TGS_REP"):
        result.outcome = Outcome.success
    return result


def _rdp(reader):
    result = ProtocolRecord("remote_session")
    f = result.fields
    subtype = reader.value("event_type")
    if subtype not in ("initial_request", "initial_response", "connect_request", "connect_response", "tls_handshake"):
        raise ValueError(f"{reader.path}: unknown RDP subtype")
    f["remote.protocol"] = fv("rdp", reader.origin("event_type"))
    f["rdp.message"] = fv(subtype, reader.origin("event_type"))
    reader.copy(f, "rdp.cookie", "cookie")
    reader.copy(f, "rdp.client_channels", "channel", "names")
    client = reader.child("client")
    if client:
        for key, typed, kind in (("build", "client_build", "text"), ("client_name", "client_name", "text"),
                ("desktop_width", "desktop_width", "count"), ("desktop_height", "desktop_height", "count"),
                ("keyboard_layout", "keyboard_layout", "text"), ("id", "client_dig_product_id", "text")):
            value = client.copy(f, "rdp." + typed, key, kind)
            if key == "build" and value is not None:
                f["rdp.client_build"] = fv(value.removeprefix("RDP "), client.origin(key))
        client.value("product_id", "count")
        depth = client.value("color_depth", "count")
        if depth is not None:
            f["rdp.requested_color_depth"] = fv(f"{depth}bit", client.origin("color_depth"))
    return result


_LDAP_REQUESTS = {"search_request": "search", "bind_request": "bind", "unbind_request": "unbind",
                  "modify_request": "modify", "add_request": "add", "del_request": "delete",
                  "mod_dn_request": "modrdn", "compare_request": "compare", "extended_request": "extended",
                  "abandon_request": "abandon"}
_LDAP_RESPONSES = frozenset({"search_result_entry", "search_result_done", "search_result_reference", "bind_response",
    "modify_response", "add_response", "del_response", "mod_dn_response", "compare_response", "extended_response",
    "intermediate_response"})


def _required(reader, key, kind="text"):
    value = reader.value(key, kind)
    if value is None:
        raise ValueError(f"{reader.origin(key)}: required field absent")
    return value


def _object_rows(reader, key):
    rows = reader.obj.get(key, [])
    if not isinstance(rows, list):
        raise TypeError(f"{reader.origin(key)}: expected array")
    return [Reader(obj, f"{reader.origin(key)}[{i}]") for i, obj in enumerate(rows)]


def _ldap_controls(reader):
    for control in _object_rows(reader, "controls"):
        _required(control, "control_type")
        control.value("criticality", "flag")
        control.value("control_value")


def _ldap_request_shape(request, operation):
    """Validate every serializer-defined request container before any field is emitted."""
    _ldap_controls(request)
    detail = request.child(operation)
    if operation in ("unbind_request", "abandon_request"):
        return
    if detail is None:
        raise ValueError(f"{request.path}: missing {operation} detail")
    if operation == "search_request":
        _required(detail, "base_object")
        _required(detail, "scope", "count")
        for key in ("deref_alias", "size_limit", "time_limit"):
            detail.value(key, "count")
        detail.value("types_only", "flag")
        detail.value("attributes", "names")
    elif operation == "bind_request":
        _required(detail, "name")
        _required(detail, "version", "count")
        for key in ("password", "credentials"):
            detail.value(key)
        sasl = detail.child("sasl")
        if sasl:
            _required(sasl, "mechanism")
            sasl.value("credentials")
    elif operation == "add_request":
        _required(detail, "entry")
        for attribute in _object_rows(detail, "attributes"):
            _required(attribute, "name")
            attribute.value("values", "names")
    elif operation == "modify_request":
        _required(detail, "object")
        for change in _object_rows(detail, "changes"):
            _required(change, "operation")
            modification = change.child("modification")
            if modification is None:
                raise ValueError(f"{change.path}: missing modification")
            _required(modification, "attribute_type")
            modification.value("attribute_values", "names")
    elif operation == "del_request":
        _required(detail, "dn")
    elif operation == "mod_dn_request":
        _required(detail, "entry")
        _required(detail, "new_rdn")
        _required(detail, "delete_old_rdn", "flag")
        detail.value("new_superior")
    elif operation == "compare_request":
        _required(detail, "entry")
        assertion = detail.child("attribute_value_assertion")
        if assertion is None:
            raise ValueError(f"{detail.path}: missing attribute assertion")
        _required(assertion, "description")
        _required(assertion, "value")
    elif operation == "extended_request":
        _required(detail, "name")
        detail.value("value")


def _ldap(reader):
    result = ProtocolRecord("ldap_tx")
    f = result.fields
    for _obj, _key, path, certainty in _ldap_sensitive_fields(reader.obj, reader.path):
        f["auth.cleartext_credentials_" + certainty] = fv(True, path + "#" + certainty)
    if any(key.startswith("auth.cleartext_credentials_") for key in f):
        result.caveats.append("LDAP credential attributes and authentication bytes withheld")
    request = reader.child("request")
    if request:
        operation = request.value("operation")
        if operation not in _LDAP_REQUESTS:
            raise ValueError(f"{request.path}: unknown LDAP operation")
        _ldap_request_shape(request, operation)
        name = _LDAP_REQUESTS[operation]
        detail = request.child(operation)
        if name == "search":
            if detail is None:
                raise ValueError(f"{request.path}: missing search request")
            detail.copy(f, "ldap.base_object", "base_object")
            scope = detail.value("scope", "count")
            if scope is not None:
                if scope not in (0, 1, 2):
                    raise ValueError(f"{detail.path}: unknown LDAP scope")
                f["ldap.scope"] = fv(("base", "one", "tree")[scope], detail.origin("scope"))
            detail.copy(f, "ldap.attributes", "attributes", "names")
            filt = detail.child("filter")
            if not filt:
                result.caveats.append("Suricata 8 serializes only LDAP present filters; omitted search filter is unknown")
            if filt:
                attr = filt.value("value")
                if filt.value("type") != "present" or not attr or not re.fullmatch(r"[A-Za-z0-9.;_-]+", attr):
                    raise ValueError(f"{filt.path}: unsupported LDAP filter representation")
                f["ldap.filter"] = fv("(" + attr + "=*)", filt.path)
        elif name == "bind" and detail:
            detail.copy(f, "ldap.object", "name")
            detail.copy(f, "ldap.version", "version", "count")
            sasl = detail.child("sasl")
            name = "bind sasl" if sasl else "bind simple"
            f["ldap.bind_type"] = fv("sasl" if sasl else "simple", detail.path)
            if sasl:
                mechanism = sasl.copy(f, "ldap.argument", "mechanism")
                if sasl.obj.get("credentials"):
                    certainty = "present" if mechanism and mechanism.upper() in ("PLAIN", "LOGIN") else "unknown"
                    f["auth.cleartext_credentials_" + certainty] = fv(True, sasl.origin("credentials") + "#" + certainty)
                    result.caveats.append("LDAP SASL credential bytes withheld")
        elif detail:
            for key in ("object", "entry", "dn"):
                detail.copy(f, "ldap.object", key)
        f["ldap.operation"] = fv(name, request.origin("operation"))
        request.copy(f, "ldap.message_id", "message_id", "count")
    responses = reader.obj.get("responses", [])
    if not isinstance(responses, list):
        raise TypeError(f"{reader.path}.responses: expected array")
    results = []
    for i, obj in enumerate(responses):
        response = Reader(obj, f"{reader.path}.responses[{i}]")
        operation = response.value("operation")
        if operation not in _LDAP_RESPONSES:
            raise ValueError(f"{response.path}: unknown LDAP response")
        _ldap_controls(response)
        detail = response.child(operation)
        if detail is None and operation != "search_result_reference":
            raise ValueError(f"{response.path}: missing LDAP response detail")
        if detail and operation == "search_result_entry":
            _required(detail, "base_object")
            attributes = detail.obj.get("attributes", [])
            if not isinstance(attributes, list):
                raise TypeError(f"{detail.path}.attributes: expected array")
            for j, attribute in enumerate(attributes):
                attr = Reader(attribute, f"{detail.path}.attributes[{j}]")
                if attr.value("type") is None:
                    raise ValueError(f"{attr.path}: missing attribute type")
                attr.value("values", "names")
        if detail:
            for key in ("matched_dn", "message", "server_sasl_creds", "name", "value"):
                detail.value(key)
            code = detail.value("result_code")
            if code is None and operation not in ("search_result_entry", "intermediate_response"):
                raise ValueError(f"{detail.path}: missing LDAP result code")
            if code is not None:
                results.append((code, detail.origin("result_code")))
    if not request and not responses:
        raise ValueError(f"{reader.path}: missing LDAP request and responses")
    if results:
        f["ldap.results"] = fv(sorted({v for v, _ in results}), "+".join(o for _, o in results))
        if len(f["ldap.results"].value) == 1:
            f["ldap.result"] = fv(results[0][0], results[0][1])
    for scalar, plural in (("operation", "operations"), ("object", "objects"), ("argument", "arguments"),
                           ("scope", "scopes"), ("base_object", "base_objects")):
        if "ldap." + scalar in f:
            value = f["ldap." + scalar]
            f["ldap." + plural] = fv([value.value], value.origin)
    return result


_FTP_CREDENTIAL_COMMANDS = frozenset({"PASS", "ACCT", "ADAT"})


def _ftp_command(value: object) -> str:
    """One command classifier for typing and raw masking; never coerce malformed values."""
    return value.strip().upper() if isinstance(value, str) else ""


def _application(reader, et, eve, origin):
    result = ProtocolRecord("address_assignment" if et == "dhcp" else "app_tx")
    f = result.fields
    protocol = "ftp" if et == "ftp_data" else et
    if et != "dhcp":
        f["app.protocol"] = fv(protocol, origin + ".event_type")
    if et == "smtp":
        if not any(key in reader.obj for key in ("helo", "mail_from", "rcpt_to")):
            raise ValueError(f"{reader.path}: missing SMTP transaction fields")
        for key, kind in (("helo", "text"), ("mail_from", "text"), ("rcpt_to", "names")):
            reader.copy(f, "smtp." + key, key, kind)
        if "email" in eve:
            email = Reader(eve["email"], origin + ".email")
            for key, typed, kind in (("from", "from", "text"), ("to", "to", "names"), ("cc", "cc", "names"),
                    ("subject", "subject", "text"), ("message_id", "msg_id", "text"), ("x_mailer", "user_agent", "text")):
                email.copy(f, "smtp." + typed, key, kind)
    elif et in ("ftp", "ftp_data"):
        command = _ftp_command(reader.value("command"))
        if not command:
            raise ValueError(f"{reader.path}: missing FTP command")
        f["app.command"] = fv(command, reader.origin("command"))
        argument = "filename" if et == "ftp_data" else "command_data"
        # Validate present values even when their contents must not be emitted.
        argument_value = reader.value(argument)
        credential = command in _FTP_CREDENTIAL_COMMANDS
        if et == "ftp_data" and credential:
            raise ValueError(f"{reader.path}: credential command is not an FTP data transfer")
        if not credential and argument_value is not None:
            f["app.arg"] = fv(argument_value, reader.origin(argument))
        if credential and argument_value:
            f["auth.cleartext_credentials_present"] = fv(True, reader.origin(argument) + "#present")
            result.caveats.append("FTP credential argument withheld")
        replies = reader.value("reply", "names")
        if credential:
            replies = None
        codes = reader.value("completion_code", "names")
        if replies and len(replies) == 1:
            f["app.reply"] = fv(replies[0], reader.origin("reply") + "[0]")
        if codes and any(not re.fullmatch(r"[0-9]{3}", code) for code in codes):
            raise ValueError(f"{reader.path}: malformed FTP completion code")
        if codes and len(codes) == 1:
            f["app.reply_code"] = fv(int(codes[0]), reader.origin("completion_code") + "[0]")
        if (replies and len(replies) > 1) or (codes and len(codes) > 1):
            result.caveats.append("FTP reply sequence has multiple values; no scalar reply or transaction count inferred")
        mode = reader.value("mode")
        if mode is not None:
            if mode not in ("active", "passive"):
                raise ValueError(f"{reader.path}: unknown FTP mode")
            f["ftp.data_channel.passive"] = fv(mode == "passive", reader.origin("mode"))
        reader.copy(f, "ftp.data_channel.resp_p", "dynamic_port", "count")
    elif et == "dhcp":
        if not reader.value("dhcp_type"):
            raise ValueError(f"{reader.path}: missing DHCP message type")
        for key, typed, kind in (("assigned_ip", "assigned_ip", "ip"), ("client_ip", "client_address", "ip"),
                ("requested_ip", "requested_ip", "ip"), ("client_mac", "client_mac", "text"),
                ("hostname", "hostname", "text"), ("lease_time", "lease_s", "count")):
            value = reader.copy(f, "dhcp." + typed, key, kind)
            if key == "client_mac" and value is not None and not re.fullmatch(r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}", value):
                raise ValueError(f"{reader.path}: invalid DHCP client MAC")
        message = reader.value("dhcp_type")
        if message is not None:
            f["dhcp.message_types"] = fv([message.upper()], reader.origin("dhcp_type"))
    elif et == "snmp":
        version = reader.value("version", "count")
        if version is None:
            raise ValueError(f"{reader.path}: missing SNMP version")
        community = reader.value("community")
        if community:
            f["auth.cleartext_credentials_present"] = fv(True, reader.origin("community") + "#present")
            result.caveats.append("SNMP community credential withheld")
        if version is not None:
            f["snmp.version"] = fv({1: "1", 2: "2c", 3: "3"}.get(version, str(version)), reader.origin("version"))
        # EVE is one PDU, Zeek's SNMP log a session; no session counters inferred.
    elif et == "tftp":
        command = reader.value("packet")
        if command not in ("read", "write", "error"):
            raise ValueError(f"{reader.path}: unknown TFTP packet")
        f["app.command"] = fv(command, reader.origin("packet"))
        reader.copy(f, "app.arg", "file")
    return result


def protocol_records(eve: dict, origin: str) -> list[ProtocolRecord]:
    """Atomic protocol parsing; caller counts an unreadable EVE record once."""
    et = eve["event_type"]
    common = Reader(eve, origin)
    for key in ("src_ip", "dest_ip"):
        common.value(key, "ip")
    for key in ("src_port", "dest_port"):
        port = common.value(key, "count")
        if port is not None and port > 65535:
            raise ValueError(f"{origin}.{key}: invalid port")
    common.value("proto")
    reader = Reader(eve.get(et), origin + "." + et)
    if et == "smb":
        return _smb(reader)
    if et == "krb5":
        return [_kerberos(reader, common)]
    functions = {"dcerpc": _rpc, "rdp": _rdp, "ldap": _ldap}
    return [functions[et](reader) if et in functions else _application(reader, et, eve, origin)]


def _ldap_sensitive_fields(value, origin):
    """Known LDAP password attributes and SASL credentials, iteratively visited per record."""
    # RFC3062: request value may contain old/new passwords; a paired unnamed
    # extended response value carries the generated password. Other operations stay intact.
    # https://www.rfc-editor.org/rfc/rfc3062 section2
    request = value.get("request") if isinstance(value, dict) else None
    extended = request.get("extended_request") if isinstance(request, dict) else None
    password_modify = isinstance(extended, dict) and extended.get("name") == "1.3.6.1.4.1.4203.1.11.1"
    if password_modify:
        if extended.get("value"):
            yield extended, "value", origin + ".request.extended_request.value", "unknown"
        responses = value.get("responses", [])
        if isinstance(responses, list):
            for i, response in enumerate(responses):
                detail = response.get("extended_response") if isinstance(response, dict) else None
                if isinstance(detail, dict) and detail.get("value"):
                    yield detail, "value", f"{origin}.responses[{i}].extended_response.value", "present"
    pending = [(value, origin)]
    while pending:
        obj, path = pending.pop()
        if isinstance(obj, dict):
            attr = obj.get("type", obj.get("attribute_type", obj.get("description", obj.get("name"))))
            attr = attr.casefold().split(";")[0].removeprefix("oid.") if isinstance(attr, str) else ""
            for key, item in obj.items():
                if not item:
                    continue
                if key in ("password", "credentials", "server_sasl_creds"):
                    mechanism = obj.get("mechanism")
                    certainty = "present" if key == "password" or mechanism in ("PLAIN", "LOGIN") else "unknown"
                    yield obj, key, f"{path}.{key}", certainty
                elif attr in LDAP_PASSWORD_ATTRIBUTES and key in ("values", "attribute_values", "value"):
                    yield obj, key, f"{path}.{key}", "present"
                elif isinstance(item, (dict, list)):
                    pending.append((item, f"{path}.{key}"))
        elif isinstance(obj, list):
            pending.extend((item, f"{path}[{i}]") for i, item in enumerate(obj) if isinstance(item, (dict, list)))


def _mask_protocol_credentials(payload: dict) -> bool:
    """Mask only recognized credential positions, retaining keys and all nonsecret values."""
    changed = False
    def mask(obj, key):
        nonlocal changed
        if isinstance(obj, dict) and key in obj and obj[key] not in (None, "", "<redacted>"):
            obj[key] = "<redacted>"
            changed = True
    for block_name in ("ftp", "ftp_data"):
        ftp = payload.get(block_name)
        if not isinstance(ftp, dict) or _ftp_command(ftp.get("command")) not in _FTP_CREDENTIAL_COMMANDS:
            continue
        # A malformed data-transfer record can still contain a recognizable credential.
        # Mask both argument positions before storage, even when normalization rejects it.
        for key in ("command_data", "filename", "reply"):
            if isinstance(ftp.get(key), list):
                replacement = ["<redacted>" for _ in ftp[key]]
                if ftp[key] != replacement:
                    ftp[key] = replacement
                    changed = True
            else:
                mask(ftp, key)
    mask(payload.get("snmp"), "community")
    ldap = payload.get("ldap")
    for obj, key, _path, _certainty in _ldap_sensitive_fields(ldap, "ldap"):
        old = obj[key]
        replacement = ["<redacted>" for _ in old] if isinstance(old, list) else "<redacted>"
        if old != replacement:
            obj[key] = replacement
            changed = True
    request = ldap.get("request") if isinstance(ldap, dict) else None
    bind = request.get("bind_request") if isinstance(request, dict) else None
    if isinstance(bind, dict):
        mask(bind, "password")
        mask(bind, "credentials")
        mask(bind.get("sasl"), "credentials")
    return changed


def scrub_suricata_source(source: dict) -> dict:
    """Return source unchanged unless an identified EVE payload carries a known credential.

    Recognizes only the same Suricata dataset/provider markers as normalization. Raw
    JSON lines preserve their exact bytes when no masking is needed. A changed line
    is serialized deterministically; the raw reference hashes that stored form.
    """
    event = source.get("event")
    event = event if isinstance(event, dict) else {}
    data_stream = source.get("data_stream")
    data_stream = data_stream if isinstance(data_stream, dict) else {}
    dataset = event.get("dataset") or data_stream.get("dataset")
    recognized = (isinstance(dataset, str) and dataset.startswith("suricata.eve")) or (
        event.get("provider") == "suricata" and isinstance(dataset, str) and dataset in SURICATA_PROTOCOL_FAMILIES)
    if not recognized:
        return source
    result = copy.deepcopy(source)
    changed = False
    for container, key in ((result.get("event"), "original"), (result, "message")):
        if not isinstance(container, dict) or not isinstance(container.get(key), str):
            continue
        try:
            payload = json.loads(container[key])
        except (ValueError, TypeError):
            continue
        if (isinstance(payload, dict) and isinstance(payload.get("event_type"), str)
                and payload["event_type"] in SURICATA_PROTOCOL_FAMILIES
                and _mask_protocol_credentials(payload)):
            container[key] = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            changed = True
    block = result.get("suricata")
    if isinstance(block, dict):
        payload = block.get("eve", block)
        if isinstance(payload, dict):
            changed = _mask_protocol_credentials(payload) or changed
    return result if changed else source
