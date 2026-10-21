"""Per-event-family normalizers for the lab schema. Dispatch on authoritative type fields only."""
from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from datetime import UTC, datetime

from romulus.evidence.auditd import (
    SOCKET_SYSCALLS,
    AuditParseError,
    AuditRecord,
    execve_argv,
    parse_record,
    parse_sockaddr,
    socket_syscall,
)
from romulus.evidence.typed import EVIDENCE_VERSION, Outcome, RawRef, TypedEvent, event_id, fv

NORMALIZER_VERSION = f"lab-ecs@{EVIDENCE_VERSION}"


class Skip(Exception):
    """Record intentionally not normalized (e.g. a duplicate copy); counted, never silent."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def raw_digest(source: dict) -> str:
    return hashlib.sha256(json.dumps(source, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _ts(s: str) -> datetime:
    return datetime.fromisoformat(s).astimezone(UTC)


def _ref(hit: dict) -> RawRef:
    return RawRef(target=hit["_index"], native_id=hit["_id"], digest=raw_digest(hit["_source"]))


def _get(src: dict, path: str):
    cur = src
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _audit_boot_field(members: list[tuple[dict, AuditRecord]]) -> dict:
    """Preserve an ECS boot identity when the shipper supplied one for an audit group."""
    for hit, _record in members:
        source = hit["_source"]
        for path in ("host.boot.id", "system.boot.id"):
            value = _get(source, path)
            if value not in (None, ""):
                return {"host.boot.id": fv(value, f"{hit['_id']}:{path}")}
    return {}


# ---------------------------------------------------------------------------------------------
# linux.audit: multi-record events grouped by (host, serial)
# ---------------------------------------------------------------------------------------------

EXEC_COMPANIONS = {"EXECVE", "SYSCALL", "CWD", "PROCTITLE"}


def group_audit(hits: list[dict]) -> tuple[dict[tuple[str, float, int], list[tuple[dict, AuditRecord]]],
                                           list[tuple[str, str]]]:
    """Group audit records into events by (host, audit timestamp, serial). Records that cannot be
    parsed, or lack the authoritative raw text, are returned as errors: they are never dropped
    silently, because a dropped exec record would make a negative look complete."""
    groups: dict[tuple[str, float, int], list[tuple[dict, AuditRecord]]] = defaultdict(list)
    errors: list[tuple[str, str]] = []
    for h in hits:
        src = h["_source"]
        raw = _get(src, "event.original") or src.get("message")
        if not raw:
            errors.append((h["_id"], "linux.audit: missing authoritative event.original/message"))
            continue
        try:
            rec = parse_record(raw)
        except AuditParseError as e:
            errors.append((h["_id"], f"linux.audit: unparseable record: {e}"))
            continue
        groups[(_get(src, "host.name") or "", rec.ts, rec.serial)].append((h, rec))
    return groups, errors


def merge_execve(execs: list[tuple[dict, AuditRecord]]) -> tuple[dict, AuditRecord]:
    """auditd splits an exec with a very long argv across several EXECVE records: the first carries
    argc, continuations carry later aN fields. Merge them. Two records both carrying argc, or the same
    argument field with different values, are ambiguous and raise (never silently pick one)."""
    if len(execs) == 1:
        return execs[0]
    heads = [(h, r) for h, r in execs if "argc" in r.raw_fields]
    if len(heads) != 1:
        raise AuditParseError(f"ambiguous exec event: {len(heads)} EXECVE records carry argc")
    h_head, r_head = heads[0]
    raw, fields = dict(r_head.raw_fields), dict(r_head.fields)
    for _h, r in execs:
        if r is r_head:
            continue
        for k, v in r.raw_fields.items():
            if k in raw and raw[k] != v:
                raise AuditParseError(f"conflicting EXECVE continuation for {k}")
            raw[k] = v
            fields[k] = r.fields[k]
    merged = AuditRecord(type="EXECVE", ts=r_head.ts, serial=r_head.serial, fields=fields, raw_fields=raw,
                         enriched=r_head.enriched)
    return h_head, merged


def _syscall_process_fields(sid: str, rs: AuditRecord) -> dict:
    """Process identity from a SYSCALL record, with field lineage. Absent fields stay absent."""
    f = {}
    for name, key in (("process.pid", "pid"), ("process.ppid", "ppid")):
        if rs.fields.get(key, "").isdigit():
            f[name] = fv(int(rs.fields[key]), f"{sid}:event.original#auditd:SYSCALL.{key}")
    if rs.fields.get("exe"):
        f["process.executable"] = fv(rs.fields["exe"], f"{sid}:event.original#auditd:SYSCALL.exe")
    if rs.fields.get("comm"):
        f["process.comm"] = fv(rs.fields["comm"], f"{sid}:event.original#auditd:SYSCALL.comm")
    for name, key in (("process.uid", "uid"), ("process.euid", "euid"), ("process.auid", "auid")):
        if key in rs.fields and not (key == "auid" and rs.fields[key] in {"-1", "4294967295"}):
            f[name] = fv(rs.fields[key], f"{sid}:event.original#auditd:SYSCALL.{key}")
    session_id = rs.fields.get("ses")
    if session_id and session_id.isdigit() and session_id != "4294967295":
        f["process.session_id"] = fv(
            int(session_id), f"{sid}:event.original#auditd:SYSCALL.ses",
        )
    for name, key in (("process.user", "UID"), ("process.effective_user", "EUID"),
                      ("process.login_user", "AUID")):
        if key in rs.enriched:
            f[name] = fv(rs.enriched[key], f"{sid}:event.original#auditd:enriched.{key}")
    if rs.fields.get("tty"):
        f["process.tty"] = fv(rs.fields["tty"], f"{sid}:event.original#auditd:SYSCALL.tty")
    return f


SOCKET_COMPANIONS = {"SYSCALL", "SOCKADDR", "PROCTITLE"}
EINPROGRESS = "-115"
AUDIT_LOGIN_TYPES = {"USER_LOGIN", "USER_START"}
# What an auth record is: an authentication decision, a completed login, or a (PAM) session opening. One login
# can appear as all three (journal sshd "Accepted", audit USER_LOGIN, audit USER_START); rules count logins.
AUTH_PHASE = {"USER_LOGIN": "login", "USER_START": "session_open"}


def normalize_audit_auth_group(host: str, members: list[tuple[dict, AuditRecord]]) -> TypedEvent:
    """Normalize authoritative audit login/session records into the shared auth family."""
    login_members = sorted(
        ((hit, record) for hit, record in members if record.type in AUDIT_LOGIN_TYPES),
        key=lambda item: (item[1].type != "USER_LOGIN", item[0]["_id"]),
    )
    hit, record = login_members[0]
    native_id = hit["_id"]
    refs = [_ref(item_hit) for item_hit, item_record in login_members]
    origin = f"{native_id}:event.original#auditd:{record.type}"
    fields = {
        "auth.method": fv(record.type.lower(), f"{origin}.type"),
        "auth.phase": fv(AUTH_PHASE[record.type], f"{origin}.type"),
        **_audit_boot_field(members),
    }
    executable = record.fields.get("exe")
    if executable:
        service = executable.rsplit("/", 1)[-1]
        fields["auth.service"] = fv(service, f"{origin}.exe")
    session_id = record.fields.get("ses")
    if session_id and session_id.isdigit() and session_id != "4294967295":
        fields["process.session_id"] = fv(int(session_id), f"{origin}.ses")
    auid = record.fields.get("auid")
    if auid not in {None, "", "-1", "4294967295"}:
        fields["process.auid"] = fv(auid, f"{origin}.auid")
    # The login account is `acct`, else the audit (login) uid's name. Never UID: that is the process writing the
    # record (sshd), so a failed login by an unknown user would read as root.
    placeholders = {None, "", "?", "(null)", "(none)", "unset", "(unknown)"}
    if record.fields.get("acct") not in placeholders:
        fields["user.name"] = fv(record.fields["acct"], f"{origin}.acct")
    elif record.enriched.get("AUID") not in placeholders:
        fields["user.name"] = fv(record.enriched["AUID"], f"{origin}.AUID")
    address = record.fields.get("addr")
    if address not in {None, "", "?", "(null)", "(none)", "0.0.0.0", "::"}:
        fields["source.ip"] = fv(address, f"{origin}.addr")
    pid = record.fields.get("pid")
    if pid and pid.isdigit():
        fields["process.pid"] = fv(int(pid), f"{origin}.pid")
    result = (record.fields.get("res") or "").strip("'\"").lower()
    outcome = (Outcome.success if result in {"success", "yes"}
               else Outcome.failure if result in {"failed", "failure", "no"}
               else Outcome.unknown)
    return TypedEvent(
        id=event_id("auth", refs), family="auth", ts=datetime.fromtimestamp(record.ts, UTC),
        host=host or None, outcome=outcome, fields=fields, raw=refs,
        normalizer=NORMALIZER_VERSION,
    )


def normalize_socket_group(host: str, members: list[tuple[dict, AuditRecord]], syscall: str) -> TypedEvent:
    """One net_socket event from a socket SYSCALL plus its SOCKADDR. connect() records the remote
    endpoint, accept() the peer, bind() the local address. A non-blocking connect that returns
    EINPROGRESS was started, not refused, so its outcome is unknown rather than failed."""
    by_type = {r.type: (h, r) for h, r in members if r.type in SOCKET_COMPANIONS}
    hs, rs = by_type["SYSCALL"]
    sid = hs["_id"]
    refs = [_ref(h) for h, r in members if r.type in SOCKET_COMPANIONS]
    f = {"socket.syscall": fv(syscall, f"{sid}:event.original#auditd:SYSCALL.arch+syscall"),
         "audit.serial": fv(rs.serial, f"{sid}:event.original#auditd:msg.serial"),
         **_audit_boot_field(members),
         **_syscall_process_fields(sid, rs)}
    if rs.fields.get("key") not in (None, "(null)"):
        f["audit.key"] = fv(rs.fields["key"], f"{sid}:event.original#auditd:SYSCALL.key")
    caveats = []
    if "SOCKADDR" in by_type:
        ha, ra = by_type["SOCKADDR"]
        addr = parse_sockaddr(ra.fields.get("saddr", ""))
        origin = f"{ha['_id']}:event.original#auditd:SOCKADDR.saddr"
        if addr.ip is None:
            raise Skip(f"audit {syscall} on a non-IP socket family ({addr.family})")
        f["socket.family"] = fv(addr.family, origin)
        side = {"connect": "destination", "accept": "source", "accept4": "source", "bind": "socket.local"}[syscall]
        f[f"{side}.ip"] = fv(addr.ip, origin)
        f[f"{side}.port"] = fv(addr.port, origin)
    else:
        caveats.append("SOCKADDR companion not retrieved: socket address unknown")
    succ, exit_code = rs.fields.get("success"), rs.fields.get("exit")
    if succ == "yes":
        outcome = Outcome.success
    elif succ == "no" and exit_code == EINPROGRESS and syscall == "connect":
        outcome = Outcome.unknown
        caveats.append("non-blocking connect returned EINPROGRESS: the connection was started; completion is "
                       "not recorded")
    elif succ == "no":
        outcome = Outcome.failure
    else:
        outcome = Outcome.unknown
    if exit_code:
        f["socket.exit"] = fv(exit_code, f"{sid}:event.original#auditd:SYSCALL.exit")
    # the audit header's own epoch, not the shipper's @timestamp: joins with sensor clocks need the kernel time
    return TypedEvent(id=event_id("net_socket", refs), family="net_socket", ts=datetime.fromtimestamp(rs.ts, UTC),
                      host=host or None, outcome=outcome, fields=f, raw=refs, normalizer=NORMALIZER_VERSION,
                      caveats=caveats)


def normalize_exec_group(host: str, members: list[tuple[dict, AuditRecord]]) -> TypedEvent:
    """Build one process_exec event from the EXECVE record plus whatever companions are present.
    Missing SYSCALL means uid/ppid/success are unknown (caveat), not defaulted."""
    by_type = {r.type: (h, r) for h, r in members if r.type in EXEC_COMPANIONS and r.type != "EXECVE"}
    execs = [(h, r) for h, r in members if r.type == "EXECVE"]
    if not execs:
        raise Skip("no EXECVE record in group")
    h_exec, r_exec = merge_execve(execs)
    by_type["EXECVE"] = (h_exec, r_exec)
    argv = execve_argv(r_exec)
    refs = [_ref(h) for h, r in members if r.type in EXEC_COMPANIONS]
    nid = h_exec["_id"]
    f = {
        "process.argv": fv(argv, f"{nid}:event.original#auditd:EXECVE.a*"),
        "process.args_count": fv(len(argv), f"{nid}:event.original#auditd:EXECVE.argc"),
        "audit.serial": fv(r_exec.serial, f"{nid}:event.original#auditd:msg.serial"),
        **_audit_boot_field(members),
    }
    caveats = []
    outcome = Outcome.unknown
    if "SYSCALL" in by_type:
        hs, rs = by_type["SYSCALL"]
        f.update(_syscall_process_fields(hs["_id"], rs))
        succ = rs.fields.get("success")
        outcome = Outcome.success if succ == "yes" else Outcome.failure if succ == "no" else Outcome.unknown
    else:
        caveats.append("SYSCALL companion not retrieved: uid/ppid/executable/outcome unknown")
    if "CWD" in by_type:
        hc, rc = by_type["CWD"]
        f["process.cwd"] = fv(rc.fields.get("cwd"), f"{hc['_id']}:event.original#auditd:CWD.cwd")
    return TypedEvent(id=event_id("process_exec", refs), family="process_exec", ts=_ts(h_exec["_source"]["@timestamp"]),
                      host=host or None, outcome=outcome, fields=f, raw=refs, normalizer=NORMALIZER_VERSION,
                      caveats=caveats)


# ---------------------------------------------------------------------------------------------
# systemd.journal: sshd / sudo messages; audit copies are duplicates of linux.audit
# ---------------------------------------------------------------------------------------------

_SSH_OK = re.compile(r"^Accepted (?P<method>password|publickey|keyboard-interactive/pam|gssapi-with-mic) for "
                     r"(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)")
_SSH_FAIL = re.compile(r"^Failed (?P<method>password|publickey|none) for (?:invalid user )?(?P<user>\S+) from "
                       r"(?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)")
_SSH_INVALID = re.compile(r"^Invalid user (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)")
_SUDO = re.compile(r"^\s*(?P<user>\S+) : (?:(?P<fail>.*?incorrect password attempts?|command not allowed|"
                   r"user NOT in sudoers) ; )?TTY=(?P<tty>\S+) ; PWD=(?P<pwd>.*?) ; USER=(?P<target>\S+) ;"
                   r"(?: COMMAND=(?P<cmd>.*))?$")


def normalize_journal(hit: dict) -> TypedEvent:
    src = hit["_source"]
    original = _get(src, "event.original")
    if not original:
        # without the structured journal record we cannot tell an sshd login from anything else
        raise ValueError("journal record missing authoritative event.original")
    try:
        j = json.loads(original)
    except json.JSONDecodeError as e:
        raise ValueError(f"journal event.original is not JSON: {e}") from e
    if not isinstance(j, dict):
        raise TypeError("journal event.original is not a JSON object")
    if j.get("_TRANSPORT") == "audit" or j.get("SYSLOG_IDENTIFIER") == "audit":
        raise Skip("journal copy of an audit record (normalized from linux.audit)")
    ident = j.get("SYSLOG_IDENTIFIER") or j.get("_COMM")
    msg = j.get("MESSAGE") or src.get("message") or ""
    nid = hit["_id"]
    ref = _ref(hit)
    host = j.get("_HOSTNAME") or _get(src, "host.name")
    base = {"journal.identifier": fv(ident, f"{nid}:event.original#journal:SYSLOG_IDENTIFIER"),
            "journal.unit": fv(j.get("_SYSTEMD_UNIT"), f"{nid}:event.original#journal:_SYSTEMD_UNIT")}
    if ident == "sshd":
        for rx, outcome in ((_SSH_OK, Outcome.success), (_SSH_FAIL, Outcome.failure), (_SSH_INVALID, Outcome.failure)):
            m = rx.match(msg)
            if m:
                g = m.groupdict()
                f = {**base,
                     "auth.service": fv("sshd", f"{nid}:event.original#journal:SYSLOG_IDENTIFIER"),
                     "auth.method": fv(g.get("method"), f"{nid}:event.original#journal:MESSAGE~sshd"),
                     "auth.phase": fv("authentication", f"{nid}:event.original#journal:MESSAGE~sshd"),
                     "user.name": fv(g["user"], f"{nid}:event.original#journal:MESSAGE~sshd"),
                     "source.ip": fv(g["ip"], f"{nid}:event.original#journal:MESSAGE~sshd")}
                if g.get("port"):
                    f["source.port"] = fv(int(g["port"]), f"{nid}:event.original#journal:MESSAGE~sshd")
                return TypedEvent(id=event_id("auth", [ref]), family="auth", ts=_ts(src["@timestamp"]), host=host,
                                  outcome=outcome, fields=f, raw=[ref], normalizer=NORMALIZER_VERSION)
        raise Skip("sshd message without an authentication outcome")
    if ident == "sudo":
        m = _SUDO.match(msg)
        if m:
            g = m.groupdict()
            f = {**base,
                 "auth.service": fv("sudo", f"{nid}:event.original#journal:SYSLOG_IDENTIFIER"),
                 "user.name": fv(g["user"], f"{nid}:event.original#journal:MESSAGE~sudo"),
                 "auth.target_user": fv(g["target"], f"{nid}:event.original#journal:MESSAGE~sudo"),
                 "sudo.command": fv(g.get("cmd"), f"{nid}:event.original#journal:MESSAGE~sudo"),
                 "process.cwd": fv(g.get("pwd"), f"{nid}:event.original#journal:MESSAGE~sudo")}
            outcome = Outcome.failure if g.get("fail") else Outcome.success
            return TypedEvent(id=event_id("privilege_use", [ref]), family="privilege_use", ts=_ts(src["@timestamp"]),
                              host=host, outcome=outcome, fields=f, raw=[ref], normalizer=NORMALIZER_VERSION)
        raise Skip("sudo message not a command record")
    raise Skip(f"journal identifier {ident!r} is not normalized")


# ---------------------------------------------------------------------------------------------
# apache
# ---------------------------------------------------------------------------------------------

def normalize_apache_access(hit: dict) -> TypedEvent:
    src, nid, ref = hit["_source"], hit["_id"], _ref(hit)
    f = {}
    for typed, native in (("source.ip", "source.ip"), ("http.request.method", "http.request.method"),
                          ("http.response.status_code", "http.response.status_code"),
                          ("url.original", "url.original"), ("user_agent.original", "user_agent.original")):
        v = _get(src, native)
        if v is not None:
            f[typed] = fv(v, f"{nid}:{native}")
    status = f.get("http.response.status_code")
    outcome = Outcome.unknown if status is None else (Outcome.success if int(status.value) < 400 else Outcome.failure)
    return TypedEvent(id=event_id("http_access", [ref]), family="http_access", ts=_ts(src["@timestamp"]),
                      host=_get(src, "host.name"), outcome=outcome, fields=f, raw=[ref], normalizer=NORMALIZER_VERSION)


def normalize_apache_error(hit: dict) -> TypedEvent:
    src, nid, ref = hit["_source"], hit["_id"], _ref(hit)
    f = {"web.error_message": fv(src.get("message"), f"{nid}:message")}
    if _get(src, "source.ip"):
        f["source.ip"] = fv(_get(src, "source.ip"), f"{nid}:source.ip")
    caveats = ["timestamp timezone assumed UTC by importer"] if _get(src, "event.timezone") == "assumed_utc" else []
    return TypedEvent(id=event_id("web_error", [ref]), family="web_error", ts=_ts(src["@timestamp"]),
                      host=_get(src, "host.name"), fields=f, raw=[ref], normalizer=NORMALIZER_VERSION, caveats=caveats)


# ---------------------------------------------------------------------------------------------
# suricata EVE (authoritative JSON in event.original)
# ---------------------------------------------------------------------------------------------
#
# Handshake and DNS fields shared by the Suricata and Arkime paths, so rules read one contract:
# - tls.ja3, tls.ja3s, tls.ja4, ssh.hassh, ssh.hassh_server: list[str], sorted and distinct, every value the record
#   carries (Arkime stores them as arrays; Suricata logs one per transaction). JA3, JA3S and HASSH are hex
#   digests and are lowercased; JA4 is kept as recorded.
# - tls.version: list[str] spelled as Arkime does ("TLSv1.2"). tls.client.server_name: str (Suricata SNI).
#   tls.resumed: bool (Suricata: the handshake resumed a session, so no certificate was sent).
# - tls.server.certificates: list[dict], one per distinct presented certificate, sorted by (sha1, subject,
#   not_before) because Arkime's array is not in chain order. Keys: subject_cn, subject_on, issuer_cn, issuer_on,
#   alt_names (list[str]); subject_dn, issuer_dn (str or None, Suricata only); not_before, not_after (ISO-8601
#   UTC or None); valid_days (int or None, as Arkime reported it); sha1, serial (lowercase hex or None);
#   names_compared ("distinguished name" or "CN and O"); self_issued (bool, or None when either name is empty:
#   the subject name equals the issuer name); issues_other (bool: its subject name is the issuer name of another
#   certificate in the same record, so it is a CA in the presented chain, not the server's own certificate).
# - tls.server.subject_cn, tls.server.issuer_cn (list[str]), tls.server.not_before, tls.server.not_after (ISO),
#   tls.server.hash_sha1 (str): the server's own certificate, set only when exactly one presented certificate
#   issues no other (Suricata logs only the server's certificate). Never a pick among several.
# - ssh.client.software, ssh.client.proto_version, ssh.server.software, ssh.server.proto_version: str (Suricata,
#   attributed by direction). ssh.version (Arkime): list[str] of SSH banners, not attributed to either side.
# - dns.question.names, dns.question.types, dns.response_codes: sorted distinct list[str]. dns.question.name,
#   dns.question.type, dns.response_code: str, only when the record holds exactly one distinct value.
#   dns.answers, dns.authorities: list of {"name", "type", "ttl", "data"} in record order.
# - parse.malformed: sorted native paths that were present but not of the documented type. Such a value is
#   dropped, never guessed or stringified; a rule that needs it counts the record as missing that field.

_HEX_DIGESTS = {"tls.ja3", "tls.ja3s", "ssh.hassh", "ssh.hassh_server"}
# Suricata writes RFC 4514-style one-line names ("C=US, O=Example, CN=host"); a comma followed by an attribute
# type and "=" starts the next attribute, so a comma inside a value ("O=Acme, Inc.") does not split.
_RDN_SPLIT = re.compile(r",\s*(?=[A-Za-z][A-Za-z0-9.-]*=)")
_SURICATA_TLS_VERSION = re.compile(r"^TLS (\d\.\d)$")


def _absent(value) -> bool:
    return value is None or value == "" or value == [] or value == {}


def _strings(value, path: str, bad: list[str], *, lower: bool = False) -> list[str] | None:
    """A string-or-array-of-strings field as a sorted distinct list (Elasticsearch stores `x` and `[x]` alike).
    None when absent; any non-string element makes the whole field malformed."""
    if _absent(value):
        return None
    items = value if isinstance(value, list) else [value]
    if not all(isinstance(item, str) for item in items):
        bad.append(path)
        return None
    out = sorted({item.lower() if lower else item for item in items if item})
    return out or None


def _scalar_str(value, path: str, bad: list[str]) -> str | None:
    if _absent(value):
        return None
    if not isinstance(value, str):
        bad.append(path)
        return None
    return value


def _objects(value, path: str, bad: list[str]) -> list[dict] | None:
    """An object-or-array-of-objects block as a list. None when absent; a non-object element is malformed."""
    if _absent(value):
        return None
    items = value if isinstance(value, list) else [value]
    if not all(isinstance(item, dict) for item in items):
        bad.append(path)
        return None
    return items


def _count(value, path: str, bad: list[str]) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        bad.append(path)
        return None
    return value


def _cert_time(value, path: str, bad: list[str]) -> str | None:
    """A certificate validity bound as ISO-8601 UTC. Arkime stores epoch milliseconds; Suricata writes ISO time
    without a zone, in UTC."""
    if value is None:
        return None
    try:
        if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0:
            return datetime.fromtimestamp(value / 1000, UTC).isoformat()
        if isinstance(value, str):
            parsed = datetime.fromisoformat(value)
            return (parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)).astimezone(UTC).isoformat()
    except (ValueError, OverflowError, OSError):
        pass
    bad.append(path)
    return None


def _hex_id(value, path: str, bad: list[str]) -> str | None:
    """A certificate hash or serial as lowercase hex; separators are kept for hashes, removed for serials."""
    text = _scalar_str(value, path, bad)
    return None if text is None else text.lower()


def _dn_parts(dn: str) -> list[tuple[str, str]]:
    parts = []
    for rdn in _RDN_SPLIT.split(dn.strip()):
        key, sep, val = rdn.partition("=")
        if sep and key.strip():
            parts.append((key.strip().upper(), val.strip()))
    return parts


def _name_key(cert: dict, side: str):
    """Comparable identity of a certificate's subject or issuer name: the whole distinguished name when the
    source recorded it, otherwise its CN and O values. None when nothing is recorded."""
    dn = cert.get(f"{side}_dn")
    if dn:
        parts = _dn_parts(dn)
        if parts:
            return ("dn", tuple((key, val.casefold()) for key, val in parts))
    cn = tuple(sorted({v.casefold() for v in cert[f"{side}_cn"]}))
    on = tuple(sorted({v.casefold() for v in cert[f"{side}_on"]}))
    return ("cn_on", cn, on) if (cn or on) else None


def _certificate_fields(certs: list[dict], origin: str, caveats: list[str]) -> dict:
    """Typed fields for the certificates one record presented: dedupe, sort, mark self-issued certificates and
    the ones that issued another presented certificate, and set the server-certificate fields only when that
    certificate is unambiguous."""
    distinct = {json.dumps(c, sort_keys=True): c for c in certs}
    certs = sorted(distinct.values(), key=lambda c: (c["sha1"] or "", json.dumps(c["subject_cn"]),
                                                     c["subject_dn"] or "", c["not_before"] or ""))
    for cert in certs:
        subject, issuer = _name_key(cert, "subject"), _name_key(cert, "issuer")
        cert["names_compared"] = "distinguished name" if cert["subject_dn"] and cert["issuer_dn"] else "CN and O"
        cert["self_issued"] = None if subject is None or issuer is None else subject == issuer
        cert["issues_other"] = subject is not None and any(
            other is not cert and _name_key(other, "issuer") == subject for other in certs)
    f = {"tls.server.certificates": fv(certs, origin)}
    leaves = [c for c in certs if not c["issues_other"]]
    if len(leaves) == 1:
        leaf, derived = leaves[0], f"{origin}#derived:server-certificate"
        for typed, key in (("tls.server.subject_cn", "subject_cn"), ("tls.server.issuer_cn", "issuer_cn"),
                           ("tls.server.not_before", "not_before"), ("tls.server.not_after", "not_after"),
                           ("tls.server.hash_sha1", "sha1")):
            if not _absent(leaf[key]):
                f[typed] = fv(leaf[key], derived)
    else:
        caveats.append(f"{len(leaves)} presented certificates issue no other presented certificate: the server's "
                       f"own certificate is ambiguous; per-certificate values are in tls.server.certificates")
    return f


def _suricata_tls(t: dict, o: str, bad: list[str], caveats: list[str]) -> dict:
    f = {}
    sni = _scalar_str(t.get("sni"), "tls.sni", bad)
    if sni is not None:
        f["tls.client.server_name"] = fv(sni, f"{o}.tls.sni")
    version = _scalar_str(t.get("version"), "tls.version", bad)
    if version is not None:
        m = _SURICATA_TLS_VERSION.match(version)
        f["tls.version"] = fv([f"TLSv{m.group(1)}" if m else version], f"{o}.tls.version")
    for typed, key in (("tls.ja3", "ja3"), ("tls.ja3s", "ja3s")):
        value, path = t.get(key), f"tls.{key}"
        if isinstance(value, dict):                     # {"hash": ..., "string": ...}
            value, path = value.get("hash"), f"tls.{key}.hash"
        hashes = _strings(value, path, bad, lower=True)
        if hashes:
            f[typed] = fv(hashes, f"{o}.{path}")
    ja4 = _strings(t.get("ja4"), "tls.ja4", bad)
    if ja4:
        f["tls.ja4"] = fv(ja4, f"{o}.tls.ja4")
    if isinstance(t.get("session_resumed"), bool):
        f["tls.resumed"] = fv(t["session_resumed"], f"{o}.tls.session_resumed")
    cert_keys = ("subject", "issuerdn", "notbefore", "notafter", "fingerprint", "serial")
    if any(not _absent(t.get(k)) for k in cert_keys):
        subject = _scalar_str(t.get("subject"), "tls.subject", bad)
        issuer = _scalar_str(t.get("issuerdn"), "tls.issuerdn", bad)
        sparts, iparts = _dn_parts(subject or ""), _dn_parts(issuer or "")
        serial = _hex_id(t.get("serial"), "tls.serial", bad)
        cert = {"subject_cn": [v for k, v in sparts if k == "CN"], "subject_on": [v for k, v in sparts if k == "O"],
                "issuer_cn": [v for k, v in iparts if k == "CN"], "issuer_on": [v for k, v in iparts if k == "O"],
                "subject_dn": subject, "issuer_dn": issuer,
                "not_before": _cert_time(t.get("notbefore"), "tls.notbefore", bad),
                "not_after": _cert_time(t.get("notafter"), "tls.notafter", bad), "valid_days": None,
                "alt_names": _strings(t.get("subjectaltname"), "tls.subjectaltname", bad) or [],
                "sha1": _hex_id(t.get("fingerprint"), "tls.fingerprint", bad),
                "serial": serial.replace(":", "") if serial else None}
        f.update(_certificate_fields([cert], f"{o}.tls.{'+'.join(cert_keys)}", caveats))
    return f


def _suricata_ssh(s: dict, o: str, bad: list[str]) -> dict:
    f = {}
    for side, typed_hassh in (("client", "ssh.hassh"), ("server", "ssh.hassh_server")):
        block = s.get(side)
        if _absent(block):
            continue
        if not isinstance(block, dict):
            bad.append(f"ssh.{side}")
            continue
        for typed, key in (("software", "software_version"), ("proto_version", "proto_version")):
            value = _scalar_str(block.get(key), f"ssh.{side}.{key}", bad)
            if value is not None:
                f[f"ssh.{side}.{typed}"] = fv(value, f"{o}.ssh.{side}.{key}")
        hassh = block.get("hassh")
        value, path = (hassh.get("hash"), f"ssh.{side}.hassh.hash") if isinstance(hassh, dict) \
            else (hassh, f"ssh.{side}.hassh")
        hashes = _strings(value, path, bad, lower=True)
        if hashes:
            f[typed_hassh] = fv(hashes, f"{o}.{path}")
    return f


def _dns_record(item: dict, path: str, bad: list[str]) -> dict:
    ttl = _count(item.get("ttl"), f"{path}.ttl", bad)
    return {"name": _scalar_str(item.get("rrname"), f"{path}.rrname", bad),
            "type": _scalar_str(item.get("rrtype"), f"{path}.rrtype", bad), "ttl": ttl,
            "data": item["rdata"] if isinstance(item.get("rdata"), str) else None}


def _dns_name_fields(names: set[str], types: set[str], codes: set[str], origin: str) -> dict:
    """List fields always; the scalar only when exactly one distinct value exists."""
    f = {}
    for values, plural, single in ((names, "dns.question.names", "dns.question.name"),
                                   (types, "dns.question.types", "dns.question.type"),
                                   (codes, "dns.response_codes", "dns.response_code")):
        if values:
            f[plural] = fv(sorted(values), origin)
            if len(values) == 1:
                f[single] = fv(next(iter(values)), origin)
    return f


def _suricata_dns(d: dict, o: str, bad: list[str]) -> dict:
    f = {"dns.type": fv(d.get("type"), f"{o}.dns.type")}
    names, types = set(), set()
    rrname = _scalar_str(d.get("rrname"), "dns.rrname", bad)
    rrtype = _scalar_str(d.get("rrtype"), "dns.rrtype", bad)
    names.update([rrname] if rrname else [])
    types.update([rrtype] if rrtype else [])
    queries = _objects(d.get("queries"), "dns.queries", bad) or []
    for i, query in enumerate(queries):
        q = _dns_record(query, f"dns.queries[{i}]", bad)
        names.update([q["name"]] if q["name"] else [])
        types.update([q["type"]] if q["type"] else [])
    code = _scalar_str(d.get("rcode"), "dns.rcode", bad)
    f.update(_dns_name_fields(names, types, {code} if code else set(), f"{o}.dns.rrname+rrtype+queries+rcode"))
    for typed, key in (("dns.answers", "answers"), ("dns.authorities", "authorities")):
        items = _objects(d.get(key), f"dns.{key}", bad)
        if items:
            f[typed] = fv([_dns_record(item, f"dns.{key}[{i}]", bad) for i, item in enumerate(items)],
                          f"{o}.dns.{key}")
    grouped = d.get("grouped")
    if "dns.answers" not in f and not _absent(grouped):
        if not isinstance(grouped, dict) or not all(isinstance(v, list) for v in grouped.values()):
            bad.append("dns.grouped")
        else:
            f["dns.answers"] = fv([{"name": None, "type": rtype, "ttl": None,
                                    "data": value if isinstance(value, str) else None}
                                   for rtype, values in sorted(grouped.items()) for value in values],
                                  f"{o}.dns.grouped")
    return f


def _app_block(eve: dict, key: str) -> dict | None:
    """An app-layer block of a Suricata record; a block of the wrong type makes the record unreadable."""
    if key not in eve:
        return None
    block = eve[key]
    if not isinstance(block, dict):
        raise TypeError(f"suricata {key} block is {type(block).__name__}, not an object")
    return block


def normalize_suricata(hit: dict) -> TypedEvent:
    src, nid, ref = hit["_source"], hit["_id"], _ref(hit)
    try:
        eve = json.loads(_get(src, "event.original") or src.get("message") or "")
    except json.JSONDecodeError as e:
        raise ValueError(f"suricata event.original is not JSON: {e}") from e
    et = eve.get("event_type")
    o = f"{nid}:event.original#eve"
    f = {"source.ip": fv(eve.get("src_ip"), f"{o}.src_ip"), "destination.ip": fv(eve.get("dest_ip"), f"{o}.dest_ip"),
         "source.port": fv(eve.get("src_port"), f"{o}.src_port"),
         "destination.port": fv(eve.get("dest_port"), f"{o}.dest_port"),
         "network.transport": fv((eve.get("proto") or "").lower() or None, f"{o}.proto"),
         "network.app_proto": fv(eve.get("app_proto"), f"{o}.app_proto"),
         "network.community_id": fv(eve.get("community_id"), f"{o}.community_id"),
         "suricata.flow_id": fv(eve.get("flow_id"), f"{o}.flow_id")}
    family = {"alert": "net_alert", "flow": "net_flow", "netflow": "net_flow", "dns": "dns_query",
              "http": "http_tx", "fileinfo": "file_transfer", "tls": "tls_session", "ssh": "ssh_session"}.get(et)
    if family is None:
        raise Skip(f"suricata event_type {et!r} is not normalized")
    if et == "alert":
        a = eve.get("alert", {})
        for k in ("signature", "signature_id", "category", "severity", "action"):
            f[f"alert.{k}"] = fv(a.get(k), f"{o}.alert.{k}")
        md = a.get("metadata") or {}
        f["alert.mitre_technique_id"] = fv(md.get("mitre_technique_id"), f"{o}.alert.metadata.mitre_technique_id")
        f["alert.signature_severity"] = fv(md.get("signature_severity"), f"{o}.alert.metadata.signature_severity")
    flow = eve.get("flow") or eve.get("netflow") or {}
    for k in ("bytes_toserver", "bytes_toclient", "pkts_toserver", "pkts_toclient", "bytes", "pkts", "start", "end",
              "state"):
        if k in flow:
            f[f"flow.{k}"] = fv(flow[k], f"{o}.flow.{k}")
    bad: list[str] = []
    caveats: list[str] = []
    d = _app_block(eve, "dns")
    if d is not None:
        f.update(_suricata_dns(d, o, bad))
    t = _app_block(eve, "tls")
    if t is not None:
        f.update(_suricata_tls(t, o, bad, caveats))
    s = _app_block(eve, "ssh")
    if s is not None:
        f.update(_suricata_ssh(s, o, bad))
    if bad:
        f["parse.malformed"] = fv(sorted(set(bad)), f"{o}#malformed")
    if "http" in eve:
        h = eve["http"]
        for typed, k in (("http.hostname", "hostname"), ("url.original", "url"),
                         ("user_agent.original", "http_user_agent"), ("http.request.method", "http_method"),
                         ("http.response.status_code", "status"), ("http.response.length", "length"),
                         ("http.content_type", "http_content_type")):
            if k in h:
                f[typed] = fv(h[k], f"{o}.http.{k}")
    if "fileinfo" in eve:
        fi = eve["fileinfo"]
        f["file.name"] = fv(fi.get("filename"), f"{o}.fileinfo.filename")
        f["file.size"] = fv(fi.get("size"), f"{o}.fileinfo.size")
    ts = _ts(eve["timestamp"]) if eve.get("timestamp") else _ts(src["@timestamp"])
    return TypedEvent(id=event_id(family, [ref]), family=family, ts=ts, host=_get(src, "host.name"),
                      fields={k: v for k, v in f.items() if v.value is not None}, raw=[ref],
                      normalizer=NORMALIZER_VERSION, caveats=caveats)


# ---------------------------------------------------------------------------------------------
# Arkime SPI session records (read from the session indices)
# ---------------------------------------------------------------------------------------------
# Arkime 6.x stores `cert` and `dns` as arrays of objects, and its string fields (ja3, hassh, versions, tags) as
# arrays. Each is read with the shared contract above; a block of an undocumented type is dropped and listed in
# parse.malformed, and the rest of the session record is kept.

IP_PROTOCOLS = {1: "icmp", 6: "tcp", 17: "udp", 58: "ipv6-icmp", 132: "sctp"}
ARKIME_FIELDS = (
    # typed name, native path: values passed through as stored
    ("source.ip", "source.ip"), ("source.port", "source.port"), ("destination.ip", "destination.ip"),
    ("destination.port", "destination.port"), ("network.community_id", "network.community_id"),
    ("source.bytes", "source.bytes"), ("source.packets", "source.packets"),
    ("destination.bytes", "destination.bytes"), ("destination.packets", "destination.packets"),
    ("client.bytes", "client.bytes"), ("server.bytes", "server.bytes"),
    ("http.hostname", "http.host"), ("url.path", "http.uri"), ("user_agent.original", "http.useragent"),
    ("http.request.method", "http.method"), ("http.response.status_code", "http.statuscode"),
    ("network.protocols", "protocol"),
)
# typed name, native path: string-or-array fields read as sorted distinct string lists (see the contract above)
ARKIME_STRING_LISTS = (
    ("tls.ja3", "tls.ja3"), ("tls.ja3s", "tls.ja3s"), ("tls.ja4", "tls.ja4"), ("tls.version", "tls.version"),
    ("ssh.hassh", "ssh.hassh"), ("ssh.hassh_server", "ssh.hasshServer"), ("ssh.version", "ssh.version"),
    ("http.body_magic", "http.bodyMagic"), ("arkime.tags", "tags"),
)
# Arkime's per-session TCP flag counters: typed suffix, native key
ARKIME_TCP_FLAGS = (("syn", "syn"), ("syn_ack", "syn-ack"), ("ack", "ack"), ("psh", "psh"), ("fin", "fin"),
                    ("rst", "rst"), ("urg", "urg"))
# keys of an Arkime DNS answer object that describe the answer rather than carry its data
_ARKIME_ANSWER_META = {"type", "class", "ttl", "name", "priority"}


def is_arkime_session(src: dict) -> bool:
    return "firstPacket" in src and "lastPacket" in src and isinstance(src.get("source"), dict)


def _epoch_ms(value) -> datetime:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise TypeError(f"Arkime packet time is not epoch milliseconds: {value!r}")
    return datetime.fromtimestamp(value / 1000, UTC)


def _arkime_path(src: dict, path: str, bad: list[str]):
    """A nested value; a non-object on the way is malformed, not merely absent."""
    cur = src
    parts = path.split(".")
    for i, part in enumerate(parts):
        if cur is None:
            return None
        if not isinstance(cur, dict):
            bad.append(".".join(parts[:i]))
            return None
        cur = cur.get(part)
    return cur


def _arkime_certificates(src: dict, nid: str, bad: list[str], caveats: list[str]) -> dict:
    objs = _objects(src.get("cert"), "cert", bad)
    if not objs:
        return {}
    certs = []
    for i, obj in enumerate(objs):
        p = f"cert[{i}]"
        names = {key: _strings(obj.get(native), f"{p}.{native}", bad) or []
                 for key, native in (("subject_cn", "subjectCN"), ("subject_on", "subjectON"),
                                     ("issuer_cn", "issuerCN"), ("issuer_on", "issuerON"), ("alt_names", "alt"))}
        serial = _hex_id(obj.get("serial"), f"{p}.serial", bad)
        certs.append({**names, "subject_dn": None, "issuer_dn": None,
                      "not_before": _cert_time(obj.get("notBefore"), f"{p}.notBefore", bad),
                      "not_after": _cert_time(obj.get("notAfter"), f"{p}.notAfter", bad),
                      "valid_days": _count(obj.get("validDays"), f"{p}.validDays", bad),
                      "sha1": _hex_id(obj.get("hash"), f"{p}.hash", bad),
                      "serial": serial.replace(":", "") if serial else None})
    return _certificate_fields(certs, f"{nid}:cert", caveats)


def _arkime_answer(obj: dict, path: str, bad: list[str]) -> dict:
    """One Arkime DNS answer. Its data is the one string held under a non-descriptive key (ip, cname, nameserver,
    mx, txt, ...); with none, or several, the data is unknown (None), never a pick."""
    held = [v for k, v in obj.items() if k not in _ARKIME_ANSWER_META and not k.endswith("Cnt")]
    values = [v for v in held if isinstance(v, str)] + [x for v in held if isinstance(v, list) for x in v
                                                        if isinstance(x, str)]
    return {"name": _scalar_str(obj.get("name"), f"{path}.name", bad),
            "type": _scalar_str(obj.get("type"), f"{path}.type", bad),
            "ttl": _count(obj.get("ttl"), f"{path}.ttl", bad),
            "data": values[0] if len(values) == 1 else None}


def _arkime_dns(src: dict, nid: str, bad: list[str]) -> dict:
    objs = _objects(src.get("dns"), "dns", bad)
    if not objs:
        return {}
    names, types, codes, answers = set(), set(), set(), []
    for i, obj in enumerate(objs):
        p = f"dns[{i}]"
        names.update(_strings(obj.get("host"), f"{p}.host", bad) or [])
        types.update(_strings(obj.get("qt"), f"{p}.qt", bad) or [])
        codes.update(_strings(obj.get("status"), f"{p}.status", bad) or [])
        for j, ans in enumerate(_objects(obj.get("answers"), f"{p}.answers", bad) or []):
            answers.append(_arkime_answer(ans, f"{p}.answers[{j}]", bad))
    f = _dns_name_fields(names, types, codes, f"{nid}:dns")
    if answers:
        f["dns.answers"] = fv(answers, f"{nid}:dns.answers")
    return f


def normalize_arkime_session(hit: dict) -> TypedEvent:
    """One net_session per Arkime SPI record. Arkime saves long sessions in several records (one per
    save interval) sharing the 5-tuple and community ID; each record is one event, and rules that need
    the whole connection stitch them by community ID. Handshake fields (tls, ssh, cert) are on the first
    record only; every record of a split session carries rootId naming the first, and a record whose
    rootId is not its own id is marked arkime.continuation."""
    src, nid, ref = hit["_source"], hit["_id"], _ref(hit)
    first, last = _epoch_ms(src.get("firstPacket")), _epoch_ms(src.get("lastPacket"))
    f = {}
    bad: list[str] = []
    caveats: list[str] = []
    for typed, native in ARKIME_FIELDS:
        v = _get(src, native)
        if v not in (None, [], ""):
            f[typed] = fv(v, f"{nid}:{native}")
    for typed, native in ARKIME_STRING_LISTS:
        values = _strings(_arkime_path(src, native, bad), native, bad, lower=typed in _HEX_DIGESTS)
        if values:
            f[typed] = fv(values, f"{nid}:{native}")
    flags = src.get("tcpflags")
    if isinstance(flags, dict):
        for typed, native in ARKIME_TCP_FLAGS:
            count = _count(flags.get(native), f"tcpflags.{native}", bad)
            if count is not None:
                f[f"tcp.flags.{typed}"] = fv(count, f"{nid}:tcpflags.{native}")
    elif not _absent(flags):
        bad.append("tcpflags")
    root = _scalar_str(src.get("rootId"), "rootId", bad)
    if root is not None:
        f["arkime.root_id"] = fv(root, f"{nid}:rootId")
        f["arkime.continuation"] = fv(root != nid, f"{nid}:rootId#derived:differs-from-own-id")
    f.update(_arkime_certificates(src, nid, bad, caveats))
    f.update(_arkime_dns(src, nid, bad))
    if bad:
        f["parse.malformed"] = fv(sorted(set(bad)), f"{nid}:#malformed")
    proto = src.get("ipProtocol")
    if proto is not None:
        f["network.transport"] = fv(IP_PROTOCOLS.get(proto, str(proto)), f"{nid}:ipProtocol")
    f["flow.start"] = fv(first.isoformat(), f"{nid}:firstPacket")
    f["flow.end"] = fv(last.isoformat(), f"{nid}:lastPacket")
    f["session.duration_s"] = fv(round((last - first).total_seconds(), 3), f"{nid}:lastPacket-firstPacket")
    f["arkime.node"] = fv(src.get("node"), f"{nid}:node")
    return TypedEvent(id=event_id("net_session", [ref]), family="net_session", ts=first, host=src.get("node"),
                      fields={k: v for k, v in f.items() if v.value is not None}, raw=[ref],
                      normalizer=NORMALIZER_VERSION, caveats=caveats)


SINGLE = {
    "systemd.journal": normalize_journal,
    "apache.access": normalize_apache_access,
    "apache.error": normalize_apache_error,
}


def normalize_hits(hits: list[dict]) -> tuple[list[TypedEvent], dict[str, int], list[tuple[str, str]]]:
    """Normalize a batch. Returns (events, skip_counts, errors[(raw_id, error)])."""
    events, skips, errors = [], defaultdict(int), []
    audit_hits = []
    for h in hits:
        ds = _get(h["_source"], "event.dataset") or ""
        try:
            if not ds and is_arkime_session(h["_source"]):
                ds = "arkime.session"
                events.append(normalize_arkime_session(h))
            elif ds == "linux.audit":
                audit_hits.append(h)
            elif ds.startswith("suricata.eve"):
                events.append(normalize_suricata(h))
            elif ds in SINGLE:
                events.append(SINGLE[ds](h))
            else:
                skips[f"dataset:{ds} is not normalized"] += 1
        except Skip as s:
            skips[s.reason] += 1
        except (ValueError, KeyError, TypeError, AttributeError) as e:   # malformed telemetry: an error, never a crash
            errors.append((h["_id"], f"{ds}: {e}"))
    groups, audit_errors = group_audit(audit_hits)
    errors.extend(audit_errors)
    for (host, _ts, _serial), members in groups.items():
        types = {r.type for _, r in members}
        # EXECVE may legitimately repeat (long-argv continuation records; merged in normalize_exec_group)
        dup = sorted(t for t in types if sum(1 for _, r in members if r.type == t) > 1
                     and t in EXEC_COMPANIONS | SOCKET_COMPANIONS and t != "EXECVE")
        if dup:
            errors.append((members[0][0]["_id"], f"linux.audit: ambiguous event group, duplicate {dup} records"))
            continue
        if types & AUDIT_LOGIN_TYPES:
            try:
                events.append(normalize_audit_auth_group(host, members))
            except (ValueError, KeyError, TypeError) as e:
                errors.append((members[0][0]["_id"], f"linux.audit.auth: {e}"))
            continue
        if "EXECVE" not in types:
            sys_rec = next((r for _, r in members if r.type == "SYSCALL"), None)
            syscall = socket_syscall(sys_rec) if sys_rec is not None else None
            if syscall is None:
                arch = sys_rec.fields.get("arch", "") if sys_rec is not None else ""
                skips["audit group without EXECVE or socket syscall" if not arch or arch in SOCKET_SYSCALLS
                      else f"audit syscall on an arch whose socket calls are not decoded ({arch})"] += 1
                continue
            try:
                events.append(normalize_socket_group(host, members, syscall))
            except Skip as s:
                skips[s.reason] += 1
            except (AuditParseError, ValueError, KeyError) as e:
                # tagged by family so the sweep marks only socket rules partial
                errors.append((members[0][0]["_id"], f"linux.audit.socket: {e}"))
            continue
        try:
            events.append(normalize_exec_group(host, members))
        except Skip as s:
            skips[s.reason] += 1
        except (AuditParseError, ValueError, KeyError) as e:
            errors.append((members[0][0]["_id"], f"linux.audit: {e}"))
    return events, dict(skips), errors
