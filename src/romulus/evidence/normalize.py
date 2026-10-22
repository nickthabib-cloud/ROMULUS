"""Per-event-family normalizers for the lab schema. Dispatch on authoritative type fields only."""
from __future__ import annotations

import hashlib
import json
import posixpath
import re
from collections import defaultdict
from datetime import UTC, datetime

from romulus.evidence.auditd import (
    AT_FDCWD,
    O_ACCMODE,
    O_CREAT,
    O_RDWR,
    O_TMPFILE_BIT,
    O_TRUNC,
    O_WRONLY,
    SOCKET_SYSCALLS,
    AuditParseError,
    AuditRecord,
    FileCall,
    execve_argv,
    file_syscall,
    parse_record,
    parse_sockaddr,
    socket_syscall,
    syscall_arg,
)
from romulus.evidence.typed import EVIDENCE_VERSION, Outcome, RawRef, TypedEvent, event_id, fv

NORMALIZER_VERSION = f"lab-ecs@{EVIDENCE_VERSION}"
# Caveat on a process_exec event whose EXECVE arguments did not all arrive (its process.argv_complete is false).
INCOMPLETE_ARGV_CAVEAT = "command line incomplete"


class Skip(Exception):
    """Record intentionally not normalized (e.g. a duplicate copy); counted, never silent."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class AuditCopy(Skip):
    """A journald copy of an audit record: a duplicate, but its journald fields name the boot it was written in."""

    def __init__(self, record: dict):
        super().__init__("journal copy of an audit record (normalized from linux.audit)")
        self.record = record


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


# journald's boot id: 128 bits as 32 lower-case hex digits. journald sets it (an underscore field), not the writer.
_BOOT_ID = re.compile(r"[0-9a-f]{32}")


def _journal_boot(j: dict) -> str | None:
    value = j.get("_BOOT_ID")
    return value if isinstance(value, str) and _BOOT_ID.fullmatch(value) else None


# Audit record type numbers (linux/audit.h, libaudit) of the records the audit normalizers group, for journald
# copies that carry only the number (_AUDIT_TYPE) and not its name (_AUDIT_TYPE_NAME).
AUDIT_TYPE_NUMBERS = {
    "1100": "USER_AUTH", "1101": "USER_ACCT", "1102": "USER_MGMT", "1103": "CRED_ACQ", "1104": "CRED_DISP",
    "1105": "USER_START", "1106": "USER_END", "1108": "USER_CHAUTHTOK", "1110": "CRED_REFR", "1112": "USER_LOGIN",
    "1113": "USER_LOGOUT", "1114": "ADD_USER", "1115": "DEL_USER", "1116": "ADD_GROUP", "1117": "DEL_GROUP",
    "1127": "SYSTEM_BOOT", "1128": "SYSTEM_SHUTDOWN", "1129": "SYSTEM_RUNLEVEL", "1130": "SERVICE_START",
    "1131": "SERVICE_STOP", "1132": "GRP_MGMT", "1133": "GRP_CHAUTHTOK", "1135": "ACCT_LOCK", "1136": "ACCT_UNLOCK",
    "1300": "SYSCALL", "1302": "PATH", "1305": "CONFIG_CHANGE", "1306": "SOCKADDR", "1307": "CWD", "1309": "EXECVE",
    "1327": "PROCTITLE",
}


def _decimal(value) -> int | None:
    """A non-negative decimal integer written in ASCII digits, else None (str.isdigit also accepts '²')."""
    return int(value) if isinstance(value, str) and value.isascii() and value.isdigit() else None


def _audit_copy_key(hit: dict, j: dict) -> tuple[tuple[str, int, int], str, str] | None:
    """((host, audit time in ms, audit serial), audit record type, boot id) of a journald copy of an audit record,
    from journald's own fields: _AUDIT_ID is the record's serial and _SOURCE_REALTIME_TIMESTAMP its audit
    timestamp (whole milliseconds, in microseconds); the type is _AUDIT_TYPE_NAME, else the name of the number in
    _AUDIT_TYPE. None when any of them, or the shipper's host name, is missing or malformed."""
    serial, micros, boot = _decimal(j.get("_AUDIT_ID")), _decimal(j.get("_SOURCE_REALTIME_TIMESTAMP")), _journal_boot(j)
    kind = j.get("_AUDIT_TYPE_NAME")
    if not (isinstance(kind, str) and kind):
        kind = AUDIT_TYPE_NUMBERS.get(j.get("_AUDIT_TYPE")) if isinstance(j.get("_AUDIT_TYPE"), str) else None
    host = _get(hit["_source"], "host.name") or ""
    if serial is None or micros is None or micros % 1000 or not boot or not kind or not isinstance(host, str):
        return None
    return (host, micros // 1000, serial), kind, boot


def _boot_partners(copies: list[tuple[tuple[str, int, int], str, str, str]]
                   ) -> dict[tuple[str, int, int], dict[str, tuple[set[str], str]]]:
    """(host, audit ms, serial) -> {boot id: (audit record types, first journald copy id)} from journald copies
    given as (key, record type, boot id, copy id)."""
    partners: dict[tuple[str, int, int], dict[str, tuple[set[str], str]]] = defaultdict(dict)
    for key, kind, boot, copy_id in copies:
        types, first = partners[key].get(boot, (set(), copy_id))
        types.add(kind)
        partners[key][boot] = (types, min(first, copy_id))
    return partners


def _partner_boot(partners: dict, host: str, ts: float, serial: int,
                  members: list[tuple[dict, AuditRecord]]) -> dict:
    """The boot id of an audit event from journald's copy of one of its records, joined on (host, audit timestamp,
    serial) and a matching record type. No copy in the batch, or copies naming two boots, leaves it unknown."""
    types = {record.type for _hit, record in members}
    boots = [(boot, first) for boot, (kinds, first) in partners.get((host, round(ts * 1000), serial), {}).items()
             if kinds & types]
    if len(boots) != 1:
        return {}
    boot, first = boots[0]
    return {"host.boot.id": fv(boot, f"{first}:event.original#journal:_BOOT_ID")}


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
    argument field with different values, are ambiguous and raise (never silently pick one). When the record
    carrying argc was lost the continuations are still merged; execve_argv reports the command line incomplete."""
    if len(execs) == 1:
        return execs[0]
    heads = [(h, r) for h, r in execs if "argc" in r.raw_fields]
    if len(heads) > 1:
        raise AuditParseError(f"ambiguous exec event: {len(heads)} EXECVE records carry argc")
    h_head, r_head = heads[0] if heads else execs[0]
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


# Account and group management records that shadow-utils, PAM and the adduser family write through libaudit. The
# record type is the action the tool reports; `op` (when it is one clean token) is the tool's own detail.
AUDIT_ACCOUNT_TYPES = {"ADD_USER": "create_user", "DEL_USER": "delete_user", "ADD_GROUP": "create_group",
                       "DEL_GROUP": "delete_group", "USER_MGMT": "modify_user", "GRP_MGMT": "modify_group",
                       "USER_CHAUTHTOK": "password_change", "GRP_CHAUTHTOK": "group_password_change",
                       "ACCT_LOCK": "lock", "ACCT_UNLOCK": "unlock"}
# The service manager's unit records, and the system state records systemd-update-utmp writes.
AUDIT_SERVICE_TYPES = {"SERVICE_START": "start", "SERVICE_STOP": "stop"}
AUDIT_SYSTEM_TYPES = {"SYSTEM_BOOT": "boot", "SYSTEM_SHUTDOWN": "shutdown", "SYSTEM_RUNLEVEL": "runlevel"}
AUDIT_ADMIN_TYPES = set(AUDIT_ACCOUNT_TYPES) | set(AUDIT_SERVICE_TYPES) | set(AUDIT_SYSTEM_TYPES) | {"CONFIG_CHANGE"}
ADMIN_COMPANIONS = {"SYSCALL", "PROCTITLE"}
# Kernel audit settings a CONFIG_CHANGE `op=set` record (or an older record without op) names.
AUDIT_SETTINGS = ("audit_enabled", "audit_pid", "audit_failure", "audit_rate_limit", "audit_backlog_limit",
                  "audit_backlog_wait_time", "audit_lost")
_PLACEHOLDERS = {None, "", "?", "(null)", "(none)", "unset", "(unknown)"}


def _user_message_field(record: AuditRecord, key: str) -> str | None:
    """A field of the quoted user message (`msg='key=value ...'`). The tokenizer reads its first pair as `msg`
    with the opening quote and its last value with the closing quote; both are recovered here."""
    opener = record.fields.get("msg", "")
    value = opener[len(key) + 2:] if opener.startswith(f"'{key}=") else record.fields.get(key)
    value = value.strip("'") if isinstance(value, str) else value
    return None if value in _PLACEHOLDERS else value


def _record_outcome(record: AuditRecord) -> Outcome:
    result = (_user_message_field(record, "res") or "").strip("'\"").lower()
    return (Outcome.success if result in {"success", "yes", "1"}
            else Outcome.failure if result in {"failed", "failure", "no", "0"} else Outcome.unknown)


def _header_process_fields(origin: str, record: AuditRecord) -> dict:
    """Actor identity from a user-space record's own header and enrichment (absent stays absent)."""
    fields = {}
    pid = record.fields.get("pid")
    if pid and pid.isdigit():
        fields["process.pid"] = fv(int(pid), f"{origin}.pid")
    if "uid" in record.fields:
        fields["process.uid"] = fv(record.fields["uid"], f"{origin}.uid")
    auid = record.fields.get("auid")
    if auid not in {None, "", "-1", "4294967295"}:
        fields["process.auid"] = fv(auid, f"{origin}.auid")
    session_id = record.fields.get("ses")
    if session_id and session_id.isdigit() and session_id != "4294967295":
        fields["process.session_id"] = fv(int(session_id), f"{origin}.ses")
    for name, key in (("process.user", "UID"), ("process.login_user", "AUID")):
        if record.enriched.get(key) not in _PLACEHOLDERS:
            fields[name] = fv(record.enriched[key], f"{origin}:enriched.{key}")
    executable = _user_message_field(record, "exe")
    if executable:
        fields["process.executable"] = fv(executable, f"{origin}.exe")
    return fields


def service_name(unit: str) -> str:
    """A unit's service name for matching: lower case, without the unit type suffix or template instance."""
    name = unit.lower()
    for suffix in (".service", ".socket"):
        name = name.removesuffix(suffix)
    return name.split("@", 1)[0]


def normalize_audit_admin_group(host: str, members: list[tuple[dict, AuditRecord]]) -> list[TypedEvent]:
    """One typed event per account, service, system-state or audit-configuration record of a group. A SYSCALL
    record of the same group (the netlink send that carried a configuration change) adds the sender's identity."""
    companions = [(hit, record) for hit, record in members if record.type in ADMIN_COMPANIONS]
    syscall = next(((hit, record) for hit, record in companions if record.type == "SYSCALL"), None)
    out = []
    for hit, record in sorted(((h, r) for h, r in members if r.type in AUDIT_ADMIN_TYPES),
                              key=lambda item: item[0]["_id"]):
        origin = f"{hit['_id']}:event.original#auditd:{record.type}"
        refs = [_ref(hit)] + [_ref(item_hit) for item_hit, _record in companions]
        fields = {"audit.record_type": fv(record.type, f"{origin}.type"), **_audit_boot_field(members)}
        fields.update(_header_process_fields(origin, record))
        outcome = _record_outcome(record)
        if record.type in AUDIT_ACCOUNT_TYPES:
            family = "account_change"
            fields["account.action"] = fv(AUDIT_ACCOUNT_TYPES[record.type], f"{origin}.type")
            op = _user_message_field(record, "op")
            if op and " " not in op:
                fields["account.op"] = fv(op, f"{origin}.op")
            for name, key in (("account.name", "acct"), ("account.id", "id"), ("account.group", "grp")):
                value = _user_message_field(record, key)
                if value:
                    fields[name] = fv(value, f"{origin}.{key}")
            address = _user_message_field(record, "addr")
            if address:
                fields["source.ip"] = fv(address, f"{origin}.addr")
        elif record.type in AUDIT_SERVICE_TYPES:
            family = "service_change"
            unit = _user_message_field(record, "unit")
            if not unit:
                raise ValueError(f"{record.type} record without a unit")
            fields.update({"service.unit": fv(unit, f"{origin}.unit"),
                           "service.name": fv(service_name(unit), f"{origin}.unit"),
                           "service.job": fv(AUDIT_SERVICE_TYPES[record.type], f"{origin}.type"),
                           "service.job_phase": fv("done", f"{origin}.type"),
                           "service.scope": fv("system", f"{origin}.type"),
                           "service.source": fv("audit", f"{origin}.type")})
        elif record.type in AUDIT_SYSTEM_TYPES:
            family = "system_state"
            fields["system.event"] = fv(AUDIT_SYSTEM_TYPES[record.type], f"{origin}.type")
            for name, key in (("system.runlevel", "new-level"), ("system.previous_runlevel", "old-level")):
                value = _user_message_field(record, key)
                if value:
                    fields[name] = fv(value, f"{origin}.{key}")
        else:
            family = "audit_config"
            setting = next((key for key in AUDIT_SETTINGS if key in record.fields), None)
            op = (record.fields.get("op") or "").strip("'\"") or ("set" if setting else "")
            if not op:
                raise ValueError("CONFIG_CHANGE record names neither an operation nor a setting")
            fields["audit.config.op"] = fv(op, f"{origin}.op")
            if setting:
                fields["audit.config.setting"] = fv(setting, f"{origin}.{setting}")
                fields["audit.config.value"] = fv(record.fields[setting], f"{origin}.{setting}")
                if "old" in record.fields:
                    # numeric: the parser's hex decoding of `old` (meant for other record types) must not apply
                    fields["audit.config.old"] = fv(record.raw_fields["old"][0], f"{origin}.old")
            if record.fields.get("key") not in _PLACEHOLDERS:
                fields["audit.key"] = fv(record.fields["key"], f"{origin}.key")
            if record.fields.get("list", "").isdigit():
                fields["audit.config.list"] = fv(record.fields["list"], f"{origin}.list")
            if syscall is not None:
                fields.update(_syscall_process_fields(syscall[0]["_id"], syscall[1]))
        out.append(TypedEvent(id=event_id(family, refs), family=family, ts=datetime.fromtimestamp(record.ts, UTC),
                              host=host or None, outcome=outcome, fields=fields, raw=refs,
                              normalizer=NORMALIZER_VERSION))
    return out


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
    argv, argv_problem = execve_argv(r_exec)
    refs = [_ref(h) for h, r in members if r.type in EXEC_COMPANIONS]
    nid = h_exec["_id"]
    f = {
        "process.argv": fv(argv, f"{nid}:event.original#auditd:EXECVE.a*"),
        "process.args_count": fv(len(argv), f"{nid}:event.original#auditd:EXECVE.argc"),
        "audit.serial": fv(r_exec.serial, f"{nid}:event.original#auditd:msg.serial"),
        **_audit_boot_field(members),
    }
    caveats = []
    if argv_problem:
        # what arrived is kept as evidence; rules see the flag and say the command line is incomplete
        f["process.argv_complete"] = fv(False, f"{nid}:event.original#auditd:EXECVE.a*")
        caveats.append(f"{INCOMPLETE_ARGV_CAVEAT}: {argv_problem}")
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
    used, exec_caveats = _exec_file_fields(f, members, argv, by_type.get("CWD"))
    refs += [_ref(h) for h in used]
    caveats += exec_caveats
    return TypedEvent(id=event_id("process_exec", refs), family="process_exec", ts=_ts(h_exec["_source"]["@timestamp"]),
                      host=host or None, outcome=outcome, fields=f, raw=refs, normalizer=NORMALIZER_VERSION,
                      caveats=caveats)


# PATH records: one per name a system call looked up, numbered by `item` in lookup order. `nametype` says what
# the call did with it (NORMAL: used an existing file; CREATE/DELETE: added or removed a directory entry; PARENT:
# the directory holding a created or deleted entry; UNKNOWN: the lookup failed).
_NO_NAME = {"", "(null)", "(none)"}


def _path_items(members: list[tuple[dict, AuditRecord]]) -> dict[int, tuple[dict, AuditRecord]]:
    items: dict[int, tuple[dict, AuditRecord]] = {}
    for hit, record in members:
        if record.type != "PATH":
            continue
        number = record.fields.get("item", "")
        if not number.isdigit():
            raise AuditParseError("PATH record without an item number")
        if int(number) in items:
            raise AuditParseError(f"ambiguous event group, duplicate PATH item {number}")
        items[int(number)] = (hit, record)
    return items


def _lexical(path: str) -> str:
    normalized = posixpath.normpath(path)
    return "/" + normalized.lstrip("/")


def _resolve(name: str | None, dirfd: int | None, syscall: AuditRecord, cwd: tuple[dict, AuditRecord] | None,
             parents: list[tuple[dict, AuditRecord]]) -> tuple[str | None, list[dict], str, str]:
    """(absolute path, records used to place it, origin suffix, why it could not be placed) for a PATH name.

    A relative name is relative to the working directory unless the call passed a directory descriptor other than
    the working directory's; that descriptor's path is not recorded, so such a name is never guessed. Without a
    CWD record, a bare name is placed under its PARENT record when that is absolute (for a bare name the kernel
    writes the working directory there)."""
    if name is None or name in _NO_NAME:
        return None, [], "", "the kernel recorded no name for the file"
    if name.startswith("/"):
        return _lexical(name), [], "", ""
    if dirfd is not None and syscall.fields.get(f"a{dirfd}", "").lower() not in AT_FDCWD:
        return None, [], "", ("the relative name is resolved against a directory descriptor whose path is not "
                              "recorded")
    if cwd is not None and cwd[1].fields.get("cwd", "").startswith("/"):
        return _lexical(posixpath.join(cwd[1].fields["cwd"], name)), [cwd[0]], "+CWD.cwd", ""
    if "/" not in name:
        dirs = {(record.fields.get("name") or ""): hit for hit, record in parents
                if (record.fields.get("name") or "").startswith("/")}
        if len(dirs) == 1:
            directory, hit = next(iter(dirs.items()))
            return _lexical(posixpath.join(directory, name)), [hit], "+PATH(PARENT).name", ""
    return None, [], "", "the relative name has no recorded working directory"


def _owner_fields(prefix: str, hit: dict, record: AuditRecord) -> dict:
    """Inode identity, mode and ownership of a PATH item as the kernel recorded them at the call."""
    origin = f"{hit['_id']}:event.original#auditd:PATH"
    out = {}
    for name, key in (("inode", "inode"), ("device", "dev"), ("mode", "mode"), ("owner.id", "ouid"),
                      ("group.id", "ogid")):
        value = record.fields.get(key)
        if value not in (None, ""):
            out[f"{prefix}.{name}"] = fv(int(value) if key == "inode" and value.isdigit() else value,
                                         f"{origin}.{key}")
    for name, key in (("owner.name", "OUID"), ("group.name", "OGID")):
        if record.enriched.get(key):
            out[f"{prefix}.{name}"] = fv(record.enriched[key], f"{origin}:enriched.{key}")
    return out


def _exec_file_fields(f: dict, members: list[tuple[dict, AuditRecord]], argv: list[str],
                      cwd: tuple[dict, AuditRecord] | None) -> tuple[list[dict], list[str]]:
    """Add the executed file's inode, mode and ownership from the exec's PATH records.

    PATH item 0 is the file the exec call named: the program, or a `#!` script. For a script the kernel rewrites
    argv to `<interpreter> [arg] <script> ...` and looks the interpreter up as a later item, so item 0 is the
    script when its name is argv[1] or argv[2] and a later item's name is argv[0]; that later item is the
    interpreter. Returns the PATH records used and caveats."""
    try:
        items = _path_items(members)
    except AuditParseError as e:
        return [], [f"exec PATH records not used: {e}"]
    if 0 not in items:
        return [], ["PATH record of the executed file not retrieved: its owner and mode are unknown"]
    hit, record = items[0]
    used = [hit]
    name = record.fields.get("name")
    f.update(_owner_fields("process.exec_file", hit, record))
    path, extra, suffix, _why = _resolve(name, None, record, cwd, [])
    if path:
        f["process.exec_file.path"] = fv(path, f"{hit['_id']}:event.original#auditd:PATH.name{suffix}")
        used += extra
    interpreter = None
    if argv and name and name != argv[0] and name in argv[1:3]:
        interpreter = next(((h, r) for i, (h, r) in sorted(items.items())
                            if i > 0 and r.fields.get("name") == argv[0]), None)
    role_origin = f"{hit['_id']}:event.original#auditd:PATH.item+EXECVE.a0"
    f["process.exec_file.role"] = fv("script" if interpreter else "executable", role_origin)
    if interpreter is not None:
        ih, ir = interpreter
        used.append(ih)
        f.update(_owner_fields("process.interpreter_file", ih, ir))
        ipath, iextra, isuffix, _ = _resolve(ir.fields.get("name"), None, ir, cwd, [])
        if ipath:
            f["process.interpreter_file.path"] = fv(ipath, f"{ih['_id']}:event.original#auditd:PATH.name{isuffix}")
            used += iextra
    return list({h["_id"]: h for h in used}.values()), []


# What a call did to each named file, by kind: the PATH nametypes that name a changed file.
_CHANGE_NAMETYPES = {"truncate": ("NORMAL",), "attributes": ("NORMAL",), "delete": ("DELETE",),
                     "create": ("CREATE",), "link": ("CREATE",)}
_KIND_CHANGE = {"truncate": "content", "attributes": "attributes", "delete": "delete", "create": "create",
                "link": "link"}


def _open_intent(call: FileCall, rs: AuditRecord) -> tuple[int | None, str | None]:
    """(open flags, the register they were read from); flags None when the call does not record them."""
    if call.name == "creat":
        return O_CREAT | O_WRONLY | O_TRUNC, None
    if call.flags is None:
        return None, None
    return syscall_arg(rs, call.flags), f"a{call.flags}"


def _file_targets(call: FileCall, items: dict[int, tuple[dict, AuditRecord]], failed: bool,
                  flags: int | None) -> list[tuple[tuple[dict, AuditRecord], str | None, int]]:
    """(PATH item, change, name slot) for each file the call changed. The name slot is 0 for the call's only or
    old name and 1 for its new name (it picks the directory-descriptor argument). A change of None means the
    records do not say what changed."""
    children = [items[i] for i in sorted(items) if items[i][1].fields.get("nametype") != "PARENT"]

    def nametype(item):
        return item[1].fields.get("nametype")

    # a failed lookup is recorded as UNKNOWN: it names the file the call tried to change
    attempted = [c for c in children if failed and nametype(c) == "UNKNOWN"]
    if call.kind == "open":
        creates = [c for c in children if nametype(c) == "CREATE"]
        if creates:
            return [(c, "create", 0) for c in creates]
        if flags is None:
            return [(c, None, 0) for c in children]
        if (flags & O_ACCMODE) in (O_WRONLY, O_RDWR) or flags & O_TRUNC:
            return ([(c, "content", 0) for c in children if nametype(c) == "NORMAL"]
                    + [(c, "create" if flags & O_CREAT else "content", 0) for c in attempted])
        return []
    if call.kind == "rename":
        creates = [c for c in children if nametype(c) == "CREATE"]
        deletes = [c for c in children if nametype(c) == "DELETE"]
        if creates:
            new_names = {c[1].fields.get("name") for c in creates}
            # a DELETE item under the new name is the file the rename replaced; its path is the target's
            return ([(c, "rename_target", 1) for c in creates]
                    + [(d, "rename_source", 0) for d in deletes if d[1].fields.get("name") not in new_names])
        if len(children) == 2:
            # rename looks the old name up before the new one, so the items are in that order
            return [(children[0], "rename_source", 0), (children[1], "rename_target", 1)]
        return [(c, None, 0) for c in children]
    wanted = _CHANGE_NAMETYPES[call.kind]
    slot = 1 if call.kind == "link" else 0
    return ([(c, _KIND_CHANGE[call.kind], slot) for c in children if nametype(c) in wanted]
            + [(c, _KIND_CHANGE[call.kind], slot) for c in attempted])


def normalize_file_group(host: str, members: list[tuple[dict, AuditRecord]], call: FileCall) -> list[TypedEvent]:
    """file_change events from a SYSCALL record of a file-changing call and its PATH records: one per changed file.

    An open is a change only with write intent (write access, O_TRUNC) or when it created the file; a read-only
    open raises Skip. What cannot be decided stays absent, never defaulted: a file whose name cannot be placed has
    no `file.path`, and a call whose records do not say what changed has no `file.change`; rules count both as
    missing fields. A failed call is kept with outcome failure: it is an attempt."""
    by_type = {r.type: (h, r) for h, r in members if r.type in ("SYSCALL", "CWD", "PROCTITLE")}
    hs, rs = by_type["SYSCALL"]
    sid = hs["_id"]
    origin = f"{sid}:event.original#auditd:SYSCALL"
    items = _path_items(members)
    succ = rs.fields.get("success")
    outcome = Outcome.success if succ == "yes" else Outcome.failure if succ == "no" else Outcome.unknown
    base = {"file.syscall": fv(call.name, f"{origin}.arch+syscall"),
            "audit.serial": fv(rs.serial, f"{sid}:event.original#auditd:msg.serial"),
            **_audit_boot_field(members), **_syscall_process_fields(sid, rs)}
    if rs.fields.get("key") not in (None, "(null)"):
        base["audit.key"] = fv(rs.fields["key"], f"{origin}.key")
    if rs.fields.get("exit"):
        base["file.exit"] = fv(rs.fields["exit"], f"{origin}.exit")
    caveats = []
    expected = rs.fields.get("items", "")
    if expected.isdigit() and int(expected) != len(items):
        caveats.append(f"{len(items)} of the {expected} PATH records of this call were retrieved")
    flags = None
    if call.kind == "open":
        flags, register = _open_intent(call, rs)
        if flags is not None and register:
            base["file.open_flags"] = fv(rs.fields[register], f"{origin}.{register}")
        if flags is not None and flags & O_TMPFILE_BIT:
            raise Skip("audit open of an unnamed temporary file (O_TMPFILE)")
        if flags is None:
            caveats.append(f"{call.name} does not record its open flags: whether the file was opened for writing "
                           "is unknown")
    if call.mode is not None and (mode := syscall_arg(rs, call.mode)) is not None:
        base["file.new_mode"] = fv(f"{mode & 0o7777:04o}", f"{origin}.a{call.mode}")
    if call.owner is not None:
        for name, index in (("file.new_owner.id", call.owner[0]), ("file.new_group.id", call.owner[1])):
            value = syscall_arg(rs, index)
            if value is not None and value not in (0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF):    # -1 leaves it unchanged
                base[name] = fv(str(value), f"{origin}.a{index}")
    targets = [] if call.by_fd else _file_targets(call, items, outcome == Outcome.failure, flags)
    write = flags is not None and ((flags & O_ACCMODE) in (O_WRONLY, O_RDWR) or bool(flags & O_TRUNC))
    if call.kind == "open" and flags is not None and not write and not targets:
        raise Skip("audit open without write intent")
    extra = [_ref(by_type["PROCTITLE"][0])] if "PROCTITLE" in by_type else []
    if not targets:
        why = ("the call acts on an open file descriptor, so the kernel records no path for the file" if call.by_fd
               else "no PATH record names the changed file")
        fields = dict(base)
        change = ("content" if write else None) if call.kind == "open" else _KIND_CHANGE.get(call.kind)
        if change:
            fields["file.change"] = fv(change, f"{origin}.syscall")
        refs = [_ref(hs), *extra]
        return [TypedEvent(id=event_id("file_change", refs), family="file_change",
                           ts=datetime.fromtimestamp(rs.ts, UTC), host=host or None, outcome=outcome, fields=fields,
                           raw=refs, normalizer=NORMALIZER_VERSION, caveats=[*caveats, f"file path unknown: {why}"])]
    cwd = by_type.get("CWD")
    # a PARENT record places a bare name only when every PATH record of the call is present: with one missing,
    # the PARENT seen may belong to another of the call's names
    complete = not (expected.isdigit() and int(expected) != len(items))
    parents = [items[i] for i in sorted(items) if items[i][1].fields.get("nametype") == "PARENT"] if complete else []
    events = []
    for (ph, pr), change, slot in targets:
        fields = dict(base)
        event_caveats = list(caveats)
        porigin = f"{ph['_id']}:event.original#auditd:PATH"
        path, used, suffix, why = _resolve(pr.fields.get("name"), call.dirfd[slot], rs, cwd, parents)
        if path:
            fields["file.path"] = fv(path, f"{porigin}.name{suffix}")
        else:
            event_caveats.append(f"file path unknown: {why}")
        if change:
            fields["file.change"] = fv(change, f"{origin}.syscall+{porigin}.nametype")
        if pr.fields.get("nametype"):
            fields["file.nametype"] = fv(pr.fields["nametype"], f"{porigin}.nametype")
        fields.update(_owner_fields("file", ph, pr))
        refs = list({r.key: r for r in [_ref(hs), _ref(ph), *[_ref(h) for h in used], *extra]}.values())
        events.append(TypedEvent(id=event_id("file_change", refs), family="file_change",
                                 ts=datetime.fromtimestamp(rs.ts, UTC), host=host or None, outcome=outcome,
                                 fields=fields, raw=refs, normalizer=NORMALIZER_VERSION, caveats=event_caveats))
    return events


# ---------------------------------------------------------------------------------------------
# systemd.journal: sshd / sudo messages; audit copies are duplicates of linux.audit
# ---------------------------------------------------------------------------------------------

_SSH_OK = re.compile(r"^Accepted (?P<method>password|publickey|keyboard-interactive/pam|gssapi-with-mic) for "
                     r"(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)")
# sshd prints an attempted account name verbatim, so the name is matched greedily and the source is the last
# "from <ip> port <n>" before the fixed suffix: a name such as "x from 192.0.2.1 port 1" cannot move the source.
_SSH_FAIL = re.compile(r"^Failed (?P<method>[\w/-]+) for (?P<invalid>invalid user )?(?P<user>.*) from "
                       r"(?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)(?: ssh2)?(?:: .*)?$")
_SSH_INVALID = re.compile(r"^Invalid user (?P<user>.*) from (?P<ip>[0-9a-fA-F:.]+)(?: port (?P<port>\d+))?$")
_SSH_PREAUTH = re.compile(r"^(?:Connection closed by|Disconnected from) (?P<kind>authenticating|invalid) user "
                          r"(?P<user>.*) (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+) \[preauth\]$")
_SSH_MAXTRIES = re.compile(r"^(?:error: )?maximum authentication attempts exceeded for (?P<invalid>invalid user )?"
                           r"(?P<user>.*) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)(?: ssh2)? \[preauth\]$")
# (pattern, outcome, phase). An attempt's phase: an authentication decision ("Accepted"/"Failed"), a lookup of an
# account name that does not exist, a connection closed before authentication completed, or sshd ending a
# connection that used up its authentication attempts.
_SSH_FORMS = ((_SSH_OK, Outcome.success, "authentication"), (_SSH_FAIL, Outcome.failure, "authentication"),
              (_SSH_INVALID, Outcome.failure, "user_lookup"), (_SSH_PREAUTH, Outcome.failure, "preauth_disconnect"),
              (_SSH_MAXTRIES, Outcome.failure, "max_attempts"))
# systemd catalog message ids of unit job messages: (job type, phase).
_UNIT_JOB_IDS = {"9d1aaa27d60140bd96365438aad20286": ("stop", "done"),
                 "de5b426a63be47a7b6ac3eaac82e2f6f": ("stop", "begun"),
                 "39f53479d3a045ac8e11786248231fbf": ("start", "done"),
                 "7d4958e842da4a758f6c1cdc7b36dcc5": ("start", "begun")}
# Newer systemd names the unit in the message ("Stopped auditd.service - Security Auditing Service.").
_UNIT_JOB_TEXT = re.compile(r"^(?P<verb>Stopped|Stopping|Started|Starting|Reached target|Stopped target) "
                            r"(?P<unit>[\w@:.\\-]+\.(?:service|socket|target|timer|path|mount|scope|slice))"
                            r"(?: - .*|\.\.\.|\.)?$")
_UNIT_EXIT = re.compile(r"^(?P<unit>[\w@:.\\-]+): (?:Main process exited, code=(?P<code>killed|dumped), "
                        r"status=\S+|Failed with result '(?P<result>signal|core-dump)')\.?$")
# Process names sshd runs as (OpenSSH 9.8 splits per-session work into sshd-session and sshd-auth).
_SSHD_COMMS = ("sshd",)
_UNIT_JOB_VERBS = {"Stopped": ("stop", "done"), "Stopping": ("stop", "begun"), "Started": ("start", "done"),
                   "Starting": ("start", "begun"), "Reached target": ("start", "done"),
                   "Stopped target": ("stop", "done")}
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
        raise AuditCopy(j)
    ident = j.get("SYSLOG_IDENTIFIER") or j.get("_COMM")
    msg = j.get("MESSAGE") or src.get("message") or ""
    nid = hit["_id"]
    ref = _ref(hit)
    host = j.get("_HOSTNAME") or _get(src, "host.name")
    base = {"journal.identifier": fv(ident, f"{nid}:event.original#journal:SYSLOG_IDENTIFIER"),
            "journal.unit": fv(j.get("_SYSTEMD_UNIT"), f"{nid}:event.original#journal:_SYSTEMD_UNIT")}
    if _journal_boot(j):
        base["host.boot.id"] = fv(_journal_boot(j), f"{nid}:event.original#journal:_BOOT_ID")
    if ident == "sshd":
        # SYSLOG_IDENTIFIER is chosen by the writer; journald's own _COMM/_EXE/_SYSTEMD_UNIT are not. When any of
        # them is recorded, one must name sshd, or the line came from another program.
        trusted = [str(v) for v in (j.get("_COMM"), basename_of(j.get("_EXE")), j.get("_SYSTEMD_UNIT")) if v]
        if trusted and not any(v.startswith(_SSHD_COMMS) or v.startswith(("ssh.service", "ssh@", "sshd@"))
                               for v in trusted):
            raise Skip("sshd-identified journal line written by another program")
        for rx, outcome, phase in _SSH_FORMS:
            m = rx.match(msg)
            if m:
                g = m.groupdict()
                origin = f"{nid}:event.original#journal:MESSAGE~sshd"
                f = {**base,
                     "auth.service": fv("sshd", f"{nid}:event.original#journal:SYSLOG_IDENTIFIER"),
                     "auth.method": fv(g.get("method"), origin),
                     "auth.phase": fv(phase, origin),
                     "auth.user_valid": fv(not (g.get("invalid") or g.get("kind") == "invalid"
                                                or rx is _SSH_INVALID), origin),
                     "source.ip": fv(g["ip"], origin)}
                if g["user"]:
                    f["user.name"] = fv(g["user"], origin)
                if g.get("port"):
                    f["source.port"] = fv(int(g["port"]), origin)
                return TypedEvent(id=event_id("auth", [ref]), family="auth", ts=_ts(src["@timestamp"]), host=host,
                                  outcome=outcome, fields=f, raw=[ref], normalizer=NORMALIZER_VERSION)
        raise Skip("sshd message without an authentication outcome")
    if ident == "systemd":
        return _unit_job(hit, j, msg, base, host)
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


def basename_of(path) -> str:
    return str(path).rsplit("/", 1)[-1] if path else ""


def _unit_job(hit: dict, j: dict, msg: str, base: dict, host: str | None) -> TypedEvent:
    """A service manager's unit job message: which unit, which job (stop/start/...) and its phase (begun, done or
    another job result). The unit comes from the structured UNIT/USER_UNIT field, or from newer systemd's message
    that names it; the job from JOB_TYPE/JOB_RESULT, the catalog MESSAGE_ID, or that message's verb. A message
    that names no unit or no job (a description-only "Stopped ...", a resource summary) is not typed."""
    nid = hit["_id"]
    o = f"{nid}:event.original#journal"
    unit, scope, unit_origin = j.get("UNIT"), "system", f"{o}:UNIT"
    if not unit and j.get("USER_UNIT"):
        unit, scope, unit_origin = j["USER_UNIT"], "user", f"{o}:USER_UNIT"
    text = _UNIT_JOB_TEXT.match(msg)
    if not unit and text:
        unit, unit_origin = text.group("unit"), f"{o}:MESSAGE~systemd"
    job = phase = None
    if j.get("JOB_TYPE"):
        job, phase, job_origin = j["JOB_TYPE"], j.get("JOB_RESULT") or "begun", f"{o}:JOB_TYPE+JOB_RESULT"
    elif j.get("MESSAGE_ID") in _UNIT_JOB_IDS:
        (job, phase), job_origin = _UNIT_JOB_IDS[j["MESSAGE_ID"]], f"{o}:MESSAGE_ID"
    elif text and unit == text.group("unit"):
        (job, phase), job_origin = _UNIT_JOB_VERBS[text.group("verb")], f"{o}:MESSAGE~systemd"
    else:
        # The service manager's record of a unit's main process ending by signal or core dump (no job involved).
        exited = _UNIT_EXIT.match(msg)
        if unit and exited and exited.group("unit") == unit:
            job, phase = "exit", exited.group("code") or exited.group("result")
            job_origin = f"{o}:MESSAGE~systemd"
    if not unit or not job:
        raise Skip("systemd message is not a unit job record")
    fields = {**base,
              "service.unit": fv(unit, unit_origin), "service.name": fv(service_name(unit), unit_origin),
              "service.job": fv(job, job_origin), "service.job_phase": fv(phase, job_origin),
              "service.scope": fv(scope, unit_origin), "service.source": fv("journal", f"{o}:SYSLOG_IDENTIFIER")}
    pid = j.get("_PID")
    if isinstance(pid, str) and pid.isdigit():
        fields["process.pid"] = fv(int(pid), f"{o}:_PID")
    outcome = (Outcome.success if phase == "done" else Outcome.unknown if phase in {"begun", "skipped"}
               else Outcome.failure)
    ref = _ref(hit)
    return TypedEvent(id=event_id("service_change", [ref]), family="service_change", ts=_ts(hit["_source"]["@timestamp"]),
                      host=host, outcome=outcome, fields=fields, raw=[ref], normalizer=NORMALIZER_VERSION)


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
    """EVE DNS in its three layouts. Query records (every version) and v2 answer records carry the question in
    the top-level rrname/rrtype; v3 records carry it in `queries`. A v1 answer record (no `version`) is one
    resource record of the response: its rrname/rrtype/ttl/rdata describe that answer (a CNAME target, say), so
    they are typed as an answer and never as the question."""
    f = {"dns.type": fv(d.get("type"), f"{o}.dns.type")}
    names, types = set(), set()
    if d.get("type") == "answer" and d.get("version") is None:
        answer = _dns_record(d, "dns", bad)
        if any(v is not None for v in answer.values()):
            f["dns.answers"] = fv([answer], f"{o}.dns.rrname+rrtype+ttl+rdata")
        rrname = rrtype = None
    else:
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
        if items and typed not in f:
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
    """Normalize a batch. Returns (events, skip_counts, errors[(raw_id, error)]).

    An audit event's boot id (`host.boot.id`) comes from the shipper's own field, else from journald's copy of one
    of its records when that copy is in the same batch. Without either it stays unknown: never guessed."""
    events, skips, errors = [], defaultdict(int), []
    audit_hits = []
    audit_copies: list[tuple[tuple[str, int, int], str, str, str]] = []
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
        except AuditCopy as copy:
            skips[copy.reason] += 1
            found = _audit_copy_key(h, copy.record)
            if found is not None:
                audit_copies.append((*found, h["_id"]))
        except Skip as s:
            skips[s.reason] += 1
        except (ValueError, KeyError, TypeError, AttributeError) as e:   # malformed telemetry: an error, never a crash
            errors.append((h["_id"], f"{ds}: {e}"))
    groups, audit_errors = group_audit(audit_hits)
    errors.extend(audit_errors)
    partners = _boot_partners(audit_copies)
    audit_start, boot_by_hit = len(events), {}
    for (host, ts, serial), members in groups.items():
        boot = _partner_boot(partners, host, ts, serial, members) if partners else {}
        if boot:
            boot_by_hit.update({hit["_id"]: boot for hit, _record in members})
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
        if types & AUDIT_ADMIN_TYPES:
            try:
                events.extend(normalize_audit_admin_group(host, members))
            except (ValueError, KeyError, TypeError) as e:
                errors.append((members[0][0]["_id"], f"linux.audit.admin: {e}"))
            continue
        if "EXECVE" not in types:
            sys_rec = next((r for _, r in members if r.type == "SYSCALL"), None)
            syscall = socket_syscall(sys_rec) if sys_rec is not None else None
            file_call = file_syscall(sys_rec) if sys_rec is not None and syscall is None else None
            if file_call is not None:
                try:
                    events.extend(normalize_file_group(host, members, file_call))
                except Skip as s:
                    skips[s.reason] += 1
                except (AuditParseError, ValueError, KeyError) as e:
                    # tagged by family so the sweep marks only file-change rules partial
                    errors.append((members[0][0]["_id"], f"linux.audit.file: {e}"))
                continue
            if syscall is None:
                arch = sys_rec.fields.get("arch", "") if sys_rec is not None else ""
                skips["audit group without EXECVE, socket or file-change syscall"
                      if not arch or arch in SOCKET_SYSCALLS
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
            event = normalize_exec_group(host, members)
            events.append(event)
            # the event is kept, but its command line is incomplete: the partition cannot assure a negative
            errors += [(members[0][0]["_id"], f"linux.audit: {c}") for c in event.caveats
                       if c.startswith(INCOMPLETE_ARGV_CAVEAT)]
        except Skip as s:
            skips[s.reason] += 1
        except (AuditParseError, ValueError, KeyError) as e:
            errors.append((members[0][0]["_id"], f"linux.audit: {e}"))
    # Every audit event cites records of its own group only, so its first record names the group.
    for event in events[audit_start:]:
        boot = boot_by_hit.get(event.raw[0].native_id) if event.raw else None
        if boot and not event.has("host.boot.id"):
            event.fields.update(boot)
    return events, dict(skips), errors
