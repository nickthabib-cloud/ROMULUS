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
                    fields["audit.config.old"] = fv(record.fields["old"], f"{origin}.old")
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
        raise Skip("journal copy of an audit record (normalized from linux.audit)")
    ident = j.get("SYSLOG_IDENTIFIER") or j.get("_COMM")
    msg = j.get("MESSAGE") or src.get("message") or ""
    nid = hit["_id"]
    ref = _ref(hit)
    host = j.get("_HOSTNAME") or _get(src, "host.name")
    base = {"journal.identifier": fv(ident, f"{nid}:event.original#journal:SYSLOG_IDENTIFIER"),
            "journal.unit": fv(j.get("_SYSTEMD_UNIT"), f"{nid}:event.original#journal:_SYSTEMD_UNIT")}
    if ident == "sshd":
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
    if "dns" in eve:
        d = eve["dns"]
        f["dns.type"] = fv(d.get("type"), f"{o}.dns.type")
        f["dns.question.name"] = fv(d.get("rrname"), f"{o}.dns.rrname")
        f["dns.question.type"] = fv(d.get("rrtype"), f"{o}.dns.rrtype")
        f["dns.response_code"] = fv(d.get("rcode"), f"{o}.dns.rcode")
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
                      normalizer=NORMALIZER_VERSION)


# ---------------------------------------------------------------------------------------------
# Arkime SPI session records (read from the session indices)
# ---------------------------------------------------------------------------------------------

IP_PROTOCOLS = {1: "icmp", 6: "tcp", 17: "udp", 58: "ipv6-icmp", 132: "sctp"}
ARKIME_FIELDS = (
    # typed name, native path
    ("source.ip", "source.ip"), ("source.port", "source.port"), ("destination.ip", "destination.ip"),
    ("destination.port", "destination.port"), ("network.community_id", "network.community_id"),
    ("source.bytes", "source.bytes"), ("source.packets", "source.packets"),
    ("destination.bytes", "destination.bytes"), ("destination.packets", "destination.packets"),
    ("client.bytes", "client.bytes"), ("server.bytes", "server.bytes"),
    ("tls.ja3", "tls.ja3"), ("tls.ja3s", "tls.ja3s"), ("tls.ja4", "tls.ja4"), ("tls.version", "tls.version"),
    ("ssh.hassh", "ssh.hassh"), ("ssh.hassh_server", "ssh.hasshServer"), ("ssh.version", "ssh.version"),
    ("http.hostname", "http.host"), ("url.path", "http.uri"), ("user_agent.original", "http.useragent"),
    ("http.request.method", "http.method"), ("http.response.status_code", "http.statuscode"),
    ("dns.question.name", "dns.host"), ("tls.server.subject_cn", "cert.subjectCN"),
    ("tls.server.issuer_cn", "cert.issuerCN"), ("tls.server.not_after", "cert.notAfter"),
    ("network.protocols", "protocol"), ("arkime.tags", "tags"),
)


def is_arkime_session(src: dict) -> bool:
    return "firstPacket" in src and "lastPacket" in src and isinstance(src.get("source"), dict)


def _epoch_ms(value) -> datetime:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise TypeError(f"Arkime packet time is not epoch milliseconds: {value!r}")
    return datetime.fromtimestamp(value / 1000, UTC)


def normalize_arkime_session(hit: dict) -> TypedEvent:
    """One net_session per Arkime SPI record. Arkime saves long sessions in several records (one per
    save interval) sharing the 5-tuple and community ID; each record is one event, and rules that need
    the whole connection stitch them by community ID."""
    src, nid, ref = hit["_source"], hit["_id"], _ref(hit)
    first, last = _epoch_ms(src.get("firstPacket")), _epoch_ms(src.get("lastPacket"))
    f = {}
    for typed, native in ARKIME_FIELDS:
        v = _get(src, native)
        if v not in (None, [], ""):
            f[typed] = fv(v, f"{nid}:{native}")
    proto = src.get("ipProtocol")
    if proto is not None:
        f["network.transport"] = fv(IP_PROTOCOLS.get(proto, str(proto)), f"{nid}:ipProtocol")
    f["flow.start"] = fv(first.isoformat(), f"{nid}:firstPacket")
    f["flow.end"] = fv(last.isoformat(), f"{nid}:lastPacket")
    f["session.duration_s"] = fv(round((last - first).total_seconds(), 3), f"{nid}:lastPacket-firstPacket")
    f["arkime.node"] = fv(src.get("node"), f"{nid}:node")
    return TypedEvent(id=event_id("net_session", [ref]), family="net_session", ts=first, host=src.get("node"),
                      fields={k: v for k, v in f.items() if v.value is not None}, raw=[ref],
                      normalizer=NORMALIZER_VERSION)


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
        if types & AUDIT_ADMIN_TYPES:
            try:
                events.extend(normalize_audit_admin_group(host, members))
            except (ValueError, KeyError, TypeError) as e:
                errors.append((members[0][0]["_id"], f"linux.audit.admin: {e}"))
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
