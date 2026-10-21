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
    parents = [items[i] for i in sorted(items) if items[i][1].fields.get("nametype") == "PARENT"]
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
            events.append(normalize_exec_group(host, members))
        except Skip as s:
            skips[s.reason] += 1
        except (AuditParseError, ValueError, KeyError) as e:
            errors.append((members[0][0]["_id"], f"linux.audit: {e}"))
    return events, dict(skips), errors
