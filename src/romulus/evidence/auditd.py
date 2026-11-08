"""Parse Linux audit records (raw `type=... msg=audit(ts:serial): k=v ...` lines) exactly."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import NamedTuple

_HEADER = re.compile(r"^(?:node=(?P<node>\S+)\s+)?type=(?P<type>[A-Z_]+)\s+msg=audit\((?P<ts>[0-9.]+):(?P<serial>\d+)\):\s?"
                     r"(?P<body>.*)$", re.DOTALL)
_HEX = re.compile(r"^[0-9A-Fa-f]+$")
_ARG = re.compile(r"^a(\d+)(?:\[(\d+)\])?$")
_ARG_LEN = re.compile(r"^a(\d+)_len$")
# auditd hex-encodes only "untrusted string" fields; numeric fields (argc, pid, a0 of SYSCALL...) never.
_ENCODABLE = {"proctitle", "name", "cwd", "comm", "exe", "path", "cmd", "data", "acct", "old", "new", "key",
              "watch", "hostname", "addr", "terminal", "exe_path"}


class AuditParseError(ValueError):
    pass


def _tokenize(body: str) -> list[tuple[str, str, bool]]:
    """Split `k=v k2="quoted v" k3=HEX` into (key, value, was_quoted). Quotes never span pairs.

    A space-separated word without `=` is not a field of its own: the kernel writes some unquoted values with a
    space in them (an AppArmor subject is `subj=<label> (enforce)`). Such a word continues the preceding unquoted
    value; after a quoted value, or with nothing before it, it is skipped so it cannot swallow the next key."""
    out: list[tuple[str, str, bool]] = []
    i, n = 0, len(body)
    while i < n:
        while i < n and body[i] == " ":
            i += 1
        if i >= n:
            break
        word_end = body.find(" ", i)
        word_end = n if word_end < 0 else word_end
        eq = body.find("=", i, word_end)
        if eq < 0:
            if out and not out[-1][2]:
                key, value, _quoted = out[-1]
                out[-1] = (key, f"{value} {body[i:word_end]}", False)
            i = word_end
            continue
        key = body[i:eq]
        j = eq + 1
        if j < n and body[j] == '"':
            end = body.find('"', j + 1)
            if end < 0:
                raise AuditParseError(f"unterminated quote for {key}")
            out.append((key, body[j + 1:end], True))
            i = end + 1
        else:
            end = body.find(" ", j)
            end = n if end < 0 else end
            out.append((key, body[j:end], False))
            i = end
    return out


def decode_value(value: str, quoted: bool) -> str:
    """auditd hex-encodes values containing spaces/quotes/control chars; quoted values are literal."""
    if quoted or value in ("(null)", "(none)"):
        return value
    if _HEX.match(value) and len(value) % 2 == 0:
        try:
            return bytes.fromhex(value).decode("utf-8", errors="replace")
        except ValueError:
            return value
    return value


@dataclass
class AuditRecord:
    type: str
    ts: float
    serial: int
    fields: dict[str, str]
    raw_fields: dict[str, tuple[str, bool]] = field(default_factory=dict)
    enriched: dict[str, str] = field(default_factory=dict)   # after \x1d: UID="root" etc.
    node: str | None = None                                  # the header's node= name, when the line has one
    # For a record rebuilt from fields a shipper parsed (no raw line): the indexed path each key was read from.
    origins: dict[str, str] | None = None
    # Why the command line of a rebuilt EXECVE record is incomplete, beyond what its argument keys show.
    argv_problem: str | None = None
    # Keys whose value was decoded from hex although the shipper does not record whether it was hex-encoded.
    hex_guessed: tuple[str, ...] = ()

    @property
    def reconstructed(self) -> bool:
        return self.origins is not None


def parse_record(line: str) -> AuditRecord:
    main, _, enrich = line.partition("\x1d")
    m = _HEADER.match(main.strip())
    if not m:
        raise AuditParseError("not an audit record header")
    toks = _tokenize(m.group("body"))
    raw = {k: (v, q) for k, v, q in toks}
    rtype = m.group("type")
    fields = {}
    for k, v, q in toks:
        encodable = k in _ENCODABLE or (rtype == "EXECVE" and _ARG.match(k) is not None)
        fields[k] = decode_value(v, q) if encodable else v
    enriched = {k: v for k, v, _ in _tokenize(enrich.strip())} if enrich else {}
    return AuditRecord(type=m.group("type"), ts=float(m.group("ts")), serial=int(m.group("serial")),
                       fields=fields, raw_fields=raw, enriched=enriched, node=m.group("node"))


def is_audit_line(text) -> bool:
    """Whether `text` is a raw audit record line (its header parses)."""
    return isinstance(text, str) and _HEADER.match(text.partition("\x1d")[0].strip()) is not None


AF_NAMES = {0: "unspec", 1: "local", 2: "inet", 10: "inet6", 16: "netlink", 17: "packet"}

# Socket syscalls by audit arch. Other arches (e.g. i386 socketcall multiplexing) are not decoded.
SOCKET_SYSCALLS = {
    "c000003e": {42: "connect", 43: "accept", 288: "accept4", 49: "bind"},       # x86_64
    "c00000b7": {203: "connect", 202: "accept", 242: "accept4", 200: "bind"},    # aarch64
}


@dataclass
class SockAddr:
    family: str
    ip: str | None = None
    port: int | None = None


def socket_syscall(rec: AuditRecord) -> str | None:
    """The socket syscall a SYSCALL record made, decoded by (arch, number); None if it is not one."""
    table = SOCKET_SYSCALLS.get(rec.fields.get("arch", ""))
    number = rec.fields.get("syscall", "")
    return table.get(int(number)) if table and number.isdigit() else None


@dataclass(frozen=True)
class FileCall:
    """A system call that changes a file or its attributes, and where its arguments are.

    `kind` is what the call does to the named file: open (a change only with write intent), truncate, rename,
    link, delete, create or attributes. `dirfd` gives the argument index of the directory descriptor that a
    relative name is resolved against, for the call's only (or old) name and for its new name; None when the
    call resolves relative names against the working directory. `flags` is the argument index of open flags,
    `mode` of a new permission mode and `owner` of a new owner and group. A `by_fd` call acts on an open
    descriptor, so the kernel records no path for the changed file."""
    name: str
    kind: str
    dirfd: tuple[int | None, int | None] = (None, None)
    flags: int | None = None
    mode: int | None = None
    owner: tuple[int, int] | None = None
    by_fd: bool = False


_AT = (0, 0)
FILE_SYSCALLS: dict[str, dict[int, FileCall]] = {
    "c000003e": {                                                                # x86_64
        2: FileCall("open", "open", flags=1),
        85: FileCall("creat", "open"),
        257: FileCall("openat", "open", dirfd=_AT, flags=2),
        437: FileCall("openat2", "open", dirfd=_AT),                         # flags are inside a struct
        304: FileCall("open_by_handle_at", "open", flags=2, by_fd=True),
        76: FileCall("truncate", "truncate"),
        77: FileCall("ftruncate", "truncate", by_fd=True),
        82: FileCall("rename", "rename"),
        264: FileCall("renameat", "rename", dirfd=(0, 2)),
        316: FileCall("renameat2", "rename", dirfd=(0, 2)),
        86: FileCall("link", "link"),
        265: FileCall("linkat", "link", dirfd=(0, 2)),
        88: FileCall("symlink", "link"),
        266: FileCall("symlinkat", "link", dirfd=(None, 1)),
        87: FileCall("unlink", "delete"),
        263: FileCall("unlinkat", "delete", dirfd=_AT),
        84: FileCall("rmdir", "delete"),
        83: FileCall("mkdir", "create"),
        258: FileCall("mkdirat", "create", dirfd=_AT),
        133: FileCall("mknod", "create"),
        259: FileCall("mknodat", "create", dirfd=_AT),
        90: FileCall("chmod", "attributes", mode=1),
        91: FileCall("fchmod", "attributes", mode=1, by_fd=True),
        268: FileCall("fchmodat", "attributes", dirfd=_AT, mode=2),
        452: FileCall("fchmodat2", "attributes", dirfd=_AT, mode=2),
        92: FileCall("chown", "attributes", owner=(1, 2)),
        93: FileCall("fchown", "attributes", owner=(1, 2), by_fd=True),
        94: FileCall("lchown", "attributes", owner=(1, 2)),
        260: FileCall("fchownat", "attributes", dirfd=_AT, owner=(2, 3)),
        188: FileCall("setxattr", "attributes"),
        189: FileCall("lsetxattr", "attributes"),
        190: FileCall("fsetxattr", "attributes", by_fd=True),
        197: FileCall("removexattr", "attributes"),
        198: FileCall("lremovexattr", "attributes"),
        199: FileCall("fremovexattr", "attributes", by_fd=True),
        132: FileCall("utime", "attributes"),
        235: FileCall("utimes", "attributes"),
        280: FileCall("utimensat", "attributes", dirfd=_AT),
        261: FileCall("futimesat", "attributes", dirfd=_AT),
    },
    "c00000b7": {                                                                # aarch64 (generic table)
        56: FileCall("openat", "open", dirfd=_AT, flags=2),
        437: FileCall("openat2", "open", dirfd=_AT),
        265: FileCall("open_by_handle_at", "open", flags=2, by_fd=True),
        45: FileCall("truncate", "truncate"),
        46: FileCall("ftruncate", "truncate", by_fd=True),
        38: FileCall("renameat", "rename", dirfd=(0, 2)),
        276: FileCall("renameat2", "rename", dirfd=(0, 2)),
        37: FileCall("linkat", "link", dirfd=(0, 2)),
        36: FileCall("symlinkat", "link", dirfd=(None, 1)),
        35: FileCall("unlinkat", "delete", dirfd=_AT),
        34: FileCall("mkdirat", "create", dirfd=_AT),
        33: FileCall("mknodat", "create", dirfd=_AT),
        52: FileCall("fchmod", "attributes", mode=1, by_fd=True),
        53: FileCall("fchmodat", "attributes", dirfd=_AT, mode=2),
        452: FileCall("fchmodat2", "attributes", dirfd=_AT, mode=2),
        55: FileCall("fchown", "attributes", owner=(1, 2), by_fd=True),
        54: FileCall("fchownat", "attributes", dirfd=_AT, owner=(2, 3)),
        5: FileCall("setxattr", "attributes"),
        6: FileCall("lsetxattr", "attributes"),
        7: FileCall("fsetxattr", "attributes", by_fd=True),
        14: FileCall("removexattr", "attributes"),
        15: FileCall("lremovexattr", "attributes"),
        16: FileCall("fremovexattr", "attributes", by_fd=True),
        88: FileCall("utimensat", "attributes", dirfd=_AT),
    },
}
# The descriptor value meaning "the working directory" (-100), as auditd prints a 64- or 32-bit argument.
AT_FDCWD = {"ffffffffffffff9c", "ffffff9c"}
# Open flags shared by the supported arches (asm-generic values; x86_64 and aarch64 agree on these bits).
O_ACCMODE, O_WRONLY, O_RDWR = 0o3, 0o1, 0o2
O_CREAT, O_TRUNC, O_APPEND, O_TMPFILE_BIT = 0o100, 0o1000, 0o2000, 0o20000000


def file_syscall(rec: AuditRecord) -> FileCall | None:
    """The file-changing system call a SYSCALL record made, decoded by (arch, number); None if it is not one."""
    table = FILE_SYSCALLS.get(rec.fields.get("arch", ""))
    number = rec.fields.get("syscall", "")
    return table.get(int(number)) if table and number.isdigit() else None


def syscall_arg(rec: AuditRecord, index: int) -> int | None:
    """A SYSCALL argument register (aN, printed as hex); None when it is absent or not hex."""
    value = rec.fields.get(f"a{index}", "")
    return int(value, 16) if value and _HEX.match(value) else None


def parse_sockaddr(saddr: str) -> SockAddr:
    """Decode the raw sockaddr auditd logs as hex. The family is little-endian (host order on the
    supported arches); the port and address are in network order."""
    if not saddr or not _HEX.match(saddr) or len(saddr) % 2 or len(saddr) < 4:
        raise AuditParseError("SOCKADDR saddr is not hex")
    b = bytes.fromhex(saddr)
    fam = int.from_bytes(b[0:2], "little")
    name = AF_NAMES.get(fam, f"af_{fam}")
    if fam == 2:
        if len(b) < 8:
            raise AuditParseError("short AF_INET sockaddr")
        return SockAddr(name, str(ipaddress.IPv4Address(b[4:8])), int.from_bytes(b[2:4], "big"))
    if fam == 10:
        if len(b) < 24:
            raise AuditParseError("short AF_INET6 sockaddr")
        addr = ipaddress.IPv6Address(b[8:24])
        ip = str(addr.ipv4_mapped) if addr.ipv4_mapped else str(addr)
        return SockAddr(name, ip, int.from_bytes(b[2:4], "big"))
    return SockAddr(name)


class ExecveArgv(NamedTuple):
    """The arguments that arrived, in order, and why the command line is incomplete (None when it is complete)."""
    args: list[str]
    problem: str | None = None


def _join_chunks(i: int, chunks: dict[int, tuple[str, bool]], stated: str | None) -> tuple[str | None, str | None]:
    """One split argument from its chunks: (the text up to the first gap or None, the problem or None).

    The kernel logs a split argument in one encoding (hex whenever it spans buffers or holds spaces, quotes or
    control characters, else quoted) and states its logged length in `aN_len`: hex characters for a hex
    argument, bytes for a quoted one. Text is never spliced across a missing chunk."""
    run: list[tuple[str, bool]] = []
    while len(run) in chunks:
        run.append(chunks[len(run)])
    if not run:
        return None, f"a{i} first chunk missing (have {sorted(chunks)})"
    encodings = {quoted for _text, quoted in run}
    if len(encodings) > 1:
        return None, f"a{i} chunks mix quoted and hex encodings"
    texts = [text for text, _quoted in run]
    if encodings.pop():
        value, logged = "".join(texts), sum(len(text) for text in texts)
    else:
        hexstr = "".join(texts)
        if len(hexstr) % 2 or not _HEX.match(hexstr):
            return None, f"a{i} chunks are not hex"
        value, logged = bytes.fromhex(hexstr).decode("utf-8", errors="replace"), len(hexstr)
    if len(run) != len(chunks):
        return value, f"a{i} chunk {len(run)} missing (have {sorted(chunks)})"
    if not (stated or "").isdigit():
        return value, f"a{i}_len missing or not a number: {stated!r}"
    if int(stated) != logged:
        return value, f"a{i} chunks hold {logged} of a{i}_len={stated} logged characters"
    return value, None


def execve_argv(rec: AuditRecord) -> ExecveArgv:
    """Reassemble argv, including split long args (a2_len=..., a2[0]=..., a2[1]=...).

    A long argument is logged as `aN_len` and chunks `aN[0]`, `aN[1]`, ..., possibly in several EXECVE records of
    one event (merged before this). When anything is missing or inconsistent, the arguments that arrived before
    the first gap are returned (a split argument only up to its gap) with the problem: a lost record must never
    read as a complete, shorter command line, and what did arrive is still evidence."""
    if rec.type != "EXECVE":
        raise AuditParseError("not an EXECVE record")
    argc_text = rec.fields.get("argc")
    argc = int(argc_text) if argc_text is not None and argc_text.isdigit() else None
    parts: dict[int, dict[int, tuple[str, bool]]] = {}
    whole: dict[int, str] = {}
    lengths: dict[int, str] = {}
    for key, (value, quoted) in rec.raw_fields.items():
        m = _ARG_LEN.match(key)
        if m:
            lengths[int(m.group(1))] = value
            continue
        m = _ARG.match(key)
        if not m:
            continue
        idx = int(m.group(1))
        if m.group(2) is None:
            whole[idx] = decode_value(value, quoted)
        else:
            parts.setdefault(idx, {})[int(m.group(2))] = (value, quoted)
    problems: list[str] = [rec.argv_problem] if rec.argv_problem else []
    present = set(whole) | set(parts) | set(lengths)
    if argc is None:
        problems.append(f"argc missing or not a number: {argc_text!r}")
        limit = max(present) + 1 if present else 0
    else:
        limit = argc
        beyond = sorted(i for i in present if i >= argc)
        if beyond:
            problems.append(f"a{beyond[0]} lies beyond argc={argc}")
    argv: list[str] = []
    for i in range(limit):
        if i in whole and (i in parts or i in lengths):
            problems.append(f"a{i} is both whole and split")
            break
        if i in whole:
            argv.append(whole[i])
            continue
        if i not in parts:
            problems.append(f"a{i} missing" + (f" (argc={argc})" if argc is not None else ""))
            break
        value, problem = _join_chunks(i, parts[i], lengths.get(i))
        if value is not None:
            argv.append(value)
        if problem:
            problems.append(problem)
            break
    return ExecveArgv(argv, "; ".join(problems) or None)


# ---------------------------------------------------------------------------------------------
# Records rebuilt from the fields a shipper parsed (Elastic Agent Auditd Logs without the raw line)
# ---------------------------------------------------------------------------------------------
#
# The Auditd Logs integration's ingest pipeline (packages/auditd/data_stream/log/elasticsearch/ingest_pipeline/
# default.yml and raw.yml) parses each record's key=value pairs into auditd.log.<key>, then moves some keys to ECS
# fields. Fleet's final pipeline removes event.original unless the document is tagged preserve_original_event. A
# record is rebuilt from auditd.log.* and the reverse of these moves; whatever the pipeline dropped stays absent.

# The pipeline's renames of audit keys to ECS fields, in its order: (ECS path, audit key). A rename onto a field that
# already holds a value fails and leaves the key in auditd.log, so a key still in auditd.log always wins.
AGENT_ECS_MOVES = (
    ("user.name", "acct"), ("user.name", "user"),
    ("user.id", "uid"), ("user.group.id", "gid"), ("user.audit.group.id", "agid"), ("user.audit.id", "auid"),
    ("user.filesystem.group.id", "fsgid"), ("user.filesystem.id", "fsuid"), ("user.effective.group.id", "egid"),
    ("user.effective.id", "euid"), ("user.saved.group.id", "sgid"), ("user.saved.id", "suid"),
    ("user.owner.group.id", "ogid"), ("user.owner.id", "ouid"),
    ("process.name", "comm"), ("process.executable", "exe"), ("process.pid", "pid"), ("process.parent.pid", "ppid"),
    ("process.exit_code", "exit"), ("process.working_directory", "cwd"), ("user.terminal", "terminal"),
    ("source.address", "addr"), ("destination.address", "dst"),
)
# Record types whose acct the pipeline never renames to user.name (it is dropped with the other removed keys).
AGENT_ACCT_KEPT_TYPES = frozenset({"ACCT_LOCK", "ACCT_UNLOCK", "ADD_USER", "DEL_USER", "USER_CHAUTHTOK", "USER_MGMT"})
# Before the renames, the pipeline's ECS mapping script (generated from go-libaudit) copies identities for these
# user-space record types: auid into user.id, acct/id/uid into user.effective, user.target or group, and the
# enrichment's AUID/UID/ID names over them. For these types user.id and user.effective.* are not renamed keys.
AGENT_COPY_TYPES = frozenset({
    "ACCT_LOCK", "ACCT_UNLOCK", "ADD_GROUP", "ADD_USER", "CRED_ACQ", "CRED_DISP", "CRED_REFR", "DEL_GROUP",
    "DEL_USER", "GRP_AUTH", "GRP_CHAUTHTOK", "GRP_MGMT", "LOGIN", "USER_ACCT", "USER_AUTH", "USER_CHAUTHTOK",
    "USER_END", "USER_ERR", "USER_LOGIN", "USER_LOGOUT", "USER_MGMT", "USER_START",
})
# Where the copy put acct, per type: (ECS prefix, keys copied in preference to acct, enrichment key copied over it,
# whether the AUID enrichment name is copied to user.name, so that acct's rename to user.name failed).
_AGENT_ACCT_COPIES = {
    **{kind: ("user.effective", (), None, False) for kind in (
        "CRED_ACQ", "CRED_DISP", "CRED_REFR", "USER_ACCT", "USER_AUTH", "USER_END", "USER_ERR", "USER_LOGIN")},
    **{kind: ("user.effective", (), "UID", True) for kind in ("USER_START", "USER_LOGOUT")},
    **{kind: ("user.target", ("id",), "ID", True) for kind in ("ADD_USER", "DEL_USER", "ACCT_LOCK", "ACCT_UNLOCK")},
    "USER_CHAUTHTOK": ("user.target", (), "ID", True), "USER_MGMT": ("user.target", (), None, False),
    "ADD_GROUP": ("group", ("id",), "ID", True), "DEL_GROUP": ("group", ("id",), "ID", True),
    "GRP_CHAUTHTOK": ("group", (), None, False),
}
_COPY_SKIPPED = {None, "", "?", "unset"}
# host.architecture back to the audit arch token. The pipeline names only x86_64 and keeps any other arch as the
# header's hex token; a pre-parsed record (and Auditbeat) uses go-libaudit's names.
AGENT_ARCH_TOKENS = {"x86_64": "c000003e", "aarch64": "c00000b7", "i386": "40000003", "i686": "40000003",
                     "arm": "40000028", "armv7l": "40000028", "ppc64le": "c0000015", "ppc64": "80000015",
                     "s390x": "80000016"}
_ARCH_TOKEN = re.compile(r"^[0-9a-fA-F]{8}$")
# The pipeline decodes a hex value of these keys only when the text holds a control character, space or quote; text
# whose only reason for hex was a byte above 0x7e stays hex.
_AGENT_HEX_KEYS = {"exe", "cmd", "data", "path", "comm", "file", "name", "watch", "cwd", "acct", "dir", "proctitle",
                   "grp", "new_group", "root_dir", "sw", "device", "cgroup", "profile", "operation", "info", "vm"}
_TRUNCATED_ARGS = re.compile(r"^\[\.\.\. (\d+) truncated arguments \.\.\.\]$")
_SKIPPED_LOG_KEYS = {"record_type", "sequence", "node", "kv", "sub_kv", "sub_kv_enriched", "epoch", "copy",
                     "original_field"}
_EXECVE_KEY = re.compile(r"^(?:a\d+.*|argc)$")


def _dig(source: dict, path: str):
    cur = source
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _text(value) -> str | None:
    """A parsed scalar as the audit record wrote it: booleans as yes/no, numbers as decimal text."""
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return value
    if isinstance(value, list) and len(value) == 1:
        return _text(value[0])
    return None


def _hex_left(value: str, *, any_reason: bool) -> str | None:
    """The text of a value the shipper may have left hex-encoded, else None. It is decoded only when auditd would
    have encoded that text: with `any_reason` for any reason auditd encodes (a control character, space, quote, DEL
    or a byte above 0x7e), else only for a byte above 0x7e (the pipeline already decoded the others)."""
    if not value or len(value) % 2 or not _HEX.match(value):
        return None
    try:
        text = bytes.fromhex(value).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    controls = any(ord(char) < 0x21 or char == '"' or ord(char) == 0x7f for char in text)
    high = any(ord(char) > 0x7e for char in text)
    if any_reason:
        return text if controls or high else None
    return text if high and not controls else None


def syscall_number(name: str, arch: str) -> str | None:
    """The number of a socket, module or file call named `name` on an audit arch (None when the tables lack it)."""
    from romulus.evidence.linux_catalog import MODULE_SYSCALLS
    for table in (SOCKET_SYSCALLS.get(arch) or {}, MODULE_SYSCALLS.get(arch) or {}):
        for number, call in table.items():
            if call == name:
                return str(number)
    for number, file_call in (FILE_SYSCALLS.get(arch) or {}).items():
        if file_call.name == name:
            return str(number)
    return None


def _arch_token(value) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    if _ARCH_TOKEN.match(value):
        return value.lower()
    return AGENT_ARCH_TOKENS.get(value.lower())


def _epoch(value) -> float:
    from datetime import UTC, datetime
    if not isinstance(value, str) or not value:
        raise AuditParseError("rebuilt audit record without @timestamp")
    try:
        when = datetime.fromisoformat(value)
    except ValueError as e:
        raise AuditParseError(f"rebuilt audit record @timestamp is not ISO-8601: {value!r}") from e
    return (when if when.tzinfo else when.replace(tzinfo=UTC)).timestamp()


def record_from_agent_fields(source: dict) -> AuditRecord:
    """Rebuild one audit record from the fields the Elastic Agent Auditd Logs pipeline parsed (see above).

    `type` is auditd.log.record_type (else the lower-case record type in event.action), `ts` the header epoch the
    pipeline wrote to @timestamp (milliseconds), `serial` auditd.log.sequence. Lower-case auditd.log keys are
    fields, upper-case ones the enrichment. The ECS moves are reversed; EXECVE arguments come from process.args.
    `origins` names the indexed path of every key. A SYSCALL record whose arch is not known is refused: its call
    numbers cannot be read without it. Raises AuditParseError."""
    log = _dig(source, "auditd.log")
    if not isinstance(log, dict):
        raise AuditParseError("no auditd.log fields")
    rtype = log.get("record_type")
    action = _dig(source, "event.action")
    if not (isinstance(rtype, str) and rtype) and isinstance(action, str) and re.fullmatch(r"[a-z_]+", action):
        rtype = action.upper()
    if not (isinstance(rtype, str) and re.fullmatch(r"[A-Z_]+", rtype)):
        raise AuditParseError("rebuilt audit record has no record type")
    sequence = _text(log.get("sequence"))
    if sequence is None or not sequence.isascii() or not sequence.isdigit():
        raise AuditParseError("rebuilt audit record has no sequence number")
    ts = round(_epoch(_dig(source, "@timestamp")), 3)
    fields: dict[str, str] = {}
    enriched: dict[str, str] = {}
    origins: dict[str, str] = {}
    guessed: list[str] = []
    for key, value in log.items():
        if key in _SKIPPED_LOG_KEYS or (rtype == "EXECVE" and _EXECVE_KEY.match(key)):
            continue
        text = _text(value)
        if text is None:
            continue
        if key.isupper():
            enriched[key] = text
            continue
        if key in _AGENT_HEX_KEYS and (decoded := _hex_left(text, any_reason=False)) is not None:
            text = decoded
            guessed.append(key)
        fields[key] = text
        origins[key] = f"auditd.log.{key}"
    copied = rtype in AGENT_COPY_TYPES
    for path, key in AGENT_ECS_MOVES:
        if key in fields or key in ("acct", "user"):
            continue        # user.name may hold either, or the enrichment's UID name: acct is read below
        if copied and path in ("user.id", "user.effective.id") and not (
                key == "uid" and rtype != "LOGIN" and _dig(source, "user.audit.id") is None):
            # a copy may have set it; uid is the renamed key only when no auid was there to be copied
            continue
        if key == "exe" and rtype == "EXECVE":
            continue        # the pipeline sets process.executable to the first argument
        text = _text(_dig(source, path))
        if text is not None:
            fields[key] = text
            origins[key] = path
    if "acct" not in fields and (acct := _agent_acct(source, log, rtype)) is not None:
        fields["acct"], origins["acct"] = acct
    outcome = _dig(source, "event.outcome")
    if "res" not in fields and outcome in ("success", "failure"):
        fields["res"] = "success" if outcome == "success" else "failed"
        origins["res"] = "event.outcome"
    arch = _arch_token(_dig(source, "host.architecture"))
    if arch is None and "arch" in fields:
        arch = _arch_token(fields["arch"])     # a pre-parsed record keeps its arch in auditd.log
    if arch is not None:
        fields["arch"] = arch
        origins.setdefault("arch", "host.architecture")
    if rtype == "SYSCALL":
        if arch is None:
            raise AuditParseError(f"SYSCALL record with an unknown architecture "
                                  f"({_dig(source, 'host.architecture')!r}): its call cannot be read")
        number = fields.get("syscall", "")
        if number and not number.isdigit():
            mapped = syscall_number(number, arch)
            if mapped is not None:
                fields["syscall"] = mapped
    raw = {key: (value, True) for key, value in fields.items()}
    argv_problem = _agent_execve(source, raw, fields, origins, guessed) if rtype == "EXECVE" else None
    return AuditRecord(type=rtype, ts=ts, serial=int(sequence), fields=fields, raw_fields=raw, enriched=enriched,
                       node=_text(log.get("node")), origins=origins, argv_problem=argv_problem,
                       hex_guessed=tuple(guessed))


def _agent_acct(source: dict, log: dict, rtype: str) -> tuple[str, str] | None:
    """(acct, the path it was read from) when the pipeline left it recoverable, else None. The identity copy puts
    acct in user.effective, user.target or group (by type) unless a key it prefers, or the enrichment's name,
    took that place; otherwise acct was renamed to user.name, unless the enrichment's AUID name was copied there
    first. user.name equal to the enrichment's UID name may be that name and not acct."""
    copy = _AGENT_ACCT_COPIES.get(rtype)
    if copy is not None:
        prefix, before, override, auid_named = copy
        name = _text(_dig(source, f"{prefix}.name"))
        if (name is not None and all(log.get(key) in _COPY_SKIPPED for key in before)
                and (override is None or log.get(override) in _COPY_SKIPPED)):
            return name, f"{prefix}.name"
        if auid_named and log.get("AUID") not in _COPY_SKIPPED:
            return None
    if rtype in AGENT_ACCT_KEPT_TYPES:
        return None
    name = _text(_dig(source, "user.name"))
    uid_name = log.get("UID")
    if name is None or (uid_name not in _COPY_SKIPPED and uid_name == name):
        return None
    return name, "user.name"


def _agent_execve(source: dict, raw: dict, fields: dict, origins: dict, guessed: list[str]) -> str | None:
    """EXECVE arguments from process.args: a0.. in order, or aN.. after the pipeline's marker for a record whose
    head (with argc) was lost. A split argument's chunks become separate elements there, and an argument auditd
    hex-encoded stays hex; such a value is decoded when auditd would have encoded its text."""
    args = _dig(source, "process.args")
    count = _text(_dig(source, "process.args_count"))
    if isinstance(args, str):
        args = [args]
    if not isinstance(args, list) or not all(isinstance(arg, str) for arg in args):
        return "process.args missing or not a list of strings"
    first, problem = 0, None
    if args and (marker := _TRUNCATED_ARGS.match(args[0])):
        first, args = int(marker.group(1)), args[1:]
        problem = f"the shipper recorded only the arguments from a{first} on"
    elif count is not None and count.isascii() and count.isdigit():
        raw["argc"] = (count, True)
        fields["argc"], origins["argc"] = count, "process.args_count"
    for offset, arg in enumerate(args):
        key = f"a{first + offset}"
        decoded = _hex_left(arg, any_reason=True)
        if decoded is not None:
            arg = decoded
            guessed.append(key)
        raw[key] = (arg, True)
        fields[key], origins[key] = arg, "process.args"
    return problem
