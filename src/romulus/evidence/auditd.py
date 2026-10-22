"""Parse Linux audit records (raw `type=... msg=audit(ts:serial): k=v ...` lines) exactly."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import NamedTuple

_HEADER = re.compile(r"^(?:node=\S+\s+)?type=(?P<type>[A-Z_]+)\s+msg=audit\((?P<ts>[0-9.]+):(?P<serial>\d+)\):\s?"
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
                       fields=fields, raw_fields=raw, enriched=enriched)


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
    problems: list[str] = []
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
