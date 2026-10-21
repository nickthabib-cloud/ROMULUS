"""Parse Linux audit records (raw `type=... msg=audit(ts:serial): k=v ...` lines) exactly."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

_HEADER = re.compile(r"^(?:node=\S+\s+)?type=(?P<type>[A-Z_]+)\s+msg=audit\((?P<ts>[0-9.]+):(?P<serial>\d+)\):\s?"
                     r"(?P<body>.*)$", re.DOTALL)
_HEX = re.compile(r"^[0-9A-Fa-f]+$")
_ARG = re.compile(r"^a(\d+)(?:\[(\d+)\])?$")
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


def execve_argv(rec: AuditRecord) -> list[str]:
    """Reassemble argv, including split long args (a2_len=..., a2[0]=..., a2[1]=...)."""
    if rec.type != "EXECVE":
        raise AuditParseError("not an EXECVE record")
    argc = int(rec.fields.get("argc", "0"))
    parts: dict[int, dict[int, str]] = {}
    whole: dict[int, str] = {}
    for key, (value, quoted) in rec.raw_fields.items():
        m = _ARG.match(key)
        if not m:
            continue
        idx = int(m.group(1))
        if m.group(2) is None:
            whole[idx] = decode_value(value, quoted)
        else:
            # chunks are hex-encoded pieces of one arg; concatenate the hex, then decode
            parts.setdefault(idx, {})[int(m.group(2))] = value if not quoted else value.encode().hex()
    argv = []
    for i in range(argc):
        if i in whole:
            argv.append(whole[i])
        elif i in parts:
            hexstr = "".join(parts[i][k] for k in sorted(parts[i]))
            argv.append(decode_value(hexstr, False))
        else:
            raise AuditParseError(f"EXECVE missing a{i} (argc={argc})")
    return argv
