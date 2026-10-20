"""Token-aware helpers for Linux context rules: program identity from the kernel-recorded executable, file
operands from argv, path normalization, and per-tool option grammars. Nothing here reads serialized records
or substrings of them."""
from __future__ import annotations

import posixpath
import re
from typing import NamedTuple

from romulus.detect.base import basename
from romulus.evidence.typed import TypedEvent

# Applet multiplexers: the kernel records the multiplexer; argv[0] (or argv[1]) selects the applet.
MULTIPLEXERS = {"busybox", "toybox"}

# Distribution alternatives and versioned names that denote one canonical tool. Positive-only: this only ever
# adds matches, it never suppresses one.
_CANONICAL = {
    "nc.openbsd": "nc", "nc.traditional": "nc", "ncat": "nc",
    "mawk": "awk", "gawk": "awk", "original-awk": "awk",
    "vim.basic": "vi", "vim.tiny": "vi", "vim": "vi", "nvi": "vi", "view": "vi",
    "w.procps": "w", "egrep": "grep", "fgrep": "grep", "rgrep": "grep",
}
_PY3 = re.compile(r"^python3\.\d+$")
_PY2 = re.compile(r"^python2\.\d+$")
_TRIPLET_STRINGS = re.compile(r"^[A-Za-z0-9_]+-[A-Za-z0-9_.-]*strings$")


def canonical(name: str) -> str:
    if name in _CANONICAL:
        return _CANONICAL[name]
    if _PY3.match(name):
        return "python3"
    if _PY2.match(name):
        return "python2"
    if _TRIPLET_STRINGS.match(name):
        return "strings"
    return name


class Program(NamedTuple):
    name: str                # canonical program name
    args: list[str]          # operands after the program token
    name_from_argv0: bool    # True when the name came from argv[0] (a multiplexer applet)


def program(event: TypedEvent) -> Program | None:
    """Program identity for an exec record. The name comes from the kernel-recorded `process.executable`;
    argv[0] is trusted for identity only to select a multiplexer applet, which is exactly what the
    multiplexer dispatches on. The canonical name folds distribution alternatives together."""
    executable = event.get("process.executable")
    if not executable:
        return None
    argv = event.get("process.argv")
    args = [str(item) for item in argv] if isinstance(argv, list) else []
    exe_name = basename(str(executable))
    name, rest, from_argv0 = exe_name, args[1:], False
    if exe_name in MULTIPLEXERS and args:
        applet = basename(args[0])
        if applet in MULTIPLEXERS:
            if len(args) <= 1:
                return None
            name, rest, from_argv0 = basename(args[1]), args[2:], True
        else:
            name, rest, from_argv0 = applet, args[1:], True
    return Program(canonical(name), rest, from_argv0)


def split_flags(args: list[str]) -> tuple[set[str], list[str]]:
    """Short flags (grouped letters split: `-lvnp` -> l, v, n, p), long flags (with any `=value` removed) and
    operands. `--` ends option parsing."""
    flags: set[str] = set()
    operands: list[str] = []
    ended = False
    for arg in args:
        if ended or arg == "-" or not arg.startswith("-"):
            operands.append(arg)
        elif arg == "--":
            ended = True
        elif arg.startswith("--"):
            flags.add(arg.split("=", 1)[0])
        else:
            flags.update(f"-{letter}" for letter in arg[1:])
    return flags, operands


def normalize_path(path: str, cwd: str | None = None) -> str:
    """Absolute, normalized POSIX path, or "" when a relative path has no usable working directory."""
    if not path:
        return ""
    if not path.startswith("/"):
        if not cwd or not str(cwd).startswith("/"):
            return ""
        path = posixpath.join(str(cwd), path)
    normalized = posixpath.normpath(path)
    return "/" + normalized.lstrip("/")


def is_under(path: str, prefixes: tuple[str, ...]) -> bool:
    return any(path == prefix or path.startswith(prefix.rstrip("/") + "/") for prefix in prefixes)


# ------------------------------------------------------------------------------------------------
# Permission masks (for a setuid/setgid search).
# ------------------------------------------------------------------------------------------------

def is_suid_perm(value: str) -> bool:
    """True when a `find -perm` value selects the setuid or setgid bit (numeric or symbolic forms)."""
    if re.search(r"[ug][=+]s", value):
        return True
    stripped = value.lstrip("-+/")
    if stripped.isdigit():
        try:
            return bool(int(stripped, 8) & 0o6000)
        except ValueError:
            return False
    return False


# ------------------------------------------------------------------------------------------------
# File-reading programs: the paths they were given to open.
# ------------------------------------------------------------------------------------------------

# Options of a plain reader that take a separate value operand (so the value is not a file to open).
_READER_VALUE_FLAGS = {
    "head": {"-n", "-c", "--bytes", "--lines"}, "tail": {"-n", "-c", "--bytes", "--lines"},
    "od": {"-N", "-j", "-A", "-t", "-w", "-S", "-s"}, "xxd": {"-l", "-s", "-c", "-g", "-o"},
    "hexdump": {"-n", "-s", "-e", "-f"}, "strings": {"-n", "-t", "-e"},
    "cut": {"-d", "-f", "-b", "-c", "--output-delimiter", "--delimiter", "--fields", "--bytes", "--characters"},
    "sort": {"-o", "-k", "-t", "-S", "-T", "--output", "--files0-from", "--key", "--field-separator",
             "--buffer-size"},
    "base64": {"-w", "--wrap"}, "base32": {"-w", "--wrap"},
    "cp": {"-t", "--target-directory", "-S", "--suffix"},
}
PLAIN_READERS = {"cat", "tac", "nl", "less", "more", "vi", "nano", "md5sum", "sha1sum", "sha256sum", "sha512sum",
                 "cp", "head", "tail", "od", "xxd", "hexdump", "strings", "base64", "base32", "cut", "sort",
                 "zcat", "unshadow"}
PATTERN_READERS = {"grep", "awk", "sed"}
_PATTERN_VALUE_FLAGS = {
    "grep": {"-e", "-f", "-m", "-A", "-B", "-C", "--regexp", "--file", "--max-count"},
    "awk": {"-f", "-v", "-F"},
    "sed": {"-e", "-f", "--expression", "--file"},
}
_PATTERN_SOURCE_FLAGS = {"-e", "-f", "--regexp", "--file", "--expression"}


def _plain_operands(name: str, args: list[str]) -> tuple[list[str], bool]:
    """Non-option operands of a plain reader, and whether a target-directory option was present (cp -t)."""
    value_flags = _READER_VALUE_FLAGS.get(name, set())
    operands: list[str] = []
    target_dir = False
    skip = False
    ended = False
    for arg in args:
        if skip:
            skip = False
            continue
        if ended or arg == "-" or not arg.startswith("-"):
            operands.append(arg)
            continue
        if arg == "--":
            ended = True
            continue
        if arg in {"-t", "--target-directory"} or arg.startswith("--target-directory="):
            target_dir = True
            skip = arg in {"-t", "--target-directory"}
            continue
        if arg in value_flags:
            skip = True
            continue
        if arg.startswith("--") and "=" in arg:
            continue
        # a short flag; ignore (none of the plain readers group a value into the same token for our needs)
    return operands, target_dir


def read_operands(name: str, args: list[str], cwd: str | None = None) -> list[str]:
    """Normalized absolute paths a reader program was given as files to open. Positive-only: a reader can be
    given files in ways argv does not show (stdin, shell redirects, globs expanded by nobody)."""
    raw: list[str] = []
    if name in PLAIN_READERS:
        operands, target_dir = _plain_operands(name, args)
        if name == "cp" and not target_dir and len(operands) > 1:
            operands = operands[:-1]              # SRC... DEST: the last operand is the destination
        raw = operands
    elif name in PATTERN_READERS:
        value_flags = _PATTERN_VALUE_FLAGS[name]
        explicit_pattern = False
        operands = []
        skip = False
        for arg in args:
            if skip:
                skip = False
                continue
            if arg in value_flags:
                explicit_pattern = explicit_pattern or arg in _PATTERN_SOURCE_FLAGS
                skip = True
                continue
            if arg.split("=", 1)[0] in {"--regexp", "--file", "--expression"}:
                explicit_pattern = True
                continue
            if arg.startswith("-") and arg != "-":
                continue
            operands.append(arg)
        raw = operands if explicit_pattern else operands[1:]
    elif name == "dd":
        raw = [arg[3:] for arg in args if arg.startswith("if=")]
    out = []
    for item in raw:
        path = normalize_path(item, cwd)
        if path:
            out.append(path)
    return out


# ------------------------------------------------------------------------------------------------
# Archive utilities: which inputs are staged, and whether the mode stages at all.
# ------------------------------------------------------------------------------------------------

_TAR_VALUE_LETTERS = set("fCbXTVHLgoN")
_TAR_LONG_VALUE = {"--file", "--directory", "--exclude-from", "--files-from", "--exclude", "--transform",
                   "--owner", "--group", "--mode", "--use-compress-program", "--format", "--label",
                   "--blocking-factor", "--newer", "--after-date"}
_TAR_LONG_MODE = {"--create": "c", "--extract": "x", "--get": "x", "--list": "t", "--append": "r",
                  "--update": "u", "--concatenate": "r"}


def tar_spec(args: list[str]) -> tuple[bool, list[str]]:
    """(is_staging, input paths) for a tar invocation. Only create/append/update modes stage data; extract
    and list do not. The archive file (-f) and chdir (-C) values are not inputs."""
    modes: set[str] = set()
    inputs: list[str] = []

    def apply(letters: str) -> int:
        for ch in letters:
            if ch in "cxtru":
                modes.add(ch)
        return sum(1 for ch in letters if ch in _TAR_VALUE_LETTERS)

    index = 0
    if args and not args[0].startswith("-") and args[0].isalpha():
        pending = apply(args[0])                  # traditional bundled first key, e.g. czf / xzf
        index = 1 + pending
    while index < len(args):
        arg = args[index]
        if arg == "--":
            inputs.extend(args[index + 1:])
            break
        if arg.startswith("--"):
            key = arg.split("=", 1)[0]
            if key in _TAR_LONG_MODE:
                modes.add(_TAR_LONG_MODE[key])
            elif key in _TAR_LONG_VALUE and "=" not in arg:
                index += 1
            index += 1
            continue
        if arg.startswith("-"):
            index += 1 + apply(arg[1:])
            continue
        inputs.append(arg)
        index += 1
    is_staging = bool(modes & set("cru")) and not (modes & set("xt"))
    return is_staging, inputs


# ------------------------------------------------------------------------------------------------
# Remote-service clients: destination host and per-client value options.
# ------------------------------------------------------------------------------------------------

_CLIENT_VALUE_OPTS = {
    "ssh": {"-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J", "-L", "-l", "-m", "-O", "-o", "-p", "-Q",
            "-R", "-S", "-W", "-w", "-B"},
    "scp": {"-P", "-S", "-o", "-i", "-F", "-c", "-l", "-J"},
    "sftp": {"-P", "-S", "-o", "-i", "-F", "-c", "-l", "-b", "-D", "-R"},
    "rsync": {"-e", "--rsh", "--rsync-path", "--exclude-from", "--include-from", "--files-from", "--log-file",
              "--compare-dest", "--copy-dest", "--link-dest", "-T", "--temp-dir", "--partial-dir", "--bwlimit",
              "--timeout", "--contimeout", "--port", "--block-size", "-B", "--modify-window", "--max-size",
              "--min-size", "--address", "--sockopts", "--password-file", "--out-format", "--chmod",
              "--backup-dir", "--suffix"},
    "nc": {"-e", "-c", "-p", "-s", "-w", "-i", "-x", "-X", "-q", "-b", "-g", "-G", "-O", "-T"},
}


def operands_after_options(args: list[str], value_opts: set[str]) -> list[str]:
    """Non-option operands, skipping the values of the named value-taking options. `--opt=value` is one token;
    `--` ends options."""
    out: list[str] = []
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--":
            out.extend(args[index + 1:])
            break
        if arg in value_opts:
            index += 2
            continue
        if arg.startswith("--") and "=" in arg:
            index += 1
            continue
        if arg.startswith("-") and arg != "-":
            index += 1
            continue
        out.append(arg)
        index += 1
    return out


def remote_endpoint(operand: str) -> str | None:
    """The host of a remote file operand: `[user@]host:path`, `host::module`, or `rsync://[user@]host/path`.
    A local path (absolute, `./`, `~`, or with no host before the colon) returns None."""
    if not operand or operand.startswith(("/", "./", "../", "~", "-")):
        return None
    if operand.startswith("rsync://"):
        host = operand[len("rsync://"):].split("/", 1)[0].split("@")[-1]
        return host or None
    for sep in ("::", ":"):
        if sep in operand:
            left = operand.split(sep, 1)[0]
            if "/" in left or left == "":
                return None
            return left.split("@")[-1] or None
    return None


def scp_remote_host(name: str, args: list[str]) -> str | None:
    """Destination host of an scp/sftp/rsync invocation, or None when every operand is local."""
    for operand in operands_after_options(args, _CLIENT_VALUE_OPTS.get(name, set())):
        host = remote_endpoint(operand)
        if host:
            return host
    return None


def ssh_destination(args: list[str]) -> str | None:
    """The host operand of an ssh invocation (`[user@]host [command...]`)."""
    operands = operands_after_options(args, _CLIENT_VALUE_OPTS["ssh"])
    if not operands:
        return None
    host = operands[0].split("@")[-1]
    return host or None


def nc_destination(args: list[str]) -> tuple[str | None, bool]:
    """(host, is_listen) for a netcat invocation. The first operand after options is the host."""
    flags, _ = split_flags(args)
    is_listen = bool(flags & {"-l", "--listen"})
    operands = operands_after_options(args, _CLIENT_VALUE_OPTS["nc"])
    host = operands[0] if operands else None
    return host, is_listen
