"""Token-aware helpers for Linux context rules: program identity from the kernel-recorded executable, file
operands from argv, and path normalization. Nothing here reads serialized records or substrings of them."""
from __future__ import annotations

import posixpath

from romulus.detect.base import basename
from romulus.evidence.typed import TypedEvent

# Applet multiplexers: the kernel records the multiplexer; argv[0] (or argv[1]) selects the applet.
MULTIPLEXERS = {"busybox", "toybox"}


def program(event: TypedEvent) -> tuple[str, list[str]] | None:
    """(program name, operands) for an exec record. The name comes from the kernel-recorded
    `process.executable`; argv[0] is never trusted for identity, except to select a multiplexer applet,
    where argv[0] is exactly what the multiplexer dispatches on."""
    executable = event.get("process.executable")
    if not executable:
        return None
    argv = event.get("process.argv")
    args = [str(item) for item in argv] if isinstance(argv, list) else []
    name = basename(str(executable))
    if name in MULTIPLEXERS and args:
        applet = basename(args[0])
        if applet in MULTIPLEXERS:
            return (basename(args[1]), args[2:]) if len(args) > 1 else None
        return applet, args[1:]
    return name, args[1:]


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


# Readers whose every non-option operand is a file they open.
PLAIN_READERS = {"cat", "head", "tail", "less", "more", "tac", "nl", "strings", "xxd", "od", "hexdump", "base64",
                 "base32", "view", "vi", "vim", "nano", "cp", "md5sum", "sha1sum", "sha256sum"}
# Options of plain readers that take a separate value operand.
_READER_VALUE_FLAGS = {"-n", "-c", "-s", "-l", "-t", "-w", "-o", "-S"}
PATTERN_READERS = {"grep", "egrep", "fgrep", "rg", "awk", "gawk", "sed"}
_PATTERN_VALUE_FLAGS = {
    "grep": {"-e", "-f", "-m", "-A", "-B", "-C", "--regexp", "--file", "--max-count"},
    "awk": {"-f", "-v", "-F"},
    "sed": {"-e", "-f", "--expression", "--file"},
}
_PATTERN_SOURCE_FLAGS = {"-e", "-f", "--regexp", "--file", "--expression"}


def _pattern_family(name: str) -> str:
    return {"egrep": "grep", "fgrep": "grep", "rg": "grep", "gawk": "awk"}.get(name, name)


def read_operands(name: str, args: list[str], cwd: str | None = None) -> list[str]:
    """Normalized absolute paths a reader program was given as files to open. Positive-only: a reader can be
    given files in ways argv does not show (stdin, shell redirects, globs expanded by nobody)."""
    raw: list[str] = []
    if name in PLAIN_READERS:
        skip = False
        for arg in args:
            if skip:
                skip = False
                continue
            if arg in _READER_VALUE_FLAGS and name in {"head", "tail", "strings", "od", "xxd", "hexdump"}:
                skip = True
                continue
            if arg.startswith("-") and arg != "-":
                continue
            raw.append(arg)
        if name == "cp" and len(raw) > 1:
            raw = raw[:-1]                      # the last cp operand is the destination
    elif name in PATTERN_READERS:
        family = _pattern_family(name)
        value_flags = _PATTERN_VALUE_FLAGS[family]
        explicit_pattern = False
        operands: list[str] = []
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


def is_under(path: str, prefixes: tuple[str, ...]) -> bool:
    return any(path == prefix or path.startswith(prefix.rstrip("/") + "/") for prefix in prefixes)
