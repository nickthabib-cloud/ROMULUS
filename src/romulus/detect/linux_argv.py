"""Token-aware helpers for Linux context rules: program identity from the kernel-recorded executable, file
operands from argv, path normalization, and per-tool option grammars. Nothing here reads serialized records
or substrings of them."""
from __future__ import annotations

import posixpath
import re
from typing import NamedTuple
from urllib.parse import urlsplit

from romulus.detect.base import basename
from romulus.evidence.shellparse import SHELLS, UnknownShellScript, shell_script_of
from romulus.evidence.shellparse import _lex as _shell_tokens  # the parser's own lexer, reused read-only
from romulus.evidence.shellparse import _Unmodelled as _ShellUnmodelled
from romulus.evidence.typed import TypedEvent

# Applet multiplexers: the kernel records the multiplexer; argv[0] (or argv[1]) selects the applet.
MULTIPLEXERS = {"busybox", "toybox"}

# Distribution alternatives and versioned names that denote one canonical tool. Positive-only: this only ever
# adds matches, it never suppresses one.
_CANONICAL = {
    "nc.openbsd": "nc", "nc.traditional": "nc", "ncat": "nc",
    "mawk": "awk", "gawk": "awk", "original-awk": "awk",
    "vim.basic": "vi", "vim.tiny": "vi", "vim": "vi", "nvi": "vi", "view": "vi",
    "vim.nox": "vi", "vim.gtk": "vi", "vim.gtk3": "vi", "vim.athena": "vi", "gvim": "vi",
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


def program_name_hint(event: TypedEvent) -> str | None:
    """Cheap exact program identity for rejecting irrelevant execs before option/script parsing."""
    argv = event.get("process.argv")
    if not isinstance(argv, list) or not argv:
        return None
    executable = event.get("process.executable")
    if not executable:
        return canonical(basename(str(argv[0])))
    name = basename(str(executable))
    if name not in MULTIPLEXERS:
        return canonical(name)
    applet = basename(str(argv[0]))
    if applet in MULTIPLEXERS:
        return canonical(basename(str(argv[1]))) if len(argv) > 1 else None
    return canonical(applet)


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
    return read_operand_paths(name, args, cwd)[0]


def read_operand_paths(name: str, args: list[str], cwd: str | None = None) -> tuple[list[str], bool]:
    """`read_operands`, and whether a named file could not be placed (a relative operand with no usable working
    directory). A caller must count such a record as missing a required field, never as a clean no-match."""
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
    unresolved = False
    for item in raw:
        if item in ("", "-"):
            continue                              # no file, or standard input
        path = normalize_path(item, cwd)
        if path:
            out.append(path)
        else:
            unresolved = True
    return out, unresolved


# ------------------------------------------------------------------------------------------------
# Archive utilities: which inputs are staged, and whether the mode stages at all.
# ------------------------------------------------------------------------------------------------

_TAR_VALUE_LETTERS = set("fCbXTVHLgoN")
_TAR_LONG_VALUE = {"--file", "--directory", "--exclude-from", "--files-from", "--exclude", "--transform",
                   "--owner", "--group", "--mode", "--use-compress-program", "--format", "--label",
                   "--blocking-factor", "--newer", "--after-date"}
_TAR_LONG_MODE = {"--create": "c", "--extract": "x", "--get": "x", "--list": "t", "--append": "r",
                  "--update": "u", "--concatenate": "r"}


def tar_spec(args: list[str]) -> tuple[bool, list[str], str | None]:
    """(is_staging, input paths, chdir) for a tar invocation. Only create/append/update modes stage data;
    extract and list do not. The archive file (-f) and chdir (-C) values are not inputs; the chdir is returned
    so inputs can be resolved against it."""
    modes: set[str] = set()
    inputs: list[str] = []
    chdir: str | None = None

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
            key, _, inline = arg.partition("=")
            if key in _TAR_LONG_MODE:
                modes.add(_TAR_LONG_MODE[key])
            elif key == "--directory":
                chdir = inline if "=" in arg else (args[index + 1] if index + 1 < len(args) else None)
                index += 0 if "=" in arg else 1
            elif key in _TAR_LONG_VALUE and "=" not in arg:
                index += 1
            index += 1
            continue
        if arg.startswith("-"):
            letters = arg[1:]
            apply(letters)
            consumed = 0
            for ch in letters:
                if ch in _TAR_VALUE_LETTERS and index + 1 + consumed < len(args):
                    if ch == "C":
                        chdir = args[index + 1 + consumed]
                    consumed += 1
            index += 1 + consumed
            continue
        inputs.append(arg)
        index += 1
    is_staging = bool(modes & set("cru")) and not (modes & set("xt"))
    return is_staging, inputs, chdir


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
    "nc": {"-e", "-c", "-p", "-s", "-w", "-i", "-x", "-X", "-q", "-b", "-g", "-G", "-O", "-T",
           "--exec", "--sh-exec", "--lua-exec", "--source", "--source-port", "--wait", "--proxy",
           "--proxy-type", "--proxy-auth", "--ssl-cert", "--ssl-key", "--max-conns", "--delay",
           "--output", "--idle-timeout"},
}


def client_operands(name: str, args: list[str]) -> list[str]:
    """Non-option operands of a remote-service client, in order."""
    return operands_after_options(args, _CLIENT_VALUE_OPTS.get(name, set()))


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


# ------------------------------------------------------------------------------------------------
# Write-capable programs: the files a command line names as the file it changes.
# ------------------------------------------------------------------------------------------------

class WriteTarget(NamedTuple):
    path: str        # normalized absolute path
    form: str        # what the command line shows, worded as an attempt, never as a completed change
    assumed: bool = False   # derived on the assumption that a destination operand is a directory


# Editors (canonical names; `vi` covers vim, nvi and view, see canonical()). Read-only invocations are excluded.
_VI_EDITORS = {"vi", "nvim"}
_VI_VALUE = {"-c", "-S", "-u", "-U", "-i", "-T", "-w", "-W", "-s", "-t", "-q", "-r", "--cmd", "--servername",
             "--startuptime", "--remote-send", "--remote-expr", "--log"}
_VI_READONLY_FLAGS = {"-R", "-M"}
_VI_READONLY_NAMES = {"view", "rview", "nview"}
_NANO_EDITORS = {"nano", "pico", "rnano"}
_NANO_VALUE = {"-o", "--operatingdir", "-Y", "--syntax", "-T", "--tabsize", "-r", "--fill", "-s", "--speller",
               "-X", "--wordchars", "-Q", "--quotestr", "-J", "--guidestripe", "-f", "--rcfile"}
_NANO_READONLY_FLAGS = {"-v", "--view"}
_ED_EDITORS = {"ed", "red"}
_ED_VALUE = {"-p", "--prompt"}
_EMACS_VALUE = {"-l", "--load", "-f", "--funcall", "--eval", "-L", "--directory", "-u", "--user", "--insert",
                "-t", "--terminal", "-d", "--display", "--chdir", "--execute", "--script", "-x"}
_EMACS_FILE_OPTS = ("--file=", "--find-file=", "--visit=")
_OTHER_EDITORS = {"joe", "jed", "mcedit", "micro", "ne", "kak", "hx", "helix", "mg", "jove", "zile", "jmacs",
                  "jstar", "jpico", "vis", "emacs"}
EDITORS = _VI_EDITORS | _NANO_EDITORS | _ED_EDITORS | _OTHER_EDITORS


def _is_emacs(name: str) -> bool:
    return name == "emacs" or name.startswith("emacs-")


def is_editor(name: str) -> bool:
    return name in EDITORS or _is_emacs(name)


def _editor_files(name: str, args: list[str], argv0: str) -> list[str]:
    """File operands an interactive editor was started on; [] for a read-only invocation."""
    if name in _VI_EDITORS:
        if basename(argv0) in _VI_READONLY_NAMES or any(arg in _VI_READONLY_FLAGS for arg in args):
            return []
        value_opts = _VI_VALUE
    elif name in _NANO_EDITORS:
        if any(arg in _NANO_READONLY_FLAGS for arg in args):
            return []
        value_opts = _NANO_VALUE
    elif name in _ED_EDITORS:
        value_opts = _ED_VALUE
    elif _is_emacs(name):
        value_opts = _EMACS_VALUE
    else:
        value_opts = set()
    files: list[str] = []
    index, ended = 0, False
    while index < len(args):
        arg = args[index]
        if ended:
            files.append(arg)
        elif arg == "--":
            ended = True
        elif arg in value_opts:
            index += 1
        elif _is_emacs(name) and arg.startswith(_EMACS_FILE_OPTS):
            files.append(arg.split("=", 1)[1])
        elif arg.startswith(("-", "+")) and arg != "-":
            pass                                    # a flag, or a `+line` / `+cmd` position argument
        else:
            files.append(arg)
        index += 1
    return [item for item in files if item != "-"]


# GNU long options, used to resolve the abbreviations getopt_long accepts (`--in-pl` is `--in-place`).
_SED_LONG = ("--expression", "--file", "--follow-symlinks", "--in-place", "--line-length", "--null-data",
             "--zero-terminated", "--posix", "--quiet", "--silent", "--regexp-extended", "--separate", "--sandbox",
             "--unbuffered", "--debug", "--binary", "--help", "--version")
_DEST_LONG = {
    "cp": ("--archive", "--attributes-only", "--backup", "--copy-contents", "--dereference", "--force",
           "--interactive", "--link", "--no-dereference", "--no-clobber", "--preserve", "--no-preserve", "--parents",
           "--recursive", "--reflink", "--remove-destination", "--sparse", "--strip-trailing-slashes",
           "--symbolic-link", "--suffix", "--target-directory", "--no-target-directory", "--update", "--verbose",
           "--one-file-system", "--context", "--debug", "--keep-directory-symlink", "--help", "--version"),
    "mv": ("--backup", "--force", "--interactive", "--no-clobber", "--strip-trailing-slashes", "--suffix",
           "--target-directory", "--no-target-directory", "--update", "--verbose", "--context", "--exchange",
           "--no-copy", "--debug", "--help", "--version"),
    "install": ("--backup", "--compare", "--directory", "--group", "--mode", "--owner", "--preserve-timestamps",
                "--strip", "--strip-program", "--suffix", "--target-directory", "--no-target-directory", "--verbose",
                "--preserve-context", "--context", "--debug", "--help", "--version"),
    "ln": ("--backup", "--directory", "--force", "--interactive", "--logical", "--no-dereference", "--physical",
           "--relative", "--symbolic", "--suffix", "--target-directory", "--no-target-directory", "--verbose",
           "--help", "--version"),
}


def gnu_long(key: str, options: tuple[str, ...]) -> str | None:
    """The long option a `--key` names: an exact match, or an unambiguous prefix as getopt_long accepts."""
    if key in options:
        return key
    hits = [option for option in options if option.startswith(key)]
    return hits[0] if len(hits) == 1 else None


def _sed_in_place(args: list[str]) -> list[str]:
    """Files GNU sed edits in place (`-i[SUFFIX]`, a grouped `-ni`, `--in-place[=SUFFIX]`); [] when sed only
    writes to stdout. Without -e/-f the first operand is the script, not a file."""
    in_place = script_given = False
    operands: list[str] = []
    index, ended = 0, False
    while index < len(args):
        arg = args[index]
        if ended or arg == "-" or not arg.startswith("-"):
            operands.append(arg)
        elif arg == "--":
            ended = True
        elif arg.startswith("--"):
            key = gnu_long(arg.split("=", 1)[0], _SED_LONG)
            if key == "--in-place":
                in_place = True
            elif key in {"--expression", "--file", "--line-length"}:
                script_given = script_given or key != "--line-length"
                if "=" not in arg:
                    index += 1
        else:
            letters = arg[1:]
            for position, letter in enumerate(letters):
                if letter == "i":
                    in_place = True
                    break                           # the rest of the group is the backup suffix
                if letter in "efl":
                    script_given = script_given or letter in "ef"
                    if position == len(letters) - 1:
                        index += 1                  # the value is the next argument
                    break
        index += 1
    if not in_place:
        return []
    return operands if script_given else operands[1:]


def _perl_in_place(args: list[str]) -> list[str]:
    """Files perl edits in place (`-i[EXT]`, grouped as in `-pi`, `-pi.bak`); [] without -i."""
    in_place = code_given = False
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--":
            index += 1
            break
        if not arg.startswith("-") or arg == "-":
            break
        letters = arg[1:]
        for position, letter in enumerate(letters):
            if letter == "i":
                in_place = True
                break                               # the rest of the group is the backup extension
            if letter in "eE":
                code_given = True
                if position == len(letters) - 1:
                    index += 1                      # the code is the next argument
                break
            if letter in "IMmxCFdDl0V":
                break                               # the rest of the group is this switch's value
        index += 1
    if not in_place:
        return []
    operands = args[index:]
    return operands if code_given else operands[1:]


# Short options of cp, mv, install and ln that take a value (attached or as the next argument).
_DEST_VALUE_LETTERS = {"cp": "St", "mv": "St", "install": "Stmog", "ln": "St"}
_DEST_LONG_VALUE = {"--suffix", "--target-directory", "--mode", "--owner", "--group"}


def _destination_spec(name: str, args: list[str]) -> tuple[list[str], str | None, bool, set[str]]:
    """(operands, target directory, no-target-directory, short flags) for cp, mv, install and ln."""
    value_letters = _DEST_VALUE_LETTERS[name]
    operands: list[str] = []
    flags: set[str] = set()
    target_dir: str | None = None
    no_target_dir = False
    index, ended = 0, False
    while index < len(args):
        arg = args[index]
        if ended or arg == "-" or not arg.startswith("-"):
            operands.append(arg)
        elif arg == "--":
            ended = True
        elif arg.startswith("--"):
            raw_key, has_value, inline = arg.partition("=")
            key = gnu_long(raw_key, _DEST_LONG[name])
            if key == "--no-target-directory":
                no_target_dir = True
            elif key == "--directory":
                flags.add("d")
            elif key in _DEST_LONG_VALUE:
                value = inline if has_value else (args[index + 1] if index + 1 < len(args) else "")
                if not has_value:
                    index += 1
                if key == "--target-directory":
                    target_dir = value
        else:
            letters = arg[1:]
            for position, letter in enumerate(letters):
                if letter in value_letters:
                    rest = letters[position + 1:]
                    if not rest:
                        rest = args[index + 1] if index + 1 < len(args) else ""
                        index += 1
                    if letter == "t":
                        target_dir = rest
                    break
                flags.add(letter)
            if "T" in flags:
                no_target_dir = True
        index += 1
    return operands, target_dir, no_target_dir, flags


def names_directory(operand: str) -> bool:
    """True when an operand can only name a directory: a trailing '/', or '.' / '..' as its last component."""
    return operand.endswith("/") or posixpath.basename(operand) in {".", ".."}


def _destination_files(name: str, args: list[str]) -> list[tuple[str, str, bool]]:
    """(destination, how it was derived, assumed) for a copy, move, install or link command. A destination
    operand may be a directory; the path inside it is offered too, marked assumed unless the operand can only
    name a directory (see names_directory)."""
    operands, target_dir, no_target_dir, flags = _destination_spec(name, args)
    if name == "install" and "d" in flags:
        return []                                   # install -d creates directories only
    out: list[tuple[str, str, bool]] = []
    if target_dir:
        for source in operands:
            leaf = posixpath.basename(source.rstrip("/"))
            if leaf:
                out.append((posixpath.join(target_dir, leaf), "target-directory operand plus the source name",
                            False))
        return out
    if name == "ln" and len(operands) == 1:
        leaf = posixpath.basename(operands[0].rstrip("/"))
        return [(leaf, "link created in the working directory", False)] if leaf else []
    if len(operands) < 2:
        return []
    destination, sources = operands[-1], operands[:-1]
    is_dir = names_directory(destination)
    if not is_dir:
        out.append((destination, "destination operand", False))
    if not no_target_dir:
        for source in sources:
            leaf = posixpath.basename(source.rstrip("/"))
            if leaf:
                out.append((posixpath.join(destination, leaf),
                            "destination directory operand plus the source name" if is_dir else
                            "destination operand read as a directory, plus the source name", not is_dir))
    return out


_ATTR_FLAG_LETTERS = set("RcfvhHLP")


def _attribute_files(args: list[str]) -> list[str]:
    """Files chmod, chown or chgrp is given; the first operand is the mode or owner unless --reference is used.
    A chmod mode such as `-x` is an operand, not a flag."""
    reference = any(arg.startswith("--reference") for arg in args)
    operands: list[str] = []
    ended = False
    for arg in args:
        if ended:
            operands.append(arg)
        elif arg == "--":
            ended = True
        elif arg.startswith("--") or (len(arg) > 1 and arg[0] == "-" and set(arg[1:]) <= _ATTR_FLAG_LETTERS):
            continue                                # an option (a mode such as `-x` is not all flag letters)
        else:
            operands.append(arg)
    return operands if reference else operands[1:]


_CURL_VALUE_LETTERS = set("oHduxXAebcTFwKrmEYyzCUQtPD")
_WGET_VALUE_LETTERS = set("OoaPUeitTwQlARDIXB")


def _output_file(args: list[str], letter: str, long_names: set[str], value_letters: set[str],
                 keep_stdout: bool = False) -> list[str]:
    """The value of a downloader's output-file option (`-o F`, `-oF`, grouped `-so F`, `--output=F`); `-` (stdout)
    is dropped unless keep_stdout."""
    out: list[str] = []
    index = 0
    while index < len(args):
        arg = args[index]
        key, has_value, inline = arg.partition("=")
        if key in long_names:
            if has_value:
                out.append(inline)
            elif index + 1 < len(args):
                out.append(args[index + 1])
                index += 1
        elif arg.startswith("-") and not arg.startswith("--") and len(arg) > 1:
            letters = arg[1:]
            for position, item in enumerate(letters):
                if item in value_letters:
                    rest = letters[position + 1:]
                    if not rest and index + 1 < len(args):
                        rest = args[index + 1]
                        index += 1
                    if item == letter and rest:
                        out.append(rest)
                    break
        index += 1
    return [item for item in out if keep_stdout or item != "-"]


_URL = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")


def _url_operands(args: list[str], value_letters: set[str]) -> list[str]:
    """URL operands of a downloader, skipping the values of its short value options."""
    out: list[str] = []
    index = 0
    while index < len(args):
        arg = args[index]
        if arg.startswith("-") and not arg.startswith("--") and len(arg) > 1:
            letters = arg[1:]
            for position, letter in enumerate(letters):
                if letter in value_letters:
                    if position == len(letters) - 1:
                        index += 1                  # the value is the next argument
                    break
        elif _URL.match(arg):
            out.append(arg)
        index += 1
    return out


def _url_leaf(url: str) -> str:
    try:
        return posixpath.basename(urlsplit(url).path)
    except ValueError:
        return ""


def _expand_long(args: list[str], full: str, shortest: int) -> list[str]:
    """Rewrite abbreviations of one long option (at least `shortest` characters) to its full name."""
    out = []
    for arg in args:
        key = arg.split("=", 1)[0]
        out.append(full + arg[len(key):] if len(key) >= shortest and full.startswith(key) else arg)
    return out


def _curl_remote_name(args: list[str]) -> tuple[bool, bool, str | None]:
    """(remote-name download requested, file name taken from the server's header, --output-dir value)."""
    remote = header_name = False
    out_dir: str | None = None
    index = 0
    while index < len(args):
        arg = args[index]
        key, has_value, inline = arg.partition("=")
        if key in {"--remote-name", "--remote-name-all"}:
            remote = True
        elif key == "--remote-header-name":
            header_name = True
        elif key == "--output-dir":
            out_dir = inline if has_value else (args[index + 1] if index + 1 < len(args) else None)
            index += 0 if has_value else 1
        elif arg.startswith("-") and not arg.startswith("--") and len(arg) > 1:
            letters = arg[1:]
            for position, letter in enumerate(letters):
                if letter == "O":
                    remote = True
                elif letter == "J":
                    header_name = True
                elif letter in _CURL_VALUE_LETTERS:
                    if position == len(letters) - 1:
                        index += 1
                    break
        index += 1
    return remote, header_name, out_dir


def write_targets(name: str, args: list[str], cwd: str | None = None,
                  argv0: str = "") -> tuple[list[WriteTarget], bool]:
    """Files a write-capable command line names as the file it changes, and whether a named file could not be
    placed (a relative operand with no usable working directory). Positive-only: a program can change files in
    ways argv does not show, so an empty result proves nothing. Device and process pseudo-files are ignored."""
    raw: list[tuple[str, str]] = []
    assumed: set[int] = set()
    if is_editor(name):
        # the editor as the record shows it (argv[0]): the canonical name ('vi' for vim) only groups
        shown = basename(argv0) or name
        raw = [(item, f"the editor '{shown}' was started on it") for item in _editor_files(name, args, argv0)]
    elif name == "sed":
        raw = [(item, "'sed' was run with in-place editing on it") for item in _sed_in_place(args)]
    elif name == "perl":
        raw = [(item, "'perl' was run with in-place editing on it") for item in _perl_in_place(args)]
    elif name in {"tee", "sponge"}:
        raw = [(item, f"'{name}' was given it as an output file")
               for item in operands_after_options(args, set()) if item != "-"]
    elif name in {"cp", "mv", "install", "ln"}:
        verb = {"cp": "copy", "mv": "move", "install": "install", "ln": "link"}[name]
        for item, how, guess in _destination_files(name, args):
            if guess:
                assumed.add(len(raw))
            raw.append((item, f"a '{name}' {verb} named it ({how})"))
    elif name in {"chmod", "chown", "chgrp"}:
        raw = [(item, f"'{name}' was run to change its permissions or owner") for item in _attribute_files(args)]
    elif name == "truncate":
        raw = [(item, "'truncate' was run on it")
               for item in operands_after_options(args, {"-s", "--size", "-r", "--reference"})]
    elif name == "dd":
        raw = [(arg[3:], "'dd' was given it as the output file (of=)") for arg in args if arg.startswith("of=")]
    elif name == "curl":
        raw = [(item, "'curl' was given it as the output file")
               for item in _output_file(args, "o", {"--output"}, _CURL_VALUE_LETTERS)]
        remote, header_name, out_dir = _curl_remote_name(args)
        if remote:
            # -O saves each URL under its own file name, in --output-dir or the working directory
            for url in _url_operands(args, _CURL_VALUE_LETTERS):
                leaf = _url_leaf(url)
                if leaf:
                    if header_name:
                        assumed.add(len(raw))
                    raw.append((posixpath.join(out_dir, leaf) if out_dir else leaf,
                                "'curl -O' was run to save a download under the URL's file name"))
    elif name == "wget":
        expanded = _expand_long(args, "--output-document", len("--output-d"))
        expanded = _expand_long(expanded, "--directory-prefix", len("--directory-"))
        documents = _output_file(expanded, "O", {"--output-document"}, _WGET_VALUE_LETTERS, keep_stdout=True)
        raw = [(item, "'wget' was given it as the output document") for item in documents if item != "-"]
        if not documents:
            # without -O wget saves each URL under its file name in --directory-prefix or the working directory
            # (as NAME.1 when NAME already exists); recursive or host-directory layouts are not modelled
            prefixes = _output_file(expanded, "P", {"--directory-prefix"}, _WGET_VALUE_LETTERS)
            layout = any(arg in {"-r", "--recursive", "-x", "--force-directories", "-m", "--mirror"}
                         for arg in expanded)
            for url in _url_operands(expanded, _WGET_VALUE_LETTERS):
                leaf = _url_leaf(url) or "index.html"
                if layout:
                    assumed.add(len(raw))
                raw.append((posixpath.join(prefixes[-1], leaf) if prefixes else leaf,
                            "'wget' was run to save a download under the URL's file name"))
    elif name in {"scp", "rsync"}:
        operands = client_operands(name, args)
        if len(operands) >= 2 and remote_endpoint(operands[-1]) is None:
            destination = operands[-1]
            is_dir = names_directory(destination)
            if not is_dir:
                raw.append((destination, f"'{name}' was given it as the local destination"))
            for source in operands[:-1]:
                leaf = posixpath.basename(source.split(":", 1)[-1].rstrip("/"))
                if leaf:
                    if not is_dir:
                        assumed.add(len(raw))
                    raw.append((posixpath.join(destination, leaf),
                                f"'{name}' local destination directory plus the source name" if is_dir else
                                f"'{name}' local destination read as a directory, plus the source name"))
    targets: list[WriteTarget] = []
    unresolved = False
    for position, (item, form) in enumerate(raw):
        if not item:
            continue
        path = normalize_path(item, cwd)
        if not path:
            unresolved = True
            continue
        if is_under(path, ("/dev", "/proc", "/sys")):
            continue
        targets.append(WriteTarget(path, form, position in assumed))
    return list(dict.fromkeys(targets)), unresolved


# ------------------------------------------------------------------------------------------------
# GNU getopt_long, for tools whose options decide what a command line asks for.
# ------------------------------------------------------------------------------------------------

class Getopt(NamedTuple):
    options: list[tuple[str, str | None]]   # (short letter, or long name without an alias; value or None)
    operands: list[str]
    uncertain: bool                          # an unknown option was met: the operand split may be wrong


def getopt_long(args: list[str], short_values: str, short_flags: str,
                long_options: dict[str, tuple[str, bool]]) -> Getopt:
    """Parse argv the way GNU getopt_long does. Short options group (`-aG sudo` is `-a` then `-G sudo`); a
    value-taking short option takes the rest of its group or the next argument (`-u0`, `-u 0`); a long option
    takes `--name=value` or the next argument and may be any unambiguous prefix (`--gro`); operands may sit
    between options; `--` ends options. `long_options` maps a long name to (key, takes_value): the key is the short
    letter it aliases, or the long name itself. An option the grammar does not know is kept (value None) and marks
    the parse uncertain, because it may have taken the next argument as its value."""
    options: list[tuple[str, str | None]] = []
    operands: list[str] = []
    uncertain = False
    names = tuple(long_options)
    index, ended = 0, False
    while index < len(args):
        arg = args[index]
        if ended or arg == "-" or not arg.startswith("-"):
            operands.append(arg)
        elif arg == "--":
            ended = True
        elif arg.startswith("--"):
            raw, has_value, inline = arg.partition("=")
            name = gnu_long(raw, names)
            if name is None:
                options.append((raw, inline if has_value else None))
                uncertain = True
            else:
                key, takes_value = long_options[name]
                value = None
                if takes_value:
                    if has_value:
                        value = inline
                    elif index + 1 < len(args):
                        index += 1
                        value = args[index]
                options.append((key, value))
        else:
            letters = arg[1:]
            for position, letter in enumerate(letters):
                if letter in short_values:
                    value = letters[position + 1:]
                    if not value and index + 1 < len(args):
                        index += 1
                        value = args[index]
                    options.append((letter, value or None))
                    break
                options.append((letter, None))
                if letter not in short_flags:
                    uncertain = True
        index += 1
    return Getopt(options, operands, uncertain)


# ------------------------------------------------------------------------------------------------
# Shell command text: simple commands with their assignment prefixes and redirects.
# ------------------------------------------------------------------------------------------------

class Segment(NamedTuple):
    assignments: list[str]       # NAME=VALUE words before the command name
    argv: list[str]
    redirects: list[tuple[str, str]]


_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def shell_segments(name: str, args: list[str]) -> tuple[list[Segment], bool]:
    """Simple commands of a shell started with -c, and whether the text was only partly modelled. Read with the
    shell parser's own lexer, so quoting is honoured; unlike the parser, assignment prefixes (`HISTFILE=/dev/null`)
    are kept as assignments, because they are what this module looks for. Nothing a construct the lexer does not
    model (expansions, substitutions, here-documents) would run is read."""
    if name not in SHELLS:
        return [], False
    script = shell_script_of([name, *args])
    if isinstance(script, UnknownShellScript):
        return [], True
    if not script:
        return [], False
    incomplete = False
    try:
        tokens = _shell_tokens(script)
    except _ShellUnmodelled as error:
        tokens, incomplete = error.tokens, True
    segments: list[Segment] = []
    current = Segment([], [], [])
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token.kind in {"operator", "pipe"}:
            if current.argv or current.assignments or current.redirects:
                segments.append(current)
            current = Segment([], [], [])
        elif token.kind == "redirect":
            if index + 1 < len(tokens) and tokens[index + 1].kind == "word":
                current.redirects.append((token.value, tokens[index + 1].value))
                index += 1
            else:
                incomplete = True
        elif not current.argv and _ASSIGNMENT.match(token.value):
            current.assignments.append(token.value)
        else:
            current.argv.append(token.value)
        index += 1
    if current.argv or current.assignments or current.redirects:
        segments.append(current)
    return segments, incomplete
