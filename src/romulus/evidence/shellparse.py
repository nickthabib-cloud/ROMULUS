"""Token-aware parsing of shell command strings into pipelines, commands and redirections.

Used to decide what a `sh -c '<script>'` actually executes. A word that merely appears inside a
quoted argument (e.g. `grep "curl | sh" notes.txt`) is data, not a command.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

_RESERVED = {"if", "then", "elif", "else", "fi", "for", "while", "case", "esac", "do", "done", "!",
             "function"}
_DYNAMIC_COMMANDS = {"eval", "exec", "command", "env", "builtin"}
_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")
_ASCII_BLANK = {" ", "\t"}


@dataclass(frozen=True)
class _Token:
    kind: str
    value: str


class _Unmodelled(ValueError):
    def __init__(self, message: str, tokens: list[_Token] | None = None):
        super().__init__(message)
        self.tokens = list(tokens or [])


def _lex(script: str) -> list[_Token]:
    """Lex the deliberately small shell subset in one quote/comment-aware pass."""
    tokens: list[_Token] = []
    word: list[str] = []
    word_started = False
    word_plain = True
    quote: str | None = None
    comment = False
    index = 0

    def flush_word() -> None:
        nonlocal word, word_started, word_plain
        if word_started:
            tokens.append(_Token("word", "".join(word)))
        word = []
        word_started = False
        word_plain = True

    def emit(kind: str, value: str) -> None:
        flush_word()
        tokens.append(_Token(kind, value))

    def fail(message: str) -> None:
        last_complete_line = max(
            (i for i, token in enumerate(tokens) if token.kind == "operator" and token.value == "\n"),
            default=-1,
        )
        raise _Unmodelled(message, tokens[:last_complete_line + 1])

    while index < len(script):
        char = script[index]

        if comment:
            if char == "\n":
                comment = False
                emit("operator", "\n")
            index += 1
            continue

        if quote == "'":
            if char == "'":
                quote = None
            else:
                word.append(char)
            index += 1
            continue

        if quote == '"':
            if char == '"':
                quote = None
                index += 1
                continue
            if char == "$":
                fail("dollar expansion in double quotes is not modelled")
            if char == "`":
                fail("backtick substitution is not modelled")
            if char == "\\":
                if index + 1 >= len(script):
                    fail("dangling double-quote escape")
                escaped = script[index + 1]
                if escaped == "\n":
                    fail("backslash-newline line continuation is not modelled")
                if escaped not in {'"', "\\", "$"}:
                    fail("double-quote escape is not modelled")
                word.append(escaped)
                index += 2
                continue
            word.append(char)
            index += 1
            continue

        # Unquoted state. A comment begins only when no word is in progress; this exactly captures
        # start-of-script and positions after unescaped ASCII blanks, newlines, or operators.
        if char == "#" and not word_started:
            comment = True
            index += 1
            continue
        if char in _ASCII_BLANK:
            flush_word()
            index += 1
            continue
        if char == "\n":
            emit("operator", "\n")
            index += 1
            continue
        if char.isspace():
            fail("non-modelled whitespace outside quotes")
        if char in {"'", '"'}:
            quote = char
            word_started = True
            word_plain = False
            index += 1
            continue
        if char == "\\":
            if index + 1 >= len(script):
                fail("dangling backslash escape")
            escaped = script[index + 1]
            if escaped == "\n":
                fail("backslash-newline line continuation is not modelled")
            if escaped.isspace() and escaped not in _ASCII_BLANK:
                fail("non-modelled whitespace outside quotes")
            word.append(escaped)
            word_started = True
            word_plain = False
            index += 2
            continue
        if char == "$":
            reason = ("ANSI-C quoting is not modelled" if script.startswith("$'", index)
                      else "command substitution is not modelled" if script.startswith("$(", index)
                      else "dollar expansion is not modelled")
            fail(reason)
        if char == "`":
            fail("backtick command substitution is not modelled")
        if char in "()":
            fail("parenthesis syntax is not modelled")
        if char in "{}":
            fail("brace syntax is not modelled")
        if char in "*?[":
            fail("pathname expansion is not modelled")

        if char in "<>":
            if index + 1 < len(script) and script[index + 1] == "(":
                fail("process substitution is not modelled")
            if script.startswith("<<<", index):
                fail("here-string syntax is not modelled")
            if script.startswith("<<", index):
                fail("heredoc syntax is not modelled")

            # Operator core, longest match first: duplications (">&"/"<&"), clobber (">|") and
            # read-write ("<>") are two characters; plain redirects are one. The following word (if
            # any) is the target, read by the parser: an fd digit, "-" (close) or a path.
            two = script[index:index + 2]
            if char == ">":
                core = two if two in (">>", ">|", ">&") else ">"
            else:
                core = two if two in ("<>", "<&") else "<"

            # An unquoted digit run written directly against the operator is the file descriptor it
            # redirects (e.g. "2>&1", "0<&1"), not a separate word.
            if word_started and word_plain and "".join(word).isdigit():
                tokens.append(_Token("redirect", "".join(word) + core))
                word = []
                word_started = False
                word_plain = True
            else:
                emit("redirect", core)
            index += len(core)
            continue

        if char == "&":
            # bash: `&>WORD` / `&>>WORD` send both stdout and stderr to WORD. A descriptor digit
            # cannot prefix these, so an immediately preceding word stays a word (flushed by emit).
            if script.startswith("&>>", index):
                emit("redirect", "&>>")
                index += 3
                continue
            if script.startswith("&>", index):
                emit("redirect", "&>")
                index += 2
                continue
            if script.startswith("&&", index):
                emit("operator", "&&")
                index += 2
            else:
                emit("operator", "&")
                index += 1
            continue
        if char == "|":
            if script.startswith("|&", index):
                fail("operator form is not modelled")
            if script.startswith("||", index):
                emit("operator", "||")
                index += 2
            else:
                emit("pipe", "|")
                index += 1
            continue
        if char == ";":
            emit("operator", ";")
            index += 1
            continue

        word.append(char)
        word_started = True
        index += 1

    if quote is not None:
        fail("unterminated shell quote")
    flush_word()
    return tokens


@dataclass
class Command:
    argv: list[str]
    redirects: list[tuple[str, str]] = field(default_factory=list)   # (op, target)

    @property
    def name(self) -> str:
        return self.argv[0].rsplit("/", 1)[-1] if self.argv else ""


@dataclass
class Pipeline:
    commands: list[Command]


@dataclass
class ParsedScript:
    pipelines: list[Pipeline]
    ok: bool = True
    error: str = ""
    partial: bool = False

    def commands(self) -> list[Command]:
        return [c for p in self.pipelines for c in p.commands]


def _check_redirect(op: str, target: str, dialect: str) -> None:
    """Reject a redirect whose meaning is not sound to model: an unknown operator, a descriptor-prefixed
    ``N>&WORD`` (N other than 1) or ``<&WORD`` with a non-digit WORD (a bash error or ambiguity), and,
    for a POSIX shell, the bash-only "both streams" forms."""
    redirect = classify_redirect(op, target)
    if redirect.action == "unknown":
        raise _Unmodelled(f"redirect operator {op!r} is not modelled")
    bash_word = op.endswith(("&", "&>", "&>>")) and target != "-" and not target.isdigit()
    if bash_word and op.endswith("<&"):
        raise _Unmodelled("input duplication from a non-descriptor word is not modelled")
    if bash_word and op.endswith(">&") and op[:-2] not in ("", "1"):
        raise _Unmodelled("descriptor-prefixed duplication onto a file word is not modelled")
    if dialect != "bash" and (op in ("&>", "&>>") or (bash_word and op.endswith(">&"))):
        raise _Unmodelled("bash-only redirect form is not modelled for a POSIX sh")


def parse_script(script: str, dialect: str = "bash") -> ParsedScript:
    """Parse only the explicit safe shell subset; every other construct is unevaluable.

    ``dialect`` is ``"bash"`` or ``"posix"`` (dash and other plain ``sh``). The bash-only redirect
    forms ``&>WORD``, ``&>>WORD`` and ``>&WORD`` (non-digit WORD) mean something else, or are a
    syntax error, in a POSIX shell, so under ``"posix"`` they are unevaluable rather than guessed.
    """
    lex_error = ""
    try:
        tokens = _lex(script)
    except _Unmodelled as e:
        tokens = e.tokens
        lex_error = str(e)

    pipelines: list[Pipeline] = []
    current = Pipeline(commands=[])
    cmd = Command(argv=[])
    requires_command = False

    def close_cmd() -> None:
        nonlocal cmd
        if cmd.argv or cmd.redirects:
            current.commands.append(cmd)
        cmd = Command(argv=[])

    def close_pipeline() -> None:
        nonlocal current
        close_cmd()
        if current.commands:
            pipelines.append(current)
        current = Pipeline(commands=[])

    try:
        index = 0
        while index < len(tokens):
            token = tokens[index]
            if token.kind == "redirect":
                if index + 1 >= len(tokens) or tokens[index + 1].kind != "word":
                    raise _Unmodelled("redirect target is missing or unmodelled")
                _check_redirect(token.value, tokens[index + 1].value, dialect)
                cmd.redirects.append((token.value, tokens[index + 1].value))
                requires_command = False
                index += 2
                continue
            if token.kind == "word":
                if not cmd.argv:
                    name = token.value.rsplit("/", 1)[-1]
                    if token.value in _RESERVED:
                        raise _Unmodelled(f"reserved word {token.value!r} is not modelled")
                    if _ASSIGNMENT.match(token.value):
                        raise _Unmodelled("assignment prefix is not modelled")
                    if name in _DYNAMIC_COMMANDS:
                        raise _Unmodelled(f"command is not modelled: {name}")
                cmd.argv.append(token.value)
                requires_command = False
                index += 1
                continue
            if token.kind == "pipe":
                if not (cmd.argv or cmd.redirects):
                    raise _Unmodelled("pipeline command is missing")
                close_cmd()
                requires_command = True
                index += 1
                continue

            # Control operators delimit pipelines. Blank/comment-only lines are harmless, while
            # && and || require a command on both sides.
            if token.value in {"&&", "||"}:
                if not (cmd.argv or cmd.redirects or current.commands):
                    raise _Unmodelled("conditional operator is missing a command")
                close_pipeline()
                requires_command = True
            elif token.value == "\n":
                if requires_command:
                    raise _Unmodelled("line continuation after an operator is not modelled")
                close_pipeline()
            else:  # ; or &
                if not (cmd.argv or cmd.redirects or current.commands):
                    raise _Unmodelled("control operator is missing a command")
                close_pipeline()
            index += 1

        if requires_command:
            raise _Unmodelled("trailing operator is missing a command")
        close_pipeline()
    except _Unmodelled as e:
        return ParsedScript(pipelines=[], ok=False, error=str(e), partial=False)

    if lex_error:
        return ParsedScript(pipelines=pipelines, ok=False, error=lex_error, partial=bool(pipelines))
    return ParsedScript(pipelines=pipelines)


# ------------------------------------------------------------------------------------------------
# Typed redirection model
#
# `Command.redirects` stays a list of raw ``(op, target)`` tuples, so existing consumers keep
# unpacking them unchanged. `classify_redirect` turns one such tuple into typed semantics without
# reading the rest of the script, so a consumer can ask "which file does this write?" or "is a
# descriptor duplicated?" instead of testing operator substrings. It never infers that the
# redirection actually ran — that is a claim only process- or file-level evidence can make.
# ------------------------------------------------------------------------------------------------

_PLAIN_REDIRECT_ACTIONS = {">": "write", ">>": "append", ">|": "clobber", "<": "read", "<>": "readwrite"}


@dataclass(frozen=True)
class Redirect:
    """The POSIX/bash meaning of one parsed ``(op, target)`` redirection.

    - ``fd``: the descriptor the redirection affects, with its default resolved (1 for output
      operators, 0 for input). ``-1`` marks a token this model does not recognise.
    - ``action``: ``write`` (``>``), ``append`` (``>>``), ``clobber`` (``>|``), ``read`` (``<``),
      ``readwrite`` (``<>``), ``dup`` (``N>&M`` / ``N<&M``), or ``close`` (``N>&-``).
    - ``target``: a path, the source-descriptor digits of a duplication, or ``""`` for a close.
    - ``target_is_fd``: the target names a descriptor (a duplication), not a path.
    - ``affects_stderr``: the bash shorthands ``>&WORD`` / ``&>WORD`` / ``&>>WORD`` that also send
      fd 2 to the same target.
    """

    fd: int
    action: str
    target: str
    target_is_fd: bool
    affects_stderr: bool

    @property
    def writes_file(self) -> str | None:
        """The path this redirection opens for writing (stdout/stderr → file), else None."""
        if self.target_is_fd or not self.target:
            return None
        return self.target if self.action in ("write", "append", "clobber", "readwrite") else None

    @property
    def reads_file(self) -> str | None:
        """The path this redirection opens for reading (stdin ← file), else None."""
        if self.target_is_fd or not self.target:
            return None
        return self.target if self.action in ("read", "readwrite") else None


def classify_redirect(op: str, target: str) -> Redirect:
    """Resolve one parsed redirection token and its target word into typed semantics."""
    # bash "both streams" shorthands: &>WORD / &>>WORD send stdout and stderr to WORD.
    if op in ("&>", "&>>"):
        return Redirect(fd=1, action="append" if op == "&>>" else "write", target=target,
                        target_is_fd=False, affects_stderr=True)
    prefix = ""
    rest = op
    while rest and rest[0].isdigit():
        prefix += rest[0]
        rest = rest[1:]
    if rest in ("<&", ">&"):
        reading = rest == "<&"
        fd = int(prefix) if prefix else (0 if reading else 1)
        if target == "-":                                   # N>&- / N<&- : close the descriptor
            return Redirect(fd=fd, action="close", target="", target_is_fd=False, affects_stderr=False)
        if target.isdigit():                                # N>&M / N<&M : duplicate descriptor M
            return Redirect(fd=fd, action="dup", target=target, target_is_fd=True, affects_stderr=False)
        # A non-digit word. ">&FILE" without an explicit descriptor sends both stdout and stderr to
        # the file; a descriptor-prefixed ">&FILE" sends only that descriptor. "<&FILE" is a bash
        # error, so it is read (the safe, non-overclaiming interpretation), never a write.
        if reading:
            return Redirect(fd=fd, action="read", target=target, target_is_fd=False, affects_stderr=False)
        return Redirect(fd=fd, action="write", target=target, target_is_fd=False,
                        affects_stderr=prefix == "")
    action = _PLAIN_REDIRECT_ACTIONS.get(rest)
    if action is None:                                      # an unmodelled token: recognise nothing
        return Redirect(fd=-1, action="unknown", target=target, target_is_fd=False, affects_stderr=False)
    fd = int(prefix) if prefix else (0 if action in ("read", "readwrite") else 1)
    return Redirect(fd=fd, action=action, target=target, target_is_fd=False, affects_stderr=False)


NETWORK_PSEUDO_PATHS = ("/dev/tcp/", "/dev/udp/")


def network_redirects(parsed: ParsedScript) -> tuple[list[str], list[str]]:
    """``(outbound, inbound)`` network pseudo-paths among the script's redirections: the ``/dev/tcp``
    or ``/dev/udp`` targets written to (stdout/stderr) or read from (stdin). A sound reading of the
    parsed redirects; it never claims the redirection ran. Targets keep first-seen order."""
    outbound: list[str] = []
    inbound: list[str] = []
    for command in parsed.commands():
        for op, target in command.redirects:
            redirect = classify_redirect(op, target)
            written = redirect.writes_file
            if written and written.startswith(NETWORK_PSEUDO_PATHS):
                outbound.append(written)
            read = redirect.reads_file
            if read and read.startswith(NETWORK_PSEUDO_PATHS):
                inbound.append(read)
    return outbound, inbound


POSIX_SHELLS = {"sh", "bash", "dash", "ash", "busybox"}
NON_POSIX_SHELLS = {"zsh", "ksh", "fish", "csh", "tcsh"}
SHELLS = POSIX_SHELLS | NON_POSIX_SHELLS
# Kernel executables that implement a plain POSIX sh (no bash redirect extensions).
_POSIX_SH_EXES = {"dash", "sh"}


def shell_dialect(executable: object, argv: object = None) -> str:
    """``"posix"`` when the kernel-recorded executable (else argv[0]) is dash or plain sh, else
    ``"bash"``. The dialect decides how bash-only redirect forms are read."""
    name = str(executable).rsplit("/", 1)[-1] if executable else ""
    if not name and isinstance(argv, list) and argv:
        name = str(argv[0]).rsplit("/", 1)[-1].removeprefix("-")
    return "posix" if name in _POSIX_SH_EXES else "bash"


@dataclass(frozen=True)
class UnknownShellScript:
    """A shell-like command used ``-c``, but its script position is not safely modelled."""

    reason: str


@dataclass(frozen=True)
class _ShellArgLayout:
    script_file: str | None = None
    has_command_option: bool = False
    reads_stdin: bool = False
    error: str = ""


_SHELL_OPTIONS_WITH_VALUES = {"-o", "+o", "-O", "+O", "--init-file", "--rcfile"}


def _scan_shell_args(args: list[str]) -> _ShellArgLayout:
    """Locate a shell script file while respecting the option values we model."""
    index = 0
    reads_stdin = False
    while index < len(args):
        arg = args[index]
        if arg == "--":
            if reads_stdin:
                return _ShellArgLayout(reads_stdin=True)
            return _ShellArgLayout(script_file=args[index + 1] if index + 1 < len(args) else None)
        if arg in _SHELL_OPTIONS_WITH_VALUES:
            if index + 1 >= len(args):
                return _ShellArgLayout(error=f"shell option {arg!r} is missing its value")
            index += 2
            continue
        if arg == "-c" or (arg.startswith("-") and not arg.startswith("--") and "c" in arg[1:]):
            return _ShellArgLayout(has_command_option=True)
        if arg == "-s" or (arg.startswith("-") and not arg.startswith("--") and "s" in arg[1:]):
            reads_stdin = True
            index += 1
            continue
        if arg.startswith(("-", "+")):
            index += 1
            continue
        if reads_stdin:
            return _ShellArgLayout(reads_stdin=True)
        return _ShellArgLayout(script_file=arg)
    return _ShellArgLayout(reads_stdin=reads_stdin)


def _shell_argv(argv: list[str], shell_name: str | None = None) -> tuple[str, list[str]] | None:
    if not argv:
        return None
    name = shell_name or argv[0].rsplit("/", 1)[-1]
    if name.startswith("-"):
        name = name[1:]
    if name not in SHELLS:
        return None
    args = argv[1:]
    if name == "busybox":
        if not args or args[0] not in SHELLS:
            return None
        name, args = args[0], args[1:]
    return name, args


def _has_c_option(args: list[str]) -> bool:
    return _scan_shell_args(args).has_command_option


def shell_script_file_of(argv: list[str], *, shell_name: str | None = None) -> str | UnknownShellScript | None:
    """Return the shell script-file operand, an explicit unknown, or no script file."""
    shell_argv = _shell_argv(argv, shell_name)
    if shell_argv is None:
        return None
    name, args = shell_argv
    layout = _scan_shell_args(args)
    if layout.error:
        return UnknownShellScript(layout.error)
    if name in NON_POSIX_SHELLS and any(arg.startswith(("-", "+")) for arg in args):
        return UnknownShellScript(f"the {name} shell option grammar is not modelled")
    if layout.has_command_option or layout.reads_stdin:
        return None
    return layout.script_file


def shell_script_of(argv: list[str]) -> str | UnknownShellScript | None:
    """Return a certainly located direct-shell script, explicit unknown, or definite no-script.

    Only the exact direct forms ``shell -c SCRIPT`` and ``shell -lc SCRIPT`` are modelled. Shell
    option parsing is otherwise deliberately not emulated: if a command still appears to request
    ``-c``, callers receive an explicit unknown and must not publish a complete negative claim.
    """
    shell_argv = _shell_argv(argv)
    if shell_argv is None:
        return None
    name, args = shell_argv
    direct_name = argv[0].rsplit("/", 1)[-1]
    if direct_name.startswith("-"):
        direct_name = direct_name[1:]
    if name in NON_POSIX_SHELLS:
        if _has_c_option(args):
            return UnknownShellScript(f"the {name} shell grammar is not modelled")
        return None

    if direct_name != "busybox" and len(args) >= 2 and args[0] in {"-c", "-lc"}:
        script = args[1]
        if script and not script.startswith(("-", "+")):
            return script
        return UnknownShellScript("the shell -c script position is missing or option-like")

    layout = _scan_shell_args(args)
    if layout.error:
        return UnknownShellScript(layout.error)
    if layout.has_command_option:
        return UnknownShellScript("the shell -c option layout is not modelled")
    return None
