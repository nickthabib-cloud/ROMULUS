"""Token-aware parsing of shell command strings into pipelines, commands and redirections.

Used to decide what a `sh -c '<script>'` actually executes. A word that merely appears inside a
quoted argument (e.g. `grep "curl | sh" notes.txt`) is data, not a command.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

_RESERVED = {"if", "then", "fi", "for", "while", "case", "do", "done", "!", "function"}
_DYNAMIC_COMMANDS = {"eval", "exec", "command", "env", "builtin"}
_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")
_ASCII_BLANK = {" ", "\t"}


@dataclass(frozen=True)
class _Token:
    kind: str
    value: str


class _Unmodelled(ValueError):
    pass


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
                raise _Unmodelled("dollar expansion in double quotes is not modelled")
            if char == "`":
                raise _Unmodelled("backtick substitution is not modelled")
            if char == "\\":
                if index + 1 >= len(script):
                    raise _Unmodelled("dangling double-quote escape")
                escaped = script[index + 1]
                if escaped == "\n":
                    raise _Unmodelled("backslash-newline line continuation is not modelled")
                if escaped not in {'"', "\\", "$"}:
                    raise _Unmodelled("double-quote escape is not modelled")
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
            raise _Unmodelled("non-modelled whitespace outside quotes")
        if char in {"'", '"'}:
            quote = char
            word_started = True
            word_plain = False
            index += 1
            continue
        if char == "\\":
            if index + 1 >= len(script):
                raise _Unmodelled("dangling backslash escape")
            escaped = script[index + 1]
            if escaped == "\n":
                raise _Unmodelled("backslash-newline line continuation is not modelled")
            if escaped.isspace() and escaped not in _ASCII_BLANK:
                raise _Unmodelled("non-modelled whitespace outside quotes")
            word.append(escaped)
            word_started = True
            word_plain = False
            index += 2
            continue
        if char == "$":
            reason = ("ANSI-C quoting is not modelled" if script.startswith("$'", index)
                      else "command substitution is not modelled" if script.startswith("$(", index)
                      else "dollar expansion is not modelled")
            raise _Unmodelled(reason)
        if char == "`":
            raise _Unmodelled("backtick command substitution is not modelled")
        if char in "()":
            raise _Unmodelled("parenthesis syntax is not modelled")
        if char in "{}":
            raise _Unmodelled("brace syntax is not modelled")
        if char in "*?[":
            raise _Unmodelled("pathname expansion is not modelled")

        if char in "<>":
            if index + 1 < len(script) and script[index + 1] == "(":
                raise _Unmodelled("process substitution is not modelled")
            if script.startswith("<<<", index):
                raise _Unmodelled("here-string syntax is not modelled")
            if script.startswith("<<", index):
                raise _Unmodelled("heredoc syntax is not modelled")
            if script.startswith((">&", "<&", ">|"), index):
                raise _Unmodelled("redirect form is not modelled")

            size = 2 if char == ">" and script.startswith(">>", index) else 1
            op = script[index:index + size]
            if char == ">" and word_started and word_plain and "".join(word).isdigit():
                descriptor = "".join(word)
                if descriptor != "2":
                    raise _Unmodelled("file-descriptor redirect is not modelled")
                word = []
                word_started = False
                word_plain = True
                tokens.append(_Token("redirect", descriptor + op))
            else:
                emit("redirect", op)
            index += size
            continue

        if char == "&":
            if index + 1 < len(script) and script[index + 1] == ">":
                raise _Unmodelled("redirect form is not modelled")
            if script.startswith("&&", index):
                emit("operator", "&&")
                index += 2
            else:
                emit("operator", "&")
                index += 1
            continue
        if char == "|":
            if script.startswith("|&", index):
                raise _Unmodelled("operator form is not modelled")
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
        raise _Unmodelled("unterminated shell quote")
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

    def commands(self) -> list[Command]:
        return [c for p in self.pipelines for c in p.commands]


def parse_script(script: str) -> ParsedScript:
    """Parse only the explicit safe shell subset; every other construct is unevaluable."""
    try:
        tokens = _lex(script)
    except _Unmodelled as e:
        return ParsedScript(pipelines=[], ok=False, error=str(e))

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
        return ParsedScript(pipelines=[], ok=False, error=str(e))

    return ParsedScript(pipelines=pipelines)


POSIX_SHELLS = {"sh", "bash", "dash", "ash", "busybox"}
NON_POSIX_SHELLS = {"zsh", "ksh", "fish", "csh", "tcsh"}
SHELLS = POSIX_SHELLS | NON_POSIX_SHELLS


@dataclass(frozen=True)
class UnknownShellScript:
    """A shell-like command used ``-c``, but its script position is not safely modelled."""

    reason: str


def _has_c_option(args: list[str]) -> bool:
    option_takes_value = False
    for arg in args:
        if option_takes_value:
            option_takes_value = False
            continue
        if arg == "--" or not arg.startswith(("-", "+")):
            return False
        if arg in {"-o", "+o", "-O", "+O", "--init-file", "--rcfile"}:
            option_takes_value = True
            continue
        if arg == "-c" or (arg.startswith("-") and not arg.startswith("--") and "c" in arg[1:]):
            return True
    return False


def shell_script_of(argv: list[str]) -> str | UnknownShellScript | None:
    """Return a certainly located direct-shell script, explicit unknown, or definite no-script.

    Only the exact direct forms ``shell -c SCRIPT`` and ``shell -lc SCRIPT`` are modelled. Shell
    option parsing is otherwise deliberately not emulated: if a command still appears to request
    ``-c``, callers receive an explicit unknown and must not publish a complete negative claim.
    """
    if not argv:
        return None
    name = argv[0].rsplit("/", 1)[-1]
    if name.startswith("-"):
        name = name[1:]
    if name not in SHELLS:
        return None

    args = argv[1:]
    if name in NON_POSIX_SHELLS:
        if _has_c_option(args):
            return UnknownShellScript(f"the {name} shell grammar is not modelled")
        return None

    if name != "busybox" and len(args) >= 2 and args[0] in {"-c", "-lc"}:
        script = args[1]
        if script and not script.startswith(("-", "+")):
            return script
        return UnknownShellScript("the shell -c script position is missing or option-like")

    scan_args = args[1:] if name == "busybox" and args and args[0] in SHELLS else args
    if _has_c_option(scan_args):
        return UnknownShellScript("the shell -c option layout is not modelled")
    return None
