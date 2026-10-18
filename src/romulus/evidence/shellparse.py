"""Token-aware parsing of shell command strings into pipelines, commands and redirections.

Used to decide what a `sh -c '<script>'` actually executes. A word that merely appears inside a
quoted argument (e.g. `grep "curl | sh" notes.txt`) is data, not a command.
"""
from __future__ import annotations

import shlex
from dataclasses import dataclass, field

_OPERATORS = {"|", "||", "&&", ";", "&", "|&"}
_REDIRECTS = {">", ">>", "<", "2>", "2>>", "&>", ">|", "1>", "1>>"}
_PUNCTUATION = "|&;<>"


def _quote_aware_input(script: str) -> tuple[str, dict[int, str]]:
    """Protect quoted punctuation and expose unquoted newlines as command separators."""
    protected: dict[int, str] = {}
    used = set(script)
    next_codepoint = 0xE000
    for char in _PUNCTUATION:
        while chr(next_codepoint) in used:
            next_codepoint += 1
        protected[next_codepoint] = char
        next_codepoint += 1
    sentinels = {char: chr(codepoint) for codepoint, char in protected.items()}

    out: list[str] = []
    quote: str | None = None
    index = 0
    while index < len(script):
        char = script[index]
        if char == "\\" and quote != "'" and index + 1 < len(script):
            out.extend((char, script[index + 1]))
            index += 2
            continue
        if char in {"'", '"'}:
            if quote is None:
                quote = char
            elif quote == char:
                quote = None
            out.append(char)
        elif quote is not None and char in sentinels:
            out.append(sentinels[char])
        elif quote is None and char == "\n":
            out.append(" ; ")
        else:
            out.append(char)
        index += 1
    return "".join(out), protected


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
    """Parse a POSIX-ish shell script. Unparseable input returns ok=False (callers must treat the
    claim as unknown, never as a match)."""
    try:
        prepared, protected = _quote_aware_input(script)
        lex = shlex.shlex(prepared, posix=True, punctuation_chars=_PUNCTUATION)
        lex.whitespace_split = True
        lex.commenters = ""
        tokens = list(lex)
    except ValueError as e:
        return ParsedScript(pipelines=[], ok=False, error=str(e))

    pipelines: list[Pipeline] = []
    current = Pipeline(commands=[])
    cmd = Command(argv=[])
    pending_redirect: str | None = None

    def literal(token: str) -> str:
        return token.translate(protected)

    def close_cmd():
        nonlocal cmd
        if cmd.argv or cmd.redirects:
            current.commands.append(cmd)
        cmd = Command(argv=[])

    for i, tok in enumerate(tokens):
        if pending_redirect:
            cmd.redirects.append((pending_redirect, literal(tok)))
            pending_redirect = None
            continue
        # shlex splits "2>" into "2", ">" — rejoin fd-prefixed redirects
        if tok in (">", ">>") and cmd.argv and cmd.argv[-1] in ("1", "2") and i > 0:
            pending_redirect = cmd.argv.pop() + tok
            continue
        if tok in _REDIRECTS or tok in (">&", "<&"):
            pending_redirect = tok
            continue
        if tok in ("|", "|&"):
            close_cmd()
            continue
        if tok in _OPERATORS:
            close_cmd()
            if current.commands:
                pipelines.append(current)
            current = Pipeline(commands=[])
            continue
        cmd.argv.append(literal(tok))
    if pending_redirect:
        return ParsedScript(pipelines=[], ok=False, error="dangling redirect")
    close_cmd()
    if current.commands:
        pipelines.append(current)
    return ParsedScript(pipelines=pipelines)


SHELLS = {"sh", "bash", "dash", "zsh", "ksh", "ash", "busybox"}


def shell_script_of(argv: list[str]) -> str | None:
    """If argv is `<shell> [-opts] -c <script> ...`, return the script string."""
    if not argv:
        return None
    name = argv[0].rsplit("/", 1)[-1]
    if name not in SHELLS:
        return None
    for i, a in enumerate(argv[1:], start=1):
        if a == "-c" or (a.startswith("-") and not a.startswith("--") and "c" in a[1:]):
            return argv[i + 1] if i + 1 < len(argv) else None
        if not a.startswith("-"):
            return None
    return None
