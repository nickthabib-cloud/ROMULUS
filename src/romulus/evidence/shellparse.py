"""Token-aware parsing of shell command strings into pipelines, commands and redirections.

Used to decide what a `sh -c '<script>'` actually executes. A word that merely appears inside a
quoted argument (e.g. `grep "curl | sh" notes.txt`) is data, not a command.
"""
from __future__ import annotations

import shlex
from dataclasses import dataclass, field

_OPERATORS = {"|", "||", "&&", ";", "&", "|&"}
_REDIRECTS = {">", ">>", "<", "2>", "2>>", "&>", ">|", "1>", "1>>"}


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
        lex = shlex.shlex(script, posix=True, punctuation_chars="|&;<>")
        lex.whitespace_split = True
        lex.commenters = ""
        tokens = list(lex)
    except ValueError as e:
        return ParsedScript(pipelines=[], ok=False, error=str(e))

    pipelines: list[Pipeline] = []
    current = Pipeline(commands=[])
    cmd = Command(argv=[])
    pending_redirect: str | None = None

    def close_cmd():
        nonlocal cmd
        if cmd.argv or cmd.redirects:
            current.commands.append(cmd)
        cmd = Command(argv=[])

    for i, tok in enumerate(tokens):
        if pending_redirect:
            cmd.redirects.append((pending_redirect, tok))
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
        cmd.argv.append(tok)
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
