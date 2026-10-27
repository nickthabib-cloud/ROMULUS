"""Windows command lines read as tokens, never as substrings.

Three grammars meet on a Windows command line, and each is applied only where it governs:

- The process's own arguments follow the documented ``CommandLineToArgvW`` rules (the Microsoft C runtime's rules
  since 2008): spaces and tabs separate arguments outside double quotes; ``2n`` backslashes before a quote give
  ``n`` backslashes and toggle quoting, ``2n+1`` give ``n`` backslashes and a literal quote; other backslashes are
  literal; ``""`` inside a quoted span is a literal quote. The program name (the first argument) ends at its closing
  quote or at the first space and takes no escapes.
- ``cmd.exe /c`` (or ``/k``, ``/r``) hands the rest of its command line to cmd's own parser: carets escape the next
  character outside quotes and are removed, ``&``, ``&&``, ``||`` and ``|`` separate commands outside quotes, and
  ``>``, ``>>``, ``<`` (optionally with a handle number) redirect. A builtin such as ``copy`` never becomes a process
  of its own, so a rule that must see it reads cmd's payload.
- The PowerShell host matches its switches by prefix, case-insensitively, after ``-``, ``/`` or a Unicode dash (en
  dash, em dash, horizontal bar), in the host's order with each switch's smallest accepted prefix, so ``-e``,
  ``-en``, ``-enc`` and ``-EncodedCommand`` are one switch and ``-ex`` is another (``-ExecutionPolicy``). Script
  text is read with a small lexer that separates comments and string literals from code words, so a cmdlet name
  inside a quoted string or a comment is a mention, not a call.

Every value derived here is labelled parsed (``PARSED``): it is an interpretation of text the process was given,
never proof of what executed.
"""
from __future__ import annotations

import base64
import binascii
import ntpath
import re
from dataclasses import dataclass, field

PARSED = "#parsed:windows-cmdline"
PARSED_DECODED = "#parsed:powershell-encodedcommand-utf16le"

_SPACE = " \t"
# PowerShell treats these as dashes wherever a dash may start a switch or parameter.
DASHES = "-–—―"
SWITCH_STARTS = DASHES + "/"
# A decoded -EncodedCommand longer than this is read only up to it (the claim says so); real launchers stay far below.
MAX_DECODED_CHARS = 1 << 20


def split_argv(line: str) -> list[str]:
    """Split a recorded process command line into arguments as ``CommandLineToArgvW`` does."""
    args: list[str] = []
    n = len(line)
    i = 0
    while i < n and line[i] in _SPACE:
        i += 1
    if i >= n:
        return args
    if line[i] == '"':
        end = line.find('"', i + 1)
        if end < 0:
            args.append(line[i + 1:])
            return args
        args.append(line[i + 1:end])
        i = end + 1
    else:
        start = i
        while i < n and line[i] not in _SPACE:
            i += 1
        args.append(line[start:i])
    args.extend(_split_rest(line, i))
    return args


def _split_rest(line: str, i: int) -> list[str]:
    args: list[str] = []
    n = len(line)
    while True:
        while i < n and line[i] in _SPACE:
            i += 1
        if i >= n:
            return args
        current: list[str] = []
        quoted = False
        while i < n:
            char = line[i]
            if char in _SPACE and not quoted:
                break
            if char == "\\":
                j = i
                while j < n and line[j] == "\\":
                    j += 1
                count = j - i
                if j < n and line[j] == '"':
                    current.append("\\" * (count // 2))
                    if count % 2:
                        current.append('"')
                        i = j + 1
                    else:
                        i = j
                else:
                    current.append("\\" * count)
                    i = j
                continue
            if char == '"':
                if quoted and i + 1 < n and line[i + 1] == '"':
                    current.append('"')
                    i += 2
                    continue
                quoted = not quoted
                i += 1
                continue
            current.append(char)
            i += 1
        args.append("".join(current))


def split_words(text: str) -> list[str]:
    """Arguments of a command that is not a program name first (a cmd payload's command, a tool's sub-command)."""
    return _split_rest(text, 0)


def is_switch(token: str) -> bool:
    return len(token) > 1 and token[0] in SWITCH_STARTS


def switch_name(token: str) -> str:
    """The casefolded name of a ``/x``, ``-x`` or Unicode-dash switch, without a ``:value`` or ``=value`` suffix."""
    body = token[1:]
    if body[:1] in DASHES:                      # --name
        body = body[1:]
    for separator in (":", "="):
        body = body.split(separator, 1)[0]
    return body.casefold()


def switch_value(token: str) -> str | None:
    """The value of ``/name:value`` or ``-name=value`` (None when the switch carries none inline)."""
    body = token[1:]
    positions = [p for p in (body.find(":"), body.find("=")) if p >= 0]
    return body[min(positions) + 1:] if positions else None


def has_switch(args: list[str], *names: str) -> bool:
    wanted = {name.casefold() for name in names}
    return any(is_switch(arg) and switch_name(arg) in wanted for arg in args)


def operands(args: list[str]) -> list[str]:
    """The arguments that are not switches."""
    return [arg for arg in args if arg and not is_switch(arg)]


# ---- cmd.exe payloads ----------------------------------------------------------------------------------------------

@dataclass
class CmdCommand:
    """One command of a cmd.exe payload: its words (carets removed) and its redirections as (operator, target)."""
    argv: list[str]
    redirects: list[tuple[str, str]] = field(default_factory=list)


def cmd_run(line: str) -> tuple[frozenset[str], str] | None:
    """(the set of switch letters cmd.exe was given, the text it runs) for a ``/c``, ``/k`` or ``/r`` invocation
    (switches may be grouped, ``/q/c``), or None when it is not such an invocation. Switch letters are casefolded
    and a ``/t:``-style value switch contributes its bare letter."""
    n = len(line)
    i = 0
    flags: set[str] = set()
    while i < n and line[i] in _SPACE:
        i += 1
    if i < n and line[i] == '"':
        end = line.find('"', i + 1)
        if end < 0:
            return None
        i = end + 1
    else:
        while i < n and line[i] not in _SPACE and line[i] != "/":
            i += 1
    while i < n:
        while i < n and line[i] in _SPACE:
            i += 1
        if i >= n or line[i] != "/":
            return None
        start = i
        i += 1
        while i < n and line[i] not in _SPACE and line[i] != '"' and line[i] != "/":
            i += 1
        name = line[start + 1:i].casefold()
        if name in {"c", "k", "r"}:
            flags.add(name)
            return frozenset(flags), line[i:].lstrip(_SPACE)
        if name.startswith(("t:", "e:", "f:", "v:")) or name in {"q", "d", "a", "u", "s", "x", "y", "e", "f", "v"}:
            flags.add(name[0])
            continue
        return None
    return None


def cmd_payload(line: str) -> str | None:
    """The text cmd.exe runs for ``/c``, ``/k`` or ``/r`` (switches may be grouped, ``/q/c``), or None."""
    run = cmd_run(line)
    return None if run is None else run[1]


def _strip_outer_quotes(payload: str) -> str:
    """cmd.exe's rule for a payload that starts with a quote: the first quote and the last quote are removed."""
    text = payload.strip()
    if text[:1] == '"':
        last = text.rfind('"')
        return text[1:last] + text[last + 1:] if last > 0 else text[1:]
    return text


def parse_cmd_payload(payload: str) -> list[CmdCommand]:
    """Split a cmd payload into commands, removing caret escapes outside quotes and taking out redirections."""
    text = _strip_outer_quotes(payload)
    commands: list[CmdCommand] = []
    current: list[str] = []
    redirects: list[tuple[str, str]] = []
    quoted = False
    i, n = 0, len(text)

    def flush() -> None:
        words = split_words("".join(current))
        if words and words[0].startswith("@"):
            words[0] = words[0][1:]
            if not words[0]:
                words = words[1:]
        if words or redirects:
            commands.append(CmdCommand(words, list(redirects)))
        current.clear()
        redirects.clear()

    while i < n:
        char = text[i]
        if char == '"':
            quoted = not quoted
            current.append(char)
            i += 1
            continue
        if quoted:
            current.append(char)
            i += 1
            continue
        if char == "^":
            if i + 1 < n:
                current.append(text[i + 1])
            i += 2
            continue
        if char in "&|":
            flush()
            i += 2 if i + 1 < n and text[i + 1] == char else 1
            continue
        handle = char.isdigit() and i + 1 < n and text[i + 1] in "<>"
        if char in "<>" or handle:
            op_start = i
            if handle:
                i += 1
            i += 1
            if i < n and text[i] == ">" and text[i - 1] == ">":
                i += 1
            operator = text[op_start:i]
            if i < n and text[i] == "&":           # 2>&1: a handle, not a file
                j = i + 1
                while j < n and text[j].isdigit():
                    j += 1
                redirects.append((operator + "&", text[i + 1:j]))
                i = j
                continue
            while i < n and text[i] in _SPACE:
                i += 1
            target, i = _redirect_target(text, i)
            redirects.append((operator, target))
            continue
        current.append(char)
        i += 1
    flush()
    return commands


_EXTENSION_URL = re.compile(r"^chrome-extension://[a-p]{32}/?$", re.IGNORECASE)
_PARENT_WINDOW = re.compile(r"^--parent-window=\d+$", re.IGNORECASE)
_NM_PIPE = "\\\\.\\pipe\\chrome.nativemessaging"


def is_chromium_native_messaging(command: str) -> bool:
    """True only for the exact Chromium native-messaging host launch, read from parsed tokens:

    ``cmd.exe /d /s /c "<host>.exe chrome-extension://<32 a-p>/ [--parent-window=<n>]" [< \\\\.\\pipe\\chrome.
    nativeMessaging.*] [> \\\\.\\pipe\\chrome.nativeMessaging.*]`` — one command, no command separators, argv[0] the
    host, argv[1] exactly the extension URL, any extra argument only ``--parent-window=<n>``, and any redirect only
    to a ``chrome.nativeMessaging`` pipe. Anything else is not recognised (so it is never silently dropped)."""
    run = cmd_run(command)
    if run is None:
        return False
    flags, payload = run
    if not {"d", "s", "c"} <= flags:
        return False
    commands = parse_cmd_payload(payload)
    if len(commands) != 1:              # any & && | || separator disqualifies it
        return False
    argv = commands[0].argv
    if len(argv) < 2 or not _EXTENSION_URL.match(argv[1].strip().strip('"')):
        return False
    if any(not _PARENT_WINDOW.match(extra.strip().strip('"')) for extra in argv[2:]):
        return False
    for _operator, target in commands[0].redirects:
        normalized = target.strip().strip('"').replace("/", "\\").casefold()
        if not normalized.startswith(_NM_PIPE):
            return False
    return True


def _redirect_target(text: str, i: int) -> tuple[str, int]:
    n = len(text)
    out: list[str] = []
    quoted = False
    while i < n:
        char = text[i]
        if char == '"':
            quoted = not quoted
            i += 1
            continue
        if not quoted and (char in _SPACE or char in "&|<>"):
            break
        if not quoted and char == "^" and i + 1 < n:
            out.append(text[i + 1])
            i += 2
            continue
        out.append(char)
        i += 1
    return "".join(out), i


# ---- PowerShell host switches ---------------------------------------------------------------------------------------

@dataclass(frozen=True)
class _PsSwitch:
    name: str
    smallest: str
    aliases: tuple[str, ...] = ()
    takes: str = "flag"                 # flag | value | rest


# The host's switches in the order it tests them, each with the shortest prefix it accepts (and its fixed aliases).
_PS_SWITCHES = (
    _PsSwitch("help", "h", ("?",)),
    _PsSwitch("login", "l"),
    _PsSwitch("noexit", "noe"),
    _PsSwitch("noprofile", "nop"),
    _PsSwitch("nologo", "nol"),
    _PsSwitch("noninteractive", "noni"),
    _PsSwitch("interactive", "i"),
    _PsSwitch("sta", "sta"),
    _PsSwitch("mta", "mta"),
    _PsSwitch("configurationname", "config", (), "value"),
    _PsSwitch("command", "c", (), "rest"),
    _PsSwitch("windowstyle", "w", (), "value"),
    _PsSwitch("file", "f", (), "rest"),
    _PsSwitch("executionpolicy", "ex", ("ep",), "value"),
    _PsSwitch("encodedcommand", "e", ("ec",), "value"),
    _PsSwitch("encodedarguments", "encodeda", ("ea",), "value"),
    _PsSwitch("settingsfile", "settings", (), "value"),
    _PsSwitch("version", "v", (), "value"),
    _PsSwitch("workingdirectory", "wo", ("wd",), "value"),
    _PsSwitch("inputformat", "inp", ("if",), "value"),
    _PsSwitch("outputformat", "o", ("of",), "value"),
    _PsSwitch("psconsolefile", "psc", (), "value"),
)


def resolve_ps_switch(token: str) -> str | None:
    """The canonical PowerShell host switch a token names (``-enc`` -> ``encodedcommand``), or None when the token is
    not a switch or names none unambiguously."""
    if not is_switch(token):
        return None
    key = switch_name(token)
    if not key:
        return None
    for switch in _PS_SWITCHES:
        if key in switch.aliases:
            return switch.name
        if switch.name.startswith(key) and len(key) >= len(switch.smallest):
            return switch.name
    return None


@dataclass
class PowerShellCall:
    """What a PowerShell host's arguments ask for: resolved switches, and the script text with where it came from."""
    switches: dict[str, str | bool] = field(default_factory=dict)
    script: str | None = None
    source: str = ""                     # command | encodedcommand | positional | file | ""
    decode_error: str = ""
    truncated: bool = False
    unresolved: list[str] = field(default_factory=list)


def parse_powershell(args: list[str]) -> PowerShellCall:
    """Read a PowerShell host's arguments (the program name excluded)."""
    call = PowerShellCall()
    i = 0
    while i < len(args):
        token = args[i]
        name = resolve_ps_switch(token)
        if name is None:
            if is_switch(token) and token[0] != "/":
                call.unresolved.append(token)
                i += 1
                continue
            # the first token that is not a switch starts the command (Windows PowerShell's positional -Command)
            call.script, call.source = " ".join(args[i:]), "positional"
            return call
        spec = next(s for s in _PS_SWITCHES if s.name == name)
        inline = switch_value(token) if ":" in token[1:] else None
        if spec.takes == "flag":
            call.switches[name] = True
            i += 1
        elif spec.takes == "value":
            if inline is not None:
                value, i = inline, i + 1
            else:
                value, i = (args[i + 1] if i + 1 < len(args) else ""), i + 2
            call.switches[name] = value
            if name == "encodedcommand":
                call.script, call.source = _decode(value, call), "encodedcommand"
        else:
            rest = args[i + 1:]
            call.switches[name] = " ".join(rest)
            if name == "command":
                call.script, call.source = " ".join(rest), "command"
            else:
                call.source = "file"
            return call
    return call


def _decode(value: str, call: PowerShellCall) -> str | None:
    text = value.strip().strip('"').strip("'")
    if len(text) > MAX_DECODED_CHARS * 2:
        text = text[:MAX_DECODED_CHARS * 2 - (MAX_DECODED_CHARS * 2) % 4]
        call.truncated = True
    try:
        raw = base64.b64decode(text + "=" * (-len(text) % 4), validate=True)
    except (binascii.Error, ValueError) as exc:
        call.decode_error = f"not Base64 ({exc})"
        return None
    if len(raw) % 2:
        raw = raw[:-1]
    decoded = raw.decode("utf-16-le", errors="replace")
    if "�" in decoded:
        call.decode_error = "not UTF-16LE text"
        return None
    return decoded


# ---- PowerShell script tokens ---------------------------------------------------------------------------------------

@dataclass(frozen=True)
class PsToken:
    kind: str           # word | member | string | variable | parameter
    text: str           # casefolded; backtick escapes removed from words


_SINGLE_QUOTES = "'‘’‚‛"
_DOUBLE_QUOTES = '"“”„'
_WORD = re.compile(r"[A-Za-z0-9_\-–—―.\\/:?*`%#]")


def ps_tokens(text: str) -> list[PsToken]:
    """Code words, member names, string literals, variables and parameters of PowerShell script text.

    Comments are dropped and string contents are returned as strings only, so a name that appears only inside a
    string or a comment never reads as a call. A ``#`` starts a line comment only at a token boundary: ``a#b`` is
    one token, not ``a`` plus a comment. Code built at run time (string concatenation, ``$()`` inside an expandable
    string, ``-f`` formatting) is not evaluated: such a call is not seen, which a positive-only rule states."""
    out: list[PsToken] = []
    i, n = 0, len(text)
    after_value = False                 # the previous token can take a member access (variable, ), ], string)
    prev_sep = True                     # at a token boundary (start of input, or after whitespace/a delimiter)
    while i < n:
        char = text[i]
        if char.isspace() or char in ";,|{}=+!&":
            after_value = False
            prev_sep = True
            i += 1
            continue
        if char == "<" and text.startswith("<#", i):
            end = text.find("#>", i + 2)
            i = n if end < 0 else end + 2
            prev_sep = True
            continue
        if char == "#" and prev_sep:
            end = text.find("\n", i)
            i = n if end < 0 else end + 1
            prev_sep = True
            continue
        if char == "@" and i + 1 < n and (text[i + 1] in _SINGLE_QUOTES or text[i + 1] in _DOUBLE_QUOTES):
            closing = text[i + 1] + "@"
            end = text.find(closing, i + 2)
            out.append(PsToken("string", text[i + 2:n if end < 0 else end].casefold()))
            i = n if end < 0 else end + 2
            after_value = True
            prev_sep = False
            continue
        if char in _SINGLE_QUOTES or char in _DOUBLE_QUOTES:
            value, i = _ps_string(text, i)
            out.append(PsToken("string", value.casefold()))
            after_value = True
            prev_sep = False
            continue
        if char == "$":
            j = i + 1
            if j < n and text[j] == "{":
                end = text.find("}", j)
                name = text[j + 1:n if end < 0 else end]
                i = n if end < 0 else end + 1
            else:
                while j < n and (text[j].isalnum() or text[j] in "_:?^$"):
                    j += 1
                name = text[i + 1:j]
                i = j
            out.append(PsToken("variable", name.casefold()))
            after_value = True
            prev_sep = False
            continue
        if char in ")]":
            after_value = True
            prev_sep = False
            i += 1
            continue
        if char in "([":
            after_value = False
            prev_sep = True
            i += 1
            continue
        if char == "." and after_value or (char == ":" and text.startswith("::", i)):
            i += 2 if char == ":" else 1
            if i < n and (text[i] in _SINGLE_QUOTES or text[i] in _DOUBLE_QUOTES):
                value, i = _ps_string(text, i)           # a quoted member name ($wc."DownloadString")
                out.append(PsToken("member", value.casefold()))
                after_value = True
                prev_sep = False
                continue
            j = i
            while j < n and (text[j].isalnum() or text[j] in "_`"):
                j += 1
            name = text[i:j].replace("`", "")
            if name:
                out.append(PsToken("member", name.casefold()))
            i = j
            after_value = True
            prev_sep = False
            continue
        if _WORD.match(char):
            j = i
            while j < n and _WORD.match(text[j]):
                if text[j] == "`" and j + 1 < n:
                    j += 2
                    continue
                j += 1
            word = text[i:j].replace("`", "")
            # a trailing member access on a bare word (`[Net.WebClient]` is a type, handled as one word)
            kind = "parameter" if word[:1] in DASHES and len(word) > 1 else "word"
            out.append(PsToken(kind, word.casefold()))
            i = j
            after_value = False
            prev_sep = False
            continue
        after_value = False
        prev_sep = False
        i += 1
    return out


def _ps_string(text: str, i: int) -> tuple[str, int]:
    quote_set = _SINGLE_QUOTES if text[i] in _SINGLE_QUOTES else _DOUBLE_QUOTES
    expandable = quote_set is _DOUBLE_QUOTES
    out: list[str] = []
    i += 1
    n = len(text)
    while i < n:
        char = text[i]
        if expandable and char == "`" and i + 1 < n:
            out.append(text[i + 1])
            i += 2
            continue
        if char in quote_set:
            if i + 1 < n and text[i + 1] in quote_set:
                out.append(char)
                i += 2
                continue
            return "".join(out), i + 1
        out.append(char)
        i += 1
    return "".join(out), n


def ps_parameter_matches(token: PsToken, name: str, smallest: str, aliases: tuple[str, ...] = ()) -> bool:
    """Whether a script parameter token names a cmdlet parameter by PowerShell's prefix rule (or one of its aliases):
    ``smallest`` is the shortest prefix that is unambiguous among that cmdlet's parameters."""
    if token.kind != "parameter":
        return False
    key = token.text[1:].split(":", 1)[0].lstrip(DASHES)
    return key in aliases or (len(key) >= len(smallest) and name.startswith(key))


_TRUE_WORDS = frozenset({"true", "$true", "1"})
_FALSE_WORDS = frozenset({"false", "$false", "0"})


def ps_bool(value: object) -> bool | None:
    """PowerShell truthiness of a switch argument token's text: True for $true/1/true, False for $false/0/false,
    None when it is neither (so the caller does not guess)."""
    text = str(value or "").strip().casefold().lstrip(":")
    if text in _TRUE_WORDS:
        return True
    if text in _FALSE_WORDS:
        return False
    return None


def ps_named_argument(tokens: list[PsToken], *names: tuple[str, ...]) -> str | None:
    """The argument value of the first matching named parameter (`-Path C:\\x`, `-Name:DisableAntiSpyware`), by
    PowerShell's prefix rule. Each ``names`` entry is ``(canonical, smallest_prefix, *aliases)``. Returns the value
    token's text (a word's text, a string's content, or a variable's name), or None when none matches."""
    for index, token in enumerate(tokens):
        if token.kind != "parameter":
            continue
        for spec in names:
            canon, smallest = spec[0], spec[1]
            aliases = tuple(spec[2:])
            if ps_parameter_matches(token, canon, smallest, aliases):
                inline = token.text.split(":", 1)
                if len(inline) == 2 and inline[1]:
                    return inline[1]
                nxt = tokens[index + 1] if index + 1 < len(tokens) else None
                if nxt is not None and nxt.kind in {"word", "string", "variable"}:
                    return nxt.text
                return None
    return None


def ps_switch_argument(tokens: list[PsToken], index: int) -> tuple[bool | None, bool]:
    """Read a PowerShell switch parameter's boolean argument at `tokens[index]`: (value, had_inline).

    A trailing ``:value`` on the parameter token, else the following token (a variable or word), decides it. A bare
    switch with no boolean argument is True (the switch is present). None means an argument was given that is not a
    boolean, so the caller treats the record as undecided rather than guessing."""
    token = tokens[index]
    inline = token.text.split(":", 1)
    if len(inline) == 2 and inline[1]:
        return ps_bool(inline[1]), True
    nxt = tokens[index + 1] if index + 1 < len(tokens) else None
    if nxt is None or nxt.kind == "parameter":
        return True, False                      # bare switch: present means "on"
    if nxt.kind in {"variable", "word"}:
        value = ps_bool(nxt.text if nxt.kind == "word" else f"${nxt.text}")
        return value, True
    return True, False


def rundll32_target(argv: list[str]) -> tuple[str, str] | None:
    """(dll basename without extension, entry point) for a `rundll32 <dll>,<entry> ...` or `rundll32 <dll> <entry>`
    invocation, both casefolded, or None. Handles the comma- or space-joined forms, a quoted or path-qualified DLL,
    a missing `.dll`, and an ordinal entry (`#24`, `#+24`, `#-4294967272`)."""
    rest = [token for token in argv[1:] if token and not is_switch(token)]
    if not rest:
        return None
    first = rest[0].strip().strip('"')
    if "," in first:
        dll, _sep, entry = first.partition(",")
        entry = entry.strip() or (rest[1].strip().strip('"') if len(rest) > 1 else "")
    else:
        dll = first
        entry = rest[1].strip().strip('"') if len(rest) > 1 else ""
    base = ntpath.basename(dll.replace("/", "\\")).casefold().removesuffix(".dll")
    return base, entry.casefold().lstrip(",").strip()


def is_ordinal(entry: str) -> bool:
    """Whether a rundll32 entry point is an ordinal reference (`#24`, `#+24`, `#-4294967272`)."""
    text = entry.strip()
    return bool(text) and text[0] == "#" and text[1:].lstrip("+-").isdigit()


@dataclass
class RegCommand:
    """A parsed ``reg.exe`` invocation: its verb, the key operand (casefolded, forward slashes normalized), and the
    ``/v`` value name, ``/d`` data and ``/t`` type when present."""
    verb: str
    key: str
    value_name: str | None = None
    data: str | None = None
    data_type: str | None = None
    import_file: str | None = None


def parse_reg(argv: list[str]) -> RegCommand | None:
    """Parse ``reg add|query|export|import|delete ...`` from argv (argv[0] is reg.exe). None when it is not reg."""
    if len(argv) < 2:
        return None
    verb = argv[1].strip().casefold()
    if verb not in {"add", "query", "export", "import", "delete", "copy", "save", "load", "unload", "restore"}:
        return None
    operands_list = []
    value_name = data = data_type = None
    i = 2
    while i < len(argv):
        token = argv[i]
        low = token.casefold()
        if low in {"/v", "-v"} and i + 1 < len(argv):
            value_name = argv[i + 1]
            i += 2
            continue
        if low in {"/d", "-d"} and i + 1 < len(argv):
            data = argv[i + 1]
            i += 2
            continue
        if low in {"/t", "-t"} and i + 1 < len(argv):
            data_type = argv[i + 1]
            i += 2
            continue
        if is_switch(token):
            i += 1
            continue
        operands_list.append(token)
        i += 1
    import_file = operands_list[-1] if verb in {"import", "restore", "load"} and operands_list else None
    key = operands_list[0].strip().strip('"').replace("/", "\\").casefold() if operands_list else ""
    return RegCommand(verb, key, value_name, data, data_type, import_file)


# ---- operands --------------------------------------------------------------------------------------------------------

_URL = re.compile(r"^(?:https?|ftps?)://[^\s/?#]+", re.IGNORECASE)


def url_in(token: str) -> str | None:
    """The URL a token is (or ends with after a ``name:``/``name=`` prefix such as ``/i:``), or None."""
    text = token.strip().strip('"').strip("'")
    if _URL.match(text):
        return text
    for separator in (":", "="):
        head, sep, tail = text.partition(separator)
        if sep and head and _URL.match(tail):
            return tail
    return None


# Path components where an ordinary user (or every user) can write: per-user profile data, temporary directories,
# ProgramData and the recycle bin. Unexpanded variables naming them count as the same places.
_USER_WRITABLE_PARTS = ("\\users\\", "\\appdata\\", "\\temp\\", "\\tmp\\", "\\programdata\\", "\\$recycle.bin\\",
                        "\\perflogs\\", "\\windows\\tasks\\", "\\windows\\tracing\\", "\\downloads\\")
_USER_WRITABLE_VARS = ("%temp%", "%tmp%", "%appdata%", "%localappdata%", "%userprofile%", "%public%",
                       "%programdata%", "%allusersprofile%", "$env:temp", "$env:tmp", "$env:appdata",
                       "$env:localappdata", "$env:userprofile", "$env:public", "$env:programdata")


def path_key(text: str) -> str:
    """Case-insensitive comparison form of a Windows path operand."""
    cleaned = text.strip().strip('"').strip("'").replace("/", "\\")
    return ntpath.normpath(cleaned).casefold() if cleaned else ""


def is_remote_path(text: str) -> bool:
    key = text.strip().strip('"').strip("'").replace("/", "\\")
    return key.startswith("\\\\") and not key.startswith(("\\\\?\\", "\\\\.\\"))


def is_user_writable(text: str) -> bool:
    """Whether a path operand points under a user-writable location (never for a remote path)."""
    raw = text.strip().strip('"').strip("'").casefold()
    if any(raw.startswith(var) for var in _USER_WRITABLE_VARS):
        return True
    key = "\\" + path_key(text).lstrip("\\")
    return not is_remote_path(text) and any(part in key + "\\" for part in _USER_WRITABLE_PARTS)
