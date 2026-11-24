"""Packet content made safe to show a reader or a model: recognised credentials masked, every line made visible.

Packet content rebuilt from a session (a response body's first bytes, the turns of a TCP conversation) is untrusted
telemetry. What is shown of it is bounded and passes through `detect.packets.show` after the credentials this module
recognises are masked:

- a header whose name is a credential name (Authorization, Cookie, X-Api-Key and the like);
- `name=value`, `name: value` and `"name": value` pairs whose name is a credential name, also when the pair is
  URL-encoded, and XML elements whose name is one (`<password>…</password>`);
- the arguments of a line protocol's credential command (FTP and POP3 `PASS`, SMTP and POP3 `AUTH`, IMAP's tagged
  `LOGIN` and `AUTHENTICATE`), and the argument lines that follow a Redis `AUTH` sent in RESP framing;
- URL userinfo, and the text of configured secrets;
- in a conversation, whatever one side sends after the other asks for a password, a passphrase, a PIN or a token, or
  for the next step of an authentication exchange (SMTP 334, IMAP and POP `+` continuations), until that side ends a
  line.

A stored packet raw copy keeps the body's first bytes as hex (`body_excerpt_hex`, part of the record its event id is
built from); `raw_view` is what a reader is shown of such a copy instead: the masked lines, never the hex.
"""
from __future__ import annotations

import re
from urllib.parse import unquote_plus

from romulus.config import Settings, redact_text
from romulus.detect.packets import PASSWORD_PROMPT, _clean, _text, show
from romulus.detect.web_attacks import _credential_name
from romulus.evidence.zeek_credentials import strip_uri_userinfo

MAX_PREVIEW_LINES = 24              # of one response body's excerpt
MAX_TURN_LINES = 12                 # of one conversation turn
MAX_LINE_CHARS = 200
MAX_TRANSCRIPT_TURNS = 60
MAX_TURN_BYTES = 4_096
WITHHELD = "[withheld]"
WITHHELD_TURN = "text sent after a password prompt or an authentication challenge"
EXCERPT_KEY = "body_excerpt_hex"
EXCERPT_NOTE = ("the response body's first bytes, as masked text lines; the stored copy keeps the bytes, and its size "
                "and SHA-256 cover the whole body")

_SECRET_HEADERS = frozenset({"authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key",
                             "x-auth-token", "api-key", "apikey", "x-access-token", "x-csrf-token", "x-xsrf-token"})
_HEADER = re.compile(r"^(\s*)([A-Za-z0-9_-]{1,64})(\s*:\s*)(.*)$")
# a line protocol's credential command and its arguments (a prompt such as "Password:" or "Last login:" is no command)
_COMMAND = re.compile(r"(?i)^(\s*)(PASS|PASSWORD|AUTH)\s+(\S.*)$")
_TAGGED = re.compile(r"(?i)^(\s*\S{1,32}\s+)(LOGIN|AUTHENTICATE)\s+(\S.*)$")
_PAIR = re.compile(r"""(["']?)([A-Za-z0-9_.\-]{1,64})\1(\s*[=:]\s*)("[^"]*"?|'[^']*'?|[^\s&;,"'<]+)""")
_ELEMENT = re.compile(r"<([A-Za-z_][\w.:-]{0,63})(\s[^<>]*)?>([^<]*)</\1\s*>")
# RESP framing: an array header (*n) and a bulk-string length line ($n)
_RESP_ARRAY = re.compile(r"^\*\d{1,9}$")
_RESP_LENGTH = re.compile(r"^\$\d{1,9}$")
# a prompt that asks for a secret, anywhere in a line that ends in ":" or "?" ("Password:", "[sudo] password for bob: ",
# "Enter passphrase for key '...': ", "Password for bob@REALM: ", "Enter PEM pass phrase:")
_SECRET_PROMPT = re.compile(
    r"(?i)\b(?:pass(?:word|wd|phrase|code)?|pass phrase|pin|secret|token|otp)\b.{0,200}?[:?]\s*$")
_CONTINUATION = re.compile(r"^(?:334|\+)(?:\s|$)")
# what of a turn's end is read for a prompt (a prompt is the tail of the turn's last line)
PROMPT_TAIL_BYTES = 512
_LINE_SPLIT = re.compile(rb"\r\n|\r\x00|\n|\r")


def _element_name(name: str) -> str:
    return name.rsplit(":", 1)[-1]


class Masker:
    """Masks recognised credentials in preview text, with the state a conversation needs."""

    def __init__(self, settings: Settings | None):
        self.settings = settings
        self.secret_owed: str | None = None          # the side whose next text is a secret
        self.resp_auth = False                       # inside the arguments of a RESP AUTH command

    def _mask(self, text: str) -> str:
        header = _HEADER.match(text)
        if header and (header.group(2).casefold() in _SECRET_HEADERS or _credential_name(header.group(2))):
            text = f"{header.group(1)}{header.group(2)}{header.group(3)}{WITHHELD}"
        command = _COMMAND.match(text) or _TAGGED.match(text)
        if command:
            text = f"{command.group(1)}{command.group(2)} {WITHHELD}"
        text = _ELEMENT.sub(lambda m: (f"<{m.group(1)}{m.group(2) or ''}>{WITHHELD}</{m.group(1)}>"
                                       if _credential_name(_element_name(m.group(1))) else m.group(0)), text)
        text = _PAIR.sub(lambda m: (f"{m.group(1)}{m.group(2)}{m.group(1)}{m.group(3)}{WITHHELD}"
                                    if _credential_name(m.group(2)) else m.group(0)), text)
        if "://" in text:
            text = strip_uri_userinfo(text)[0]
        return text

    def line(self, text: str) -> str:
        """One line with its credentials masked. A line whose URL-decoded form holds a credential the raw spelling
        hides is shown decoded and masked."""
        masked = self._mask(text)
        if "%" in text:
            decoded = unquote_plus(text)
            if decoded != text:
                decoded_masked = self._mask(decoded)
                if decoded_masked.count(WITHHELD) > masked.count(WITHHELD):
                    masked = decoded_masked
        if self.settings is not None:
            masked = redact_text(masked, self.settings)
        return masked

    def lines(self, items: list[str]) -> list[str]:
        """Lines in order, masked one by one; the argument lines of a RESP AUTH command are withheld."""
        out = []
        previous = ""
        for item in items:
            bare = item.strip()
            if _RESP_ARRAY.match(bare):
                self.resp_auth = False
                out.append(self.line(item))
            elif _RESP_LENGTH.match(bare):
                out.append(item)
            elif self.resp_auth:
                out.append(WITHHELD)
            else:
                if bare.upper() == "AUTH" and _RESP_LENGTH.match(previous.strip()):
                    self.resp_auth = True
                out.append(self.line(item))
            previous = item
        return out

    def turn(self, side: str, raw: bytes, whole: bytes | None = None) -> dict:
        """One side's bytes in a conversation turn, as preview lines (or a count of binary bytes). `raw` is what is
        shown of the turn; `whole` (default `raw`) is the whole turn, whose end is read for a prompt and a line end."""
        whole = raw if whole is None else whole
        if self.secret_owed == side:
            if _LINE_SPLIT.search(whole):
                self.secret_owed = None
            return {"from": side, "withheld": WITHHELD_TURN, "bytes": len(whole)}
        # the prompt is read on the turn's real end, whatever of it is shown
        tail = [_clean(piece) for piece in _LINE_SPLIT.split(whole[-PROMPT_TAIL_BYTES:])]
        last = next((item for item in reversed(tail) if item), "")
        if last and (PASSWORD_PROMPT.search(last) or _SECRET_PROMPT.search(last) or _CONTINUATION.match(last)):
            self.secret_owed = "client" if side == "server" else "server"
        cleaned = [_clean(piece) for piece in _LINE_SPLIT.split(raw)]
        if any(item is None for item in cleaned):
            return {"from": side, "binary_bytes": len(whole)}
        lines = [item for item in cleaned if item]
        shown = [show(item, MAX_LINE_CHARS) for item in self.lines(lines[:MAX_TURN_LINES])]
        out = {"from": side, "lines": shown}
        if len(lines) > MAX_TURN_LINES:
            out["lines_not_shown"] = len(lines) - MAX_TURN_LINES
        return out


def body_excerpt(head: bytes, settings: Settings | None) -> dict:
    """A response body's first bytes as masked preview lines, or a note that they are binary."""
    if not head:
        return {"excerpt": [], "excerpt_note": "empty body"}
    text = _text(head)
    if text is None:
        return {"excerpt": None, "excerpt_note": "binary content (not shown)"}
    lines = text.splitlines()
    out = {"excerpt": [show(line, MAX_LINE_CHARS) for line in Masker(settings).lines(lines[:MAX_PREVIEW_LINES])]}
    if len(lines) > MAX_PREVIEW_LINES:
        out["excerpt_lines_not_shown"] = len(lines) - MAX_PREVIEW_LINES
    return out


def raw_view(source, settings: Settings | None = None):
    """What a reader is shown of a stored raw copy: a packet response's copy with its hex body excerpt replaced by the
    masked lines (`body_excerpt`); any other copy as it is."""
    if not isinstance(source, dict) or EXCERPT_KEY not in source:
        return source
    shown = {key: value for key, value in source.items() if key != EXCERPT_KEY}
    hexed = source.get(EXCERPT_KEY)
    try:
        excerpt = body_excerpt(bytes.fromhex(hexed), settings) if isinstance(hexed, str) else None
    except ValueError:
        excerpt = None
    shown["body_excerpt"] = (excerpt or {}).get("excerpt")
    shown["body_excerpt_note"] = (excerpt or {}).get("excerpt_note") or (
        EXCERPT_NOTE if excerpt else "the stored excerpt could not be read")
    return shown


def transcript(data: dict[str, bytes], chunks, settings: Settings | None) -> tuple[list[dict], int]:
    """The conversation's first turns (consecutive bytes of one side are one turn), each bounded and masked; and how
    many turns were not shown."""
    turns: list[tuple[str, int, int]] = []
    for chunk in chunks:
        if turns and turns[-1][0] == chunk.direction and turns[-1][2] == chunk.offset:
            direction, start, _end = turns[-1]
            turns[-1] = (direction, start, chunk.offset + chunk.length)
        else:
            turns.append((chunk.direction, chunk.offset, chunk.offset + chunk.length))
    masker = Masker(settings)
    out = []
    for direction, start, end in turns[:MAX_TRANSCRIPT_TURNS]:
        side = "client" if direction == "c2s" else "server"
        raw = data[direction][start:min(end, start + MAX_TURN_BYTES)]
        item = masker.turn(side, raw, data[direction][start:end])
        if end - start > MAX_TURN_BYTES:
            item["bytes_not_shown"] = end - start - MAX_TURN_BYTES
        out.append(item)
    return out, max(0, len(turns) - MAX_TRANSCRIPT_TURNS)
