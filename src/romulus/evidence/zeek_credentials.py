"""Credentials inside the free text Zeek's analyzer logs keep, found and redacted in time linear in the text.

A URI's userinfo, a SIP URI's password, the literal a SQL statement sets, compares or inserts as a password, and the
password a Redis reply carries (a CONFIG GET of requirepass, an ACL user's password hashes, an AUTH command a MONITOR
stream repeats) are replaced by REDACTED; the rest of the text is kept, so what the command did stays readable. Each
scan reports whether it redacted a credential (one certainly travelled) and whether text that can carry one could not
be read and was withheld (its structure is ambiguous or unterminated, or it is longer than is read), with a caveat.

Every pattern here is possessive or reads one bounded token, so no search backtracks over text it has read; every
search resumes past what an earlier one read; and work done token by token stops at a fixed budget, beyond which the
text is withheld rather than read (a statement after its first credential cue, a reply or SIP value whole).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from itertools import accumulate

REDACTED = "<redacted>"


@dataclass
class Scrubbed:
    """A value after its credentials were redacted: its text (None when the whole value is withheld), whether a
    credential was redacted, whether text that may hold one was withheld unread, and the caveats saying why. `secrets`
    are the redacted values themselves, for removing their echo from the same record; they are never typed."""
    text: str | None
    redacted: bool = False
    unread: bool = False
    caveats: list[str] = field(default_factory=list)
    secrets: list[str] = field(default_factory=list)


def _splice(text: str, spans: list[tuple[int, int]]) -> str:
    """The text with each span (merged where they overlap) replaced by REDACTED."""
    merged: list[list[int]] = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    out, last = [], 0
    for start, end in merged:
        out.append(text[last:start])
        out.append(REDACTED)
        last = end
    out.append(text[last:])
    return "".join(out)


# ---- URIs ----------------------------------------------------------------------------------------------------------

_AUTHORITY_END = re.compile(r"[/?#\s]")


def strip_uri_userinfo(text: str) -> tuple[str, bool, bool]:
    """The text without the userinfo of any hierarchical URI in it (scheme://user:password@host), whether one was
    removed, and whether a removed one held a password (a colon) rather than a user alone (often a token). The
    userinfo runs to the last "@" before the authority ends (at "/", "?", "#", whitespace or the end)."""
    pieces, last, removed, password = [], 0, False, False
    pos = text.find("://")
    while pos != -1:
        start = pos + 3
        found = _AUTHORITY_END.search(text, start)
        end = found.start() if found else len(text)
        at = text.rfind("@", start, end)
        if at != -1:
            removed = True
            password = password or text.find(":", start, at) != -1
            pieces.append(text[last:start])
            last = at + 1
        # an authority holds no "/", so the next "://" starts at its last character (a ":") at the earliest
        pos = text.find("://", end - 1)
    if not removed:
        return text, False, False
    pieces.append(text[last:])
    return "".join(pieces), True, password


_SIP_SCHEME = re.compile(r"\bsips?:", re.IGNORECASE)
_SIP_USER_END = re.compile(r"[:@;>\s/]")
_SIP_PART_END = re.compile(r"[;>\s]")
# SIP URIs read one by one in one value, up to this many; a value with more is withheld
SIP_URI_BUDGET = 4096
SIP_UNREAD = (f"a SIP value of this record holds more than {SIP_URI_BUDGET} SIP URIs, more than are read for "
              "passwords: it was withheld")


def strip_sip_password(text: str) -> tuple[str | None, bool]:
    """The text without the password of any SIP URI's userinfo (sip:user:password@host keeps sip:user@host; the user
    is the address), and whether one was removed; None (withhold the value) when it holds more SIP URIs than are
    read. The user runs to the first ":"; the password to the last "@" before a ";", ">" or whitespace."""
    if "@" not in text:
        return text, False
    pieces, last, removed = [], 0, False
    part_end, part_at = -1, -1              # the end of the URI part being read, and its last "@"
    for count, scheme in enumerate(_SIP_SCHEME.finditer(text)):
        if count == SIP_URI_BUDGET:
            return None, False
        if scheme.start() < last:
            continue                        # inside a password already removed
        user_end = _SIP_USER_END.search(text, scheme.end())
        if user_end is None or user_end.group() != ":":
            continue
        colon = user_end.start()
        if colon >= part_end:               # a part no earlier scheme of this text opened
            found = _SIP_PART_END.search(text, colon)
            part_end = found.start() if found else len(text)
            part_at = text.rfind("@", colon, part_end)
        if part_at > colon:
            removed = True
            pieces.append(text[last:colon])
            last = part_at
    if not removed:
        return text, False
    pieces.append(text[last:])
    return "".join(pieces), True


# ---- SQL -----------------------------------------------------------------------------------------------------------

SQL_UNREAD = ("part of this record's SQL could not be read for credentials (an unterminated quote or comment, a VALUES "
              "list that does not match its columns, or more tokens than are read): its literals there, or its text "
              "from where it first names a password, are redacted")
# A statement names a password where one of these occurs: no other statement is tokenized.
_SQL_CUE = re.compile(r"pass|identified|authentication_string", re.IGNORECASE)
_WORD_REST = re.compile(r"\w*+")
# Tokens are read one by one up to this many (spaces and comments included); a longer statement that names a password
# is redacted from that name on.
SQL_TOKEN_BUDGET = 20_000
_SQL_TOKENS = r"""
    (?P<space>\s++)
  {comment}
  | (?P<str>(?:[xXbBnNeE]|_[A-Za-z0-9]++)?'(?:[^'\\]++|\\[\s\S]?|'')*+(?:(?P<str_end>')|\Z))
  | (?P<dq>"(?:[^"\\]++|\\[\s\S]?|"")*+(?:(?P<dq_end>")|\Z))
  | (?P<tick>`(?:[^`]++|``)*+(?:(?P<tick_end>`)|\Z))
  | (?P<dollar>\$(?:[A-Za-z_][A-Za-z0-9_]*+)?\$)
  | (?P<param>\$[0-9]++|\?|:[A-Za-z_][A-Za-z0-9_]*+)
  | (?P<number>0[xX][0-9A-Fa-f]++|0[bB][01]++|[0-9]++(?:\.[0-9]*+)?(?:[eE][+-]?[0-9]++)?|\.[0-9]++)
  | (?P<var>@@?[A-Za-z_][\w$.]*+)
  | (?P<word>[^\W\d][\w$]*+)
  | (?P<op><=>|<>|!=|==|<=|>=|\|\|)
  | (?P<punct>[\s\S])
"""
_SQL_TOKEN = re.compile(_SQL_TOKENS.format(
    comment=r"| (?P<comment>/\*[\s\S]*?(?:(?P<comment_end>\*/)|\Z)|--(?=\s|\Z)[^\n]*+)"), re.VERBOSE)
# a comment's text, read as SQL in its turn (a comment inside it is not one: the text is read once)
_SQL_TOKEN_IN_COMMENT = re.compile(_SQL_TOKENS.format(comment=""), re.VERBOSE)
_STRINGS = frozenset({"str", "dq", "dollar"})
_LITERALS = _STRINGS | {"number"}
_EQUALS = frozenset({"=", "==", "<>", "!=", "<=>"})
# words that stand where a value goes but are not one
_NOT_VALUES = frozenset({"NULL", "DEFAULT", "TRUE", "FALSE", "UNKNOWN", "CURRENT_USER", "CURRENT_ROLE", "SESSION_USER",
                         "SYSTEM_USER", "USER", "NOT", "ANY", "ALL", "SOME", "EXISTS", "SELECT", "CASE", "WITH",
                         "VALUES", "ROW", "ARRAY", "INTERVAL", "BINARY", "AND", "OR", "RANDOM", "PASSWORD"})
_INSERT_MODIFIERS = frozenset({"INTO", "IGNORE", "LOW_PRIORITY", "DELAYED", "HIGH_PRIORITY"})
# a libpq connection string's password inside a literal (dblink, postgres_fdw): the rest of the literal is withheld
_CONNINFO_PASSWORD = re.compile(r"password\s*+=\s*+", re.IGNORECASE)


def scrub_sql(text: str) -> Scrubbed:
    """A statement with the literal of every credential position redacted, the statement itself kept.

    Positions: after IDENTIFIED [WITH <plugin>] BY|AS (and a REPLACE that follows), [ENCRYPTED] PASSWORD, PASSWORD
    FOR <user> =, the arguments of a function whose name holds "pass" (PASSWORD(), OLD_PASSWORD()), and a comparison
    or assignment (=, <>, !=, LIKE, IN (...)) of a column whose name holds "pass" or is authentication_string (either
    side, with a value written as a concatenation ('a' || 'b', or juxtaposed strings) whole); the VALUES of an INSERT
    or REPLACE at such a column's position, or all of them when the INSERT names no columns; a connection string's
    password= inside a literal; and the same positions inside a comment's text. Literals: '...' (with '' and \\'
    escapes, and X'', B'', N'', E'' and _charset'' prefixes), "...", $$...$$ and $tag$...$tag$, numbers and 0x/0b
    numbers, and a bare word where a value goes. Placeholders ($1, ?, :name) and variables (@name) are not values:
    nothing is redacted for them. An empty literal carries nothing.

    Only a statement that names a password (a cue: "pass", "identified" or "authentication_string", in any case) is
    read. So an INSERT without a column list into a table whose name holds no cue (INSERT INTO users VALUES ('bob',
    'secret')) is kept as written: nothing in it says which value, if any, is a password."""
    cue = _SQL_CUE.search(text)
    if cue is None:
        return Scrubbed(text)
    budget = [SQL_TOKEN_BUDGET]
    main = _sql_region(text, 0, len(text), _SQL_TOKEN, budget)
    scans = [main] if main is not None else []
    for start, end in main.comments if main is not None else ():
        if _SQL_CUE.search(text, start, end) is None:
            continue
        inner = _sql_region(text, start, end, _SQL_TOKEN_IN_COMMENT, budget)
        if inner is None:
            main = None
            break
        scans.append(inner)
    if main is None:                        # more tokens than are read: from the first cue on
        tail = _WORD_REST.match(text, cue.end()).end()
        return Scrubbed(_splice(text, [(tail, len(text))]) if tail < len(text) else text, unread=True,
                        caveats=[SQL_UNREAD])
    spans = [span for scan in scans for span in scan.spans]
    secrets = [secret for scan in scans for secret in scan.secrets]
    unread = any(scan.unread for scan in scans)
    if not spans:
        return Scrubbed(text, unread=unread, caveats=[SQL_UNREAD] if unread else [])
    return Scrubbed(_splice(text, spans), redacted=bool(secrets), unread=unread,
                    caveats=[SQL_UNREAD] if unread else [], secrets=secrets)


def _sql_region(text: str, start: int, end: int, pattern: re.Pattern, budget: list[int]) -> _SqlScan | None:
    """The credential positions of the SQL text between start and end (a statement, or a comment's text); None when
    the budget of tokens runs out. A quote or comment that never ends, unless a credential was redacted to the end,
    withholds everything after the region's first cue: what it hides cannot be told from what it does not."""
    tokens = _sql_tokens(text, start, end, pattern, budget)
    if tokens is None:
        return None
    kinds, starts, ends, unterminated, unclosed, comments = tokens
    scan = _SqlScan(text, kinds, starts, ends, unclosed, end)
    scan.comments = comments
    scan.run()
    scan.strings()
    if unterminated and not any(stop == end for _start, stop in scan.spans):
        cue = _SQL_CUE.search(text, start, end)
        tail = _WORD_REST.match(text, cue.end(), end).end()
        if tail < end:
            scan.spans.append((tail, end))
        scan.unread = True
    return scan


def _sql_tokens(text: str, start: int, end: int, pattern: re.Pattern, budget: list[int]):
    """The tokens between start and end as parallel lists (kind, start, end), spaces and comments left out; whether a
    quote or comment never ends; the index of the token that never ends (None if none); and the comments' text spans.
    None when the budget (shared by every region of one statement) runs out."""
    kinds: list[str] = []
    starts: list[int] = []
    ends: list[int] = []
    comments: list[tuple[int, int]] = []
    unterminated, unclosed = False, None
    pos, match = start, pattern.match
    while pos < end:
        budget[0] -= 1
        if budget[0] < 0:
            return None
        m = match(text, pos, end)
        kind, stop = m.lastgroup, m.end()
        if kind == "space":
            pos = stop
            continue
        if kind == "comment":
            if text.startswith("/*", pos):
                closed = m.group("comment_end") is not None
                unterminated = unterminated or not closed
                comments.append((pos + 2, stop - 2 if closed else stop))
            else:
                comments.append((pos + 2, stop))
            pos = stop
            continue
        if kind == "dollar":                # PostgreSQL's dollar quoting: up to the same tag
            close = text.find(m.group(), stop, end)
            if close == -1:
                unterminated, unclosed = True, len(kinds)
            stop = end if close == -1 else close + (stop - pos)
        elif kind in ("str", "dq", "tick") and m.group(f"{kind}_end") is None:
            unterminated, unclosed = True, len(kinds)
        kinds.append(kind)
        starts.append(pos)
        ends.append(stop)
        pos = stop
    return kinds, starts, ends, unterminated, unclosed, comments


class _SqlScan:
    """The credential positions of one tokenized statement (or comment). Each range of tokens is read once: nested
    calls and lists inside a range already read are skipped (`covered`), so the scan is linear in the tokens."""

    def __init__(self, text: str, kinds: list[str], starts: list[int], ends: list[int], unclosed: int | None,
                 limit: int):
        self.text, self.kinds, self.starts, self.ends, self.unclosed = text, kinds, starts, ends, unclosed
        self.limit = limit                  # where the text read ends
        self.comments: list[tuple[int, int]] = []
        self.n = len(kinds)
        self.spans: list[tuple[int, int]] = []
        self.secrets: list[str] = []
        self.done: set[int] = set()
        self.unread = False
        self.covered = -1                   # every literal of tokens up to here was redacted by a range read
        self.closing = self._parens()

    def _parens(self) -> dict[int, int]:
        closing, stack = {}, []
        for i, kind in enumerate(self.kinds):
            if kind == "punct":
                char = self.text[self.starts[i]]
                if char == "(":
                    stack.append(i)
                elif char == ")" and stack:
                    closing[stack.pop()] = i
        return closing

    def _raw(self, i: int) -> str:
        return self.text[self.starts[i]:self.ends[i]]

    def word(self, i: int) -> str:
        return self._raw(i).upper() if 0 <= i < self.n and self.kinds[i] == "word" else ""

    def punct(self, i: int) -> str:
        return self._raw(i) if 0 <= i < self.n and self.kinds[i] in ("punct", "op") else ""

    def name(self, i: int) -> str:
        """An identifier's name, lowercased (a word, "quoted" or `quoted`); "" for anything else."""
        if not 0 <= i < self.n:
            return ""
        if self.kinds[i] == "word":
            return self._raw(i).lower()
        if self.kinds[i] in ("dq", "tick"):
            return self._raw(i)[1:-1].lower()
        return ""

    def credential_column(self, i: int) -> bool:
        name = self.name(i)
        if self.glued(i - 1):               # pass/**/word: the comment joins one name, as an evasion writes it
            name = self.name(i - 1) + name
        return bool(name) and ("pass" in name or name == "authentication_string") and self.punct(i + 1) != "("

    def glued(self, i: int) -> bool:
        """Whether words i and i + 1 are separated by one block comment alone."""
        if not (0 <= i < self.n - 1 and self.kinds[i] == "word" and self.kinds[i + 1] == "word"):
            return False
        gap = self.text[self.ends[i]:self.starts[i + 1]]
        return gap.startswith("/*") and gap.find("*/") == len(gap) - 2

    def _content(self, i: int) -> tuple[int, int]:
        """Where a literal's value lies inside its token."""
        start, end, kind = self.starts[i], self.ends[i], self.kinds[i]
        closed = i != self.unclosed
        if kind == "number":
            return start, end
        if kind == "dollar":
            tag = self.text.index("$", start + 1) + 1 - start
            return start + tag, end - tag if closed else end
        open_at = self.text.index('"' if kind == "dq" else "'", start) + 1
        return open_at, end - 1 if closed else end

    def redact(self, i: int) -> None:
        """Redact the literal at i, unless it is empty. A word or literal written against its closing quote ('it's
        x') means the quote ended inside the value (a password holding a quote the client did not escape): the
        statement is withheld from there to its end."""
        if i in self.done:
            return
        start, end = self._content(i)
        if start == end:
            return
        self.done.add(i)
        self.spans.append((self.starts[i], self.ends[i]))
        self.secrets.append(self.text[start:end])
        if i + 1 < self.n and self.starts[i + 1] == self.ends[i] and self.kinds[i] in _STRINGS and \
                self.kinds[i + 1] in ("word", "number", "str", "dq", "dollar"):
            self.done.update(range(i + 1, self.n))
            self.spans.append((self.ends[i], self.limit))
            self.unread = True

    def redact_unquoted(self, j: int) -> int:
        """Redact an unquoted value (a bare word or a number) with every token written against it (a bare
        "Hunter2-x" is three tokens), up to a space, ",", ";" or a parenthesis; the index after it."""
        if j in self.done:                  # inside a run already redacted
            return j + 1
        last = j
        while last + 1 < self.n and self.starts[last + 1] == self.ends[last] and \
                self.punct(last + 1) not in (",", ";", "(", ")"):
            last += 1
        self.done.update(range(j, last + 1))
        self.spans.append((self.starts[j], self.ends[last]))
        self.secrets.append(self.text[self.starts[j]:self.ends[last]])
        return last + 1

    def value(self, j: int) -> int:
        """Redact the value at j, written as one operand or a concatenation of them ('a' || 'b', or strings written
        one after another, which MySQL joins); the index after it."""
        k = self.operand(j)
        while k < self.n:
            if self.kinds[k] in _STRINGS:
                self.redact(k)
                k += 1
            elif self.punct(k) == "||":
                k = self.operand(k + 1)
            else:
                break
        return k

    def operand(self, j: int) -> int:
        """Redact one operand at j (a literal, the string arguments of a call, a parenthesized expression, or a bare
        word); the index after it."""
        if j >= self.n:
            return j
        kind = self.kinds[j]
        if kind == "number":
            return self.redact_unquoted(j)
        if kind in _LITERALS:
            self.redact(j)
            return j + 1
        if kind == "word" and self.punct(j + 1) == "(":
            return self.literals_in(j + 1, _STRINGS)
        if self.punct(j) == "(" and self.word(j + 1) not in ("SELECT", "WITH", "VALUES"):
            return self.literals_in(j, _STRINGS)
        if kind == "word" and self.word(j) not in _NOT_VALUES and self.punct(j + 1) != ".":
            return self.redact_unquoted(j)
        return j + 1

    def literals_in(self, open_: int, kinds: frozenset[str]) -> int:
        """Redact the literals of these kinds between a "(" and its ")" (to the end when it has none); the index
        after the ")"."""
        close = self.closing.get(open_, self.n)
        if close > self.covered:
            for k in range(max(open_ + 1, self.covered + 1), close):
                if self.kinds[k] in kinds:
                    self.redact(k)
            self.covered = close
        return close + 1

    def items(self, open_: int, close: int) -> list[tuple[int, int]]:
        """The comma-separated items between a "(" and its ")", as token ranges; nested parentheses are skipped."""
        out, start, k = [], open_ + 1, open_ + 1
        while k < close:
            char = self.punct(k)
            if char == "(":
                k = self.closing.get(k, close) + 1
                continue
            if char == ",":
                out.append((start, k))
                start = k + 1
            k += 1
        out.append((start, close))
        return out

    def run(self) -> None:
        for i in range(self.n):
            kind = self.kinds[i]
            if kind == "word":
                upper = self._raw(i).upper()
                follows = self.punct(i + 1)
                if upper == "IDENTIFIED":
                    self.identified(i)
                elif upper == "PASSWORD" and follows != "(":
                    self.password(i)
                elif upper in ("INSERT", "REPLACE") and follows != "(":
                    self.insert(i)
                if follows == "(" and "PASS" in upper:
                    self.literals_in(i + 1, _STRINGS)
            if self.credential_column(i):
                self.compare(i)
            elif kind in _LITERALS and self.punct(i + 1) in _EQUALS and self.credential_column(i + 2):
                self.redact(i)

    def identified(self, i: int) -> None:
        j = i + 1
        if self.word(j) == "WITH":
            j += 2                          # the authentication plugin's name
        if self.word(j) not in ("BY", "AS"):
            return
        j += 1
        if self.word(j) == "RANDOM":        # IDENTIFIED BY RANDOM PASSWORD: the server makes one
            return
        if self.word(j) == "PASSWORD" and j + 1 < self.n and self.kinds[j + 1] in _LITERALS:
            j += 1                          # MySQL 5's IDENTIFIED BY PASSWORD '<hash>'
        after = self.value(j)
        if self.word(after) == "REPLACE":   # ALTER USER ... IDENTIFIED BY 'new' REPLACE 'current'
            self.value(after + 1)

    def password(self, i: int) -> None:
        if self.word(i + 1) == "FOR":       # SET PASSWORD FOR <user> = <value>
            for j in range(i + 2, min(i + 18, self.n)):
                char = self.punct(j)
                if char == "=":
                    self.value(j + 1)
                    return
                if char == ";":
                    return
            return
        if i + 1 < self.n and self.kinds[i + 1] in _LITERALS:
            self.redact(i + 1)              # [ENCRYPTED] PASSWORD '<value>', OPTIONS (password '<value>')

    def compare(self, i: int) -> None:
        j = i + 1
        if self.word(j) == "NOT":
            j += 1
        if self.punct(j) in _EQUALS or self.word(j) in ("LIKE", "ILIKE"):
            self.value(j + 1)
        elif self.word(j) == "IN" and self.punct(j + 1) == "(" and \
                self.word(j + 2) not in ("SELECT", "WITH", "VALUES"):
            self.literals_in(j + 1, _LITERALS)

    def insert(self, i: int) -> None:
        if i <= self.covered:
            return
        j = i + 1
        while self.word(j) in _INSERT_MODIFIERS:
            j += 1
        if not self.name(j):
            return
        j += 1
        while self.punct(j) == "." and self.name(j + 1):
            j += 2
        if self.word(j) == "AS" and self.name(j + 1):
            j += 2
        if self.word(j) in ("VALUES", "VALUE"):
            # no column list in a statement that names a password: which value is one is not known
            self.all_values(j)
            return
        if self.punct(j) != "(" or j not in self.closing:
            return
        columns = self.items(j, self.closing[j])
        positions = [p for p, (a, b) in enumerate(columns)
                     if any("pass" in self.name(k) or self.name(k) == "authentication_string" for k in range(a, b))]
        if not positions:
            return
        readable = all(b - a == 1 and self.name(a) for a, b in columns)
        j = self.closing[j] + 1
        if self.word(j) == "OVERRIDING":    # OVERRIDING SYSTEM|USER VALUE
            j += 3
        if self.word(j) not in ("VALUES", "VALUE"):
            return
        values, rows, j = j, [], j + 1
        while readable:
            if self.word(j) == "ROW":
                j += 1
            close = self.closing.get(j)
            if self.punct(j) != "(" or close is None:
                readable = False
                break
            row = self.items(j, close)
            if len(row) != len(columns):
                readable = False
                break
            rows.append(row)
            j = close + 1
            if self.punct(j) != ",":
                break
            j += 1
        if not readable:
            self.all_values(values)
            return
        for row in rows:
            for p in positions:
                a, b = row[p]
                if b - a == 1:
                    self.value(a)
                elif b > a:
                    for k in range(a, b):
                        if self.kinds[k] in _STRINGS:
                            self.redact(k)
        self.covered = max(self.covered, j)

    def all_values(self, values: int) -> None:
        """Redact every literal of a VALUES list (from the VALUES keyword to the statement's end), as text that may
        hold a password."""
        end = values
        while end < self.n and self.punct(end) != ";":
            if self.kinds[end] in _LITERALS:
                self.redact(end)
            end += 1
        self.covered = max(self.covered, end)
        self.unread = True

    def strings(self) -> None:
        """A connection string's password inside any string literal not already redacted."""
        for i, kind in enumerate(self.kinds):
            if kind not in _STRINGS or i in self.done:
                continue
            start, end = self._content(i)
            found = _CONNINFO_PASSWORD.search(self.text, start, end)
            if found is not None and found.end() < end:
                self.done.add(i)
                self.spans.append((found.end(), end))
                self.secrets.append(self.text[found.end():end])


# ---- Redis replies -------------------------------------------------------------------------------------------------
#
# Zeek's Redis analyzer logs a reply as one string (src/analyzer/protocol/redis/redis.spicy, stringify): an array or
# push as "[a, b]", a map as "{k: v, k2: v2}", a set as "(a, b)", null as "null", a boolean as "T"/"F", and a bulk or
# simple string as its raw bytes, with no quoting or escaping. So a value holding ", " cannot be told from two values,
# and a password "x, dir, y" reads as two pairs. Only the full parameter list (CONFIG GET *, which names every
# parameter once, so a password posing as more pairs would repeat a name) is read pair by pair; in any other reply a
# credential parameter's value is taken to run to the end of the reply. A MONITOR stream's lines ("<sec>.<usec> [<db>
# <client>] "cmd" "arg" ...", each argument quoted and escaped by Redis's sdscatrepr) arrive as replies, on any row
# of the connection.

REDIS_UNREAD = ("this record's Redis reply could not be read for credentials (a CONFIG, ACL or MONITOR reply whose "
                "structure is ambiguous or unterminated): it was withheld, or its unreadable part redacted")
# CONFIG parameter names (and their aliases) of Redis 5.0, 6.2, 7.2 and 8.0 and Valkey 8.1 (src/config.c)
_CONFIG_NAMES = """
acl-pubsub-default aclfile acllog-max-len active-defrag-cycle-max active-defrag-cycle-min active-defrag-cycle-us
active-defrag-ignore-bytes active-defrag-max-scan-fields active-defrag-threshold-lower active-defrag-threshold-upper
active-expire-effort activedefrag activerehashing always-show-logo aof-disable-auto-gc aof-load-truncated
aof-rewrite-cpulist aof-rewrite-incremental-fsync aof-timestamp-enabled aof-use-rdb-preamble appenddirname
appendfilename appendfsync appendonly auto-aof-rewrite-min-size auto-aof-rewrite-percentage availability-zone
bgsave-cpulist bind bind-source-addr bio-cpulist busy-reply-threshold client-default-resp client-output-buffer-limit
client-query-buffer-limit cluster-allow-pubsubshard-when-down cluster-allow-reads-when-down
cluster-allow-replica-migration cluster-announce-bus-port cluster-announce-client-ipv4 cluster-announce-client-ipv6
cluster-announce-hostname cluster-announce-human-nodename cluster-announce-ip cluster-announce-port
cluster-announce-tls-port cluster-blacklist-ttl cluster-compatibility-sample-ratio cluster-config-file
cluster-enabled cluster-link-sendbuf-limit cluster-manual-failover-timeout cluster-migration-barrier
cluster-node-timeout cluster-ping-interval cluster-port cluster-preferred-endpoint-type cluster-replica-no-failover
cluster-replica-validity-factor cluster-require-full-coverage cluster-slave-no-failover
cluster-slave-validity-factor cluster-slot-stats-enabled commandlog-execution-slower-than
commandlog-large-reply-max-len commandlog-large-request-max-len commandlog-reply-larger-than
commandlog-request-larger-than commandlog-slow-execution-max-len crash-log-enabled crash-memcheck-enabled daemonize
databases dbfilename debug-context dir disable-thp dual-channel-replication-enabled dynamic-hz
enable-debug-assert enable-debug-command enable-module-command enable-protected-configs events-per-io-thread
extended-redis-compatibility gopher-enabled hash-max-listpack-entries hash-max-listpack-value
hash-max-ziplist-entries hash-max-ziplist-value hide-user-data-from-log hll-sparse-max-bytes hz ignore-warnings
import-mode io-threads io-threads-do-reads jemalloc-bg-thread key-load-delay latency-monitor-threshold
latency-tracking latency-tracking-info-percentiles lazyfree-lazy-eviction lazyfree-lazy-expire
lazyfree-lazy-server-del lazyfree-lazy-user-del lazyfree-lazy-user-flush lfu-decay-time lfu-log-factor
list-compress-depth list-max-listpack-size list-max-ziplist-size loading-process-events-interval-bytes
locale-collate log-format log-timestamp-format logfile loglevel lua-replicate-commands lua-time-limit masterauth
masteruser max-new-connections-per-cycle max-new-tls-connections-per-cycle maxclients maxmemory maxmemory-clients
maxmemory-eviction-tenacity maxmemory-policy maxmemory-samples min-replicas-max-lag min-replicas-to-write
min-slaves-max-lag min-slaves-to-write no-appendfsync-on-rewrite notify-keyspace-events oom-score-adj
oom-score-adj-values pidfile port prefetch-batch-max-size primaryauth primaryuser proc-title-template
propagation-error-behavior protected-mode proto-max-bulk-len rdb-del-sync-files rdb-key-save-delay
rdb-save-incremental-fsync rdb-version-check rdbchecksum rdbcompression rdma-bind rdma-completion-vector rdma-port
rdma-rx-size repl-backlog-size repl-backlog-ttl repl-disable-tcp-nodelay repl-diskless-load repl-diskless-sync
repl-diskless-sync-delay repl-diskless-sync-max-replicas repl-ping-replica-period repl-ping-slave-period
repl-rdb-channel repl-timeout replica-announce-ip replica-announce-port replica-announced
replica-full-sync-buffer-limit replica-ignore-disk-write-errors replica-ignore-maxmemory replica-lazy-flush
replica-priority replica-read-only replica-serve-stale-data replicaof req-res-logfile requirepass
sanitize-dump-payload save server-cpulist set-max-intset-entries set-max-listpack-entries set-max-listpack-value
set-proc-title shutdown-on-sigint shutdown-on-sigterm shutdown-timeout slave-announce-ip slave-announce-port
slave-ignore-maxmemory slave-lazy-flush slave-priority slave-read-only slave-serve-stale-data slaveof
slowlog-log-slower-than slowlog-max-len socket-mark-id stop-writes-on-bgsave-error stream-node-max-bytes
stream-node-max-entries supervised syslog-enabled syslog-facility syslog-ident tcp-backlog tcp-keepalive timeout
tls-auth-clients tls-ca-cert-dir tls-ca-cert-file tls-cert-file tls-ciphers tls-ciphersuites tls-client-cert-file
tls-client-key-file tls-client-key-file-pass tls-cluster tls-dh-params-file tls-key-file tls-key-file-pass tls-port
tls-prefer-server-ciphers tls-protocols tls-replication tls-session-cache-size tls-session-cache-timeout
tls-session-caching tracking-table-max-keys unixsocket unixsocketgroup unixsocketperm use-exit-on-panic
watchdog-period zset-max-listpack-entries zset-max-listpack-value zset-max-ziplist-entries zset-max-ziplist-value
"""
REDIS_CONFIG_PARAMETERS = frozenset(_CONFIG_NAMES.split())
# the parameters every one of those versions names in CONFIG GET * (none an alias): a reply naming all of them is the
# full parameter list
_CORE_NAMES = """
active-defrag-cycle-max active-defrag-cycle-min active-defrag-ignore-bytes active-defrag-max-scan-fields
active-defrag-threshold-lower active-defrag-threshold-upper activedefrag activerehashing aof-load-truncated
aof-rewrite-incremental-fsync aof-use-rdb-preamble appendfsync appendonly auto-aof-rewrite-min-size
auto-aof-rewrite-percentage bind client-output-buffer-limit client-query-buffer-limit cluster-announce-bus-port
cluster-announce-ip cluster-announce-port cluster-migration-barrier cluster-node-timeout cluster-replica-no-failover
cluster-replica-validity-factor cluster-require-full-coverage daemonize databases dbfilename dir hll-sparse-max-bytes
hz latency-monitor-threshold lazyfree-lazy-eviction lazyfree-lazy-expire lazyfree-lazy-server-del lfu-decay-time
lfu-log-factor list-compress-depth logfile loglevel maxclients maxmemory maxmemory-policy maxmemory-samples
min-replicas-max-lag min-replicas-to-write no-appendfsync-on-rewrite notify-keyspace-events pidfile port
protected-mode proto-max-bulk-len rdb-save-incremental-fsync rdbchecksum rdbcompression repl-backlog-size
repl-backlog-ttl repl-disable-tcp-nodelay repl-diskless-sync repl-diskless-sync-delay repl-ping-replica-period
repl-timeout replica-announce-ip replica-announce-port replica-ignore-maxmemory replica-lazy-flush replica-priority
replica-read-only replica-serve-stale-data replicaof requirepass save set-max-intset-entries
stop-writes-on-bgsave-error stream-node-max-bytes stream-node-max-entries supervised syslog-facility tcp-backlog
tcp-keepalive timeout unixsocket unixsocketperm watchdog-period
"""
REDIS_CORE_PARAMETERS = frozenset(_CORE_NAMES.split())
# the parameters whose value is a credential: a password (any name holding "pass") and replication's user and password
REDIS_CREDENTIAL_PARAMETERS = frozenset(
    {name for name in REDIS_CONFIG_PARAMETERS if "pass" in name} | {"masterauth", "masteruser", "primaryauth",
                                                                    "primaryuser"})
_CREDENTIAL_NAMES = "|".join(map(re.escape, sorted(REDIS_CREDENTIAL_PARAMETERS)))
# a credential parameter as one item of a container reply (whatever the command it is logged with)
_CREDENTIAL_ITEM = re.compile(r"(?:[\[{(]|, )(?:" + _CREDENTIAL_NAMES + r")(?=, |: |[\]})])", re.IGNORECASE)
# a credential parameter named as a whole word in a reply that is no list (an error naming it)
_CREDENTIAL_WORD = re.compile(r"(?<![\w-])(?:" + _CREDENTIAL_NAMES + r")(?![\w-])", re.IGNORECASE)
_CLOSERS = {"[": "]", "{": "}", "(": ")"}
# a command a MONITOR stream (or anything else) echoes as quoted arguments, starting a run of them
_ECHO = re.compile(r'(?<![\\\w"])"(?:auth|hello|migrate|config|acl)"', re.IGNORECASE)
_ARGUMENT = r'"(?:[^"\\]++|\\[\s\S])*+"'
_RUN = re.compile(_ARGUMENT + r'(?: ' + _ARGUMENT + r')*+')
_ARGUMENTS = re.compile(r'"((?:[^"\\]++|\\[\s\S])*+)"')
_MONITOR_LINE = re.compile(r"(?<![0-9])[0-9]++\.[0-9]{6} \[[0-9]++ ")
# an echoed command's arguments read one by one, up to this many; a longer run is redacted whole
ECHO_ARGUMENT_BUDGET = 1024
# ACL password rules redacted one by one, up to this many; a reply with more is withheld
ACL_RULE_BUDGET = 4096
_HEX_RUN = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{64,}+")
_HEX_ONLY = re.compile(r"[0-9A-Fa-f]{16,}+")
_ACL_PLAINTEXT = re.compile(r"(?:(?<=[\s\[({,])|^)[<>]([^\s,\]})]++)")
_REDIS_REDACTED = "(redacted)"         # what Redis 7 itself writes for a redacted argument


def scrub_redis_reply(text: str, command: str) -> Scrubbed:
    """A reply with the credentials it carries redacted, the rest kept; `command` is the row's command name,
    uppercased ("" when the row has none: a MONITOR stream's lines are logged on rows with no command).

    - any reply: the arguments of AUTH, of HELLO ... AUTH and MIGRATE ... AUTH/AUTH2, the value of CONFIG SET of a
      credential parameter, and ACL SETUSER's password rules, when a MONITOR line (or other text) quotes the command;
      every "#" + 64-hex password hash; and a credential parameter's value in a list (_config_credentials);
    - CONFIG: a reply that is no list and names a credential parameter (an error quoting what was set) is withheld;
    - ACL: bare 64-hex hashes, ">"/"<" password rules, and a reply that is one long hex string (ACL GENPASS);
    - a MONITOR line, or a CONFIG or ACL list, that does not end where its structure says is withheld."""
    spans: list[tuple[int, int]] = []
    secrets: list[str] = []
    unread = False

    def redact(start: int, end: int) -> None:
        if end > start and text[start:end] != _REDIS_REDACTED:
            spans.append((start, end))
            secrets.append(text[start:end])

    # 1. commands echoed with their arguments
    covered = 0
    for echo in _ECHO.finditer(text):
        if echo.start() < covered:
            continue
        run = _RUN.match(text, echo.start())
        covered = run.end()
        name = text[echo.start() + 1:echo.end() - 1].upper()
        if text.startswith(' "', run.end()):
            # an argument that never ends (a truncated line): it may be the credential
            spans.append((run.end() + 2, len(text)))
            if name == "AUTH":
                secrets.append(text[run.end() + 2:])
            else:
                unread = True
        if run.end() == echo.end():
            continue
        if name == "AUTH":
            if set(text[echo.end() + 1:run.end()].split(" ")) != {f'"{_REDIS_REDACTED}"'}:
                redact(echo.end() + 2, run.end() - 1)       # every argument, as one span
            continue
        arguments = []
        for k, argument in enumerate(_ARGUMENTS.finditer(text, echo.end(), run.end())):
            if k == ECHO_ARGUMENT_BUDGET:
                arguments = None
                break
            arguments.append(argument.span(1))
        if arguments is None:
            spans.append((echo.end() + 2, run.end() - 1))
            unread = True
            continue
        for start, end in _echoed_secrets(text, name, arguments):
            redact(start, end)

    # 2. a MONITOR line must be one run of quoted arguments to its end
    if _MONITOR_LINE.match(text):
        quote = text.find('"')
        run = _RUN.match(text, quote) if quote != -1 else None
        if run is None or run.end() != len(text):
            return Scrubbed(None, unread=True, caveats=[REDIS_UNREAD])

    # 3. name/value pairs: CONFIG GET's reply, or a credential parameter's name in any list
    container = len(text) >= 2 and _CLOSERS.get(text[0]) == text[-1]
    if command == "CONFIG" or (container and _CREDENTIAL_ITEM.search(text)):
        if not container:
            if _CREDENTIAL_WORD.search(text):    # a reply that is no list, naming a credential parameter
                return Scrubbed(None, unread=True, caveats=[REDIS_UNREAD])
        else:
            values, certain, rest = _config_credentials(text)
            for start, end in values:
                if certain:
                    redact(start, end)
                else:                           # may hold a credential: redacted, not counted as one
                    spans.append((start, end))
            unread = unread or rest

    # 4. password hashes, and ACL's own forms
    for run in _HEX_RUN.finditer(text):
        start, end = run.span()
        if end - start != 64 or (end < len(text) and (text[end].isalnum() or text[end] == "_")):
            continue
        before = text[start - 1] if start > 0 else " "
        if before == "#" or (command == "ACL" and not (before.isalnum() or before == "_")):
            redact(start, end)              # "#" + hash anywhere; a bare hash in an ACL reply
    if command == "ACL":
        if text[:1] in _CLOSERS and not container:
            return Scrubbed(None, unread=True, caveats=[REDIS_UNREAD])
        for count, rule in enumerate(_ACL_PLAINTEXT.finditer(text)):
            if count == ACL_RULE_BUDGET:
                return Scrubbed(None, unread=True, caveats=[REDIS_UNREAD])
            redact(*rule.span(1))
        if _HEX_ONLY.fullmatch(text):
            redact(0, len(text))            # ACL GENPASS: a password the server made
    if not spans:
        return Scrubbed(text, unread=unread, caveats=[REDIS_UNREAD] if unread else [])
    return Scrubbed(_splice(text, spans), redacted=bool(secrets), unread=unread,
                    caveats=[REDIS_UNREAD] if unread else [], secrets=secrets)


def _echoed_secrets(text: str, name: str, arguments: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Which quoted arguments of an echoed HELLO, MIGRATE, CONFIG or ACL command are a credential (spans of their
    content)."""
    words = [text[start:end].upper() if end - start <= 16 else "" for start, end in arguments]
    out: list[tuple[int, int]] = []
    if name in ("HELLO", "MIGRATE"):
        for k, word in enumerate(words):
            if word == "AUTH":                  # HELLO ... AUTH <user> <password>; MIGRATE ... AUTH <password>
                out.extend(arguments[k + 1:k + (3 if name == "HELLO" else 2)])
            elif word == "AUTH2" and name == "MIGRATE":
                out.extend(arguments[k + 1:k + 3])
    elif name == "CONFIG" and words[:1] == ["SET"]:
        for k in range(1, len(arguments) - 1, 2):
            start, end = arguments[k]
            if text[start:end].lower() in REDIS_CREDENTIAL_PARAMETERS:
                out.append(arguments[k + 1])
    elif name == "ACL" and words[:1] == ["SETUSER"]:
        for start, end in arguments[2:]:
            if end > start and text[start] in "<>#":
                out.append((start + 1, end))    # >password, <password, #hash
    return out


def _config_credentials(text: str) -> tuple[list[tuple[int, int]], bool, bool]:
    """Where a container reply that names CONFIG parameters holds credential values: the spans to redact, whether they
    are certainly credential values, and whether text that cannot be told apart from one was redacted with them.

    - the full parameter list, read as pairs (every name known, each once, and every core name present): each
      credential value alone;
    - other replies read as pairs: from the first credential value to the end of the reply, since a value holding
      ", " cannot be told from more pairs;
    - replies not read as pairs (an unknown name, an odd list, a name twice): from the value after the first item that
      is exactly a credential parameter's name to the end, as text that may hold one; none such, nothing."""
    inner = text[1:-1]
    items = inner.split(", ") if inner else []
    offsets = list(accumulate((len(item) + 2 for item in items), initial=1))
    end = len(text) - 1                     # before the closing bracket
    is_map = text[0] == "{"
    keys = [item.partition(": ")[0] for item in items] if is_map else items
    pairs = _config_pairs(text, items, offsets, keys)
    if pairs is not None:
        credentials = [(start, stop) for name, start, stop in pairs if name in REDIS_CREDENTIAL_PARAMETERS]
        if REDIS_CORE_PARAMETERS <= {name for name, _start, _stop in pairs}:
            return credentials, True, False
        if not credentials:
            return [], True, False
        start, stop = credentials[0]
        return [(start, end)], True, stop < end
    for k, key in enumerate(keys):
        if key.lower() in REDIS_CREDENTIAL_PARAMETERS:
            if is_map:
                start = offsets[k] + len(key) + 2 if items[k] != key else end
            else:
                start = offsets[k + 1] if k + 1 < len(items) else end
            return ([(start, end)] if start < end else []), False, True
    return [], False, False


def _config_pairs(text: str, items: list[str], offsets: list[int],
                  keys: list[str]) -> list[tuple[str, int, int]] | None:
    """A container reply read as CONFIG GET's name/value pairs: (name, value start, value end) each; None when it is
    not one (an odd list, an item of a map without ": ", a name no Redis or Valkey version has, a name twice)."""
    if text[0] == "[":
        names = items[0::2]
        if len(items) % 2:
            return None
        values = [(offsets[k], offsets[k] + len(items[k])) for k in range(1, len(items), 2)]
    elif text[0] == "{":
        if any(item == key for item, key in zip(items, keys, strict=True)):
            return None                     # an item without ": "
        names = keys
        values = [(offsets[k] + len(names[k]) + 2, offsets[k] + len(items[k])) for k in range(len(items))]
    else:
        return None
    if not all(name in REDIS_CONFIG_PARAMETERS for name in names) or len(set(names)) != len(names):
        return None
    return [(name, start, end) for name, (start, end) in zip(names, values, strict=True)]


# ---- LDAP search filters -------------------------------------------------------------------------------------------

# Attributes whose value is a password or a secret derived from one: RFC 4519 userPassword (2.5.4.35), RFC 3112
# authPassword (1.3.6.1.4.1.4203.1.3.4), Active Directory's unicodePwd (1.2.840.113556.1.4.90) and dBCSPwd
# (1.2.840.113556.1.4.55), its password histories and supplementalCredentials ([MS-ADA3]), the LAPS password attributes,
# the gMSA msDS-ManagedPassword, and Samba's password attributes.
LDAP_PASSWORD_ATTRIBUTES = frozenset({
    "userpassword", "authpassword", "unicodepwd", "dbcspwd", "ntpwdhistory", "lmpwdhistory",
    "supplementalcredentials", "ms-mcs-admpwd", "mslaps-password", "mslaps-encryptedpassword",
    "mslaps-encryptedpasswordhistory", "mslaps-encrypteddsrmpassword", "mslaps-encrypteddsrmpasswordhistory",
    "msds-managedpassword", "sambantpassword", "sambalmpassword", "sambapasswordhistory",
    "2.5.4.35", "1.3.6.1.4.1.4203.1.3.4", "1.2.840.113556.1.4.90", "1.2.840.113556.1.4.55",
})
# what every name above holds: a filter holding none of these is not scanned
_LDAP_PASSWORD_CUES = ("pass", "pwd", "credential", "2.5.4.35", "1.3.6.1.4.1.4203.1.3.4", "1.2.840.113556.1.4.")
# a password attribute as a whole attribute description (with its options after ";"), in lowercased text
_LDAP_PASSWORD_ATTRIBUTE = re.compile(
    r"(?<![a-z0-9.;-])(?:" + "|".join(map(re.escape, sorted(LDAP_PASSWORD_ATTRIBUTES, key=len, reverse=True)))
    + r")(?:;[a-z0-9-]*+)*+(?![a-z0-9.-])")
LDAP_FILTER_WITHHELD = ("this LDAP search filter compares a password attribute with a value (Zeek writes a filter's "
                        "values unescaped, so where that value ends cannot be told): the filter was withheld")


def scrub_ldap_filter(text: str) -> Scrubbed:
    """A search filter as Zeek writes it ("(&(objectClass=user)(userPassword=...))"), withheld whole when it compares
    a password attribute with a value: an equality, approximate, ordering, substring or extensible assertion on it (an
    extensible one Zeek writes "(rule:attribute:=value)"). A presence test ("(userPassword=*)") sends no value and is
    kept, as is every filter that names no such attribute."""
    lowered = text.lower()
    if not any(cue in lowered for cue in _LDAP_PASSWORD_CUES):
        return Scrubbed(text)
    for found in _LDAP_PASSWORD_ATTRIBUTE.finditer(lowered):
        end = found.end()
        if lowered.startswith("=*", end) and (end + 2 == len(lowered) or lowered[end + 2] == ")"):
            continue                        # a presence test: no value
        if lowered.startswith(("=", ":", "~=", ">=", "<="), end):
            return Scrubbed(None, redacted=True, caveats=[LDAP_FILTER_WITHHELD])
    return Scrubbed(text)
