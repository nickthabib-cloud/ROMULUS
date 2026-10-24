"""A mechanical check that a published finding cites what its text states.

`problems(text, cited)` reads a finding's published text (its claim and notes) against the typed events it cites and
returns what the citations do not carry. It is deliberately conservative: it flags only statements it can read
unambiguously, and wording that says honestly what is not cited passes.

1. Spans and instants. Every interval stated between two timestamps ('A – B', 'from A to B', 'between A and B') and
   every instant stated as 'at A' must start and end on the time of a cited record: its event time or any typed time
   field it carries (flow.start, flow.end, ...). An uncited start passes only when the text says the record that
   starts the interval 'was not kept for citation', an uncited end only when it says so of the record that ends it
   (one such statement excuses one endpoint), and an uncited instant only when its own sentence says its record is
   not cited or not kept.
2. Counts. A count of records, or of values drawn from them ('479 alerts', '64 distinct signatures', 'occurred 4
   times'), greater than the number of cited records needs a statement of how many of exactly that total are cited:
   'K of (the) M ... cited' or 'all M ... are cited' with M equal to the count, or 'the earliest K ... are cited' in
   the count's own sentence, with K no more than the records cited. A count in a sentence that says those records
   were not judged, not cited or not kept is hedged and passes.
3. Names. Every process id ('pid 964', 'pids 1, 2 and 3 more'), IP address, signature id ('sid 2016184'), port
   ('port 443', 'tcp/22'), bracketed example list item and quoted value the text names must appear in a cited record's
   typed fields: as a value, a list element, the last path component of a value, a part of a value set off by
   punctuation or spaces (never part of a word: 'vi' is not in 'vim'), or the command shape of a cited command line.
   An address block ('10.30.4.0/24') is named by any cited address inside it, a domain by a cited name under it,
   and a reverse-lookup name stands for its address. A quoted phrase (more than one word) that the detection code
   quotes inside one of its string literals is wording, not a value, as are the few one-word protocol states in
   WORDING_WORDS ('failed' in "protocol detection 'failed'"); any other one-word quote, such as a program name
   ('curl', 'nc', 'perl'), is a value and must be cited. A pid in a 'K more' tail is counted, not named.
4. Attribution. A process named as making connect() calls ('(pid 200, ...) made 3 connect() call(s) to 192.0.2.1
   port 4444', '(pids 1, 2), ..., making 5 connect() call(s) to 2 address(es) ... on port 443') must be the process
   of a cited connect() record to that port (and that address, when one is named).

What it does not judge: whether a value is the right one beyond attribution (a pid that appears in a cited record
may still be named for the wrong reason), counts of things other than records and values, and statements without
numbers or quotes. Those stay with review.
"""
from __future__ import annotations

import ipaddress
import re
import tokenize
from collections import Counter
from datetime import UTC, datetime
from functools import cache
from pathlib import Path

from romulus.evidence.typed import TypedEvent

_TS = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})?"
SPAN = re.compile(rf"(?:from |between )?({_TS})\s*(?:–|—| to | and )\s*({_TS})")
INSTANT = re.compile(rf"\bat ({_TS})(?! or )")
SENTENCE = re.compile(r"(?<=[.;])\s+(?=[A-Z(])")
NUMBER = re.compile(r"^\d[\d,]*$")
# Nouns a count of records, or of values drawn from records, is stated in.
COUNT_NOUNS = frozenset({
    "record", "alert", "request", "call", "connection", "command", "run", "time", "question", "exec", "login",
    "answer", "attempt", "failure", "change", "query", "queries", "lookup", "event", "signature", "port", "address",
    "addresses", "name", "process", "processes", "file", "pid", "subdomain", "url", "agent", "value", "client",
    "session", "line", "flow", "write", "read", "probe", "packet",
})
# Words that end the noun phrase after a number without naming its noun.
STOP = frozenset({"of", "to", "from", "in", "on", "at", "for", "with", "and", "or", "by", "than", "that", "as", "is",
                  "are", "was", "were", "a", "an", "the", "s", "level(s)", "level", "up", "minutes", "hours", "hour",
                  "seconds", "bytes", "byte", "%", "mib"})
HEDGES = ("not judged", "not cited", "not kept", "not held", "not evaluated", "were not", "was not", "at least")
# within one sentence: a dot ends it only when a space follows (addresses and versions carry dots)
_SAME_SENTENCE = r"(?:[^.;]|\.(?=\S))*"
# 'K of (the) M ... cited' and 'all M ... cited' say how many of the total M are cited; 'the earliest K ... cited'
# says how many of its own sentence's count are
OF_TOTAL = re.compile(rf"\b(\d[\d,]*) of (?:the |these |its |all |their )?(\d[\d,]*)\b{_SAME_SENTENCE}\bcited\b")
ALL_OF = re.compile(rf"\b[Aa]ll (\d[\d,]*)\b{_SAME_SENTENCE}\bcited\b")
FIRST_K = re.compile(rf"\b[Tt]he (?:earliest|first|latest|last) (\d[\d,]*)\b{_SAME_SENTENCE}\bcited\b")
# a process named as making connect() calls to a port (and an address)
ATTRIBUTED = re.compile(
    r"\(pids?(?:\(s\))? (\d+(?:(?:, | and )\d+(?! more))*)[^)]*\)" + _SAME_SENTENCE
    + r"?\b(?:made|making) \d[\d,]* connect\(\) call\(s\) to (?:(\S+) port (\d{1,5})\b|"
    + _SAME_SENTENCE + r"?\bon port (\d{1,5})\b)")
# one-word quotes the rules use as wording, not as values from a record: a protocol state, and the keyword of the
# sshd log line a rule names as the kind of record it read
WORDING_WORDS = frozenset({"failed", "Accepted"})
PIDS = re.compile(r"\bpids?(?:\(s\))? (\d+(?:(?:, | and )\d+(?! more))*)")
SIDS = re.compile(r"\bsid (\d+)")
PORTS = re.compile(r"\b(?:port|tcp/|udp/|sctp/)(?: )?(\d{1,5})\b(?!\.\d)")
IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
IPV6 = re.compile(r"(?<![\w:])[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}(?![\w:])")
QUOTED = re.compile(r"(?:(?<=^)|(?<=[\s(\[]))'([^'\n]+?)'(?=$|[\s,.;:)\]])")
LISTED = re.compile(r"\[([^\[\]]+)\]")
NOT_KEPT = "was not kept for citation"


@cache
def wording_constants() -> frozenset[str]:
    """Text the detection code quotes as a constant of its own wording."""
    root = Path(__file__).resolve().parents[1] / "src" / "romulus"
    found: set[str] = set()
    kinds = {tokenize.STRING, getattr(tokenize, "FSTRING_MIDDLE", tokenize.STRING)}
    for path in [*root.joinpath("detect").glob("*.py"), *root.joinpath("hunt").glob("*.py")]:
        with path.open(encoding="utf-8") as source:
            for token in tokenize.generate_tokens(source.readline):
                if token.type in kinds:                 # string literals only, never comments
                    found.update(re.findall(r"'([^'{}\n]{1,80})'", token.string))
    # a one-word quote (a program, a field, a protocol word) may be a value a claim names: only phrases are wording
    return frozenset(text for text in found if " " in text.strip()) | WORDING_WORDS


def _times(event: TypedEvent) -> set[datetime]:
    out = {event.ts.astimezone(UTC)}
    for field in event.fields.values():
        value = field.value
        if isinstance(value, str) and len(value) >= 19 and value[4] == "-" and value[10] == "T":
            try:
                parsed = datetime.fromisoformat(value)
            except ValueError:
                continue
            out.add((parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)).astimezone(UTC))
    return out


def _parse_ts(text: str) -> datetime:
    parsed = datetime.fromisoformat(text)
    return (parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)).astimezone(UTC)


def _flat(value) -> list:
    if isinstance(value, list | tuple | set):
        return [item for each in value for item in _flat(each)]
    if isinstance(value, dict):
        return [item for each in value.values() for item in _flat(each)]
    return [value]


class Cited:
    """The values a finding's cited records carry, in the forms a claim names them."""

    def __init__(self, events: list[TypedEvent]):
        self.count = len(events)
        self.times: set[datetime] = set()
        self.strings: set[str] = set()
        self.ints: set[int] = set()
        self.pids: set[int] = {0, 1}
        self.addresses: set[ipaddress._BaseAddress] = set()
        self.shapes: set[str] = set()
        for event in events:
            self.times |= _times(event)
            if event.host:
                self.strings.add(event.host)
            for name, field in event.fields.items():
                for value in _flat(field.value):
                    self._take(name, value)
            argv = event.get("process.argv")
            if isinstance(argv, list) and argv:
                self.shapes.add(" ".join(re.sub(r"\d+", "N", str(a))[:48] for a in argv[:4]))

    def _take(self, name: str, value) -> None:
        if isinstance(value, bool) or value is None:
            return
        if isinstance(value, int):
            self.ints.add(value)
            if "pid" in name:
                self.pids.add(value)
            value = str(value)
        if not isinstance(value, str):
            value = str(value)
        self.strings.add(value)
        if "/" in value:
            self.strings.add(value.rstrip("/").rsplit("/", 1)[-1])
        if value.isdigit():
            self.ints.add(int(value))
        for token in re.findall(r"[0-9a-fA-F:.]+", value):
            try:
                self.addresses.add(ipaddress.ip_address(token))
            except ValueError:
                pass
        if name.startswith("dns.question.name") and value.endswith(".in-addr.arpa"):
            octets = value.removesuffix(".in-addr.arpa").split(".")
            if len(octets) == 4:
                try:
                    self.addresses.add(ipaddress.ip_address(".".join(reversed(octets))))
                except ValueError:
                    pass

    def names(self, text: str) -> bool:
        if (text in self.strings or text.rstrip("/").rsplit("/", 1)[-1] in self.strings
                or re.sub(r"\d+", "N", text) in self.shapes):
            return True
        # a domain a cited name lies under ('example.test' of 'q1.example.test', at a label boundary)
        if "." in text and any(value.lower().endswith("." + text.lower()) for value in self.strings):
            return True
        # a part of a value set off by punctuation or spaces ('10.0.0.20' of 'alice@10.0.0.20'), never part of a word
        # ('vi' is not in 'vim')
        bounded = re.compile(rf"(?<![\w.-]){re.escape(text)}(?![\w-])")
        return any(bounded.search(value) for value in self.strings if len(value) > len(text))


def _sentences(text: str) -> list[str]:
    return [part for part in SENTENCE.split(text) if part]


def _counts(sentence: str):
    """(number, noun) for each count of records or values the sentence states."""
    words = sentence.replace("(", " (").split()
    for i, word in enumerate(words):
        token = word.strip("(),;:")
        if not NUMBER.match(token) or (i and words[i - 1].lower().lstrip("(").rstrip(":") in
                                       ("port", "pid", "pids", "pid(s)", "uid", "id", "severity", "sid", "level",
                                        "ppid", "session", "serial", "every", "last", "first", "ipv")):
            continue
        for follow in words[i + 1:i + 5]:
            bare = follow.lower().strip("'\",.;:()[]")
            bare = re.sub(r"\((?:e?s)\)$", "", bare)
            if bare in STOP or NUMBER.match(bare) or not bare:
                break
            stem = bare[:-2] if bare.endswith("es") and bare[:-2] in COUNT_NOUNS else bare.rstrip("s")
            if bare in COUNT_NOUNS or stem in COUNT_NOUNS:
                yield int(token.replace(",", "")), bare
                break


def _int(text: str) -> int:
    return int(text.replace(",", ""))


def problems(text: str, events: list[TypedEvent]) -> list[str]:
    """What `text` states that its cited `events` do not carry (empty when everything checks)."""
    cited = Cited(events)
    out: list[str] = []
    sentences = _sentences(text)
    # each 'was not kept for citation' statement excuses one uncited endpoint of the side it names
    excused: Counter = Counter()
    for sentence in sentences:
        if NOT_KEPT in sentence:
            excused["starts"] += len(re.findall(r"\bthat starts\b", sentence))
            excused["ends"] += len(re.findall(r"\bthat ends\b", sentence))
    for match in SPAN.finditer(text):
        for side, stamp in zip(("starts", "ends"), match.groups(), strict=True):
            if _parse_ts(stamp) in cited.times:
                continue
            if excused[side]:
                excused[side] -= 1
                continue
            out.append(f"span endpoint {stamp} is no cited record's time")
    for sentence in sentences:
        for match in INSTANT.finditer(sentence):
            if _parse_ts(match.group(1)) not in cited.times and not any(
                    hedge in sentence for hedge in ("not cited", "not kept")):
                out.append(f"instant {match.group(1)} is no cited record's time")
    totals: set[int] = set()
    for match in OF_TOTAL.finditer(text):
        shown, total = _int(match.group(1)), _int(match.group(2))
        totals.add(total)
        if shown > cited.count:
            out.append(f"says {shown} are cited, but {cited.count} records are")
    for match in ALL_OF.finditer(text):
        total = _int(match.group(1))
        totals.add(total)
        if total > cited.count:
            out.append(f"says {total} are cited, but {cited.count} records are")
    for sentence in sentences:
        first_k = [_int(m.group(1)) for m in FIRST_K.finditer(sentence)]
        for shown in first_k:
            if shown > cited.count:
                out.append(f"says {shown} are cited, but {cited.count} records are")
        if first_k or any(hedge in sentence for hedge in HEDGES):
            continue
        for number, noun in _counts(sentence):
            if number > cited.count and number not in totals:
                out.append(f"states {number} {noun} with {cited.count} records cited and does not say how many "
                           f"are cited")
    out += _misattributed(text, events)
    for match in PIDS.finditer(text):
        for pid in re.findall(r"\d+", match.group(1)):
            if int(pid) not in cited.pids:
                out.append(f"names pid {pid}, in no cited record")
    for match in SIDS.finditer(text):
        if int(match.group(1)) not in cited.ints:
            out.append(f"names signature id {match.group(1)}, in no cited record")
    for match in PORTS.finditer(text):
        if int(match.group(1)) not in cited.ints:
            out.append(f"names port {match.group(1)}, in no cited record")
    for regex in (IPV4, IPV6):
        for match in regex.finditer(text):
            try:
                address = ipaddress.ip_address(match.group(0))
            except ValueError:
                continue
            prefix = re.match(r"/(\d{1,3})\b", text[match.end():])
            if prefix:
                # a block ('10.30.4.0/24') is named by a cited address inside it
                try:
                    block = ipaddress.ip_network(f"{address}/{prefix.group(1)}", strict=False)
                except ValueError:
                    block = None
                if block is not None and any(a in block for a in cited.addresses if a.version == block.version):
                    continue
            if address not in cited.addresses:
                out.append(f"names address {address}, in no cited record")
    constants = wording_constants()
    for match in QUOTED.finditer(text):
        value = match.group(1)
        if value in constants or cited.names(value):
            continue
        out.append(f"quotes '{value}', in no cited record")
    for match in LISTED.finditer(text):
        for item in (part.strip() for part in match.group(1).split(",")):
            if NUMBER.match(item):
                if int(item.replace(",", "")) not in cited.ints:
                    out.append(f"lists {item}, in no cited record")
            elif (len(item) >= 2 and item[0] == item[-1] and item[0] in "'\""
                  and item[1:-1] not in constants and not cited.names(item[1:-1])):
                out.append(f"lists {item}, in no cited record")
    return list(dict.fromkeys(out))


def _misattributed(text: str, events: list[TypedEvent]) -> list[str]:
    """A pid named as making connect() calls to a port (and an address) with no cited connect() record of its own
    there."""
    calls = [e for e in events if e.family == "net_socket"]
    out = []
    for match in ATTRIBUTED.finditer(text):
        address, port = match.group(2), _int(match.group(3) or match.group(4))
        for pid in (int(p) for p in re.findall(r"\d+", match.group(1))):
            if not any(e.get("process.pid") == pid and e.get("destination.port") == port
                       and (address is None or str(e.get("destination.ip")) == address) for e in calls):
                where = f"{address} port {port}" if address else f"port {port}"
                out.append(f"names pid {pid} as calling {where}, but no cited connect() record of it does")
    return out


def finding_problems(claim: str, notes: list[str], events: list[TypedEvent]) -> list[str]:
    """A finding's claim and notes, checked as one published text."""
    return problems(" ".join([claim, *(f"{note}." for note in notes)]), events)
