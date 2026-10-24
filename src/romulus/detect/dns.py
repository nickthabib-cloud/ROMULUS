"""DNS reconnaissance and DNS channel-shape aggregates over typed `dns_query` records.

Typed fields read (no record text is ever searched):
- `dns.type`: the record's role. `query` (or `request`) is a question sent by the client, so the client is
  `source.ip` and the server `destination.ip`. `answer` (or `response`) is the server's reply, so the client is
  `destination.ip` and the server `source.ip`. A record with no `dns.type` is a whole-transaction record (one
  session-level view of a question and its reply, as a session indexer produces); its `source.ip` is the client
  that initiated the session. Any other role value is not evaluated and is counted as missing.
- `dns.question.names` (a list) or `dns.question.name`, and `dns.question.type`: the question. When the list is
  present every name in it is evaluated (a session record may hold several questions); otherwise the scalar name
  is. Rules that read names and types read them from question records (queries and transaction records) only: in
  some sensor output formats an answer record carries the name and type of one answer resource record rather than
  of the question.
- `dns.response_code`: the reply's rcode, read from answer and transaction records only.
- `suricata.flow_id` or `network.community_id`, with the question name and type and `dns.id` when typed: used only
  to tell whether an answer record's question is already present as a query record.

Coverage: a record a rule needs but cannot evaluate (no client address, no name, no type where the type decides,
an answer whose question was not retrieved as a query, or query records with no answers in the same batch for the
answer-based rule) is counted as missing, so the rule's coverage for that partition is partial, never a clean
negative. Aggregates count across every partition of the hunt window; cited examples are the earliest records by
(time, id), so output does not depend on the order records arrive in.
"""
from __future__ import annotations

import ipaddress
import math
import sys
from bisect import bisect_left, insort
from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from typing import ClassVar

from romulus.detect.base import Match, Playbook, pf
from romulus.detect.bounded import HOT_COUNT, KeyedStore
from romulus.detect.citing import (
    BoundStage,
    Ends,
    Holds,
    Named,
    bound_note,
    cite_with_bounds,
    cited_phrase,
    drained_holds,
    more,
)
from romulus.detect.host import is_internal
from romulus.evidence.typed import TypedEvent

EXAMPLE_LIMIT = 20
NAME_CAP = 20_000             # distinct names kept per group; counts at the cap are reported as lower bounds
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_US = timedelta(microseconds=1)

QTYPE_NAMES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 10: "NULL", 12: "PTR", 13: "HINFO", 15: "MX", 16: "TXT",
               25: "KEY", 28: "AAAA", 33: "SRV", 35: "NAPTR", 43: "DS", 46: "RRSIG", 48: "DNSKEY", 64: "SVCB",
               65: "HTTPS", 99: "SPF", 251: "IXFR", 252: "AXFR", 255: "ANY"}
RCODE_NAMES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED", 6: "YXDOMAIN",
               7: "YXRRSET", 8: "NXRRSET", 9: "NOTAUTH", 10: "NOTZONE"}
REVERSE_ZONES = ("in-addr.arpa", "ip6.arpa")

# Second-level public suffixes under which registrations happen one level deeper (example.co.uk). A small, offline
# subset of the public-suffix list: the common country second levels. Any other name's registered domain is its
# last two labels, so names under a suffix not listed here (including shared-hosting suffixes) group together.
MULTI_LABEL_SUFFIXES = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "ltd.uk", "plc.uk", "me.uk", "net.uk", "nhs.uk", "sch.uk", "police.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz", "school.nz",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "ad.jp", "ed.jp", "gr.jp", "lg.jp",
    "com.br", "net.br", "org.br", "gov.br", "edu.br",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
    "co.in", "net.in", "org.in", "gov.in", "ac.in", "edu.in", "nic.in",
    "co.za", "org.za", "gov.za", "ac.za", "net.za",
    "com.mx", "net.mx", "org.mx", "gob.mx", "edu.mx",
    "com.tr", "net.tr", "org.tr", "gov.tr", "edu.tr",
    "com.sg", "net.sg", "org.sg", "gov.sg", "edu.sg",
    "com.hk", "net.hk", "org.hk", "gov.hk", "edu.hk",
    "com.tw", "net.tw", "org.tw", "gov.tw", "edu.tw",
    "co.kr", "or.kr", "go.kr", "ac.kr", "ne.kr",
    "com.ar", "gob.ar", "com.co", "gov.co", "co.il", "ac.il", "gov.il", "org.il",
    "com.my", "gov.my", "com.ph", "gov.ph", "com.pk", "gov.pk", "com.ua", "gov.ua", "com.vn", "gov.vn",
    "co.th", "ac.th", "go.th", "or.th", "co.id", "go.id", "ac.id", "or.id",
    "com.sa", "gov.sa", "com.eg", "gov.eg", "com.ng", "gov.ng", "co.ke", "go.ke", "com.pe", "gob.pe",
    "com.ve", "com.ec", "com.uy", "com.py", "com.bo", "com.do", "com.gt", "com.pa", "com.qa", "com.kw",
    "com.bh", "com.om", "com.lb", "com.jo", "co.ae", "gov.ae", "ac.ae",
})


# ------------------------------------------------------------------------------------------------ typed helpers
def qtype(value) -> str | None:
    """Canonical question type mnemonic ('AXFR', 'PTR', 'TYPE65399'), from a mnemonic, a number or 'TYPEn'."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return QTYPE_NAMES.get(value, f"TYPE{value}") if 0 <= value <= 65535 else None
    if not isinstance(value, str):
        return None
    text = value.strip().upper()
    if text.isascii() and text.isdigit():
        return qtype(int(text))
    if text.startswith("TYPE") and text[4:].isascii() and text[4:].isdigit():
        return qtype(int(text[4:]))
    if text == "*":
        return "ANY"
    return text if text and text.isascii() and text.replace("-", "").isalnum() else None


def rcode(value) -> str | None:
    """Canonical reply code mnemonic ('NXDOMAIN'), from a mnemonic or a number."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return RCODE_NAMES.get(value, f"RCODE{value}")
    if not isinstance(value, str):
        return None
    text = value.strip().upper()
    if text.isascii() and text.isdigit():
        return rcode(int(text))
    return text if text and text.isascii() and text.isalnum() else None


def qname(value) -> str | None:
    """Lower-case question name without a trailing dot; '.' for the root; None when absent or not a string."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    if text in ("<root>", "."):
        return "."
    text = text.rstrip(".").lower()
    return text or None


def registered_domain(name: str) -> str:
    """The registered domain: the last two labels, or three under a listed country second-level suffix."""
    labels = name.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def subdomain_part(name: str, domain: str) -> str:
    """What sits to the left of the registered domain ('' for the domain itself)."""
    return name[: -len(domain) - 1] if name.endswith("." + domain) else ""


def entropy(text: str) -> float:
    """Shannon entropy of the characters of `text`, in bits per character."""
    if not text:
        return 0.0
    total = len(text)
    return -sum(n / total * math.log2(n / total) for n in Counter(text).values())


def reverse_zone(name: str) -> str | None:
    """'in-addr.arpa' or 'ip6.arpa' when the name sits in a reverse-lookup tree (label-exact, never a substring)."""
    labels = name.split(".")
    tail = ".".join(labels[-2:])
    return tail if tail in REVERSE_ZONES else None


def reverse_address(name: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """The address a full reverse name stands for; None for a zone (partial) name or a malformed one."""
    labels = name.split(".")
    zone = reverse_zone(name)
    if zone == "in-addr.arpa":
        octets = labels[:-2]
        # canonical decimal octets only: '010' is a different name, not another spelling of 10
        if len(octets) == 4 and all(o.isascii() and o.isdigit() and o == str(int(o)) and int(o) <= 255
                                    for o in octets):
            return ipaddress.IPv4Address(".".join(reversed(octets)))
    elif zone == "ip6.arpa":
        nibbles = labels[:-2]
        if len(nibbles) == 32 and all(len(n) == 1 and n in "0123456789abcdef" for n in nibbles):
            return ipaddress.IPv6Address(int("".join(reversed(nibbles)), 16))
    return None


def role(event: TypedEvent) -> str | None:
    """'query', 'answer' or 'transaction' (no dns.type recorded); None for any other recorded role."""
    value = event.get("dns.type")
    if value is None:
        return "transaction"
    return {"query": "query", "request": "query", "answer": "answer", "response": "answer"}.get(str(value).lower())


def endpoints(event: TypedEvent, record_role: str) -> tuple[str | None, str | None]:
    """(client, server) addresses for the record's role."""
    src, dst = event.get("source.ip"), event.get("destination.ip")
    src = str(src) if src not in (None, "") else None
    dst = str(dst) if dst not in (None, "") else None
    return (dst, src) if record_role == "answer" else (src, dst)


def flow_key(event: TypedEvent):
    flow = event.get("suricata.flow_id")
    if flow not in (None, ""):
        return ("flow", flow)
    community = event.get("network.community_id")
    return ("community", community) if community not in (None, "") else None


def question_names(event: TypedEvent) -> list[str] | None:
    """Every question name of the record: the `dns.question.names` list when present, else the scalar name."""
    names = event.get("dns.question.names")
    if isinstance(names, list):
        found = sorted({name for name in (qname(value) for value in names) if name})
        return found or None
    name = qname(event.get("dns.question.name"))
    return [name] if name else None


def transaction_keys(event: TypedEvent, names: list[str]) -> list[tuple] | None:
    """Keys that tie an answer to its question: flow, question name, question type and DNS id (when typed)."""
    flow = flow_key(event)
    if flow is None:
        return None
    kind, ident = qtype(event.get("dns.question.type")), event.get("dns.id")
    return [(flow, name, kind, ident) for name in names]


def _internal(address: str | None) -> bool | None:
    try:
        return is_internal(ipaddress.ip_address(address)) if address else None
    except ValueError:
        return None


def _micros(ts: datetime) -> int:
    return (ts - _EPOCH) // _US


def _iso_micros(value: int) -> str:
    return (_EPOCH + value * _US).isoformat()


def _short(name: str, limit: int = 80) -> str:
    return name if len(name) <= limit else name[: limit - 3] + "..."


class _Examples:
    """The earliest `limit` records of a group by (time, id), whatever order they arrive in, as identities."""

    __slots__ = ("limit", "sorted_refs")

    def __init__(self, limit: int = EXAMPLE_LIMIT):
        self.limit = limit
        self.sorted_refs: list[tuple[datetime, str]] = []

    def add(self, event: TypedEvent) -> bool:
        """Keep the record if it is among the earliest so far; True when it entered (and so may be cited). The
        earliest set only gets earlier, so a record that does not enter now can never be cited later."""
        ref = (event.ts, event.id)
        at = bisect_left(self.sorted_refs, ref)
        if at >= self.limit or (at < len(self.sorted_refs) and self.sorted_refs[at] == ref):
            return False
        self.sorted_refs.insert(at, ref)
        del self.sorted_refs[self.limit:]
        return True

    def refs(self) -> list[tuple[str, datetime]]:
        return [(event_id, ts) for ts, event_id in self.sorted_refs]

    def ids(self) -> list[str]:
        return [event_id for _ts, event_id in self.sorted_refs]


def _fill(first: list[TypedEvent], rest: list[TypedEvent], limit: int = EXAMPLE_LIMIT) -> list[TypedEvent]:
    """`first` (kept whole), then records from `rest` up to `limit`, without duplicates, in time order."""
    chosen = {e.id: e for e in first}
    for event in rest:
        if len(chosen) >= max(limit, len(first)):
            break
        chosen.setdefault(event.id, event)
    return sorted(chosen.values(), key=lambda e: (e.ts, e.id))


class _Span:
    __slots__ = ("first", "last")

    def __init__(self):
        self.first: datetime | None = None
        self.last: datetime | None = None

    def add(self, ts: datetime) -> None:
        self.first = ts if self.first is None or ts < self.first else self.first
        self.last = ts if self.last is None or ts > self.last else self.last

    def text(self) -> str:
        return f"{self.first.isoformat()} – {self.last.isoformat()}"


_COMPENSATED_SUM = sys.version_info >= (3, 12)


class _FloatSum:
    """A running sum of floats equal, bit for bit, to the builtin `sum` over the same values in the same order (the
    builtin compensates its float sums since Python 3.12), so a mean kept as a running total reads exactly as one
    computed over every value held at once."""

    __slots__ = ("c", "n", "s")

    def __init__(self):
        self.s = 0.0
        self.c = 0.0
        self.n = 0

    def add(self, x: float) -> None:
        self.n += 1
        s = self.s
        t = s + x
        if _COMPENSATED_SUM:
            self.c += (s - t) + x if abs(s) >= abs(x) else (x - t) + s
        self.s = t

    def total(self) -> float:
        if not self.n:
            return 0
        return self.s + self.c if self.c and math.isfinite(self.c) else self.s


def _top(kept: list[tuple[str, str]], name: str, event: TypedEvent, holds: Holds, n: int = 3) -> None:
    """Keep the `n` longest distinct names, ties by name, each with the record that shows it: the examples a claim
    shows. A record is held on the stage while its name is among them and released when a longer one displaces it."""
    if len(kept) >= n and (-len(name), name) >= (-len(kept[-1][0]), kept[-1][0]):
        return
    insort(kept, (name, event.id), key=lambda item: (-len(item[0]), item[0]))
    holds.hold(event)
    for _name, event_id in kept[n:]:
        holds.release(event_id)
    del kept[n:]


# ------------------------------------------------------------------------------------------------ base
class _DnsAggregate(Playbook):
    """Per-group state lives in keyed stores: the HOT most recently used groups in memory, the rest on the rule's
    disk spill, read back when a record of the group arrives again. No group is released, so a count covers the whole
    hunt window however long the group's pauses; only a store's disk budget can refuse a record (stated on coverage).
    Group states hold citation candidates as (time, id) only, so they move to disk at the end of every batch."""
    kind = "aggregate"
    anchor_class = "network_observation"
    claim_type = "aggregate_observation"
    families = ("dns_query",)
    staged = True

    def __init__(self):
        super().__init__()
        self._prev_query_flows: set = set()
        self._pending: dict[str, TypedEvent] = {}
        self.bounds = BoundStage()      # the records bounding each group's span, held while they bound it
        self.holds = Holds()            # records of examples a claim names, held while they are among them
        self.load = lambda ids: []

    def retained_events(self) -> list[TypedEvent]:
        return []

    def drain_staged(self) -> list[TypedEvent]:
        out, self._pending = list(self._pending.values()) + self.bounds.drain() + self.holds.drain(), {}
        return out

    def drain_bounds(self) -> tuple[list[str], list[str]]:
        return drained_holds(self.bounds, self.holds)

    def _named(self, store: Named, value, event: TypedEvent) -> None:
        """Keep the record of one of the first distinct values a claim names (kept to the end)."""
        if store.offer(value, event):
            self._stage(event)

    def _cite(self, ends, first: list[str], ids: list[str], named=(), limit: int = EXAMPLE_LIMIT
              ) -> tuple[list[TypedEvent], set[str]]:
        """Cited records: the bounds of the stated intervals (when held), `first` and `named` (always), then `ids` up
        to `limit` in all. Returns them in time order and the bounding ids the stage does not hold."""
        return cite_with_bounds(self.load, self._events, ends, ids, limit, [*first, *named])

    def _stage(self, event: TypedEvent) -> None:
        # only records that can still be cited reach the stage, so it grows with groups x cite limits, not with
        # DNS volume; the stage's primary key drops a record staged again in a later batch
        self._pending.setdefault(event.id, event)

    def _remember(self, store: _Examples, event: TypedEvent) -> None:
        if store.add(event):
            self._stage(event)

    def _events(self, ids: list[str]) -> list[TypedEvent]:
        wanted = list(dict.fromkeys(ids))
        loaded = self.load(wanted)
        if len(loaded) != len(wanted):
            raise RuntimeError(f"{self.id}: {len(wanted) - len(loaded)} cited event(s) absent from the stage")
        return sorted(loaded, key=lambda event: (event.ts, event.id))

    def _stores(self) -> list[KeyedStore]:
        return [value for value in vars(self).values() if isinstance(value, KeyedStore)]

    def _trim(self) -> None:
        for store in self._stores():
            store.trim()

    def _disk_full(self) -> None:
        self.evaluated -= 1
        self.refuse("disk", "the rule's disk budget for group state is spent; a record of a new group is not "
                            "evaluated")

    def _names_full(self) -> None:
        self.evaluated -= 1
        self.refuse("names", "the rule's disk budget for distinct names is spent; a record naming a new distinct "
                             "name of a large group is not evaluated")

    # A group's distinct items (names, addresses) decide its counts, so they are never capped: while a group has at
    # most the rule's NAMES_INLINE of them they are a set in its state; beyond that they move to a keyed store on
    # the rule's disk spill (key: the group's prefix and the item), most recently used in memory.
    @staticmethod
    def _first_time(store: KeyedStore, state, prefix: tuple, item: tuple, limit: int) -> bool | None:
        """True when `item` is new among the group's distinct items, False when it was seen before, None when the
        disk budget refuses to hold a new one (nothing is changed then)."""
        held = state.inline
        if held is not None:
            if item in held:
                return False
            if len(held) < limit:
                held.add(item)
                return True
            moved = [*sorted(held), item]
            for at, each in enumerate(moved):
                if not store.put(prefix + each, 1):
                    for done in moved[:at]:
                        store.pop(prefix + done)
                    return None
            state.inline = None
            return True
        key = prefix + item
        if store.get(key) is not None:
            return False
        return True if store.put(key, 1) else None

    @staticmethod
    def _forget(store: KeyedStore, state, prefix: tuple, item: tuple) -> None:
        """Undo `_first_time` of a new item (when a later part of the same record was refused)."""
        if state.inline is not None:
            state.inline.discard(item)
        else:
            store.pop(prefix + item)

    def release_state(self) -> None:
        self.load = lambda ids: []
        for value in vars(self).values():
            if isinstance(value, (dict, list, set, KeyedStore, BoundStage, Holds)):
                value.clear()
        self.close_spill()

    def _questions(self, events: list[TypedEvent]):
        """Yield (event, client, server, names) for every question record. An answer record whose (flow, question
        name, question type, DNS id) matches a query record of this batch or the one before is that query's reply
        and is skipped; any other answer record is counted as missing (its question is not in the retrieved
        telemetry as a query record)."""
        batch = [e for e in events if e.family in self.families]
        asked: set[tuple] = set()
        for event in batch:
            names = question_names(event) if role(event) == "query" else None
            keys = transaction_keys(event, names) if names else None
            asked.update(keys or ())
        known = asked | self._prev_query_flows
        self._prev_query_flows = asked
        for event in batch:
            record_role = role(event)
            if record_role == "answer":
                names = question_names(event)
                keys = transaction_keys(event, names) if names else None
                if not keys or any(key not in known for key in keys):
                    self.missing_required += 1
                continue
            if record_role is None:
                self.missing_required += 1
                continue
            client, server = endpoints(event, record_role)
            names = question_names(event)
            if client is None or names is None:
                self.missing_required += 1
                continue
            self.evaluated += 1
            yield event, client, server, names


# ---------------------------------------------------------------------------------------- zone transfer and ANY
class _ZoneGroup:
    """One (client, server, transfer zone or ANY) group of the zone-transfer rule."""

    __slots__ = ("any_names", "asked_by_flow", "deciding", "ends", "examples", "named", "replies", "requests", "span",
                 "transports")

    def __init__(self):
        self.ends = Ends()                          # the records bounding the span
        self.named = Named(5)                       # the first ANY-question names, each with its record
        self.requests: Counter = Counter()          # qtype counts of questions
        self.replies: Counter = Counter()           # (qtype, rcode) counts
        self.transports: set[str] = set()
        self.any_names: set[str] = set()
        self.span = _Span()
        self.deciding: tuple[datetime, str] | None = None
        self.asked_by_flow: dict = {}
        self.examples = _Examples()


class DnsZoneTransferOrAnyRequest(_DnsAggregate):
    id = "net.dns_zone_transfer_or_any_request"
    version = "4"
    title = "DNS zone-transfer (AXFR/IXFR) or ANY question sent by one client to one server"
    required_fields = ()
    severity, lane = "medium", "lead"
    attack = ("T1590.002",)
    benign = ("configured secondary name servers and hosted secondary-DNS providers pulling zones",
              "DNS inventory, migration and monitoring tools; administrators running dig axfr or dig any",
              "older resolvers and mail software that send ANY questions",
              "ANY questions over UDP whose source address is spoofed (the request shape of DNS reflection)")
    next_checks = ("whether the client is a configured secondary for the zone (the server's transfer allow-list)",
                   ("every answer record from the server to the client for the zone, and the transport (TCP for "
                    "a transfer that carried data)"),
                   "other reconnaissance from the client: port scans, reverse-lookup sweeps, web scans")
    REQUEST_TYPES = ("AXFR", "IXFR", "ANY")
    TRANSFER_TYPES = ("AXFR", "IXFR")
    card: ClassVar[dict] = {
        "behavior": "a client asked a DNS server for a full or incremental zone transfer (AXFR/IXFR) or for ANY "
                    "records of a name; answer records, where typed, show whether the server answered NOERROR or "
                    "refused",
        "telemetry": "dns_query: dns.type, dns.question.name, dns.question.type, dns.response_code, source.ip, "
                     "destination.ip (Suricata EVE dns: present and normalized in the lab profile; a session "
                     "indexer's DNS block reads the same typed fields once it is normalized)",
        "fidelity": "direct observation of the question type in a typed field: 'requested' is proven by a query "
                    "record; 'answered' only by an answer record with rcode NOERROR, which does not show how many "
                    "zone records were sent; nothing here proves the zone's content left the server",
        "benign_and_cost": "secondaries and DNS providers (cheap to rule out against the transfer allow-list); one "
                           "grouped finding per (client, server, zone) for transfer questions and per (client, "
                           "server) for ANY questions, whose names are listed",
        "query_cost": "none beyond the sweep: network targets are retrieved whole per partition",
        "next_pivot": "the server's transfer allow-list and the answer records' rcode and transport",
        "adds": "the only rule that reads the question type; enumeration rules count names, not transfer requests",
        "research_basis": "ATT&CK Enterprise 20.0 T1590.002 (DNS; zone transfer with query type AXFR); RFC 5936 "
                          "(AXFR), RFC 1995 (IXFR), RFC 8482 (ANY minimisation)",
        "retrieval": "the sweep retrieves every record of a network target in each partition with no field "
                     "filter, a superset of what this evaluator reads",
        "lane_policy": "lead; high when an external client's AXFR/IXFR to a server on an internal address got a "
                       "NOERROR answer over TCP (the server answered a zone-transfer question from an outside "
                       "party on the transport a transfer that carries data uses). That deciding answer, and its "
                       "question when retrieved, are always cited. Refused, unanswered, UDP or unknown-transport "
                       "cases stay lead: internet scanners try AXFR routinely, and a UDP answer can go to a "
                       "spoofed source",
    }
    QUERY_CAP = 1024        # question records per transfer group kept for pairing with the deciding answer
    # Groups exist only for AXFR, IXFR and ANY questions, which are rare; a flood of spoofed-source ANY questions
    # (about 3 KB per group with its citation candidates) overflows to disk.
    HOT = HOT_COUNT  # a count cap only: the hunt's memory budget sizes it in bytes

    def __init__(self):
        super().__init__()
        self.groups = KeyedStore(self, "dns_zone_groups", self.HOT)

    def retained_events(self) -> list[TypedEvent]:
        return []

    def consume(self, events):
        for event in events:
            if event.family not in self.families:
                continue
            record_role = role(event)
            client, server = endpoints(event, record_role) if record_role else (None, None)
            question_type = qtype(event.get("dns.question.type"))
            if record_role is None or client is None or server is None or question_type is None:
                self.missing_required += 1
                continue
            self.evaluated += 1
            if question_type not in self.REQUEST_TYPES:
                continue
            added = [self._add(event, record_role, client, server, question_type, name)
                     for name in question_names(event) or [""]]
            if not all(added):
                self._disk_full()
        self._trim()
        return []

    def _add(self, event, record_role, client, server, question_type, name) -> bool:
        if question_type in self.TRANSFER_TYPES:
            key = (client, server, "transfer", name)
        else:
            key = (client, server, "any", "")
        group = self.groups.setdefault(key, _ZoneGroup)
        if group is None:
            return False
        if question_type not in self.TRANSFER_TYPES and name:
            self._named(group.named, name, event)
        if question_type not in self.TRANSFER_TYPES and name and name not in group.any_names:
            if len(group.any_names) < NAME_CAP:
                group.any_names.add(name)
            else:
                self.note_limit("names", f"an ANY-question group passed {NAME_CAP:,} distinct names held; its name "
                                         f"count is a lower bound")
        transport = str(event.get("network.transport") or "").lower()
        if record_role in ("query", "transaction"):
            group.requests[question_type] += 1
            flow = flow_key(event)
            flows = group.asked_by_flow if question_type in self.TRANSFER_TYPES else None
            if flows is not None and flow is not None and (flow in flows or len(flows) < self.QUERY_CAP):
                held = flows.get(flow)
                ref = (event.ts, event.id)
                if held is None or ref < held:
                    flows[flow] = ref
                    self._stage(event)
        if record_role == "answer" or (record_role == "transaction" and event.has("dns.response_code")):
            code = rcode(event.get("dns.response_code")) or "not recorded"
            group.replies[(question_type, code)] += 1
            if code == "NOERROR" and question_type in self.TRANSFER_TYPES and transport == "tcp":
                held = group.deciding
                ref = (event.ts, event.id)
                if held is None or ref < held:
                    group.deciding = ref
                    self._stage(event)
        if transport:
            group.transports.add(transport)
        group.span.add(event.ts)
        self.bounds.offer_at(key, group.ends, event)
        self._remember(group.examples, event)
        return True

    def finalize(self):
        out = []
        for key in sorted(self.groups.keys()):
            group = self.groups.peek(key)
            client, server, kind, zone = key
            asked, replies = group.requests, group.replies
            types = sorted(set(asked) | {t for t, _c in replies})
            transfer = kind == "transfer"
            if transfer:
                subject = f"for zone '{zone}'" if zone else "for a zone whose name is not recorded"
            else:
                names = sorted(group.any_names)
                named = sorted(group.named.values())
                shown = ", ".join(f"'{n}'" for n in named) + more(len(named), len(names))
                at_least = "at least " if len(names) >= NAME_CAP else ""
                subject = (f"for {at_least}{len(names)} distinct name(s) ({shown})" if names
                           else "for names not recorded")
            if asked:
                claim = (f"{client} sent {sum(asked.values())} DNS question record(s) ({_tally(asked)}) {subject} "
                         f"to {server} ({group.span.text()}).")
            else:
                claim = (f"{client} received {sum(replies.values())} answer record(s) from {server} to "
                         f"{'/'.join(types)} question(s) {subject} ({group.span.text()}); the question records "
                         f"themselves were not retrieved.")
            accepted = sum(n for (t, code), n in replies.items() if code == "NOERROR" and t in self.TRANSFER_TYPES)
            if replies:
                by_code = Counter({f"{t} {c}": n for (t, c), n in replies.items()})
                claim += f" Answer records from the server: {_tally(by_code)}."
                if accepted:
                    claim += (" A NOERROR answer to a zone-transfer question means the server answered it; the "
                              "answer records do not show how many zone records were sent.")
                elif all(c in ("REFUSED", "NOTAUTH", "NOTIMP") for (_t, c) in replies):
                    claim += " The server refused or did not implement every answered question."
            else:
                claim += (" No answer record for these questions was retrieved, so whether the server answered is "
                          "not established.")
            client_internal, server_internal = _internal(client), _internal(server)
            notes = []
            if "ANY" in types and client_internal is False and "tcp" not in group.transports:
                notes.append("an ANY question over UDP from outside the internal ranges may carry a spoofed source "
                             "address (the request shape of DNS reflection, T1498.002)")
            deciding_ref = group.deciding
            deciding = self._events([deciding_ref[1]])[0] if deciding_ref is not None else None
            if accepted and deciding is None:
                claim += (" None of the NOERROR answers is recorded over TCP, the transport a zone transfer that "
                          "carries data uses; an answer over UDP can go to a spoofed source.")
            first: list[TypedEvent] = []
            if transfer and client_internal is False and server_internal and deciding is not None:
                lane, severity = "high", "high"
                asked_ref = group.asked_by_flow.get(flow_key(deciding))
                asked_event = self._events([asked_ref[1]])[0] if asked_ref is not None else None
                first = [deciding] + ([asked_event] if asked_event is not None else [])
                claim += (f" The client is outside the internal address ranges and the server ({server}) is inside "
                          f"them; the earliest NOERROR answer over TCP was recorded at {deciding.ts.isoformat()}"
                          + (" and its question record is cited." if asked_event is not None
                             else "; its question record was not retrieved."))
            else:
                lane, severity = self.lane, self.severity
            evs, missing = self._cite(group.ends, [e.id for e in first], group.examples.ids(),
                                      list(group.named.ids.values()))
            claim += (cited_phrase(len(evs), sum(asked.values()) + sum(replies.values()), not missing)
                      + bound_note(missing, group.ends))
            e0 = first[0] if first else evs[0]
            predicate = [pf(e, name) for e in (first or evs[:2])
                         for name in ("dns.question.type", "dns.question.name", "dns.response_code",
                                      "network.transport", "source.ip", "destination.ip")
                         if e.has(name)]
            match = Match(self.id, claim, self.claim_type, evs, predicate, evs[0].ts, severity, lane, "high",
                          e0.entities(), notes=notes,
                          group_key=f"{client}|{server}|{zone}" if transfer else f"{client}|{server}|ANY")
            out.append(match)
        return out


def _tally(counts: Counter) -> str:
    return ", ".join(f"{name} x{n}" for name, n in sorted(counts.items(), key=lambda item: (-item[1], str(item[0]))))


# ---------------------------------------------------------------------------------------- reverse-lookup sweep
class _ReverseClient:
    """Everything the reverse-lookup sweep rule holds for one client: counters over every distinct reverse name, and
    its distinct names, addresses and blocks (in this state while few, on the rule's keyed stores beyond that)."""

    __slots__ = ("addresses", "block_ends", "block_examples", "blocks", "densest", "ends", "examples", "inline",
                 "internal", "n_blocks", "n_names", "queries", "span", "top_blocks", "types", "vends", "vspan",
                 "zone_names")

    def __init__(self):
        # the five densest blocks without citation candidates (past BLOCK_STORES), each [block, count, record id]
        # holding one record in it, released when a denser block displaces it
        self.top_blocks: list[list] = []
        self.ends = Ends()                          # the records bounding the span
        self.vends: dict[int, Ends] = {}            # IP version -> the records naming its lowest and highest address
        self.block_ends: dict = {}                  # block (with citation candidates) -> its lowest and highest
        self.n_names = 0                            # distinct reverse names
        self.inline: set | None = set()             # ("n", name) and ("a", address) seen, while few; else on disk
        self.blocks: dict | None = {}               # block -> [block, addresses, lowest, highest], while few
        self.block_examples: dict = {}              # block -> its earliest records (up to BLOCK_STORES blocks)
        self.zone_names = 0
        self.types: dict[str, int] = {}
        self.queries = 0
        self.span = _Span()
        self.examples = _Examples()
        self.addresses = 0                          # distinct addresses named
        self.internal = 0                           # of them, in internal ranges
        self.n_blocks = 0
        self.densest = 0                            # addresses in the densest block
        self.vspan: dict[int, list] = {}            # IP version -> [lowest, highest] address

    @property
    def names(self) -> range:
        """The distinct reverse names as a sized view: they are counted exactly, not listed."""
        return range(self.n_names)


def _block_rank(entry: list) -> tuple:
    """Densest first, then IPv4 before IPv6, then by block."""
    return -entry[1], entry[0].version, entry[0]


class DnsReverseLookupSweep(_DnsAggregate):
    id = "net.dns_reverse_lookup_sweep"
    version = "4"
    title = "Many distinct reverse-lookup (in-addr.arpa / ip6.arpa) names queried by one client"
    required_fields = ()
    severity, lane = "medium", "lead"
    attack = ("T1018", "T1590.002")
    benign = ("mail, log and web servers resolving the names of the peers that connect to them",
              "IP address management, monitoring and inventory tools; network scanners run by administrators",
              "a resolver forwarding its clients' reverse lookups")
    next_checks = ("whether the client is an inventory or monitoring host",
                   "connections from the client to the swept addresses after the lookups (port scan, sessions)",
                   "the host process that issued the lookups")
    DENSE_BLOCK = 32       # distinct addresses within one IPv4 /24 or IPv6 /64
    MIN_DISTINCT = 100     # distinct reverse names from one client, wherever they fall
    card: ClassVar[dict] = {
        "behavior": "one client queried many distinct names in the reverse-lookup trees, naming addresses packed "
                    "into one block (a reverse-DNS sweep: host discovery by name) or spread across many",
        "telemetry": "dns_query question records: dns.question.name, dns.question.type (optional), source.ip "
                     "(Suricata EVE dns query records: present in the lab profile)",
        "fidelity": "direct observation of the questions; a query is a request and does not show whether a name "
                    "was returned",
        "benign_and_cost": "servers resolving their peers (scattered, external addresses), IPAM and monitoring "
                           "hosts; one grouped finding per client",
        "query_cost": "none beyond the sweep",
        "next_pivot": "connections from the client to the swept block after the lookups",
        "adds": "reports a reverse sweep with a host-discovery claim and the swept range; the subdomain "
                "enumeration rule leaves reverse-tree names to this rule, so each sweep is reported once",
        "research_basis": "ATT&CK Enterprise 20.0 T1018 (Remote System Discovery) and T1590.002 (DNS); nmap -sL "
                          "and -R reverse resolution; RFC 1035 section 3.5 and RFC 3596 section 2.5 for the "
                          "reverse name formats",
        "retrieval": "the sweep retrieves every record of a network target in each partition with no field "
                     "filter, a superset of what this evaluator reads",
        "thresholds": "reported when one IPv4 /24 or IPv6 /64 holds at least 32 of the client's distinct reverse "
                      "addresses (an eighth of a /24: a deliberate sweep, rarely reached by a server resolving its "
                      "peers), or when the client asked for at least 100 distinct reverse names anywhere (the "
                      "subdomain enumeration rule's distinct-name threshold, so a client with that many reverse "
                      "names is reported here at that rule's lane)",
        "citations": "the earliest records naming addresses in the densest block, then the client's earliest "
                     "reverse-lookup records",
        "state": "per client, exact counts over every distinct reverse name of the hunt window: distinct names and "
                 "addresses and per-block address counts are never capped (a client's own set while small, the "
                 "rule's keyed stores on its disk spill beyond that), so a dense block named after any number of "
                 "scattered names is still found and the density statement covers every name",
    }
    BLOCK_CITE = 10          # cited records per block
    BLOCK_STORES = 2048      # blocks per client holding citation candidates
    # State grows with distinct clients and their distinct reverse names, never with lookups: a server resolving the
    # same peers all day holds each name once. A client keeps its distinct names and addresses (NAMES_INLINE) and
    # blocks (BLOCKS_INLINE) in its own state while few; beyond that they move to the keyed stores below, so a
    # client's state stays small however many names it asks for.
    HOT = HOT_COUNT  # a count cap only: the hunt's memory budget sizes it in bytes
    NAMES_INLINE = 1024
    BLOCKS_INLINE = 2048

    def __init__(self):
        super().__init__()
        self.clients = KeyedStore(self, "dns_reverse_clients", self.HOT, candidate=self.reportable)
        # (client, "n", name) and (client, "a", address) -> 1, for clients beyond NAMES_INLINE distinct items
        self.names_seen = KeyedStore(self, "dns_reverse_seen", self.HOT)
        # (client, block) -> [block, addresses, lowest, highest], for clients beyond BLOCKS_INLINE blocks
        self.blocks = KeyedStore(self, "dns_reverse_blocks", self.HOT, group=lambda key: key[0])

    def reportable(self, state: _ReverseClient) -> bool:
        return state.n_names >= self.MIN_DISTINCT or state.densest >= self.DENSE_BLOCK

    @property
    def examples(self) -> dict[tuple, _Examples]:
        """Every client's earliest reverse-lookup records (reads the whole store: for tests and small hunts)."""
        return {(client,): state.examples for client, state in self.clients.items()}

    @property
    def names(self) -> dict[str, range]:
        """Every client's distinct reverse names, as sized views (reads the whole store: for tests and small hunts)."""
        return {client: state.names for client, state in self.clients.items()}

    def retained_events(self) -> list[TypedEvent]:
        return []

    def consume(self, events):
        for event, client, _server, all_names in self._questions(events):
            reverse = [name for name in all_names if reverse_zone(name) is not None]
            if not reverse:
                continue
            state = self.clients.setdefault(client, _ReverseClient)
            if state is None:
                self._disk_full()
                continue
            fresh = self._admit(client, state, reverse)
            if fresh is None:
                self._names_full()
                continue
            state.queries += 1
            kind = qtype(event.get("dns.question.type")) or "type not recorded"
            state.types[kind] = state.types.get(kind, 0) + 1
            state.span.add(event.ts)
            self.bounds.offer_at((client, "time"), state.ends, event)
            self._remember(state.examples, event)
            for name in reverse:
                self._cite_block(event, client, state, name)
            for kind, address, entry in fresh:
                self._count(state, kind, address, entry)
                if kind == "address" and entry[0] not in state.block_ends:
                    self._rank_block(state, entry, event)
        self._trim()
        return []

    def _rank_block(self, state: _ReverseClient, entry: list, event: TypedEvent) -> None:
        """Hold one record of each of the five densest blocks that keep no citation candidates, so a claim can name
        any of the densest blocks with a cited record in it."""
        top = state.top_blocks
        found = next((item for item in top if item[0] == entry[0]), None)
        if found is not None:
            found[1] = entry[1]
        elif len(top) < 5 or _block_rank(entry) < _block_rank(top[-1]):
            top.append([entry[0], entry[1], event.id])
            self.holds.hold(event)
        top.sort(key=_block_rank)
        for item in top[5:]:
            self.holds.release(item[2])
        del top[5:]

    def _cite_block(self, event: TypedEvent, client: str, state: _ReverseClient, name: str) -> None:
        """The records a claim names addresses from: the lowest and highest address of each IP version, and of each
        block that keeps citation candidates (held while they are), with the block's earliest records."""
        address = reverse_address(name)
        if address is None:
            return
        value = int(address)
        self.bounds.offer((client, "v", address.version), state.vends.setdefault(address.version, Ends()), value,
                          value, event)
        block = _block_of(address)
        stores = state.block_examples
        if block in stores or len(stores) < self.BLOCK_STORES:
            self._remember(stores.setdefault(block, _Examples(self.BLOCK_CITE)), event)
            self.bounds.offer((client, "b", str(block)), state.block_ends.setdefault(block, Ends()), value, value,
                              event)

    def _admit(self, client: str, state: _ReverseClient, reverse: list[str]) -> list | None:
        """The record's new distinct names, as (kind, address, block entry): "zone" for a name of a reverse zone,
        "name" for a new name of an address already named, "address" for a new address. Every new name, address and
        block is already held; None (and nothing held) when the disk budget refuses one of them."""
        undo, fresh = [], []
        prefix = (client,)
        for name in reverse:
            new = self._first_time(self.names_seen, state, prefix, ("n", name), self.NAMES_INLINE)
            if new is None:
                break
            if not new:
                continue
            undo.append(lambda item=("n", name): self._forget(self.names_seen, state, prefix, item))
            address = reverse_address(name)
            if address is None:
                fresh.append(("zone", None, None))
                continue
            new_address = self._first_time(self.names_seen, state, prefix, ("a", str(address)), self.NAMES_INLINE)
            if new_address is None:
                break
            if not new_address:
                fresh.append(("name", address, None))          # a new name for an address already named
                continue
            undo.append(lambda item=("a", str(address)): self._forget(self.names_seen, state, prefix, item))
            entry = self._block_entry(client, state, _block_of(address), undo)
            if entry is None:
                break
            fresh.append(("address", address, entry))
        else:
            return fresh
        for step in reversed(undo):
            step()
        return None

    def _block_entry(self, client: str, state: _ReverseClient, block, undo: list) -> list | None:
        """The block's [block, addresses, lowest, highest], created when new; None when the disk budget refuses."""
        blocks = state.blocks
        if blocks is not None:
            entry = blocks.get(block)
            if entry is not None:
                return entry
            if len(blocks) < self.BLOCKS_INLINE:
                entry = blocks[block] = [block, 0, None, None]
                undo.append(lambda: blocks.pop(block, None))
                return entry
            moved = [*blocks.values()]
            for at, each in enumerate(moved):
                if not self.blocks.put((client, str(each[0])), each):
                    for done in moved[:at]:
                        self.blocks.pop((client, str(done[0])))
                    return None
            state.blocks = None
            undo.append(lambda: self._unspill_blocks(client, state, moved))
        key = (client, str(block))
        entry = self.blocks.get(key)
        if entry is not None:
            return entry
        entry = [block, 0, None, None]
        if not self.blocks.put(key, entry):
            return None
        undo.append(lambda: self.blocks.pop(key))
        return entry

    def _unspill_blocks(self, client: str, state: _ReverseClient, moved: list) -> None:
        for each in moved:
            self.blocks.pop((client, str(each[0])))
        state.blocks = {each[0]: each for each in moved}

    @staticmethod
    def _count(state: _ReverseClient, kind: str, address, entry: list | None) -> None:
        state.n_names += 1
        if kind == "zone":
            state.zone_names += 1
            return
        if kind == "name":
            return
        state.addresses += 1
        if is_internal(address):
            state.internal += 1
        span = state.vspan.get(address.version)
        if span is None:
            state.vspan[address.version] = [address, address]
        else:
            span[0], span[1] = min(span[0], address), max(span[1], address)
        if entry[1] == 0:
            state.n_blocks += 1
        entry[1] += 1
        entry[2] = address if entry[2] is None else min(entry[2], address)
        entry[3] = address if entry[3] is None else max(entry[3], address)
        state.densest = max(state.densest, entry[1])

    def _ranked_on_disk(self, wanted: set[str]) -> dict[str, list]:
        """The five densest blocks of each wanted client whose blocks are on the store, read a client at a time."""
        ranked: dict[str, list] = {}
        for (client, _block), entry in self.blocks.grouped():
            if client not in wanted or not entry[1]:
                continue
            top = ranked.setdefault(client, [])
            insort(top, entry, key=_block_rank)
            del top[5:]
        return ranked

    def finalize(self):
        out = []
        candidates = sorted(self.clients.keys(candidates=True))
        spilled = {client for client in candidates if self.clients.peek(client).blocks is None}
        on_disk = self._ranked_on_disk(spilled) if spilled else {}
        for client in candidates:
            state = self.clients.peek(client)
            if state.blocks is not None:
                ranked = sorted((e for e in state.blocks.values() if e[1]), key=_block_rank)[:5]
            else:
                ranked = on_disk.get(client, [])
            densest = state.densest
            if densest < self.DENSE_BLOCK and state.n_names < self.MIN_DISTINCT:
                continue
            addresses = state.addresses
            claim = (f"{client} sent {state.queries} DNS question record(s) for {state.n_names} distinct "
                     f"reverse-lookup name(s) ({state.span.text()}; question types: "
                     f"{_tally(Counter(state.types))}). {addresses} of the names stand for single addresses in "
                     f"{state.n_blocks} block(s)")
            if state.zone_names:
                claim += f"; {state.zone_names} name a reverse zone rather than one address"
            # a block is named only with the records showing its lowest and highest address (blocks past BLOCK_STORES
            # keep none, and are counted instead)
            unstored = {item[0]: item[2] for item in state.top_blocks}
            listed = [entry for entry in ranked if entry[0] in state.block_ends or entry[0] in unstored]
            shown = [f"{block} ({count} address(es), {low} – {high})" if block in state.block_ends
                     else f"{block} ({count} address(es); its range is not cited)"
                     for block, count, low, high in listed]
            claim += (f". Densest: {'; '.join(shown)}" if shown else "")
            if len(listed) < len(ranked):
                claim += (f"{';' if shown else '. Of the densest blocks,'} {len(ranked) - len(listed)} "
                          f"{'more ' if shown else ''}keep no cited record and are not named")
            claim += "."
            spans = []
            for version in (4, 6):
                span = state.vspan.get(version)
                if state.n_blocks > 1 and span:
                    claim += f" IPv{version} addresses span {span[0]} – {span[1]}."
                    spans.append(state.vends[version])
            if state.n_blocks:
                claim += f" {state.internal} of the {addresses} addresses are in internal ranges."
            if densest >= self.DENSE_BLOCK:
                claim += (" Questions for the names of many addresses packed into one block are the shape of a "
                          "reverse-DNS sweep (host discovery by name).")
            else:
                claim += (f" No block holds {self.DENSE_BLOCK} or more of them: lookups spread across many blocks "
                          f"are the shape of a server resolving its peers' names as well as of a sparse sweep.")
            claim += " The question records do not show whether names were returned."
            dense_store = state.block_examples.get(listed[0][0]) if listed else None
            ends = [state.ends, *spans, *(state.block_ends[entry[0]] for entry in listed if entry[0] in state.block_ends)]
            evs, missing = self._cite(ends, [unstored[entry[0]] for entry in listed if entry[0] in unstored],
                                      [*(dense_store.ids() if dense_store else []), *state.examples.ids()])
            claim += cited_phrase(len(evs), state.queries, not missing, "question records", "question record")
            if missing:
                claim += (" A record bounding a stated span or address range was not kept for citation; the values are "
                          "computed from every record.")
            e0 = evs[0]
            notes = ["ATT&CK context: " + ("T1018 (the client is in an internal range)" if _internal(client)
                                           else "T1590.002 (the client is outside the internal ranges)")]
            predicate = [pf(e, n) for e in evs[:2] for n in ("dns.question.name", "dns.question.type", "source.ip")
                         if e.has(n)]
            out.append(Match(self.id, claim, self.claim_type, evs, predicate, e0.ts, self.severity, self.lane,
                             "high", e0.entities(), notes=notes, group_key=client))
        return out


def _block_of(address):
    """The IPv4 /24 or IPv6 /64 holding an address."""
    return ipaddress.ip_network(f"{address}/{24 if address.version == 4 else 64}", strict=False)


# ---------------------------------------------------------------------------------------- NXDOMAIN burst
RESOLVER_PHRASE = "it acts as a DNS server for other addresses (a resolver or forwarder)"


class _Address:
    """Everything the NXDOMAIN rule holds for one address: the answers it was sent as a client, and the answers it
    sent others as an answering server."""

    __slots__ = ("buckets", "busiest", "codes", "counts", "decided", "ends", "late", "named_servers", "names_capped",
                 "nx_names", "nx_sent", "nx_sent_total", "nx_unnamed", "sent_capped", "served", "servers", "span",
                 "time_capped", "times", "top")

    def __init__(self):
        self.ends = Ends()                          # the NXDOMAIN answers bounding the span
        self.top: list[tuple[str, str]] = []        # the longest distinct NXDOMAIN names, each with its record
        self.named_servers = Named(5)               # the first answering servers, each with a record
        self.codes: Counter = Counter()
        # NXDOMAIN times held: every time in an unsettled bucket or a bucket that can still hold the peak
        self.times: list[int] = []
        self.nx_names: set[str] = set()
        self.nx_unnamed = 0
        self.servers: Counter = Counter()
        self.span = _Span()
        # aligned ten-minute bucket -> its earliest NXDOMAIN records (buckets held, as for `times`)
        self.buckets: dict[int, _Examples] = {}
        # bucket -> NXDOMAIN answers in it (buckets held), and the busiest bucket so far
        self.counts: dict[int, int] = {}
        self.busiest = 0
        self.decided: int | None = None             # buckets up to this one are decided (held or released)
        self.late = False                           # answers were read after their interval was decided
        self.time_capped = False
        self.names_capped = False
        # as an answering server: client -> answer records with a recorded rcode it sent that client, and
        # bucket -> client -> times of the NXDOMAIN answers it sent (buckets that can hold its own peak; capped)
        self.served: Counter = Counter()
        self.nx_sent: dict[int, dict[str, list[int]]] = {}
        self.nx_sent_total = 0
        self.sent_capped = False


class DnsNxdomainBurst(_DnsAggregate):
    id = "net.dns_nxdomain_burst"
    version = "5"
    title = "Many NXDOMAIN answers to one client within ten minutes"
    required_fields = ()
    severity, lane = "high", "lead"
    attack = ("T1568.002",)
    benign = ("search-domain suffixing: each short name is tried under every configured search domain first",
              "misconfigured or uninstalled software retrying a name that no longer exists",
              "DNS blocklist and reputation lookups, whose 'not listed' reply is NXDOMAIN",
              "a resolver or forwarder that receives the replies on behalf of many clients",
              "browser probes of random names that detect NXDOMAIN rewriting")
    next_checks = ("the names that did resolve for the client in the same minutes, and the connections to them",
                   "the host process that issued the lookups",
                   "whether the client is a resolver forwarding for others")
    WINDOW = timedelta(minutes=10)
    MIN_BURST = 50
    TIME_CAP = 2_000_000        # NXDOMAIN times held per client; a peak above it is a lower bound
    SENT_CAP = 2_000_000        # NXDOMAIN answer times held per answering server, over all its clients
    CLIENTS_LISTED = 12
    # How far behind the newest answer read an answer may still arrive. The sweep reads each target's partitions in
    # time order and a DNS record's time is its packet time, so within one target a record arrives at most a
    # sensor-to-index delay (seconds to minutes) behind newer ones; an hour is far above that. A ten-minute interval
    # is settled once the newest record read is this much past the end of the next interval. Records that still
    # arrive into a settled interval (another sensor target read later) are counted and stated (`late`).
    SETTLE = timedelta(hours=1)
    HOT = HOT_COUNT  # count cap; sized in bytes by the hunt's memory budget
    card: ClassVar[dict] = {
        "behavior": "one client received many NXDOMAIN (name does not exist) answers within a ten-minute "
                    "interval, the shape of algorithmically generated domain lookups",
        "telemetry": "dns_query answer records: dns.response_code, destination.ip (the client), source.ip (the "
                     "server), dns.question.name (optional, for distinct names); transaction records use "
                     "source.ip as the client (Suricata EVE dns v2 answer records: present in the lab profile)",
        "fidelity": "direct observation of the rcode the client was sent; a deviation in volume, not proof of "
                    "malware",
        "benign_and_cost": "search-domain suffixing, stale software, DNSBL lookups, forwarders; one grouped "
                           "finding per client with the NXDOMAIN share as denominator. A client that itself sent DNS "
                           "answers to other addresses in the same data is said to act as a DNS server, and its finding "
                           "lists the clients it sent NXDOMAIN answers to in the peak interval (the original askers), "
                           "marking those with their own finding",
        "query_cost": "none beyond the sweep",
        "next_pivot": "the names that did resolve for the client during the burst and the connections that "
                      "followed",
        "adds": "no other rule reads the reply code",
        "research_basis": "ATT&CK Enterprise 20.0 T1568.002 (Domain Generation Algorithms); NXDOMAIN-volume DGA "
                          "detection as described in public DNS hunting guidance",
        "retrieval": "the sweep retrieves every record of a network target in each partition with no field "
                     "filter, a superset of what this evaluator reads",
        "thresholds": "at least 50 NXDOMAIN answers to one client inside any half-open ten-minute interval "
                      "[t, t+10m), measured on exact record times. A host's ordinary failures (search-domain "
                      "suffixes, browser probes) come in handfuls per minute; DGA families try hundreds of "
                      "candidates per cycle",
        "citations": "records from the peak ten-minute interval. Each client keeps the earliest 20 NXDOMAIN "
                     "records of every aligned ten-minute bucket that can still hold the peak. The peak interval "
                     "overlaps two buckets and is the earliest interval with its count, so its first bucket's records "
                     "before it are fewer than its records in the second bucket (an interval starting at the first "
                     "bucket's earliest record would otherwise hold at least as many); the two stores therefore hold "
                     "20 records inside it",
        "state": "one record per address, as a client and as an answering server, kept for the whole hunt window: "
                 "the most recently used in memory, the rest on the rule's disk spill. Exact times and citation "
                 "candidates are kept only for the buckets of the last hour and for buckets in a pair whose count "
                 "reaches max(50, the client's busiest bucket), which is the only place the peak can be; a settled "
                 "bucket below that is dropped from a record in memory, and every peak is decided at the end of the "
                 "hunt",
    }

    def __init__(self):
        super().__init__()
        self.addresses = KeyedStore(self, "dns_nx_addresses", self.HOT, candidate=self.reportable)
        self.watermark: int | None = None      # newest answer time read (microseconds)
        self._pruned_at: int | None = None

    def reportable(self, state: _Address) -> bool:
        """Whether some ten-minute interval of the address's held answers can reach the threshold: an interval lies
        within two adjacent buckets, so no pair reaching it means no burst."""
        counts = state.counts
        return any(n + counts.get(b + 1, 0) >= self.MIN_BURST for b, n in counts.items())

    @property
    def times(self) -> dict[str, list[int]]:
        """Every client's held NXDOMAIN times (reads the whole store: for tests and small hunts)."""
        return {address: state.times for address, state in self.addresses.items() if state.times}

    def retained_events(self) -> list[TypedEvent]:
        return []

    def consume(self, events):
        batch = [e for e in events if e.family in self.families]
        has_answers = any(role(e) == "answer" for e in batch)
        for event in batch:
            record_role = role(event)
            if record_role == "query":
                if not has_answers:
                    # no answer records at all alongside these questions: the replies are not in the telemetry
                    self.missing_required += 1
                continue
            if record_role is None:
                self.missing_required += 1
                continue
            client, server = endpoints(event, record_role)
            code = rcode(event.get("dns.response_code"))
            if client is None or code is None:
                self.missing_required += 1
                continue
            self.evaluated += 1
            state = self.addresses.setdefault(client, _Address)
            sender = self.addresses.setdefault(server, _Address) if server and server != client else None
            if state is None or (server and server != client and sender is None):
                self._disk_full()
                continue
            state.codes[code] += 1
            if sender is not None:
                sender.served[client] += 1
            if code != "NXDOMAIN":
                continue
            micros = _micros(event.ts)
            bucket = micros // (self.WINDOW // _US)
            self.watermark = micros if self.watermark is None else max(self.watermark, micros)
            if sender is not None:
                if sender.nx_sent_total < self.SENT_CAP:
                    sender.nx_sent_total += 1
                    sender.nx_sent.setdefault(bucket, {}).setdefault(client, []).append(micros)
                else:
                    sender.sent_capped = True
            if state.decided is not None and bucket <= state.decided + 1:
                # its interval (or the neighbour a decided interval was judged with) was already decided from the
                # answers read before: the finding says so
                state.late = True
                self.note_limit("late", "NXDOMAIN answers arrived for ten-minute intervals already released (a "
                                        "target read after another one); those clients' peaks are computed from "
                                        "the answers still held and may be lower bounds")
            counts = state.counts
            counts[bucket] = counts.get(bucket, 0) + 1
            state.busiest = max(state.busiest, counts[bucket])
            timed = len(state.times) < self.TIME_CAP
            if timed:
                state.times.append(micros)
            else:
                state.time_capped = True
                self.note_limit("times", f"a client's NXDOMAIN times reached {self.TIME_CAP:,} held at once; its "
                                         f"peak is a lower bound")
            names = question_names(event)
            if names is None:
                state.nx_unnamed += 1
            else:
                held = state.nx_names
                for name in names:
                    if name in held:
                        continue
                    if len(held) < NAME_CAP:
                        held.add(name)
                        _top(state.top, name, event, self.holds, 5)
                    else:
                        state.names_capped = True   # the per-client cap: the count is stated as a lower bound
            if server:
                state.servers[server] += 1
                self._named(state.named_servers, server, event)
            state.span.add(event.ts)
            self.bounds.offer_at(client, state.ends, event)
            if timed:
                # the peak is found among the held times only, so only their buckets can be cited
                self._remember(state.buckets.setdefault(bucket, _Examples()), event)
        self._release()
        self._trim()
        return []

    def _release(self) -> None:
        """Drop, from the address records in memory, every settled bucket that cannot hold the client's peak. The
        peak is at least the busiest bucket (the interval from that bucket's first answer holds all of it) and lies
        within two adjacent buckets, so a bucket is needed only while one of its pairs reaches max(MIN_BURST,
        busiest): below that, no interval through it can reach the peak or the publication threshold. A bucket is
        decided once the newest answer read is SETTLE past the end of its right neighbour, when both its pairs are
        final. Records on disk keep their buckets until they are read back; finalize decides every peak from the
        times each record holds, so the release only saves memory."""
        window = self.WINDOW // _US
        if self.watermark is None:
            return
        settled = (self.watermark - self.SETTLE // _US) // window          # buckets below this one are complete
        if self._pruned_at is not None and settled <= self._pruned_at:
            return
        self._pruned_at = settled
        upto = settled - 2                                                  # their right neighbour is complete too
        for state in self.addresses.hot.values():
            counts = state.counts
            if counts:
                floor = max(self.MIN_BURST, state.busiest)
                released = {b for b in counts if b <= upto
                            and counts.get(b - 1, 0) + counts[b] < floor and counts[b] + counts.get(b + 1, 0) < floor}
                state.decided = upto if state.decided is None else max(state.decided, upto)
                if released:
                    for b in released:
                        del counts[b]
                        state.buckets.pop(b, None)
                    state.times = [t for t in state.times if t // window not in released]
            # An answering server's sent times are needed only where its own peak as a client can be: a held bucket,
            # or the bucket after one (a peak interval starting in a bucket runs into the next).
            sent = state.nx_sent
            for b in [b for b in sent if b <= upto and b not in counts and b - 1 not in counts]:
                state.nx_sent_total -= sum(len(times) for times in sent.pop(b).values())

    def _peak_records(self, state: _Address, start: int) -> list[TypedEvent]:
        window = self.WINDOW // _US
        candidates: dict[str, datetime] = {}
        for bucket in (start // window, start // window + 1):
            store = state.buckets.get(bucket)
            for event_id, ts in store.refs() if store else ():
                if start <= _micros(ts) < start + window:
                    candidates[event_id] = ts
        ids = [event_id for event_id, _ts in sorted(
            candidates.items(), key=lambda item: (item[1], item[0]),
        )[:EXAMPLE_LIMIT]]
        return self._events(ids)

    def _peak(self, times: list[int]) -> tuple[int, int]:
        """Most records in any half-open interval [t, t + WINDOW), and that interval's start."""
        window = self.WINDOW // _US
        times.sort()
        best, start, j = 0, times[0], 0
        for i, t in enumerate(times):
            while t - times[j] >= window:
                j += 1
            if i - j + 1 > best:
                best, start = i - j + 1, times[j]
        return best, start

    def _as_server(self, address: str, state: _Address, start: int, bursts: dict) -> str:
        """Wording for a burst client that itself answered DNS for other addresses in the same data: it acts as a
        resolver or forwarder, so NXDOMAIN answers it received can be its upstream lookups for the clients it
        answered. Names those clients (the original askers) with the NXDOMAIN answers it sent each in the peak
        interval; '' when the address answered no other address."""
        served = state.served
        if not served:
            return ""
        window = self.WINDOW // _US
        in_peak = Counter()
        for bucket in (start // window, start // window + 1):         # the peak interval spans these two only
            for asker, times in state.nx_sent.get(bucket, {}).items():
                n = sum(1 for t in times if start <= t < start + window)
                if n:
                    in_peak[asker] += n
        text = (f" {address} also appears as the answering server: it sent {sum(served.values())} DNS answer "
                f"record(s) to {len(served)} other address(es) in the same data, so {RESOLVER_PHRASE}; NXDOMAIN "
                f"answers it received can be its upstream lookups on those clients' behalf.")
        if in_peak:
            # the clients it answered are counted, not named: their answers are not among this finding's citations
            own = sorted(set(in_peak) & bursts.keys())
            text += (f" In the peak interval it sent {sum(in_peak.values())} NXDOMAIN answer(s) to {len(in_peak)} "
                     f"client(s) (counted from answer records that are not cited"
                     + (f"; {len(own)} of those clients have their own finding" if own else "") + ").")
            if not bursts.keys() & set(in_peak):
                text += " No client it answered reached the burst threshold on its own."
        else:
            text += " It sent no NXDOMAIN answer in the peak interval."
        if state.sent_capped:
            text += " (Its sent-answer times are capped: the per-client counts are lower bounds.)"
        return text

    def finalize(self):
        out = []
        bursts: dict[str, tuple[int, int]] = {}         # every bursting client's (peak, start); read one at a time
        for address in self.addresses.keys(candidates=True):
            state = self.addresses.peek(address)
            if state.times:
                peak, start = self._peak(list(state.times))
                if peak >= self.MIN_BURST:
                    bursts[address] = (peak, start)
        for client in sorted(bursts):
            state = self.addresses.peek(client)
            peak, start = bursts[client]
            codes = state.codes
            nx, answered = codes["NXDOMAIN"], sum(codes.values())
            names = state.nx_names
            capped = " (time list capped: the peak is a lower bound)" if state.time_capped else ""
            if state.late:
                capped += (" (some of these answers were read after their ten-minute interval had been released, "
                           "from a target read later, so the peak and its citations come from the answers still "
                           "held and the peak may be a lower bound)")
            claim = (f"{client} was sent {nx} NXDOMAIN answer(s) ({nx / answered:.0%} of the {answered} answer "
                     f"record(s) to it with a recorded rcode; rcodes: {_tally(codes)}) between "
                     f"{state.span.text()}; at most {peak} of them fell within one ten-minute interval, "
                     f"starting {_iso_micros(start)}{capped}.")
            if names:
                domains = Counter(registered_domain(n) if n != "." else "." for n in names)
                at_least = "at least " if state.names_capped else ""
                claim += (f" The NXDOMAIN answers name {at_least}{len(names)} distinct name(s) under {len(domains)} "
                          f"registered domain(s) (last two labels, or three under a listed country suffix), e.g. "
                          f"{', '.join(repr(name) for name, _id in state.top)}.")
                if len(names) < 10:
                    claim += " Few distinct names repeated many times is the shape of software retrying a name "
                    claim += "that does not exist (or a dead rendezvous domain), not of generated domains."
            if state.nx_unnamed:
                claim += f" {state.nx_unnamed} NXDOMAIN answer record(s) carry no question name."
            servers = state.servers
            named = [server for server in state.named_servers.values() if server in servers]
            if named:
                claim += (f" Answering server(s): {_tally(Counter({server: servers[server] for server in named}))}"
                          f"{more(len(named), len(servers))}.")
            claim += self._as_server(client, state, start, bursts)
            claim += (" A burst of NXDOMAIN answers is the shape of algorithmically generated domain lookups and "
                      "also of search-domain suffixing, stale software and blocklist lookups.")
            # the peak interval's earliest records, all of them, beside the records the claim's span, names and
            # servers come from
            peak = [e.id for e in self._peak_records(state, start)]
            given = [*(event_id for _name, event_id in state.top),
                     *(state.named_servers.ids[server] for server in named)]
            evs, missing = self._cite(state.ends, peak, [], given,
                                      limit=len(set(peak) | set(given) | set(state.ends.ids())))
            claim += (cited_phrase(len(evs), nx, not missing, "NXDOMAIN answer records", "NXDOMAIN answer record")
                      + " The cited records are from the peak interval, with the records bounding the span and those "
                        "of the names and servers given." + bound_note(missing, state.ends))
            e0 = evs[0]
            predicate = [pf(e, n) for e in evs[:2] for n in ("dns.response_code", "destination.ip", "source.ip",
                                                             "dns.type") if e.has(n)]
            out.append(Match(self.id, claim, self.claim_type, evs, predicate, e0.ts, self.severity, self.lane,
                             "medium", e0.entities(), group_key=client))
        return out


# ---------------------------------------------------------------------------------------- tunnel shape
class _TunnelKey:
    """Everything the tunnel-shape rule holds for one (client, registered domain): counters over every distinct
    subdomain, and the distinct subdomains themselves while few (the rule's keyed store holds them beyond that)."""

    __slots__ = ("ends", "entropy", "examples", "inline", "max_label", "n_long", "queries", "span", "strong_examples",
                 "strong_long", "top_any", "top_long", "types", "unique", "untyped")

    def __init__(self):
        self.ends = Ends()                           # the records bounding the span
        self.queries = 0
        self.untyped = 0
        self.span = _Span()
        self.examples = _Examples()
        self.inline: set[tuple] | None = set()       # (subdomain,) seen, while few; None once they are on disk
        self.unique = 0                              # distinct subdomains
        self.n_long = 0                              # of them, long
        self.entropy = _FloatSum()                   # character entropy summed over the distinct long subdomains
        self.top_any: list[tuple[str, str]] = []     # the three longest distinct subdomains, with their records
        self.top_long: list[tuple[str, str]] = []    # the three longest distinct long subdomains, with their records
        self.max_label = 0
        self.types: dict[str, int] = {}              # question types of questions that carry a subdomain
        self.strong_long = 0                         # strong-type questions for long names
        self.strong_examples: _Examples | None = None


class DnsTunnelShape(_DnsAggregate):
    id = "net.dns_tunnel_shape"
    version = "5"
    title = "Query names under one registered domain from one client with a DNS-tunnel shape"
    required_fields = ()
    severity, lane = "high", "lead"
    attack = ("T1071.004", "T1572", "T1048.003", "T1132.001")
    benign = ("anti-virus, file-reputation and blocklist lookups that encode hashes or addresses into names",
              "CDN and cloud names with generated labels",
              "telemetry and licensing clients that encode identifiers into names",
              "DKIM/DMARC/SPF and _acme-challenge TXT lookups (few distinct names; not reached by these thresholds)")
    next_checks = ("the host process sending the queries",
                   ("how many other clients query the same registered domain (reputation services are queried by "
                    "many hosts; a tunnel endpoint by one)"),
                   "the registered domain's age and its authoritative name servers",
                   "the timing regularity of the queries and any answers carrying data")
    LONG_LABEL = 30
    LONG_SUBDOMAIN = 50
    MIN_UNIQUE = 50
    MIN_LONG = 20
    LONG_SHARE = 0.5
    MIN_ENTROPY = 3.5
    MIN_TYPED = 20
    TYPED_SHARE = 0.5
    VOLUME = 300
    UNUSUAL_TYPES = frozenset({"TXT", "NULL", "CNAME", "MX"})
    STRONG_TYPES = frozenset({"NULL", "CNAME", "MX"})
    STRONG_CITE = 10
    SHARED_CLIENTS = 3
    NOT_DELEGATED = frozenset({"local", "arpa"})       # mDNS and the reverse trees: no outside endpoint
    card: ClassVar[dict] = {
        "behavior": "one client sent many questions under one registered domain whose names are long, unique and "
                    "high-entropy, or whose question types are TXT/NULL/CNAME/MX/private-use: the query shape of "
                    "data encoded into names (DNS tunnelling, DNS exfiltration, DNS command and control)",
        "telemetry": "dns_query question records: dns.question.name, dns.question.type, source.ip (Suricata EVE "
                     "dns query records: present in the lab profile; the lab's names are short, so the shape is "
                     "validated by fixtures only)",
        "fidelity": "a deviation computed from typed question names and types; not proof of a tunnel. Answers are "
                    "not read, so data flowing back is not shown",
        "benign_and_cost": "reputation and anti-virus lookups have the same shape (they stay lead); one grouped "
                           "finding per (client, registered domain), or one per registered domain listing every "
                           "client when three or more clients show the shape under it",
        "query_cost": "none beyond the sweep",
        "next_pivot": "the issuing process and the domain's prevalence across clients",
        "adds": "the subdomain enumeration rule counts names only; this rule measures what the names carry",
        "research_basis": "ATT&CK Enterprise 20.0 T1071.004, T1572, T1048.003, T1132.001; public tunnel tool "
                          "behaviour (iodine NULL/TXT/CNAME/MX questions with near-63-character labels, dnscat2 "
                          "hex-encoded TXT/CNAME/MX questions, dns2tcp TXT); public DNS tunnelling hunting guidance "
                          "on label length, entropy and record-type mix",
        "retrieval": "the sweep retrieves every record of a network target in each partition with no field "
                     "filter, a superset of what this evaluator reads",
        "thresholds": "at least 50 distinct subdomains and two of four indicators: long (at least 20 distinct "
                      "names with a label of 30+ characters or 50+ characters left of the registered domain, and "
                      "at least half of the distinct names); entropy (mean character entropy of those long names "
                      "at least 3.5 bits/char); types (at least 20 questions for subdomains, and half of them, of "
                      "type TXT, NULL, CNAME, MX or private use 65280-65534); volume (at least 300 distinct subdomains). "
                      "Host names rarely carry labels over 30 characters; encoders fill labels toward the 63 limit",
        "lane_policy": "lead; high when all four indicators hold and at least 20 questions for long names are "
                       "NULL, CNAME, MX or private-use types, which clients almost never ask with long unique random "
                       "names; those questions are cited first. TXT-only shapes stay lead: hash-reputation services "
                       "answer TXT questions with this exact shape. A shared-domain finding takes the highest lane "
                       "of its members",
        "prevalence": "when 3 or more clients show the shape under one registered domain, one finding lists them "
                      "all with their counts and cites each one. A tunnel is set up on one host, at most a pair, "
                      "while deployed anti-virus, reputation and telemetry software produces the same shape on "
                      "every host it runs on; grouping keeps every member visible without one lead per endpoint",
        "limitations": "the registered domain is the last two labels (three under a short list of country "
                       "second-level suffixes), so customers of one shared hosting suffix group together; names "
                       "under .local and .arpa are not evaluated (no outside endpoint can answer them)",
        "state": "one record per (client, registered domain), counted over the whole hunt window however long its "
                 "pauses (a beacon that asks once a day is still one group): the most recently used records in "
                 "memory, the rest on the rule's disk spill, read back when the pair is asked again. Every "
                 "indicator is counted over every distinct subdomain of the pair, never a capped sample: a pair's "
                 "distinct subdomains are a set in its record while few and on the rule's keyed store beyond that, "
                 "so a tunnel that starts after any number of ordinary names under the same domain still counts",
    }
    HOT = HOT_COUNT  # count cap; sized in bytes by the hunt's memory budget
    ASKERS_HOT = HOT_COUNT  # count cap; sized in bytes by the hunt's memory budget
    NAMES_INLINE = 256          # distinct subdomains a pair keeps in its own record; beyond, they are on `names`

    def __init__(self):
        super().__init__()
        self.pairs = KeyedStore(self, "dns_tunnel_pairs", self.HOT, candidate=self.reportable)
        self.askers = KeyedStore(self, "dns_tunnel_askers", self.ASKERS_HOT)     # domain -> clients that asked
        # (client, domain, subdomain) -> 1, for pairs beyond NAMES_INLINE distinct subdomains
        self.names = KeyedStore(self, "dns_tunnel_names", self.HOT)

    def reportable(self, record: _TunnelKey) -> bool:
        return record.unique >= self.MIN_UNIQUE

    def retained_events(self) -> list[TypedEvent]:
        return []

    @classmethod
    def unusual(cls, kind: str) -> bool:
        return kind in cls.UNUSUAL_TYPES or _private_type(kind)

    @classmethod
    def strong(cls, kind: str) -> bool:
        return kind in cls.STRONG_TYPES or _private_type(kind)

    def is_long(self, sub: str) -> bool:
        return len(sub) >= self.LONG_SUBDOMAIN or max(len(label) for label in sub.split(".")) >= self.LONG_LABEL

    def consume(self, events):
        for event, client, _server, names in self._questions(events):
            kind = qtype(event.get("dns.question.type"))
            if kind is None:
                self.missing_required += 1          # the type mix cannot be measured for this record
            taken = [self._name(event, client, name, kind) for name in names]     # every name, no short circuit
            if any(t is False for t in taken):
                self._disk_full()                   # a name of the record was refused: never a clean evaluation
            elif any(t is None for t in taken):
                self._names_full()
        self._trim()
        return []

    def _record(self, client: str, domain: str) -> _TunnelKey | None:
        key = (client, domain)
        record = self.pairs.get(key)
        if record is not None:
            return record
        record = _TunnelKey()
        if not self.pairs.put(key, record):
            return None
        if not self.askers.put(domain, self.askers.get(domain, 0) + 1):
            self.note_limit("askers", "the disk budget of the per-domain client counts is spent; a later domain's "
                                      "client count is a lower bound")
        return record

    def _name(self, event: TypedEvent, client: str, name: str, kind: str | None) -> bool | None:
        """Count one question name: True when counted, False when the group budget refused a new pair, None when
        the names budget refused a new distinct name (nothing of the name is counted then)."""
        labels = name.split(".")
        if labels[-1] in self.NOT_DELEGATED or len(labels) < 2:
            return True
        domain = registered_domain(name)
        record = self._record(client, domain)
        if record is None:
            return False
        sub = subdomain_part(name, domain)
        new = self._first_time(self.names, record, (client, domain), (sub,), self.NAMES_INLINE) if sub else False
        if new is None:
            return None                             # a new distinct name the disk budget cannot hold
        record.queries += 1
        if kind is None:
            record.untyped += 1
        record.span.add(event.ts)
        self.bounds.offer_at((client, domain), record.ends, event)
        self._remember(record.examples, event)
        if not sub:
            return True
        if kind is not None:
            record.types[kind] = record.types.get(kind, 0) + 1
        long_name = self.is_long(sub)
        if long_name and kind is not None and self.strong(kind):
            record.strong_long += 1
            if record.strong_examples is None:
                record.strong_examples = _Examples(self.STRONG_CITE)
            self._remember(record.strong_examples, event)
        if not new:
            return True
        record.unique += 1
        record.max_label = max(record.max_label, max(len(label) for label in sub.split(".")))
        _top(record.top_any, sub, event, self.holds)
        if long_name:
            record.n_long += 1
            record.entropy.add(entropy(sub.replace(".", "")))
            _top(record.top_long, sub, event, self.holds)
        return True

    def _assess(self, record: _TunnelKey) -> dict | None:
        """The shape of one (client, registered domain) group, or None when it is not reported."""
        unique = record.unique
        if unique < self.MIN_UNIQUE:
            return None
        n_long = record.n_long
        mean_entropy = record.entropy.total() / n_long if n_long else 0.0
        typed = Counter(record.types)
        n_typed = sum(typed.values())
        unusual = sum(n for kind, n in typed.items() if self.unusual(kind))
        indicators = []
        if n_long >= self.MIN_LONG and n_long >= self.LONG_SHARE * unique:
            indicators.append("long names")
        if n_long >= self.MIN_LONG and mean_entropy >= self.MIN_ENTROPY:
            indicators.append("high entropy")
        if unusual >= self.MIN_TYPED and n_typed and unusual >= self.TYPED_SHARE * n_typed:
            indicators.append("unusual question types")
        if unique >= self.VOLUME:
            indicators.append("volume")
        if len(indicators) < 2:
            return None
        strong = record.strong_long
        lane = "high" if len(indicators) == 4 and strong >= self.MIN_TYPED else self.lane
        return {"unique": unique, "n_long": n_long, "entropy": mean_entropy, "typed": typed, "n_typed": n_typed,
                "unusual": unusual, "strong": strong, "indicators": indicators, "lane": lane}

    def finalize(self):
        # the shape of every pair that can be reported, read one record at a time; records are read again to word
        # the findings, so only the small shape summaries are held together
        shaped: dict[str, dict[str, dict]] = defaultdict(dict)
        for key in sorted(self.pairs.keys(candidates=True)):
            found = self._assess(self.pairs.peek(key))
            if found is not None:
                shaped[key[1]][key[0]] = found
        out = []
        for domain in sorted(shaped):
            members = shaped[domain]
            if len(members) >= self.SHARED_CLIENTS:
                out.append(self._shared(domain, members, self.askers.peek(domain, 0)))
            else:
                out += [self._single(client, domain, found) for client, found in sorted(members.items())]
        return out

    def _cited(self, record: _TunnelKey, found: dict) -> tuple[list[TypedEvent], set[str]]:
        """The strong-type examples (for the high lane), the records of the example names and the span's bounds,
        then the earliest records."""
        strong_store = record.strong_examples
        strong = strong_store.ids() if found["lane"] == "high" and strong_store else []
        sample = record.top_long or record.top_any
        return self._cite(record.ends, strong, record.examples.ids(), [event_id for _name, event_id in sample])

    def _single(self, client: str, domain: str, found: dict) -> Match:
        record = self.pairs.peek((client, domain))
        unique, typed = found["unique"], found["typed"]
        claim = (f"{client} sent {record.queries} DNS question(s) for {unique} distinct subdomain(s) "
                 f"under '{domain}' ({record.span.text()}). {found['n_long']} of the distinct names have a label "
                 f"of {self.LONG_LABEL}+ characters or {self.LONG_SUBDOMAIN}+ characters left of the domain "
                 f"(longest label {record.max_label}); mean character entropy of those names "
                 f"{found['entropy']:.2f} bits/char; {found['unusual']} of {found['n_typed']} typed question(s) for "
                 f"subdomains are TXT, NULL, CNAME, MX or private-use types (question types: "
                 f"{_tally(typed) if typed else 'none recorded'}).")
        if record.untyped:
            claim += f" {record.untyped} question(s) carry no question type."
        claim += (f" Indicators met: {', '.join(found['indicators'])}. This is the query shape of data encoded into "
                  f"names (DNS tunnelling or exfiltration); reputation and anti-virus lookups that encode hashes look "
                  f"the same, so it is a deviation, not proof. The registered domain is the last two labels (three "
                  f"under a listed country suffix).")
        sample = record.top_long or record.top_any
        claim += f" Examples: {', '.join(repr(sub + '.' + domain) for sub, _id in sample)}."
        if found["lane"] == "high":
            claim += (f" {found['strong']} questions for long names are NULL, CNAME, MX or private-use types, which "
                      f"clients almost never ask with long unique names; examples of them are cited.")
        evs, missing = self._cited(record, found)
        claim += cited_phrase(len(evs), record.queries, not missing, "questions", "question") + bound_note(
            missing, record.ends)
        predicate = [pf(e, n) for e in evs[:2] for n in ("dns.question.name", "dns.question.type", "source.ip")
                     if e.has(n)]
        return Match(self.id, claim, self.claim_type, evs, predicate, evs[0].ts, self.severity, found["lane"],
                     "medium", evs[0].entities(), notes=[f"indicators: {', '.join(found['indicators'])}"],
                     group_key=f"{client}|{domain}")

    def _shared(self, domain: str, members: dict[str, dict], askers: int) -> Match:
        """One finding for a shape many clients share; every member is listed, cited and keeps its lane."""
        clients = sorted(members)
        lane = "high" if any(found["lane"] == "high" for found in members.values()) else self.lane
        high = [client for client in clients if members[client]["lane"] == "high"]
        listed = ", ".join(f"{c} ({members[c]['unique']} names)" for c in clients[:10])
        more = f" and {len(clients) - 10} more (all listed in the notes)" if len(clients) > 10 else ""
        records = [self.pairs.peek((c, domain)) for c in clients]
        first, last = min(r.span.first for r in records), max(r.span.last for r in records)
        ends = Ends()
        for record in records:
            ends.fold(record.ends)
        askers = max(askers, len(clients))
        of_askers = f"at least {askers}" if "askers" in self.limits else str(askers)
        claim = (f"{len(clients)} of the {of_askers} clients that queried '{domain}' sent questions with a DNS-tunnel "
                 f"shape under it ({first.isoformat()} – {last.isoformat()}): {listed}{more}. The same encoded-name "
                 f"shape from many hosts to one domain is typical of deployed software that encodes hashes or "
                 f"identifiers into names (anti-virus, reputation, telemetry); a tunnel usually runs from one or two "
                 f"hosts, so a member whose volume, types or timing differ from the rest is the one to check.")
        if high:
            claim += (f" {', '.join(high)} also sent at least {self.MIN_TYPED} NULL, CNAME, MX or private-use "
                      f"questions for long names with all four indicators met.")
        claim += " The registered domain is the last two labels (three under a listed country suffix)."
        cited: dict[str, TypedEvent] = {}
        for client in clients:
            found = members[client]
            per_client, _missing = self._cited(self.pairs.peek((client, domain)), found)
            take = per_client if found["lane"] == "high" else per_client[:1]
            cited.update((e.id, e) for e in take)
        # the records bounding the stated span, across the members
        cited.update((e.id, e) for e in self.load(ends.ids()))
        evs = sorted(cited.values(), key=lambda e: (e.ts, e.id))
        queries = sum(r.queries for r in records)
        claim += (f" {len(evs)} of the members' {queries} questions are cited: at least one per member, every "
                  f"example of a high-lane member, and the records bounding the span when the stage holds them.")
        notes = [f"{c}: {members[c]['unique']} distinct subdomains, {members[c]['n_long']} long, indicators "
                 f"{', '.join(members[c]['indicators'])}; lane {members[c]['lane']}" for c in clients]
        predicate = [pf(e, n) for e in evs[:2] for n in ("dns.question.name", "dns.question.type", "source.ip")
                     if e.has(n)]
        return Match(self.id, claim, self.claim_type, evs, predicate, evs[0].ts, self.severity, lane, "medium",
                     evs[0].entities(), notes=notes, group_key=f"*|{domain}")


def _private_type(kind: str) -> bool:
    """Question types in the private-use range 65280-65534 (RFC 6895), which some tunnel tools use."""
    return kind.startswith("TYPE") and kind[4:].isdigit() and 65280 <= int(kind[4:]) <= 65534


DNS_PLAYBOOKS = [DnsZoneTransferOrAnyRequest, DnsReverseLookupSweep, DnsNxdomainBurst, DnsTunnelShape]
