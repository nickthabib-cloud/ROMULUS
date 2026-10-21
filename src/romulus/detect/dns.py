"""DNS reconnaissance and DNS channel-shape aggregates over typed `dns_query` records.

Typed fields read (no record text is ever searched):
- `dns.type`: the record's role. `query` (or `request`) is a question sent by the client, so the client is
  `source.ip` and the server `destination.ip`. `answer` (or `response`) is the server's reply, so the client is
  `destination.ip` and the server `source.ip`. A record with no `dns.type` is a whole-transaction record (one
  session-level view of a question and its reply, as a session indexer produces); its `source.ip` is the client
  that initiated the session. Any other role value is not evaluated and is counted as missing.
- `dns.question.name`, `dns.question.type`: the question. Rules that read names and types read them from question
  records (queries and transaction records) only: in some sensor output formats an answer record carries the name
  and type of one answer resource record rather than of the question.
- `dns.response_code`: the reply's rcode, read from answer and transaction records only.
- `suricata.flow_id` or `network.community_id`: the flow, used only to tell whether an answer record's question is
  already present as a query record.

Coverage: a record a rule needs but cannot evaluate (no client address, no name, no type where the type decides,
an answer whose question was not retrieved as a query, or query records with no answers in the same batch for the
answer-based rule) is counted as missing, so the rule's coverage for that partition is partial, never a clean
negative. Aggregates count across every partition of the hunt window; cited examples are the earliest records by
(time, id), so output does not depend on the order records arrive in.
"""
from __future__ import annotations

import ipaddress
import math
from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from typing import ClassVar

from romulus.detect.base import Match, Playbook, pf
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
    """The earliest `limit` records of a group by (time, id), whatever order they arrive in."""

    __slots__ = ("items", "limit")

    def __init__(self, limit: int = EXAMPLE_LIMIT):
        self.limit = limit
        self.items: dict[str, TypedEvent] = {}

    def add(self, event: TypedEvent) -> None:
        self.items[event.id] = event
        if len(self.items) > self.limit * 4:
            self.items = {e.id: e for e in self.sorted()}

    def sorted(self) -> list[TypedEvent]:
        return sorted(self.items.values(), key=lambda e: (e.ts, e.id))[: self.limit]


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


# ------------------------------------------------------------------------------------------------ base
class _DnsAggregate(Playbook):
    kind = "aggregate"
    anchor_class = "network_observation"
    claim_type = "aggregate_observation"
    families = ("dns_query",)

    def __init__(self):
        super().__init__()
        self._prev_query_flows: set = set()
        self.examples: dict[tuple, _Examples] = defaultdict(_Examples)

    def retained_events(self) -> list[TypedEvent]:
        return [e for store in self.examples.values() for e in store.items.values()]

    def _cite(self, key: tuple) -> list[TypedEvent]:
        return self.examples[key].sorted()

    def _questions(self, events: list[TypedEvent]):
        """Yield (event, client, server, name) for every question record. An answer record whose flow carries a
        query record in this batch or the one before is that query's reply and is skipped; any other answer
        record is counted as missing (its question is not in the retrieved telemetry as a query record)."""
        batch = [e for e in events if e.family in self.families]
        query_flows = {flow_key(e) for e in batch if role(e) == "query"} - {None}
        known = query_flows | self._prev_query_flows
        self._prev_query_flows = query_flows
        for event in batch:
            record_role = role(event)
            if record_role == "answer":
                key = flow_key(event)
                if key is None or key not in known:
                    self.missing_required += 1
                continue
            if record_role is None:
                self.missing_required += 1
                continue
            client, server = endpoints(event, record_role)
            name = qname(event.get("dns.question.name"))
            if client is None or name is None:
                self.missing_required += 1
                continue
            self.evaluated += 1
            yield event, client, server, name


# ---------------------------------------------------------------------------------------- zone transfer and ANY
class DnsZoneTransferOrAnyRequest(_DnsAggregate):
    id = "net.dns_zone_transfer_or_any_request"
    version = "1"
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
                       "NOERROR answer (the server answered a zone-transfer question from an outside party). External "
                       "requests that were refused or whose answer is not retrieved stay lead: internet scanners "
                       "try AXFR routinely, and the request alone does not show exposure",
    }

    def __init__(self):
        super().__init__()
        self.requests: dict[tuple, Counter] = defaultdict(Counter)        # key -> qtype counts of questions
        self.replies: dict[tuple, Counter] = defaultdict(Counter)         # key -> (qtype, rcode) counts
        self.transports: dict[tuple, set] = defaultdict(set)
        self.any_names: dict[tuple, set[str]] = defaultdict(set)
        self.spans: dict[tuple, _Span] = defaultdict(_Span)

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
            name = qname(event.get("dns.question.name")) or ""
            if question_type in self.TRANSFER_TYPES:
                key = (client, server, "transfer", name)
            else:
                key = (client, server, "any", "")
                if name and len(self.any_names[key]) < NAME_CAP:
                    self.any_names[key].add(name)
            if record_role in ("query", "transaction"):
                self.requests[key][question_type] += 1
            if record_role == "answer" or (record_role == "transaction" and event.has("dns.response_code")):
                code = rcode(event.get("dns.response_code")) or "not recorded"
                self.replies[key][(question_type, code)] += 1
            transport = event.get("network.transport")
            if transport:
                self.transports[key].add(str(transport).lower())
            self.spans[key].add(event.ts)
            self.examples[key].add(event)
        return []

    def finalize(self):
        out = []
        for key in sorted(set(self.requests) | set(self.replies)):
            client, server, kind, zone = key
            asked, replies = self.requests.get(key, Counter()), self.replies.get(key, Counter())
            types = sorted(set(asked) | {t for t, _c in replies})
            transfer = kind == "transfer"
            if transfer:
                subject = f"for zone '{zone}'" if zone else "for a zone whose name is not recorded"
            else:
                names = sorted(self.any_names.get(key, ()))
                shown = ", ".join(f"'{_short(n)}'" for n in names[:5]) + (f" and {len(names) - 5} more"
                                                                         if len(names) > 5 else "")
                subject = f"for {len(names)} distinct name(s) ({shown})" if names else "for names not recorded"
            if asked:
                claim = (f"{client} sent {sum(asked.values())} DNS question record(s) ({_tally(asked)}) {subject} "
                         f"to {server} ({self.spans[key].text()}).")
            else:
                claim = (f"{client} received {sum(replies.values())} answer record(s) from {server} to "
                         f"{'/'.join(types)} question(s) {subject} ({self.spans[key].text()}); the question records "
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
            if "ANY" in types and client_internal is False and "tcp" not in self.transports.get(key, set()):
                notes.append("an ANY question over UDP from outside the internal ranges may carry a spoofed source "
                             "address (the request shape of DNS reflection, T1498.002)")
            if transfer and client_internal is False and server_internal and accepted:
                lane, severity = "high", "high"
                claim += (f" The client is outside the internal address ranges and the server ({server}) is inside "
                          f"them.")
            else:
                lane, severity = self.lane, self.severity
            evs = self._cite(key)
            e0 = evs[0]
            predicate = [pf(e, name) for e in evs[:2] for name in ("dns.question.type", "dns.question.name",
                                                                  "dns.response_code", "source.ip", "destination.ip")
                         if e.has(name)]
            match = Match(self.id, claim, self.claim_type, evs, predicate, e0.ts, severity, lane, "high",
                          e0.entities(), notes=notes,
                          group_key=f"{client}|{server}|{zone}" if transfer else f"{client}|{server}|ANY")
            out.append(match)
        return out


def _tally(counts: Counter) -> str:
    return ", ".join(f"{name} x{n}" for name, n in sorted(counts.items(), key=lambda item: (-item[1], str(item[0]))))


# ---------------------------------------------------------------------------------------- reverse-lookup sweep
class DnsReverseLookupSweep(_DnsAggregate):
    id = "net.dns_reverse_lookup_sweep"
    version = "1"
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
                "enumeration rule no longer counts reverse-tree names, so each sweep is reported once",
        "research_basis": "ATT&CK Enterprise 20.0 T1018 (Remote System Discovery) and T1590.002 (DNS); nmap -sL "
                          "and -R reverse resolution; RFC 1035 section 3.5 and RFC 3596 section 2.5 for the "
                          "reverse name formats",
        "retrieval": "the sweep retrieves every record of a network target in each partition with no field "
                     "filter, a superset of what this evaluator reads",
        "thresholds": "reported when one IPv4 /24 or IPv6 /64 holds at least 32 of the client's distinct reverse "
                      "addresses (an eighth of a /24: a deliberate sweep, rarely reached by a server resolving its "
                      "peers), or when the client asked for at least 100 distinct reverse names anywhere (the "
                      "threshold the subdomain enumeration rule applied to the reverse trees before they moved "
                      "here, so nothing it reported is lost)",
    }

    def __init__(self):
        super().__init__()
        self.names: dict[str, set[str]] = defaultdict(set)
        self.blocks: dict[str, dict] = defaultdict(lambda: defaultdict(set))
        self.zone_names: dict[str, int] = defaultdict(int)
        self.types: dict[str, Counter] = defaultdict(Counter)
        self.queries: dict[str, int] = defaultdict(int)
        self.spans: dict[str, _Span] = defaultdict(_Span)

    def consume(self, events):
        for event, client, _server, name in self._questions(events):
            if reverse_zone(name) is None:
                continue
            key = (client,)
            self.queries[client] += 1
            self.types[client][qtype(event.get("dns.question.type")) or "type not recorded"] += 1
            self.spans[client].add(event.ts)
            self.examples[key].add(event)
            names = self.names[client]
            if name in names or len(names) >= NAME_CAP:
                continue
            names.add(name)
            address = reverse_address(name)
            if address is None:
                self.zone_names[client] += 1
                continue
            prefix = 24 if address.version == 4 else 64
            block = ipaddress.ip_network(f"{address}/{prefix}", strict=False)
            self.blocks[client][block].add(address)
        return []

    def finalize(self):
        out = []
        for client in sorted(self.names):
            names = self.names[client]
            blocks = self.blocks.get(client, {})
            ranked = sorted(blocks.items(), key=lambda item: (-len(item[1]), item[0].version, item[0]))
            densest = len(ranked[0][1]) if ranked else 0
            if densest < self.DENSE_BLOCK and len(names) < self.MIN_DISTINCT:
                continue
            addresses = sum(len(a) for a in blocks.values())
            capped = " at least" if len(names) >= NAME_CAP else ""
            claim = (f"{client} sent {self.queries[client]} DNS question record(s) for{capped} {len(names)} distinct "
                     f"reverse-lookup name(s) ({self.spans[client].text()}; question types: "
                     f"{_tally(self.types[client])}). {addresses} of the names stand for single addresses in "
                     f"{len(blocks)} block(s)")
            if self.zone_names.get(client):
                claim += f"; {self.zone_names[client]} name a reverse zone rather than one address"
            shown = []
            for block, members in ranked[:5]:
                low, high = min(members), max(members)
                shown.append(f"{block} ({len(members)} address(es), {low} – {high})")
            claim += (f". Densest: {'; '.join(shown)}." if shown else ".")
            for version in (4, 6):
                members = [a for block, found in blocks.items() if block.version == version for a in found]
                if len(blocks) > 1 and members:
                    claim += f" IPv{version} addresses span {min(members)} – {max(members)}."
            internal = sum(1 for members in blocks.values() for a in members if is_internal(a))
            if blocks:
                claim += f" {internal} of the {addresses} addresses are in internal ranges."
            if densest >= self.DENSE_BLOCK:
                claim += (" Questions for the names of many addresses packed into one block are the shape of a "
                          "reverse-DNS sweep (host discovery by name).")
            else:
                claim += (f" No block holds {self.DENSE_BLOCK} or more of them: lookups spread across many blocks "
                          f"are the shape of a server resolving its peers' names as well as of a sparse sweep.")
            claim += " The question records do not show whether names were returned."
            evs = self._cite((client,))
            e0 = evs[0]
            notes = ["ATT&CK context: " + ("T1018 (the client is in an internal range)" if _internal(client)
                                           else "T1590.002 (the client is outside the internal ranges)")]
            predicate = [pf(e, n) for e in evs[:2] for n in ("dns.question.name", "dns.question.type", "source.ip")
                         if e.has(n)]
            out.append(Match(self.id, claim, self.claim_type, evs, predicate, e0.ts, self.severity, self.lane,
                             "high", e0.entities(), notes=notes, group_key=client))
        return out


# ---------------------------------------------------------------------------------------- NXDOMAIN burst
class DnsNxdomainBurst(_DnsAggregate):
    id = "net.dns_nxdomain_burst"
    version = "1"
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
    TIME_CAP = 2_000_000        # NXDOMAIN times kept per client; a peak above it is a lower bound
    card: ClassVar[dict] = {
        "behavior": "one client received many NXDOMAIN (name does not exist) answers within a ten-minute "
                    "interval, the shape of algorithmically generated domain lookups",
        "telemetry": "dns_query answer records: dns.response_code, destination.ip (the client), source.ip (the "
                     "server), dns.question.name (optional, for distinct names); transaction records use "
                     "source.ip as the client (Suricata EVE dns v2 answer records: present in the lab profile)",
        "fidelity": "direct observation of the rcode the client was sent; a deviation in volume, not proof of "
                    "malware",
        "benign_and_cost": "search-domain suffixing, stale software, DNSBL lookups, forwarders; one grouped "
                           "finding per client with the NXDOMAIN share as denominator",
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
    }

    def __init__(self):
        super().__init__()
        self.codes: dict[str, Counter] = defaultdict(Counter)
        self.times: dict[str, list[int]] = defaultdict(list)
        self.nx_names: dict[str, set[str]] = defaultdict(set)
        self.nx_unnamed: dict[str, int] = defaultdict(int)
        self.servers: dict[str, Counter] = defaultdict(Counter)
        self.spans: dict[str, _Span] = defaultdict(_Span)

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
            self.codes[client][code] += 1
            if code != "NXDOMAIN":
                continue
            if len(self.times[client]) < self.TIME_CAP:
                self.times[client].append(_micros(event.ts))
            name = qname(event.get("dns.question.name"))
            if name is None:
                self.nx_unnamed[client] += 1
            elif len(self.nx_names[client]) < NAME_CAP:
                self.nx_names[client].add(name)
            if server:
                self.servers[client][server] += 1
            self.spans[client].add(event.ts)
            self.examples[(client,)].add(event)
        return []

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

    def finalize(self):
        out = []
        for client in sorted(self.times):
            times = self.times[client]
            peak, start = self._peak(times)
            if peak < self.MIN_BURST:
                continue
            codes = self.codes[client]
            nx, answered = codes["NXDOMAIN"], sum(codes.values())
            names = self.nx_names.get(client, set())
            capped = " (time list capped: the peak is a lower bound)" if len(times) >= self.TIME_CAP else ""
            claim = (f"{client} was sent {nx} NXDOMAIN answer(s) ({nx / answered:.0%} of the {answered} answer "
                     f"record(s) to it with a recorded rcode; rcodes: {_tally(codes)}) between "
                     f"{self.spans[client].text()}; at most {peak} of them fell within one ten-minute interval, "
                     f"starting {_iso_micros(start)}{capped}.")
            if names:
                domains = Counter(registered_domain(n) if n != "." else "." for n in names)
                sample = sorted(names, key=lambda n: (-len(n), n))[:5]
                claim += (f" The NXDOMAIN answers name {len(names)} distinct name(s) under {len(domains)} registered "
                          f"domain(s) (last two labels, or three under a listed country suffix), e.g. "
                          f"{', '.join(_short(n) for n in sample)}.")
                if len(names) < 10:
                    claim += " Few distinct names repeated many times is the shape of software retrying a name "
                    claim += "that does not exist (or a dead rendezvous domain), not of generated domains."
            if self.nx_unnamed.get(client):
                claim += f" {self.nx_unnamed[client]} NXDOMAIN answer record(s) carry no question name."
            servers = self.servers.get(client)
            if servers:
                claim += f" Answering server(s): {_tally(Counter(dict(servers.most_common(5))))}."
            claim += (" A burst of NXDOMAIN answers is the shape of algorithmically generated domain lookups and "
                      "also of search-domain suffixing, stale software and blocklist lookups.")
            evs = self._cite((client,))
            e0 = evs[0]
            predicate = [pf(e, n) for e in evs[:2] for n in ("dns.response_code", "destination.ip", "source.ip",
                                                             "dns.type") if e.has(n)]
            out.append(Match(self.id, claim, self.claim_type, evs, predicate, e0.ts, self.severity, self.lane,
                             "medium", e0.entities(), group_key=client))
        return out


# ---------------------------------------------------------------------------------------- tunnel shape
class DnsTunnelShape(_DnsAggregate):
    id = "net.dns_tunnel_shape"
    version = "1"
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
                           "finding per (client, registered domain)",
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
                      "at least 3.5 bits/char); types (at least 20 questions and half of all of them of type TXT, "
                      "NULL, CNAME, MX or private use 65280-65534); volume (at least 300 distinct subdomains). "
                      "Host names rarely carry labels over 30 characters; encoders fill labels toward the 63 limit",
        "lane_policy": "lead; high when all four indicators hold and at least 20 questions are NULL, CNAME, MX or "
                       "private-use types, which clients almost never ask with long unique random names. TXT-only "
                       "shapes stay lead: hash-reputation services answer TXT questions with this exact shape",
        "limitations": "the registered domain is the last two labels (three under a short list of country "
                       "second-level suffixes), so customers of one shared hosting suffix group together; names "
                       "under .local and .arpa are not evaluated (no outside endpoint can answer them)",
    }

    def __init__(self):
        super().__init__()
        self.queries: dict[tuple, int] = defaultdict(int)
        self.subdomains: dict[tuple, set[str]] = defaultdict(set)
        self.long: dict[tuple, dict[str, float]] = defaultdict(dict)
        self.max_label: dict[tuple, int] = defaultdict(int)
        self.types: dict[tuple, Counter] = defaultdict(Counter)
        self.spans: dict[tuple, _Span] = defaultdict(_Span)
        self.untyped: dict[tuple, int] = defaultdict(int)

    @classmethod
    def unusual(cls, kind: str) -> bool:
        return kind in cls.UNUSUAL_TYPES or _private_type(kind)

    @classmethod
    def strong(cls, kind: str) -> bool:
        return kind in cls.STRONG_TYPES or _private_type(kind)

    def consume(self, events):
        for event, client, _server, name in self._questions(events):
            labels = name.split(".")
            if labels[-1] in self.NOT_DELEGATED or len(labels) < 2:
                continue
            domain = registered_domain(name)
            key = (client, domain)
            self.queries[key] += 1
            kind = qtype(event.get("dns.question.type"))
            if kind is None:
                self.untyped[key] += 1
                self.missing_required += 1          # the type mix cannot be measured for this record
            else:
                self.types[key][kind] += 1
            self.spans[key].add(event.ts)
            self.examples[key].add(event)
            sub = subdomain_part(name, domain)
            if not sub:
                continue
            subs = self.subdomains[key]
            if sub in subs or len(subs) >= NAME_CAP:
                continue
            subs.add(sub)
            longest = max(len(label) for label in sub.split("."))
            self.max_label[key] = max(self.max_label[key], longest)
            if longest >= self.LONG_LABEL or len(sub) >= self.LONG_SUBDOMAIN:
                self.long[key][sub] = entropy(sub.replace(".", ""))
        return []

    def finalize(self):
        out = []
        for key in sorted(self.subdomains):
            unique = len(self.subdomains[key])
            if unique < self.MIN_UNIQUE:
                continue
            client, domain = key
            long_names = self.long.get(key, {})
            n_long = len(long_names)
            mean_entropy = sum(long_names.values()) / n_long if n_long else 0.0
            typed = self.types.get(key, Counter())
            n_typed = sum(typed.values())
            unusual = sum(n for kind, n in typed.items() if self.unusual(kind))
            strong = sum(n for kind, n in typed.items() if self.strong(kind))
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
                continue
            q = self.queries[key]
            capped = "at least " if unique >= NAME_CAP else ""
            claim = (f"{client} sent {q} DNS question record(s) for {capped}{unique} distinct subdomain(s) under "
                     f"'{domain}' ({self.spans[key].text()}). {n_long} of the distinct names have a label of "
                     f"{self.LONG_LABEL}+ characters or {self.LONG_SUBDOMAIN}+ characters left of the domain "
                     f"(longest label {self.max_label[key]}); mean character entropy of those names "
                     f"{mean_entropy:.2f} bits/char; {unusual} of {n_typed} typed question(s) are TXT, NULL, CNAME, "
                     f"MX or private-use types (question types: {_tally(typed) if typed else 'none recorded'}).")
            if self.untyped.get(key):
                claim += f" {self.untyped[key]} question record(s) carry no question type."
            claim += (f" Indicators met: {', '.join(indicators)}. This is the query shape of data encoded into names "
                      f"(DNS tunnelling or exfiltration); reputation and anti-virus lookups that encode hashes look "
                      f"the same, so it is a deviation, not proof. The registered domain is the last two labels "
                      f"(three under a listed country suffix).")
            sample = sorted(long_names or self.subdomains[key], key=lambda s: (-len(s), s))[:3]
            claim += f" Examples: {', '.join(_short(s + '.' + domain) for s in sample)}."
            if len(indicators) == 4 and strong >= self.MIN_TYPED:
                lane = "high"
                claim += (f" {strong} questions are NULL, CNAME, MX or private-use types, which clients almost never "
                          f"ask with long unique names.")
            else:
                lane = self.lane
            evs = self._cite(key)
            e0 = evs[0]
            predicate = [pf(e, n) for e in evs[:2] for n in ("dns.question.name", "dns.question.type", "source.ip")
                         if e.has(n)]
            out.append(Match(self.id, claim, self.claim_type, evs, predicate, e0.ts, self.severity, lane, "medium",
                             e0.entities(), notes=[f"indicators: {indicators}"], group_key=f"{client}|{domain}"))
        return out


def _private_type(kind: str) -> bool:
    """Question types in the private-use range 65280-65534 (RFC 6895), which some tunnel tools use."""
    return kind.startswith("TYPE") and kind[4:].isdigit() and 65280 <= int(kind[4:]) <= 65534


DNS_PLAYBOOKS = [DnsZoneTransferOrAnyRequest, DnsReverseLookupSweep, DnsNxdomainBurst, DnsTunnelShape]
