"""Network-session playbooks over Arkime SPI records (net_session) and Suricata handshake records.

Arkime writes a long-lived connection as several session records, one per save interval, sharing the
5-tuple and community ID. These rules stitch records by community ID so a connection is judged as a
whole. The fingerprint rarity rule also reads Suricata tls/ssh records through the same typed handshake
fields. Every value comes from typed fields; nothing is matched in text.
"""
from __future__ import annotations

import itertools
import statistics
from array import array
from bisect import bisect_left, bisect_right
from datetime import UTC, datetime
from typing import ClassVar

from romulus.detect.base import Match, Playbook, pf
from romulus.detect.bounded import HOT_COUNT, HeldExamples, KeyedStore, RecentIds
from romulus.detect.correlation import StageMissing, canon_ip, external, routable_remote
from romulus.detect.netdef import assume_direction
from romulus.evidence.typed import TypedEvent

EXAMPLE_LIMIT = 20
PERIODIC_BY_DESIGN = {"ntp"}      # Arkime parser protocol names whose normal operation is a fixed poll interval


def _public(ip) -> bool:
    """Routable and outside the configured internal space: the same boundary the host rules use."""
    return external(canon_ip(ip))


def _both_routable(e: TypedEvent) -> bool:
    return routable_remote(canon_ip(e.get("source.ip"))) and routable_remote(canon_ip(e.get("destination.ip")))


def _epoch(value) -> float | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return (parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)).timestamp()


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, UTC).isoformat()


def _absorb(parts: list[list], start: float, end: float, seq: int, event_id: str, protocols: frozenset,
            idle: float) -> bool:
    """Add one record to a connection's stretches of activity: [start, end, first record's order, its id,
    protocols], kept sorted and disjoint, each more than `idle` from the next. Stretches the record comes within
    `idle` of are merged; True when the record opened a new stretch (it was then more than `idle` from every record
    of the identity read before it)."""
    lo = bisect_left(parts, start - idle, key=lambda p: p[1])
    hi = bisect_right(parts, end + idle, key=lambda p: p[0])
    if lo == hi:
        parts.insert(lo, [start, end, seq, event_id, protocols])
        return True
    touched = parts[lo:hi]
    lead = min(touched, key=lambda p: p[2])
    parts[lo:hi] = [[min(start, touched[0][0]), max(end, max(p[1] for p in touched)), lead[2], lead[3],
                     protocols.union(*(p[4] for p in touched))]]
    return False


class _Stitched(Playbook):
    """Groups net_session records into connections by community ID (or the 5-tuple when absent). Memory
    holds per-connection summaries and event ids; the events themselves are staged on disk.

    Every connection the rule can report (`wants`) is held for the whole window in a keyed store: the HOT most
    recently used in memory, the rest on the rule's disk spill, read back when the identity is seen again. Nothing
    is closed or forgotten on a time horizon, so a channel that sleeps for hours keeps its whole history. Each
    connection also keeps its stretches of activity (records more than IDLE apart start a new stretch): Arkime writes
    a long session's intermediate record at least every tcpSaveTimeout (720 s by default) and closes a TCP session
    idle for tcpTimeout (480 s), so a gap of an hour is a channel that slept or a 5-tuple used again. Only the
    store's disk budget may refuse a record of a new connection (counted, and said on coverage)."""
    kind = "aggregate"
    anchor_class = "network_observation"
    staged = True
    claim_type = "network_observation"
    families = ("net_session",)
    required_fields = ("source.ip", "destination.ip", "flow.start", "flow.end")
    IDLE = 3600.0
    CONN_IDS = EXAMPLE_LIMIT        # record ids held (and staged) per connection
    HOT = HOT_COUNT  # count cap; sized in bytes by the hunt's memory budget

    def __init__(self):
        super().__init__()
        self.conns = KeyedStore(self, f"conns_{type(self).__name__.lower()}", self.HOT, candidate=self.candidate)
        self._seen = RecentIds()        # bounded re-read guard
        self._pending: list[TypedEvent] = []
        self.load = lambda ids: []
        self._seq = 0

    def candidate(self, conn: dict) -> bool:
        """Whether a held connection can be reported (read at finalize); every one by default."""
        return True

    def drain_staged(self) -> list[TypedEvent]:
        out, self._pending = self._pending, []
        self.conns.trim()
        return out

    def release_state(self) -> None:
        self.load = lambda ids: []
        for value in list(vars(self).values()):
            if isinstance(value, KeyedStore):
                value.clear()
        self.close_spill()

    def _events(self, ids: list[str]) -> list[TypedEvent]:
        loaded = self.load(ids)
        if len(loaded) != len(set(ids)):
            raise StageMissing(f"{self.id}: {len(set(ids)) - len(loaded)} cited event(s) absent from the stage")
        return sorted(loaded, key=lambda e: (e.ts, e.id))

    def _conn_key(self, e: TypedEvent) -> str:
        cid = e.get("network.community_id")
        if cid:
            return str(cid)
        return f"{e.get('network.transport')}|{e.get('source.ip')}:{e.get('source.port')}|" \
               f"{e.get('destination.ip')}:{e.get('destination.port')}"

    def wants(self, e: TypedEvent) -> bool:
        """Whether this rule can report the connection a first record opens (judged from that record, as the
        connection's address, port and transport fields are)."""
        return True

    @staticmethod
    def skipped_for_direction(e: TypedEvent) -> bool:
        """Whether a record this rule does not want was refused for its direction across the site boundary alone
        (direction-dependent rules say so; see Playbook.direction_dependent)."""
        return False

    def consume(self, events):
        for e in self.applicable([e for e in events if e.id not in self._seen]):
            self._seen.add(e.id)               # re-reading a partition must not count a record twice
            start, end = _epoch(e.get("flow.start")), _epoch(e.get("flow.end"))
            if start is None or end is None:
                self.evaluated -= 1
                self.missing_required += 1
                continue
            key = self._conn_key(e)
            c = self.conns.get(key)
            if c is None:
                if not self.wants(e):
                    if self.skipped_for_direction(e):
                        assume_direction(self)  # judged by a direction the default definition only assumes
                    continue                  # judged: a connection this rule cannot report
                c = {"start": start, "end": end, "records": 0, "events": [], "c2s": 0, "s2c": 0,
                     "src": e.get("source.ip"), "sport": e.get("source.port"),
                     "dst": e.get("destination.ip"), "dport": e.get("destination.port"),
                     "transport": e.get("network.transport"), "observer": e.host, "protocols": set(),
                     "seq": self._seq, "parts": []}
                if not self.conns.put(key, c):
                    self.evaluated -= 1
                    self.refuse("disk", "the connections' disk budget is spent; a record of a new connection is not "
                                        "evaluated")
                    continue
            protocols = e.get("network.protocols")
            protocols = frozenset(protocols if isinstance(protocols, list) else [protocols] if protocols else [])
            c["protocols"].update(protocols)
            c["start"], c["end"] = min(c["start"], start), max(c["end"], end)
            c["records"] += 1
            c["c2s"] += int(e.get("source.bytes") or 0)
            c["s2c"] += int(e.get("destination.bytes") or 0)
            opened = _absorb(c["parts"], start, end, self._seq, e.id, protocols, self.IDLE)
            self._seq += 1
            if self.cite(c, e, opened):
                self._pending.append(e)
        return []

    def cite(self, conn: dict, e: TypedEvent, opened: bool) -> bool:
        """Whether this record may be cited later (so it goes to the stage): the connection's first CONN_IDS."""
        if len(conn["events"]) >= self.CONN_IDS:
            return False
        conn["events"].append(e.id)
        return True

    def retained_events(self) -> list[TypedEvent]:
        return []           # staged on disk instead


class LongExternalConnection(_Stitched):
    id = "net.long_external_connection"
    version = "3"
    direction_dependent = True
    title = "Long-lived TCP connection between an internal and a public address"
    severity, lane = "medium", "lead"
    attack = ("T1071", "T1095", "T1571")
    benign = ("remote administration sessions (SSH, RDP gateways)", "VPN tunnels and persistent push channels",
              "streaming and long downloads")
    next_checks = ("process connections on the internal host for this endpoint", "flow detail for the community ID",
                   "packets of the connection (cleartext content, TLS fingerprint)")
    MIN_SECONDS = 1800
    card: ClassVar[dict] = {
        "behavior": "one TCP connection between an address inside the site and one outside it, recorded by Arkime "
                    "as session records that together span at least 30 minutes",
        "telemetry": "Arkime 6.x sessions as net_session: source.ip, destination.ip, flow.start, flow.end, "
                     "network.transport, network.community_id (present and normalized in the lab profile)",
        "fidelity": "direct observation of the connection's lifetime by the sensor; says nothing about what it "
                    "carried",
        "benign_and_cost": "remote administration, VPN tunnels, push channels, long downloads; one item per "
                           "connection",
        "query_cost": "none beyond the sweep",
        "next_pivot": "the internal host's process for the endpoint, then the connection's packets",
        "adds": "the only rule that judges a connection's duration across the site boundary",
        "research_basis": "ATT&CK Enterprise 20.0 T1071, T1095 and T1571 (network traffic flow detection); "
                          "reimplemented from the behavior",
        "retrieval": "the sweep retrieves every record of the Arkime session index in each partition, a superset "
                     "of what this evaluator reads",
        "direction": "inside and outside are decided by the site's internal-network definition; under the default "
                     "(RFC 1918 and reserved ranges, not configured for the site) a partition holding a TCP record "
                     "between two routable addresses on the same side, skipped for that reason alone, is partial "
                     "with the reason 'direction assumed', never a complete negative",
        "lanes": "lead; severity medium: a long connection is a channel, not an impact",
    }

    @staticmethod
    def skipped_for_direction(e: TypedEvent) -> bool:
        """A TCP record between two routable addresses on the same side: skipped for its direction alone."""
        return (e.get("network.transport") == "tcp" and _both_routable(e)
                and _public(e.get("source.ip")) == _public(e.get("destination.ip")))

    def wants(self, e: TypedEvent) -> bool:
        # a TCP connection with exactly one public end; anything else is never reported
        return e.get("network.transport") == "tcp" and _public(e.get("source.ip")) != _public(e.get("destination.ip"))

    def candidate(self, conn: dict) -> bool:
        return conn["end"] - conn["start"] >= self.MIN_SECONDS

    def finalize(self):
        out = []
        order = sorted((c["seq"], key) for key, c in self.conns.items(candidates=True))
        for _seq, key in order:
            c = self.conns.peek(key)
            evs = self._events(c["events"])
            minutes = (c["end"] - c["start"]) / 60
            claim = (f"Arkime recorded {c['records']} session record(s) for one TCP connection {c['src']}:{c['sport']} "
                     f"-> {c['dst']}:{c['dport']} spanning {minutes:.0f} minutes ({_iso(c['start'])} – "
                     f"{_iso(c['end'])}), {c['c2s']} bytes from the client and {c['s2c']} bytes from the server. "
                     f"Only the part of the connection that started inside the hunt window is counted.")
            gaps = len(c["parts"]) - 1
            if gaps:
                # Arkime writes a live connection's record at least every save interval: a long silence is a
                # channel that slept, or the 5-tuple used again by a separate connection. Either way it is reported.
                claim += (f" The records show {gaps} gap(s) of more than {self.IDLE / 3600:.0f} hour(s) without a "
                          f"record, so this may be one channel that slept between bursts or the same 5-tuple reused "
                          f"by separate connections; the span covers all of them.")
            preds = [pf(evs[0], "source.ip"), pf(evs[0], "destination.ip"), pf(evs[0], "flow.start"),
                     pf(evs[-1], "flow.end")]
            out.append(Match(self.id, claim, self.claim_type, evs, preds, evs[0].ts, self.severity, self.lane,
                             "high", evs[0].entities(), group_key=key))
        return out


class _Series:
    """One (internal source, public destination, port, transport) series, built at finalize: every connection's
    start (8 bytes each), the earliest connections' first record ids, and the protocols every connection was
    identified as."""

    __slots__ = ("first", "protocols", "starts")

    def __init__(self):
        self.starts = array("d")
        self.first: list[tuple[float, int, str]] = []        # (start, first record's order, its id), earliest
        self.protocols: frozenset | None = None

    def add(self, part: list) -> None:
        start, _end, seq, event_id, protocols = part
        self.starts.append(start)
        ref = (start, seq, event_id)
        if len(self.first) < EXAMPLE_LIMIT or ref < self.first[-1]:
            self.first = sorted([*self.first, ref])[:EXAMPLE_LIMIT]
        self.protocols = protocols if self.protocols is None else self.protocols & protocols


class Beaconing(_Stitched):
    """Many separate connections from one internal address to one public endpoint at regular intervals. A
    connection identity whose records are more than IDLE apart is counted as separate connections (one per stretch
    of activity), so a 5-tuple reused by a periodic client still shows its period."""
    id = "net.beaconing"
    version = "3"
    direction_dependent = True
    title = "Regular, repeated connections from an internal address to one public endpoint"
    severity, lane = "medium", "lead"
    attack = ("T1071", "T1029", "T1573")
    benign = ("NTP, update checks, telemetry and monitoring agents", "scheduled jobs polling an approved service")
    next_checks = ("process connections on the internal host for this endpoint",
                   "scheduled tasks or cron entries on the internal host", "DNS history for the endpoint")
    MIN_CONNECTIONS = 8
    MIN_INTERVAL = 10.0
    MAX_JITTER = 0.1          # median absolute deviation of the intervals, relative to their median
    card: ClassVar[dict] = {
        "behavior": "at least 8 separate connections from one address inside the site to one address outside it, "
                    "on one port and transport, starting at a regular interval (median at least 10 s, median "
                    "absolute deviation at most a tenth of it)",
        "telemetry": "Arkime 6.x sessions as net_session: source.ip, destination.ip, destination.port, "
                     "network.transport, flow.start, flow.end, network.protocols (present in the lab profile)",
        "fidelity": "aggregate observation of connection start times; regularity is a deviation, not proof of "
                    "command and control",
        "benign_and_cost": "NTP (context lane when the parser names it), update checks, telemetry and monitoring "
                           "agents; one item per (source, destination, port, transport)",
        "query_cost": "none beyond the sweep",
        "next_pivot": "the internal host's process and scheduled jobs for the endpoint",
        "adds": "the only rule that measures the regularity of repeated connections",
        "research_basis": "ATT&CK Enterprise 20.0 T1071, T1029 and T1573; reimplemented from the behavior",
        "retrieval": "the sweep retrieves every record of the Arkime session index in each partition, a superset "
                     "of what this evaluator reads",
        "direction": "inside and outside are decided by the site's internal-network definition; under the default "
                     "(RFC 1918 and reserved ranges, not configured for the site) a partition holding a record "
                     "between two routable addresses that is not inside-to-outside, skipped for that reason alone, "
                     "is partial with the reason 'direction assumed', never a complete negative",
        "lanes": "lead, or context when Arkime's parser identified every connection as a protocol periodic by "
                 "design; severity medium",
    }

    @staticmethod
    def skipped_for_direction(e: TypedEvent) -> bool:
        """Only internal-to-public series are judged: any other routable pair is skipped for its direction alone."""
        return _both_routable(e) and not (_public(e.get("destination.ip")) and not _public(e.get("source.ip")))

    TRIM_EVERY = 10_000

    def wants(self, e: TypedEvent) -> bool:
        return _public(e.get("destination.ip")) and not _public(e.get("source.ip"))

    def cite(self, conn: dict, e: TypedEvent, opened: bool) -> bool:
        # A stretch is cited by its first record read, which opened a stretch when it was read (stretches only merge
        # as records arrive): staging exactly the records that open one keeps every possible citation.
        return opened

    def finalize(self):
        series = KeyedStore(self, "beacon_series", self.HOT)
        for i, (_key, c) in enumerate(self.conns.items()):
            s = series.setdefault((c["src"], c["dst"], c["dport"], c["transport"]), _Series)
            if s is None:
                self.refuse("disk", "the series' disk budget is spent; a connection is not evaluated")
                continue
            for part in c["parts"]:
                s.add(part)
            if i % self.TRIM_EVERY == self.TRIM_EVERY - 1:
                series.trim()
        out = []
        for (src, dst, dport, transport), s in series.items():
            if len(s.starts) < self.MIN_CONNECTIONS:
                continue
            starts = sorted(s.starts)
            gaps = [b - a for a, b in itertools.pairwise(starts)]
            median = statistics.median(gaps)
            if median < self.MIN_INTERVAL:
                continue
            mad = statistics.median(abs(g - median) for g in gaps)
            if mad / median > self.MAX_JITTER:
                continue
            evs = self._events([event_id for _start, _seq, event_id in s.first])
            # Protocols that are periodic by design, identified by Arkime's parser from packet content (not the
            # port): still reported, in the context lane, never dropped
            periodic = sorted(s.protocols & PERIODIC_BY_DESIGN)
            claim = (f"Arkime recorded {len(starts)} separate {transport} connections from {src} to {dst} port {dport} "
                     f"({_iso(starts[0])} – {_iso(starts[-1])}) starting every {median:.0f} s (median), with a median "
                     f"deviation of {mad:.1f} s between starts."
                     + (f" Arkime's parser identified every connection as {', '.join(periodic)}, a protocol that is "
                        f"periodic by design." if periodic else ""))
            preds = [pf(evs[0], "source.ip"), pf(evs[0], "destination.ip"), pf(evs[0], "destination.port")]
            out.append(Match(self.id, claim, self.claim_type, evs, preds, evs[0].ts, self.severity,
                             "context" if periodic else self.lane, "medium", evs[0].entities(),
                             group_key=f"{src}|{dst}|{dport}|{transport}"))
        series.clear()
        return out


class RareClientFingerprint(_Stitched):
    """A handshake fingerprint or SSH client software string used by only one internal address in the window,
    toward public endpoints. Reads Arkime sessions and Suricata tls/ssh records through the shared typed contract
    (every value of a list-valued fingerprint field counts). Rarity in one window, with no baseline, is context,
    not a verdict: the lane stays context."""
    id = "net.rare_client_fingerprint"
    version = "4"
    direction_dependent = True
    title = "TLS or SSH handshake fingerprint, or SSH client software, seen from only one internal address"
    families = ("net_session", "tls_session", "ssh_session")
    required_fields = ("source.ip", "destination.ip")
    severity, lane = "low", "context"
    attack = ("T1071.001", "T1573", "T1021.004")
    benign = ("uncommon but legitimate clients, new software versions, a short hunt window",
              "automation clients (configuration management, backup jobs) used from one host")
    next_checks = ("process connections on the internal host for these sessions",
                   "the same fingerprint across a longer window or other sites")
    MAX_CONNECTIONS = 5
    # kind label, typed field, how the claim names it. JA3S is the server's reply to this client's offer; the SSH
    # software string is what the client announced (self-reported text, so it groups but never proves a tool).
    KINDS = (("JA3", "tls.ja3", "JA3 client fingerprint"), ("JA4", "tls.ja4", "JA4 client fingerprint"),
             ("JA3S", "tls.ja3s", "JA3S server fingerprint"), ("HASSH", "ssh.hassh", "HASSH client fingerprint"),
             ("SSH client software", "ssh.client.software", "SSH client software string"))
    card: ClassVar[dict] = {
        "behavior": "a JA3, JA4, JA3S or HASSH value, or an SSH client software string, appears only on "
                    "connections from one internal address to public endpoints in the window",
        "telemetry": "Arkime 6.x tls.ja3/ja4/ja3s and ssh.hassh (arrays) as net_session; Suricata EVE tls.ja3.hash, "
                     "ja3s.hash, ja4 as tls_session and ssh.client.software_version/hassh as ssh_session. Present in "
                     "the lab profile (Suricata hassh disabled; Arkime SSH banners are not attributed to a side, so "
                     "client software comes from Suricata only)",
        "fidelity": "deviation only: typed handshake values grouped by distinct internal sources; client strings "
                    "are self-reported",
        "benign_and_cost": "rare but legitimate clients and versions; one context item per value",
        "query_cost": "none beyond the sweep",
        "next_pivot": "the internal process behind the sessions, and the value across a longer window",
        "adds": "extends the JA3/HASSH rarity to JA4, JA3S and SSH client software, across both sensors",
        "research_basis": "JA3/JA3S (Salesforce), JA4 (FoxIO) and HASSH (Salesforce) fingerprint definitions as "
                          "the sensors compute them",
        "retrieval": "the sweep retrieves every record of the network targets in each partition, a superset",
        "direction": "inside and outside are decided by the site's internal-network definition; under the default "
                     "(RFC 1918 and reserved ranges, not configured for the site) a partition holding a "
                     "fingerprinted record between two routable addresses that is not inside-to-outside, skipped "
                     "for that reason alone, is partial with the reason 'direction assumed'",
    }

    # A value is reported only while one source used it on at most MAX_CONNECTIONS connections, so a value holds at
    # most two sources and MAX_CONNECTIONS + 1 connections; once it cannot be rare its citations are dropped. Values
    # (about 600 bytes each) are held in a keyed store: HOT in memory, the rest on disk; only its disk budget refuses.
    HOT = HOT_COUNT  # a count cap only: the hunt's memory budget sizes it in bytes

    def __init__(self):
        super().__init__()
        self.prints = KeyedStore(self, "rare_prints", self.HOT, candidate=self._rare)

    def _rare(self, p: dict) -> bool:
        return len(p["sources"]) == 1 and len(p["conns"]) <= self.MAX_CONNECTIONS

    def drain_staged(self) -> list[TypedEvent]:
        out = super().drain_staged()
        self.prints.trim()
        return out

    def consume(self, events):
        for e in self.applicable([e for e in events if e.id not in self._seen]):
            self._seen.add(e.id)               # re-reading a partition must not count a record twice
            malformed = e.get("parse.malformed") or []
            unreadable = any(p in ("tls", "ssh") or p.startswith(("tls.ja", "ssh.hassh", "ssh.client"))
                             for p in malformed)
            carries = any(e.has(field) for _kind, field, _label in self.KINDS)
            no_address = canon_ip(e.get("source.ip")) is None or canon_ip(e.get("destination.ip")) is None
            if unreadable or (carries and no_address):
                # a fingerprint present but unreadable, or one whose session direction is unknown
                self.evaluated -= 1
                self.missing_required += 1
            elif not self.observe(e, None):
                self.evaluated -= 1
                self.refuse("disk", "the fingerprint values' disk budget is spent; a record carrying a new value is "
                                    "not evaluated")
        return []

    @staticmethod
    def _judged(e: TypedEvent) -> bool:
        """An internal source to a public destination: the only direction this rule reads."""
        return (_public(e.get("destination.ip")) and not _public(e.get("source.ip"))
                and canon_ip(e.get("source.ip")) is not None)

    @classmethod
    def skipped_for_direction(cls, e: TypedEvent) -> bool:
        """A fingerprinted record between two routable addresses that is not internal-to-public."""
        return (not cls._judged(e) and _both_routable(e)
                and any(e.has(field) for _kind, field, _label in cls.KINDS))

    def observe(self, e, conn) -> bool:
        if not self._judged(e):
            if self.skipped_for_direction(e):
                assume_direction(self)              # judged by a direction the default definition only assumes
            return True
        taken = True
        for kind, field, _label in self.KINDS:
            value = e.get(field)
            for item in value if isinstance(value, list) else [value]:
                if not isinstance(item, str) or not item:
                    continue
                p = self.prints.setdefault((kind, item), lambda field=field: {"sources": set(), "conns": set(),
                                                                              "events": [], "field": field})
                if p is None:
                    taken = False
                    continue
                source = canon_ip(e.get("source.ip"))
                if len(p["sources"]) < 2:
                    p["sources"].add(source)
                if len(p["conns"]) <= self.MAX_CONNECTIONS:
                    p["conns"].add(self._conn_key(e))
                if not self._rare(p):
                    p["events"] = []                  # it can no longer be reported: nothing to cite
                elif len(p["events"]) < EXAMPLE_LIMIT and e.id not in p["events"]:
                    p["events"].append(e.id)
                    self._pending.append(e)          # the stage ignores events it already holds
        return taken

    def finalize(self):
        out = []
        labels = {kind: label for kind, _field, label in self.KINDS}
        for (kind, value), p in self.prints.items(candidates=True):
            if not self._rare(p):
                continue
            evs = self._events(p["events"])
            src = next(iter(p["sources"]))
            dsts = sorted({str(e.get("destination.ip")) for e in evs})
            shown = value if kind != "SSH client software" else f"'{value}'"
            claim = (f"{labels[kind]} {shown} appears on {len(p['conns'])} connection(s) in this window, all "
                     f"from {src}, to {', '.join(dsts[:5])}. No other internal address used it in the window.")
            cited = next(e for e in evs if e.has(p["field"]))
            out.append(Match(self.id, claim, self.claim_type, evs, [pf(cited, p["field"]), pf(cited, "source.ip")],
                             evs[0].ts, self.severity, self.lane, "medium", evs[0].entities(),
                             group_key=f"{kind}|{value}"))
        return out


class ArkimeSshReverseShellTag(Playbook):
    """Arkime's own SSH heuristic tagged the session `ssh-reverse-shell`. Arkime decides this from the traffic
    shape of the encrypted session; ROMULUS does not reproduce or verify the heuristic. It is reported like an
    IDS alert: a vendor detection with its own false-positive rate, a lead to check, never proof."""
    id = "net.arkime_ssh_reverse_shell_tag"
    version = "3"
    title = "Arkime's heuristic tagged an SSH session as a possible reverse shell"
    kind = "aggregate"
    anchor_class = "network_observation"
    claim_type = "network_observation"
    families = ("net_session",)
    required_fields = ("source.ip", "destination.ip")
    severity, lane = "high", "lead"
    attack = ("T1021.004", "T1572", "T1059.004")
    assures_negative = False
    positive_only_reason = (
        "the rule reports a tag that Arkime's heuristic applies; sessions the heuristic does not recognise, and "
        "sensors where it is not enabled, carry no tag, so absence proves nothing")
    TAG = "ssh-reverse-shell"
    PAIR_CONNS_CAP = 10_000      # SSH connections remembered per pair for the untagged count (a lower bound above it)
    benign = (("interactive SSH sessions whose traffic shape resembles the heuristic's pattern (port forwarding, "
               "tools that open a channel back to the client)"), "the heuristic's own false positives")
    next_checks = ("the SSH login and the commands run on both ends around the session (host audit records)",
                   "which process owns the connection on each internal end", "other sessions between the same hosts")
    card: ClassVar[dict] = {
        "behavior": "Arkime's capture tagged an SSH session 'ssh-reverse-shell'",
        "telemetry": "Arkime 6.x session tags (arkime.tags) as net_session; present in the lab profile",
        "fidelity": "vendor heuristic over encrypted-traffic shape; neither the shell nor its direction is observed",
        "benign_and_cost": "the heuristic's false positives, notably interactive administration between internal "
                           "hosts; one finding per (client, server, server port). The claim states the session's own "
                           "context so the analyst can weigh the tag: whether each end is internal or public, the SSH "
                           "software both ends announced and the HASSH values, the bytes each way, and how many other "
                           "SSH connections between the same pair Arkime recorded without the tag",
        "query_cost": "none beyond the sweep",
        "next_pivot": "host audit records of the SSH login and the processes on both ends",
        "adds": "no other rule reads Arkime's tags; the session rules see only duration, timing and fingerprints",
        "research_basis": "Arkime's built-in SSH tagging; treated like an IDS alert (spec section 7, IDS alerts as "
                          "leads with their own false-positive rate)",
        "retrieval": "the sweep retrieves every Arkime session record in each partition, a superset",
    }

    # One state per (client, server, server port) pair with SSH or a tag, in a keyed store: HOT pairs in memory, the
    # rest on disk, only its disk budget refuses. A pair remembers at most PAIR_CONNS_CAP SSH connections for the
    # untagged count (the claim says "at least" above it); a tagged pair also holds its context and cited references.
    staged = True
    HOT = HOT_COUNT  # a count cap only: the hunt's memory budget sizes it in bytes

    def __init__(self):
        super().__init__()
        self._seen = RecentIds()        # bounded re-read guard
        self.pairs = KeyedStore(self, "ssh_pairs", self.HOT, candidate=lambda pair: pair["info"] is not None)
        self._pending: list[TypedEvent] = []
        self._fresh: list[HeldExamples] = []
        self.load = lambda ids: []

    def drain_staged(self) -> list[TypedEvent]:
        out, self._pending = self._pending, []
        for store in self._fresh:
            store.staged()
        self._fresh = []
        self.pairs.trim()                       # after staging: a trimmed pair holds references only
        return out

    def release_state(self) -> None:
        self.load = lambda ids: []
        self.pairs.clear()
        self.close_spill()

    def retained_events(self) -> list[TypedEvent]:
        return []                               # staged on disk instead

    def consume(self, events):
        for e in self.applicable([e for e in events if e.id not in self._seen]):
            self._seen.add(e.id)
            if "tags" in (e.get("parse.malformed") or []):          # native path of arkime.tags
                self.evaluated -= 1
                self.missing_required += 1
                continue
            key = (str(e.get("source.ip")), str(e.get("destination.ip")), str(e.get("destination.port")))
            protocols = e.get("network.protocols")
            ssh = "ssh" in (protocols if isinstance(protocols, list) else [protocols])
            tags = e.get("arkime.tags")
            tags = tags if isinstance(tags, list) else [tags]
            tagged = self.TAG in tags
            if not ssh and not tagged:
                continue
            pair = self.pairs.setdefault(key, lambda: {"ssh": set(), "info": None, "examples": None})
            if pair is None:
                self.evaluated -= 1
                self.refuse("disk", "the SSH pairs' disk budget is spent; a record of a new pair is not evaluated")
                continue
            if ssh:
                conns = pair["ssh"]
                if len(conns) < self.PAIR_CONNS_CAP:
                    conns.add(self._conn_key(e))
            if not tagged:
                continue
            if pair["info"] is None:
                pair["info"] = {"records": 0, "conns": set(), "first": e.ts, "last": e.ts, "c2s": 0, "s2c": 0,
                                "versions": set(), "hassh": set(), "hassh_server": set(), "tags": set(), "end": None}
                pair["examples"] = HeldExamples(EXAMPLE_LIMIT)
            g = pair["info"]
            g["records"] += 1
            g["conns"].add(self._conn_key(e))
            g["first"], g["last"] = min(g["first"], e.ts), max(g["last"], e.ts)
            end = _epoch(e.get("flow.end"))
            if end is not None:
                g["end"] = end if g["end"] is None else max(g["end"], end)
            for name, side in (("source.bytes", "c2s"), ("destination.bytes", "s2c")):
                value = e.get(name)
                if isinstance(value, int) and not isinstance(value, bool):
                    g[side] += value
                else:
                    g[f"{side}_missing"] = g.get(f"{side}_missing", 0) + 1
            for name, bucket in (("ssh.version", "versions"), ("ssh.hassh", "hassh"),
                                 ("ssh.hassh_server", "hassh_server")):
                value = e.get(name)
                g[bucket].update(v for v in (value if isinstance(value, list) else [value]) if isinstance(v, str))
            g["tags"].update(t for t in tags if isinstance(t, str) and t != self.TAG)
            group = pair["examples"]
            if group.offer(e):
                self._pending.append(e)
                self._fresh.append(group)
        return []

    @staticmethod
    def _scope(src: str, dst: str) -> str:
        """Where the two ends sit, by the configured internal ranges ('' when either is not a routable address)."""
        client, server = canon_ip(src), canon_ip(dst)
        if not (routable_remote(client) and routable_remote(server)):
            return ""
        if not external(client) and not external(server):
            return " Both ends are internal addresses."
        if external(client) and external(server):
            return " Both ends are public addresses."
        if external(server):
            return f" The client {src} is internal and the server {dst} is a public address."
        return f" The client {src} is a public address and the server {dst} is internal."

    def _context(self, key: tuple, g: dict, known: set) -> str:
        """The session's own context, stated beside the tag: address scope, bytes, announced software,
        fingerprints, other tags, and the pair's untagged SSH connections (a denominator for the heuristic)."""
        src, dst, port = key
        text = self._scope(src, dst)
        span = (g["end"] - g["first"].timestamp()) if g["end"] is not None else None
        def volume(side: str) -> str:
            missing = g.get(f"{side}_missing", 0)
            if missing == g["records"]:
                return "a byte count not recorded"
            return (f"at least {g[side]} bytes (not recorded on {missing} record(s))" if missing
                    else f"{g[side]} bytes")

        text += (f" The tagged record(s) carry {volume('c2s')} from the client and {volume('s2c')} from the server"
                 + (f" over {span:.0f} s." if span is not None else "."))
        if g["versions"]:
            text += (" SSH software the two ends announced (self-reported; Arkime does not say which end sent which): "
                     + ", ".join(f"'{v}'" for v in sorted(g["versions"])) + ".")
        prints = [f"client HASSH {', '.join(sorted(g['hassh']))}" if g["hassh"] else "",
                  f"server HASSH {', '.join(sorted(g['hassh_server']))}" if g["hassh_server"] else ""]
        if any(prints):
            text += f" Fingerprints: {'; '.join(p for p in prints if p)}."
        if g["tags"]:
            text += f" Other Arkime tags on these records: {', '.join(sorted(g['tags']))}."
        others = len(known - g["conns"])
        at_least = "at least " if len(known) >= self.PAIR_CONNS_CAP else ""
        if at_least:
            self.note_limit("connections", f"a pair passed {self.PAIR_CONNS_CAP:,} SSH connections held; its untagged "
                                           f"count is a lower bound")
        text += (f" Arkime recorded {at_least}{others} other SSH connection(s) from {src} to {dst} port {port} without "
                 "the tag "
                 "in the window." if others else
                 f" Arkime recorded no other SSH connection from {src} to {dst} port {port} in the window.")
        return text

    @staticmethod
    def _conn_key(e: TypedEvent) -> str:
        return str(e.get("network.community_id") or e.id)

    def finalize(self):
        out = []
        for key, pair in self.pairs.items(candidates=True):
            evs = pair["examples"].events(self.load)
            g = pair["info"]
            src, dst, port = key
            claim = (f"Arkime's heuristic tagged {g['records']} session record(s) of {len(g['conns'])} connection(s) "
                     f"from {src} to {dst} port {port} '{self.TAG}' ({g['first'].isoformat()} – "
                     f"{g['last'].isoformat()}). This is Arkime's own detection from the traffic shape, like an IDS "
                     f"alert; it does not show that a shell ran.") + self._context(key, g, pair["ssh"])
            out.append(Match(self.id, claim, self.claim_type, evs,
                             [pf(evs[0], "arkime.tags"), pf(evs[0], "source.ip"), pf(evs[0], "destination.ip")],
                             evs[0].ts, self.severity, self.lane, "medium", evs[0].entities(),
                             group_key="|".join(key)))
        return out


SESSION_PLAYBOOKS = [LongExternalConnection, Beaconing, RareClientFingerprint, ArkimeSshReverseShellTag]
