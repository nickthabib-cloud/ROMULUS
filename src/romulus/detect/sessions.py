"""Network-session playbooks over Arkime sessions and bidirectional Suricata and Zeek flows.

Arkime writes a long-lived connection as several session records, one per save interval, sharing the
5-tuple and community ID. The timing rules join records by direction-independent endpoints so a connection is judged as a
whole. The fingerprint rarity rule also reads Suricata tls/ssh records through the same typed handshake
fields. Every value comes from typed fields; nothing is matched in text.
"""
from __future__ import annotations

import heapq
import sqlite3
import statistics
from collections import Counter
from datetime import UTC, datetime
from itertools import groupby, pairwise
from typing import ClassVar

from romulus.detect.base import Match, Playbook, pf
from romulus.detect.bounded import (
    HOT_COUNT,
    CitationUnavailable,
    HeldExamples,
    KeyedStore,
    Limit,
    RecentIds,
    SpillList,
)
from romulus.detect.citing import (
    BoundStage,
    Ends,
    bound_note,
    citation_group,
    cite_with_bounds,
    cited_phrase,
)
from romulus.detect.correlation import canon_ip, external, routable_remote
from romulus.detect.flows import (
    ARKIME,
    EPHEMERAL_FLOOR,
    EXCHANGED,
    HALF_SENTENCES,
    OPENED_BY_OUTSIDE,
    OUTBOUND_CLIENT_SHAPED,
    OUTBOUND_INSIDE_HALF,
    OUTBOUND_NOT_REPORTED,
    OUTBOUND_OUTSIDE_HALF,
    OUTBOUND_REPORTED,
    OUTBOUND_SERVED,
    OUTBOUND_UNKNOWN,
    OUTBOUND_UNSHAPED,
    SIDE_SILENT,
    SURICATA,
    ZEEK,
    ZEEK_NO_DURATION,
    _per_sensor_cited,
    _sensor_counts,
    flow_view,
    judge_connection,
    outbound_reading,
    record_kind,
    sensor_of,
    server_shaped,
    side_states,
)
from romulus.detect.netdef import DIRECTION_ASSUMED_REASON, assume_direction, current
from romulus.detect.site_roles import address_member
from romulus.evidence.typed import TypedEvent
from romulus.site import absent_site_facts

EXAMPLE_LIMIT = 20
PERIODIC_BY_DESIGN = {"ntp"}      # parser protocol names whose normal operation is a fixed poll interval


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


def _syn(e: TypedEvent) -> bool | None:
    """Whether Arkime counted a SYN on this TCP record (None when the record carries no flag counts). Arkime orients a
    session it saw open by the SYN, so the record's source sent it."""
    count = e.get("tcp.flags.syn")
    if not isinstance(count, int) or isinstance(count, bool):
        return None
    return count > 0


def _merge_stretch(first: list, other: list) -> list:
    """Merge overlapping/continuing intervals with one first witness per sensor kind."""
    lead = min((first, other), key=lambda part: part[2])
    witnesses = dict(first[5])
    for sensor, ref in other[5].items():
        witnesses[sensor] = min(witnesses.get(sensor, ref), ref)
    return [min(first[0], other[0]), max(first[1], other[1]), lead[2], lead[3],
            first[4] | other[4], witnesses]


def _ends(c: dict) -> tuple[tuple, tuple]:
    """(internal (address, port), external (address, port)) of a held connection with one public end."""
    first, second = (c["src"], c["sport"]), (c["dst"], c["dport"])
    return (second, first) if _public(c["src"]) else (first, second)


def _judgement(c: dict) -> str:
    """romulus.detect.flows.judge_connection over every record of a held connection."""
    return judge_connection(c["openers"], c.get("states") or {}, *_ends(c))


def _outbound(c: dict) -> str:
    """How an outbound rule reads a held connection (romulus.detect.flows.outbound_reading)."""
    inside, outside = _ends(c)
    return outbound_reading(_judgement(c), inside[1], outside[1])


def _endpoint(side: tuple) -> str:
    return f"{side[0]}:{side[1]}" if side[1] is not None else str(side[0])


class _NotReported(Limit):
    """Connections a rule did not report because of what their records show (not a state budget), named on the
    window cell with their count; the cell is partial."""

    def reason(self) -> str:
        return f"not reported: {self.text} ({self.records} connection(s))"


class _Unreported:
    """The connections an outbound session rule did not report, per reading (OUTBOUND_NOT_REPORTED): a count, and the
    LISTED largest by the rule's measure, named on the window cell. Bounded: four readings, LISTED entries each."""
    LISTED = 10

    def __init__(self):
        self.counts: Counter = Counter()
        self.top: dict[str, list] = {}

    def add(self, reading: str, measure: float, c: dict) -> None:
        self.counts[reading] += 1
        inside, outside = _ends(c)
        entry = (measure, _endpoint(inside), _endpoint(outside))
        heap = self.top.setdefault(reading, [])
        if len(heap) < self.LISTED:
            heapq.heappush(heap, entry)
        elif entry > heap[0]:
            heapq.heapreplace(heap, entry)

    def publish(self, rule: Playbook, describe, extra: dict | None = None) -> None:
        """Informational readings become coverage notes; the others make the window cell partial. `describe(measure)`
        words one listed connection's measure; `extra` adds readings of the rule's own."""
        for reading, (partial, text) in {**OUTBOUND_NOT_REPORTED, **(extra or {})}.items():
            count = self.counts[reading]
            if not count:
                continue
            listed = sorted(self.top[reading], reverse=True)
            names = "; ".join(f"{inside} and {outside}, {describe(measure)}" for measure, inside, outside in listed)
            more = f"; and {count - len(listed)} more" if count > len(listed) else ""
            detail = f"{text}: {names}{more}"
            name = "not_reported_" + reading.replace(" ", "_").replace(",", "")
            if partial:
                rule.limits[name] = _NotReported(detail, records=count, hits=1)
            else:
                rule.note_coverage(name, f"not reported (informational): {detail} ({count} connection(s))")


class _Stitched(Playbook):
    """Groups bidirectional records into connections by the shared FlowView endpoint identity. Memory
    holds per-connection summaries and event ids; the events themselves are staged on disk.

    Every connection the rule can report (`wants`) is held for the whole window in a keyed store: the HOT most
    recently used in memory, the rest on the rule's disk spill, read back when the identity is seen again. Nothing
    is closed or forgotten on a time horizon, so a channel that sleeps for hours keeps its whole history. Each
    connection keeps one open stretch in memory; closed stretches spill and are reconciled in time order at
    finalize, including late records that bridge earlier stretches. Records more than IDLE apart start a TCP
    stretch: Arkime writes
    a long session's intermediate record at least every tcpSaveTimeout (720 s by default) and closes a TCP session
    idle for tcpTimeout (480 s), so a gap of an hour is a channel that slept or a 5-tuple used again. Only the
    store's disk budget may refuse a record of a new connection (counted, and said on coverage)."""
    kind = "aggregate"
    anchor_class = "network_observation"
    staged = True
    claim_type = "network_observation"
    families = ("net_session", "net_flow")
    required_fields = ("source.ip", "destination.ip", "flow.start")
    IDLE = 3600.0
    UDP_GAP = 5.0
    STRETCH_HOT = 1024
    CONN_IDS = EXAMPLE_LIMIT        # record ids held (and staged) per connection
    HOT = HOT_COUNT  # count cap; sized in bytes by the hunt's memory budget
    BOUNDED = False                 # the rule's claims state each connection's span: stage the records bounding it

    def __init__(self):
        super().__init__()
        self.conns = KeyedStore(self, f"conns_{type(self).__name__.lower()}", self.HOT, candidate=self.candidate)
        # Keep the existing Arkime finding key while joining records by the sensor-neutral endpoint identity.
        if "net_flow" in self.families:
            self.identities = KeyedStore(self, "session_identities", self.HOT)
            self.stretches = SpillList(self, "session_stretches", min(self.HOT, self.STRETCH_HOT))
        if self.BOUNDED:
            self.byte_totals = KeyedStore(self, "session_byte_totals", self.HOT)
            self.report_keys = KeyedStore(self, "session_report_keys", self.HOT)
        self._seen = RecentIds()        # bounded re-read guard
        self._pending: list[TypedEvent] = []
        self.bounds = BoundStage()      # records bounding each connection's span, staged when a batch ends
        self.load = lambda ids: []
        self._seq = 0

    def candidate(self, conn: dict) -> bool:
        """Whether a held connection can be reported (read at finalize); every one by default."""
        return True

    def drain_staged(self) -> list[TypedEvent]:
        out, self._pending = self._pending + self.bounds.drain(), []
        for value in list(vars(self).values()):
            if isinstance(value, (KeyedStore, SpillList)):
                value.trim()
        return out

    def drain_bounds(self) -> tuple[list[str], list[str]]:
        return self.bounds.last

    def release_state(self) -> None:
        self.load = lambda ids: []
        for value in list(vars(self).values()):
            if isinstance(value, (KeyedStore, BoundStage, SpillList)):
                value.clear()
        self.close_spill()

    def _events(self, ids: list[str]) -> list[TypedEvent]:
        loaded = self.load(ids)
        if len(loaded) != len(set(ids)):
            raise CitationUnavailable(f"{self.id}: {len(set(ids)) - len(loaded)} cited event(s) absent from the stage")
        return sorted(loaded, key=lambda e: (e.ts, e.id))

    def _conn_key(self, e: TypedEvent) -> str:
        cid = e.get("network.community_id")
        if cid:
            return str(cid)
        # the two endpoints in a fixed order, as the community ID hashes them: a record Arkime oriented the other way
        # (picked up mid-stream) is the same connection
        ends = sorted([f"{e.get('source.ip')}:{e.get('source.port')}",
                       f"{e.get('destination.ip')}:{e.get('destination.port')}"])
        return f"{e.get('network.transport')}|{ends[0]}|{ends[1]}"

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
        fresh = [e for e in events if e.family in self.families and e.id not in self._seen]
        flow_observers = {e.host for e in fresh if record_kind(e) == "flow"}
        selected = []
        for e in fresh:
            kind = record_kind(e)
            if kind == "netflow":
                self._seen.add(e.id)
                if e.host not in flow_observers:
                    self.missing_required += 1
            elif kind is None:
                self._seen.add(e.id)
                self.missing_required += 1
            else:
                selected.append(e)
        for e in self.applicable(selected):
            self._seen.add(e.id)               # re-reading a partition must not count a record twice
            view = flow_view(e, record_kind(e))
            if view is None or not view.timed:
                self.evaluated -= 1
                self.missing_required += 1
                continue
            start, end = view.start, view.end
            if self.skipped_for_direction(e):
                assume_direction(self)
            key = self.identities.get(view.key)
            if key is None:
                if not self.wants(e):
                    continue
                key = self._conn_key(e)
                previous = self.conns.get(key)
                if previous is not None and previous["identity"] != view.key:
                    key = repr(view.key)
                if not self.identities.put(view.key, key):
                    self.evaluated -= 1
                    self.refuse("disk", "the connection identities' disk budget is spent; a new identity is not evaluated")
                    continue
            c = self.conns.get(key)
            if c is None:
                # Keep the first record's sides; later opening evidence can orient the connection independently.
                c = {"start": start, "end": end, "records": 0, "events": [], "sent_src": 0, "sent_dst": 0,
                     "src": view.src, "sport": view.sport, "dst": view.dst, "dport": view.dport,
                     "identity": view.key, "transport": view.transport, "observer": e.host, "protocols": set(),
                     "report_key": key, "arkime_key": None,
                     "seq": self._seq, "parts": [], "ends": Ends(), "openers": [], "opener_id": None,
                     "opener_field": None, "flagged": False, "sensors": Counter(), "sensor_bytes": {},
                     "span_known": False, "duration_missing": False, "closed_stretches": False, "states": {}}
                if not self.conns.put(key, c):
                    self.evaluated -= 1
                    self.refuse("disk", "the connections' disk budget is spent; a record of a new connection is not "
                                        "evaluated")
                    continue
            protocols = view.protocols or frozenset()
            c["protocols"].update(protocols)
            c["duration_missing"] = c["duration_missing"] or view.duration_missing
            if not self.BOUNDED or not view.duration_missing:
                if c["span_known"]:
                    c["start"], c["end"] = min(c["start"], start), max(c["end"], end)
                else:
                    c["start"], c["end"] = start, end
                    c["span_known"] = True
            c["records"] += 1
            c["sensors"][view.sensor] += 1
            if self.BOUNDED:
                self._bytes(c, view, e)
                if view.sensor == ARKIME and e.get("network.community_id"):
                    cid = str(e.get("network.community_id"))
                    identity = self.report_keys.setdefault(cid, lambda view=view: view.key)
                    if identity == view.key:
                        c["arkime_key"] = min(c["arkime_key"] or cid, cid)
                        c["report_key"] = c["arkime_key"]
                    elif identity is None:
                        self.note_limit("report_keys", "the finding-identity disk budget is spent; the endpoint identity is used")
                        c["report_key"] = repr(view.key)
                    elif c["arkime_key"] is None:
                        c["report_key"] = repr(view.key)
            if any(e.has(field) for field in ("tcp.flags.syn", "tcp.opened_by_orig", "tcp.tcp_flags_ts", "tcp.syn")):
                c["flagged"] = True
            if view.opened:
                side = (view.src, view.sport)
                if side not in c["openers"]:
                    c["openers"].append(side)
                if c["opener_id"] is None:
                    c["opener_id"] = e.id
                    c["opener_field"] = ("tcp.flags.syn" if view.sensor == ARKIME else
                                         "tcp.opened_by_orig" if view.sensor == ZEEK else
                                         "tcp.tcp_flags_ts" if e.has("tcp.tcp_flags_ts") else "tcp.syn")
            # each side's strongest exchange state across the connection's records (romulus.detect.flows)
            for side, state in zip(((view.src, view.sport), (view.dst, view.dport)), side_states(e, view),
                                   strict=True):
                c["states"][side] = max(c["states"].get(side, SIDE_SILENT), state)
            if self.BOUNDED and not view.duration_missing:
                # staged only once the connection can be reported; its first records are staged by `cite`
                self.bounds.offer(key, c["ends"], start, end, e, stage=self.candidate(c))
            opened = False
            if not self.BOUNDED or not view.duration_missing:
                opened = self._stretch(key, c, view, e, protocols)
                if opened is None:
                    self.evaluated -= 1
                    continue
            self._seq += 1
            if self.cite(c, e, opened):
                self._pending.append(e)
        return []

    def _closed(self, key, part):
        if not self.stretches.append((key, part), (key, part[0])):
            self.refuse("disk", "the closed activity-stretch disk budget is spent; an activity start is not evaluated")
            return False
        if len(self.stretches.buffer) >= self.stretches.hot_size:
            self.stretches.trim(0)
        return True

    def _stretch(self, key, conn, view, event, protocols):
        part = [view.start, view.end, self._seq, event.id, protocols,
                {view.sensor: (view.start, self._seq, event.id)}]
        if not conn["parts"]:
            conn["parts"] = [part]
            return True
        current = conn["parts"][0]
        idle = self.UDP_GAP if view.transport == "udp" else self.IDLE
        if part[0] <= current[1] + idle and part[1] >= current[0] - idle:
            witness = view.sensor not in current[5] or view.start < current[5][view.sensor][0]
            conn["parts"] = [_merge_stretch(current, part)]
            return witness
        older, newer = (current, part) if current[1] <= part[1] else (part, current)
        if not self._closed(key, older):
            return None
        conn["closed_stretches"] = True
        conn["parts"] = [newer]
        return True

    def _merged_stretches(self):
        """One chronological merge pass over capped history, so late copies and bridges cannot inflate starts."""
        for key, conn in self.conns.items():
            for part in conn["parts"]:
                if conn["closed_stretches"]:
                    self._closed(key, part)
                else:
                    yield key, part
        held_key, held, idle = None, None, self.IDLE
        for key, part in self.stretches.ordered():
            if key == held_key and part[0] <= held[1] + idle:
                held = _merge_stretch(held, part)
                continue
            if held is not None:
                yield held_key, held
            held_key, held = key, part
            idle = self.UDP_GAP if self.conns.peek(key)["transport"] == "udp" else self.IDLE
        if held is not None:
            yield held_key, held

    def _bytes(self, conn, view, event):
        """Keep one observer's directional counters, never a sum of duplicate sensor observations."""
        forward = (view.src, view.sport) == (conn["src"], conn["sport"])
        counts = (view.c2s_bytes or 0, view.s2c_bytes or 0)[::1 if forward else -1]
        totals = self.byte_totals.setdefault((view.key, view.sensor, event.host), lambda: [0, 0])
        if totals is None:
            self.evaluated -= 1
            self.refuse("disk", "the per-sensor byte totals' disk budget is spent; byte totals are incomplete")
            return
        # Arkime save intervals are disjoint counters; Zeek interim and Suricata flow counters are cumulative.
        for side in (0, 1):
            totals[side] = totals[side] + counts[side] if view.sensor == ARKIME else max(totals[side], counts[side])
        old = conn["sensor_bytes"].get(view.sensor, (0, 0))
        conn["sensor_bytes"][view.sensor] = max(old, tuple(totals), key=lambda values: (sum(values), values))
        chosen = next(sensor for sensor in (ARKIME, ZEEK, SURICATA) if sensor in conn["sensor_bytes"])
        conn["sent_src"], conn["sent_dst"] = conn["sensor_bytes"][chosen]

    def cite(self, conn: dict, e: TypedEvent, opened: bool) -> bool:
        """Whether this record may be cited later (so it goes to the stage): the connection's first CONN_IDS, and
        the first record that shows which side opened it."""
        if len(conn["events"]) >= self.CONN_IDS and e.id != conn["opener_id"]:
            return False
        if e.id not in conn["events"]:
            conn["events"].append(e.id)
        return True

    def retained_events(self) -> list[TypedEvent]:
        return []           # staged on disk instead


SERVED_ELSEWHERE = "served, other service"      # an inbound session the inbound-session rule reports


class LongExternalConnection(_Stitched):
    """A long TCP channel an internal address holds to a public one: the internal side opened it, or both sides
    exchanged traffic with the internal side on a client port, or the records cannot say who opened it. A connection
    an outside address opened (an internal server answering) and records of unsolicited answers are not channels the
    internal side opened; they are counted on the window cell instead (romulus.detect.flows, outbound_reading)."""
    id = "net.long_external_connection"
    version = "8"
    direction_dependent = True
    title = "Long-lived TCP connection between an internal and a public address"
    severity, lane = "medium", "lead"
    attack = ("T1071", "T1095", "T1571")
    benign = ("remote administration sessions (SSH, RDP gateways)", "VPN tunnels and persistent push channels",
              "streaming and long downloads")
    next_checks = ("process connections on the internal host for this endpoint", "flow detail for the community ID",
                   "packets of the connection (cleartext content, TLS fingerprint)")
    MIN_SECONDS = 1800
    BOUNDED = True
    card: ClassVar[dict] = {
        "behavior": "one TCP connection between an address inside the site and one outside it, whose records "
                    "together span at least 30 minutes (overlapping observations by several sensors count once), "
                    "read as a channel the internal side holds: a record shows the internal side opened it; or no "
                    "record shows the opening, both sides sent traffic beyond resets and handshake answers, and the "
                    "internal side is on a port of 32768 or above facing a port below it; or no record shows the "
                    "opening and the records show only one side's half of it (one-way capture), or exchanges whose "
                    "ports mark neither side as the client, or lack the per-side counters to tell (all reported with "
                    "the opener stated as unknown, as are connections whose records disagree about the opener)",
        "telemetry": "Arkime sessions as net_session (source.packets, destination.packets, client.bytes, "
                     "server.bytes, tcp.flags.syn/syn_ack/rst), Suricata flow and Zeek conn as net_flow "
                     "(flow.pkts_toserver/toclient, flow.bytes_toserver/toclient, tcp.tcp_flags_ts/tc, "
                     "conn.history, tcp.opened_by_orig): source.ip, destination.ip, endpoint ports, flow.start/end, "
                     "network.transport. Arkime and Suricata carry every one of these in the lab profile",
        "fidelity": "direct observation of the connection's lifetime by the sensor; says nothing about what it "
                    "carried. Bytes are given per side. A side is named the client only when a record shows the "
                    "opening through the sensor's typed SYN flags or Zeek conn history; a connection picked up "
                    "mid-stream or that opened before the hunt window is worded with its two ends and the opener "
                    "stated as unknown, and when it is reported on its port shape the claim says so. The cited "
                    "records always include the records with the earliest start and the latest end, and the claim "
                    "says how many records it rests on and how many are cited",
        "benign_and_cost": "remote administration, VPN tunnels, push channels, long downloads; one item per "
                           "connection. Not reported, and named on the window cell with a count and the longest "
                           "ones: connections a recorded opening shows an outside address opened (informational: "
                           "those to the ordinary web ports 80, 443, 8080 and 8443 are routine, and those to any "
                           "other internal service are reported by net.long_inbound_session), records in which the "
                           "internal side answered with nothing beyond resets and handshake answers, or neither side "
                           "sent more (unsolicited answers such as backscatter of a spoofed flood; informational), and "
                           "exchanged connections with the internal side on a port below 32768 facing an outside port "
                           "at or above it (an internal server's shape; the cell is partial)",
        "query_cost": "none beyond the sweep",
        "next_pivot": "the internal host's process for the endpoint, then the connection's packets",
        "adds": "the only rule that judges the duration of a channel an internal address holds across the site "
                "boundary. Long sessions an outside address opened to an internal server are judged by "
                "net.long_inbound_session (every internal service except the ordinary web ports), net.external_rdp and net.vnc_session (RDP and VNC negotiation from outside), "
                "host.ssh_login_external_source and win.rdp_external_source (host logons from outside), "
                "net.long_unidentified_session (long data-carrying connections with no identified protocol, in "
                "either direction) and net.protocol_port_mismatch (a protocol that does not fit its port)",
        "research_basis": "ATT&CK Enterprise 20.0 T1071, T1095 and T1571 (network traffic flow detection); "
                          "reimplemented from the behavior. Opening and exchange semantics: Arkime "
                          "capture/parsers/tcp.c (a session is oriented by its SYN, and swapped when its first packet "
                          "is a SYN-ACK), Suricata EVE flow tcp_flags_ts/tc, Zeek conn.log history letters, "
                          "RFC 9293 section 3.10.7 (an endpoint answers a segment for no connection with a reset)",
        "retrieval": "the existing sweep retrieves Arkime sessions and bidirectional flow records, including "
                     "Zeek overlap lookback and interim records; unidirectional netflow follows flow-rule coverage",
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
        return conn["span_known"] and conn["end"] - conn["start"] >= self.MIN_SECONDS

    def reading(self, c: dict) -> str | None:
        """The reading a reportable connection is reported under, or None (counted on the window cell)."""
        reading = _outbound(c)
        if reading in OUTBOUND_REPORTED:
            return reading
        if reading == OUTBOUND_SERVED and not _web_only(c):
            reading = SERVED_ELSEWHERE
        self._unreported.add(reading, c["end"] - c["start"], c)
        return None

    @staticmethod
    def _sides(c: dict) -> str:
        """The connection's two ends and each one's bytes, with the client named only when a record shows it."""
        first = (c["src"], c["sport"])
        span = f"{(c['end'] - c['start']) / 60:.0f} minutes ({_iso(c['start'])} – {_iso(c['end'])})"
        if len(c["openers"]) == 1:
            client_first = tuple(c["openers"][0]) == first
            client, server = ((c["src"], c["sport"]), (c["dst"], c["dport"]))[::1 if client_first else -1]
            sent = (c["sent_src"], c["sent_dst"])[::1 if client_first else -1]
            return (f"one TCP connection that {client[0]}:{client[1]} opened to {server[0]}:{server[1]} (a record "
                    f"shows its SYN) spanning {span}, {sent[0]} bytes from the client and {sent[1]} bytes from the "
                    f"server.")
        if c["openers"]:
            unknown = "its records disagree about which side opened it (each side is recorded sending a SYN)"
        elif c["flagged"]:
            unknown = ("no record of it shows a SYN (Arkime picked it up mid-stream, or it opened before the hunt "
                       "window)" if set(c["sensors"]) == {ARKIME} else
                       "no record shows the opening (the sensors picked it up mid-stream, or it opened before the hunt window)")
        else:
            unknown = "no record of it carries TCP flag counts"
        return (f"one TCP connection between {c['src']}:{c['sport']} and {c['dst']}:{c['dport']} spanning {span}, "
                f"{c['sent_src']} bytes from {c['src']}:{c['sport']} and {c['sent_dst']} bytes from "
                f"{c['dst']}:{c['dport']}. Which side opened it is not known: {unknown}.")

    @staticmethod
    def _port_shape(client: tuple, server: tuple) -> str:
        """Why a connection with no recorded opening is read with `client` as the client."""
        return (f" Both sides sent traffic beyond resets and handshake answers (per-side packet counts and TCP "
                f"flags), and {client[0]} used port {client[1]} (at or above {EPHEMERAL_FLOOR}, where common systems "
                f"pick client ports) while {server[0]} used port {server[1]}: the port shape of {client[0]} as the "
                f"client.")

    def explain(self, c: dict, reading: str) -> str:
        """What the claim adds about how the connection was read."""
        inside, outside = _ends(c)
        if reading == OUTBOUND_CLIENT_SHAPED:
            return self._port_shape(inside, outside)
        if reading == OUTBOUND_UNSHAPED:
            return (f" Both sides sent traffic beyond resets and handshake answers; the ports ({inside[0]} on "
                    f"{inside[1]}, {outside[0]} on {outside[1]}) mark neither side as the client.")
        if reading in HALF_SENTENCES:
            return " " + HALF_SENTENCES[reading].format(inside=inside[0], outside=outside[0])
        return ""

    def finalize(self):
        out = []
        self._unreported = _Unreported()
        for key, parts in groupby(self._merged_stretches(), key=lambda item: item[0]):
            c = self.conns.peek(key)
            staged = set(c["events"])
            count, leads = 0, []
            for _key, part in parts:
                count += 1
                if count > 1 and len(leads) < self.CONN_IDS and part[3] in staged:
                    leads.append(part[3])
            if not self.candidate(c):
                continue
            reading = self.reading(c)
            if reading is None:
                continue
            with citation_group(self, out, key, c):
                # the records bounding the span, the record showing the opening, the first record of each later stretch
                # of activity, then the connection's first records
                ids = ([c["opener_id"]] if c["opener_id"] in staged else []) + leads + c["events"]
                evs, missing = cite_with_bounds(self.load, self._events, c["ends"], ids, EXAMPLE_LIMIT)
                arkime_only = set(c["sensors"]) == {ARKIME}
                claim = (f"Arkime recorded {c['records']} session record(s) for {self._sides(c)} Only the part of the "
                         "connection that started inside the hunt window is counted." if arkime_only else
                         f"The sensors recorded {_sensor_counts(c['sensors'])} for {self._sides(c)} "
                         "The span uses the typed connection start and end, including overlapping lookback records. "
                         "Byte totals use one sensor's counters (Arkime when available, otherwise Zeek, then Suricata); "
                         "cumulative flow counters are counted once and are a lower bound when the same endpoints are reused.")
                claim += self.explain(c, reading)
                gaps = count - 1
                if gaps:
                    # Arkime writes a live connection's record at least every save interval: a long silence is a
                    # channel that slept, or the 5-tuple used again by a separate connection. Either way it is reported.
                    claim += (f" The records show {gaps} gap(s) of more than {self.IDLE / 3600:.0f} hour(s) without a "
                              f"record, so this may be one channel that slept between bursts or the same 5-tuple reused "
                              f"by separate connections; the span covers all of them.")
                claim += cited_phrase(len(evs), c["records"], not missing) + bound_note(missing, c["ends"], "the span")
                if not arkime_only:
                    claim += _per_sensor_cited(evs, {sensor: {"records": count} for sensor, count in c["sensors"].items()})
                if c["duration_missing"]:
                    claim += f" {ZEEK_NO_DURATION}; those records do not extend the stated span."
                by_id = {e.id: e for e in evs}
                opening = by_id.get(c["ends"].first[1]) or evs[0]
                closing = by_id.get(c["ends"].last[1]) or max(evs, key=lambda e: (_epoch(e.get("flow.end")) or 0, e.id))
                preds = [pf(opening, "source.ip"), pf(opening, "destination.ip"), pf(opening, "flow.start")]
                if closing.has("flow.end"):
                    preds.append(pf(closing, "flow.end"))
                if c["opener_id"] in by_id and len(c["openers"]) == 1:
                    preds.append(pf(by_id[c["opener_id"]], c["opener_field"]))
                out.append(Match(self.id, claim, self.claim_type, evs, preds, evs[0].ts, self.severity, self.lane,
                                 "high", evs[0].entities(), group_key=c["report_key"]))
        self._unreported.publish(self, lambda seconds: f"{seconds / 60:.0f} minutes", {SERVED_ELSEWHERE: (
            False, ("connections a recorded TCP opening shows an external address opened to an internal service other "
                   "than the ordinary web ports (reported as inbound sessions by net.long_inbound_session)"))})
        return out


# Remote-access and remote-administration services, by the internal (server) side's TCP port and by the protocol a
# sensor's parser identified: an outside client holding one of these open is interactive access to the inside.
REMOTE_ACCESS_PORTS: dict[int, str] = {22: "SSH", 23: "Telnet", 512: "rexec", 513: "rlogin", 514: "rsh",
                                       3389: "RDP", 5985: "WinRM over HTTP", 5986: "WinRM over HTTPS",
                                       **{port: "VNC" for port in range(5900, 5910)},
                                       **{port: "X11" for port in range(6000, 6064)}}
REMOTE_ACCESS_PROTOCOLS: dict[str, str] = {"ssh": "SSH", "telnet": "Telnet", "rdp": "RDP", "rfb": "VNC",
                                           "x11": "X11"}
_REMOTE_NAMES = frozenset({*REMOTE_ACCESS_PROTOCOLS, "vnc"})
# Ordinary public web service ports: HTTP 80 and HTTPS 443 (IANA) and their registered alternates http-alt 8080 and
# https-alt 8443. An outside client holding one of these open for half an hour is routine use of a published site
# (keep-alive, streaming, WebSocket and long-polling clients), so a session to one is not reported as inbound access
# unless a sensor identified a remote-access protocol on it. Every other internal service an outside address holds a
# long session to is reported.
WEB_PORTS = frozenset({80, 443, 8080, 8443})


def _remote_services(c: dict) -> list[str]:
    """The remote-access services a held connection's internal side offered, by its port and by identified protocol."""
    inside, _outside = _ends(c)
    names = {REMOTE_ACCESS_PROTOCOLS[p] for p in c["protocols"] if p in REMOTE_ACCESS_PROTOCOLS}
    if inside[1] in REMOTE_ACCESS_PORTS:
        names.add(REMOTE_ACCESS_PORTS[inside[1]])
    return sorted(names)


def _web_only(c: dict) -> bool:
    """The internal side's port is an ordinary web port and no remote-access protocol was identified on it."""
    return _ends(c)[0][1] in WEB_PORTS and not _remote_services(c)


class LongInboundSession(LongExternalConnection):
    """Long TCP sessions an outside address held open to one internal service: a record shows the outside address
    opened each, or no record shows the opening and both sides exchanged traffic with the outside address on a client
    port facing the service port. Ordinary web ports are left out. One item per (outside address, internal address,
    service port), counting and citing its sessions."""
    id = "net.long_inbound_session"
    version = "1"
    title = "Long TCP sessions an outside address held to an internal service"
    severity, lane = "medium", "lead"
    attack = ("T1133", "T1021")
    assures_negative = False
    uses_site_facts = True
    site_facts = absent_site_facts()
    positive_only_reason = (
        "only connections whose records show the outside address opened them, or show both sides exchanging traffic "
        "with the outside address on a client port, are read; a connection whose opener and exchange are not "
        "recorded is not judged here, and sessions to the ordinary web ports are not reported, so the absence of a "
        "match proves nothing")
    benign = ("administrators, vendors and partners using an exposed SSH, RDP or VNC service",
              ("VPN concentrators, jump hosts, mail, database and directory services deliberately exposed to outside "
              "clients"))
    next_checks = ("the logon or client session on the internal host for these sessions (account, method)",
                   "what the account or client did on the host during the sessions",
                   "the outside address (ownership, other internal hosts it reached)")
    SESSIONS_CITED = 6                  # sessions whose bounding and opening records are cited per item
    card: ClassVar[dict] = {
        "behavior": "an outside address held one or more TCP sessions, each spanning at least 30 minutes, open to one "
                    "service port of one internal address, read as sessions the outside address held: a record shows "
                    "the outside address opened each, or no record shows the opening, both sides sent traffic beyond "
                    "resets and handshake answers, and the outside address is on a port of 32768 or above facing the "
                    "internal port below it. Sessions to the ordinary web ports (80, 443, 8080, 8443) are not "
                    "reported unless a sensor identified a remote-access protocol on them",
        "telemetry": LongExternalConnection.card["telemetry"],
        "fidelity": "direct observation of the sessions' lifetime and opening by the sensors; it does not show a "
                    "logon succeeded or what was done. The opening is stated from the sensor's typed SYN evidence or, "
                    "when not recorded, the claim says the outside address is read as the client from the port shape. "
                    "A remote-access service (SSH 22, Telnet 23, rexec 512, rlogin 513, rsh 514, RDP 3389, VNC "
                    "5900-5909, WinRM 5985/5986, X11 6000-6063, or a sensor's ssh, telnet, rdp, rfb or x11 "
                    "identification) is named; other services are named by port and identified protocol",
        "benign_and_cost": "administrators, vendors and partners using exposed services, jump hosts, VPN "
                           "concentrators, exposed mail, database and directory services; one item per (outside "
                           "address, internal address, service port), with exact session counts. Scanners and "
                           "password guessers rarely hold a session for 30 minutes",
        "query_cost": "none beyond the sweep",
        "next_pivot": "the host's logon or service records for the sessions, then what was done",
        "adds": "the inbound view net.long_external_connection does not report (it reads outbound channels only). "
                "Overlaps net.external_rdp and net.vnc_session where Zeek or Suricata parse the negotiation; adds "
                "SSH, Telnet, r-services, WinRM, X11, databases, SMB, directory, VPN and any other exposed service, "
                "and Arkime-only sites",
        "research_basis": "ATT&CK Enterprise 20.0 T1133 (External Remote Services: network connection creation "
                          "and session metadata) and T1021; opening and exchange semantics as for "
                          "net.long_external_connection; web port list from the IANA registry (http, https, "
                          "http-alt, https-alt)",
        "retrieval": LongExternalConnection.card["retrieval"],
        "direction": LongExternalConnection.card["direction"],
        "lanes": "lead. Severity high for a remote-access service when the site's internal networks are configured "
                 "(interactive access from outside the declared site is high impact if unauthorized); medium for "
                 "other services, and for any service when the internal networks are the RFC 1918 defaults (the "
                 "item then carries the 'direction assumed' reason). A declared management host as the outside "
                 "address keeps the lead lane, with a note",
    }

    def wants(self, e: TypedEvent) -> bool:
        # a TCP connection with one public end, unless its first record puts the internal side on an ordinary web port
        # with no remote-access protocol identified
        if not super().wants(e):
            return False
        inside_port = e.get("destination.port") if _public(e.get("source.ip")) else e.get("source.port")
        if inside_port not in WEB_PORTS:
            return True
        listed = e.get("network.protocols")
        names = {str(p).lower() for p in (listed if isinstance(listed, list) else [listed]) if p}
        app = e.get("network.app_proto")
        if isinstance(app, str):
            names.add(app.lower())
        return bool(names & _REMOTE_NAMES)

    @staticmethod
    def held(c: dict) -> str | None:
        """OPENED_BY_OUTSIDE or EXCHANGED when the outside address held this long connection to an internal service
        this rule reports, else None."""
        if _web_only(c):
            return None
        judgement = _judgement(c)
        inside, outside = _ends(c)
        if judgement == OPENED_BY_OUTSIDE or (judgement == EXCHANGED and server_shaped(inside[1], outside[1])):
            return judgement
        return None

    def finalize(self):
        out = []
        groups = KeyedStore(self, "inbound_groups", self.HOT)
        for i, (key, c) in enumerate(self.conns.items(candidates=True)):
            if not self.candidate(c):
                continue
            judgement = self.held(c)
            if judgement is None:
                continue
            inside, outside = _ends(c)
            g = groups.setdefault((outside[0], inside[0], inside[1]), lambda: {
                "sessions": 0, "opened": 0, "records": 0, "first": None, "last": None, "longest": 0.0,
                "sensors": Counter(), "protocols": set(), "services": set(), "cited": [], "latest": None,
                "outside_ports": set()})
            if g is None:
                self.refuse("disk", "the inbound session groups' disk budget is spent; a session is not reported")
                continue
            g["sessions"] += 1
            g["opened"] += judgement == OPENED_BY_OUTSIDE
            g["records"] += c["records"]
            g["first"] = c["start"] if g["first"] is None else min(g["first"], c["start"])
            g["last"] = c["end"] if g["last"] is None else max(g["last"], c["end"])
            g["longest"] = max(g["longest"], c["end"] - c["start"])
            g["sensors"].update(c["sensors"])
            g["protocols"].update(c["protocols"])
            g["services"].update(_remote_services(c))
            if len(g["outside_ports"]) < EXAMPLE_LIMIT:
                g["outside_ports"].add(outside[1])
            ref = (c["start"], key)
            if g["latest"] is None or ref > g["latest"]:
                g["latest"] = ref
            if len(g["cited"]) < self.SESSIONS_CITED - 1 or ref < g["cited"][-1]:
                g["cited"] = sorted([*g["cited"], ref])[:self.SESSIONS_CITED - 1]
            if i % 10_000 == 9_999:
                groups.trim()
        configured = current().configured
        for (outside, inside, port), g in groups.items():
            with citation_group(self, out, (outside, inside, port), g):
                out.append(self._item(outside, inside, port, g, configured))
        groups.clear()
        return out

    def _item(self, outside: str, inside: str, port, g: dict, configured: bool) -> Match:
        refs = list(dict.fromkeys([*g["cited"], g["latest"]]))
        conns = [self.conns.peek(key) for _start, key in refs]
        ids = []
        for c in conns:
            staged = c["events"]
            ids += ([c["opener_id"]] if c["opener_id"] in staged else []) + staged[:1]
        evs, missing = cite_with_bounds(self.load, self._events, [c["ends"] for c in conns], ids, EXAMPLE_LIMIT)
        n, opened = g["sessions"], g["opened"]
        remote = sorted(g["services"])
        named = " and ".join(remote) if remote else (
            f"identified as {', '.join(sorted(g['protocols']))}" if g["protocols"] else "no protocol identified")
        service = f"port {port} ({named})"
        span = f"{_iso(g['first'])} – {_iso(g['last'])}"
        claim = (f"{outside} held {n} TCP session(s) of at least {self.MIN_SECONDS // 60} minutes open to {inside} "
                 f"{service} ({span}); the longest lasted {g['longest'] / 60:.0f} minutes. ")
        shaped = n - opened
        if opened:
            claim += (f"{'A record shows' if opened == 1 else 'Records show'} {outside} opened "
                      f"{'the session' if n == 1 else f'{opened} of them'} (its SYN). ")
        if shaped:
            ports = ", ".join(str(p) for p in sorted(g["outside_ports"]) if p is not None)
            claim += (f"{'It has' if n == 1 else f'{shaped} have'} no recorded opening, but both sides sent traffic "
                      f"beyond resets and handshake answers with {outside} on a port of {EPHEMERAL_FLOOR} or above "
                      f"(seen: {ports}) facing port {port}: the port shape of {outside} as the client. ")
        claim += (f"{inside} is an internal address and {outside} is outside the site's configured internal networks."
                  if configured else
                  f"The site's internal networks are not configured, so {inside} is internal and {outside} external "
                  f"only by the RFC 1918 defaults.")
        claim += " The sessions show access held open, not that a logon succeeded or what was done."
        claim += (f" The sensors recorded {_sensor_counts(g['sensors'])}."
                  + cited_phrase(len(evs), g["records"], not missing))
        if missing:
            claim += " A record bounding a cited session was not kept for citation; the span is computed from every record."
        severity = "high" if remote and configured else "medium"
        notes = [] if configured else [DIRECTION_ASSUMED_REASON]
        if address_member(outside, getattr(self.site_facts, "management_hosts", ())):
            notes.append("declared management source; authorized administration can produce these sessions")
        first = evs[0]
        preds = [pf(first, name) for name in ("source.ip", "destination.ip", "destination.port", "flow.start")
                 if first.has(name)]
        opener = next((c for c in conns if c["opener_id"] in {e.id for e in evs} and len(c["openers"]) == 1), None)
        if opener is not None:
            record = next(e for e in evs if e.id == opener["opener_id"])
            preds.append(pf(record, opener["opener_field"]))
        match = Match(self.id, claim, self.claim_type, evs, preds, first.ts, severity, self.lane, "high",
                      evs[0].entities(), notes, group_key=f"{outside}|{inside}|{port}")
        return match


class _Series:
    """One (internal source, public destination, port, transport) series, built at finalize: every connection's
    count, the earliest connections' first record ids and the latest connection's, and the protocols
    every connection was identified as."""

    __slots__ = ("count", "duration_missing", "first", "halves", "last", "opened", "protocols", "sensors")

    def __init__(self):
        self.count = 0
        self.first: list[tuple] = []                       # (start, first order, first id, sensor witnesses)
        self.last: tuple | None = None                     # latest-starting connection's witnesses
        self.protocols: frozenset | None = None
        self.sensors = Counter()
        self.opened = True
        self.halves = 0                                    # connections whose records show one side's half only
        self.duration_missing = False

    def add(self, part: list) -> None:
        start, _end, seq, event_id, protocols, witnesses = part
        self.count += 1
        ref = (start, seq, event_id, witnesses)
        if self.last is None or ref > self.last:
            self.last = ref
        if len(self.first) < EXAMPLE_LIMIT or ref < self.first[-1]:
            self.first = sorted([*self.first, ref])[:EXAMPLE_LIMIT]
        self.protocols = protocols if self.protocols is None else self.protocols & protocols

    def citation_ids(self):
        refs = list({ref[1]: ref for ref in (self.first[0], self.last, *self.first)}.values())
        sensors = (ARKIME, SURICATA, ZEEK)
        preferred = lambda ref: next((ref[3][sensor][2] for sensor in sensors if sensor in ref[3]), ref[2])
        ids = [preferred(refs[0]), preferred(refs[1] if len(refs) > 1 else refs[0])]
        ids.extend(min(ref[3].values())[2] for ref in refs[:2])       # exact start bounds, even under sensor skew
        # Keep one example from each observed sensor before filling the remaining bounded slots with Arkime.
        for sensor in sensors:
            ids.extend(next(([ref[3][sensor][2]] for ref in refs if sensor in ref[3]), []))
        for sensor in sensors:
            ids.extend(ref[3][sensor][2] for ref in refs if sensor in ref[3])
        ids = list(dict.fromkeys(ids))[:EXAMPLE_LIMIT]
        cited = set(ids)
        connections = sum(any(event_id in cited for _start, _seq, event_id in ref[3].values()) for ref in refs)
        return ids, connections


class Beaconing(_Stitched):
    """Many separate connections from one internal address to one public endpoint at regular intervals. A
    connection identity whose records are more than IDLE apart is counted as separate connections (one per stretch
    of activity), so a 5-tuple reused by a periodic client still shows its period. UDP uses UDP_GAP, half of
    MIN_INTERVAL. A gap shorter than MIN_INTERVAL can never be a reportable period, so merging inside half of it
    cannot hide a beacon. It absorbs millisecond truncation, ordinary sensor skew, and Arkime's back-to-back splits
    of one long UDP session."""
    id = "net.beaconing"
    version = "9"
    direction_dependent = True
    title = "Regular, repeated connections from an internal address to one public endpoint"
    severity, lane = "medium", "lead"
    attack = ("T1071", "T1029", "T1573")
    benign = ("NTP, update checks, telemetry and monitoring agents", "scheduled jobs polling an approved service")
    next_checks = ("process connections on the internal host for this endpoint",
                   "scheduled tasks or cron entries on the internal host", "DNS history for the endpoint")
    MIN_CONNECTIONS = 8
    MIN_INTERVAL = 10.0
    UDP_GAP = MIN_INTERVAL / 2
    MAX_JITTER = 0.1          # median absolute deviation of the intervals, relative to their median
    card: ClassVar[dict] = {
        "behavior": "at least 8 separate connections from one address inside the site to one address outside it, "
                    "on one port and transport, starting at a regular interval (median at least 10 s, median "
                    "absolute deviation at most a tenth of it)",
        "telemetry": "Arkime sessions as net_session, Suricata flow and Zeek conn as net_flow: source.ip, "
                     "destination.ip, endpoint ports, network.transport, flow.start/end and identified protocols",
        "fidelity": "aggregate observation of connection start times; regularity is a deviation, not proof of "
                    "command and control. A connection counts when a record shows the internal address opened it, "
                    "when no record shows the opening but both sides sent traffic beyond resets and handshake "
                    "answers with the internal address on a port of 32768 or above facing a port below it, when "
                    "the records show only one side's half of it (one-way capture; read from the internal address "
                    "outwards, as the claim says), or when the records lack the per-side counters to tell or show "
                    "an exchange whose ports mark neither side (then the recorded sides are used). Connections an "
                    "outside address is shown to have opened, and records in which the internal address answered "
                    "with nothing beyond resets and handshake answers or neither side sent more (unsolicited "
                    "answers such as backscatter), are not counted and are named on the window cell; exchanged "
                    "connections with the internal address on a port below 32768 facing an outside port at or "
                    "above it are named there too and make the cell partial",
        "benign_and_cost": "NTP (context lane when the parser names it), update checks, telemetry and monitoring "
                           "agents; one item per (source, destination, port, transport)",
        "query_cost": "none beyond the sweep",
        "next_pivot": "the internal host's process and scheduled jobs for the endpoint",
        "adds": "the only rule that measures the regularity of repeated connections",
        "research_basis": "ATT&CK Enterprise 20.0 T1071, T1029 and T1573; reimplemented from the behavior",
        "retrieval": "the existing sweep retrieves Arkime sessions and bidirectional flow records; the shared "
                     "endpoint identity merges sensors, and unidirectional netflow follows flow-rule coverage",
        "direction": "inside and outside are decided by the site's internal-network definition; under the default "
                     "(RFC 1918 and reserved ranges, not configured for the site) a partition holding a record "
                     "between two routable addresses that is not inside-to-outside, skipped for that reason alone, "
                     "is partial with the reason 'direction assumed', never a complete negative",
        "lanes": "lead, or context when a sensor's parser identified every connection as a protocol periodic by "
                 "design; severity medium",
    }

    @staticmethod
    def skipped_for_direction(e: TypedEvent) -> bool:
        """Only internal-to-public series are judged: any other routable pair is skipped for its direction alone."""
        return _both_routable(e) and not (_public(e.get("destination.ip")) and not _public(e.get("source.ip")))

    TRIM_EVERY = 10_000
    TIMING_HOT = 1024             # bounded scratch avoids needing disk for a small, already-held positive

    def __init__(self):
        super().__init__()
        self.starts = SpillList(self, "beacon_starts", min(self.HOT, self.TIMING_HOT))

    @staticmethod
    def _median(rows, count):
        """Exact median of ordered (value, multiplicity) rows with constant Python state."""
        low, high = (count - 1) // 2, count // 2
        seen, first = 0, None
        for value, copies in rows:
            seen += copies
            if first is None and seen > low:
                first = value
            if seen > high:
                return (first + value) / 2
        raise ValueError("incomplete beacon interval statistics")

    def _timing(self, key, count):
        """Small populations use bounded scratch; larger populations use the capped spill database."""
        if not self.starts.on_disk:
            starts = sorted(order[0] for order, _record in self.starts.buffer if order[1] == key)
            gaps = [second - first for first, second in pairwise(starts)]
            median = statistics.median(gaps)
            return median, statistics.median(abs(gap - median) for gap in gaps)
        spill = self.spill()
        if not getattr(self, "_timing_ready", False):
            spill.table("beacon_gaps", "value REAL PRIMARY KEY, copies INTEGER")
            spill.cap()
            try:
                spill.db.execute("CREATE INDEX beacon_start_order ON beacon_starts(o2, o1)")
            except sqlite3.Error as exc:
                raise spill.failed(exc) from exc
            finally:
                spill.grew()
            self._timing_ready = True
        spill.write("DELETE FROM beacon_gaps", [()])
        previous, pending = None, Counter()
        for (start,) in spill.execute("SELECT o1 FROM beacon_starts WHERE o2=? ORDER BY o1", (key,)):
            if previous is not None:
                pending[start - previous] += 1
            previous = start
            if len(pending) >= self.starts.hot_size:
                spill.write("INSERT INTO beacon_gaps VALUES (?, ?) ON CONFLICT(value) DO UPDATE SET copies=copies+excluded.copies",
                            list(pending.items()))
                pending.clear()
        if pending:
            spill.write("INSERT INTO beacon_gaps VALUES (?, ?) ON CONFLICT(value) DO UPDATE SET copies=copies+excluded.copies",
                        list(pending.items()))
        median = self._median(spill.execute("SELECT value, copies FROM beacon_gaps ORDER BY value"), count - 1)
        left = ((median - value, copies) for value, copies in spill.execute(
            "SELECT value, copies FROM beacon_gaps WHERE value<? ORDER BY value DESC", (median,)))
        right = ((value - median, copies) for value, copies in spill.execute(
            "SELECT value, copies FROM beacon_gaps WHERE value>=? ORDER BY value", (median,)))
        mad = self._median(heapq.merge(left, right), count - 1)
        return median, mad

    def wants(self, e: TypedEvent) -> bool:
        # Retain either recorded orientation: a later sensor can provide the opening evidence.
        return _public(e.get("destination.ip")) != _public(e.get("source.ip"))

    def cite(self, conn: dict, e: TypedEvent, opened: bool) -> bool:
        # A stretch is cited by its first record read, which opened a stretch when it was read (stretches only merge
        # as records arrive): staging exactly the records that open one keeps every possible citation.
        return opened

    @staticmethod
    def _oriented(c: dict, unreported: _Unreported) -> tuple | None:
        """(internal source, its port, public destination, its port) of a connection the rule counts, or None. A
        connection whose opener the records cannot settle keeps its recorded sides and counts only when they run
        from inside to outside."""
        reading = _outbound(c)
        if reading not in OUTBOUND_REPORTED:
            unreported.add(reading, c["records"], c)
            return None
        if reading not in (OUTBOUND_UNKNOWN, OUTBOUND_UNSHAPED):
            (src, sport), (dst, dport) = _ends(c)
            return src, sport, dst, dport, reading in (OUTBOUND_OUTSIDE_HALF, OUTBOUND_INSIDE_HALF)
        if _public(c["src"]) or not _public(c["dst"]):
            return None
        return c["src"], c["sport"], c["dst"], c["dport"], False

    def finalize(self):
        series = KeyedStore(self, "beacon_series", self.HOT)
        unreported = _Unreported()
        previous, c, oriented = None, None, None
        for i, (key, part) in enumerate(self._merged_stretches()):
            first = key != previous
            if first:
                previous, c = key, self.conns.peek(key)
                oriented = self._oriented(c, unreported)
            if oriented is None:
                continue
            src, _sport, dst, dport, half = oriented
            s = series.setdefault((src, dst, dport, c["transport"]), _Series)
            if s is None:
                self.refuse("disk", "the series' disk budget is spent; a connection is not evaluated")
                continue
            if first:
                s.halves += half
                s.sensors.update(c["sensors"])
                s.opened = s.opened and len(c["openers"]) == 1
                s.duration_missing = s.duration_missing or c["duration_missing"]
            if not self.starts.append(part[0], (part[0], f"{src}|{dst}|{dport}|{c['transport']}")):
                self.refuse("disk", "the connection-start disk budget is spent; a connection is not evaluated")
                continue
            s.add(part)
            if len(self.starts.buffer) >= self.starts.hot_size:
                self.starts.trim(0)
            if i % self.TRIM_EVERY == self.TRIM_EVERY - 1:
                series.trim()
        if self.starts.on_disk:
            self.starts.trim(0)
        unreported.publish(self, lambda records: f"{records} record(s)")
        out = []
        for (src, dst, dport, transport), s in series.items():
            with citation_group(self, out, (src, dst, dport, transport), s):
                if s.count < self.MIN_CONNECTIONS:
                    continue
                median, mad = self._timing(f"{src}|{dst}|{dport}|{transport}", s.count)
                if median < self.MIN_INTERVAL:
                    continue
                if mad / median > self.MAX_JITTER:
                    continue
                # the first and the last connection bound the stated span; the earliest others fill the rest
                ids, cited_connections = s.citation_ids()
                evs = sorted(self._events(ids), key=lambda e: ((ARKIME, SURICATA, ZEEK).index(sensor_of(e)), e.ts, e.id))
                # Protocols that are periodic by design, identified by Arkime's parser from packet content (not the
                # port): still reported, in the context lane, never dropped
                periodic = sorted(s.protocols & PERIODIC_BY_DESIGN)
                arkime_only = set(s.sensors) == {ARKIME}
                observer = "Arkime" if arkime_only else "The sensors"
                parser = "Arkime's parser" if arkime_only else "The sensors' parsers"
                claim = (f"{observer} recorded {s.count} separate {transport} connections from {src} to {dst} port {dport} "
                         f"({_iso(s.first[0][0])} – {_iso(s.last[0])}) starting every {median:.0f} s (median), with a median "
                         f"deviation of {mad:.1f} s between starts. "
                         + (f"The first records of all {s.count} connections are cited." if cited_connections >= s.count
                            else f"The first records of {cited_connections} of the {s.count} connections are cited, including "
                                 f"the first and the last.")
                         + (f" {parser} identified every connection as {', '.join(periodic)}, a protocol that is "
                            f"periodic by design." if periodic else ""))
                if not arkime_only:
                    claim += _per_sensor_cited(evs, {sensor: {"records": count} for sensor, count in s.sensors.items()})
                if not s.opened:
                    claim += (f" The records do not show that {src} opened every connection: where no opening is "
                              f"recorded, {src} is the side on a client port when both sides exchanged traffic, and "
                              f"otherwise the side the sensor recorded first.")
                if s.halves:
                    claim += (f" For {s.halves} of the connections the records show only one side's half (the other "
                              f"side sent nothing, or nothing beyond resets and handshake answers: one-way capture "
                              f"or an unanswered peer); they are read from {src} outwards.")
                if s.duration_missing:
                    claim += f" {ZEEK_NO_DURATION}; only the recorded starts are used for those records."
                cited = next((e for e in evs if canon_ip(e.get("source.ip")) == src), evs[0])
                preds = [pf(cited, "source.ip"), pf(cited, "destination.ip"), pf(cited, "destination.port")]
                out.append(Match(self.id, claim, self.claim_type, evs, preds, evs[0].ts, self.severity,
                                 "context" if periodic else self.lane, "medium", evs[0].entities(),
                                 group_key=f"{src}|{dst}|{dport}|{transport}"))
        series.clear()
        self.starts.clear()
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
            with citation_group(self, out, (kind, value), p):
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
    version = "5"
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
                           "hosts; one finding per (recorded source, destination, destination port). The claim states "
                           "the session's own context so the analyst can weigh the tag: whether each end is internal "
                           "or public, which end opened it when a tagged record shows the SYN (otherwise that it is "
                           "not recorded, and no end is called the client), the SSH software both ends announced and "
                           "the HASSH values, the bytes each way, and how many other SSH connections between the same "
                           "pair Arkime recorded without the tag. The cited records include the tagged records with "
                           "the first and last record time and the latest end",
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
        self.bounds = BoundStage()      # the tagged records bounding each pair's stated span, staged when a batch ends
        self.load = lambda ids: []

    def drain_bounds(self) -> tuple[list[str], list[str]]:
        return self.bounds.last

    def drain_staged(self) -> list[TypedEvent]:
        out, self._pending = self._pending + self.bounds.drain(), []
        for store in self._fresh:
            store.staged()
        self._fresh = []
        self.pairs.trim()                       # after staging: a trimmed pair holds references only
        return out

    def release_state(self) -> None:
        self.load = lambda ids: []
        self.pairs.clear()
        self.bounds.clear()
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
                                "versions": set(), "hassh": set(), "hassh_server": set(), "tags": set(), "end": None,
                                "by_time": Ends(), "by_end": Ends(), "opened": set(), "flagged": False}
                pair["examples"] = HeldExamples(EXAMPLE_LIMIT)
            g = pair["info"]
            g["records"] += 1
            g["conns"].add(self._conn_key(e))
            g["first"], g["last"] = min(g["first"], e.ts), max(g["last"], e.ts)
            end = _epoch(e.get("flow.end"))
            if end is not None:
                g["end"] = end if g["end"] is None else max(g["end"], end)
            # the tagged records that bound the claim's span: the first and last record time, and the latest end
            ts = e.ts.timestamp()
            self.bounds.offer((key, "time"), g["by_time"], ts, ts, e)
            self.bounds.offer((key, "end"), g["by_end"], ts, ts if end is None else end, e)
            syn = _syn(e)
            if syn is not None:
                g["flagged"] = True
            if syn:
                g["opened"].add(self._conn_key(e))      # a connection this tagged record shows src opened
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
    def _scope(src: str, dst: str, opened: bool) -> str:
        """Where the two ends sit, by the configured internal ranges ('' when either is not a routable address).
        Each end is named client or server only when tagged records show the opening of every tagged connection."""
        client, server = canon_ip(src), canon_ip(dst)
        if not (routable_remote(client) and routable_remote(server)):
            return ""
        if not external(client) and not external(server):
            return " Both ends are internal addresses."
        if external(client) and external(server):
            return " Both ends are public addresses."
        first, second = ("The client ", "the server ") if opened else ("", "")
        if external(server):
            return f" {first}{src} is internal and {second}{dst} is a public address."
        return f" {first}{src} is a public address and {second}{dst} is internal."

    @staticmethod
    def _opening(src: str, g: dict) -> str:
        """What the tagged records show about which end opened the sessions."""
        opened, tagged = len(g["opened"]), len(g["conns"])
        if opened and opened == tagged:
            return (f" A tagged record shows the SYN from {src}, so {src} opened the session." if tagged == 1 else
                    f" Tagged records show the SYN from {src} on all {tagged} tagged connections, so {src} opened "
                    f"them.")
        if opened:
            return (f" Tagged records show the SYN from {src} on {opened} of the {tagged} tagged connections, so "
                    f"{src} opened those; for the others, which end opened them is not recorded.")
        if g["flagged"]:
            return (" No tagged record shows the SYN (Arkime picked the session up mid-stream, or it opened before "
                    "the hunt window), so which end opened it is not recorded.")
        return " No tagged record carries TCP flag counts, so which end opened the session is not recorded."

    def _context(self, key: tuple, g: dict, known: set) -> str:
        """The session's own context, stated beside the tag: address scope, bytes, announced software,
        fingerprints, other tags, and the pair's untagged SSH connections (a denominator for the heuristic)."""
        src, dst, port = key
        every = len(g["opened"]) == len(g["conns"])      # every tagged connection shows src opened it
        text = self._scope(src, dst, every) + self._opening(src, g)
        span = (g["end"] - g["first"].timestamp()) if g["end"] is not None else None
        def volume(side: str) -> str:
            missing = g.get(f"{side}_missing", 0)
            if missing == g["records"]:
                return "a byte count not recorded"
            return (f"at least {g[side]} bytes (not recorded on {missing} record(s))" if missing
                    else f"{g[side]} bytes")

        sides = ("the client", "the server") if every else (src, dst)
        text += (f" The tagged record(s) carry {volume('c2s')} from {sides[0]} and {volume('s2c')} from {sides[1]}"
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
                 "the tag in the window (counted; their records are not cited)." if others else
                 f" Arkime recorded no other SSH connection from {src} to {dst} port {port} in the window.")
        return text

    @staticmethod
    def _conn_key(e: TypedEvent) -> str:
        return str(e.get("network.community_id") or e.id)

    def finalize(self):
        out = []
        for key, pair in self.pairs.items(candidates=True):
            with citation_group(self, out, key, pair):
                g = pair["info"]
                # the tagged records bounding the stated span and its duration first, then the held examples
                bounds = list(dict.fromkeys(g["by_time"].ids() + g["by_end"].ids()))
                held = {e.id: e for e in self.load(bounds)}
                examples = pair["examples"].events(self.load)
                ordered = list(dict.fromkeys([*(i for i in bounds if i in held), *(e.id for e in examples)]))
                by_id = {**{e.id: e for e in examples}, **held}
                evs = sorted((by_id[i] for i in ordered[:EXAMPLE_LIMIT]), key=lambda e: (e.ts, e.id))
                missing = set(bounds) - set(held)
                src, dst, port = key
                # the span runs from the first tagged record's start to the latest end of a tagged record (or the last
                # tagged record's time when no end is recorded): the interval the stated duration measures
                end = _iso(g["end"]) if g["end"] is not None else g["last"].isoformat()
                claim = (f"Arkime's heuristic tagged {g['records']} session record(s) of {len(g['conns'])} connection(s) "
                         f"from {src} to {dst} port {port} '{self.TAG}' ({g['first'].isoformat()} – {end}). This is "
                         f"Arkime's own detection from the traffic shape, like an IDS alert; it does not show that a shell "
                         f"ran.") + self._context(key, g, pair["ssh"])
                claim += cited_phrase(len(evs), g["records"], not missing, "tagged records", "tagged record")
                if g["by_time"].first and g["by_time"].first[1] in missing:
                    claim += (" The record that starts the tagged records' span was not kept for citation; the interval is "
                              "computed from every record.")
                if g["end"] is not None and g["by_end"].last and g["by_end"].last[1] in missing:
                    claim += " The record that ends the last tagged session was not kept for citation."
                elif g["end"] is None and g["by_time"].last and g["by_time"].last[1] in missing:
                    claim += " The last tagged record was not kept for citation."
                out.append(Match(self.id, claim, self.claim_type, evs,
                                 [pf(evs[0], "arkime.tags"), pf(evs[0], "source.ip"), pf(evs[0], "destination.ip")],
                                 evs[0].ts, self.severity, self.lane, "medium", evs[0].entities(),
                                 group_key="|".join(key)))
        return out


SESSION_PLAYBOOKS = [LongExternalConnection, LongInboundSession, Beaconing, RareClientFingerprint,
                     ArkimeSshReverseShellTag]
