"""Network-session playbooks over Arkime SPI records (net_session).

Arkime writes a long-lived connection as several session records, one per save interval, sharing the
5-tuple and community ID. These rules stitch records by community ID so a connection is judged as a
whole. Every value comes from typed session fields; nothing is matched in text.
"""
from __future__ import annotations

import itertools
import statistics
from collections import defaultdict
from datetime import UTC, datetime

from romulus.detect.base import Match, Playbook, pf
from romulus.detect.correlation import StageMissing, canon_ip, external
from romulus.evidence.typed import TypedEvent

EXAMPLE_LIMIT = 20
PERIODIC_BY_DESIGN = {"ntp"}      # Arkime parser protocol names whose normal operation is a fixed poll interval


def _public(ip) -> bool:
    """Routable and outside the configured internal space: the same boundary the host rules use."""
    return external(canon_ip(ip))


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


def _first(value):
    return value[0] if isinstance(value, list) and value else value


class _Stitched(Playbook):
    """Groups net_session records into connections by community ID (or the 5-tuple when absent). Memory
    holds per-connection summaries and event ids; the events themselves are staged on disk."""
    kind = "aggregate"
    staged = True
    claim_type = "network_observation"
    families = ("net_session",)
    required_fields = ("source.ip", "destination.ip", "flow.start", "flow.end")

    def __init__(self):
        super().__init__()
        self.conns: dict[str, dict] = {}
        self._seen: set[str] = set()
        self._pending: list[TypedEvent] = []
        self.load = lambda ids: []

    def drain_staged(self) -> list[TypedEvent]:
        out, self._pending = self._pending, []
        return out

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
                c = self.conns[key] = {"start": start, "end": end, "records": 0, "events": [], "c2s": 0, "s2c": 0,
                                       "src": e.get("source.ip"), "sport": e.get("source.port"),
                                       "dst": e.get("destination.ip"), "dport": e.get("destination.port"),
                                       "transport": e.get("network.transport"), "observer": e.host,
                                       "protocols": set()}
            protocols = e.get("network.protocols")
            c["protocols"].update(protocols if isinstance(protocols, list) else [protocols] if protocols else [])
            c["start"], c["end"] = min(c["start"], start), max(c["end"], end)
            c["records"] += 1
            c["c2s"] += int(e.get("source.bytes") or 0)
            c["s2c"] += int(e.get("destination.bytes") or 0)
            if len(c["events"]) < EXAMPLE_LIMIT:
                c["events"].append(e.id)
                self._pending.append(e)
            self.observe(e, c)
        return []

    def observe(self, e: TypedEvent, conn: dict) -> None:
        """Per-record hook for subclasses."""

    def retained_events(self) -> list[TypedEvent]:
        return []           # staged on disk instead


class LongExternalConnection(_Stitched):
    id = "net.long_external_connection"
    title = "Long-lived TCP connection between an internal and a public address"
    severity, lane = "medium", "lead"
    attack = ("T1071", "T1095", "T1571")
    benign = ("remote administration sessions (SSH, RDP gateways)", "VPN tunnels and persistent push channels",
              "streaming and long downloads")
    next_checks = ("process connections on the internal host for this endpoint", "flow detail for the community ID",
                   "packets of the connection (cleartext content, TLS fingerprint)")
    MIN_SECONDS = 1800

    def finalize(self):
        out = []
        for key, c in self.conns.items():
            if c["transport"] != "tcp" or c["end"] - c["start"] < self.MIN_SECONDS:
                continue
            if _public(c["src"]) == _public(c["dst"]):
                continue                          # both internal or both public: not a boundary connection
            evs = self._events(c["events"])
            minutes = (c["end"] - c["start"]) / 60
            claim = (f"Arkime recorded {c['records']} session record(s) for one TCP connection {c['src']}:{c['sport']} "
                     f"-> {c['dst']}:{c['dport']} spanning {minutes:.0f} minutes ({_iso(c['start'])} – "
                     f"{_iso(c['end'])}), {c['c2s']} bytes from the client and {c['s2c']} bytes from the server. "
                     f"Only the part of the connection that started inside the hunt window is counted.")
            preds = [pf(evs[0], "source.ip"), pf(evs[0], "destination.ip"), pf(evs[0], "flow.start"),
                     pf(evs[-1], "flow.end")]
            out.append(Match(self.id, claim, self.claim_type, evs, preds, evs[0].ts, self.severity, self.lane,
                             "high", evs[0].entities(), group_key=key))
        return out


class Beaconing(_Stitched):
    """Many separate connections from one internal address to one public endpoint at regular intervals."""
    id = "net.beaconing"
    title = "Regular, repeated connections from an internal address to one public endpoint"
    severity, lane = "medium", "lead"
    attack = ("T1071", "T1029", "T1573")
    benign = ("NTP, update checks, telemetry and monitoring agents", "scheduled jobs polling an approved service")
    next_checks = ("process connections on the internal host for this endpoint",
                   "scheduled tasks or cron entries on the internal host", "DNS history for the endpoint")
    MIN_CONNECTIONS = 8
    MIN_INTERVAL = 10.0
    MAX_JITTER = 0.1          # median absolute deviation of the intervals, relative to their median

    def finalize(self):
        series: dict[tuple, list[dict]] = defaultdict(list)
        for c in self.conns.values():
            if _public(c["dst"]) and not _public(c["src"]):
                series[(c["src"], c["dst"], c["dport"], c["transport"])].append(c)
        out = []
        for (src, dst, dport, transport), conns in series.items():
            if len(conns) < self.MIN_CONNECTIONS:
                continue
            starts = sorted(c["start"] for c in conns)
            gaps = [b - a for a, b in itertools.pairwise(starts)]
            median = statistics.median(gaps)
            if median < self.MIN_INTERVAL:
                continue
            mad = statistics.median(abs(g - median) for g in gaps)
            if mad / median > self.MAX_JITTER:
                continue
            evs = self._events([c["events"][0] for c in sorted(conns, key=lambda c: c["start"])][:EXAMPLE_LIMIT])
            # Protocols that are periodic by design, identified by Arkime's parser from packet content (not the
            # port): still reported, in the context lane, never dropped
            periodic = sorted(set.intersection(*(c["protocols"] for c in conns)) & PERIODIC_BY_DESIGN)
            claim = (f"Arkime recorded {len(conns)} separate {transport} connections from {src} to {dst} port {dport} "
                     f"({_iso(starts[0])} – {_iso(starts[-1])}) starting every {median:.0f} s (median), with a median "
                     f"deviation of {mad:.1f} s between starts."
                     + (f" Arkime's parser identified every connection as {', '.join(periodic)}, a protocol that is "
                        f"periodic by design." if periodic else ""))
            preds = [pf(evs[0], "source.ip"), pf(evs[0], "destination.ip"), pf(evs[0], "destination.port")]
            out.append(Match(self.id, claim, self.claim_type, evs, preds, evs[0].ts, self.severity,
                             "context" if periodic else self.lane, "medium", evs[0].entities(),
                             group_key=f"{src}|{dst}|{dport}|{transport}"))
        return out


class RareClientFingerprint(_Stitched):
    """A TLS (JA3) or SSH (HASSH) client fingerprint used by only one internal address in the window, toward
    public endpoints. Rarity in one window is context, not a verdict."""
    id = "net.rare_client_fingerprint"
    title = "TLS or SSH client fingerprint seen from only one internal address"
    severity, lane = "low", "context"
    attack = ("T1071.001", "T1573", "T1021.004")
    benign = ("uncommon but legitimate clients, new software versions, a short hunt window",)
    next_checks = ("process connections on the internal host for these sessions",
                   "the same fingerprint across a longer window or other sites")
    MAX_CONNECTIONS = 5

    def __init__(self):
        super().__init__()
        self.prints: dict[tuple[str, str], dict] = {}

    def observe(self, e, conn):
        if not _public(e.get("destination.ip")) or _public(e.get("source.ip")):
            return
        for kind, field in (("JA3", "tls.ja3"), ("HASSH", "ssh.hassh")):
            value = _first(e.get(field))
            if not value:
                continue
            p = self.prints.setdefault((kind, str(value)), {"sources": set(), "conns": set(), "events": [],
                                                            "field": field})
            p["sources"].add(e.get("source.ip"))
            p["conns"].add(self._conn_key(e))
            if len(p["events"]) < EXAMPLE_LIMIT and e.id not in p["events"]:
                p["events"].append(e.id)
                self._pending.append(e)          # the stage ignores events it already holds

    def finalize(self):
        out = []
        for (kind, value), p in self.prints.items():
            if len(p["sources"]) != 1 or len(p["conns"]) > self.MAX_CONNECTIONS:
                continue
            evs = self._events(p["events"])
            src = next(iter(p["sources"]))
            dsts = sorted({str(e.get("destination.ip")) for e in evs})
            claim = (f"{kind} client fingerprint {value} appears on {len(p['conns'])} connection(s) in this window, all "
                     f"from {src}, to {', '.join(dsts[:5])}. No other internal address used it in the window.")
            out.append(Match(self.id, claim, self.claim_type, evs, [pf(evs[0], p["field"]), pf(evs[0], "source.ip")],
                             evs[0].ts, self.severity, self.lane, "medium", evs[0].entities(),
                             group_key=f"{kind}|{value}"))
        return out


SESSION_PLAYBOOKS = [LongExternalConnection, Beaconing, RareClientFingerprint]
