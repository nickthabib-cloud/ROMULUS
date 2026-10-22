"""Network-session playbooks over Arkime SPI records (net_session) and Suricata handshake records.

Arkime writes a long-lived connection as several session records, one per save interval, sharing the
5-tuple and community ID. These rules stitch records by community ID so a connection is judged as a
whole. The fingerprint rarity rule also reads Suricata tls/ssh records through the same typed handshake
fields. Every value comes from typed fields; nothing is matched in text.
"""
from __future__ import annotations

import itertools
import statistics
from collections import defaultdict
from datetime import UTC, datetime
from typing import ClassVar

from romulus.detect.base import Match, Playbook, pf
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


class _Stitched(Playbook):
    """Groups net_session records into connections by community ID (or the 5-tuple when absent). Memory
    holds per-connection summaries and event ids; the events themselves are staged on disk."""
    kind = "aggregate"
    anchor_class = "network_observation"
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
    version = "2"
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

    def observe(self, e, conn):
        # a TCP record between two routable addresses on the same side is skipped for its direction alone
        if e.get("network.transport") == "tcp" and _both_routable(e) \
                and _public(e.get("source.ip")) == _public(e.get("destination.ip")):
            assume_direction(self)

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
    version = "2"
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

    def observe(self, e, conn):
        # only internal-to-public series are judged: any other routable pair is skipped for its direction alone
        if _both_routable(e) and not (_public(e.get("destination.ip")) and not _public(e.get("source.ip"))):
            assume_direction(self)

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
    """A handshake fingerprint or SSH client software string used by only one internal address in the window,
    toward public endpoints. Reads Arkime sessions and Suricata tls/ssh records through the shared typed contract
    (every value of a list-valued fingerprint field counts). Rarity in one window, with no baseline, is context,
    not a verdict: the lane stays context."""
    id = "net.rare_client_fingerprint"
    version = "3"
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

    def __init__(self):
        super().__init__()
        self.prints: dict[tuple[str, str], dict] = {}

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
            self.observe(e, None)
        return []

    def observe(self, e, conn):
        if not _public(e.get("destination.ip")) or _public(e.get("source.ip")) or canon_ip(e.get("source.ip")) is None:
            if _both_routable(e) and any(e.has(field) for _kind, field, _label in self.KINDS):
                assume_direction(self)              # a fingerprint skipped for its direction alone
            return
        for kind, field, _label in self.KINDS:
            value = e.get(field)
            for item in value if isinstance(value, list) else [value]:
                if not isinstance(item, str) or not item:
                    continue
                p = self.prints.setdefault((kind, item), {"sources": set(), "conns": set(), "events": [],
                                                          "field": field})
                p["sources"].add(canon_ip(e.get("source.ip")))
                p["conns"].add(self._conn_key(e))
                if len(p["events"]) < EXAMPLE_LIMIT and e.id not in p["events"]:
                    p["events"].append(e.id)
                    self._pending.append(e)          # the stage ignores events it already holds

    def finalize(self):
        out = []
        labels = {kind: label for kind, _field, label in self.KINDS}
        for (kind, value), p in self.prints.items():
            if len(p["sources"]) != 1 or len(p["conns"]) > self.MAX_CONNECTIONS:
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
    version = "2"
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

    def __init__(self):
        super().__init__()
        self._seen: set[str] = set()
        self.groups: dict[tuple, list[TypedEvent]] = defaultdict(list)
        self.info: dict[tuple, dict] = {}
        self.ssh_conns: dict[tuple, set[str]] = defaultdict(set)    # every SSH connection of a pair, tagged or not

    def consume(self, events):
        for e in self.applicable([e for e in events if e.id not in self._seen]):
            self._seen.add(e.id)
            if "tags" in (e.get("parse.malformed") or []):          # native path of arkime.tags
                self.evaluated -= 1
                self.missing_required += 1
                continue
            key = (str(e.get("source.ip")), str(e.get("destination.ip")), str(e.get("destination.port")))
            protocols = e.get("network.protocols")
            if "ssh" in (protocols if isinstance(protocols, list) else [protocols]):
                conns = self.ssh_conns[key]
                if len(conns) < self.PAIR_CONNS_CAP:
                    conns.add(self._conn_key(e))
            tags = e.get("arkime.tags")
            tags = tags if isinstance(tags, list) else [tags]
            if self.TAG not in tags:
                continue
            g = self.info.setdefault(key, {"records": 0, "conns": set(), "first": e.ts, "last": e.ts, "c2s": 0,
                                           "s2c": 0, "versions": set(), "hassh": set(), "hassh_server": set(),
                                           "tags": set(), "end": None})
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
            if len(self.groups[key]) < EXAMPLE_LIMIT:
                self.groups[key].append(e)
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

    def _context(self, key: tuple, g: dict) -> str:
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
        known = self.ssh_conns.get(key, set())
        others = len(known - g["conns"])
        at_least = "at least " if len(known) >= self.PAIR_CONNS_CAP else ""
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
        for key, evs in self.groups.items():
            g = self.info[key]
            src, dst, port = key
            claim = (f"Arkime's heuristic tagged {g['records']} session record(s) of {len(g['conns'])} connection(s) "
                     f"from {src} to {dst} port {port} '{self.TAG}' ({g['first'].isoformat()} – "
                     f"{g['last'].isoformat()}). This is Arkime's own detection from the traffic shape, like an IDS "
                     f"alert; it does not show that a shell ran.") + self._context(key, g)
            out.append(Match(self.id, claim, self.claim_type, evs,
                             [pf(evs[0], "arkime.tags"), pf(evs[0], "source.ip"), pf(evs[0], "destination.ip")],
                             evs[0].ts, self.severity, self.lane, "medium", evs[0].entities(),
                             group_key="|".join(key)))
        return out


SESSION_PLAYBOOKS = [LongExternalConnection, Beaconing, RareClientFingerprint, ArkimeSshReverseShellTag]
