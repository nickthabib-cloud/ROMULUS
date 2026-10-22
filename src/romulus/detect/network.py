"""Network and web-access playbooks (Suricata EVE, Apache access). Aggregates are exact counts
accumulated across every partition, so bursts spanning partition boundaries are not lost."""
from __future__ import annotations

from typing import ClassVar

from romulus.detect.base import Match, Playbook, pf
from romulus.detect.bounded import KeyedStore
from romulus.detect.correlation import StageMissing
from romulus.evidence.typed import TypedEvent

TOOL_UA_PREFIXES = ("curl/", "wget/", "python-requests/", "python-urllib/", "go-http-client/", "libwww-perl/",
                    "powershell", "nmap", "sqlmap", "nikto", "fuzz faster u fool", "gobuster", "dirbuster")
EXAMPLE_LIMIT = 20


def _registered(name: str) -> str:
    parts = name.lower().rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else name.lower()


class _Group:
    """One group's state: an exact count, its first and last record times, per-rule sets, and up to EXAMPLE_LIMIT
    cited examples (the event until the sweep has staged it, then its id)."""

    __slots__ = ("count", "errors", "extra", "first", "held", "last", "replies")

    def __init__(self, ts):
        self.count = 0
        self.errors = 0                     # 4xx/5xx responses (web scan)
        self.extra: dict[str, set] = {}
        self.first = self.last = ts
        self.held: list[TypedEvent | str] = []
        self.replies: dict[int, list] = {}  # port scan: destination port of a low-source-port flow -> [first, sports]

    def bag(self, name: str) -> set:
        found = self.extra.get(name)
        if found is None:
            found = self.extra[name] = set()
        return found


class _Grouped(Playbook):
    """Exact per-group counts with up to EXAMPLE_LIMIT cited examples per group. Examples are held as ids once the
    sweep has staged their events. Group states live in a keyed store: the HOT most recently used in memory, the
    rest on the rule's disk spill, read back when a record of the group arrives again, so no group is ever released
    and a group's counts cover the whole hunt window however long its pauses. Only the store's disk budget can
    refuse a record (stated on coverage)."""
    kind = "aggregate"
    anchor_class = "network_observation"
    claim_type = "aggregate_observation"
    staged = True
    # Group states held in memory between batches: a few hundred bytes each, up to tens of kilobytes for a group
    # whose per-rule sets have filled (their caps are per group), so the hot set stays small.
    HOT: ClassVar[int] = 5_000

    def __init__(self):
        super().__init__()
        self.groups = KeyedStore(self, "net_groups", self.HOT, candidate=self.reportable)
        self._pending: list[TypedEvent] = []
        self._fresh: set[tuple] = set()             # groups holding events not yet handed to the stage
        self.load = lambda ids: []

    @property
    def counts(self) -> dict[tuple, int]:
        """Every group's record count (reads the whole store: for tests and small hunts)."""
        return {key: state.count for key, state in self.groups.items()}

    def reportable(self, state: _Group) -> bool:
        """Whether a group's state can still be reported (finalize reads only these from disk)."""
        return True

    def drain_staged(self) -> list[TypedEvent]:
        out, self._pending = self._pending, []
        for key in self._fresh:
            state = self.groups.hot.get(key)
            if state is not None:
                state.held = [x.id if isinstance(x, TypedEvent) else x for x in state.held]
        self._fresh.clear()
        self.trim()
        return out

    def trim(self) -> None:
        """Move the least recently used states to disk (only once their events are staged)."""
        self.groups.trim()

    def retained_events(self) -> list[TypedEvent]:
        return []                                   # staged on disk instead

    def state(self, key: tuple, e: TypedEvent) -> _Group | None:
        """The group's state for this record; None (refused, stated on coverage) when the disk budget is spent."""
        state = self.groups.setdefault(key, lambda: _Group(e.ts))
        if state is None:
            self.evaluated -= 1
            self.refuse("disk", "the groups' disk budget is spent; a record of a new group is not evaluated")
        return state

    def keep(self, key: tuple, e: TypedEvent) -> _Group | None:
        """Exact count for every record; retain up to EXAMPLE_LIMIT cited examples per group."""
        state = self.state(key, e)
        if state is None:
            return None
        state.count += 1
        if len(state.held) < EXAMPLE_LIMIT:
            state.held.append(e)
            self._fresh.add(key)
            self._pending.append(e)
        state.first, state.last = min(state.first, e.ts), max(state.last, e.ts)
        return state

    def examples(self, state: _Group) -> list[TypedEvent]:
        """The group's cited examples in the order they were read: from the stage, or the events themselves while
        they have not been handed to it (a caller that drives the rule without a sweep)."""
        ids = [x for x in state.held if isinstance(x, str)]
        found = {e.id: e for e in self.load(ids)} if ids else {}
        missing = [i for i in ids if i not in found]
        if missing:
            raise StageMissing(f"{self.id}: {len(missing)} cited event(s) absent from the stage")
        return [found[x] if isinstance(x, str) else x for x in state.held]

    def reported(self):
        """(key, state) of every group that can be reported, in key order, one state read at a time."""
        for key in sorted(self.groups.keys(candidates=True), key=lambda k: tuple(str(part) for part in k)):
            yield key, self.groups.peek(key)

    def release_state(self) -> None:
        self.load = lambda ids: []
        self.groups.clear()
        self._fresh.clear()
        self.close_spill()

    @staticmethod
    def span(state: _Group) -> str:
        return f"{state.first.isoformat()} – {state.last.isoformat()}"


class SuricataAlertStack(_Grouped):
    id = "net.suricata_alert_stack"
    title = "IDS alert signature observed between a source and destination"
    families = ("net_alert",)
    required_fields = ("alert.signature", "alert.severity", "source.ip", "destination.ip")
    severity, lane = "medium", "lead"
    attack = ()
    benign = ("signature false positives; scanners and crawlers on internet-facing services",)
    next_checks = ("ip_sessions for the source", "http_requests to the destination in the same minutes",
                   "entity_timeline of the destination host after the first alert")

    version = "2"

    def consume(self, events):
        """Group by (source, destination, category, severity); signatures are listed inside the group so a
        scanner triggering hundreds of signatures is one item, not hundreds."""
        for e in self.applicable(events):
            key = (e.get("source.ip"), e.get("destination.ip"), e.get("alert.category"), e.get("alert.severity"))
            state = self.keep(key, e)
            if state is None:
                continue
            sigs = state.bag("sigs")
            if len(sigs) < 2000:
                sigs.add((e.get("alert.signature_id"), e.get("alert.signature")))
            tech = e.get("alert.mitre_technique_id")
            if tech:
                state.bag("tech").update(tech if isinstance(tech, list) else [tech])
        return []

    def finalize(self):
        out = []
        for key, state in self.reported():
            evs = self.examples(state)
            src, dst, cat, sev = key
            n = state.count
            sigs = sorted(state.bag("sigs"), key=lambda s: (str(s[1]), str(s[0])))
            if cat == "Not Suspicious Traffic" or sev == 3:
                lane, severity = "context", "low"
            elif sev == 1:
                lane, severity = "high", "high"
            else:
                lane, severity = "lead", "medium"
            names = "; ".join(f"{s[1]} (sid {s[0]})" for s in sigs[:3])
            more = f" and {len(sigs) - 3} more" if len(sigs) > 3 else ""
            claim = (f"Suricata raised {n} '{cat}' alert(s) at severity {sev} across {len(sigs)} distinct signature(s) "
                     f"for traffic from {src} to {dst} ({self.span(state)}): {names}{more}. IDS alerts are signature "
                     f"matches, not proof of successful exploitation.")
            e0 = evs[0]
            m = Match(self.id, claim, self.claim_type, evs, [pf(e0, "alert.signature"), pf(e0, "alert.severity"),
                                                            pf(e0, "source.ip"), pf(e0, "destination.ip")],
                      e0.ts, severity, lane, "medium", e0.entities(), group_key=f"{src}|{dst}|{cat}|{sev}")
            if state.bag("tech"):
                m.notes.append(f"signature metadata ATT&CK: {sorted(state.bag('tech'))[:8]}")
            m.notes.append(f"signatures: {[s[0] for s in sigs[:50]]}")
            out.append(m)
        return out


class WebScanBurst(_Grouped):
    id = "web.scan_burst"
    title = "High-volume error-heavy web requests from one source"
    families = ("http_access",)
    required_fields = ("source.ip", "http.response.status_code", "url.original")
    severity, lane = "medium", "lead"
    attack = ("T1595.002", "T1595.003")
    benign = ("authorized vulnerability scans, search-engine crawlers, broken client loops",)
    next_checks = ("http_requests from the source with 2xx status after the burst",
                   "ids_alerts for the source", "entity_timeline of the web host after the burst")
    MIN_REQUESTS, MIN_ERROR_RATIO = 200, 0.5

    def reportable(self, state: _Group) -> bool:
        return state.count >= self.MIN_REQUESTS and state.errors / state.count >= self.MIN_ERROR_RATIO

    def consume(self, events):
        for e in self.applicable(events):
            key = (e.host, e.get("source.ip"))
            state = self.keep(key, e)
            if state is None:
                continue
            try:
                st = int(e.get("http.response.status_code"))
            except (TypeError, ValueError):
                self.evaluated -= 1
                self.missing_required += 1
                continue
            if st >= 400:
                state.errors += 1
            urls = state.bag("urls")
            if len(urls) < 5000:
                urls.add(e.get("url.original"))
            ua = e.get("user_agent.original")
            uas = state.bag("uas")
            if ua and len(uas) < 10:
                uas.add(ua)
        return []

    def finalize(self):
        out = []
        for key, state in self.reported():
            n, errs = state.count, state.errors
            if n < self.MIN_REQUESTS or errs / n < self.MIN_ERROR_RATIO:
                continue
            evs = self.examples(state)
            host, src = key
            uas = sorted(state.bag("uas"))
            claim = (f"{n} HTTP requests to {host} from {src} ({self.span(state)}), {errs} ({errs / n:.0%}) with "
                     f"4xx/5xx responses across {len(state.bag('urls'))}+ distinct URLs.")
            m = Match(self.id, claim, self.claim_type, evs, [pf(evs[0], "source.ip")], evs[0].ts, self.severity,
                      self.lane, "high", evs[0].entities(), group_key=f"{host}|{src}")
            if uas:
                m.notes.append("user-agent strings seen (self-reported, not proof of tool): " + "; ".join(uas[:5]))
            out.append(m)
        return out


class DnsSubdomainEnumeration(_Grouped):
    """Forward names only. Names in the reverse-lookup trees (in-addr.arpa, ip6.arpa) are evaluated and left to
    the reverse-lookup sweep rule, which reports any client with this rule's distinct-name count of reverse names at
    this rule's lane, with a host-discovery claim and the swept address range. Question records are `query`
    (`request` in newer sensor output) or carry no role; answers (`answer`, `response`) are not evaluated."""
    id = "net.dns_subdomain_enumeration"
    version = "4"
    title = "Many distinct subdomains of one domain queried by one source"
    families = ("dns_query",)
    required_fields = ("source.ip", "dns.question.name")
    severity, lane = "medium", "lead"
    attack = ("T1590.002",)
    benign = ("resolvers forwarding for many clients, CDN-heavy browsing, mail servers",)
    next_checks = ("ip_sessions for the source", "web.scan_burst or ids_alerts from the same source")
    MIN_DISTINCT = 100
    REVERSE_TREES = ("in-addr.arpa", "ip6.arpa")
    card: ClassVar[dict] = {
        "behavior": "one source queried many distinct names under one forward registered domain (last two labels)",
        "telemetry": "dns_query question records: source.ip, dns.question.name, dns.type (Suricata EVE dns: "
                     "present in the lab profile)",
        "fidelity": "direct observation of the questions; a query does not show which names exist",
        "benign_and_cost": "resolvers forwarding for many clients, CDN-heavy browsing, mail servers; one grouped "
                           "finding per (source, domain)",
        "query_cost": "none beyond the sweep",
        "next_pivot": "connections from the source to names that resolved",
        "adds": "wordlist brute force of a domain's names; reverse-tree names are the reverse-lookup sweep rule's",
        "research_basis": "ATT&CK Enterprise 20.0 T1590.002 (DNS)",
        "retrieval": "the sweep retrieves every record of a network target in each partition with no field "
                     "filter, a superset of what this evaluator reads",
        "state": "one group per (source, registered domain), counted over the whole hunt window however long its "
                 "pauses (a slow enumeration spread over days is still one group); groups not used recently are "
                 "held on the rule's disk spill and read back when the pair is queried again",
    }

    def reportable(self, state: _Group) -> bool:
        return len(state.bag("names")) >= self.MIN_DISTINCT

    def consume(self, events):
        for e in self.applicable(events):
            if e.get("dns.type") is not None and str(e.get("dns.type")).lower() not in ("query", "request"):
                # answers/other record types are not evaluated by this rule: they must not count toward a
                # complete negative (an answer-only capture still carries the enumeration)
                self.evaluated -= 1
                self.missing_required += 1
                continue
            if not isinstance(e.get("dns.question.name"), str):
                self.evaluated -= 1
                self.missing_required += 1
                continue
            key = (e.get("source.ip"), _registered(e.get("dns.question.name")))
            if key[1] in self.REVERSE_TREES:
                continue
            state = self.keep(key, e)
            if state is None:
                continue
            names = state.bag("names")
            if len(names) <= self.MIN_DISTINCT * 50:
                names.add(e.get("dns.question.name").lower())
        return []

    def finalize(self):
        out = []
        for key, state in self.reported():
            distinct = len(state.bag("names"))
            if distinct < self.MIN_DISTINCT:
                continue
            evs = self.examples(state)
            src, dom = key
            claim = (f"{src} issued {state.count} DNS queries for {distinct} distinct names under '{dom}' "
                     f"({self.span(state)}).")
            out.append(Match(self.id, claim, self.claim_type, evs, [pf(evs[0], "source.ip"),
                                                                     pf(evs[0], "dns.question.name")],
                             evs[0].ts, self.severity, self.lane, "medium", evs[0].entities(),
                             group_key=f"{src}|{dom}"))
        return out


class ToolUserAgentHttp(_Grouped):
    """Positive-only: the user agent is self-reported, attacker-controlled text, so its absence
    proves nothing; the prefix list also cannot see tools whose agent string does not start with the name."""
    id = "net.tool_user_agent_http"
    version = "2"
    assures_negative = False
    title = "HTTP requests whose user agent begins with a known command-line tool name"
    families = ("http_tx",)
    required_fields = ("source.ip", "destination.ip", "user_agent.original")
    severity, lane = "low", "lead"
    attack = ("T1105",)
    benign = ("health checks, package managers, monitoring scripts",)
    next_checks = ("process executions on the source host at the same time", "file_transfer for what was fetched")

    def consume(self, events):
        for e in self.applicable(events):
            ua = e.get("user_agent.original")
            if not isinstance(ua, str):
                self.evaluated -= 1
                self.missing_required += 1
                continue
            ua = ua.lower()
            if not ua.startswith(TOOL_UA_PREFIXES):
                continue
            key = (e.get("source.ip"), e.get("destination.ip"), e.get("http.hostname"), ua.split(" ")[0])
            state = self.keep(key, e)
            if state is None:
                continue
            urls = state.bag("urls")
            if len(urls) < 50:
                urls.add(e.get("url.original"))
        return []

    def finalize(self):
        out = []
        for key, state in self.reported():
            evs = self.examples(state)
            src, dst, hostname, ua = key
            urls = sorted(u for u in state.bag("urls") if u)
            claim = (f"{state.count} HTTP request(s) from {src} to {dst} (Host: {hostname}) with user agent "
                     f"'{ua}' ({self.span(state)}); URLs include {urls[:3]}. The user agent is self-reported.")
            out.append(Match(self.id, claim, self.claim_type, evs, [pf(evs[0], "user_agent.original"),
                                                                     pf(evs[0], "source.ip")],
                             evs[0].ts, self.severity, self.lane, "medium", evs[0].entities(),
                             group_key=f"{src}|{dst}|{ua}"))
        return out


class PortScan(_Grouped):
    id = "net.port_scan"
    title = "One source contacted many distinct ports on one destination"
    families = ("net_flow",)
    required_fields = ("source.ip", "destination.ip", "destination.port")
    severity, lane = "medium", "lead"
    attack = ("T1046", "T1595.001")
    benign = ("authorized vulnerability scanners, monitoring systems, some service discovery",)
    next_checks = ("ids_alerts for the source", "web.scan_burst / http_requests from the source afterwards",
                   "ip_sessions for the source across the network")
    MIN_PORTS = 25
    # Modern stacks pick client ports from 32768 and up (Linux 32768-60999, Windows 49152-65535), so a service's
    # answers go to ports there; a sweep of service ports lands mostly below it.
    EPHEMERAL_FLOOR = 32768
    # Ports are counted per (source, destination) over the whole hunt window, however slow the scan: a pair's state
    # is held on the rule's disk spill while it is quiet. The index of requests to services (the earliest start of
    # each 4-tuple, to tell an answer from a probe) is a keyed store too, HOT entries in memory.
    REQUESTS_HOT = 200_000
    version = "7"

    def __init__(self):
        super().__init__()
        self.requests = KeyedStore(self, "port_requests", self.REQUESTS_HOT)

    def reportable(self, state: _Group) -> bool:
        return len(state.bag("ports") | set(state.replies)) >= self.MIN_PORTS

    def trim(self) -> None:
        super().trim()
        self.requests.trim()

    def release_state(self) -> None:
        self.requests.clear()
        super().release_state()

    def consume(self, events):
        for e in self.applicable(events):
            src, dst = e.get("source.ip"), e.get("destination.ip")
            key = (src, dst)
            state = self.keep(key, e)
            if state is None:
                continue
            try:
                sport, dport = int(e.get("source.port")), int(e.get("destination.port"))
            except (TypeError, ValueError):
                sport = None
                try:
                    dport = int(e.get("destination.port"))
                except (TypeError, ValueError):
                    self.missing_required += 1
                    continue
            if sport is not None and sport < 1024 <= dport:
                # A service answering a client, or a probe sent from a fixed low source port (nmap -g 53) to
                # slip past stateless filters. Judged in finalize against the requests seen.
                seen = state.replies.setdefault(dport, [e.ts, set()])
                seen[0] = min(seen[0], e.ts)
                if len(seen[1]) < 8:
                    seen[1].add(sport)
                continue
            ports = state.bag("ports")
            if len(ports) < 70000:
                ports.add(dport)
            if sport is not None and sport >= 1024 > dport:
                tuple_ = (src, sport, dst, dport)
                held = self.requests.get(tuple_)
                if held is None:
                    if not self.requests.put(tuple_, e.ts):
                        self.note_limit("requests", "the request index's disk budget is spent; an answer to an "
                                                    "unindexed request is counted as a probe (more leads, never "
                                                    "fewer)")
                elif e.ts < held:
                    self.requests.put(tuple_, e.ts)
        return []

    def _answered(self, src, dst, port, seen) -> bool:
        """A port's low-source-port flows look like answers when a flow on the mirrored 4-tuple started strictly
        before the earliest of them. A probe's own response starts after the probe, and so does every response
        to an earlier run of the same scan, so a repeated scan is never matched this way."""
        first, sports = seen
        for sport in sports:
            start = self.requests.peek((dst, port, src, sport))
            if start is not None and start < first:
                return True
        return False

    def finalize(self):
        rows = []
        for key, state in self.reported():
            src, dst = key
            forward = state.bag("ports")
            replies = state.replies
            ports = forward | set(replies)
            if len(ports) < self.MIN_PORTS:
                continue
            evs = self.examples(state)
            answered = {port for port, seen in replies.items() if self._answered(src, dst, port, seen)}
            unanswered = set(replies) - answered
            client_range = {port for port in unanswered if port >= self.EPHEMERAL_FLOOR}
            probed = forward | (unanswered - client_range)
            sample = sorted(ports)[:12]
            claim = (f"{state.count} flow record(s) from {src} to {dst} covering {len(ports)} distinct destination "
                     f"ports ({self.span(state)}); e.g. {sample}.")
            if replies:
                sports = sorted({sport for _first, seen_ports in replies.values() for sport in seen_ports})
                claim += (f" {len(replies)} of the ports were reached from source port(s) {sports[:5]} below 1024: "
                          f"on {len(answered)} a flow from {dst} in the opposite direction started earlier (the shape "
                          f"of a request and its answer), {len(client_range)} go to client "
                          f"(ephemeral) ports with no recorded request, and {len(unanswered) - len(client_range)} "
                          f"have neither, the shape of a scan sent from a fixed low source port.")
                if "requests" in self.limits:
                    claim += (" The index of earlier flows reached its disk budget, so some answers may be counted as "
                              "probes.")
            if len(probed) >= self.MIN_PORTS:
                lane, severity = self.lane, self.severity
            else:
                # Mostly a service answering clients: kept visible, not a lead.
                lane, severity = "context", "low"
                claim += f" Only {len(probed)} port(s) look probed (retained for context)."
            rows.append((src, dst, claim, lane, severity, evs))
        scanned = {(src, dst) for src, dst, _claim, lane, _sev, _evs in rows if lane == self.lane}
        out = []
        for src, dst, claim, lane, severity, evs in rows:
            if lane == "context" and (dst, src) in scanned:
                # The target's answers to a scan that is itself a lead belong to that attack: keep them visible.
                lane, severity = self.lane, self.severity
                claim += f" These are reverse-direction flows of the port scan from {dst} to {src}, which is reported as a lead."
            out.append(Match(self.id, claim, self.claim_type, evs, [pf(evs[0], "source.ip"),
                                                                     pf(evs[0], "destination.ip")],
                             evs[0].ts, severity, lane, "high", evs[0].entities(), group_key=f"{src}|{dst}"))
        return out


NETWORK_PLAYBOOKS = [SuricataAlertStack, WebScanBurst, DnsSubdomainEnumeration, ToolUserAgentHttp, PortScan]
