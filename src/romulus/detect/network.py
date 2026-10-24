"""Network and web-access playbooks (Suricata EVE, Apache access). Aggregates are exact counts
accumulated across every partition, so bursts spanning partition boundaries are not lost."""
from __future__ import annotations

from typing import ClassVar

from romulus.detect.base import Match, Playbook, pf
from romulus.detect.bounded import HOT_COUNT, KeyedStore
from romulus.detect.citing import BoundStage, Ends, Named, bound_note, cite_extra, cited_phrase, more
from romulus.detect.correlation import StageMissing
from romulus.evidence.typed import TypedEvent

# A Suricata TCP flow record in one of these states shows its engine tracked the connection from its handshake, so its
# source opened it (romulus.detect.flows.OPENED_STATES); netflow records and other states show no opener.
OPENED_STATES = frozenset({"established", "closed"})
TOOL_UA_PREFIXES = ("curl/", "wget/", "python-requests/", "python-urllib/", "go-http-client/", "libwww-perl/",
                    "powershell", "nmap", "sqlmap", "nikto", "fuzz faster u fool", "gobuster", "dirbuster")
EXAMPLE_LIMIT = 20


def _values(value) -> list:
    return value if isinstance(value, list) else [value]


def _registered(name: str) -> str:
    parts = name.lower().rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else name.lower()


class _Group:
    """One group's state: an exact count, its first and last record times, per-rule sets, up to EXAMPLE_LIMIT cited
    examples (the event until the sweep has staged it, then its id), the records bounding its span (`ends`, held on
    the stage while they bound it) and one cited record for each value the claim names (`named`)."""

    __slots__ = ("count", "ends", "errors", "extra", "first", "held", "last", "named", "replies")

    def __init__(self, ts):
        self.count = 0
        self.errors = 0                     # 4xx/5xx responses (web scan)
        self.extra: dict[str, set] = {}
        self.first = self.last = ts
        self.held: list[TypedEvent | str] = []
        self.replies: dict[int, list] = {}  # port scan: destination port of a low-source-port flow -> [first, sports]
        self.ends = Ends()
        self.named: dict[str, Named] = {}

    def names(self, kind: str, limit: int) -> Named:
        found = self.named.get(kind)
        if found is None:
            found = self.named[kind] = Named(limit)
        return found

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
    HOT: ClassVar[int] = HOT_COUNT  # a count cap only: the hunt's memory budget sizes it in bytes

    def __init__(self):
        super().__init__()
        self.groups = KeyedStore(self, "net_groups", self.HOT, candidate=self.reportable)
        self._pending: list[TypedEvent] = []
        self._fresh: list[tuple[_Group, int]] = []  # (group, place) of each example not yet handed to the stage
        self.bounds = BoundStage()                  # the records bounding each group's span, staged when a batch ends
        self.load = lambda ids: []

    @property
    def counts(self) -> dict[tuple, int]:
        """Every group's record count (reads the whole store: for tests and small hunts)."""
        return {key: state.count for key, state in self.groups.items()}

    def reportable(self, state: _Group) -> bool:
        """Whether a group's state can still be reported (finalize reads only these from disk)."""
        return True

    def drain_staged(self) -> list[TypedEvent]:
        # each kept record once (an example may also be a named value's record), then the bounds' holds
        out, self._pending = list({e.id: e for e in self._pending}.values()) + self.bounds.drain(), []
        for state, place in self._fresh:            # staged now: each held example becomes its id
            held = state.held[place]
            if isinstance(held, TypedEvent):
                state.held[place] = held.id
        self._fresh.clear()
        self.trim()
        return out

    def drain_bounds(self) -> tuple[list[str], list[str]]:
        return self.bounds.last

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
            self._fresh.append((state, len(state.held) - 1))
            self._pending.append(e)
        state.first, state.last = min(state.first, e.ts), max(state.last, e.ts)
        self.bounds.offer_at(key, state.ends, e)
        return state

    def name(self, state: _Group, kind: str, value, e: TypedEvent, limit: int = 10) -> None:
        """Keep a cited record for one of the first `limit` distinct values of `kind` the group shows."""
        if state.names(kind, limit).offer(value, e):
            self._pending.append(e)

    def cite(self, state: _Group) -> tuple[list[TypedEvent], set[str]]:
        """The group's cited records: its first examples (what the finding is about), and for what the claim states
        its span's bounding records (when held) and every record a named value comes from. Returns them in time order,
        the bounding ids not held, and the ids cited only for the claim's statements."""
        examples = self.examples(state)
        named = [i for kind in sorted(state.named) for i in state.named[kind].ids.values()]
        unstaged = {e.id: e for e in [*self._pending, *(entry[0] for entry in self.bounds.pending.values())]}
        unstaged.update((e.id, e) for e in examples)

        def load(ids):
            found = {e.id: e for e in self.load([i for i in ids if i not in unstaged])}
            return [unstaged.get(i) or found[i] for i in ids if i in unstaged or i in found]

        def events(ids):
            found = load(ids)
            if len(found) != len(set(ids)):
                raise StageMissing(f"{self.id}: {len(set(ids)) - len(found)} cited event(s) absent from the stage")
            return found

        return cite_extra(load, events, state.ends, [e.id for e in examples], named)

    @staticmethod
    def told(evs: list[TypedEvent], state: _Group, missing: set[str], noun: str, one: str) -> str:
        """How many of the group's records are cited, and whether a bounding record was not kept."""
        return cited_phrase(len(evs), state.count, not missing, noun, one) + bound_note(missing, state.ends)

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
        self.bounds.clear()
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

    version = "3"
    SIGNATURES_NAMED = 10
    SIGNATURES_HELD = 2000      # distinct signatures held per group; beyond it the count is "at least"

    def consume(self, events):
        """Group by (source, destination, category, severity); signatures are listed inside the group so a
        scanner triggering hundreds of signatures is one item, not hundreds. The first SIGNATURES_NAMED distinct
        signatures each keep a cited record: those are the ones the claim names."""
        for e in self.applicable(events):
            key = (e.get("source.ip"), e.get("destination.ip"), e.get("alert.category"), e.get("alert.severity"))
            state = self.keep(key, e)
            if state is None:
                continue
            sigs = state.bag("sigs")
            sig = (e.get("alert.signature_id"), e.get("alert.signature"))
            if sig not in sigs:
                if len(sigs) < self.SIGNATURES_HELD:
                    sigs.add(sig)
                else:
                    state.extra["sigs_capped"] = True
                    self.note_limit("signatures", f"a group passed {self.SIGNATURES_HELD:,} distinct signatures held; "
                                                  f"its signature count is stated as a lower bound")
            self.name(state, "sigs", sig, e, self.SIGNATURES_NAMED)
            tech = e.get("alert.mitre_technique_id")
            if tech:
                state.bag("tech").update(tech if isinstance(tech, list) else [tech])
        return []

    def finalize(self):
        out = []
        for key, state in self.reported():
            evs, missing, context = self.cite(state)
            src, dst, cat, sev = key
            n = state.count
            sigs = sorted(state.bag("sigs"), key=lambda s: (str(s[1]), str(s[0])))
            named = sorted(state.names("sigs", self.SIGNATURES_NAMED).values(), key=lambda s: (str(s[1]), str(s[0])))
            if cat == "Not Suspicious Traffic" or sev == 3:
                lane, severity = "context", "low"
            elif sev == 1:
                lane, severity = "high", "high"
            else:
                lane, severity = "lead", "medium"
            names = "; ".join(f"'{s[1]}' (sid {s[0]})" for s in named[:3])
            # the signatures of the cited alerts, ordered as the claim names signatures: by name, then id
            cited_sigs = [sid for sid, _name in sorted(
                {(e.get("alert.signature_id"), e.get("alert.signature")) for e in evs
                 if e.get("alert.signature_id") is not None}, key=lambda s: (str(s[1]), str(s[0])))]
            cited_sigs = list(dict.fromkeys(cited_sigs))
            capped = bool(state.extra.get("sigs_capped"))
            at_least = "at least " if capped else ""
            in_cited = (f" All {len(sigs)} signatures are in cited alerts." if len(cited_sigs) >= len(sigs) and not capped
                        else f" {len(cited_sigs)} of {at_least or 'the '}{len(sigs)} signatures are in cited alerts.")
            listed = more(min(3, len(named)), len(sigs))
            claim = (f"Suricata raised {n} '{cat}' alert(s) at severity {sev} across {at_least}{len(sigs)} distinct "
                     f"signature(s) for traffic from {src} to {dst} ({self.span(state)}): {names}"
                     f"{listed + ' or more' if capped and listed else listed}."
                     + (in_cited if len(sigs) > 1 else "")
                     + self.told(evs, state, missing, "alerts", "alert")
                     + " IDS alerts are signature matches, not proof of successful exploitation.")
            e0 = evs[0]
            m = Match(self.id, claim, self.claim_type, evs, [pf(e0, "alert.signature"), pf(e0, "alert.severity"),
                                                            pf(e0, "source.ip"), pf(e0, "destination.ip")],
                      e0.ts, severity, lane, "medium", e0.entities(), group_key=f"{src}|{dst}|{cat}|{sev}",
                      context_ids=context)
            techs = sorted({t for e in evs for t in _values(e.get("alert.mitre_technique_id")) if t})
            if techs:
                others = len(state.bag("tech")) - len(techs)
                shown = f"{techs[:8]}{more(min(8, len(techs)), len(techs))}"
                m.notes.append(f"signature metadata ATT&CK of the cited alerts: {shown}"
                               + (f"; {others} other technique id(s) are in alerts not cited" if others > 0 else ""))
            others = len(sigs) - len(cited_sigs)
            shown = f"{cited_sigs[:10]}{more(min(10, len(cited_sigs)), len(cited_sigs))}"
            m.notes.append(f"signatures of the cited alerts: {shown}"
                           + (f"; {at_least}{others} other signature(s) are in alerts not cited" if others > 0 else ""))
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
    version = "2"
    AGENTS_NAMED = 5

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
            if ua:
                self.name(state, "uas", ua, e, self.AGENTS_NAMED)
        return []

    def finalize(self):
        out = []
        for key, state in self.reported():
            n, errs = state.count, state.errors
            if n < self.MIN_REQUESTS or errs / n < self.MIN_ERROR_RATIO:
                continue
            evs, missing, context = self.cite(state)
            host, src = key
            uas = sorted(state.names("uas", self.AGENTS_NAMED).values())
            claim = (f"{n} HTTP requests to {host} from {src} ({self.span(state)}), {errs} ({errs / n:.0%}) with "
                     f"4xx/5xx responses across {len(state.bag('urls'))}+ distinct URLs."
                     + self.told(evs, state, missing, "requests", "request"))
            m = Match(self.id, claim, self.claim_type, evs, [pf(evs[0], "source.ip")], evs[0].ts, self.severity,
                      self.lane, "high", evs[0].entities(), group_key=f"{host}|{src}", context_ids=context)
            if uas:
                every = len(state.bag("uas"))
                m.notes.append("user-agent strings of cited requests (self-reported, not proof of tool): "
                               + "; ".join(f"'{ua}'" for ua in uas)
                               + (more(len(uas), every) if every < 10 else " and possibly more"))
            out.append(m)
        return out


class DnsSubdomainEnumeration(_Grouped):
    """Forward names only. Names in the reverse-lookup trees (in-addr.arpa, ip6.arpa) are evaluated and left to
    the reverse-lookup sweep rule, which reports any client with this rule's distinct-name count of reverse names at
    this rule's lane, with a host-discovery claim and the swept address range. Question records are `query`
    (`request` in newer sensor output) or carry no role; answers (`answer`, `response`) are not evaluated."""
    id = "net.dns_subdomain_enumeration"
    version = "5"
    title = "Many distinct subdomains of one domain queried by one source"
    families = ("dns_query",)
    required_fields = ("source.ip", "dns.question.name")
    severity, lane = "medium", "lead"
    attack = ("T1590.002",)
    benign = ("resolvers forwarding for many clients, CDN-heavy browsing, mail servers",)
    next_checks = ("ip_sessions for the source", "web.scan_burst or ids_alerts from the same source")
    MIN_DISTINCT = 100
    NAMES_HELD = MIN_DISTINCT * 50      # distinct names held per group; beyond it the count is "at least"
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
            name = e.get("dns.question.name").lower()
            if name not in names:
                if len(names) < self.NAMES_HELD:
                    names.add(name)
                else:
                    state.extra["names_capped"] = True
                    self.note_limit("names", f"a group passed {self.NAMES_HELD:,} distinct names held; its name "
                                             f"count is stated as a lower bound")
        return []

    def finalize(self):
        out = []
        for key, state in self.reported():
            distinct = len(state.bag("names"))
            if distinct < self.MIN_DISTINCT:
                continue
            evs, missing, context = self.cite(state)
            src, dom = key
            at_least = "at least " if state.extra.get("names_capped") else ""
            shown = len({str(e.get("dns.question.name")).lower() for e in evs if e.get("dns.question.name")})
            claim = (f"{src} issued {state.count} DNS queries for {at_least}{distinct} distinct names under '{dom}' "
                     f"({self.span(state)}). {min(shown, distinct)} of {at_least or 'the '}{distinct} names are in "
                     f"cited records." + self.told(evs, state, missing, "queries", "query"))
            out.append(Match(self.id, claim, self.claim_type, evs, [pf(evs[0], "source.ip"),
                                                                     pf(evs[0], "dns.question.name")],
                             evs[0].ts, self.severity, self.lane, "medium", evs[0].entities(),
                             group_key=f"{src}|{dom}", context_ids=context))
        return out


class ToolUserAgentHttp(_Grouped):
    """Positive-only: the user agent is self-reported, attacker-controlled text, so its absence
    proves nothing; the prefix list also cannot see tools whose agent string does not start with the name."""
    id = "net.tool_user_agent_http"
    version = "3"
    URLS_NAMED = 3
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
            if e.get("url.original"):
                self.name(state, "urls", e.get("url.original"), e, self.URLS_NAMED)
        return []

    def finalize(self):
        out = []
        for key, state in self.reported():
            evs, missing, context = self.cite(state)
            src, dst, hostname, ua = key
            urls = sorted(u for u in state.names("urls", self.URLS_NAMED).values())
            every = len([u for u in state.bag("urls") if u])
            claim = (f"{state.count} HTTP request(s) from {src} to {dst} (Host: {hostname}) with user agent "
                     f"'{ua}' ({self.span(state)}); URLs include {urls}"
                     + (more(len(urls), every) if every < 50 else " and possibly more") + "."
                     + self.told(evs, state, missing, "requests", "request") + " The user agent is self-reported.")
            out.append(Match(self.id, claim, self.claim_type, evs, [pf(evs[0], "user_agent.original"),
                                                                     pf(evs[0], "source.ip")],
                             evs[0].ts, self.severity, self.lane, "medium", evs[0].entities(),
                             group_key=f"{src}|{dst}|{ua}", context_ids=context))
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
    REQUESTS_HOT = HOT_COUNT  # a count cap only: the hunt's memory budget sizes it in bytes
    version = "8"
    # Destination ports the claim names, each with a cited record (the first seen); and probed ports whose opening a
    # cited record shows (a Suricata TCP flow its engine tracked from the handshake).
    PORTS_NAMED = 12

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
                self.name(state, "ports", dport, e, self.PORTS_NAMED)
                seen = state.replies.setdefault(dport, [e.ts, set()])
                seen[0] = min(seen[0], e.ts)
                if len(seen[1]) < 8:
                    seen[1].add(sport)
                continue
            # a port number is 0-65535, so the distinct ports are bounded by construction and counted exactly
            state.bag("ports").add(dport)
            self.name(state, "ports", dport, e, self.PORTS_NAMED)
            if (e.get("network.transport") == "tcp" and e.get("flow.state") in OPENED_STATES
                    and e.get("flow.bytes_toserver") is not None):
                # a flow record (not netflow) its engine tracked from the handshake: its source opened the connection
                self.name(state, "opened", dport, e, self.PORTS_NAMED)
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
            evs, missing, context = self.cite(state)
            answered = {port for port, seen in replies.items() if self._answered(src, dst, port, seen)}
            unanswered = set(replies) - answered
            client_range = {port for port in unanswered if port >= self.EPHEMERAL_FLOOR}
            probed = forward | (unanswered - client_range)
            sample = sorted(state.names("ports", self.PORTS_NAMED).values())
            claim = (f"{state.count} flow record(s) from {src} to {dst} covering {len(ports)} distinct destination "
                     f"ports ({self.span(state)}); e.g. {sample}{more(len(sample), len(ports))}.")
            if replies:
                cited_sports = sorted({e.get("source.port") for e in evs if isinstance(e.get("source.port"), int)
                                       and e.get("source.port") < 1024 <= (e.get("destination.port") or 0)})
                claim += (f" {len(replies)} of the ports were reached from source ports below 1024"
                          + (f" (cited: {cited_sports[:5]})" if cited_sports else "") + ": "
                          f"on {len(answered)} a flow from {dst} in the opposite direction started earlier (the shape "
                          f"of a request and its answer), {len(client_range)} go to client "
                          f"(ephemeral) ports with no recorded request, and {len(unanswered) - len(client_range)} "
                          f"have neither, the shape of a scan sent from a fixed low source port.")
                if "requests" in self.limits:
                    claim += (" The index of earlier flows reached its disk budget, so some answers may be counted as "
                              "probes.")
            claim += self.told(evs, state, missing, "flow records", "flow record")
            if len(probed) >= self.MIN_PORTS:
                lane, severity = self.lane, self.severity
            else:
                lane, severity = "context", "low"     # mostly a service answering clients: kept visible, not a lead
                claim += f" Only {len(probed)} port(s) look probed."
            opened = sorted(port for port in state.names("opened", self.PORTS_NAMED).values() if port in probed)
            rows.append((src, dst, claim, lane, severity, evs, len(probed), opened, len(answered), context))
        scanned = {(src, dst) for src, dst, _claim, lane, *_rest in rows if lane == self.lane}
        out = []
        for src, dst, claim, lane, severity, evs, n_probed, opened, n_answered, context in rows:
            if lane == "context" and (dst, src) in scanned:
                # The target's side of a scan that is itself a lead belongs to that attack: keep it visible at the
                # scan's lane, saying what this pair's own records show (answers, and ports it probed itself).
                lane, severity = self.lane, self.severity
                claim += (f" The opposite direction, {dst} to {src}, is reported as a port scan lead, so this pair is "
                          f"raised to the same lane: {n_answered} of its ports answer earlier requests from {dst}, "
                          f"and {n_probed} look probed in this direction.")
                if opened:
                    claim += (f" A cited Suricata flow record in state established or closed shows {src} opened the "
                              f"connection on tcp/" + ", tcp/".join(str(port) for port in opened)
                              + " (its engine tracked the handshake).")
                elif n_probed:
                    claim += " No cited record shows which side opened the connections on the probed ports."
            elif lane == "context":
                claim += " Retained for context."
            out.append(Match(self.id, claim, self.claim_type, evs, [pf(evs[0], "source.ip"),
                                                                     pf(evs[0], "destination.ip")],
                             evs[0].ts, severity, lane, "high", evs[0].entities(), group_key=f"{src}|{dst}",
                             context_ids=context))
        return out


NETWORK_PLAYBOOKS = [SuricataAlertStack, WebScanBurst, DnsSubdomainEnumeration, ToolUserAgentHttp, PortScan]
