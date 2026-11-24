"""Network and web-access playbooks (Suricata EVE, Apache access). Aggregates are exact counts
accumulated across every partition, so bursts spanning partition boundaries are not lost."""
from __future__ import annotations

from datetime import timedelta
from typing import ClassVar
from urllib.parse import urlsplit

from romulus.detect.alert_lanes import BENIGN_LOW_PRIORITY_CATEGORIES, alert_stack_lane, attack_tagged
from romulus.detect.base import Match, Playbook, pf
from romulus.detect.bounded import HOT_COUNT, CitationUnavailable, KeyedStore
from romulus.detect.citing import (
    BoundStage,
    Ends,
    Holds,
    Named,
    bound_note,
    citation_group,
    cite_extra,
    cited_phrase,
    drained_holds,
    more,
)
from romulus.detect.dns import endpoints
from romulus.detect.flows import PORTED, SURICATA, ZEEK, source_opened
from romulus.detect.packets import show
from romulus.evidence.typed import TypedEvent
from romulus.hunt.citations import COMPACT_CITATION_NOTE, compact_event, expand_event

# Lower-cased user-agent prefixes of command-line HTTP tools, and the tool each one is the signature of.
TOOL_UA_SIGNATURES = {
    "curl/": "curl", "wget/": "wget", "python-requests/": "python-requests", "python-urllib/": "python-urllib",
    "go-http-client/": "Go net/http", "libwww-perl/": "libwww-perl", "powershell": "PowerShell", "nmap": "nmap",
    "sqlmap": "sqlmap", "nikto": "nikto", "fuzz faster u fool": "ffuf", "gobuster": "gobuster",
    "dirbuster": "DirBuster",
}
TOOL_UA_PREFIXES = tuple(TOOL_UA_SIGNATURES)
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

    def refreshes_citation_on_next_record(self, store, state) -> bool:
        """An unfilled sample necessarily stages its next record, regardless of timestamp ordering."""
        return store is self.groups and len(state.held) < EXAMPLE_LIMIT

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
                raise CitationUnavailable(f"{self.id}: {len(set(ids)) - len(found)} cited event(s) absent from the stage")
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
            raise CitationUnavailable(f"{self.id}: {len(missing)} cited event(s) absent from the stage")
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

    version = "5"
    SIGNATURES_NAMED = 10
    SIGNATURES_HELD = 2000      # distinct signatures held per group; beyond it the count is "at least"

    def scope_partition(self, events: list[TypedEvent]) -> list[TypedEvent]:
        # Zeek's notice, weird, signature and intel records are net.zeek_alert's input: neither evaluated nor
        # missing here
        return [event for event in super().scope_partition(events) if event.get("alert.provider") != "zeek"]

    def consume(self, events):
        """Group by (source, destination, category, severity); signatures are listed inside the group so a
        scanner triggering hundreds of signatures is one item, not hundreds. The first SIGNATURES_NAMED distinct
        signatures each keep a cited record: those are the ones the claim names. Zeek's alerts are another rule's."""
        for e in self.applicable([event for event in events if event.get("alert.provider") != "zeek"]):
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
            if attack_tagged(e):
                state.extra["tagged"] = True
                # the first tagged alert is cited, so the record that raised the lane is shown
                self.name(state, "tagged", sig, e, 1)
        return []

    def finalize(self):
        out = []
        for key, state in self.reported():
            with citation_group(self, out, key, state):
                evs, missing, context = self.cite(state)
                src, dst, cat, sev = key
                n = state.count
                sigs = sorted(state.bag("sigs"), key=lambda s: (str(s[1]), str(s[0])))
                named = sorted(state.names("sigs", self.SIGNATURES_NAMED).values(), key=lambda s: (str(s[1]), str(s[0])))
                lane, severity = alert_stack_lane(cat, sev, bool(state.extra.get("tagged")))
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
                if isinstance(sev, int) and sev >= 3 and lane == "lead":
                    m.notes.append(f"priority {sev}, kept as a lead: " + (
                        f"the '{cat}' classtype is not one of the benign low-priority classtypes"
                        if cat not in BENIGN_LOW_PRIORITY_CATEGORIES
                        else "the signature metadata ties it to an attack (ATT&CK technique or Major/Critical "
                             "signature severity)"))
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


    def uncited_finding(self, key, state, match):
        _src, _dst, category, severity = key
        match.proposed_lane, match.severity = alert_stack_lane(category, severity, bool(state.extra.get("tagged")))
        return match


class _Burst:
    """One run of a source's requests to one web host, as read from one source target: consecutive requests less than
    WebScanBurst.GAP apart. The records bounding it are kept compact in the run's own state (no stage write per
    record); its first error answers are stage holds (ids), released when the run ends without qualifying."""

    __slots__ = ("count", "errors", "first", "first_blob", "held", "last", "last_blob", "target", "uas", "urls")

    def __init__(self, ts, target):
        self.count = 0
        self.errors = 0
        self.first = self.last = ts
        self.first_blob: bytes | None = None   # the earliest record, compact
        self.last_blob: bytes | None = None    # the latest record, compact
        self.held: list[str] = []              # held ids of the run's first EXAMPLE_LIMIT error answers
        self.uas: set = set()                  # recorded user agents, at most AGENTS_NAMED
        self.urls: set = set()                 # distinct request targets, at most URLS_HELD
        self.target = target


class WebScanBurst(_Grouped):
    """Each burst is its own finding: a run of one source's requests to one web host with no pause of GAP or more,
    holding at least MIN_REQUESTS requests of which at least MIN_ERROR_RATIO were answered 4xx/5xx. A burst cites its
    own records (its first EXAMPLE_LIMIT error answers, the records that bound it, and one per user agent it names).

    Runs are read per (host, source, source target) in time order: the sweep reads one target's partitions in time
    order and each batch is sorted here. One run per key is open; a later record past the gap closes it, and a run
    that closes without qualifying releases its held records, so only qualifying bursts keep citations on the stage.
    A record from before an open run (more than GAP earlier than its first record) cannot be placed in a closed run:
    it is counted in the source's window totals and named on coverage (partial), never dropped.

    A source that reaches the thresholds over the whole hunt window but in no single burst (a slow scan with long
    pauses) is still reported, once for the window, citing its first error responses."""
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
    # A pause this long ends a burst. Scanners and fuzzers send requests seconds apart even when rate-limited (one per
    # minute is already a slow scan); half an hour without a request from the source is a different session, on any
    # site, whatever its traffic.
    GAP = timedelta(minutes=30)
    version = "3"
    AGENTS_NAMED = 5
    URLS_HELD = 1000            # distinct targets counted per run; beyond it the count is a lower bound
    STALE_CHECKED = 4096        # open runs examined per batch for closing (least recently used first)
    card: ClassVar[dict] = {
        "behavior": "one source sent at least 200 requests to one web host in a burst (no pause of 30 minutes or "
                    "more) and at least half were answered with a 4xx/5xx status: wordlist or vulnerability scanning",
        "telemetry": "http_access (web-server access logs: source.ip, http.response.status_code, url.original, "
                     "user_agent.original); present in the lab profile",
        "fidelity": "aggregate observation of requests and the server's answers; it does not show that any request "
                    "exploited anything",
        "benign_and_cost": "authorized vulnerability scans, crawlers, broken client loops; one lead per burst, so a "
                           "source scanning twice gives two leads, each citing its own records",
        "query_cost": "none beyond the sweep",
        "next_pivot": "the source's 2xx answers after the burst, and the web host's activity after it",
        "adds": "access-log-only scan detection; each burst is placed in time with its own records",
        "research_basis": "ATT&CK Enterprise 20.0 T1595.002, T1595.003",
        "retrieval": "the sweep retrieves every record of the target in each partition with no field filter, a "
                     "superset of what this evaluator reads",
        "state": "one open run per (host, source, target) in a keyed store (hot set over the rule's disk spill), "
                 "its bounding records compact in its own state and at most 20 error answers held on the stage; "
                 "runs quiet for longer than the gap behind the target's newest record are closed as batches are "
                 "read; qualifying bursts kept on disk to the end; window totals per (host, source); a run that ends "
                 "without qualifying releases its held records",
        "lanes": "lead, severity medium: scanning is reconnaissance; what followed decides more",
    }

    def __init__(self):
        super().__init__()
        self.open = KeyedStore(self, "scan_open", self.HOT)
        self.bursts = KeyedStore(self, "scan_bursts", self.HOT)
        self.holds = Holds()
        self._unstaged: dict[str, TypedEvent] = {}   # held records not yet handed to the stage
        self._latest: dict[tuple, TypedEvent] = {}   # open run -> its latest record this batch (compacted at the end)
        self.late = 0

    def reportable(self, state: _Group) -> bool:
        return state.count >= self.MIN_REQUESTS and state.errors / state.count >= self.MIN_ERROR_RATIO

    def qualifies(self, burst: _Burst) -> bool:
        return burst.count >= self.MIN_REQUESTS and burst.errors / burst.count >= self.MIN_ERROR_RATIO

    # ---- staging --------------------------------------------------------------------------------------------------
    def _hold(self, e: TypedEvent) -> str:
        self.holds.hold(e)
        self._unstaged[e.id] = e
        return e.id

    def _release(self, event_id: str | None) -> None:
        if event_id:
            self.holds.release(event_id)

    def drain_staged(self) -> list[TypedEvent]:
        for key in list(self._latest):
            burst = self.open.get(key)
            if burst is not None:
                self._settle(key, burst)
                self.open.put(key, burst)
        self._latest.clear()
        out = super().drain_staged() + self.holds.drain()
        self._unstaged.clear()
        return out

    def drain_bounds(self) -> tuple[list[str], list[str]]:
        return drained_holds(self.bounds, self.holds)

    def trim(self) -> None:
        super().trim()
        self.open.trim()
        self.bursts.trim()

    def release_state(self) -> None:
        self.open.clear()
        self.bursts.clear()
        self.holds.clear()
        self._unstaged.clear()
        super().release_state()

    # ---- evaluation -----------------------------------------------------------------------------------------------
    def consume(self, events):
        counted = []
        for e in self.applicable(events):
            try:
                status = int(e.get("http.response.status_code"))
            except (TypeError, ValueError):
                self.evaluated -= 1
                self.missing_required += 1
                continue
            error = status >= 400
            host, src = e.host, e.get("source.ip")
            window = self.state((host, src), e)
            if window is None:
                continue
            window.count += 1
            window.first, window.last = min(window.first, e.ts), max(window.last, e.ts)
            if error:
                window.errors += 1
                if len(window.held) < EXAMPLE_LIMIT:         # the window's cited records: its first error answers
                    window.held.append(e)
                    self._fresh.append((window, len(window.held) - 1))
                    self._pending.append(e)
            self.bounds.offer_at((host, src), window.ends, e)
            counted.append((e, error))
        # bursts are read in time order: the batch's records sorted, after the target's earlier partitions
        for e, error in sorted(counted, key=lambda item: (item[0].ts, item[0].id)):
            self._place(e, e.host, e.get("source.ip"), error)
        if counted:
            self._close_stale(self.raw_target(), max(e.ts for e, _error in counted))
        return []

    def _close_stale(self, target, newest) -> None:
        """Close the open runs of this target whose last record is more than GAP behind its newest record read (no
        later record can join them while the target is read in time order), so their holds go as early as possible.
        The least recently used runs in memory are examined first, at most STALE_CHECKED per batch."""
        checked = 0
        for key in list(self.open.hot):
            if checked >= self.STALE_CHECKED:
                break
            checked += 1
            if key[2] != target:
                continue
            burst = self.open.hot.get(key)
            if burst is not None and burst.last < newest - self.GAP:
                self._close(key, burst)

    def _place(self, e: TypedEvent, host, src, error: bool) -> None:
        target = self.raw_target()
        key = (host, src, target)
        burst = self.open.get(key)
        if burst is not None and e.ts > burst.last + self.GAP:
            self._close(key, burst)
            burst = None
        if burst is not None and e.ts < burst.first - self.GAP:
            self.late += 1
            self.note_limit("late_records", "requests arrived after a later burst of the same source and host had "
                                            "begun; they are counted in the source's window totals but not placed "
                                            "in a burst", 1)
            return
        if burst is None:
            burst = _Burst(e.ts, target)
            if not self.open.put(key, burst):
                # counted in the source's window totals already: only its place in a burst is not evaluated
                self.note_limit("burst_disk", "the burst store took no new key (its disk budget is spent); records "
                                              "that would start a new burst are counted in their source's window "
                                              "totals but are in no burst", 1)
                return
        burst.count += 1
        burst.errors += error
        if e.ts < burst.first or burst.first_blob is None:
            burst.first, burst.first_blob = e.ts, compact_event(e)
        if e.ts >= burst.last or burst.last_blob is None:
            burst.last, burst.last_blob = e.ts, None      # compacted when the batch ends (one per run, not per record)
            self._latest[key] = e
        if error and len(burst.held) < EXAMPLE_LIMIT:
            burst.held.append(self._hold(e))
        if len(burst.urls) < self.URLS_HELD:
            burst.urls.add(e.get("url.original"))
        ua = e.get("user_agent.original")
        if isinstance(ua, str) and ua and len(burst.uas) < self.AGENTS_NAMED:
            burst.uas.add(ua)
        self.open.put(key, burst)

    def _settle(self, key, burst: _Burst) -> None:
        latest = self._latest.pop(key, None)
        if latest is not None and burst.last_blob is None:
            burst.last_blob = compact_event(latest)

    def _close(self, key, burst: _Burst) -> None:
        self._settle(key, burst)
        self.open.pop(key)
        if not self.qualifies(burst):
            for held in burst.held:
                self._release(held)
            return
        host, src, _target = key
        if not self.bursts.put((*key, burst.first.isoformat()), burst):
            # its held records stay on the stage; the burst is published from the window group instead
            self.note_limit("burst_disk_kept", "the store of qualifying bursts took no new key (its disk budget is "
                                               "spent); such a burst is reported only within its source's window "
                                               "finding")
            return
        window = self.groups.get((host, src))
        if window is not None:
            window.extra["bursts"] = window.extra.get("bursts", 0) + 1
            self.groups.put((host, src), window)

    def _load(self, ids: list[str]) -> list[TypedEvent]:
        """The held records by id: those not yet staged as they are, the rest from the stage."""
        wanted = [i for i in ids if i not in self._unstaged]
        found = {e.id: e for e in self.load(wanted)} if wanted else {}
        missing = [i for i in wanted if i not in found]
        if missing:
            raise CitationUnavailable(f"{self.id}: {len(missing)} cited event(s) absent from the stage")
        return [self._unstaged.get(i) or found[i] for i in dict.fromkeys(ids)]

    def finalize(self):
        for key in list(self.open.keys()):
            burst = self.open.peek(key)
            self._close(key, burst)
        out = []
        for key in sorted(self.bursts.keys(), key=lambda k: tuple(str(part) for part in k)):
            burst = self.bursts.peek(key)
            with citation_group(self, out, key[:2] + key[3:], burst):
                out.append(self._burst_match(key, burst))
        for key, state in self.reported():
            if state.extra.get("bursts"):
                continue                       # its bursts are reported, each with its own records
            with citation_group(self, out, key, state):
                n, errs = state.count, state.errors
                if n < self.MIN_REQUESTS or errs / n < self.MIN_ERROR_RATIO:
                    continue
                evs, missing, context = self.cite(state)
                host, src = key
                claim = (f"{n} HTTP requests to {host} from {src} ({self.span(state)}), {errs} ({errs / n:.0%}) with "
                         f"4xx/5xx responses, spread over the hunt window with pauses of 30 minutes or more, so none of "
                         f"its bursts qualifies on its own."
                         + self.told(evs, state, missing, "requests", "request")
                         + " The cited records are the source's first error responses.")
                out.append(Match(self.id, claim, self.claim_type, evs, [pf(evs[0], "source.ip")], evs[0].ts,
                                 self.severity, self.lane, "high", evs[0].entities(), group_key=f"{host}|{src}",
                                 context_ids=context))
        return out

    def _burst_match(self, key, burst: _Burst) -> Match:
        host, src, _target, _first = key
        own = self._load(burst.held)
        bounding = [expand_event(blob).model_copy(update={"caveats": [*expand_event(blob).caveats,
                                                                       COMPACT_CITATION_NOTE]})
                    for blob in (burst.first_blob, burst.last_blob) if blob]
        cited = {e.id: e for e in own}
        for event in bounding:
            cited.setdefault(event.id, event)
        evs = sorted(cited.values(), key=lambda e: (e.ts, e.id))
        context = set(cited) - {e.id for e in own}
        n, errs = burst.count, burst.errors
        claim = (f"{n} HTTP requests to {host} from {src} in one burst ({burst.first.isoformat()} – "
                 f"{burst.last.isoformat()}), {errs} ({errs / n:.0%}) with 4xx/5xx responses across "
                 f"{'at least ' if len(burst.urls) >= self.URLS_HELD else ''}{len(burst.urls)} distinct URLs; no "
                 f"request "
                 f"from this source to this host came within 30 minutes before or after it."
                 + cited_phrase(len(evs), n, True, "requests", "request"))
        window = self.groups.peek((host, src))
        m = Match(self.id, claim, self.claim_type, evs, [pf(evs[0], "source.ip")], burst.first, self.severity,
                  self.lane, "high", evs[0].entities(), group_key=f"{host}|{src}|{burst.first.isoformat()}",
                  context_ids=context)
        if window is not None and window.count > n:
            m.notes.append(f"over the hunt window this source sent {window.count} requests to {host}, "
                           f"{window.extra.get('bursts', 1)} burst(s) of which are reported; those other records "
                           f"are not cited here")
        agents = sorted({e.get("user_agent.original") for e in evs if isinstance(e.get("user_agent.original"), str)
                         and e.get("user_agent.original")})
        if agents:
            m.notes.append("user-agent strings of cited requests (self-reported, not proof of tool): "
                           + "; ".join(f"'{show(ua)}'" for ua in agents[:self.AGENTS_NAMED])
                           + (" and possibly more" if len(burst.uas) > len(agents[:self.AGENTS_NAMED]) else ""))
        return m


class DnsSubdomainEnumeration(_Grouped):
    """Forward names only. Names in the reverse-lookup trees (in-addr.arpa, ip6.arpa) are evaluated and left to
    the reverse-lookup sweep rule, which reports any client with this rule's distinct-name count of reverse names at
    this rule's lane, with a host-discovery claim and the swept address range. Question records are `query`
    (`request` in newer sensor output) or carry no role; answers (`answer`, `response`) are not evaluated."""
    id = "net.dns_subdomain_enumeration"
    version = "6"
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
        "telemetry": "dns_query question records: source and destination ip and port (the client is the endpoint "
                     "not on the DNS port), dns.question.name, dns.type (Suricata EVE dns: present in the lab "
                     "profile)",
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
            client, _server = endpoints(e)       # the client is the endpoint not on the DNS port
            if client is None:
                self.evaluated -= 1
                self.missing_required += 1
                continue
            key = (client, _registered(e.get("dns.question.name")))
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
            with citation_group(self, out, key, state):
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
    proves nothing; the prefix list also cannot see tools whose agent string does not start with the name.

    Reads sensor HTTP transactions (`http_tx`) and web-server or proxy access-log lines (`http_access`). An access-log
    line names no server address: the server is the host whose log holds the line (origin-form request targets), or,
    for a forward proxy's line, the host of the absolute-form URL it fetched."""
    id = "net.tool_user_agent_http"
    version = "5"
    URLS_NAMED = 3
    AGENTS_NAMED = 3            # recorded user agents quoted, each with a cited record
    AGENTS_COUNTED = 50         # distinct recorded user agents counted per group; beyond it, "and possibly more"
    assures_negative = False
    title = "HTTP requests whose user agent begins with a known command-line tool name"
    families = ("http_tx", "http_access")
    required_fields = ("user_agent.original",)
    # A sensor transaction needs its client and server addresses; an access-log line's server is the logging host
    # and its client may be logged by name (source.host) when the server resolves addresses.
    REQUIRED_BY_FAMILY: ClassVar[dict[str, tuple[str, ...]]] = {"http_tx": ("source.ip", "destination.ip"),
                                                                "http_access": ()}
    severity, lane = "low", "lead"
    attack = ("T1105",)
    benign = ("health checks, package managers, monitoring scripts",)
    next_checks = ("process executions on the source host at the same time", "file_transfer for what was fetched")
    card: ClassVar[dict] = {
        "behavior": "HTTP requests whose self-reported user agent begins with a command-line tool's own identifier "
                    "(curl, wget, python-requests, Go net/http, PowerShell, nmap, sqlmap, nikto, ffuf, gobuster, ...)",
        "telemetry": "http_tx (Zeek/Suricata HTTP: source.ip, destination.ip, user_agent.original, url.original, "
                     "http.hostname) and http_access (Apache/nginx combined access logs and proxy logs that record a "
                     "user agent: source.ip, user_agent.original, url.original; the server is the logging host). "
                     "Both are present in the lab profile",
        "fidelity": "a self-reported string, never proof of the tool: any client can send it, and a tool can send "
                    "another agent",
        "benign_and_cost": "health checks, package managers, monitoring and API scripts; one grouped lead per "
                           "(client, server, tool token)",
        "query_cost": "none beyond the sweep",
        "next_pivot": "process executions on the client at the same time; what the requests fetched",
        "adds": "web servers with no sensor in front of them: their own access logs show the same agent strings",
        "research_basis": "the tools' published default user agents; ATT&CK Enterprise 20.0 T1105",
        "retrieval": "the sweep retrieves every record of the target in each partition with no field filter, a "
                     "superset of what this evaluator reads",
        "lanes": "lead, severity low: the string alone shows a tool may have been used, nothing about what it did",
    }

    @staticmethod
    def _access_server(e) -> str | None:
        """The server an access-log line's request went to: the logging host for an origin-form target, the URL's
        host for a proxy's absolute-form target, None when neither is recorded."""
        target = e.get("url.original")
        if isinstance(target, str) and target and not target.startswith(("/", "*")):
            # absolute form (a proxy's GET http://site/...) or authority form (a proxy's CONNECT site:443)
            try:
                host = urlsplit(target if "://" in target.split("?", 1)[0] else "//" + target).hostname
            except ValueError:
                host = None
            return host or None
        return e.host or None

    def consume(self, events):
        for e in self.applicable(events):
            ua = e.get("user_agent.original")
            needed = self.REQUIRED_BY_FAMILY.get(e.family, ())
            if not isinstance(ua, str) or any(e.get(name) in (None, "", [], {}) for name in needed):
                self.evaluated -= 1
                self.missing_required += 1
                continue
            recorded, ua = ua, ua.lower()
            if not ua.startswith(TOOL_UA_PREFIXES):
                continue
            if e.family == "http_access":
                server = self._access_server(e)
                client = e.get("source.ip") or e.get("source.host")
                if server is None or not client:
                    self.evaluated -= 1
                    self.missing_required += 1
                    continue
                key = ("access", client, server, ua.split(" ")[0])
            else:
                key = (e.get("source.ip"), e.get("destination.ip"), e.get("http.hostname"), ua.split(" ")[0])
            state = self.keep(key, e)
            if state is None:
                continue
            state.bag("tools").add(next(TOOL_UA_SIGNATURES[p] for p in TOOL_UA_PREFIXES if ua.startswith(p)))
            agents = state.bag("agents")
            if len(agents) < self.AGENTS_COUNTED:
                agents.add(recorded)
            self.name(state, "agents", recorded, e, self.AGENTS_NAMED)
            urls = state.bag("urls")
            if len(urls) < 50:
                urls.add(e.get("url.original"))
            if e.get("url.original"):
                self.name(state, "urls", e.get("url.original"), e, self.URLS_NAMED)
        return []

    def finalize(self):
        out = []
        for key, state in self.reported():
            with citation_group(self, out, key, state):
                evs, missing, context = self.cite(state)
                access = key[0] == "access"
                if access:
                    _kind, src, dst, ua = key
                    hostname = None
                else:
                    src, dst, hostname, ua = key
                urls = sorted(u for u in state.names("urls", self.URLS_NAMED).values())
                every = len([u for u in state.bag("urls") if u])
                # the user agents as recorded (each quoted one with a cited record); the grouping token is not a value
                agents = sorted(state.names("agents", self.AGENTS_NAMED).values())
                n_agents = len(state.bag("agents"))
                quoted = ", ".join(f"'{agent}'" for agent in agents) + (
                    more(len(agents), n_agents) if n_agents < self.AGENTS_COUNTED else " and possibly more")
                tools = " or ".join(sorted(state.bag("tools")))
                if not access:
                    where = f"from {src} to {dst} (Host: {hostname})"
                elif dst == evs[0].host:
                    where = f"from {src} recorded in the access log of {dst}"
                else:
                    where = f"from {src} to {dst} recorded in the proxy access log on {evs[0].host}"
                claim = (f"{state.count} HTTP request(s) {where} with user agent(s) "
                         f"{quoted} ({self.span(state)}), which matched the {tools} tool signature; URLs include {urls}"
                         + (more(len(urls), every) if every < 50 else " and possibly more") + "."
                         + self.told(evs, state, missing, "requests", "request") + " The user agent is self-reported.")
                predicate = [pf(evs[0], "user_agent.original")]
                predicate += [pf(evs[0], name) for name in ("source.ip", "source.host") if evs[0].has(name)][:1]
                if access and evs[0].has("url.original"):
                    predicate.append(pf(evs[0], "url.original"))
                out.append(Match(self.id, claim, self.claim_type, evs, predicate,
                                 evs[0].ts, self.severity, self.lane, "medium", evs[0].entities(),
                                 group_key=f"access|{dst}|{src}|{ua}" if access else f"{src}|{dst}|{ua}",
                                 context_ids=context))
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
    version = "11"
    # Destination ports the claim names, each with a cited record (the first seen); and probed ports whose opening a
    # cited record shows (a Suricata directional TCP flag summary with a SYN toward the server, or a Zeek conn history
    # that begins with the originator's SYN).
    PORTS_NAMED = 12
    # The cited record that shows a probed port's opening, and how each sensor's claim names it.
    OPENED_KINDS: ClassVar[dict[str, tuple[str, str, str]]] = {
        SURICATA: ("opened", "A cited Suricata directional TCP flag summary shows", "it records a SYN toward the server"),
        ZEEK: ("opened_zeek", "A cited Zeek conn history shows", "it begins with the originator's SYN"),
    }

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
            transport = e.get("network.transport")
            if isinstance(transport, str) and transport.lower() not in PORTED:
                # a transport without ports: Zeek keeps an ICMP connection's type and counterpart type in its port
                # fields, and they are not ports (evaluated: such a record is no port of a scan)
                continue
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
            if not 0 <= dport <= 65535:
                self.missing_required += 1      # not a port number: not evaluated
                continue
            if sport is not None and not 0 <= sport <= 65535:
                sport = None                    # not a port number: judged as a record without a source port
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
            opener = source_opened(e)
            if opener is not None and e.get("flow.bytes_toserver") is not None:
                # a flow or conn record (not netflow) whose own typed field shows its source sent the opening SYN
                self.name(state, self.OPENED_KINDS[opener][0], dport, e, self.PORTS_NAMED)
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

    def _scan_ports(self, key, state):
        src, dst = key
        answered = {port for port, seen in state.replies.items() if self._answered(src, dst, port, seen)}
        unanswered = set(state.replies)-answered
        client_range = {port for port in unanswered if port >= self.EPHEMERAL_FLOOR}
        probed = state.bag("ports") | (unanswered-client_range)
        return answered, unanswered, client_range, probed

    def uncited_finding(self, key, state, match):
        answered, _unanswered, _client_range, probed = self._scan_ports(key, state)
        if len(probed) < self.MIN_PORTS:
            match.proposed_lane, match.severity = "context", "low"
        match.claim += f" {len(probed)} port(s) look probed; {len(answered)} answer earlier requests."
        return match

    def finalize(self):
        rows = []
        uncited = []
        for key, state in self.reported():
            with citation_group(self, uncited, key, state):
                src, dst = key
                forward = state.bag("ports")
                replies = state.replies
                ports = forward | set(replies)
                if len(ports) < self.MIN_PORTS:
                    continue
                evs, missing, context = self.cite(state)
                answered, unanswered, client_range, probed = self._scan_ports(key, state)
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
                # how many of the counted ports the cited records show
                in_cited = {e.get("destination.port") for e in evs if isinstance(e.get("destination.port"), int)}
                low = (f", and {len(in_cited & set(replies))} of the {len(replies)} reached from a source port below "
                       f"1024," if replies else "")
                claim += f" {len(in_cited & ports)} of the {len(ports)} ports{low} are in cited records."
                if len(probed) >= self.MIN_PORTS:
                    lane, severity = self.lane, self.severity
                else:
                    lane, severity = "context", "low"     # mostly a service answering clients: kept visible, not a lead
                    claim += f" Only {len(probed)} port(s) look probed."
                opened = {sensor: sorted(port for port in state.names(kind, self.PORTS_NAMED).values()
                                         if port in probed)
                          for sensor, (kind, _shows, _how) in self.OPENED_KINDS.items()}
                rows.append((src, dst, claim, lane, severity, evs, len(probed), opened, len(answered), context))
        scanned = {(src, dst) for src, dst, _claim, lane, *_rest in rows if lane == self.lane}
        scanned.update(tuple(match.group_key.split("|")) for match in uncited if match.proposed_lane == self.lane)
        for match in uncited:
            src, dst = match.group_key.split("|")
            if match.proposed_lane == "context" and (dst, src) in scanned:
                match.proposed_lane, match.severity = self.lane, self.severity
                match.claim += (f" The opposite direction, {dst} to {src}, is reported as a port scan lead, "
                                "so this pair is raised to the same lane.")
        out = list(uncited)
        for src, dst, claim, lane, severity, evs, n_probed, opened, n_answered, context in rows:
            if lane == "context" and (dst, src) in scanned:
                # The target's side of a scan that is itself a lead belongs to that attack: keep it visible at the
                # scan's lane, saying what this pair's own records show (answers, and ports it probed itself).
                lane, severity = self.lane, self.severity
                claim += (f" The opposite direction, {dst} to {src}, is reported as a port scan lead, so this pair is "
                          f"raised to the same lane: {n_answered} of its ports answer earlier requests from {dst}, "
                          f"and {n_probed} look probed in this direction.")
                if any(opened.values()):
                    for sensor, (_kind, shows, how) in self.OPENED_KINDS.items():
                        if opened[sensor]:
                            claim += (f" {shows} {src} opened the connection on tcp/"
                                      + ", tcp/".join(str(port) for port in opened[sensor]) + f" ({how}).")
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
