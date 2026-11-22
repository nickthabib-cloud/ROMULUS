"""SSH password guessing, spraying and success after failures; account and group creation or modification.

SSH rules read the journal sshd records the normalizer types (family `auth`, `auth.service` sshd): "Accepted" and
"Failed" authentication lines, "Invalid user" lookups, connections closed before authentication completed, and
"maximum authentication attempts exceeded". They count failed attempts, never logins:
- A connection is (host, source address, source port). Every record of a connection arrives within sshd's login
  grace time (120 s by default), so a record is judged once the stream has moved SETTLE_SECONDS past it.
- A connection that ends in an accepted login contributes no failures: those are key or password probes before
  the accepted one (a client offering several keys), not guessing.
- Each "Failed" line is one attempt. A failed connection without any "Failed" line (key-only servers log only the
  invalid-user lookup or the pre-authentication close) counts as one attempt.
- Audit USER_LOGIN failures are not counted: they carry no source port, so they cannot be split into connections,
  and sshd writes them for key probes inside connections that then succeed.
The rules are positive-only: sshd's message grammar is text, and lines it words differently are not typed.

The account rule reads exec records of the account and group tools (argv parsed with each tool's option grammar),
commands and shell text that write the account files directly, and the audit records the tools write (family
`account_change`). An exec record shows a command was run; only the tool's own audit record (joined by process
id) or a kernel file-change record shows the change. A tool's audit record and its own syslog line of the same change
are one change citing both. A host's run of changes naming several accounts or groups (provisioning, or an intruder
creating several accounts) is one item with the lane of its strongest change, so a privileged grant inside it keeps
its lane and is named and cited first. The same run on several hosts in one rollout window is one fleet item at the
lane of its strongest run; a host whose run differs keeps its own item and is named in the fleet item.
"""
from __future__ import annotations

import hashlib
import heapq
import itertools
import json
import re
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import ClassVar, NamedTuple

from romulus.detect.base import Match, Playbook, argv_incomplete, basename, pf
from romulus.detect.bounded import HOT_COUNT, KeyedStore, RecentIds, SpillList, StateExhausted
from romulus.detect.citing import Ends, bound_note, citation_call, citation_group, cited_phrase
from romulus.detect.host import (
    UNBUDGETED,
    Lineage,
    ProcessLineage,
    _argv_summary,
    _outcome_tally,
    add_unheld,
    alone,
    boot_of,
    need,
)
from romulus.detect.linux_argv import (
    canonical,
    getopt_long,
    is_editor,
    normalize_path,
    program,
    program_name_hint,
    shell_segments,
    write_targets,
)
from romulus.detect.log_writer import writer_sentence, writer_state
from romulus.evidence.shellparse import SHELLS
from romulus.evidence.typed import Outcome, TypedEvent

SSHD_ATTEMPT_PHASES = {"authentication", "user_lookup", "preauth_disconnect", "max_attempts"}
SETTLE_SECONDS = 150.0          # sshd LoginGraceTime defaults to 120 s: every record of a connection is in by then
GRACE_SECONDS = 120.0           # one connection spans at most sshd's login grace time ...
MAX_TRIES = 6                   # ... and at most sshd's default MaxAuthTries failed lines; beyond either, a reused
#                                 source port is a new connection
CITE = 10                       # attempt records cited per finding; claims give exact totals
PRUNE_EVERY = 300.0             # seconds of event time between sweeps of idle sliding windows


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, UTC).isoformat()


def _unique(events) -> list[TypedEvent]:
    """Events in first-seen order, each once (typed events are not hashable; their ids are)."""
    out: dict[str, TypedEvent] = {}
    for event in events:
        if event is not None:
            out.setdefault(event.id, event)
    return list(out.values())


def _names(items, limit: int = 8, more_than: int | None = None) -> str:
    """The first `limit` items quoted, and how many more of `more_than` (all of `items` by default) there are; with
    none to quote, how many there are and that none is in a cited record."""
    items = sorted(items)
    total = len(items) if more_than is None else more_than
    shown = items[:limit]
    if not shown:
        return f"none of the {total} is in a cited record" if total else "none"
    return ", ".join(f"'{item}'" for item in shown) + (f" and {total - len(shown)} more" if total > len(shown) else "")


class _Attempt(NamedTuple):
    ts: float
    host: str | None
    ip: str
    account: str | None
    valid: bool | None
    new_connection: bool
    event: TypedEvent


@dataclass
class _Connection:
    first_ts: float = 0.0
    failed_lines: int = 0
    success: bool = False
    counted: bool = False           # a connection without "Failed" lines already gave its one attempt
    attempted: bool = False
    open_records: int = 0


class _SshAttemptStream(Playbook):
    """Shared settling of sshd records into failed attempts and accepted logins (see the module docstring)."""
    kind = "aggregate"
    families = ("auth",)
    os_families = ("linux",)
    claim_type = "aggregate_observation"
    assures_negative = False
    positive_only_reason = (
        "attempts and logins are read from sshd's log message grammar; lines sshd words differently (versions, "
        "PAM-only messages, verbose levels) are not typed, so a window without matches proves nothing")
    anchor_class = "credential_access"
    benign = ("automation retrying with a stale password or key",
              "users mistyping passwords, or trying several of their own account names",
              "internet background scanning of an exposed SSH service (high volume, low value unless a login follows)")
    next_checks = ("auth_activity for the source address across every host",
                   "ip_sessions for the source address: what else it reached",
                   "entity_timeline of the host after any accepted login from the source")

    # Every evaluated sshd record is staged when read, as any of them may be cited later. Per-key state (tallies,
    # sliding windows, accepted-login counts, found logins) lives in keyed stores: HOT keys in memory, the rest on
    # the rule's disk spill, never forgotten. Only a store's disk budget refuses, and coverage says so.
    staged = True
    HOT = HOT_COUNT  # a count cap only: the hunt's memory budget sizes it in bytes

    def __init__(self):
        super().__init__()
        self._heap: list[tuple[float, str, TypedEvent]] = []
        self._latest = float("-inf")
        self._seen = RecentIds()        # bounded re-read guard
        self._conns: dict[tuple, _Connection] = {}
        self._last_prune = float("-inf")
        self.probe_failures = 0     # failures inside connections that then succeeded (not counted)
        self._pending: list[TypedEvent] = []
        self._alone: list[Match] = []   # findings published as they were judged (no room to hold them)
        self.load = lambda ids: []

    def drain_staged(self) -> list[TypedEvent]:
        out, self._pending = self._pending, []
        for store in self._stores():
            store.trim()
        return out

    def retained_events(self) -> list[TypedEvent]:
        return list(self._pending)                      # the rest are staged on disk

    def _load(self, ids: list[str]) -> list[TypedEvent]:
        """Records by id: every evaluated record is staged, so from the stage, or from those not yet handed to it."""
        wanted = [i for i in dict.fromkeys(ids) if i]
        pending = {e.id: e for e in self._pending}
        found = {e.id: e for e in self.load([i for i in wanted if i not in pending])}
        return [pending.get(i) or found[i] for i in wanted if i in pending or i in found]

    def _stores(self) -> tuple[KeyedStore, ...]:
        return ()

    @staticmethod
    def _conn_key(e: TypedEvent) -> tuple:
        port = e.get("source.port")
        return (e.host, str(e.get("source.ip")), port) if isinstance(port, int) else (e.host, e.id)

    def consume(self, events):
        batch = []
        for e in events:
            if e.family != "auth" or e.id in self._seen:
                continue
            if e.get("auth.service") != "sshd" or e.get("auth.phase") not in SSHD_ATTEMPT_PHASES:
                continue                      # audit login and PAM session records, other services
            self._seen.add(e.id)
            if not e.has("source.ip") or e.outcome == Outcome.unknown:
                self.missing_required += 1
                continue
            self.evaluated += 1
            self._pending.append(e)
            batch.append(e)
        for e in self._without_duplicate_lookups(sorted(batch, key=lambda x: (x.ts, x.id))):
            key, ts = self._conn_key(e), e.ts.timestamp()
            failed_line = e.outcome != Outcome.success and e.get("auth.phase") == "authentication"
            conn = self._conns.get(key)
            if conn is None or ts - conn.first_ts > GRACE_SECONDS or (failed_line and conn.failed_lines >= MAX_TRIES):
                conn = self._conns[key] = _Connection(first_ts=ts)
            conn.open_records += 1
            if e.outcome == Outcome.success:
                conn.success = True
            elif failed_line:
                conn.failed_lines += 1
            heapq.heappush(self._heap, (ts, e.id, e, conn))
            self._latest = max(self._latest, ts)
        self._drain(self._latest - SETTLE_SECONDS)
        out, self._alone = self._alone, []
        return out

    @staticmethod
    def _without_duplicate_lookups(batch: list[TypedEvent]) -> list[TypedEvent]:
        """Older sshd logs an "Invalid user NAME from IP" line without a port, followed by the same attempt's
        "Failed ... for invalid user NAME from IP port N" line: the port-less lookup is not another attempt."""
        with_port: dict[tuple, list[float]] = defaultdict(list)
        for e in batch:
            if isinstance(e.get("source.port"), int):
                with_port[(e.host, e.get("source.ip"), e.get("user.name"))].append(e.ts.timestamp())
        out = []
        for e in batch:
            if e.get("auth.phase") == "user_lookup" and not isinstance(e.get("source.port"), int):
                ts = e.ts.timestamp()
                if any(0 <= t - ts <= 10 for t in with_port.get((e.host, e.get("source.ip"), e.get("user.name")), ())):
                    continue
            out.append(e)
        return out

    def _drain(self, limit: float) -> None:
        while self._heap and self._heap[0][0] <= limit:
            ts, _id, e, conn = heapq.heappop(self._heap)
            self._settle(ts, e, conn)
            if ts - self._last_prune >= PRUNE_EVERY:
                self._prune(ts)
                self._last_prune = ts

    def _settle(self, ts: float, e: TypedEvent, conn: _Connection) -> None:
        key = self._conn_key(e)
        conn.open_records -= 1
        if conn.open_records <= 0 and self._conns.get(key) is conn:
            del self._conns[key]
        if e.outcome == Outcome.success:
            self._success(ts, e)
            return
        if conn.success:
            self.probe_failures += 1
            return
        if e.get("auth.phase") != "authentication":
            if conn.failed_lines or conn.counted:
                return
            conn.counted = True
        new = not conn.attempted
        conn.attempted = True
        account = e.get("user.name")
        self._attempt(_Attempt(ts, e.host, str(e.get("source.ip")), str(account) if account else None,
                               e.get("auth.user_valid"), new, e))

    # A key's totals are stated when it crosses, so per-key state is held for the whole hunt (on disk when cold).
    def _state(self, store: KeyedStore, key: tuple, factory):
        """The key's state; None (the attempt is refused, coverage says so) only when the store's disk budget is
        spent."""
        state = store.setdefault(key, factory)
        if state is None:
            self.evaluated -= 1
            self.refuse("disk", f"the {store.name} disk budget is spent; an attempt of a new source or account is "
                                f"not counted")
        return state

    def _count(self, store: KeyedStore, key: tuple) -> None:
        """One more accepted login for the key; a login the disk budget refuses makes every login count a lower
        bound, and the claims say so."""
        if not store.put(key, store.get(key, 0) + 1):
            self.logins_uncounted = True
            self.note_limit("logins_disk", f"the {store.name} disk budget is spent; a later accepted login is not "
                                           f"counted")

    logins_uncounted = False

    def finalize(self):
        self._drain(float("inf"))
        out, self._alone = self._alone, []
        return out + self._findings()

    # subclass hooks
    def _attempt(self, a: _Attempt) -> None: ...
    def _success(self, ts: float, e: TypedEvent) -> None: ...
    def _prune(self, now: float) -> None: ...
    def _findings(self) -> list[Match]: return []


def _prune_windows(windows: KeyedStore, now: float, span: float) -> None:
    """Drop the in-memory windows that are past their span (a window on disk is trimmed when read back)."""
    for key in [k for k, w in windows.hot.items() if not w or now - w[-1].ts > span]:
        windows.pop(key)


def _logins(n: int, uncounted: bool) -> int | str:
    return f"at least {n}" if uncounted else n


def _trim(window: deque, now: float, span: float) -> None:
    while window and now - window[0].ts > span:
        window.popleft()


def _ssh_predicate(events: list[TypedEvent]):
    return [pf(e, name) for e in events for name in ("auth.phase", "user.name", "source.ip", "source.port")
            if e.has(name)]


@dataclass
class _Tally:
    first: float
    attempts: int = 0
    connections: int = 0
    last: float = 0.0
    invalid: bool = False
    peak: int = 0
    crossed: float | None = None
    cited: list[TypedEvent] = field(default_factory=list)
    first_id: str = ""              # the earliest and the latest attempt's records: they bound the stated span
    last_id: str = ""
    names: set[str] = field(default_factory=set)
    invalid_names: set[str] = field(default_factory=set)
    more_names: int = 0
    window: deque = field(default_factory=deque)
    in_window: Counter = field(default_factory=Counter)

    def add(self, a: _Attempt) -> None:
        self.attempts += 1
        self.connections += a.new_connection
        self.last = a.ts
        self.invalid = self.invalid or a.valid is False
        if not self.first_id:
            self.first_id = a.event.id
        self.last_id = a.event.id


class SshPasswordGuessing(_SshAttemptStream):
    id = "host.ssh_password_guessing"
    version = "2"
    title = "Many failed sshd attempts from one source against one account"
    severity, lane = "medium", "lead"
    attack = ("T1110.001",)
    THRESHOLD = 10               # failed attempts ...
    WINDOW = 600.0               # ... within this many seconds, per (host, source, account)
    card: ClassVar[dict] = {
        "behavior": "one source address made many failed sshd authentication attempts against one account on one "
                    "host in a short time",
        "telemetry": "journal sshd records typed as auth (auth.phase, user.name, auth.user_valid, source.ip, "
                     "source.port, outcome): present in the lab profile (accepted logins observed; failure "
                     "volume not profiled)",
        "fidelity": "direct sshd records of failed attempts, counted per connection; never a claim that guessing "
                    "succeeded (the success-after-failures rule reports that)",
        "benign_and_cost": "automation with a stale password retrying, users mistyping, internet scanning; one "
                           "grouped lead per (host, source, account)",
        "query_cost": "none beyond the sweep (host journal partitions)",
        "next_pivot": "accepted logins from the source on any host; the source's other targets",
        "adds": "no earlier rule counts failed sshd attempts",
        "research_basis": "ATT&CK Enterprise 20.0 T1110.001 (data component: user account authentication); Elastic "
                          "detection-rules 'Potential External/Internal Linux SSH Brute Force Detected' and SigmaHQ "
                          "Linux sshd failure rules as behaviour references (reimplemented; upstream commits not "
                          "re-verified offline)",
        "thresholds": "10 attempts within 10 minutes: above sshd's 6 attempts per connection and the 3 prompts a "
                      "client gives a typing human, below automated guessing rates (tools manage hundreds per "
                      "minute); low-and-slow guessing below it is left to the spray and success rules",
        "retrieval": "the sweep retrieves every record of the host datasets in each partition (dataset filter "
                     "only), a superset of what this evaluator reads",
    }

    def __init__(self):
        super().__init__()
        self.tallies = KeyedStore(self, "ssh_guess_tallies", self.HOT, candidate=lambda t: t.crossed is not None)
        self.successes = KeyedStore(self, "ssh_guess_logins", self.HOT)

    def _stores(self):
        return self.tallies, self.successes

    def _attempt(self, a):
        if a.account is None:
            return
        key = (a.host, a.ip, a.account)
        tally = self._state(self.tallies, key, lambda: _Tally(first=a.ts))
        if tally is None:
            return
        tally.add(a)
        window = tally.window
        window.append(a)
        _trim(window, a.ts, self.WINDOW)
        tally.peak = max(tally.peak, len(window))
        if tally.crossed is None and len(window) >= self.THRESHOLD:
            tally.crossed = a.ts
            tally.cited = [x.event for x in window][-CITE:]

    def _success(self, ts, e):
        self._count(self.successes, (e.host, str(e.get("source.ip")), str(e.get("user.name"))))

    def _prune(self, now):
        for tally in self.tallies.hot.values():
            if tally.window and now - tally.window[-1].ts > self.WINDOW:
                tally.window.clear()

    def _findings(self):
        out = []
        for key in sorted(self.tallies.keys(candidates=True), key=str):
            with citation_group(self, out, key, self.tallies.peek(key)):
                host, ip, account = key
                t = self.tallies.peek(key)
                if t.crossed is None:
                    continue
                # the attempts the finding is about, and the first and last attempt cited for the stated span
                spanning = [e for e in self._load([t.first_id, t.last_id]) if e.id not in {x.id for x in t.cited}]
                events = sorted(_unique([*t.cited, *spanning]), key=lambda e: (e.ts, e.id))
                ok = _logins(self.successes.peek(key, 0), self.logins_uncounted)
                claim = (f"On {host}, sshd recorded {t.attempts} failed authentication attempt(s) for account "
                         f"'{account}' from {ip} in {t.connections} connection(s) between {_iso(t.first)} and "
                         f"{_iso(t.last)}; the most within any {self.WINDOW / 60:.0f} minutes was {t.peak} (threshold "
                         f"{self.THRESHOLD}), first reached at {_iso(t.crossed)}.")
                if t.invalid:
                    claim += (f" sshd reported '{account}' as an invalid user (no such account, or one not permitted to "
                              "log in).")
                claim += (f" The retrieved records hold {ok} accepted sshd login(s) for this account from this source."
                          if ok else " The retrieved records hold no accepted sshd login for this account from this "
                                     "source.")
                claim += " Failures inside connections that then logged in are not counted."
                claim += _span_cited(events, t, "attempt records", "attempt record")
                m = Match(self.id, claim, self.claim_type, events, _ssh_predicate(events[:3]), events[0].ts,
                          self.severity, self.lane, "high", events[0].entities(), group_key=f"{host}|{ip}|{account}",
                          context_ids={e.id for e in spanning})
                out.append(m)
        return out


class SshPasswordSpraying(_SshAttemptStream):
    id = "host.ssh_password_spraying"
    version = "2"
    title = "Failed sshd attempts from one source against many account names"
    severity, lane = "medium", "lead"
    attack = ("T1110.003",)
    THRESHOLD = 5                # distinct account names with failed attempts ...
    WINDOW = 3600.0              # ... within this many seconds, per (host, source)
    NAME_CAP = 1000
    card: ClassVar[dict] = {
        "behavior": "one source address made failed sshd attempts against many different account names on one host",
        "telemetry": "journal sshd records typed as auth (user.name, auth.user_valid, source.ip, source.port, "
                     "outcome): present in the lab profile",
        "fidelity": "direct sshd records; invalid (nonexistent) names are counted, and reported separately",
        "benign_and_cost": "a user trying a few of their own names; misconfigured automation iterating accounts. "
                           "One grouped lead per (host, source)",
        "query_cost": "none beyond the sweep",
        "next_pivot": "accepted logins from the source; whether the tried names exist on the host",
        "adds": "spraying spreads attempts thin per account, below the guessing threshold",
        "research_basis": "ATT&CK Enterprise 20.0 T1110.003 (names SSH as a common target); Elastic detection-rules "
                          "'Potential Linux SSH Password Spraying' and SigmaHQ failed logons from a single source with "
                          "different accounts as references (reimplemented; upstream commits not re-verified offline)",
        "thresholds": "5 distinct names within 60 minutes: a person rarely tries more than two or three of their "
                      "own names, and the 60-minute span keeps slow spraying (one name every few minutes) visible",
        "retrieval": "the sweep retrieves every record of the host datasets in each partition (dataset filter "
                     "only), a superset of what this evaluator reads",
    }

    def __init__(self):
        super().__init__()
        self.tallies = KeyedStore(self, "ssh_spray_tallies", self.HOT, candidate=lambda t: t.crossed is not None)
        self.successes = KeyedStore(self, "ssh_spray_logins", self.HOT)

    def _stores(self):
        return self.tallies, self.successes

    def _attempt(self, a):
        key = (a.host, a.ip)
        tally = self._state(self.tallies, key, lambda: _Tally(first=a.ts))
        if tally is None:
            return
        tally.add(a)
        if a.account is None:
            return
        if a.account in tally.names or len(tally.names) < self.NAME_CAP:
            tally.names.add(a.account)
        else:
            tally.more_names += 1           # a source's names beyond NAME_CAP are counted, not listed
        if a.valid is False and len(tally.invalid_names) < self.NAME_CAP:
            tally.invalid_names.add(a.account)
        window, counts = tally.window, tally.in_window
        window.append(a)
        counts[a.account] += 1
        while window and a.ts - window[0].ts > self.WINDOW:
            old = window.popleft()
            counts[old.account] -= 1
            if counts[old.account] <= 0:
                del counts[old.account]
        tally.peak = max(tally.peak, len(counts))
        if tally.crossed is None and len(counts) >= self.THRESHOLD:
            tally.crossed = a.ts
            first_per_name: dict[str, TypedEvent] = {}
            for x in window:
                first_per_name.setdefault(x.account, x.event)
            tally.cited = list(first_per_name.values())[:CITE]

    def _success(self, ts, e):
        self._count(self.successes, (e.host, str(e.get("source.ip"))))

    def _prune(self, now):
        for tally in self.tallies.hot.values():
            if tally.window and now - tally.window[-1].ts > self.WINDOW:
                tally.window.clear()
                tally.in_window.clear()

    def _findings(self):
        out = []
        for key in sorted(self.tallies.keys(candidates=True), key=str):
            with citation_group(self, out, key, self.tallies.peek(key)):
                host, ip = key
                t = self.tallies.peek(key)
                if t.crossed is None:
                    continue
                # the attempts the finding is about, and the first and last attempt cited for the stated span
                spanning = [e for e in self._load([t.first_id, t.last_id]) if e.id not in {x.id for x in t.cited}]
                events = sorted(_unique([*t.cited, *spanning]), key=lambda e: (e.ts, e.id))
                total_names = len(t.names) + t.more_names
                named = {str(e.get("user.name")) for e in events if e.get("user.name")} & t.names
                ok = _logins(self.successes.peek(key, 0), self.logins_uncounted)
                claim = (f"On {host}, sshd recorded failed authentication attempts for {total_names} distinct account "
                         f"name(s) from {ip} between {_iso(t.first)} and {_iso(t.last)} ({t.attempts} attempt(s) in "
                         f"{t.connections} connection(s)); the most distinct names within any "
                         f"{self.WINDOW / 60:.0f} minutes was {t.peak} (threshold {self.THRESHOLD}), first reached at "
                         f"{_iso(t.crossed)}. {_names_cited(named, total_names)}. Of "
                         f"all the names, sshd reported {len(t.invalid_names)} of them as invalid users (no such account, "
                         f"or not permitted to log in).")
                claim += (f" The retrieved records hold {ok} accepted sshd login(s) from this source." if ok else
                          " The retrieved records hold no accepted sshd login from this source.")
                claim += " Failures inside connections that then logged in are not counted."
                claim += _span_cited(events, t, "attempt records", "attempt record")
                m = Match(self.id, claim, self.claim_type, events, _ssh_predicate(events[:3]), events[0].ts,
                          self.severity, self.lane, "high", events[0].entities(), group_key=f"{host}|{ip}",
                          context_ids={e.id for e in spanning})
                out.append(m)
        return out


def _names_cited(named: set[str], total: int) -> str:
    """Which of a count of names the cited records show: 'All 3 names are in cited records: ...', '5 of the 30 names
    are in cited records: ...' or 'None of the 30 names is in a cited record'."""
    if not named:
        return f"None of the {total} names is in a cited record"
    if len(named) >= total:
        return f"All {total} names are in cited records: {_names(named)}"
    return f"{len(named)} of the {total} names are in cited records: {_names(named)}"


def _span_cited(events: list[TypedEvent], t, noun: str, one: str) -> str:
    """How many of the counted records are cited, and whether the first and the last are among them: a bounding
    record the stage no longer holds is named as not cited."""
    ids = {e.id for e in events}
    missing = {i for i in (t.first_id, t.last_id) if i and i not in ids}
    bounded = not missing and bool(t.first_id) and bool(t.last_id)
    return (cited_phrase(len(events), t.attempts, bounded, noun, one)
            + bound_note(missing, Ends(first=(0.0, t.first_id), last=(0.0, t.last_id)), "the stated span"))


@dataclass
class _Followed:
    success: TypedEvent
    failures: list[TypedEvent]
    count: int
    accounts: set[str]
    sources: set[str]
    own: int = 0
    later: list[TypedEvent] = field(default_factory=list)
    repeats: int = 1
    invalid: bool = False


class SshSuccessAfterFailures(_SshAttemptStream):
    id = "host.ssh_success_after_failures"
    version = "3"
    title = "Accepted sshd login after a burst of failed attempts"
    anchor_class = "remote_login"
    severity, lane = "high", "high"
    attack = ("T1110", "T1078", "T1021.004")
    WINDOW = 1800.0              # failures counted in this many seconds before the accepted login
    SOURCE_MIN = 5               # failed attempts from the login's own source address
    ACCOUNT_MIN = 10             # failed attempts against the login's account from other source addresses
    SPRAY_NAMES = 3              # names among the source's failures that show spraying rather than one account
    LATER = 4
    benign = ("a user who mistyped several times before succeeding",
              ("an administrator's login to an account that internet scanners are guessing from other addresses "
               "(the account variant, kept at lead)"))
    next_checks = ("entity_timeline of the host after the login: the session's commands and connections",
                   "auth_activity for the account across hosts", "ip_sessions for the source address")
    card: ClassVar[dict] = {
        "behavior": "sshd accepted a login after failed attempts, either from the same source address or against "
                    "the same account from other addresses",
        "telemetry": "journal sshd records typed as auth (auth.phase, auth.method, user.name, source.ip, "
                     "source.port, outcome): present in the lab profile (accepted logins)",
        "fidelity": "both sides are direct sshd records; that one actor made both is not established (shared "
                    "address, or shared account)",
        "benign_and_cost": "users mistyping then succeeding (bounded by the 5-attempt floor); administrators logging "
                           "in while scanners guess the same account from elsewhere (account variant, lead)",
        "query_cost": "none beyond the sweep",
        "next_pivot": "the accepted session's commands, file changes and connections",
        "adds": "the guessing and spraying rules report failures only; this reports the success that follows",
        "research_basis": "ATT&CK Enterprise 20.0 T1110 and T1078; Elastic detection-rules 'Potential Successful SSH "
                          "Brute Force Attack' as a behaviour reference (reimplemented; upstream commit not "
                          "re-verified offline)",
        "thresholds": "source variant: 5 failed attempts from the login's own address within the 30 minutes before "
                      "it (high): more than the 3 prompts a client gives a person; account variant: 10 failed "
                      "attempts against the account from other addresses (lead: on an exposed server, scanners "
                      "guess common accounts all day, so an administrator's own login from elsewhere would match)",
        "retrieval": "the sweep retrieves every record of the host datasets in each partition (dataset filter "
                     "only), a superset of what this evaluator reads",
    }

    def __init__(self):
        super().__init__()
        self.by_source = KeyedStore(self, "ssh_after_sources", self.HOT)
        self.by_account = KeyedStore(self, "ssh_after_accounts", self.HOT)
        self.found = KeyedStore(self, "ssh_after_found", self.HOT)

    def _stores(self):
        return self.by_source, self.by_account, self.found

    def _attempt(self, a):
        for windows, key in ((self.by_source, (a.host, a.ip)), (self.by_account, (a.host, a.account))):
            if key[1] is None:
                continue
            window = self._state(windows, key, deque)
            if window is None:
                return
            window.append(a)
            _trim(window, a.ts, self.WINDOW)

    def _success(self, ts, e):
        host, ip, account = e.host, str(e.get("source.ip")), e.get("user.name")
        own = list(self.by_source.peek((host, ip), ()))
        own = [x for x in own if ts - x.ts <= self.WINDOW]
        if len(own) >= self.SOURCE_MIN:
            self._record(("source", host, ip, str(account)), e, own, len(own))
            return
        if account is None:
            return
        others = [x for x in self.by_account.peek((host, str(account)), ()) if ts - x.ts <= self.WINDOW
                  and x.ip != ip]
        if len(others) >= self.ACCOUNT_MIN:
            self._record(("account", host, ip, str(account)), e, others, len(own))

    def _record(self, key, success, failures, own):
        found = self.found.get(key)
        if found is None:
            followed = _Followed(success, [x.event for x in failures][-CITE:], len(failures),
                                 {x.account for x in failures if x.account}, {x.ip for x in failures}, own,
                                 invalid=any(x.valid is False for x in failures))
            if not self.found.put(key, followed):
                # the failures are held and the login is read: judged now and published as it is, not refused
                self.note_limit("found_alone", "the found logins' store took no new key; a later login after failures "
                                               "is published as it is judged, without later logins of the same key")
                add_unheld(self._alone, alone(self._match(key, followed), self, success))
            return
        found.repeats += 1
        if len(found.later) < self.LATER:
            found.later.append(success)

    def _prune(self, now):
        _prune_windows(self.by_source, now, self.WINDOW)
        _prune_windows(self.by_account, now, self.WINDOW)

    def _findings(self):
        return [_citation for key in sorted(self.found.keys(), key=str) for _citation in citation_call(self, self._match, key, self.found.peek(key))]

    def _match(self, key, f: _Followed) -> Match:
        variant, host, ip, account = key
        s = f.success
        method = s.get("auth.method") or "unrecorded-method"
        when = s.ts.isoformat()
        # the accounts and sources named are those of the cited failures (the latest CITE); the rest are counted
        tried = {str(e.get("user.name")) for e in f.failures if e.get("user.name")} & f.accounts
        sources = {str(e.get("source.ip")) for e in f.failures if e.get("source.ip")} & f.sources
        if variant == "source":
            claim = (f"On {host}, sshd accepted a {method} login for account '{account}' from {ip} at {when} "
                     f"after {f.count} failed attempt(s) from {ip} in the preceding {self.WINDOW / 60:.0f} "
                     f"minutes (threshold {self.SOURCE_MIN}; accounts tried: "
                     f"{_names(tried, more_than=len(f.accounts))}). The "
                     "failures and the login share the source address; whether one actor made both is not "
                     "established by the records.")
            lane, confidence = "high", "high"
            spraying = len(f.accounts) >= self.SPRAY_NAMES or f.invalid
            if account not in f.accounts and not spraying:
                # e.g. a bastion's automation failing for one account while a person logs in as another
                claim += (f" None of the failures named '{account}', and they show neither several names nor "
                          "invalid users, so they need not belong to this login.")
                lane, confidence = "lead", "medium"
        else:
            claim = (f"On {host}, sshd accepted a {method} login for account '{account}' from {ip} at {when}; in "
                     f"the preceding {self.WINDOW / 60:.0f} minutes sshd recorded {f.count} failed attempt(s) "
                     f"against '{account}' from {len(f.sources)} other source address(es) "
                     f"({_names(sources, more_than=len(f.sources))}; "
                     f"threshold {self.ACCOUNT_MIN}), and {f.own} from {ip} itself. The login's source differs "
                     "from the failing sources, so the records do not link them.")
            lane, confidence = "lead", "medium"
        if f.repeats > 1:
            claim += (f" Logins of this account from this source followed such failures {f.repeats} time(s); "
                      f"the first and up to {self.LATER} later ones are cited.")
        claim += " Failures inside connections that then logged in are not counted."
        claim += cited_phrase(len(f.failures), f.count, False, "failed attempts", "failed attempt")
        if len(f.failures) < f.count:
            claim = claim[:-1] + " (the latest before the login)."
        events = sorted(_unique([*f.failures, s, *f.later]), key=lambda e: (e.ts, e.id))
        predicate = [pf(s, n) for n in ("auth.phase", "user.name", "source.ip", "source.port") if s.has(n)]
        predicate += _ssh_predicate(f.failures[-2:])
        m = Match(self.id, claim, "correlated_observation", events, predicate, s.ts, self.severity, lane,
                  confidence, s.entities(), group_key=f"{variant}|{host}|{ip}|{account}")
        m.notes.append("T1110.001" if len(f.accounts) <= 1 else "T1110.003")
        return m


# ------------------------------------------------------------------------------------------------
# Account and group creation or modification.
# ------------------------------------------------------------------------------------------------

# Membership that grants root or its equivalent: sudo/wheel/admin through sudoers, root by gid, docker/lxd/lxc by
# starting a privileged container that mounts the host, disk by raw block-device access.
PRIVILEGED_GROUPS = {"sudo", "wheel", "root", "admin", "docker", "lxd", "lxc", "disk"}


class AccountForm(NamedTuple):
    action: str                    # create_user | create_group | add_to_group | remove_from_group | modify_user |
    #                                modify_group | delete_user | delete_group | password_change | expiry_change |
    #                                account_db_edit | defaults_change
    accounts: tuple[str, ...]
    groups: tuple[str, ...]
    detail: str                    # what the command line asks for, worded as a request
    privileged: str                # why the request grants root or its equivalent; "" otherwise


def _long(spec: str) -> dict[str, tuple[str, bool]]:
    """`name:k=` (takes a value) / `name:k` (flag) pairs; k is the short alias or '-' for none."""
    out = {}
    for item in spec.split():
        name, _, rest = item.partition(":")
        takes = rest.endswith("=")
        key = rest.rstrip("=")
        out[f"--{name}"] = (f"--{name}" if key == "-" else key, takes)
    return out


# Option grammars of the shadow-utils tools, Debian's adduser family and BusyBox's applets.
_GRAMMARS: dict[str, tuple[str, str, dict[str, tuple[str, bool]]]] = {
    "useradd": ("bcdefgGkKpsuZRP", "DhlmMNorUF", _long(
        "base-dir:b= comment:c= home-dir:d= defaults:D expiredate:e= inactive:f= gid:g= groups:G= help:h skel:k= "
        "key:K= no-log-init:l create-home:m no-create-home:M no-user-group:N non-unique:o password:p= system:r "
        "root:R= prefix:P= shell:s= uid:u= user-group:U selinux-user:Z= btrfs-subvolume-home:- badname:- "
        "add-subids-for-system:F selinux-range:-=")),
    "usermod": ("cdefgGlpsuRPZvVwW", "ahLmoUr", _long(
        "append:a badname:- comment:c= home:d= expiredate:e= inactive:f= gid:g= groups:G= help:h login:l= lock:L "
        "move-home:m non-unique:o password:p= remove:r root:R= prefix:P= shell:s= uid:u= unlock:U add-subuids:v= "
        "del-subuids:V= add-subgids:w= del-subgids:W= selinux-user:Z= selinux-range:-=")),
    "userdel": ("RP", "fhrZ", _long("force:f help:h remove:r root:R= prefix:P= selinux-user:Z")),
    "groupadd": ("gKpRPU", "fhor", _long(
        "force:f gid:g= help:h key:K= non-unique:o password:p= system:r root:R= prefix:P= users:U=")),
    "groupmod": ("gnpRPU", "aho", _long(
        "append:a gid:g= help:h new-name:n= non-unique:o password:p= root:R= prefix:P= users:U=")),
    "groupdel": ("RP", "fh", _long("force:f help:h root:R= prefix:P=")),
    "gpasswd": ("adMAQ", "rRh", _long(
        "add:a= delete:d= members:M= administrators:A= remove-password:r restrict:R root:Q= help:h")),
    "passwd": ("nxwirRP", "adehklqSuf", _long(
        "all:a delete:d expire:e help:h keep-tokens:k inactive:i= lock:l mindays:n= quiet:q repository:r= root:R= "
        "prefix:P= status:S unlock:u warndays:w= maxdays:x= stdin:-")),
    "chpasswd": ("csRP", "emh", _long("crypt-method:c= encrypted:e help:h md5:m sha-rounds:s= root:R= prefix:P=")),
    "chage": ("dEImMWRP", "hli", _long(
        "lastday:d= expiredate:E= help:h iso8601:i inactive:I= list:l mindays:m= maxdays:M= root:R= prefix:P= "
        "warndays:W=")),
    "newusers": ("csRP", "rh", _long("crypt-method:c= system:r sha-rounds:s= root:R= prefix:P= help:h badname:-")),
    "vipw": ("R", "gpqsh", _long("group:g passwd:p quiet:q shadow:s root:R= help:h")),
    "debian-adduser": ("c", "qdhv", _long(
        "home:-= shell:-= no-create-home:- uid:-= firstuid:-= lastuid:-= firstgid:-= lastgid:-= gecos:-= "
        "comment:-= ingroup:-= gid:-= disabled-password:- disabled-login:- add-extra-groups:- add_extra_groups:- "
        "encrypt-home:- system:- group:- conf:c= quiet:q debug:d force-badname:- allow-badname:- allow-all-names:- "
        "help:h version:v extrausers:-")),
    "debian-deluser": ("c", "qdhv", _long(
        "remove-home:- remove-all-files:- backup:- backup-to:-= system:- group:- conf:c= quiet:q debug:d help:h "
        "version:v only-if-empty:-")),
    "busybox-adduser": ("hgsGuk", "SDH", {}),
    "busybox-addgroup": ("g", "S", {}),
    "busybox-deluser": ("", "", {}),
}
_TOOL_GRAMMAR = {"useradd": "useradd", "usermod": "usermod", "userdel": "userdel", "groupadd": "groupadd",
                 "groupmod": "groupmod", "groupdel": "groupdel", "gpasswd": "gpasswd", "passwd": "passwd",
                 "chpasswd": "chpasswd", "chgpasswd": "chpasswd", "chage": "chage", "newusers": "newusers",
                 "vipw": "vipw", "vigr": "vipw", "adduser": "debian-adduser", "addgroup": "debian-adduser",
                 "deluser": "debian-deluser", "delgroup": "debian-deluser"}
ACCOUNT_TOOLS = frozenset(_TOOL_GRAMMAR)
_ACCOUNT_WRITE_PROGRAMS = {
    "sed", "perl", "tee", "sponge", "cp", "mv", "install", "ln", "truncate", "dd", "curl", "wget",
    "scp", "rsync",
}


def _is_zero(value: str | None) -> bool:
    return value is not None and value.isdigit() and int(value) == 0


def _privilege(uid: str | None = None, gid: str | None = None, groups: tuple[str, ...] = ()) -> str:
    reasons = []
    if _is_zero(uid):
        reasons.append("user id 0 (root's)")
    if _is_zero(gid) or gid == "root":
        reasons.append("primary group root")
    held = sorted(set(groups) & PRIVILEGED_GROUPS)
    if held:
        reasons.append(f"membership of privileged group(s) {', '.join(held)}")
    return "; ".join(reasons)


def _split_groups(value: str | None) -> tuple[str, ...]:
    return tuple(item for item in (value or "").split(",") if item)


def account_command(name: str, args: list[str], busybox: bool = False,
                    actor: str | None = None) -> tuple[list[AccountForm], bool]:
    """What an account or group tool's command line asks for, and whether the parse is uncertain. Read-only
    invocations (help, version, listing defaults, `passwd -S`, `chage -l`) ask for nothing."""
    grammar = _TOOL_GRAMMAR.get(name)
    if grammar is None:
        return [], False
    if busybox and name in {"adduser", "addgroup", "deluser", "delgroup"}:
        grammar = {"adduser": "busybox-adduser", "addgroup": "busybox-addgroup"}.get(name, "busybox-deluser")
    short_values, short_flags, long_options = _GRAMMARS[grammar]
    parsed = getopt_long(args, short_values, short_flags, long_options)
    opts: dict[str, str | None] = {}
    for key, value in parsed.options:
        opts[key] = value if key not in opts or value is not None else opts[key]
    ops = parsed.operands
    if any(k in opts for k in ("--help", "--version")) or ("h" in opts and not grammar.startswith("busybox")):
        return [], False
    forms: list[AccountForm] = []
    first = ops[0] if ops else None

    def add(action, accounts=(), groups=(), detail="", privileged=""):
        forms.append(AccountForm(action, tuple(a for a in accounts if a), tuple(g for g in groups if g), detail,
                                 privileged))

    if name == "useradd":
        if "D" in opts:
            if len(opts) > 1:
                add("defaults_change", detail="change the defaults for new accounts")
            return forms, parsed.uncertain
        groups = _split_groups(opts.get("G"))
        uid, gid = opts.get("u"), opts.get("g")
        traits = [f"user id {uid}" if uid else "", "non-unique id" if "o" in opts else "",
                  "system account" if "r" in opts else "", "with a password hash set" if "p" in opts else "",
                  f"primary group {gid}" if gid else ""]
        add("create_user", [first], groups, f"create account '{first}'" + _traits(traits),
            _privilege(uid, gid, groups))
        if groups:
            add("add_to_group", [first], groups, f"add the new account to group(s) {', '.join(groups)}",
                _privilege(groups=groups))
    elif name == "usermod":
        login = ops[-1] if ops else None
        groups = _split_groups(opts.get("G"))
        if groups and "r" in opts:
            add("remove_from_group", [login], groups, f"remove '{login}' from group(s) {', '.join(groups)}")
        elif groups:
            detail = (f"add '{login}' to group(s) {', '.join(groups)}" if "a" in opts else
                      f"set the supplementary groups of '{login}' to {', '.join(groups)}")
            add("add_to_group", [login], groups, detail, _privilege(groups=groups))
        changes = {"u": "user id", "g": "primary group", "l": "login name", "s": "shell", "d": "home directory",
                   "e": "expiry date", "f": "inactivity period", "p": "password hash"}
        asked = [f"{label} to {opts[k]!r}" if k != "p" else "set the password hash" for k, label in changes.items()
                 if opts.get(k) is not None]
        asked += [label for k, label in (("L", "lock the account"), ("U", "unlock the account"),
                                         ("o", "allow a non-unique user id")) if k in opts]
        asked += ["change subordinate id ranges" for k in "vVwW" if opts.get(k) is not None][:1]
        if asked:
            add("modify_user", [login], (), f"modify '{login}': " + "; ".join(asked),
                _privilege(opts.get("u"), opts.get("g")))
    elif name == "userdel":
        add("delete_user", [first], (), f"delete account '{first}'" + (" and its home" if "r" in opts else ""))
    elif name == "groupadd":
        members = _split_groups(opts.get("U"))
        add("create_group", (), [first], f"create group '{first}'" + _traits(
            [f"group id {opts['g']}" if opts.get("g") else "", "non-unique id" if "o" in opts else ""]),
            _privilege(gid=opts.get("g")))
        if members:
            add("add_to_group", members, [first], f"add {_names(members)} to the new group",
                _privilege(groups=(first,)) if first else "")
    elif name == "groupmod":
        members = _split_groups(opts.get("U"))
        asked = [f"group id to {opts['g']!r}" if opts.get("g") else "", f"name to {opts['n']!r}" if opts.get("n") else "",
                 "set the group password" if opts.get("p") else ""]
        if any(asked):
            add("modify_group", (), [first], f"modify group '{first}': " + "; ".join(a for a in asked if a),
                _privilege(gid=opts.get("g")))
        if members:
            add("add_to_group", members, [first], f"add {_names(members)} to group '{first}'",
                _privilege(groups=(first,)) if first else "")
    elif name == "groupdel":
        add("delete_group", (), [first], f"delete group '{first}'")
    elif name == "gpasswd":
        group = ops[-1] if ops else None
        if opts.get("a"):
            add("add_to_group", [opts["a"]], [group], f"add '{opts['a']}' to group '{group}'",
                _privilege(groups=(group,)) if group else "")
        if opts.get("d"):
            add("remove_from_group", [opts["d"]], [group], f"remove '{opts['d']}' from group '{group}'")
        if opts.get("M") is not None:
            members = _split_groups(opts.get("M"))
            add("add_to_group", members, [group], f"set the members of group '{group}' to {_names(members)}",
                _privilege(groups=(group,)) if group and members else "")
        if opts.get("A") is not None or "r" in opts or "R" in opts:
            add("modify_group", (), [group], f"change the administrators or password of group '{group}'")
        if not forms:
            add("modify_group", (), [group], f"set the password of group '{group}'")
    elif name == "passwd":
        if "S" in opts:
            return [], False
        target = first or actor
        whose = f"'{target}'" if first else f"the running account's own ('{actor}')" if actor else "the running account"
        if "d" in opts:
            add("password_change", [target], (), f"delete the password of {whose} (password-less login)")
        elif "l" in opts or "u" in opts:
            add("modify_user", [target], (), f"{'lock' if 'l' in opts else 'unlock'} the password of {whose}")
        elif "e" in opts or any(opts.get(k) is not None for k in "nxwi"):
            add("expiry_change", [target], (), f"change the password aging of {whose}")
        else:
            add("password_change", [target], (), f"set the password of {whose}")
    elif name in {"chpasswd", "chgpasswd"}:
        add("password_change", (), (), "set passwords for the accounts given on standard input (not in argv)")
    elif name == "chage":
        if "l" in opts:
            return [], False
        if any(opts.get(k) is not None for k in "dEImMW"):
            add("expiry_change", [first], (), f"change the password aging or expiry of '{first}'")
    elif name == "newusers":
        add("create_user", (), (), "create or update accounts in bulk from " + (f"file '{first}'" if first else
                                                                                 "standard input"))
    elif name in {"vipw", "vigr"}:
        database = "group" if name == "vigr" or "g" in opts else "passwd"
        add("account_db_edit", (), (), f"open the {database}{' shadow' if 's' in opts else ''} database in an "
            "editor")
    elif grammar == "debian-adduser":
        uid, gid, ingroup = opts.get("--uid"), opts.get("--gid"), opts.get("--ingroup")
        if len(ops) >= 2:
            add("add_to_group", [ops[0]], [ops[1]], f"add '{ops[0]}' to group '{ops[1]}'",
                _privilege(groups=(ops[1],)))
        elif first and (name == "addgroup" or ("--group" in opts and "--system" not in opts)):
            add("create_group", (), [first], f"create group '{first}'" + _traits(
                [f"group id {gid}" if gid else ""]), _privilege(gid=gid))
        elif first:
            add("create_user", [first], tuple(g for g in (ingroup,) if g), f"create account '{first}'" + _traits(
                [f"user id {uid}" if uid else "", "system account" if "--system" in opts else "",
                 f"primary group {ingroup or gid}" if ingroup or gid else ""]),
                _privilege(uid, gid, (ingroup,) if ingroup else ()))
    elif grammar == "debian-deluser":
        if len(ops) >= 2:
            add("remove_from_group", [ops[0]], [ops[1]], f"remove '{ops[0]}' from group '{ops[1]}'")
        elif first and (name == "delgroup" or "--group" in opts):
            add("delete_group", (), [first], f"delete group '{first}'")
        elif first:
            add("delete_user", [first], (), f"delete account '{first}'")
    elif grammar == "busybox-adduser":
        groups = _split_groups(opts.get("G"))
        if len(ops) >= 2:
            add("add_to_group", [ops[0]], [ops[1]], f"add '{ops[0]}' to group '{ops[1]}'",
                _privilege(groups=(ops[1],)))
        elif first:
            add("create_user", [first], groups, f"create account '{first}'" + _traits(
                [f"user id {opts['u']}" if opts.get("u") else "", f"group {groups[0]}" if groups else ""]),
                _privilege(opts.get("u"), None, groups))
    elif grammar == "busybox-addgroup":
        if len(ops) >= 2:
            add("add_to_group", [ops[0]], [ops[1]], f"add '{ops[0]}' to group '{ops[1]}'",
                _privilege(groups=(ops[1],)))
        elif first:
            add("create_group", (), [first], f"create group '{first}'", _privilege(gid=opts.get("g")))
    elif grammar == "busybox-deluser":
        if len(ops) >= 2:
            add("remove_from_group", [ops[0]], [ops[1]], f"remove '{ops[0]}' from group '{ops[1]}'")
        elif first:
            add("delete_group" if name == "delgroup" else "delete_user", (), (),
                f"delete {'group' if name == 'delgroup' else 'account'} '{first}'")
    uncertain = parsed.uncertain or any(
        f.action not in {"password_change", "account_db_edit", "defaults_change"} and not (f.accounts or f.groups)
        for f in forms) or (not forms and not ops)
    return forms, uncertain


# The account databases the tools edit. Writing them directly creates or changes accounts without the tools (and
# without the tools' audit records).
ACCOUNT_FILES = frozenset({"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow"})
_TEXT_WRITERS = {"echo", "printf"}


def _written_line_privilege(path: str, words: list[str]) -> str:
    """Privilege a passwd or group line printed into an account file grants (user id 0, or a privileged group
    with members). The words are the printing command's arguments, so this reads intent, not the file."""
    for word in words:
        for line in word.replace("\\n", "\n").splitlines():
            fields = line.split(":")
            if path == "/etc/passwd" and len(fields) >= 7 and _is_zero(fields[2]):
                return "user id 0 (root's) in the written passwd line"
            if path == "/etc/group" and len(fields) >= 4 and fields[0] in PRIVILEGED_GROUPS and fields[3]:
                return f"membership of privileged group {fields[0]} in the written group line"
    return ""


def account_file_writes(name: str, args: list[str], cwd: str | None,
                        argv0: str = "") -> tuple[list[AccountForm], bool]:
    """Direct writes to the account databases by a write-capable program (an editor, sed -i, tee, cp/mv/install,
    dd), or by shell command text that redirects into them; and whether a write target could not be placed.
    Permission and owner changes are not writes."""
    if name in {"chmod", "chown", "chgrp"}:
        return [], False
    forms: list[AccountForm] = []
    targets, uncertain = write_targets(name, args, cwd, argv0=argv0)
    for target in targets:
        if target.path in ACCOUNT_FILES and not target.assumed:
            forms.append(AccountForm("account_db_edit", (), (), f"write {target.path} directly ({target.form})", ""))
    segments, incomplete = shell_segments(name, args)
    for segment in segments:
        command = canonical(basename(segment.argv[0])) if segment.argv else ""
        for op, target_text in segment.redirects:
            path = normalize_path(target_text, cwd)
            if op in {">", ">>", "1>", "1>>"} and path in ACCOUNT_FILES:
                privileged = (_written_line_privilege(path, segment.argv[1:]) if command in _TEXT_WRITERS else "")
                forms.append(AccountForm("account_db_edit", (), (), f"write {path} with a shell redirect ('{op}')",
                                         privileged))
        if command and command not in ACCOUNT_TOOLS:
            text_forms, text_uncertain = account_file_writes(command, segment.argv[1:], cwd, segment.argv[0])
            forms += [f._replace(detail=f"{f.detail} in shell command text") for f in text_forms]
            uncertain = uncertain or text_uncertain
    return forms, uncertain or incomplete


def _traits(items: list[str]) -> str:
    present = [item for item in items if item]
    return f" ({', '.join(present)})" if present else ""


_ACTION_TECHNIQUE = {"create_user": "T1136.001", "add_to_group": "T1098.007", "delete_user": "T1531",
                     "account_db_edit": "T1136.001"}
_RECORD_PHRASE = {"create_user": "an account was added", "delete_user": "an account was deleted",
                  "create_group": "a group was added", "delete_group": "a group was deleted",
                  "modify_user": "an account was modified", "modify_group": "a group was modified",
                  "password_change": "a password was changed", "group_password_change": "a group password was changed",
                  "lock": "an account was locked", "unlock": "an account was unlocked"}


@dataclass
class _Change:
    host: str | None
    ts: float
    action: str
    accounts: tuple[str, ...]
    groups: tuple[str, ...]
    detail: str
    privileged: str
    lineage: Lineage
    actor: str
    command: TypedEvent | None = None
    records: list[TypedEvent] = field(default_factory=list)
    login: str | None = None       # the audit login user or uid recorded on the command or record, if any
    exec_seen: bool = True         # an exec record of the changing process was retrieved


def _login(e: TypedEvent) -> str | None:
    """The audit login user (or login uid) recorded on a record; None when neither is recorded."""
    value = e.get("process.login_user") or e.get("process.auid")
    return str(value) if value not in (None, "") else None


def _offsets(seconds: list[float]) -> str:
    """'from 40 s to 41 s after', '12 s before', 'from 5 s before to 30 s after'."""
    low, high = min(seconds), max(seconds)
    if low >= 0:
        return f"{low:.0f} s after" if round(low) == round(high) else f"from {low:.0f} s to {high:.0f} s after"
    if high <= 0:
        return (f"{-high:.0f} s before" if round(low) == round(high)
                else f"from {-low:.0f} s to {-high:.0f} s before")
    return f"from {-low:.0f} s before to {high:.0f} s after"


_GRANT_OPS = re.compile(r"(?:^|[-:_])add(?:$|[-:_])")


def _record_privilege(e: TypedEvent) -> str:
    """A grant only when the tool's own operation is an addition (or the record creates the account in the group);
    a removal, or an operation that is absent or unclear, is not read as a grant (see _record_mention)."""
    group, op = e.get("account.group"), str(e.get("account.op") or "")
    if group in PRIVILEGED_GROUPS and (_GRANT_OPS.search(op) or e.get("account.action") == "create_user"):
        return f"membership of privileged group {group}"
    # gpasswd -M / -A replace a group's member or administrator list: whoever is on it now holds the group
    if group in PRIVILEGED_GROUPS and op in ("set-group-members", "set-group-administrators"):
        return f"the {op.rsplit('-', 1)[-1]} of privileged group {group} set"
    # account.new_id is a value the tool says it assigned (usermod's "change user 'u' UID from 'a' to '0'"); a
    # modification record's account.id only names the account it changed, so it is never read as an assignment. A
    # creation record's id is the new account's (useradd's "new user: ... UID=n", ADD_USER id=n).
    if e.get("account.action") == "modify_user" and str(e.get("account.new_id")) == "0":
        return "assignment of user id 0"
    if e.get("account.action") == "create_user" and str(e.get("account.id")) == "0":
        return "a new account with user id 0"
    # usermod's primary group change to gid 0, and groupmod's new gid 0
    if e.get("account.action") == "modify_user" and op == "change-gid" and str(e.get("account.group_id")) == "0":
        return "primary group id 0 (root's group)"
    if e.get("account.action") == "modify_group" and str(e.get("account.new_id")) == "0":
        return "group id 0 given to a group"
    return ""


def _record_mention(e: TypedEvent) -> str:
    group = e.get("account.group")
    if group in PRIVILEGED_GROUPS and not _record_privilege(e):
        return f"names privileged group {group}"
    return ""


def _record_text(e: TypedEvent) -> str:
    kind = e.get("audit.record_type")
    parts = [str(kind) if kind else f"account tool log line action={e.get('account.action')}"]
    for name, label in (("account.op", "op"), ("account.name", "acct"), ("account.group", "grp")):
        if e.has(name):
            parts.append(f"{label}={e.get(name)}")
    result = {Outcome.success: "success", Outcome.failure: "failed"}.get(e.outcome, "unrecorded")
    return " ".join(parts) + f" res={result}"


# Two views of one change. A tool that changes an account writes its own audit record (when built with audit support)
# and its own syslog line, both from the same process within milliseconds. Without an exec record of that process
# they would be two changes with two actors ("root" from the audit record, "an unrecorded account" from the line).
_REMOVAL_OPS = re.compile(r"(?:^|[-:_])(?:del|delete|remove|removed)(?:$|[-:_])")


def _op_class(e: TypedEvent) -> str | None:
    """The class of a record's operation that must agree between two views of one change: a grant, a removal or a
    list set; None when the operation is absent or of another kind (the audit and line operations name the same
    change differently, so only these classes are compared)."""
    op = str(e.get("account.op") or "")
    if op.startswith("set-group-"):
        return "set"
    if _GRANT_OPS.search(op):
        return "grant"
    if _REMOVAL_OPS.search(op):
        return "removal"
    return None


def _view_fit(a: TypedEvent, b: TypedEvent) -> tuple[int, int] | None:
    """How well two tool records fit as the two views of one change, or None when they cannot be one.

    One must be an audit record and the other a tool line (two records of one view are two changes: chage writes a
    record per attribute, a loop repeats a change); they are on the same host with the same action; every field both
    carry agrees (account, group, operation class, known outcome); and their pids are equal, or one pid is missing
    and both name the same account. A higher fit (pids both recorded, more fields agreeing) wins."""
    if a.host != b.host or a.has("audit.record_type") == b.has("audit.record_type"):
        return None
    if a.get("account.action") != b.get("account.action"):
        return None
    agree = 0
    for name in ("account.name", "account.group"):
        x, y = a.get(name), b.get(name)
        if x not in (None, "") and y not in (None, ""):
            if str(x) != str(y):
                return None
            agree += 1
    ox, oy = _op_class(a), _op_class(b)
    if ox and oy:
        if ox != oy:
            return None
        agree += 1
    if Outcome.unknown not in (a.outcome, b.outcome) and a.outcome != b.outcome:
        return None
    pa, pb = a.get("process.pid"), b.get("process.pid")
    both = isinstance(pa, int) and isinstance(pb, int)
    if both and pa != pb:
        return None
    if not both and not (a.get("account.name") not in (None, "") and a.get("account.name") == b.get("account.name")):
        return None
    return int(both), agree


def _record_actor(e: TypedEvent) -> str | None:
    """Who a tool record says made the change: the audit login user, the process's user, then the audit login uid."""
    value = e.get("process.login_user") or e.get("process.user")
    if value not in (None, ""):
        return str(value)
    return f"audit login uid {e.get('process.auid')}" if e.has("process.auid") else None


def _change_privilege(c: _Change) -> list[str]:
    return sorted(({c.privileged} | set(map(_record_privilege, c.records))) - {""})


def _change_failed(c: _Change) -> bool:
    """Every recorded exec or tool result of the change failed (the same test the grouped findings apply)."""
    if c.command is not None:
        return c.command.outcome == Outcome.failure and not any(r.outcome == Outcome.success for r in c.records)
    return bool(c.records) and all(r.outcome == Outcome.failure for r in c.records)


def _change_status(c: _Change) -> str:
    """What the evidence shows of a change: 'reported' (a tool's own record reports it), 'requested' (only a command
    asked for it: whether the account database changed is not established) or 'failed' (every recorded exec or tool
    result failed)."""
    if _change_failed(c):
        return "failed"
    return "reported" if c.records else "requested"


_STATUS_PHRASE = {"reported": "reported by the tools' own records",
                  "requested": "requested by commands, with no tool record from the same process",
                  "failed": "attempted, every recorded result failed"}


def _status_counts(counts: Counter) -> str:
    """'reported by ...: 3 account(s) added, 1 group membership grant(s); requested by ...: ...' from (status, kind)
    counts, with the sentence that a request does not show the change took effect."""
    parts = []
    for status in ("reported", "requested", "failed"):
        kinds = sorted(((kind, n) for (s, kind), n in counts.items() if s == status), key=lambda item: (-item[1],
                                                                                                         item[0]))
        if kinds:
            text = ", ".join(f"{n} {_KIND_NOUN.get(kind, kind + ' change(s)')}" for kind, n in kinds)
            parts.append(f"{_STATUS_PHRASE[status]}: {text}")
    requested = sum(n for (s, _kind), n in counts.items() if s == "requested")
    return "; ".join(parts) + (f" (for these {requested} request(s), whether the account database changed is not "
                               "established)" if requested else "")


def _change_lane(c: _Change) -> str:
    """The lane the change would have on its own: high for a privileged request or report (or a web-service exec
    lineage) unless every recorded result failed, else lead."""
    if (c.lineage.kind == "web" or _change_privilege(c)) and not _change_failed(c):
        return "high"
    return "lead"


def _change_text(c: _Change) -> str:
    """The change as a burst names it: what was requested or reported, with the account and group a record names."""
    text = c.detail
    if c.command is None:
        # a group record names the group it adds, deletes or modifies in its account field
        noun = "group" if c.action in _GROUP_ACTIONS and not c.groups else "account"
        text += (f" ({noun} '{c.accounts[0]}')" if c.accounts else "") + (f" (group '{c.groups[0]}')" if c.groups
                                                                         else "")
    return text


_GROUP_ACTIONS = frozenset({"create_group", "delete_group", "modify_group", "group_password_change"})


def _change_kind(c: _Change) -> str:
    if c.action in ("add_to_group", "remove_from_group", "expiry_change"):
        return {"add_to_group": "grant", "remove_from_group": "removal", "expiry_change": "expiry"}[c.action]
    if c.action in ("modify_user", "modify_group"):
        ops = [r for r in c.records if r.has("account.op")]
        kind = next((k for k in map(_op_class, ops) if k), None)
        if kind:
            return kind
        if any("expiry" in str(r.get("account.op")) for r in ops):
            return "expiry"
    return c.action


def _timeline_order(c: _Change) -> tuple[str, str]:
    """A change's place in the run timeline: by host, then time, then the record and the form (one command can
    request several changes at one instant), so the order never depends on how the state was held."""
    ident = c.command.id if c.command is not None else (c.records[0].id if c.records else "")
    return (f"{int(c.host is None)}|{c.host or ''}",
            f"{c.ts:020.6f}|{ident}|{c.action}|{','.join(c.accounts)}|{','.join(c.groups)}|{c.detail}")


_KIND_NOUN = {"create_user": "account(s) added", "delete_user": "account(s) deleted", "create_group": "group(s) added",
              "delete_group": "group(s) deleted", "grant": "group membership grant(s)",
              "removal": "group membership removal(s)", "set": "group member or administrator list(s) set",
              "password_change": "password change(s)", "group_password_change": "group password change(s)",
              "expiry": "password aging or expiry change(s)", "lock": "account lock(s)",
              "unlock": "account unlock(s)", "modify_user": "other account modification(s)",
              "modify_group": "other group modification(s)", "account_db_edit": "direct account database edit(s)",
              "defaults_change": "change(s) to the defaults for new accounts"}


def _writer_kind(e: TypedEvent) -> str:
    """The evidence a tool record is: a kernel audit record, or a tool line whose writer journald confirms, cannot
    confirm or contradicts (a line anyone can log under the tool's name)."""
    return "audit record" if e.has("audit.record_type") else f"tool line ({writer_state(e)} writer)"


def _change_class(c: _Change) -> tuple:
    """What a run's changes must share: the account that made them, the kind of evidence that records them, the audit
    login and whether an exec record of the changing process was retrieved. A change that differs in any of these
    is not folded into the others' run (a forged tool line beside audit-recorded changes, an interactive login's
    change inside a scripted run)."""
    writers = tuple(sorted({_writer_kind(r) for r in c.records})) or ("exec record only",)
    login = c.login or next((value for value in map(_login, c.records) if value), None) or ""
    return c.actor, writers, str(login), c.command is not None or c.exec_seen


def _class_text(cls: tuple) -> str:
    actor, writers, login, exec_seen = cls
    return (f"made as '{actor}'" + (f" (audit login '{login}')" if login else " (no audit login recorded)")
            + f", recorded by {' and '.join(writers)}, "
            + ("with an exec record of the changing process" if exec_seen else
               "with no exec record of the changing process"))


@dataclass
class _Burst:
    """One segment of a run of one evidence class of changes on one host, held as an aggregate: exact counts, every
    distinct change named (a segment holds at most NAMED distinct changes), bounded exemplars."""
    host: str | None
    cls: tuple
    first: float
    last: float
    first_id: str
    segment: int = 1                    # this item's segment of the run ...
    segments: int = 1                   # ... of this many
    run_changes: int = 0                # the whole run's changes of this class, and their kinds
    run_kinds: Counter = field(default_factory=Counter)
    changes: int = 0
    kinds: Counter = field(default_factory=Counter)     # (status, kind) -> changes
    targets: set = field(default_factory=set)
    targets_more: bool = False
    accounts: set = field(default_factory=set)          # account names, for one entity each
    accounts_more: int = 0
    privileged: dict = field(default_factory=dict)      # privileged change text -> count
    privileged_count: int = 0
    named: dict = field(default_factory=dict)           # other change text -> count
    high: int = 0
    commands: int = 0
    records: int = 0
    unexplained: int = 0
    cited_privileged: list = field(default_factory=list)
    cited_other: list = field(default_factory=list)
    lineage: object = None
    lineage_high: bool = False
    techniques: set = field(default_factory=set)
    mentions: set = field(default_factory=set)
    # the shape the fleet merge compares (see AccountOrGroupChange._fleets)
    signatures: set = field(default_factory=set)
    lineages: set = field(default_factory=set)


@dataclass
class _RunShape:
    """A finished run segment item and what a fleet merge compares: its shape key (empty when it cannot be merged,
    with the reason) and the parts the shape is made of."""
    key: str
    unmergeable: str
    host: str | None
    first: float
    last: float
    lane: str
    anchor_id: str
    signatures: frozenset
    cls: tuple
    lineages: tuple
    segment: tuple
    changes: int
    match: Match


@dataclass
class _Fleet:
    """Runs of one shape on several hosts inside one fleet window: exact counts, bounded names and exemplars; the
    full host list is in the rule's member store, in chunks."""
    fid: str
    key: str
    first: float
    last: float
    template: _RunShape
    runs: int = 0
    hosts: int = 0
    lane: str = "lead"
    sample_hosts: list = field(default_factory=list)
    exemplars: list = field(default_factory=list)
    chunks: int = 0
    chunk_fill: int = 0
    changes_min: int = 0
    changes_max: int = 0
    excluded: list = field(default_factory=list)
    excluded_count: int = 0


def _signature_text(sig: tuple) -> str:
    kind, accounts, groups, privileges, status = sig
    text = _KIND_NOUN.get(kind, kind).replace("(s)", "")
    noun = "group" if kind in _GROUP_ACTIONS and not groups else "account"
    names = ", ".join([f"{noun} '{a}'" for a in accounts] + [f"group '{g}'" for g in groups])
    return (f"{text} ({names})" if names else text) + (f": {'; '.join(privileges)}" if privileges else "") + {
        "reported": "", "requested": " (requested only; not shown to have taken effect)",
        "failed": " (failed)"}[status]


class AccountOrGroupChange(Playbook):
    state_slice = "strong"           # a strong-indicator rule (see Playbook.state_slice)
    id = "host.account_or_group_change"
    version = "8"
    title = "Account or group created, deleted or modified (command or account-management audit record)"
    anchor_class = "persistence"
    kind = "aggregate"
    families = ("process_exec", "account_change", "system_state")
    context_families = ("process_observed",)
    os_families = ("linux",)
    claim_type = "aggregate_observation"
    assures_negative = False
    positive_only_reason = (
        "commands are recognised from argv with each tool's option grammar, and the tools' own audit records exist "
        "only when the tool was built with audit support; accounts can also be changed by editing the account "
        "files directly, so a window without matches proves nothing")
    severity, lane = "high", "lead"
    attack = ("T1136.001", "T1098", "T1098.007", "T1531")
    benign = ("administrators provisioning or removing accounts", "package installation creating system accounts",
              "cloud-init or configuration management applying account policy")
    next_checks = ("the account's first authentication after the change", "auth_activity for the actor's session",
                   "the account files' current content for the named accounts and groups")
    JOIN_SECONDS = 10.0
    # A first-boot provisioning agent (cloud-init's users and set-passwords modules, a first-boot script) changes
    # accounts within minutes of the boot, often before exec auditing is in place, so its exec lineage is missing.
    BOOT_SECONDS = 900.0            # after the boot record (half-open)
    PRE_BOOT_SECONDS = 120.0        # before it: records buffered before the audit daemon logged the boot
    BOOT_CITE = 64                  # distinct changes of a boot group cited with a record each
    BOOTS_KEPT = 64                 # boot records kept per host for the join and the citation
    # Two views of one change (an audit record and the tool's line) are written by one process within milliseconds;
    # the tolerance only absorbs timestamp granularity and shipper stamping (plain syslog has 1 s resolution), the
    # same allowance the join of a record to its exec uses. The pid, not the time, is what identifies the process.
    VIEW_SECONDS = JOIN_SECONDS
    VIEW_OPEN = 4096                # unpaired records held per host while a partner may still come (10 s of them)
    # A run of changes on one host. Steps of one automated run (configuration management, an image build, a
    # first-boot agent, an administrator's script) follow each other within seconds, and its longest pauses are the
    # package transactions and service restarts between its account steps, which take minutes; ten minutes spans
    # those. The hour bounds what one item covers (the window that holds one hands-on session or one scripted stage,
    # as in the ranking's co-occurrence), so a host changing accounts all day is one item per hour, each saying the
    # run goes on. Neither value decides a lane: they decide only how many items one host's changes become.
    BURST_GAP = 600.0               # a change joins the run when it is less than this after the previous one
    BURST_SPAN = 3600.0             # ... and less than this after the run's first change
    # One account's setup (the account, its private group of the same name, one group grant, its password and
    # expiry) names at most two names; three distinct account or group names make a run of several accounts or
    # several grants. Below it the per-actor findings stand, so a lone account created with a sudo grant stays its
    # own item.
    BURST_TARGETS = 3
    BURST_TARGET_NAMES = 4096       # distinct names counted exactly per run segment; beyond, "more than"
    BURST_CITE = 64                 # changes cited per run segment (privileged first, then the earliest)
    # A run segment names every distinct change it holds, with repeat counts; a run with more distinct changes goes
    # on in a further segment item, so every change is named in some item and no item's notes grow without bound.
    NAMED = 500
    RUN_CLASSES = 64                # evidence classes of one run told apart; changes of further classes stay alone
    ALONE_HOSTS = 65536             # hosts whose changes published alone are counted by host
    # The same run on several hosts. A rollout (configuration management applied across an inventory, an image or
    # template deployment wave, an autoscaling batch) applies one run to its hosts within one maintenance window;
    # six hours spans such a window, and a host whose same run comes later stays its own item (an odd moment is
    # never merged away). Three hosts is the least that shows a rollout rather than a pair of hosts, the same floor
    # the ranking's fleet prevalence uses. Neither value decides a lane.
    FLEET_WINDOW = 6 * 3600.0       # a run joins a fleet when it starts less than this after the fleet's first run
    FLEET_MIN_HOSTS = 3
    FLEET_HOSTS_NAMED = 12          # hosts named in a fleet item's claim (every host is in its paged host list)
    FLEET_CITE_RUNS = 8             # member runs a fleet item cites changes from
    FLEET_CITE = 64                 # records a fleet item cites from its exemplar runs
    # Each listed host's record (its run's first record) is cited too, so its host-list entry opens a stored record;
    # beyond this many hosts the entries name a record that is not stored with the item, and the item says so.
    FLEET_HOST_CITE = 1000
    FLEET_EXCLUDED_NAMED = 32       # excluded similar runs named per fleet (all are counted)
    FLEET_ACTIVE = 256              # fleets compared at once with the runs that were not merged
    FLEET_CHUNK = 1000              # hosts per chunk of a fleet's member list
    FLEET_SIMILAR = 0.5             # a run sharing at least this share of a fleet's changes is named as excluded
    # A similar run is named as excluded when it starts within a day of the fleet's span: the same run repeated at
    # another hour of the same day is the odd moment an analyst should see beside the fleet.
    FLEET_NEAR = 24 * 3600.0
    program_prefilter = True
    card: ClassVar[dict] = {
        "behavior": "an account or group tool was run to create, delete or modify an account, group membership, "
                    "password or expiry; a command or shell text wrote /etc/passwd, /etc/shadow, /etc/group or "
                    "/etc/gshadow directly; or a tool's audit record reports such a change",
        "telemetry": "auditd EXECVE+SYSCALL as process_exec and other audit SYSCALL records as process_observed "
                     "for lineage (process.executable, process.argv, process.pid, "
                     "process.ppid, process.user): present (root execs captured); audit ADD_USER/DEL_USER/ADD_GROUP/"
                     "DEL_GROUP/USER_MGMT/GRP_MGMT/USER_CHAUTHTOK/GRP_CHAUTHTOK/ACCT_LOCK/ACCT_UNLOCK as "
                     "account_change: typed; the lab profile holds password-change records only. Audit SYSTEM_BOOT as "
                     "system_state (system.event) places a change relative to the host's boot",
        "fidelity": "exec: the command was run (outcome stated), never that the change happened; record: the tool "
                    "reports the change and its result",
        "benign_and_cost": "routine provisioning and package-created system accounts (grouped per host under "
                           "package or cloud-init lineage); first-boot provisioning that left only the tools' audit "
                           "records (no exec record of the changing process) is one lead per (host, boot) when every "
                           "change is from 2 minutes before to 15 minutes after a recorded boot and carries no audit "
                           "login uid; one record is cited per distinct change and every change is in the notes; "
                           "a provisioning run (configuration management, an image build, an administrator's "
                           "script creating accounts and adding the administrator to privileged groups) is one item "
                           "per host and run, high when it grants a privileged group, so a freshly built fleet costs "
                           "one item per host rather than one per change. Cost of the fold: an intruder's grant made "
                           "inside such a run shares its item (named and cited first, lane kept)",
        "query_cost": "none beyond the sweep",
        "next_pivot": "the account's first login and what that session ran",
        "adds": "no earlier rule covers account or group changes",
        "research_basis": "ATT&CK Enterprise 20.0 T1136.001, T1098, T1098.007, T1531 (procedure: useradd/usermod); "
                          "shadow-utils and Debian adduser option grammars; libaudit audit_log_acct_message record "
                          "format; shadow-utils SYSLOG statements (src/useradd.c, usermod.c, userdel.c, groupadd.c, "
                          "groupdel.c, groupmod.c, gpasswd.c, chage.c, passwd.c on master) and the Elastic System "
                          "integration's auth pipeline test logs (test-gpasswd, test-usermod-group, test-userdel)",
        "text_records": "the tools' own syslog lines (any Linux shipper shape) are account_change records with the "
                        "same actions and operations as the audit records and the writer's pid (journald _PID, the "
                        "shipper's process.pid or the syslog header's), so a line joins the exec of its process like "
                        "an audit record; usermod's UID change to 0 (account.new_id) and a created account with user id 0 "
                        "(useradd's line or ADD_USER id=0) are user id 0 grants; gpasswd -M/-A onto a root-equivalent group, "
                        "usermod's GID change to 0 and groupmod's new gid 0 are high too; a high claim resting on the "
                        "tools' own lines names their writer when journald does not confirm it",
        "lanes": "high for a web-service account in the exec lineage, or a request for user/group id 0 or "
                 "membership of a root-equivalent group; package/cloud-init lineage is one grouped lead per host; "
                 "unprivileged audit records with no exec record of their process and no login uid, from 2 minutes "
                 "before to 15 minutes after a recorded boot, are one grouped lead per (host, boot), worded as "
                 "boot-time provisioning or a boot-time job; a run of changes on one host naming at least 3 "
                 "distinct accounts and groups is one item per run with the lane of its strongest change (high when "
                 "any change in it is), never lower; the same run on 3 or more hosts in one rollout window is one "
                 "fleet item at the lane of its strongest run; web-service lineage is never folded into a run; "
                 "everything else is a lead",
        "views": "a tool's audit record and its own syslog line of one change (opposite views, same host and action, "
                 "at most 10 s apart, equal pids or one pid missing with the same account, every shared field "
                 "agreeing, grants never paired with removals) are one change citing both; the actor comes from the "
                 "record that names one (audit record first). A line with neither a pid nor an account name, or "
                 "farther than 10 s from its audit record, stays a change of its own",
        "bursts": "a host's changes outside package/cloud-init lineage, outside the boot group and outside a "
                  "web-service lineage are read in time order; a run continues while each change is less than 10 "
                  "minutes after the previous one, and is held whole (spilled) until it ends; it is split by "
                  "evidence class (the account that made the change, whether audit records, journald-confirmed, "
                  "unconfirmed or contradicted tool lines record it, the audit login, and whether an exec record of "
                  "the changing process was retrieved): a class naming at least 3 distinct account or group names "
                  "becomes run items, every other change (an outlier) keeps its per-actor finding, so a forged tool "
                  "line or an interactive login's change never hides inside a scripted run; a class's run is cut "
                  "into segments of less than an hour and at most 500 distinct changes, each item saying which "
                  "segment of how many and the whole run's counts; every distinct change is named in its segment's "
                  "notes, privileged ones first, up to 64 changes cited (privileged first; more privileged ones are "
                  "named, counted and the cell partial), one entity per account name; counts are split into "
                  "changes the tools' own records report, changes only a command requested (whether the account "
                  "database changed is not established) and changes whose every recorded result failed",
        "fleets": "run segment items of the same shape (the same distinct changes and their status, the same "
                  "evidence class, the same exec lineage kinds, the same segment of the same count) on at least 3 "
                  "hosts, each starting less than 6 hours after the first, are one fleet item at the lane of its "
                  "strongest run, with every host in its paged host list, records cited from up to 8 hosts' runs, "
                  "and wording that it groups by shape, not proven common origin; a run that differs (an extra or "
                  "missing change, another evidence class or lineage, or the same run more than 6 hours later) "
                  "keeps its own item, and the fleet item names it with how it differs when it shares at least half "
                  "the fleet's changes and starts within a day of the fleet",
        "retrieval": "the sweep retrieves every record of the host datasets in each partition (dataset filter "
                     "only), a superset of what this evaluator reads",
    }

    # Commands' changes (per host and pid, for the join with the tools' records), the tools' records and the boot
    # records are the findings' citations: each is staged when read and held to finalize in a keyed store or list,
    # HOT in memory and the rest on the rule's disk spill. Changes and records have their own disk budgets; only
    # a spent budget refuses, and coverage says so.
    staged = True
    HOT = HOT_COUNT  # a count cap only: the hunt's memory budget sizes it in bytes
    CHANGES_DISK = 2 * 2**30
    RECORDS_DISK = 2 * 2**30
    FINALIZE_TRIM = 10_000

    def __init__(self):
        super().__init__()
        self.lineage = ProcessLineage(self)
        self.by_pid = KeyedStore(self, "acct_by_pid", self.HOT, disk_budget=self.CHANGES_DISK)  # (host, pid) -> changes
        self.loose = SpillList(self, "acct_loose", self.HOT, disk_budget=self.CHANGES_DISK)  # changes without a pid
        self.records = SpillList(self, "acct_records", self.HOT, disk_budget=self.RECORDS_DISK)
        self.boots = KeyedStore(self, "acct_boots", self.HOT)           # host -> boot records
        self._seen = RecentIds()        # bounded re-read guard
        self._pending: list[TypedEvent] = []
        self._alone: list[Match] = []   # changes published on their own (the budget refused holding them)
        self._boot_events: dict[str, TypedEvent] = {}
        self._alone_hosts: Counter = Counter()   # changes published alone, by host (ALONE_HOSTS hosts at most) ...
        self._alone_other = 0                     # ... and on further hosts
        self.load = lambda ids: []

    def drain_staged(self) -> list[TypedEvent]:
        out, self._pending = self._pending, []
        self._trim()
        return out

    def retained_events(self) -> list[TypedEvent]:
        return []                                       # staged on disk instead

    def _trim(self) -> None:
        self.lineage.trim()
        self.by_pid.trim()
        self.loose.trim()
        self.records.trim()
        self.boots.trim()

    @staticmethod
    def _process_relevant(event: TypedEvent) -> bool:
        name = program_name_hint(event)
        return (name is None or name in ACCOUNT_TOOLS or name in _ACCOUNT_WRITE_PROGRAMS
                or name in SHELLS or is_editor(name))

    def consume(self, events):
        fresh = [e for e in events if e.family in self.families + self.context_families and e.id not in self._seen]
        self._batch = events
        order = {"process_observed": 0, "process_exec": 1, "account_change": 2, "system_state": 3}
        for e in sorted(fresh, key=lambda x: (x.ts, order.get(x.family, 9), x.id)):
            self._seen.add(e.id)
            if e.family == "process_observed":
                self.lineage.observe(e, self.raw_of(e), self.raw_target())
                continue
            if e.family == "process_exec":
                self.lineage.observe(e, self.raw_of(e), self.raw_target())
                if self.program_prefilter and not self._process_relevant(e):
                    self.evaluated += 1
                    self.missing_required += int(argv_incomplete(e))
                    continue
                self._exec(e)
            elif e.family == "system_state":
                # context only (where a change sits relative to a boot); never a change itself
                boots = self.boots.setdefault(e.host, list) if e.get("system.event") == "boot" else None
                if boots is not None and len(boots) < self.BOOTS_KEPT:
                    boots.append(e)
                    self._pending.append(e)
            else:
                self._record(e)
        self._batch = None
        out, self._alone = self._alone, []
        return out

    def _publish_alone(self, changes: list[_Change], record: TypedEvent) -> None:
        """An account change the budget refused to hold is a finding by itself: published now, one finding per
        group it would have joined, without the tool records a later join would have added."""
        self.note_limit("changes_alone", "the account changes' disk budget is spent; later changes are published as "
                                         "they are read, not grouped or joined to their tool records")
        groups: dict[tuple, list[_Change]] = {}
        for change in changes:
            groups.setdefault(self._group(change), []).append(change)
            if change.host in self._alone_hosts or len(self._alone_hosts) < self.ALONE_HOSTS:
                self._alone_hosts[change.host] += 1
            else:
                self._alone_other += 1
        for key, held in groups.items():
            add_unheld(self._alone, alone(self._finding(key, held), self, record))

    def _exec(self, e: TypedEvent) -> None:
        argv = e.get("process.argv")
        if not isinstance(argv, list) or not argv:
            self.missing_required += 1
            return
        # An incomplete argv cannot settle read-only flags (passwd -S) or the last operand (the login): the prefix
        # still yields a lead, worded as incomplete and never raised by what it appears to request.
        incomplete = argv_incomplete(e)
        if incomplete:
            self.missing_required += 1
        prog = program(e)
        if prog is None:
            name, args, busybox = canonical(basename(str(argv[0]))), [str(a) for a in argv[1:]], False
            if name in ACCOUNT_TOOLS:
                self.missing_required += 1      # identity from argv[0] only: the kernel-recorded executable is absent
        else:
            name, args, busybox = prog.name, prog.args, prog.name_from_argv0
        self.evaluated += 1
        if name in ACCOUNT_TOOLS:
            forms, uncertain = account_command(name, args, busybox, e.get("process.user"))
        elif incomplete:
            return
        else:
            forms, uncertain = account_file_writes(name, args, e.get("process.cwd"),
                                                   str((e.get("process.argv") or [""])[0]))
        if uncertain and not incomplete:
            self.missing_required += 1
        if not forms:
            return
        if incomplete:
            forms = [f._replace(detail=f"{f.detail}" + (f", requesting {f.privileged}" if f.privileged else "")
                                + " (read from an incomplete command line; later arguments are unknown)",
                                privileged="") for f in forms]
        lineage = self.lineage.classify(e)
        actor = str(e.get("process.user") or f"uid {e.get('process.uid')}")
        changes = [_Change(e.host, e.ts.timestamp(), form.action, form.accounts, form.groups, form.detail,
                           form.privileged, lineage, actor, command=e, login=_login(e)) for form in forms]
        if isinstance(e.get("process.pid"), int):
            held = self.by_pid.setdefault((e.host, e.get("process.pid")), list)
            if held is None:
                self._publish_alone(changes, e)
                return
            held += changes
        elif not self.loose.append(changes, (changes[0].ts, e.id)):
            self._publish_alone(changes, e)
            return
        self._pending.append(e)

    def _record(self, e: TypedEvent) -> None:
        if not e.has("account.action"):
            self.missing_required += 1
            return
        self.evaluated += 1
        if not self.records.append(e, (e.ts.timestamp(), e.id)):
            self._publish_alone([self._record_change([e])], e)
            return
        self._pending.append(e)

    def _boot(self, change: _Change) -> TypedEvent | None:
        """The host's recorded boot nearest the change, when the change is at most PRE_BOOT_SECONDS before it or
        less than BOOT_SECONDS after it."""
        near = [b for b in self.boots.peek(change.host, ())
                if -self.PRE_BOOT_SECONDS <= change.ts - b.ts.timestamp() < self.BOOT_SECONDS]
        return min(near, key=lambda b: (abs(b.ts.timestamp() - change.ts), b.ts, b.id)) if near else None

    def finalize(self):
        # Join each tool record to the command of the same process (same host and pid, close in time).
        unjoined = SpillList(self, "acct_unjoined", self.HOT, disk_budget=UNBUDGETED)
        for i, record in enumerate(self.records.ordered()):
            ts = record.ts.timestamp()
            candidates = [c for c in self.by_pid.get((record.host, record.get("process.pid")), ())
                          if abs(c.ts - ts) <= self.JOIN_SECONDS]
            if candidates:
                for change in candidates:
                    change.records.append(record)
            else:
                need(unjoined.append(record, (str(record.host or ""), f"{ts:020.6f}|{record.id}")), self,
                     "the unjoined tool records")
            if i % self.FINALIZE_TRIM == self.FINALIZE_TRIM - 1:
                self.by_pid.trim()
                unjoined.trim()
        groups = KeyedStore(self, "acct_groups", self.HOT, disk_budget=UNBUDGETED)
        # the changes a run may fold, by host then time (see _bursts)
        timeline = SpillList(self, "acct_timeline", self.HOT, disk_budget=UNBUDGETED)
        self._boot_events: dict[str, TypedEvent] = {}
        changes = (c for _key, held in self.by_pid.items() for c in held)
        loose = (c for held in self.loose for c in held)
        views = (self._record_change(view) for view in self._views(unjoined.ordered()))
        for i, change in enumerate(itertools.chain(changes, loose, views)):
            key = self._group(change)
            if key[0] == "actor" and change.lineage.kind != "web":
                need(timeline.append(change, _timeline_order(change)), self, "the account change timeline")
            else:
                need(groups.setdefault(key, list), self, "the account change grouping").append(change)
            if i % self.FINALIZE_TRIM == self.FINALIZE_TRIM - 1:
                groups.trim()
                timeline.trim()
        unjoined.clear()
        run_items = SpillList(self, "acct_runs", self.HOT, disk_budget=UNBUDGETED)
        self._bursts(timeline, groups, run_items)
        timeline.clear()
        runs = self._fleets(run_items)
        run_items.clear()
        out = [_citation for key in sorted(groups.keys(), key=str)
               for _citation in citation_call(self, self._finding, key, groups.peek(key))]
        groups.clear()
        return out + runs

    def finalize_fallback(self, reason: str) -> list[Match]:
        """Every held change on its own (grouping and joining needed disk): command changes by process, changes
        without a pid, then each tool record as the change it reports."""
        self._boot_events = {}
        out: list[Match] = []

        def each(changes) -> None:
            for change in changes:
                with citation_group(self, out, self._group(change), change):
                    m = self._finding(self._group(change), [change])
                    m.group_key += f"|alone:{(change.command or change.records[0]).id}"
                    m.notes.append(f"published on its own: grouping and joining needed disk ({reason})")
                    out.append(m)
        for source in (lambda: (c for _key, held in self.by_pid.items() for c in held),
                       lambda: (c for held in self.loose for c in held),
                       lambda: (self._record_change([record]) for record in self.records)):
            try:
                each(source())
            except StateExhausted:
                continue                            # a table on disk cannot be read: what was read stands
        return out

    def _views(self, records):
        """The changes the unjoined tool records report, as lists of the records that report each: a record alone,
        or an audit record and a tool line that are two views of one change (`_view_fit`). Records arrive ordered by
        host, then time; a record waits VIEW_SECONDS for its partner, and at most VIEW_OPEN unpaired records of a
        host wait at once (beyond, the oldest is taken alone and the rule says a pairing may have been missed)."""
        # unpaired records by (action, "name", account name or "") and, with a pid, by (action, "pid", pid): a record
        # with a name looks up its name and the nameless; a nameless one looks up the nameless and its pid (a
        # nameless pair needs equal pids), so the pairing does not depend on which view arrives first
        waiting: dict[tuple, list[TypedEvent]] = {}
        order: deque = deque()                           # unpaired records in time order (paired ones skipped)
        alive: set[str] = set()
        host = None

        def buckets(e: TypedEvent) -> list[tuple]:
            action, pid = str(e.get("account.action")), e.get("process.pid")
            return [(action, "name", str(e.get("account.name") or ""))] + (
                [(action, "pid", pid)] if isinstance(pid, int) else [])

        def lookups(e: TypedEvent) -> list[tuple]:
            action, name, pid = str(e.get("account.action")), str(e.get("account.name") or ""), e.get("process.pid")
            if name:
                return [(action, "name", name), (action, "name", "")]
            return [(action, "name", "")] + ([(action, "pid", pid)] if isinstance(pid, int) else [])

        def take(e: TypedEvent) -> None:
            alive.discard(e.id)
            for key in buckets(e):
                waiting[key].remove(e)
                if not waiting[key]:
                    del waiting[key]

        def oldest() -> TypedEvent | None:
            while order:
                e = order.popleft()
                if e.id in alive:
                    take(e)
                    return e
            return None

        for record in records:
            ts = record.ts.timestamp()
            if record.host != host:
                while (e := oldest()) is not None:
                    yield [e]
                host = record.host
            while order and (order[0].id not in alive or ts - order[0].ts.timestamp() > self.VIEW_SECONDS):
                e = order.popleft()
                if e.id in alive:
                    take(e)
                    yield [e]
            pool = list({other.id: other for key in lookups(record) for other in waiting.get(key, ())}.values())
            best = None
            for other in pool:
                fit = _view_fit(other, record)
                if fit is not None and (best is None or fit > best[0]
                                        or (fit == best[0] and (other.ts, other.id) < (best[1].ts, best[1].id))):
                    best = (fit, other)
            if best is not None:
                take(best[1])
                yield sorted([best[1], record], key=lambda e: (e.ts, e.id))
                continue
            alive.add(record.id)
            for key in buckets(record):
                waiting.setdefault(key, []).append(record)
            order.append(record)
            if len(alive) > self.VIEW_OPEN:
                self.note_limit("views_open", f"more than {self.VIEW_OPEN} account tool records of one host were "
                                              f"unpaired within {self.VIEW_SECONDS:.0f} s; the oldest were taken as "
                                              "changes of their own, so an audit record and the line of the same "
                                              "change may be counted as two changes")
                yield [oldest()]
        while (e := oldest()) is not None:
            yield [e]

    def _record_change(self, records: list[TypedEvent]) -> _Change:
        """The change one tool record, or two views of one change, report. The actor is the first record's that names
        one (an audit record before a tool line); the lineage and the exec check use a record with a pid (an audit
        record first, for its serial and boot); the change is timed by its earliest record."""
        records = sorted(records, key=lambda e: (e.ts, e.id))
        named = min(records, key=lambda r: (_record_actor(r) is None, not r.has("audit.record_type"), r.ts, r.id))
        anchor = min(records, key=lambda r: (not isinstance(r.get("process.pid"), int),
                                             not r.has("audit.record_type"), r.ts, r.id))
        ts = records[0].ts.timestamp()
        at = anchor.ts.timestamp()
        pid = anchor.get("process.pid")
        lineage = self.lineage.classify_pid(anchor.host, pid, at, boot_of(anchor), anchor.get("audit.serial"))
        exec_seen = (isinstance(pid, int)
                     and self.lineage.parent(anchor.host, pid, at, boot_of(anchor),
                                             anchor.get("audit.serial")) is not None)
        ordered = sorted(records, key=lambda r: (not r.has("audit.record_type"), r.ts, r.id))
        name = next((r.get("account.name") for r in ordered if r.get("account.name") not in (None, "")), None)
        group = next((r.get("account.group") for r in ordered if r.get("account.group") not in (None, "")), None)
        action = str(ordered[0].get("account.action"))
        return _Change(anchor.host, ts, action, (str(name),) if name else (), (str(group),) if group else (),
                       _RECORD_PHRASE.get(action, "an account change"),
                       next((p for p in map(_record_privilege, ordered) if p), ""), lineage,
                       _record_actor(named) or "an unrecorded account", records=records,
                       login=next((login for login in map(_login, ordered) if login), None), exec_seen=exec_seen)

    def _bursts(self, timeline: SpillList, groups: KeyedStore, runs: SpillList) -> None:
        """Run items. The timeline is read by host then time; a host's changes each less than BURST_GAP after the
        previous one are one run, held whole on a spilling list and read again when it ends (`_close_run`). Each
        finished run item goes to `runs` with its shape, ordered by shape then start, for the fleet merge."""
        pending = SpillList(self, "acct_pending", self.HOT, disk_budget=UNBUDGETED)
        host, last = None, 0.0
        for i, change in enumerate(timeline.ordered()):
            if len(pending) and (change.host != host or change.ts - last >= self.BURST_GAP):
                self._close_run(pending, groups, runs)
                pending.clear()
            if not len(pending):
                host, last = change.host, change.ts
            last = max(last, change.ts)
            need(pending.append(change, _timeline_order(change)), self, "the account change run")
            if i % self.FINALIZE_TRIM == self.FINALIZE_TRIM - 1:
                pending.trim()
                groups.trim()
        if len(pending):
            self._close_run(pending, groups, runs)
        pending.clear()

    def _segments(self, pending: SpillList, folding: set):
        """Each change of a folding class with its segment number: a segment ends when the next change is BURST_SPAN
        or more after the segment's first, or would be its NAMED + 1st distinct change. Read in the run's order, so
        the cut is the same however the run was held."""
        state: dict[tuple, list] = {}                   # class -> [segment number, first time, distinct texts]
        for change in pending.ordered():
            cls = _change_class(change)
            if cls not in folding:
                yield change, cls, 0
                continue
            seg = state.get(cls)
            text = _change_text(change)
            if seg is None:
                seg = state[cls] = [1, change.ts, set()]
            elif change.ts - seg[1] >= self.BURST_SPAN or (text not in seg[2] and len(seg[2]) >= self.NAMED):
                seg[0], seg[1], seg[2] = seg[0] + 1, change.ts, set()
            seg[2].add(text)
            yield change, cls, seg[0]

    def _close_run(self, pending: SpillList, groups: KeyedStore, runs: SpillList) -> None:
        """A finished run of one host. Its changes are split by evidence class (`_change_class`): a class naming at
        least BURST_TARGETS distinct account or group names is folded into run items, in segments of at most
        BURST_SPAN and NAMED distinct changes; every other change (an outlier class, or more than RUN_CLASSES classes)
        keeps its per-actor finding."""
        names: dict[tuple, set] = {}
        overflow = False
        for change in pending.ordered():
            cls = _change_class(change)
            if cls not in names:
                if len(names) >= self.RUN_CLASSES:
                    overflow = True
                    continue
                names[cls] = set()
            if len(names[cls]) < self.BURST_TARGETS:
                names[cls].update((change.accounts + change.groups)[:self.BURST_TARGETS])
        if overflow:
            self.note_limit("run_classes", f"a run of account changes held more than {self.RUN_CLASSES} evidence "
                                           "classes; changes of the further classes keep their own per-actor "
                                           "findings, not folded")
        folding = {cls for cls, held in names.items() if len(held) >= self.BURST_TARGETS}
        # the whole run's counts and segment count per folding class
        totals: dict[tuple, list] = {cls: [0, Counter(), 0] for cls in folding}   # changes, kinds, segments
        for change, cls, segment in self._segments(pending, folding):
            if segment:
                total = totals[cls]
                total[0] += 1
                total[1][(_change_status(change), _change_kind(change))] += 1
                total[2] = segment
        open_runs: dict[tuple, _Burst] = {}
        for i, (change, cls, segment) in enumerate(self._segments(pending, folding)):
            if not segment:
                need(groups.setdefault(self._group(change), list), self, "the account change grouping").append(change)
            else:
                run = open_runs.get(cls)
                if run is not None and run.segment != segment:
                    self._finish_run(run, runs)
                    run = None
                if run is None:
                    ident = change.command.id if change.command is not None else change.records[0].id
                    changes, kinds, segments = totals[cls]
                    run = open_runs[cls] = _Burst(change.host, cls, change.ts, change.ts, ident, segment, segments,
                                                  changes, kinds)
                run.last = max(run.last, change.ts)
                self._burst_add(run, change)
            if i % self.FINALIZE_TRIM == self.FINALIZE_TRIM - 1:
                groups.trim()
        for cls in sorted(open_runs, key=str):
            self._finish_run(open_runs[cls], runs)

    def _finish_run(self, run: _Burst, runs: SpillList) -> None:
        key = f"burst|{run.host}|{run.first_id}|{run.segment}"
        made: list[Match] = []
        with citation_group(self, made, key, run):
            made.append(self._burst_finding(run))
        for match in made:
            shape = self._run_shape(run, match)
            need(runs.append(shape, (shape.key, f"{shape.first:020.6f}|{shape.host or ''}|{shape.anchor_id}")),
                 self, "the account change runs")

    def _run_shape(self, run: _Burst, match: Match) -> _RunShape:
        """A finished run segment item and its shape: its distinct changes, its evidence class, its exec lineage
        kinds and which segment of how many it is. It is merged across hosts only when it was cited."""
        reason = "" if match.events and not match.citation_unavailable else "its records could not be cited"
        signatures = frozenset(run.signatures)
        lineages = tuple(sorted(run.lineages))
        segment = (run.segment, run.segments)
        key = "" if reason else hashlib.sha256(json.dumps(
            [sorted(signatures), list(run.cls), lineages, list(segment)]).encode()).hexdigest()[:32]
        own = [e for e in match.events if e.id not in match.context_ids]
        anchor = (own or match.events)[0].id if match.events else run.first_id
        return _RunShape(key, reason, run.host, run.first, run.last, match.proposed_lane, anchor, signatures,
                         run.cls, lineages, segment, run.changes, match)

    def _fleets(self, runs: SpillList) -> list[Match]:
        """Run items of one shape on at least FLEET_MIN_HOSTS hosts, starting within FLEET_WINDOW of the first, are
        one fleet item at the lane of its strongest run; every other run item is published as it is. Runs are read
        by shape then start, so one cluster is open at a time. Runs that were not merged are then compared with the
        fleets near them in time: one sharing at least FLEET_SIMILAR of a fleet's changes is named in that fleet's
        item as excluded, with how it differs (it keeps its own item)."""
        out: list[Match] = []
        if getattr(self, "_fleet_members", None) is not None:
            self._fleet_members.clear()
        members = self._fleet_members = KeyedStore(self, "acct_fleet_members", self.HOT, disk_budget=UNBUDGETED)
        seen = KeyedStore(self, "acct_fleet_seen", self.HOT, disk_budget=UNBUDGETED)
        anchors = self._fleet_anchors = KeyedStore(self, "acct_fleet_anchors", self.HOT, disk_budget=UNBUDGETED)
        fleets = KeyedStore(self, "acct_fleets", self.HOT, disk_budget=UNBUDGETED)
        windows = SpillList(self, "acct_fleet_windows", self.HOT, disk_budget=UNBUDGETED)
        leftovers = SpillList(self, "acct_leftover_runs", self.HOT, disk_budget=UNBUDGETED)
        fleet: _Fleet | None = None
        waiting: list[_RunShape] = []        # a cluster's runs while it has fewer than FLEET_MIN_HOSTS hosts

        def leave(shape: _RunShape) -> None:
            need(leftovers.append(shape, (shape.first, f"{shape.host or ''}|{shape.anchor_id}")), self,
                 "the account change runs not merged")

        def add(shape: _RunShape) -> None:
            fleet.runs += 1
            fleet.last = max(fleet.last, shape.last)
            fleet.changes_min = min(fleet.changes_min or shape.changes, shape.changes)
            fleet.changes_max = max(fleet.changes_max, shape.changes)
            if shape.lane == "high":
                fleet.lane = "high"
            if seen.peek((fleet.fid, shape.host)) is not None:
                return                                        # a repeat on a host already counted
            need(seen.put((fleet.fid, shape.host), 1), self, "the fleet host index")
            fleet.hosts += 1
            if not fleet.chunks or fleet.chunk_fill >= self.FLEET_CHUNK:
                fleet.chunks, fleet.chunk_fill = fleet.chunks + 1, 0
            chunk = need(members.setdefault((fleet.fid, fleet.chunks - 1), list), self, "the fleet host list")
            chunk.append((shape.host, shape.anchor_id))
            fleet.chunk_fill += 1
            if fleet.hosts <= self.FLEET_HOST_CITE:
                anchor = next(e for e in shape.match.events if e.id == shape.anchor_id)
                need(anchors.put((fleet.fid, fleet.hosts - 1), anchor), self, "the fleet hosts' records")
            if len(fleet.sample_hosts) < self.FLEET_HOSTS_NAMED:
                fleet.sample_hosts.append(shape.host)
            if len(fleet.exemplars) < self.FLEET_CITE_RUNS:
                fleet.exemplars.append(shape)

        def close() -> None:
            nonlocal fleet, waiting
            if fleet is not None:
                need(fleets.put(fleet.fid, fleet), self, "the fleets")
                need(windows.append(fleet.fid, (fleet.first - self.FLEET_NEAR, fleet.fid)), self, "the fleets")
            for shape in waiting:
                leave(shape)
            fleet, waiting = None, []

        key, start = None, 0.0
        for i, shape in enumerate(runs.ordered()):
            if not shape.key:
                leave(shape)
                continue
            if shape.key != key or shape.first - start >= self.FLEET_WINDOW:
                close()
                key, start = shape.key, shape.first
            if fleet is not None:
                add(shape)
            else:
                waiting.append(shape)
                if len({s.host for s in waiting}) >= self.FLEET_MIN_HOSTS:
                    first = waiting[0]
                    fleet = _Fleet(f"{first.key}|{first.anchor_id}", first.key, first.first, first.last, first,
                                   lane=first.lane)
                    for held in waiting:
                        add(held)
                    waiting = []
            if i % self.FINALIZE_TRIM == self.FINALIZE_TRIM - 1:
                for store in (members, seen, fleets, windows, leftovers):
                    store.trim()
        close()
        seen.clear()
        # compare the runs that were not merged with the fleets whose span, widened by FLEET_NEAR, holds their start
        order = iter(windows.ordered())
        upcoming = next(order, None)
        active: list[tuple[str, float]] = []           # (fleet id, end of its widened span)
        for i, shape in enumerate(leftovers.ordered()):
            while upcoming is not None and fleets.peek(upcoming).first - self.FLEET_NEAR <= shape.first:
                found = fleets.peek(upcoming)
                active.append((upcoming, found.last + self.FLEET_NEAR))
                if len(active) > self.FLEET_ACTIVE:
                    active.pop(0)
                    self.note_limit("fleet_active", f"more than {self.FLEET_ACTIVE} fleets of account change runs "
                                                    "overlapped in time; runs that were not merged were compared "
                                                    "with the latest of them only, so a fleet item may not name every "
                                                    "similar run it excluded")
                upcoming = next(order, None)
            active = [(fid, end) for fid, end in active if end >= shape.first]
            for fid, _end in active:
                found = fleets.peek(fid)
                reason = self._excluded(found, shape)
                if reason:
                    found.excluded_count += 1
                    if len(found.excluded) < self.FLEET_EXCLUDED_NAMED:
                        found.excluded.append((shape.host, reason))
                    need(fleets.put(fid, found), self, "the fleets")
            out.append(shape.match)
            if i % self.FINALIZE_TRIM == self.FINALIZE_TRIM - 1:
                fleets.trim()
        for fid in sorted(fleets.keys(), key=str):
            found = fleets.peek(fid)
            with citation_group(self, out, f"burst-fleet|{fid}", found):
                out.append(self._fleet_finding(found))
        fleets.clear()
        windows.clear()
        leftovers.clear()
        anchors.clear()
        return out

    def _excluded(self, fleet: _Fleet, shape: _RunShape) -> str:
        """How a run that was not merged differs from a fleet it resembles ('' when it does not resemble it)."""
        template = fleet.template
        if not template.signatures or len(shape.signatures & template.signatures) < (
                self.FLEET_SIMILAR * len(template.signatures)):
            return ""
        parts = []
        if shape.unmergeable:
            parts.append(f"not compared whole: {shape.unmergeable}")
        extra = sorted(shape.signatures - template.signatures)
        missing = len(template.signatures - shape.signatures)
        if extra:
            parts.append(f"{len(extra)} change(s) the fleet's runs do not make: "
                         + "; ".join(map(_signature_text, extra[:3])) + ("; and more" if len(extra) > 3 else ""))
        if missing:
            parts.append(f"{missing} of the fleet's changes not made")
        if shape.cls != template.cls:
            parts.append(f"{_class_text(shape.cls)} rather than {_class_text(template.cls).removeprefix('made as ')}")
        if shape.segment != template.segment:
            parts.append(f"segment {shape.segment[0]} of {shape.segment[1]} rather than {template.segment[0]} of "
                         f"{template.segment[1]}")
        if shape.lineages != template.lineages:
            parts.append("under another exec lineage")
        if not fleet.first <= shape.first < fleet.first + self.FLEET_WINDOW:
            parts.append(f"started at {_iso(shape.first)}, outside the fleet window")
        return "; ".join(parts)

    def _fleet_finding(self, fleet: _Fleet) -> Match:
        template = fleet.template
        signatures = sorted(template.signatures)
        kind_text = _status_counts(Counter((sig[4], sig[0]) for sig in signatures))
        span = (f"{fleet.changes_min} change(s) per host" if fleet.changes_min == fleet.changes_max
                else f"{fleet.changes_min} to {fleet.changes_max} change(s) per host (repeats of the same changes)")
        claim = (f"On {fleet.hosts} hosts, the same run of account and group changes was recorded from "
                 f"{_iso(fleet.first)} to {_iso(fleet.last)}: each host's run requested or reported the same "
                 f"{len(signatures)} distinct change(s) ({kind_text}; {span}), {_class_text(template.cls)}"
                 + (f", as segment {template.segment[0]} of {template.segment[1]} of each host's run"
                    if template.segment[1] > 1 else "")
                 + f". This item groups hosts whose runs match in shape and started less than "
                   f"{self.FLEET_WINDOW / 3600:.0f} hours after the first; it does not show that the runs share an "
                   "origin.")
        if fleet.runs > fleet.hosts:
            claim += f" {fleet.runs} runs in all ({fleet.runs - fleet.hosts} more on hosts already counted)."
        privileged = [_signature_text(sig) for sig in signatures if sig[3]]
        if privileged:
            claim += (f" On every host the run requests or reports privileged access: {'; '.join(privileged[:8])}"
                      + (f"; and {len(privileged) - 8} more (each is in the notes)" if len(privileged) > 8 else "")
                      + ".")
        more = fleet.hosts - len(fleet.sample_hosts)
        claim += (f" Hosts: {', '.join(str(h) for h in fleet.sample_hosts)}"
                  + (f" and {more} more (all {fleet.hosts} are in the paged host list)" if more else "") + ".")
        if fleet.excluded_count:
            shown = "; ".join(f"{host} ({reason})" for host, reason in fleet.excluded[:4])
            rest = fleet.excluded_count - min(4, len(fleet.excluded))
            claim += (f" {fleet.excluded_count} similar host run(s) differ from this shape and keep their own items: "
                      f"{shown}" + (f"; and {rest} more" + (" (named in the notes)" if fleet.excluded_count
                                                             <= self.FLEET_EXCLUDED_NAMED else
                                                             f" (the first {self.FLEET_EXCLUDED_NAMED} are named in "
                                                             "the notes)") if rest else "") + ".")
        claim += (" A provisioning run rolled out across a fleet looks like this; so does one intruder making the same "
                  "changes on many hosts, so the item keeps the lane of its strongest run.")
        # exemplar records from several hosts' runs: the privileged changes' records first
        # (each cited host's host-list record, its run's first cited record, among them)
        per_run = max(1, self.FLEET_CITE // max(1, len(fleet.exemplars)))
        events: list[TypedEvent] = []
        for shape in fleet.exemplars:
            own = [e for e in shape.match.events if e.id not in shape.match.context_ids]
            own.sort(key=lambda e: (e.id != shape.anchor_id, not _record_privilege(e), e.ts, e.id))
            events += own[:per_run]
        exemplar_ids = {e.id for e in events}
        # each listed host's own record (the one its host-list entry names), up to FLEET_HOST_CITE hosts
        listed = [self._fleet_anchors.peek((fleet.fid, index)) for index in range(min(fleet.hosts,
                                                                                         self.FLEET_HOST_CITE))]
        missing = sum(anchor is None for anchor in listed)
        events = sorted(_unique([*events, *(anchor for anchor in listed if anchor is not None)]),
                        key=lambda e: (e.ts, e.id))
        claim += (f" Records of the runs on {len(fleet.exemplars)} of the {fleet.hosts} hosts are cited, and so is "
                  "the record each listed host's entry names")
        rest = fleet.hosts - len(listed) + missing
        if rest:
            claim += (f", except for {rest} host(s) whose entries name a record that is not stored with this item "
                      f"(at most {self.FLEET_HOST_CITE} hosts' records are)")
            self.note_limit("fleet_host_records", f"a fleet of account change runs listed more than "
                                                  f"{self.FLEET_HOST_CITE} hosts; the further hosts' list entries name a "
                                                  "record not stored with the item")
        claim += "."
        notes = sorted({n for n in template.match.notes if n.startswith("T")})
        notes += [f"fleet change: {_signature_text(sig)}" for sig in signatures]      # at most NAMED (a segment's)
        notes += [f"excluded: {host} ({reason})" for host, reason in fleet.excluded]
        if fleet.excluded_count > len(fleet.excluded):
            notes.append(f"{fleet.excluded_count - len(fleet.excluded)} further excluded run(s) are counted, not named")
        entities = list(template.match.entities)
        predicate = [pf(e, n) for e in sorted(events, key=lambda e: (not _record_privilege(e), e.ts, e.id))[:4]
                     for n in ("process.argv", "process.executable", "audit.record_type", "account.action",
                               "account.name", "account.group") if e.has(n)]
        match = Match(self.id, claim, self.claim_type, events, predicate,
                      min(e.ts for e in events), self.severity, fleet.lane, template.match.confidence, entities,
                      group_key=f"burst-fleet|{fleet.fid}", fleet_hosts=self._fleet_hosts(fleet.fid, fleet.chunks),
                      fleet_host_count=fleet.hosts, fleet_hosts_complete=True)
        match.notes = notes
        match.context_ids = {e.id for e in events} - exemplar_ids       # the hosts' records support the host list
        return match

    def _fleet_hosts(self, fid: str, chunks: int):
        """A fleet item's hosts with each host's first cited record, read from the rule's member store when the
        finding is published."""
        store = self._fleet_members
        for index in range(chunks):
            chunk = store.peek((fid, index))
            if chunk is None:
                self.note_limit("fleet_hosts", f"the host list of fleet {fid} could not be fully read")
                raise LookupError(f"the host list of fleet {fid} could not be fully read")
            yield from chunk

    def _burst_add(self, run: _Burst, change: _Change) -> None:
        """Count one change into a run segment: exact counts, every distinct change named (the segment holds at most
        NAMED of them), one entity per account name, and an exemplar and a citation while their caps allow (privileged
        changes have their own, so other changes never crowd them out)."""
        run.changes += 1
        status = _change_status(change)
        run.kinds[(status, _change_kind(change))] += 1
        for name in change.accounts + change.groups:
            if name in run.targets:
                continue
            if len(run.targets) < self.BURST_TARGET_NAMES:
                run.targets.add(name)
            else:
                run.targets_more = True
        for name in change.accounts:
            if name not in run.accounts:
                if len(run.accounts) < self.BURST_TARGET_NAMES:
                    run.accounts.add(name)
                else:
                    run.accounts_more += 1
        run.commands += change.command is not None
        run.records += len(change.records)
        run.unexplained += change.command is None and not change.exec_seen
        signature = (_change_kind(change), tuple(sorted(change.accounts)), tuple(sorted(change.groups)),
                     tuple(_change_privilege(change)), status)
        run.signatures.add(signature)                   # at most NAMED distinct per segment
        run.lineages.add(change.lineage.kind)
        run.techniques.add(_ACTION_TECHNIQUE.get(change.action, "T1098"))
        run.mentions.update(m for m in map(_record_mention, change.records[:4]) if m)
        lane = _change_lane(change)
        if lane == "high":
            run.high += 1
        if run.lineage is None or (lane == "high" and not run.lineage_high):
            run.lineage, run.lineage_high = change.lineage, lane == "high"
        # an exemplar keeps the change's command and its first records only (a bulk tool's change can hold thousands)
        exemplar = replace(change, records=change.records[:3])
        text = _change_text(change)
        privileges = _change_privilege(change)
        if privileges:
            run.privileged_count += 1
            text = f"{text}: {'; '.join(privileges)}" + {
                "reported": "", "requested": " (requested only; not shown to have taken effect)",
                "failed": " (every recorded result failed)"}[status]
            run.privileged[text] = run.privileged.get(text, 0) + 1
            if len(run.cited_privileged) < self.BURST_CITE - 1:
                run.cited_privileged.append(exemplar)
            return
        run.named[text] = run.named.get(text, 0) + 1
        if len(run.cited_other) < self.BURST_CITE:
            run.cited_other.append(exemplar)

    def _burst_finding(self, run: _Burst) -> Match:
        host = run.host
        count = f"more than {len(run.targets)}" if run.targets_more else str(len(run.targets))
        claim = (f"On {host}, {run.changes} account or group change(s) were requested or reported close together in "
                 f"time from {_iso(run.first)} to {_iso(run.last)}, each less than {self.BURST_GAP / 60:.0f} minutes "
                 f"after the one before (a run: grouped by time and by evidence: every change in it was "
                 f"{_class_text(run.cls)}), naming {count} distinct account and group name(s): "
                 f"{_status_counts(run.kinds)}.")
        if run.segments > 1:
            claim += (f" This is segment {run.segment} of {run.segments} of the run (a segment covers less than "
                      f"{self.BURST_SPAN / 3600:.0f} hour and at most {self.NAMED} distinct changes); the whole run "
                      f"holds {run.run_changes} change(s): {_status_counts(run.run_kinds)}.")
        if run.privileged_count:
            shown = [text + (f" (x{n})" if n > 1 else "") for text, n in list(run.privileged.items())[:8]]
            rest = len(run.privileged) - len(shown)
            claim += (f" {run.privileged_count} of them request or report privileged access: {'; '.join(shown)}"
                      + (f"; and {rest} more distinct (each is named in the notes)" if rest else "") + ".")
        backed = run.changes - run.commands
        claim += (f" {run.commands} of the changes rest on an exec record of the account tool or command and {backed} "
                  f"on the tools' own records only ({run.records} account-management record(s) in all)")
        claim += (f"; no exec record of the changing process was retrieved for {run.unexplained} of them, so what "
                  "started those is unknown." if run.unexplained else ".")
        claim += (" Changes on this host made by another account, recorded by other evidence, under another audit "
                  "login or with a different exec-record status are not in this item; they keep their own findings.")
        claim += (" Configuration management, an image build, a first-boot agent or an administrator's script "
                  "creating accounts and adding the administrator to its groups looks like this; so does an intruder "
                  "creating an account and granting it a privileged group inside such a run, so the item takes the "
                  "lane of its strongest change and names and cites the privileged changes first.")
        if run.mentions:
            claim += (f" A record {'; '.join(sorted(run.mentions)[:4])}, but its operation does not show a membership "
                      "being granted.")
        phrase, lineage_events, lineage_raw = self.lineage.cited_phrase(run.lineage)
        if phrase:
            claim += f" Exec lineage of the first {'privileged ' if run.lineage_high else ''}change: {phrase}."
        lane = "high" if run.high else "lead"
        # the privileged changes first (at most BURST_CITE - 1); one slot is kept for the earliest other change, which
        # times the run
        cited_privileged = run.cited_privileged
        cited = cited_privileged + run.cited_other[:self.BURST_CITE - len(cited_privileged)]
        if lane == "high":
            claim += writer_sentence([r for c in cited_privileged for r in c.records if not r.has("audit.record_type")],
                                     lambda r: str(r.get("log.identifier") or r.get("journal.identifier")
                                                   or "the account tool"))
        events: list[TypedEvent] = []
        for c in cited:
            if c.command is not None:
                events.append(c.command)
            events += c.records if (_change_privilege(c) or c.command is None) else c.records[:1]
        events = sorted(_unique(events), key=lambda e: (e.ts, e.id))
        notes = sorted(run.techniques)
        if run.changes > len(cited):
            claim += (f" The records of {len(cited)} of the {run.changes} changes are cited: the privileged ones "
                      "first, then the earliest; every change is named in the notes.")
        if run.privileged_count > len(cited_privileged):
            claim += (f" {run.privileged_count - len(cited_privileged)} privileged change(s) are named but not cited "
                      f"(at most {self.BURST_CITE - 1} are).")
            self.note_limit("burst_privileged_cited", f"a run segment of account changes held more than "
                                                      f"{self.BURST_CITE - 1} privileged changes; the rest are named "
                                                      "and counted in its item, not cited")
        notes += [f"privileged change: {text}" + (f" (x{n})" if n > 1 else "") for text, n in run.privileged.items()]
        notes += [f"change: {text}" + (f" (x{n})" if n > 1 else "") for text, n in run.named.items()]
        if run.targets_more:
            notes.append(f"more than {self.BURST_TARGET_NAMES} distinct account and group names: the count is a "
                         "lower bound")
        alone = self._alone_hosts.get(host, 0)
        if alone:
            notes.append(f"{alone} account change(s) on this host were published as findings of their own when the "
                         "change budget was spent; they are not counted in this item")
        elif self._alone_other:
            notes.append(f"{self._alone_other} account change(s) on hosts beyond the first {self.ALONE_HOSTS} counted "
                         "by host were published as findings of their own when the change budget was spent; any on "
                         "this host are not counted in this item")
        # the predicate is read from the privileged changes' records first
        first = _unique([e for c in cited_privileged for e in (c.command, *c.records) if e is not None] + events)
        predicate = [pf(e, n) for e in first[:4]
                     for n in ("process.argv", "process.executable", "audit.record_type", "account.action",
                               "account.name", "account.group") if e.has(n)]
        # one entity per account name the segment changes (the intruder's account among them, as a pivot)
        entities = list(events[0].entities())
        entities += [("account", f"{host}\\{a}", "subject") for a in sorted(run.accounts)]
        if run.accounts_more:
            notes.append(f"{run.accounts_more} further account name(s) are named in the changes but not listed as "
                         f"entities (the first {self.BURST_TARGET_NAMES} are)")
            self.note_limit("burst_entities", f"a run segment named more than {self.BURST_TARGET_NAMES} accounts; "
                                              "the rest are named in its notes, not listed as entities")
        when = events[0].ts
        cited_ids = {e.id for e in events}
        events = sorted(_unique([*events, *lineage_events]), key=lambda e: (e.ts, e.id))
        match = Match(self.id, claim, self.claim_type, events, predicate, when, self.severity, lane,
                      "high" if run.records else "medium", list(dict.fromkeys(entities)),
                      group_key=f"burst|{host}|{run.first_id}")
        match.notes = notes
        match.raw_copies.update(lineage_raw)
        match.context_ids = {e.id for e in lineage_events} - cited_ids
        return match

    def _group(self, change: _Change) -> tuple:
        privileged = change.privileged or any(_record_privilege(r) for r in change.records)
        no_login = change.login is None and not any(_login(r) for r in change.records)
        # only a tool's own record whose process left no exec record: nothing shows what started it
        record_only = change.command is None and not change.exec_seen
        marker = self._boot(change) if not privileged and record_only and no_login else None
        if change.lineage.kind in {"package", "cloud-init"} and not privileged:
            return ("lineage", change.host, change.lineage.kind)
        if marker is not None:
            self._boot_events[marker.id] = marker
            return ("boot", change.host, marker.id)
        return ("actor", change.host, change.actor, change.action, change.accounts, change.groups,
                change.command is None)


    def _finding(self, key: tuple, items: list[_Change]) -> Match:
        items = sorted(items, key=lambda c: (c.ts, c.command.id if c.command else c.records[0].id))
        host = key[1]
        commands = _unique(c.command for c in items)
        records = _unique(r for c in items for r in c.records)
        first = items[0]
        privileged = sorted({c.privileged for c in items if c.privileged}
                            | {p for c in items for p in map(_record_privilege, c.records) if p})
        web = next((c.lineage for c in items if c.lineage.kind == "web"), None)
        marker = self._boot_events.get(key[2]) if key[0] == "boot" else None
        unexplained = [c for c in items if c.command is None and not c.exec_seen]
        if marker is not None:
            boot_ts = marker.ts.timestamp()
            details = [c.detail + (f" (account '{c.accounts[0]}')" if c.command is None and c.accounts else "")
                       + (f" (group '{c.groups[0]}')" if c.command is None and c.groups else "") for c in items]
            details = list(dict.fromkeys(details))
            claim = (f"On {host}, {len(items)} account or group change(s) were made "
                     f"{_offsets([c.ts - boot_ts for c in items])} the host's recorded boot at "
                     f"{marker.ts.isoformat()} (audit SYSTEM_BOOT), with no audit login uid recorded on any of them: "
                     f"{'; '.join(details[:6])}"
                     + (f"; and {len(details) - 6} more (every change is in the notes)" if len(details) > 6 else "")
                     + ".")
            writers = sorted({str(r.get("process.executable") or "an unrecorded program") for r in records})
            claim += (f" The record(s) were written by {', '.join(repr(w) for w in writers)} as "
                      f"{', '.join(sorted({c.actor for c in items}))}.")
        elif key[0] == "lineage":
            what = "package management" if key[2] == "package" else "cloud-init"
            claim = (f"On {host}, {len(items)} account or group change request(s) were made under {what}: "
                     f"{'; '.join(dict.fromkeys(c.detail for c in items[:6]))}"
                     + (f"; and {len(items) - 6} more" if len(items) > 6 else "") + ".")
        elif commands:
            login = commands[0].get("process.login_user")
            claim = (f"On {host}, account '{first.actor}'"
                     + (f" (audit login user '{login}')" if login and login != first.actor else "")
                     + f" ran {len(commands)} command(s) to {first.detail} (e.g. "
                     f"{_argv_summary(commands[0].get('process.argv'), 120)}); {_outcome_tally(commands)}.")
        else:
            exe = next((r.get("process.executable") for r in records if r.get("process.executable")), None)
            noun = ("account-management audit record(s)" if all(r.has("audit.record_type") for r in records)
                    else "account-management record(s) (audit records or the tool's own log lines)")
            claim = (f"On {host}, {len(records)} {noun} report that "
                     f"{first.detail}" + (f" (account '{first.accounts[0]}')" if first.accounts else "")
                     + (f" (group '{first.groups[0]}')" if first.groups else "")
                     + f", written by '{exe or 'an unrecorded program'}' as {first.actor}.")
        if commands and records:
            claim += (f" {len(records)} account-management record(s) from the same process(es) report the change: "
                      f"{'; '.join(_record_text(r) for r in records[:4])}.")
        elif commands:
            claim += (" No account-management audit record from the same process was retrieved, so whether the "
                      "account database changed is not established.")
        else:
            claim += f" Recorded: {'; '.join(_record_text(r) for r in records[:4])}."
        if unexplained and marker is None and not commands:
            them = "it" if len(records) == 1 else "them"
            claim += (" No exec record of the changing process was retrieved, so what started it is unknown"
                      + (f", and no audit login uid is recorded on {them}." if not any(_login(r) for r in records)
                         else "."))
        elif unexplained:
            claim += (" No exec record of the changing process was retrieved for "
                      + ("any of them, so what started them is unknown." if len(unexplained) == len(items)
                         else f"{len(unexplained)} of them."))
        if marker is not None:
            claim += (" Boot-time provisioning (cloud-init or a first-boot script setting initial passwords or "
                      "creating accounts) looks like this; so does a job an intruder set to run at boot.")
        if privileged:
            claim += f" It requests or reports {'; '.join(privileged)}."
        mentions = sorted({m for c in items for m in map(_record_mention, c.records) if m})
        if mentions:
            claim += (f" The record {'; '.join(mentions)}, but its operation does not show a membership being "
                      "granted.")
        lineage = web or first.lineage
        phrase, lineage_events, lineage_raw = self.lineage.cited_phrase(lineage)
        if phrase:
            claim += f" Exec lineage: {phrase}."
        if web is not None or privileged:
            lane = "high"
        else:
            lane = "lead"
        notes = []
        all_failed = (commands and all(c.outcome == Outcome.failure for c in commands)
                      and not any(r.outcome == Outcome.success for r in records))
        if lane == "high" and (all_failed or (not commands and records and all(r.outcome == Outcome.failure
                                                                               for r in records))):
            lane = "lead"
            notes.append("lane lowered: every recorded exec or tool result failed")
        if lane == "high":
            # a high claim resting on the tools' own log lines says what is known about who wrote them
            claim += writer_sentence([r for r in records if not r.has("audit.record_type")],
                                     lambda r: str(r.get("log.identifier") or r.get("journal.identifier")
                                                   or "the account tool"))
        if marker is not None:
            # one record for every distinct change, so no account in the group goes uncited
            distinct: dict[tuple, TypedEvent] = {}
            for c in items:
                distinct.setdefault((c.action, c.detail, c.accounts, c.groups), c.records[0])
            cited = list(distinct.values())[:self.BOOT_CITE]
            if len(distinct) > self.BOOT_CITE:
                notes.append(f"{len(distinct)} distinct changes; a record is cited for the first {self.BOOT_CITE}")
            notes += [f"change: {d}" for d in details]
            events = sorted(_unique([*cited, marker]), key=lambda e: (e.ts, e.id))
        else:
            events = sorted(_unique([*commands[:10], *records[:10]]), key=lambda e: (e.ts, e.id))
            told = [f"{min(10, n)} of the {n} {noun}" for n, noun in ((len(commands), "commands"),
                                                                     (len(records), "audit records")) if n > 10]
            if told:
                claim += f" The earliest {' and '.join(told)} are cited."
        predicate =[pf(e, n) for e in events[:4] for n in ("process.argv", "process.executable", "audit.record_type",
                                                             "account.action", "account.name", "account.group",
                                                             "system.event")
                     if e.has(n)]
        techniques = {_ACTION_TECHNIQUE.get(c.action, "T1098") for c in items}
        notes += sorted(techniques)
        entities = list(events[0].entities())
        for c in items:
            entities += [("account", f"{c.host}\\{a}", "subject") for a in c.accounts]
        # the change's own records time it and carry its predicate; the exec ancestor the lineage names is cited too
        when = events[0].ts
        events = sorted(_unique([*events, *lineage_events]), key=lambda e: (e.ts, e.id))
        match = Match(self.id, claim, self.claim_type, events, predicate, when, self.severity, lane,
                      "high" if records else "medium", list(dict.fromkeys(entities)),
                      group_key="|".join(str(part) for part in key))
        match.notes = notes
        match.raw_copies.update(lineage_raw)
        match.context_ids = {e.id for e in lineage_events} - {e.id for e in [*commands[:10], *records[:10]]}
        return match


AUTH_PLAYBOOKS = [SshPasswordGuessing, SshPasswordSpraying, SshSuccessAfterFailures, AccountOrGroupChange]
