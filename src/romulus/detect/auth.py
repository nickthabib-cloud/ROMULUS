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
id) or a kernel file-change record shows the change.
"""
from __future__ import annotations

import heapq
import itertools
import re
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import ClassVar, NamedTuple

from romulus.detect.base import Match, Playbook, argv_incomplete, basename, pf
from romulus.detect.bounded import HOT_COUNT, KeyedStore, RecentIds, SpillList, StateExhausted
from romulus.detect.citing import cited_phrase
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
    """The first `limit` items quoted, and how many more of `more_than` (all of `items` by default) there are."""
    items = sorted(items)
    total = len(items) if more_than is None else more_than
    shown = items[:limit]
    text = ", ".join(f"'{item}'" for item in shown) or "none"
    return text + (f" and {total - len(shown)} more" if total > len(shown) else "")


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
            claim += cited_phrase(len(events), t.attempts, True, "attempt records", "attempt record")
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
                     f"{_iso(t.crossed)}. Names in the cited records: {_names(named, more_than=total_names)}. Of "
                     f"all the names, sshd reported {len(t.invalid_names)} of them as invalid users (no such account, "
                     f"or not permitted to log in).")
            claim += (f" The retrieved records hold {ok} accepted sshd login(s) from this source." if ok else
                      " The retrieved records hold no accepted sshd login from this source.")
            claim += " Failures inside connections that then logged in are not counted."
            claim += cited_phrase(len(events), t.attempts, True, "attempt records", "attempt record")
            m = Match(self.id, claim, self.claim_type, events, _ssh_predicate(events[:3]), events[0].ts,
                      self.severity, self.lane, "high", events[0].entities(), group_key=f"{host}|{ip}",
                      context_ids={e.id for e in spanning})
            out.append(m)
        return out


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
        return [self._match(key, self.found.peek(key)) for key in sorted(self.found.keys(), key=str)]

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
    return ""


def _record_mention(e: TypedEvent) -> str:
    group = e.get("account.group")
    if group in PRIVILEGED_GROUPS and not _record_privilege(e):
        return f"names privileged group {group}"
    return ""


def _record_text(e: TypedEvent) -> str:
    parts = [str(e.get("audit.record_type"))]
    for name, label in (("account.op", "op"), ("account.name", "acct"), ("account.group", "grp")):
        if e.has(name):
            parts.append(f"{label}={e.get(name)}")
    result = {Outcome.success: "success", Outcome.failure: "failed"}.get(e.outcome, "unrecorded")
    return " ".join(parts) + f" res={result}"


class AccountOrGroupChange(Playbook):
    state_slice = "strong"           # a strong-indicator rule (see Playbook.state_slice)
    id = "host.account_or_group_change"
    version = "5"
    title = "Account or group created, deleted or modified (command or account-management audit record)"
    anchor_class = "persistence"
    kind = "aggregate"
    families = ("process_exec", "account_change", "system_state")
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
    program_prefilter = True
    card: ClassVar[dict] = {
        "behavior": "an account or group tool was run to create, delete or modify an account, group membership, "
                    "password or expiry; a command or shell text wrote /etc/passwd, /etc/shadow, /etc/group or "
                    "/etc/gshadow directly; or a tool's audit record reports such a change",
        "telemetry": "auditd EXECVE+SYSCALL as process_exec (process.executable, process.argv, process.pid, "
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
                           "login uid; one record is cited per distinct change and every change is in the notes",
        "query_cost": "none beyond the sweep",
        "next_pivot": "the account's first login and what that session ran",
        "adds": "no earlier rule covers account or group changes",
        "research_basis": "ATT&CK Enterprise 20.0 T1136.001, T1098, T1098.007, T1531 (procedure: useradd/usermod); "
                          "shadow-utils and Debian adduser option grammars; libaudit audit_log_acct_message record "
                          "format",
        "lanes": "high for a web-service account in the exec lineage, or a request for user/group id 0 or "
                 "membership of a root-equivalent group; package/cloud-init lineage is one grouped lead per host; "
                 "unprivileged audit records with no exec record of their process and no login uid, from 2 minutes "
                 "before to 15 minutes after a recorded boot, are one grouped lead per (host, boot), worded as "
                 "boot-time provisioning or a boot-time job; "
                 "everything else is a lead",
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
        fresh = [e for e in events if e.family in self.families and e.id not in self._seen]
        self._batch = events
        for e in sorted(fresh, key=lambda x: (x.ts, x.family != "process_exec", x.id)):
            self._seen.add(e.id)
            if e.family == "process_exec":
                self.lineage.observe(e, self.raw_of(e))
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
            self._publish_alone(list(self._record_changes([e])), e)
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
                need(unjoined.append(record), self, "the unjoined tool records")
            if i % self.FINALIZE_TRIM == self.FINALIZE_TRIM - 1:
                self.by_pid.trim()
                unjoined.trim()
        groups = KeyedStore(self, "acct_groups", self.HOT, disk_budget=UNBUDGETED)
        self._boot_events: dict[str, TypedEvent] = {}
        changes = (c for _key, held in self.by_pid.items() for c in held)
        loose = (c for held in self.loose for c in held)
        for i, change in enumerate(itertools.chain(changes, loose, self._record_changes(unjoined))):
            need(groups.setdefault(self._group(change), list), self, "the account change grouping").append(change)
            if i % self.FINALIZE_TRIM == self.FINALIZE_TRIM - 1:
                groups.trim()
        out = [self._finding(key, groups.peek(key)) for key in sorted(groups.keys(), key=str)]
        groups.clear()
        unjoined.clear()
        return out

    def finalize_fallback(self, reason: str) -> list[Match]:
        """Every held change on its own (grouping and joining needed disk): command changes by process, changes
        without a pid, then each tool record as the change it reports."""
        self._boot_events = {}
        out: list[Match] = []

        def each(changes) -> None:
            for change in changes:
                m = self._finding(self._group(change), [change])
                m.group_key += f"|alone:{(change.command or change.records[0]).id}"
                m.notes.append(f"published on its own: grouping and joining needed disk ({reason})")
                out.append(m)
        for source in (lambda: (c for _key, held in self.by_pid.items() for c in held),
                       lambda: (c for held in self.loose for c in held),
                       lambda: self._record_changes(self.records)):
            try:
                each(source())
            except StateExhausted:
                continue                            # a table on disk cannot be read: what was read stands
        return out

    def _record_changes(self, unjoined):
        """A change for each tool record no command of its process explains."""
        for record in unjoined:
            ts = record.ts.timestamp()
            lineage = self.lineage.classify_pid(record.host, record.get("process.pid"), ts, boot_of(record),
                                                record.get("audit.serial"))
            actor = str(record.get("process.login_user") or record.get("process.user")
                        or (f"audit login uid {record.get('process.auid')}" if record.has("process.auid")
                            else "an unrecorded account"))
            name = record.get("account.name")
            group = record.get("account.group")
            pid = record.get("process.pid")
            exec_seen = (isinstance(pid, int)
                         and self.lineage.parent(record.host, pid, ts, boot_of(record),
                                                             record.get("audit.serial")) is not None)
            yield _Change(record.host, ts, str(record.get("account.action")),
                          (str(name),) if name else (), (str(group),) if group else (),
                          _RECORD_PHRASE.get(str(record.get("account.action")), "an account change"),
                          _record_privilege(record), lineage, actor, records=[record],
                          login=_login(record), exec_seen=exec_seen)

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
            exe = records[0].get("process.executable")
            claim = (f"On {host}, {len(records)} account-management audit record(s) report that "
                     f"{first.detail}" + (f" (account '{first.accounts[0]}')" if first.accounts else "")
                     + (f" (group '{first.groups[0]}')" if first.groups else "")
                     + f", written by '{exe or 'an unrecorded program'}' as {first.actor}.")
        if commands and records:
            claim += (f" {len(records)} audit record(s) from the same process(es) report the change: "
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
