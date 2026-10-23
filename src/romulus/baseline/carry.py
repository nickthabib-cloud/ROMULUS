"""Disk-backed process-parent carry-in and explicit Pending resolution."""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from romulus.baseline.spec import (
    SPEC_BY_ID,
    BaselineKey,
    BaselineSpec,
    Pending,
    exec_pair_key,
    exec_serial,
    parent_at,
)
from romulus.detect.correlation import boot_of, boots_conflict
from romulus.evidence.typed import Outcome, TypedEvent
from romulus.store.repo import Repo

# Ten thousand hot hosts avoid a read per exec in large sites; overflow remains correct through indexed disk
# lookups, so memory never grows with the total number of hosts.
MARKER_CACHE_CAP = 10_000


@dataclass(frozen=True)
class ParentExec:
    host: str
    boot: str | None
    pid: int
    ts: datetime
    executable: str
    parent_pid: int | None
    raw_id: str
    # The kernel's audit serial, which increases within a boot: it orders execs of one instant (a shebang's
    # env, then its interpreter, on the same pid). None when the record carries none.
    serial: int | None = None


def _same_instant(a_serial: int | None, b_serial: int | None) -> bool:
    """Two execs of one pid at one timestamp are only ordered when both carry distinct serials."""
    return a_serial is None or b_serial is None or a_serial == b_serial


def _latest_image(tied: list[tuple]):
    """One instant's generations (ts, serial, image, ...): the latest by serial, or None when unordered.

    Distinct known serials order them. Without that (any serial missing, or repeated), they are one exec only
    when every image matches; otherwise the image after that instant is unknown, whatever the input order.
    """
    serials = [entry[1] for entry in tied]
    if None not in serials and len(set(serials)) == len(serials):
        return max(tied, key=lambda entry: entry[1])
    return tied[0] if len({entry[2] for entry in tied}) == 1 else None


def place_child(generations: list[tuple], ts: float, serial: int | None):
    """The generation that is a pid's image when a child is exec'd at (ts, serial), or None when unknown.

    `generations` are (ts, serial, image, ...) tuples, image None when unknown. A generation at the child's
    exact instant precedes the child only when both serials are known and its serial is lower; with either
    serial missing the order is unknown, and the answer is None unless every such generation has the image the
    child would otherwise get.
    """
    before, unsure = [], []
    for entry in generations:
        if entry[0] < ts or (entry[0] == ts and entry[1] is not None and serial is not None
                             and entry[1] < serial):
            before.append(entry)
        elif entry[0] == ts and (entry[1] is None or serial is None):
            unsure.append(entry)
    answer = None
    if before:
        latest = max(entry[0] for entry in before)
        answer = _latest_image([entry for entry in before if entry[0] == latest])
        if answer is None:
            return None
    if unsure and (answer is None or any(entry[2] != answer[2] for entry in unsure)):
        return None
    return answer


class HourParents:
    """ParentLookup over the execs of one completely fetched hour, for children in that hour.

    The PID's meaning when a child is exec'd at (ts, serial) is its latest successful exec before the child,
    ordered by (time, audit serial) (`place_child`). Execs of one pid at one instant without distinct serials
    are ambiguous when their images differ; so is a child at its parent's exec instant without serials to order
    them; and an exec of unknown outcome or without an executable leaves the image unknown. All of these answer
    None, so the child stays Pending and the carry (which records the same facts) leaves it unresolved. A failed
    exec never replaced the image and is ignored.
    """

    def __init__(self):
        self._execs: dict[tuple[str, int], list[tuple]] = defaultdict(list)

    def add(self, event: TypedEvent) -> None:
        if event.family != "process_exec" or event.outcome == Outcome.failure or not event.host:
            return
        pid, executable = event.get("process.pid"), event.get("process.executable")
        if isinstance(pid, bool) or not isinstance(pid, int):
            return
        known = event.outcome == Outcome.success and isinstance(executable, str) and bool(executable)
        ppid = event.get("process.ppid")
        self._execs[(event.host, pid)].append((
            event.ts.timestamp(), exec_serial(event), executable if known else None,
            ppid if isinstance(ppid, int) and not isinstance(ppid, bool) else None,
            event.raw[0].native_id if event.raw else "", boot_of(event),
        ))

    def lookup(self, host: str, pid: int, ts: float, boot: str | None = None):
        return self.lookup_ordered(host, pid, ts, boot, None)

    def lookup_ordered(self, host: str, pid: int, ts: float, boot: str | None, serial: int | None):
        chosen = place_child(self._execs.get((host, pid), []), ts, serial)
        if chosen is None or chosen[2] is None or boots_conflict(boot, chosen[5]):
            return None
        return chosen[0], chosen[2], chosen[3], chosen[4], chosen[5]


@dataclass(frozen=True)
class PendingResolution:
    event_id: str
    keys: tuple[BaselineKey, ...]
    reason: str | None


_HOUR = timedelta(hours=1)

UNOBSERVED_HOUR = "parent exec in an unobserved hour"
UNCARRIED_EXEC = "an exec of the host between parent and child was not carried"
BEFORE_HISTORY = "parent exec before history"
SPANS_TARGETS = "host exec history spans targets"


def _hour(value: datetime) -> datetime:
    return value.astimezone(UTC).replace(minute=0, second=0, microsecond=0)


class CarryInStore:
    """Latest two exec generations per live PID in the newest observed boot per host, for one hunt and target.

    History may arrive newest-first. A different boot only replaces a host when its timestamp is newer than
    the current marker; older-boot rows are ignored. Within the chosen boot, the primary-key upsert retains the
    latest two execs for each PID. Romulus currently normalizes execs but not process-exit records, so "live" means
    not superseded by a PID reuse or reboot as far as available telemetry shows.

    A stored generation is the PID's meaning at a later time only when nothing between them went unseen:
    - the observed ledger records the target's hours whose every record was fed here. A lookup needs one
      continuous observed run from the generation's exec hour through the child's hour, and on through the
      `horizon` (the end of the history being filled) when one is set. A failed, partial, budget-omitted or
      skipped hour could hold a later exec of the same PID, including one whose typed time is earlier than the
      hour it is retrieved in, so the answer is then unknown;
    - the break ledger records, per host, the hours holding an exec that was fed but not stored: no pid or
      executable, an unknown boot against a recorded one (or a recorded boot not provably older than an
      unknown one), or a typed time outside the hour it was retrieved in. Such an exec may be the PID's
      reuse, so a break between the generation and the child makes that host's answer unknown. Breaks are
      per host, so one host's unstorable exec never blanks the others. Only an exec of a recorded boot that is
      provably older than the host's recorded current boot is dropped without a break: no child of the
      current boot can descend from it.
    An exec with no host could belong to any host, so its hour never joins the observed ledger.
    """

    def __init__(self, repo: Repo, hunt_id: str, target: str = "", *, horizon: datetime | None = None,
                 _markers: dict[tuple[str, str], tuple[str, datetime]] | None = None,
                 _dirty: set[tuple[str, str]] | None = None):
        self.repo, self.hunt_id, self.target, self.horizon = repo, hunt_id, target, horizon
        # Shared across the per-target views of one hunt, so the cache cap bounds the whole hunt.
        self._markers: dict[tuple[str, str], tuple[str, datetime]] = {} if _markers is None else _markers
        # Cached markers advanced in memory but not yet on disk; a flush writes only these.
        self._dirty: set[tuple[str, str]] = set() if _dirty is None else _dirty
        # Fed but not stored since the last take_uncarried(): host -> typed hours, and whether any had no host.
        self._uncarried: dict[str, set[datetime]] = {}
        self._hostless = False

    def for_target(self, target: str, *, horizon: datetime | None = None) -> CarryInStore:
        """The same hunt's carry for another target; the marker cache and its cap are shared."""
        return CarryInStore(self.repo, self.hunt_id, target, horizon=horizon,
                            _markers=self._markers, _dirty=self._dirty)

    def mark_observed(self, start: datetime, end: datetime) -> None:
        """Record that every record of this target in [start, end) has been fed to the carry."""
        self.repo.mark_baseline_parent_observed(self.hunt_id, self.target, start, end)

    def _uncarry(self, host: str | None, ts: datetime) -> None:
        if not host:
            self._hostless = True
        else:
            self._uncarried.setdefault(host, set()).add(_hour(ts))

    def take_uncarried(self) -> tuple[dict[str, set[datetime]], bool]:
        """Return and reset the execs fed but not stored: {host: typed hours}, and whether one had no host."""
        found, hostless = self._uncarried, self._hostless
        self._uncarried, self._hostless = {}, False
        return found, hostless

    def record_breaks(self, uncarried: dict[str, set[datetime]]) -> None:
        """Write each host's uncarried hours to its break ledger, adjacent hours as one range."""
        for host in sorted(uncarried):
            hours = sorted(uncarried[host])
            run_start = previous = hours[0]
            for hour in [*hours[1:], None]:
                if hour is not None and hour == previous + _HOUR:
                    previous = hour
                    continue
                self.repo.mark_baseline_parent_break(self.hunt_id, self.target, host, run_start, previous + _HOUR)
                if hour is not None:
                    run_start = previous = hour

    def parent(self, host: str, pid: int, ts: datetime, boot: str | None = None,
               serial: int | None = None) -> tuple[tuple | None, str | None]:
        """The parent identity for a child exec'd at (ts, serial), or None with the reason it cannot be known."""
        if len(self.repo.baseline_parent_targets(self.hunt_id, host)) > 1:
            return None, SPANS_TARGETS
        child_hour = _hour(ts)
        child_end = child_hour + _HOUR
        # Observation must also run on to the horizon: a later hour could hold an earlier-typed exec.
        observed_end = max(child_end, self.horizon) if self.horizon is not None else child_end
        generations = [
            (stored["exec_ts"].timestamp(), stored["serial"], stored["executable"], stored["parent_pid"],
             stored["raw_id"], boot, stored["ambiguous"])
            for stored in self.repo.baseline_parent_generations(self.hunt_id, self.target, host, pid, boot)
        ]
        at = ts.timestamp()
        entry = place_child(generations, at, serial)
        if entry is None and any(held[0] == at and (held[1] is None or serial is None) for held in generations):
            # A held generation at the child's exact instant, with no order between them.
            return None, UNCARRIED_EXEC
        if entry is None:
            # No stored generation precedes the child. An uncarried exec of the host before the child may be the
            # parent. Only when observation runs unbroken from the start of this target's ledger through the
            # child (and horizon) is the exec before history; otherwise it may sit in an unobserved hour.
            if self.repo.baseline_parent_break_overlaps(
                    self.hunt_id, self.target, host, datetime.fromtimestamp(0, UTC), child_end):
                return None, UNCARRIED_EXEC
            ranges = self.repo.baseline_parent_observed_ranges(self.hunt_id, self.target)
            if not ranges or (ranges[0][0] <= child_hour and observed_end <= ranges[0][1]):
                return None, BEFORE_HISTORY
            return None, UNOBSERVED_HOUR
        exec_hour = _hour(datetime.fromtimestamp(entry[0], UTC))
        if not self.repo.baseline_parent_observed_covers(self.hunt_id, self.target, exec_hour, observed_end):
            return None, UNOBSERVED_HOUR
        if entry[6] or self.repo.baseline_parent_break_overlaps(
                self.hunt_id, self.target, host, exec_hour, child_end):
            # An ambiguous generation (two images at one instant, unordered) is an uncarried exec too.
            return None, UNCARRIED_EXEC
        return (entry[0], entry[2], entry[3], entry[4], entry[5]), None

    def lookup(self, host: str, pid: int, ts: float, boot: str | None = None) -> tuple | None:
        """ParentLookup: the continuity-checked parent identity, else None."""
        return self.lookup_ordered(host, pid, ts, boot, None)

    def lookup_ordered(self, host: str, pid: int, ts: float, boot: str | None,
                       serial: int | None) -> tuple | None:
        return self.parent(host, pid, datetime.fromtimestamp(ts, UTC), boot, serial)[0]

    def _marker(self, host: str) -> tuple[str, datetime] | None:
        key = (self.target, host)
        if key not in self._markers:
            stored = self.repo.baseline_parent_boot(self.hunt_id, self.target, host)
            if stored is not None:
                self._remember_marker(host, stored)
                return stored
        return self._markers.get(key)

    def _remember_marker(self, host: str, marker: tuple[str, datetime]) -> None:
        """Cache common hosts while leaving overflow authoritative on disk."""
        key = (self.target, host)
        if key in self._markers or len(self._markers) < MARKER_CACHE_CAP:
            self._markers[key] = marker

    def observe_events(self, events: Iterable[TypedEvent], *, chunk_size: int = 100_000,
                       hour: tuple[datetime, datetime] | None = None) -> int:
        """Feed execs; `hour` is the retrieval interval they came from, when known.

        A failed exec never replaced the PID's image, so it is skipped. An exec of unknown outcome may or may not
        have, so it is uncarried. Every other exec is stored, or recorded as uncarried (see the class note). With
        `hour`, an exec typed outside it is stored and also recorded as uncarried at both its typed and retrieval
        hours: the hours then no longer vouch for that host.
        """
        def rows():
            for event in events:
                if event.family != "process_exec" or event.outcome == Outcome.failure:
                    continue
                if not event.host:
                    self._uncarry(None, event.ts)
                    continue
                if hour is not None and not hour[0] <= event.ts < hour[1]:
                    self._uncarry(event.host, event.ts)
                    self._uncarry(event.host, hour[0])
                pid, executable = event.get("process.pid"), event.get("process.executable")
                if (event.outcome != Outcome.success or isinstance(pid, bool) or not isinstance(pid, int)
                        or pid < 0 or not isinstance(executable, str) or not executable):
                    self._uncarry(event.host, event.ts)
                    continue
                ppid = event.get("process.ppid")
                yield ParentExec(
                    event.host, boot_of(event), pid, event.ts, executable,
                    ppid if isinstance(ppid, int) and not isinstance(ppid, bool) else None,
                    event.raw[0].native_id if event.raw else "", exec_serial(event),
                )

        return self.observe_rows(rows(), chunk_size=chunk_size)

    def observe_rows(self, rows: Iterable[ParentExec], *, chunk_size: int = 100_000) -> int:
        if chunk_size < 1:
            raise ValueError("carry-in chunk size must be positive")
        pending: dict[tuple[str, str, int], list[dict]] = {}
        seen = maximum = 0

        def flush() -> None:
            nonlocal maximum, seen
            if pending:
                self.repo.upsert_baseline_parents(
                    row for generations in pending.values() for row in generations
                )
                pending.clear()
            for key in sorted(key for key in self._dirty if key[0] == self.target):
                boot, latest = self._markers[key]
                self.repo.set_baseline_parent_boot(self.hunt_id, key[0], key[1], boot, latest)
                self._dirty.discard(key)
            maximum = max(maximum, self.repo.baseline_parent_count(self.hunt_id))
            seen = 0

        for item in rows:
            if item.ts.tzinfo is None or item.ts.utcoffset() is None:
                raise ValueError("parent exec timestamp must carry a timezone")
            if (not item.host or isinstance(item.pid, bool) or not isinstance(item.pid, int)
                    or item.pid < 0 or not item.executable):
                self._uncarry(item.host, item.ts)
                continue
            timestamp, boot = item.ts.astimezone(UTC), item.boot or ""
            marker = self._marker(item.host)
            if marker is None:
                if not self.repo.set_baseline_parent_boot(
                        self.hunt_id, self.target, item.host, boot, timestamp):
                    self._uncarry(item.host, timestamp)
                    continue
                self._remember_marker(item.host, (boot, timestamp))
            elif marker[0] != boot:
                if marker[1] >= timestamp:
                    # Dropped silently only when both boots are recorded: then the exec is provably in an older
                    # boot. An unknown boot on either side may be the current one.
                    if not (boot and marker[0]):
                        self._uncarry(item.host, timestamp)
                    continue
                # A newer reboot supersedes every process in the former boot, including buffered rows.
                pending = {key: value for key, value in pending.items() if key[0] != item.host}
                if not self.repo.set_baseline_parent_boot(
                        self.hunt_id, self.target, item.host, boot, timestamp):
                    self._uncarry(item.host, timestamp)
                    continue
                self._remember_marker(item.host, (boot, timestamp))
            elif timestamp > marker[1]:
                if (self.target, item.host) in self._markers:
                    self._remember_marker(item.host, (boot, timestamp))
                    self._dirty.add((self.target, item.host))
                elif not self.repo.set_baseline_parent_boot(
                        self.hunt_id, self.target, item.host, boot, timestamp):
                    self._uncarry(item.host, timestamp)
                    continue
            key = (item.host, boot, item.pid)
            row = {
                "hunt_id": self.hunt_id, "target": self.target, "host": item.host, "boot": boot, "pid": item.pid,
                "exec_ts": timestamp, "serial": item.serial, "executable": item.executable,
                "parent_pid": item.parent_pid, "raw_id": item.raw_id, "ambiguous": 0,
            }
            _keep_latest_two(pending.setdefault(key, []), row)
            seen += 1
            if seen >= chunk_size:
                flush()
        flush()
        return maximum


def _keep_latest_two(generations: list[dict], row: dict) -> None:
    """Merge one exec into a pid's buffered generations, newest first by (time, serial), keeping two.

    The same rule as the store's upsert: an exec at the instant of a held generation is the same exec when the
    serials match or the images match; with different images and no distinct serials the generation is marked
    ambiguous, so it can never answer as a parent.
    """
    for generation in generations:
        if generation["exec_ts"] == row["exec_ts"] and _same_instant(generation["serial"], row["serial"]):
            if generation["executable"] != row["executable"]:
                generation["ambiguous"] = 1
            return
    generations.append(row)
    generations.sort(key=lambda item: (item["exec_ts"], item["serial"] if item["serial"] is not None else -1),
                     reverse=True)
    del generations[2:]


class PendingResolver:
    """Resolve compact pending children without silently dropping an unresolvable one."""

    def __init__(self, parents, spec: BaselineSpec = SPEC_BY_ID["bl.exec_pair"]):
        self.parents, self.spec = parents, spec

    def resolve(self, pending: Pending) -> PendingResolution:
        if pending.ppid in (1, 2):
            return PendingResolution(pending.event_id, (), "parent pid 1/2 out of scope")
        if isinstance(self.parents, CarryInStore):
            parent, reason = self.parents.parent(
                pending.host, pending.ppid, pending.ts, pending.boot, pending.serial)
        else:
            parent = parent_at(self.parents, pending.host, pending.ppid, pending.ts.timestamp(), pending.boot,
                               pending.serial)
            reason = None
        if parent is None or not isinstance(parent[1], str) or not parent[1]:
            return PendingResolution(pending.event_id, (), reason or BEFORE_HISTORY)
        resolved = exec_pair_key(self.spec, pending.host, parent[1], pending.child_executable)
        return PendingResolution(pending.event_id, (resolved,), None)

    def resolve_all(self, pendings: Iterable[Pending]) -> tuple[PendingResolution, ...]:
        return tuple(self.resolve(pending) for pending in pendings)
