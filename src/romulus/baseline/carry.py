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
from romulus.detect.observed import Observed, observation, process_view
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
    # Set on a generation replayed from a persisted carry hour: whether two images shared its instant unordered,
    # and the time bounds of the pid's execs that hour displaced from the two exact slots.
    ambiguous: bool = False
    evicted_earliest_ts: datetime | None = None
    evicted_latest_ts: datetime | None = None


@dataclass(frozen=True)
class ParentObservation:
    """One non-exec audit observation of a process image, compact enough for the disk carry."""

    host: str
    boot: str | None
    pid: int
    ts: datetime
    executable: str
    parent_pid: int
    session: int | None
    event_id: str
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
      executable, an unrecorded boot (an exec or process image whose boot is unknown: nothing proves it is
      not a reuse in the current boot, even beside other unknown-boot records), or a typed time outside the
      hour it was retrieved in. Such an exec may be the PID's
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

    def replay_hour(self, hour: CarryHour) -> bool:
        """Feed one persisted carry hour through the same rules as its records; True when the hour may join the
        observed ledger (it held no exec without a host).

        The hour's execs are already reduced to the latest two per (host, boot, pid) with the bounds of the rest,
        and its observations to their state-run boundaries; boot, reuse and break decisions that depend on what
        the carry already holds are made here, exactly as for records.
        """
        self.observe_rows(sorted(hour.execs, key=lambda item: (
            item.ts, -1 if item.serial is None else item.serial, item.raw_id, item.host, item.pid,
        )))
        self.observe_observation_rows(sorted(hour.observations, key=lambda item: (
            item.ts, -1 if item.serial is None else item.serial, item.event_id, item.host, item.pid,
        )))
        uncarried, _hostless = self.take_uncarried()
        for host, hours in hour.breaks.items():
            uncarried.setdefault(host, set()).update(hours)
        if uncarried:
            self.record_breaks(uncarried)
        return not hour.hostless

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
        """Feed execs and non-exec process observations; `hour` is their retrieval interval, when known.

        A failed exec never replaced the PID's image, so it is skipped. An exec of unknown outcome may or may not
        have, so it is uncarried. Every other exec is stored, or recorded as uncarried (see the class note). With
        `hour`, an exec typed outside it is stored and also recorded as uncarried at both its typed and retrieval
        hours: the hours then no longer vouch for that host.
        """
        if chunk_size < 1:
            raise ValueError("carry-in chunk size must be positive")
        parents: list[ParentExec] = []
        observed: list[ParentObservation] = []
        maximum = 0

        def flush() -> None:
            nonlocal maximum
            if parents:
                maximum = max(maximum, self.observe_rows(parents, chunk_size=chunk_size))
                parents.clear()
            if observed:
                self.observe_observation_rows(observed, chunk_size=chunk_size)
                observed.clear()

        for event in events:
            if event.family != "process_exec":
                found = observation(event)
                if found is not None and event.host and (hour is None or hour[0] <= event.ts < hour[1]):
                    pid, item, _ref = found
                    observed.append(ParentObservation(
                        event.host, item.boot, pid, event.ts, item.exe, item.ppid,
                        item.session, item.event_id, item.serial,
                    ))
            elif event.outcome != Outcome.failure:
                if not event.host:
                    self._uncarry(None, event.ts)
                else:
                    if hour is not None and not hour[0] <= event.ts < hour[1]:
                        self._uncarry(event.host, event.ts)
                        self._uncarry(event.host, hour[0])
                    pid, executable = event.get("process.pid"), event.get("process.executable")
                    if (event.outcome != Outcome.success or isinstance(pid, bool) or not isinstance(pid, int)
                            or pid < 0 or not isinstance(executable, str) or not executable):
                        self._uncarry(event.host, event.ts)
                    else:
                        ppid = event.get("process.ppid")
                        parents.append(ParentExec(
                            event.host, boot_of(event), pid, event.ts, executable,
                            ppid if isinstance(ppid, int) and not isinstance(ppid, bool) else None,
                            event.raw[0].native_id if event.raw else "", exec_serial(event),
                        ))
            if len(parents) + len(observed) >= chunk_size:
                flush()
        flush()
        return maximum

    def observe_window_rows(self, rows: Iterable[dict], *, hour: tuple[datetime, datetime],
                            chunk_size: int = 100_000) -> int:
        """Feed durable compact window process rows through the same rules as typed events."""
        if chunk_size < 1:
            raise ValueError("carry-in chunk size must be positive")
        parents: list[ParentExec] = []
        observed: list[ParentObservation] = []
        maximum = 0

        def flush() -> None:
            nonlocal maximum
            if parents:
                maximum = max(maximum, self.observe_rows(parents, chunk_size=chunk_size))
                parents.clear()
            if observed:
                self.observe_observation_rows(observed, chunk_size=chunk_size)
                observed.clear()

        for row in rows:
            ts = row["ts"]
            if row.get("family", "process_exec") != "process_exec":
                host, boot = row.get("host"), row.get("boot")
                pid, ppid, executable = row.get("pid"), row.get("ppid"), row.get("executable")
                if (hour[0] <= ts < hour[1] and host
                        and isinstance(pid, int) and not isinstance(pid, bool)
                        and isinstance(ppid, int) and not isinstance(ppid, bool)
                        and isinstance(executable, str) and executable):
                    # an unrecorded boot becomes a break in observe_observation_rows
                    observed.append(ParentObservation(
                        host, boot, pid, ts, executable, ppid, row.get("session"),
                        row["event_id"], row.get("serial"),
                    ))
            else:
                outcome = Outcome(row["outcome"])
                host = row.get("host")
                if outcome != Outcome.failure:
                    if not host:
                        self._uncarry(None, ts)
                    else:
                        if not hour[0] <= ts < hour[1]:
                            self._uncarry(host, ts)
                            self._uncarry(host, hour[0])
                        pid, executable = row.get("pid"), row.get("executable")
                        if (outcome != Outcome.success or isinstance(pid, bool) or not isinstance(pid, int)
                                or pid < 0 or not isinstance(executable, str) or not executable):
                            self._uncarry(host, ts)
                        else:
                            ppid = row.get("ppid")
                            parents.append(ParentExec(
                                host, row.get("boot"), pid, ts, executable,
                                ppid if isinstance(ppid, int) and not isinstance(ppid, bool) else None,
                                row["event_id"], row.get("serial"),
                            ))
            if len(parents) + len(observed) >= chunk_size:
                flush()
        flush()
        return maximum

    def observe_observation_rows(self, rows: Iterable[ParentObservation], *,
                                 chunk_size: int = 100_000) -> int:
        """Stream process-image observations to disk; an unrecorded boot is never used for carry-in."""
        if chunk_size < 1:
            raise ValueError("observation chunk size must be positive")
        pending: list[dict] = []
        written = 0

        def flush() -> None:
            nonlocal written
            if pending:
                written += self.repo.upsert_baseline_parent_observations(pending, chunk_size=chunk_size)
                pending.clear()

        for item in rows:
            if item.ts.tzinfo is None or item.ts.utcoffset() is None:
                raise ValueError("parent observation timestamp must carry a timezone")
            if (not item.host or isinstance(item.pid, bool) or not isinstance(item.pid, int)
                    or item.pid < 0 or isinstance(item.parent_pid, bool) or not isinstance(item.parent_pid, int)
                    or not item.executable):
                continue
            if not item.boot:
                # A process image seen in an unrecorded boot may be a reuse of its pid in the current boot: its
                # hour is a break for its host, as for an unknown-boot exec.
                self._uncarry(item.host, item.ts)
                continue
            timestamp = item.ts.astimezone(UTC)
            marker = self._marker(item.host)
            if marker is None:
                if not self.repo.set_baseline_parent_boot(
                        self.hunt_id, self.target, item.host, item.boot, timestamp):
                    continue
                self._remember_marker(item.host, (item.boot, timestamp))
            elif marker[0] != item.boot:
                if marker[1] >= timestamp:
                    continue
                flush()
                if not self.repo.set_baseline_parent_boot(
                        self.hunt_id, self.target, item.host, item.boot, timestamp):
                    continue
                self._remember_marker(item.host, (item.boot, timestamp))
            elif timestamp > marker[1]:
                if (self.target, item.host) in self._markers:
                    self._remember_marker(item.host, (item.boot, timestamp))
                    self._dirty.add((self.target, item.host))
                elif not self.repo.set_baseline_parent_boot(
                        self.hunt_id, self.target, item.host, item.boot, timestamp):
                    continue
            pending.append({
                "hunt_id": self.hunt_id, "target": self.target, "host": item.host,
                "boot": item.boot, "pid": item.pid, "observed_ts": timestamp,
                "serial": item.serial, "executable": item.executable, "parent_pid": item.parent_pid,
                "session": item.session, "event_id": item.event_id,
            })
            if len(pending) >= chunk_size:
                flush()
        flush()
        for key in sorted(key for key in self._dirty if key[0] == self.target):
            boot, latest = self._markers[key]
            self.repo.set_baseline_parent_boot(self.hunt_id, key[0], key[1], boot, latest)
            self._dirty.discard(key)
        return written

    def observed_parent(self, host: str, pid: int, ts: datetime, boot: str | None,
                        serial: int | None = None) -> tuple[tuple | None, str | None]:
        """Resolve a long-lived parent from its nearest same-boot process observations, never by inference."""
        if not boot:
            return None, "parent boot is not recorded"
        if len(self.repo.baseline_parent_targets(self.hunt_id, host)) > 1:
            return None, SPANS_TARGETS
        rows = self.repo.baseline_parent_observations(
            self.hunt_id, self.target, host, pid, boot, ts, serial,
        )
        prior_states = {
            (row["executable"], row["parent_pid"], row["session"])
            for row in rows if row["observed_ts"] < ts
        }
        if len(prior_states) > 1:
            return None, (f"lineage ambiguous for pid {pid} on {host}: records at one instant without audit "
                          "serials to order them show different states")
        instants: dict[datetime, list[dict]] = defaultdict(list)
        for row in rows:
            instants[row["observed_ts"]].append(row)
        for instant_rows in instants.values():
            states = {
                (row["executable"], row["parent_pid"], row["session"])
                for row in instant_rows
            }
            serials = [row["serial"] for row in instant_rows]
            if len(states) > 1 and (None in serials or len(set(serials)) < len(serials)):
                return None, (f"lineage ambiguous for pid {pid} on {host}: records at one instant without audit "
                              "serials to order them show different states")
        observed = [Observed(
            row["observed_ts"].timestamp(), row["serial"], row["executable"], row["parent_pid"],
            row["session"], boot, row["event_id"], row["event_id"],
            row["observed_ts"].timestamp(), False,
        ) for row in rows]
        view = process_view(
            [], observed, ts.timestamp(), serial, boot, inclusive=False, pid=pid, host=host,
        )
        if view.image is None:
            return None, view.why or BEFORE_HISTORY
        if not view.prior:
            return None, "parent observation follows child"
        observed_ts = datetime.fromtimestamp(view.image.ts, UTC)
        observed_end = max(_hour(ts) + _HOUR, self.horizon) if self.horizon is not None else _hour(ts) + _HOUR
        if not self.repo.baseline_parent_observed_covers(
                self.hunt_id, self.target, _hour(observed_ts), observed_end):
            return None, UNOBSERVED_HOUR
        if self.repo.baseline_parent_break_overlaps(
                self.hunt_id, self.target, host, observed_ts, _hour(ts) + _HOUR):
            return None, UNCARRIED_EXEC
        evicted = self.repo.baseline_parent_eviction_bounds(
            self.hunt_id, self.target, host, pid, boot,
        )
        if evicted is not None and not (evicted[1] < observed_ts or evicted[0] > ts):
            # Only bounds are retained after the exact two generations. If their interval overlaps this
            # observation-to-child interval, an evicted exec may have replaced the observed image.
            return None, UNCARRIED_EXEC
        return (view.image.ts, view.image.exe, view.image.ppid, view.image.entry.event_id, boot), None

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
            if not boot:
                # An exec whose boot is not recorded may be a reuse of its pid in any boot, the current one
                # included, and nothing proves continuity across it, even against other unknown-boot execs (a
                # reboot between them is invisible). It is never stored and never moves the boot marker: its hour
                # is a break for its host.
                self._uncarry(item.host, timestamp)
                continue
            marker = self._marker(item.host)
            if marker is None:
                if not self.repo.set_baseline_parent_boot(
                        self.hunt_id, self.target, item.host, boot, timestamp):
                    self._uncarry(item.host, timestamp)
                    continue
                self._remember_marker(item.host, (boot, timestamp))
            elif marker[0] != boot:
                if marker[1] >= timestamp:
                    # Dropped silently only when both boots are recorded (an unknown-boot exec never gets here,
                    # and never sets a marker): then the exec is provably in an older boot.
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
                "parent_pid": item.parent_pid, "raw_id": item.raw_id, "ambiguous": int(item.ambiguous),
                "evicted_earliest_ts": item.evicted_earliest_ts, "evicted_latest_ts": item.evicted_latest_ts,
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
            if generation["executable"] != row["executable"] or row.get("ambiguous"):
                generation["ambiguous"] = 1
            bounds = [
                value for item in (generation, row)
                for value in (item.get("evicted_earliest_ts"), item.get("evicted_latest_ts"))
                if value is not None
            ]
            if bounds:
                generation["evicted_earliest_ts"] = min(bounds)
                generation["evicted_latest_ts"] = max(bounds)
            return
    generations.append(row)
    generations.sort(key=lambda item: (item["exec_ts"], item["serial"] if item["serial"] is not None else -1),
                     reverse=True)
    evicted = generations[2:]
    bounds = [
        value for item in generations
        for value in (item.get("evicted_earliest_ts"), item.get("evicted_latest_ts"))
        if value is not None
    ]
    bounds.extend(item["exec_ts"] for item in evicted)
    del generations[2:]
    if bounds:
        for generation in generations:
            generation["evicted_earliest_ts"] = min(bounds)
            generation["evicted_latest_ts"] = max(bounds)


# Bumped whenever what a persisted carry hour holds, or how it is reduced, changes: other formats are never read.
CARRY_FORMAT = 1


@dataclass(frozen=True)
class CarryHour:
    """What one completely fetched target hour contributes to the parent carry, compact enough to persist.

    Built once per hour by `CarryHourBuilder`, stored beside the hour's segments, and replayed into any later hunt's
    carry (`CarryInStore.replay_hour`). A hunt that reads the hour and a hunt that finds it already covered feed
    their carries the same input, so their parents resolve alike.
    """

    execs: tuple[ParentExec, ...]
    observations: tuple[ParentObservation, ...]
    # host -> hours holding an exec that could not be stored whatever the carry holds (no pid or executable, an
    # unknown outcome, a typed time outside the hour)
    breaks: dict[str, frozenset[datetime]]
    hostless: bool


class CarryHourBuilder:
    """Reduce one hour's records to its `CarryHour` as they are fetched, without holding the records.

    Execs keep the latest two generations per (host, boot, pid) with the time bounds of the rest, the store's own
    rule; observations keep their state-run boundaries, which is all the store keeps of them.
    """

    def __init__(self, hour: tuple[datetime, datetime]):
        self.hour = hour
        self._generations: dict[tuple[str, str, int], list[dict]] = {}
        self._observations: dict[tuple[str, str, int], dict[tuple, ParentObservation]] = {}
        self._breaks: dict[str, set[datetime]] = {}
        self._hostless = False

    def _break(self, host: str, ts: datetime) -> None:
        self._breaks.setdefault(host, set()).add(_hour(ts))

    def add(self, events: Iterable[TypedEvent]) -> None:
        start, end = self.hour
        for event in events:
            if event.family != "process_exec":
                found = observation(event)
                if found is not None and event.host and start <= event.ts < end:
                    pid, item, _ref = found
                    valid = (not isinstance(pid, bool) and isinstance(pid, int) and pid >= 0
                             and not isinstance(item.ppid, bool) and isinstance(item.ppid, int) and bool(item.exe))
                    if valid and not item.boot:
                        # an image in an unrecorded boot may be a reuse of its pid: a break, as when replayed
                        self._break(event.host, event.ts)
                    elif valid:
                        record = ParentObservation(event.host, item.boot, pid, event.ts.astimezone(UTC), item.exe,
                                                   item.ppid, item.session, item.event_id, item.serial)
                        self._observations.setdefault((event.host, item.boot, pid), {})[
                            (record.ts, record.event_id)] = record
                continue
            if event.outcome == Outcome.failure:
                continue
            if not event.host:
                self._hostless = True
                continue
            if not start <= event.ts < end:
                self._break(event.host, event.ts)
                self._break(event.host, start)
            pid, executable = event.get("process.pid"), event.get("process.executable")
            if (event.outcome != Outcome.success or isinstance(pid, bool) or not isinstance(pid, int) or pid < 0
                    or not isinstance(executable, str) or not executable):
                self._break(event.host, event.ts)
                continue
            ppid = event.get("process.ppid")
            boot = boot_of(event) or ""
            if not boot:
                # never stored when replayed (an unrecorded boot is a break): keep only the break
                self._break(event.host, event.ts)
                continue
            _keep_latest_two(self._generations.setdefault((event.host, boot, pid), []), {
                "exec_ts": event.ts.astimezone(UTC), "serial": exec_serial(event), "executable": executable,
                "parent_pid": ppid if isinstance(ppid, int) and not isinstance(ppid, bool) else None,
                "raw_id": event.raw[0].native_id if event.raw else "", "ambiguous": 0,
                "evicted_earliest_ts": None, "evicted_latest_ts": None,
            })

    def finish(self) -> CarryHour:
        execs = tuple(
            ParentExec(host, boot or None, pid, row["exec_ts"], row["executable"], row["parent_pid"], row["raw_id"],
                       row["serial"], bool(row["ambiguous"]), row["evicted_earliest_ts"], row["evicted_latest_ts"])
            for (host, boot, pid), rows in sorted(self._generations.items()) for row in rows
        )
        observations: list[ParentObservation] = []
        for key in sorted(self._observations):
            ordered = sorted(self._observations[key].values(), key=lambda item: (
                item.ts, item.serial is None, item.serial or 0, item.event_id,
            ))
            state = [(item.executable, item.parent_pid, item.session) for item in ordered]
            observations.extend(
                item for index, item in enumerate(ordered)
                if not (0 < index < len(ordered) - 1 and state[index - 1] == state[index] == state[index + 1])
            )
        return CarryHour(execs, tuple(observations),
                         {host: frozenset(hours) for host, hours in sorted(self._breaks.items())}, self._hostless)


_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_MICRO = timedelta(microseconds=1)


def _us(value: datetime | None) -> int | None:
    return None if value is None else (value.astimezone(UTC) - _EPOCH) // _MICRO


def _from_us(value: int | None) -> datetime | None:
    return None if value is None else _EPOCH + value * _MICRO


def save_carry_hour(repo: Repo, *, site: str, target: str, hour: datetime, normalizer: str,
                    carry: CarryHour) -> bool:
    """Persist a carry hour once (the first complete read of an hour is kept), in typed compact rows."""
    refs: dict[tuple[str, str | None], int] = {}

    def ref(host: str, boot: str | None) -> int:
        return refs.setdefault((host, boot), len(refs))

    execs = [{"ref": ref(item.host, item.boot), "pid": item.pid, "ts_us": _us(item.ts), "serial": item.serial,
              "executable": item.executable, "parent_pid": item.parent_pid, "raw_id": item.raw_id,
              "ambiguous": int(item.ambiguous), "evicted_earliest_us": _us(item.evicted_earliest_ts),
              "evicted_latest_us": _us(item.evicted_latest_ts)} for item in carry.execs]
    observations = [{"ref": ref(item.host, item.boot), "pid": item.pid, "ts_us": _us(item.ts),
                     "serial": item.serial, "executable": item.executable, "parent_pid": item.parent_pid,
                     "session": item.session, "event_id": item.event_id} for item in carry.observations]
    breaks = [{"ref": ref(host, None), "hour_us": _us(value)}
              for host, hours in sorted(carry.breaks.items()) for value in sorted(hours)]
    return repo.save_baseline_carry_hour(
        site=site, target=target, hour=hour, normalizer=normalizer, format_=CARRY_FORMAT, hostless=carry.hostless,
        hosts=sorted(refs, key=refs.__getitem__), execs=execs, observations=observations, breaks=breaks,
    )


def load_carry_hour(repo: Repo, *, site: str, target: str, hour: datetime, normalizer: str) -> CarryHour | None:
    """A persisted carry hour of the current format, or None when none is kept (never kept, pruned, or trimmed by
    the disk budget): the caller then reads the hour again or leaves it unobserved."""
    stored = repo.baseline_carry_hour(site=site, target=target, hour=hour, normalizer=normalizer,
                                      format_=CARRY_FORMAT)
    if stored is None:
        return None
    hosts = stored["hosts"]
    breaks: dict[str, set[datetime]] = {}
    for row in stored["break"]:
        breaks.setdefault(hosts[row["ref"]][0], set()).add(_from_us(row["hour_us"]))
    return CarryHour(
        tuple(ParentExec(hosts[row["ref"]][0], hosts[row["ref"]][1], row["pid"], _from_us(row["ts_us"]),
                         row["executable"], row["parent_pid"], row["raw_id"], row["serial"], bool(row["ambiguous"]),
                         _from_us(row["evicted_earliest_us"]), _from_us(row["evicted_latest_us"]))
              for row in stored["exec"]),
        tuple(ParentObservation(hosts[row["ref"]][0], hosts[row["ref"]][1], row["pid"], _from_us(row["ts_us"]),
                                row["executable"], row["parent_pid"], row["session"], row["event_id"],
                                row["serial"]) for row in stored["observation"]),
        {host: frozenset(hours) for host, hours in sorted(breaks.items())},
        bool(stored["hostless"]),
    )


class PendingResolver:
    """Resolve compact pending children without silently dropping an unresolvable one."""

    def __init__(self, parents, spec: BaselineSpec = SPEC_BY_ID["bl.exec_pair"]):
        self.parents, self.spec = parents, spec

    def resolve(self, pending: Pending) -> PendingResolution:
        if pending.ppid in (1, 2):
            parent = "init" if pending.ppid == 1 else "kthreadd"
            resolved = exec_pair_key(self.spec, pending.host, parent, pending.child_executable)
            return PendingResolution(pending.event_id, (resolved,), None)
        if isinstance(self.parents, CarryInStore):
            parent, reason = self.parents.parent(
                pending.host, pending.ppid, pending.ts, pending.boot, pending.serial)
            if parent is None and reason == BEFORE_HISTORY:
                parent, reason = self.parents.observed_parent(
                    pending.host, pending.ppid, pending.ts, pending.boot, pending.serial,
                )
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
