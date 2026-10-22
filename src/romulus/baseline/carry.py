"""Disk-backed process-parent carry-in and explicit Pending resolution."""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from romulus.baseline.spec import SPEC_BY_ID, BaselineKey, BaselineSpec, Pending, exec_pair_key
from romulus.detect.correlation import boot_of
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


@dataclass(frozen=True)
class PendingResolution:
    event_id: str
    keys: tuple[BaselineKey, ...]
    reason: str | None


_HOUR = timedelta(hours=1)

UNOBSERVED_HOUR = "parent exec in an unobserved hour"
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

    A stored generation is the PID's meaning at a later time only when nothing between them went unseen. The
    observed ledger records the hours whose every record was fed here; a lookup answers only when one
    continuous observed run spans the generation's exec hour through the child's hour. A failed, partial,
    budget-omitted or skipped hour in between could hold a later exec of the same PID, so the answer is unknown.
    """

    def __init__(self, repo: Repo, hunt_id: str, target: str = "", *,
                 _markers: dict[tuple[str, str], tuple[str, datetime]] | None = None,
                 _dirty: set[tuple[str, str]] | None = None):
        self.repo, self.hunt_id, self.target = repo, hunt_id, target
        # Shared across the per-target views of one hunt, so the cache cap bounds the whole hunt.
        self._markers: dict[tuple[str, str], tuple[str, datetime]] = {} if _markers is None else _markers
        # Cached markers advanced in memory but not yet on disk; a flush writes only these.
        self._dirty: set[tuple[str, str]] = set() if _dirty is None else _dirty

    def for_target(self, target: str) -> CarryInStore:
        """The same hunt's carry for another target; the marker cache and its cap are shared."""
        return CarryInStore(self.repo, self.hunt_id, target, _markers=self._markers, _dirty=self._dirty)

    def mark_observed(self, start: datetime, end: datetime) -> None:
        """Record that every record of this target in [start, end) has been fed to the carry."""
        self.repo.mark_baseline_parent_observed(self.hunt_id, self.target, start, end)

    def parent(self, host: str, pid: int, ts: datetime,
               boot: str | None = None) -> tuple[tuple | None, str | None]:
        """The parent identity at `ts`, or None with the reason it cannot be known."""
        if len(self.repo.baseline_parent_targets(self.hunt_id, host)) > 1:
            return None, SPANS_TARGETS
        child_hour = _hour(ts)
        entry = self.repo.baseline_parent_lookup(self.hunt_id, self.target, host, pid, ts.timestamp(), boot)
        if entry is None:
            # No stored generation precedes the child. Only when observation runs unbroken from the start of
            # this target's ledger through the child is the exec before history; otherwise it may sit in an
            # unobserved hour.
            ranges = self.repo.baseline_parent_observed_ranges(self.hunt_id, self.target)
            if not ranges or (ranges[0][0] <= child_hour and child_hour + _HOUR <= ranges[0][1]):
                return None, BEFORE_HISTORY
            return None, UNOBSERVED_HOUR
        exec_hour = _hour(datetime.fromtimestamp(entry[0], UTC))
        if not self.repo.baseline_parent_observed_covers(
                self.hunt_id, self.target, exec_hour, child_hour + _HOUR):
            return None, UNOBSERVED_HOUR
        return entry, None

    def lookup(self, host: str, pid: int, ts: float, boot: str | None = None) -> tuple | None:
        """ParentLookup: the continuity-checked parent identity, else None."""
        return self.parent(host, pid, datetime.fromtimestamp(ts, UTC), boot)[0]

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

    def observe_events(self, events: Iterable[TypedEvent], *, chunk_size: int = 100_000) -> int:
        def rows():
            for event in events:
                if event.family != "process_exec" or event.outcome == Outcome.failure or not event.host:
                    continue
                pid, executable = event.get("process.pid"), event.get("process.executable")
                if isinstance(pid, bool) or not isinstance(pid, int) or pid < 0:
                    continue
                if not isinstance(executable, str) or not executable:
                    continue
                ppid = event.get("process.ppid")
                yield ParentExec(
                    event.host, boot_of(event), pid, event.ts, executable,
                    ppid if isinstance(ppid, int) and not isinstance(ppid, bool) else None,
                    event.raw[0].native_id if event.raw else "",
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
                continue
            timestamp, boot = item.ts.astimezone(UTC), item.boot or ""
            marker = self._marker(item.host)
            if marker is None:
                if not self.repo.set_baseline_parent_boot(
                        self.hunt_id, self.target, item.host, boot, timestamp):
                    continue
                self._remember_marker(item.host, (boot, timestamp))
            elif marker[0] != boot:
                if marker[1] >= timestamp:
                    continue
                # A newer reboot supersedes every process in the former boot, including buffered rows.
                pending = {key: value for key, value in pending.items() if key[0] != item.host}
                if not self.repo.set_baseline_parent_boot(
                        self.hunt_id, self.target, item.host, boot, timestamp):
                    continue
                self._remember_marker(item.host, (boot, timestamp))
            elif timestamp > marker[1]:
                if (self.target, item.host) in self._markers:
                    self._remember_marker(item.host, (boot, timestamp))
                    self._dirty.add((self.target, item.host))
                elif not self.repo.set_baseline_parent_boot(
                        self.hunt_id, self.target, item.host, boot, timestamp):
                    continue
            key = (item.host, boot, item.pid)
            row = {
                "hunt_id": self.hunt_id, "target": self.target, "host": item.host, "boot": boot, "pid": item.pid,
                "exec_ts": timestamp, "executable": item.executable,
                "parent_pid": item.parent_pid, "raw_id": item.raw_id,
            }
            generations = pending.setdefault(key, [])
            if all(generation["exec_ts"] != timestamp for generation in generations):
                generations.append(row)
                generations.sort(key=lambda generation: generation["exec_ts"], reverse=True)
                del generations[2:]
            seen += 1
            if seen >= chunk_size:
                flush()
        flush()
        return maximum


class PendingResolver:
    """Resolve compact pending children without silently dropping an unresolvable one."""

    def __init__(self, parents, spec: BaselineSpec = SPEC_BY_ID["bl.exec_pair"]):
        self.parents, self.spec = parents, spec

    def resolve(self, pending: Pending) -> PendingResolution:
        if pending.ppid in (1, 2):
            return PendingResolution(pending.event_id, (), "parent pid 1/2 out of scope")
        if isinstance(self.parents, CarryInStore):
            parent, reason = self.parents.parent(pending.host, pending.ppid, pending.ts, pending.boot)
        else:
            parent = self.parents.lookup(pending.host, pending.ppid, pending.ts.timestamp(), pending.boot)
            reason = None
        if parent is None or not isinstance(parent[1], str) or not parent[1]:
            return PendingResolution(pending.event_id, (), reason or BEFORE_HISTORY)
        resolved = exec_pair_key(self.spec, pending.host, parent[1], pending.child_executable)
        return PendingResolution(pending.event_id, (resolved,), None)

    def resolve_all(self, pendings: Iterable[Pending]) -> tuple[PendingResolution, ...]:
        return tuple(self.resolve(pending) for pending in pendings)
