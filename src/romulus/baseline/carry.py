"""Disk-backed process-parent carry-in and explicit Pending resolution."""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime

from romulus.baseline.spec import BaselineKey, Pending, key_digest_of, key_id_of
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


class CarryInStore:
    """Latest two exec generations per live PID in the newest observed boot per host.

    History may arrive newest-first. A different boot only replaces a host when its timestamp is newer than
    the current marker; older-boot rows are ignored. Within the chosen boot, the primary-key upsert retains the
    latest two execs for each PID. Romulus currently normalizes execs but not process-exit records, so "live" means
    not superseded by a PID reuse or reboot as far as available telemetry shows.
    """

    def __init__(self, repo: Repo, hunt_id: str):
        self.repo, self.hunt_id = repo, hunt_id
        self._markers: dict[str, tuple[str, datetime]] = {}

    def lookup(self, host: str, pid: int, ts: float, boot: str | None = None) -> tuple | None:
        return self.repo.baseline_parent_lookup(self.hunt_id, host, pid, ts, boot)

    def _marker(self, host: str) -> tuple[str, datetime] | None:
        if host not in self._markers:
            stored = self.repo.baseline_parent_boot(self.hunt_id, host)
            if stored is not None:
                self._remember_marker(host, stored)
                return stored
        return self._markers.get(host)

    def _remember_marker(self, host: str, marker: tuple[str, datetime]) -> None:
        """Cache common hosts while leaving overflow authoritative on disk."""
        if host in self._markers or len(self._markers) < MARKER_CACHE_CAP:
            self._markers[host] = marker

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
            for host, (boot, latest) in sorted(self._markers.items()):
                self.repo.set_baseline_parent_boot(self.hunt_id, host, boot, latest)
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
                if not self.repo.set_baseline_parent_boot(self.hunt_id, item.host, boot, timestamp):
                    continue
                self._remember_marker(item.host, (boot, timestamp))
            elif marker[0] != boot:
                if marker[1] >= timestamp:
                    continue
                # A newer reboot supersedes every process in the former boot, including buffered rows.
                pending = {key: value for key, value in pending.items() if key[0] != item.host}
                if not self.repo.set_baseline_parent_boot(self.hunt_id, item.host, boot, timestamp):
                    continue
                self._remember_marker(item.host, (boot, timestamp))
            elif timestamp > marker[1]:
                if item.host in self._markers:
                    self._remember_marker(item.host, (boot, timestamp))
                elif not self.repo.set_baseline_parent_boot(self.hunt_id, item.host, boot, timestamp):
                    continue
            key = (item.host, boot, item.pid)
            row = {
                "hunt_id": self.hunt_id, "host": item.host, "boot": boot, "pid": item.pid,
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

    def __init__(self, parents):
        self.parents = parents

    def resolve(self, pending: Pending) -> PendingResolution:
        if pending.ppid in (1, 2):
            return PendingResolution(pending.event_id, (), "parent pid 1/2 out of scope")
        parent = self.parents.lookup(pending.host, pending.ppid, pending.ts.timestamp(), pending.boot)
        if parent is None or not isinstance(parent[1], str) or not parent[1]:
            return PendingResolution(pending.event_id, (), "parent exec before history")
        key = {"child_executable": pending.child_executable, "parent_executable": parent[1]}
        scope = f"host:{pending.host.lower()}"
        resolved = BaselineKey(
            scope_kind="host", scope=scope, key=key,
            key_digest=key_digest_of("bl.exec_pair", "1", scope, key),
            key_id=key_id_of("bl.exec_pair", "1", key),
        )
        return PendingResolution(pending.event_id, (resolved,), None)

    def resolve_all(self, pendings: Iterable[Pending]) -> tuple[PendingResolution, ...]:
        return tuple(self.resolve(pending) for pending in pendings)
