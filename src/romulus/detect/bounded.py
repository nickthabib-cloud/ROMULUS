"""Bounded detector state.

A hunt can read hundreds of millions of records over weeks from thousands of hosts, so no playbook may keep state
that grows with the number of records it reads. Each structure is bounded in one of four ways:

- a time horizon the rule's own semantics define (a join window, a protocol timeout, a burst interval);
- a cap sized by an explicit memory budget; reaching it makes the rule's coverage partial and names what was not
  evaluated (`Playbook.refuse` and `Playbook.note_limit`), and it never lowers the lane of what was evaluated;
- the sweep's on-disk event stage (full events on disk, compact keys in memory);
- streaming.

This module holds the shared pieces: the re-delivery guard and the limit record the sweep turns into coverage.
"""
from __future__ import annotations

from bisect import insort
from collections import OrderedDict
from dataclasses import dataclass

# Ids remembered by the re-delivery guard per generation (two generations are kept). The sweep reads each raw record
# once: partitions are disjoint half-open windows of one time field per target, and a capped fetch is discarded
# before any playbook sees it. The guard therefore protects only against a batch handed over again, which it
# catches whenever fewer than this many other ids arrived in between. Budget: about 100 bytes per id, so at most
# about 13 MB per playbook.
RECENT_IDS = 65_536


class RecentIds:
    """A duplicate check over recently seen ids, in two generations of at most `limit` ids each: an id is
    recognised again while fewer than `limit` other ids arrived after it. Memory is at most 2 x `limit` ids."""

    __slots__ = ("_current", "_previous", "limit")

    def __init__(self, limit: int | None = None):
        self.limit = RECENT_IDS if limit is None else limit
        self._current: set[str] = set()
        self._previous: set[str] = set()

    def __contains__(self, key: object) -> bool:
        return key in self._current or key in self._previous

    def add(self, key: str) -> None:
        if key in self._current:
            return
        self._current.add(key)
        if len(self._current) >= self.limit:
            self._previous, self._current = self._current, set()

    def __len__(self) -> int:
        return len(self._current) + len(self._previous)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, RecentIds):
            return self._current | self._previous == other._current | other._previous
        if isinstance(other, (set, frozenset)):
            return self._current | self._previous == other
        return NotImplemented

    __hash__ = None                 # mutable, like a set

    def clear(self) -> None:
        self._current.clear()
        self._previous.clear()


@dataclass
class Limit:
    """One budget a playbook reached: what it bounds, and how many records it left unevaluated (0 when the cap
    only reduced what the claims can say, such as an exact count becoming a lower bound)."""
    text: str
    records: int = 0
    hits: int = 0

    def reason(self) -> str:
        if self.records:
            return f"state limit: {self.text} ({self.records} record(s) not evaluated)"
        return f"state limit: {self.text}"


class HeldExamples:
    """The cited records of one group. Each is held as its event only until the sweep has handed that event to the
    disk stage (`staged`), then as its (time, id) reference, so a group costs references, not events. With
    `earliest` it keeps the `limit` earliest records by (time, id) whatever the arrival order; otherwise the first
    `limit` records to arrive, in arrival order."""

    __slots__ = ("earliest", "items", "limit")

    def __init__(self, limit: int, earliest: bool = False):
        self.limit = limit
        self.earliest = earliest
        self.items: list[list] = []                     # [(time, id), event or None]

    def __len__(self) -> int:
        return len(self.items)

    def offer(self, event) -> bool:
        """Hold the record if it is among those kept; True when it entered (so it must reach the stage)."""
        ref = (event.ts, event.id)
        if not self.earliest:
            if len(self.items) >= self.limit:
                return False
            self.items.append([ref, event])
            return True
        if len(self.items) >= self.limit and ref >= self.items[-1][0]:
            return False
        if len(self.items) >= self.limit:
            self.items.pop()
        self.items.append([ref, event])
        self.items.sort(key=lambda item: item[0])
        return True

    def staged(self) -> None:
        """Every held event has reached the stage: keep its reference only."""
        for item in self.items:
            item[1] = None

    def ids(self) -> list[str]:
        return [item[0][1] for item in self.items]

    def events(self, load) -> list:
        """The held records as events, in held order: events not yet staged as they are, the rest from `load`."""
        wanted = [item[0][1] for item in self.items if item[1] is None]
        found = {event.id: event for event in load(wanted)} if wanted else {}
        missing = [event_id for event_id in wanted if event_id not in found]
        if missing:
            raise LookupError(f"{len(missing)} cited event(s) absent from the stage, e.g. {missing[0]}")
        return [item[1] if item[1] is not None else found[item[0][1]] for item in self.items]


class ExecHistory:
    """Exec records per (host, pid), for lineage. A hunt over weeks on thousands of hosts sees a new pid for almost
    every exec, so the history is held for at most `capacity` processes, least recently used first out: adding an
    exec or finding a process as an ancestor makes it recent, so a long-lived parent that keeps starting children
    stays. Each process keeps its latest `per_key` execs (pids are reused). A rule can `pin` the entries a record's
    lineage rested on when it read the record, so a finding made at finalize still sees them after release.

    A released process makes later lineage walks stop early; `evicted` counts releases so the rule can say so. An
    entry is a tuple whose first element is its time; entries of one process are kept in time order (stable)."""

    __slots__ = ("capacity", "entries", "evicted", "per_key", "pinned")

    def __init__(self, capacity: int, per_key: int):
        self.capacity = capacity
        self.per_key = per_key
        self.entries: OrderedDict[tuple, list[tuple]] = OrderedDict()
        self.pinned: dict[tuple, list[tuple]] = {}
        self.evicted = 0

    def __len__(self) -> int:
        return len(self.entries)

    def add(self, key: tuple, entry: tuple) -> None:
        held = self.entries.get(key)
        if held is None:
            held = self.entries[key] = []
        else:
            self.entries.move_to_end(key)
        insort(held, entry, key=_first)
        if len(held) > self.per_key:
            del held[0]
        while len(self.entries) > self.capacity:
            self.entries.popitem(last=False)
            self.evicted += 1

    def get(self, key: tuple, *, touch: bool = False) -> list[tuple]:
        """The process's entries in time order (held and pinned); `touch` makes it recent."""
        held = self.entries.get(key)
        if held is not None and touch:
            self.entries.move_to_end(key)
        pinned = self.pinned.get(key)
        if not pinned:
            return held or []
        if not held:
            return pinned
        merged = list(held)
        for entry in pinned:
            if entry not in merged:
                insort(merged, entry, key=_first)
        return merged

    def pin(self, key: tuple, entries: list[tuple]) -> None:
        """Keep these entries of a process beyond its release (a cited record's lineage)."""
        if not entries:
            return
        kept = self.pinned.setdefault(key, [])
        for entry in entries:
            if entry not in kept:
                insort(kept, entry, key=_first)

    def clear(self) -> None:
        self.entries.clear()
        self.pinned.clear()


def _first(entry: tuple):
    return entry[0]


SPILL_PREFIX = "romulus-stage-spill-"     # the sweep clears stale stage directories by this prefix
SPILL_BATCH = 5000


class Spill:
    """A playbook's private on-disk tables for compact rows it must join over the whole hunt (cross-target joins
    cannot be streamed: one target is read whole before the next). Rows are buffered and written in batches; queries
    flush first. It lives in its own directory (mode 0700) under the sweep's stage directory, holds telemetry-derived
    values, and is removed by `close` (the sweep closes it on every exit path it controls; a killed process leaves it
    to the stale-stage cleanup)."""

    def __init__(self, directory=None):
        import sqlite3
        import tempfile
        from pathlib import Path
        if directory is not None:
            Path(directory).mkdir(mode=0o700, parents=True, exist_ok=True)
        self._dir = tempfile.mkdtemp(prefix=SPILL_PREFIX, dir=directory)
        self.db = sqlite3.connect(Path(self._dir) / "spill.db")
        for pragma in ("journal_mode=OFF", "synchronous=OFF", "temp_store=FILE", "cache_size=-32768"):
            self.db.execute(f"PRAGMA {pragma}")
        self._buffers: dict[str, tuple[str, list[tuple]]] = {}

    def table(self, name: str, columns: str) -> None:
        self.db.execute(f"CREATE TABLE {name} ({columns})")
        width = len(columns.split(","))
        self._buffers[name] = (f"INSERT INTO {name} VALUES ({','.join('?' * width)})", [])

    def add(self, name: str, row: tuple) -> None:
        sql, rows = self._buffers[name]
        rows.append(row)
        if len(rows) >= SPILL_BATCH:
            self.db.executemany(sql, rows)
            rows.clear()

    def flush(self) -> None:
        for sql, rows in self._buffers.values():
            if rows:
                self.db.executemany(sql, rows)
                rows.clear()
        self.db.commit()

    def execute(self, sql: str, params: tuple = ()):
        self.flush()
        return self.db.execute(sql, params)

    def close(self) -> None:
        import contextlib
        import shutil
        if self.db is not None:
            with contextlib.suppress(Exception):
                self.db.close()
            self.db = None
        shutil.rmtree(self._dir, ignore_errors=True)
