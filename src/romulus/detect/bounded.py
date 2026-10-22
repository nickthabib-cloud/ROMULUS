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

import contextlib
import json
import os
import pickle
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
        self.touch()

    def touch(self) -> None:
        """Mark the spill live, so another hunt's stale-stage cleanup (by directory age) never removes it."""
        with contextlib.suppress(OSError):
            os.utime(self._dir)

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


def scalar(value):
    """A value SQLite can bind: scalars as they are, anything else (a list, a mapping) as its JSON text."""
    if value is None or isinstance(value, (str, int, float)):
        return value
    return json.dumps(value, sort_keys=True, default=str)


# Per-store disk budget: the only limit that may refuse a record. Rows are compact pickled per-key states.
DISK_BUDGET = 8 * 2**30


class KeyedStore:
    """Per-key rule state that never forgets: a hot set in memory, least recently used out to a keyed table on disk,
    and brought back when the key is read again. Memory holds at most `hot` keys between batches (`trim`, called
    when a batch ends, so a state read in a batch stays valid for the whole batch). Only the disk byte budget
    refuses: `put` of a new key returns False once the store's rows reach `disk_budget` bytes, and the rule refuses
    that record through its honest coverage path.

    `candidate(state)` (optional) is kept as a column, so finalize can read only states that can still be reported;
    `group(key)` (optional) is kept as a text column, so finalize can read states grouped. Without an owner the
    store is memory only (callers outside the sweep whose input is bounded)."""

    def __init__(self, owner, name: str, hot: int, *, disk_budget: int | None = None, candidate=None, group=None):
        self.owner = owner
        self.name = name
        self.hot_size = hot
        self.disk_budget = DISK_BUDGET if disk_budget is None else disk_budget
        self.candidate = candidate
        self.group = group
        self.hot: OrderedDict = OrderedDict()
        self.on_disk = 0
        self.disk_bytes = 0
        self._ready = False

    # ---- disk -------------------------------------------------------------------------------------
    def _db(self):
        spill = self.owner.spill()
        if not self._ready:
            spill.db.execute(f"CREATE TABLE IF NOT EXISTS {self.name} (k BLOB PRIMARY KEY, v BLOB, n INTEGER, "
                             f"c INTEGER, g TEXT)")
            self._ready = True
        return spill.db

    @staticmethod
    def _k(key) -> bytes:
        return pickle.dumps(key, protocol=4)

    def _load(self, key, *, remove: bool):
        if not self.on_disk:
            return None
        db = self._db()
        row = db.execute(f"SELECT v, n FROM {self.name} WHERE k = ?", (self._k(key),)).fetchone()
        if row is None:
            return None
        if remove:
            db.execute(f"DELETE FROM {self.name} WHERE k = ?", (self._k(key),))
            self.on_disk -= 1
            self.disk_bytes -= row[1]
        return pickle.loads(row[0])

    def _rows(self, sql: str):
        cursor = self._db().execute(sql)
        while True:
            batch = cursor.fetchmany(1000)
            if not batch:
                return
            yield from batch

    # ---- reads and writes ---------------------------------------------------------------------------
    def get(self, key, default=None):
        """The key's state, made hot (read back from disk when it was moved there)."""
        state = self.hot.get(key)
        if state is not None:
            self.hot.move_to_end(key)
            return state
        state = self._load(key, remove=True)
        if state is None:
            return default
        self.hot[key] = state
        return state

    def peek(self, key, default=None):
        """The key's state without making it hot (for finalize, while iterating)."""
        state = self.hot.get(key)
        if state is not None:
            return state
        state = self._load(key, remove=False)
        return default if state is None else state

    def __contains__(self, key) -> bool:
        return key in self.hot or self._load(key, remove=False) is not None

    def __len__(self) -> int:
        return len(self.hot) + self.on_disk

    def put(self, key, state) -> bool:
        """Hold a new key's state; False when the disk budget is spent (the caller refuses the record)."""
        if key not in self.hot and self.disk_bytes >= self.disk_budget:
            return False
        self.hot[key] = state
        self.hot.move_to_end(key)
        return True

    def setdefault(self, key, factory):
        """The key's state, created by `factory` when new; None when the disk budget refuses a new key."""
        state = self.get(key)
        if state is None:
            state = factory()
            if not self.put(key, state):
                return None
        return state

    def pop(self, key, default=None):
        state = self.hot.pop(key, None)
        if state is None:
            state = self._load(key, remove=True)
        return default if state is None else state

    def trim(self, keep: int | None = None) -> None:
        """Write the least recently used states beyond the hot size (or `keep`) to disk."""
        limit = self.hot_size if keep is None else keep
        if len(self.hot) <= limit or self.owner is None:
            return
        db = self._db()
        rows = []
        while len(self.hot) > limit:
            key, state = self.hot.popitem(last=False)
            blob = pickle.dumps(state, protocol=4)
            rows.append((self._k(key), blob, len(blob), 1 if self.candidate is None or self.candidate(state) else 0,
                         None if self.group is None else self.group(key)))
            self.disk_bytes += len(blob)
        db.executemany(f"INSERT OR REPLACE INTO {self.name} VALUES (?, ?, ?, ?, ?)", rows)
        self.on_disk += len(rows)
        self.owner.spill().touch()

    # ---- finalize -------------------------------------------------------------------------------------
    def items(self, *, candidates: bool = False):
        """Every (key, state), hot ones first then from disk a batch at a time (read only)."""
        for key, state in list(self.hot.items()):
            if not candidates or self.candidate is None or self.candidate(state):
                yield key, state
        if self.on_disk:
            where = " WHERE c = 1" if candidates else ""
            for k, v in self._rows(f"SELECT k, v FROM {self.name}{where} ORDER BY rowid"):
                yield pickle.loads(k), pickle.loads(v)

    def keys(self, *, candidates: bool = False) -> list:
        """Every key (or every candidate's key). Holds the keys, not the states."""
        out = [key for key, state in self.hot.items()
               if not candidates or self.candidate is None or self.candidate(state)]
        if self.on_disk:
            where = " WHERE c = 1" if candidates else ""
            out += [pickle.loads(k) for (k,) in self._rows(f"SELECT k FROM {self.name}{where}")]
        return out

    def grouped(self):
        """Every (key, state) ordered by the group column, all moved to disk first, so a group's states arrive
        together and nothing is held but the group being read."""
        if self.owner is None:
            yield from sorted(self.hot.items(), key=lambda item: self.group(item[0]))
            return
        self.trim(0)
        for k, v in self._rows(f"SELECT k, v FROM {self.name} ORDER BY g, rowid"):
            yield pickle.loads(k), pickle.loads(v)

    def clear(self) -> None:
        self.hot.clear()
        if self.on_disk and self.owner is not None and self._ready:
            self._db().execute(f"DELETE FROM {self.name}")
        self.on_disk = self.disk_bytes = 0


class SpillList:
    """An append-only list of compact records that never forgets: at most `hot` in memory, the rest on disk, read
    back in arrival order, or in the order of a (number, text) key given at append (`ordered`). Only the disk byte
    budget refuses (`append` returns False)."""

    def __init__(self, owner, name: str, hot: int, *, disk_budget: int | None = None):
        self.owner = owner
        self.name = name
        self.hot_size = hot
        self.disk_budget = DISK_BUDGET if disk_budget is None else disk_budget
        self.buffer: list = []                  # (order, record)
        self.on_disk = 0
        self.disk_bytes = 0
        self._ready = False

    def __len__(self) -> int:
        return len(self.buffer) + self.on_disk

    def append(self, record, order: tuple = (0.0, "")) -> bool:
        if self.disk_bytes >= self.disk_budget:
            return False
        self.buffer.append((order, record))
        return True

    def trim(self, keep: int | None = None) -> None:
        """Write the records beyond the hot size (or `keep`) to disk (called when a batch ends)."""
        limit = self.hot_size if keep is None else keep
        if len(self.buffer) <= limit or self.owner is None:
            return
        db = self.owner.spill().db
        if not self._ready:
            db.execute(f"CREATE TABLE IF NOT EXISTS {self.name} (seq INTEGER PRIMARY KEY, o1, o2, v BLOB)")
            self._ready = True
        rows = []
        for (o1, o2), record in self.buffer:
            blob = pickle.dumps(record, protocol=4)
            self.disk_bytes += len(blob)
            rows.append((self.on_disk, o1, o2, blob))
            self.on_disk += 1
        db.executemany(f"INSERT INTO {self.name} VALUES (?, ?, ?, ?)", rows)
        self.buffer = []
        self.owner.spill().touch()

    def _disk(self, order_by: str):
        cursor = self.owner.spill().db.execute(f"SELECT v FROM {self.name} ORDER BY {order_by}")
        while True:
            batch = cursor.fetchmany(1000)
            if not batch:
                return
            for (blob,) in batch:
                yield pickle.loads(blob)

    def __iter__(self):
        if self.on_disk:
            yield from self._disk("seq")
        yield from [record for _order, record in list(self.buffer)]

    def ordered(self):
        """Every record in (number, text) order of its append key, then arrival (all moved to disk first)."""
        if self.owner is None:
            yield from [record for _order, record in sorted(self.buffer, key=lambda item: item[0])]
            return
        self.trim(0)
        if self.on_disk:
            yield from self._disk("o1, o2, seq")

    def clear(self) -> None:
        if self.on_disk and self._ready:
            self.owner.spill().db.execute(f"DELETE FROM {self.name}")
        self.buffer, self.on_disk, self.disk_bytes = [], 0, 0


class ExecHistory:
    """Exec records per (host, pid), for lineage. A process's entries are kept in time order (stable), its latest
    `per_key` (pids are reused). Memory holds the `capacity` most recently used processes; the rest are on disk and
    read back when a lineage walk reaches them, so a lookup is exact however old the process. Without an owner it is
    memory only (expansion and baseline callers, whose input is bounded)."""

    __slots__ = ("per_key", "store")

    def __init__(self, capacity: int, per_key: int, owner=None, name: str = "exec_history"):
        self.per_key = per_key
        self.store = KeyedStore(owner, name, capacity)

    def __len__(self) -> int:
        return len(self.store)

    @property
    def evicted(self) -> int:
        """Processes whose records are on disk now (read back when needed; never forgotten)."""
        return self.store.on_disk

    def add(self, key: tuple, entry: tuple) -> None:
        held = self.store.get(key)
        if held is None:
            held = []
            if not self.store.put(key, held):
                self.store.owner.note_limit("exec_history", "exec records on disk reached the disk budget; a later "
                                                            "process's lineage is not recorded")
                return
        insort(held, entry, key=_first)
        if len(held) > self.per_key:
            del held[0]

    def get(self, key: tuple, *, touch: bool = False) -> list[tuple]:
        """The process's entries in time order (read back from disk when it was moved there)."""
        return self.store.get(key) or []

    def trim(self) -> None:
        self.store.trim()

    def clear(self) -> None:
        self.store.clear()


def _first(entry: tuple):
    return entry[0]
