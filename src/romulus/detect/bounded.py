"""Bounded detector state.

A hunt can read hundreds of millions of records over weeks from thousands of hosts, so no playbook may keep state
in memory that grows with the number of records it reads, and no memory bound may cost detection. Per-key state
lives in a KeyedStore (or a SpillList, or an ExecHistory): a hot set in memory, sized by the hunt's memory budget,
and everything else on the playbook's private disk spill, read back when needed and never forgotten. Only disk can
refuse a record: a store's own byte budget (so one flood cannot starve another rule) and the hunt's StateBudget (a
total and a free-space reserve on the stage volume). A refusal makes the rule's coverage partial and names what was
not evaluated (`Playbook.refuse` and `Playbook.note_limit`); it never lowers the lane of what was evaluated. Time
horizons only release what a rule's own semantics define as finished (a join window, a burst interval).

This module also holds the re-delivery guard and the limit record the sweep turns into coverage.
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
SPILL_CACHE_KIB = 4096            # each spill's SQLite page cache (memory beside the hot sets)


# ---- the hunt's state budget -------------------------------------------------------------------------------------
# Defaults; the sweep takes the hunt's values from the settings (romulus.config).
DISK_RESERVE = 2 * 2**30          # free space always left on the stage volume
DISK_TOTAL_FALLBACK = 64 * 2**30  # the hunt's disk total when the stage volume's free space cannot be read
MEMORY_TOTAL = 1536 * 2**20       # the memory every hot set of the hunt shares (an estimate, see KeyedStore)
FREE_CHECK_BYTES = 64 * 2**20     # the stage volume's free space is read again after this much growth
SAMPLE_MIN = 1000                 # hot sets smaller than this are not measured (they are small whatever they hold)
MEM_FACTOR = 3                    # a state's Python objects take about this many times its pickled size
KEY_OVERHEAD = 200                # per hot key: the key, its order number and two table slots


class StateExhausted(RuntimeError):
    """Detector state could not be written to disk at finalize (the stage volume is at its free-space reserve, or a
    write failed): the rule's finalize stops and its window cell says so, instead of the hunt failing."""


class StateBudget:
    """The hunt's ledger for detector state, shared by every playbook's spill.

    Disk: every spill reports how much its file grew. Once the total reaches `disk_total`, or the stage volume's free
    space falls below `reserve`, or a write fails, the budget is spent: the sweep refuses every later record of each
    playbook that holds state (coverage partial, the reason named), so no state grows any more, and nothing already
    held is dropped. The total can be passed by at most one batch's writes, which the reserve absorbs. At finalize
    the total no longer applies (finalize re-reads what consume kept); only the reserve does, and a finalize that
    would need disk below it stops with `StateExhausted`.

    Memory: each store reports an estimate of its hot set's size; while the estimates together exceed
    `memory_total`, a store above its fair share moves its least recently used states to disk at its next trim."""

    def __init__(self, directory=None, *, disk_total: int | None = None, reserve: int = DISK_RESERVE,
                 memory_total: int = MEMORY_TOTAL):
        self.directory = directory
        self.reserve = reserve
        self.memory_total = memory_total
        if not disk_total:
            free = self.free()
            disk_total = DISK_TOTAL_FALLBACK if free is None else max(2**30, (free - reserve) // 2)
        self.disk_total = disk_total
        self.disk_used = 0
        self.over_total = ""            # why the disk total is spent (sticky)
        self.low_space = ""             # why the stage volume is at its reserve (sticky)
        self.broken = ""                # a write failed (sticky)
        self.finalizing = False
        self._since_check = 0
        self._mem: dict[int, int] = {}
        self.mem_used = 0

    # ---- disk ----
    def free(self) -> int | None:
        import shutil
        import tempfile
        path = self.directory if self.directory is not None else tempfile.gettempdir()
        try:
            from pathlib import Path
            probe = Path(path)
            while not probe.exists() and probe.parent != probe:
                probe = probe.parent
            return shutil.disk_usage(probe).free
        except OSError:
            return None

    def check_free(self) -> None:
        free = self.free()
        if free is not None and free < self.reserve and not self.low_space:
            self.low_space = (f"the stage volume's free space ({free / 2**30:.1f} GiB) is below the reserve of "
                              f"{self.reserve / 2**30:.1f} GiB kept free")

    def preflight(self) -> str:
        """Read the stage volume's free space before the sweep; the reason when it is already at the reserve."""
        self.check_free()
        return self.low_space

    def grew(self, nbytes: int) -> None:
        if nbytes <= 0:
            return
        self.disk_used += nbytes
        self._since_check += nbytes
        if self.disk_used >= self.disk_total and not self.over_total:
            self.over_total = (f"detector state on disk reached the hunt's budget of "
                               f"{self.disk_total / 2**30:.1f} GiB")
        if self._since_check >= FREE_CHECK_BYTES:
            self._since_check = 0
            self.check_free()

    def fail(self, reason: str) -> None:
        self.broken = self.broken or reason

    @property
    def spent(self) -> str:
        """Why state may no longer grow during consume ("" while it may)."""
        return self.broken or self.low_space or self.over_total

    def may_write(self) -> bool:
        """Whether state may be moved to disk now."""
        if self.finalizing:
            return not (self.broken or self.low_space)
        return not self.spent

    def blocked(self) -> str:
        return self.broken or self.low_space or ("" if self.finalizing else self.over_total)

    # ---- memory ----
    def hot_allowance(self, store, own: int) -> int | None:
        """Record a store's estimated hot bytes; the bytes it may keep when the hunt is over its memory total."""
        key = id(store)
        previous = self._mem.get(key)
        if previous is None:
            import weakref
            weakref.finalize(store, self.forget, key)
        self._mem[key] = own
        self.mem_used += own - (previous or 0)
        if self.mem_used <= self.memory_total:
            return None
        fair = self.memory_total // max(1, sum(1 for v in self._mem.values() if v))
        if own <= fair:
            return None
        return max(fair, own - (self.mem_used - self.memory_total))

    def forget(self, key: int) -> None:
        self.mem_used -= self._mem.pop(key, 0)


def _budget_of(owner) -> StateBudget:
    return owner.state_budget()


class Spill:
    """A playbook's private on-disk tables for compact rows it must join over the whole hunt (cross-target joins
    cannot be streamed: one target is read whole before the next). Rows are buffered and written in batches; queries
    flush first. It lives in its own directory (mode 0700) under the sweep's stage directory, holds telemetry-derived
    values, and is removed by `close` (the sweep closes it on every exit path it controls; a killed process leaves it
    to the stale-stage cleanup, which goes by directory age: every write and every sweep heartbeat refreshes it).
    Its file's growth is charged to the hunt's state budget."""

    def __init__(self, directory=None, budget: StateBudget | None = None):
        import sqlite3
        import tempfile
        from pathlib import Path
        if directory is not None:
            Path(directory).mkdir(mode=0o700, parents=True, exist_ok=True)
        self._dir = tempfile.mkdtemp(prefix=SPILL_PREFIX, dir=directory)
        self.path = Path(self._dir) / "spill.db"
        self.db = sqlite3.connect(self.path)
        # The page cache is memory outside the hunt's memory budget: SPILL_CACHE_KIB per spill.
        for pragma in ("journal_mode=OFF", "synchronous=OFF", "temp_store=FILE", f"cache_size=-{SPILL_CACHE_KIB}"):
            self.db.execute(f"PRAGMA {pragma}")
        self._page = self.db.execute("PRAGMA page_size").fetchone()[0]
        self.budget = budget if budget is not None else StateBudget(directory)
        self._size = 0
        self._buffers: dict[str, tuple[str, list[tuple]]] = {}

    def table(self, name: str, columns: str) -> None:
        self.db.execute(f"CREATE TABLE {name} ({columns})")
        width = len(columns.split(","))
        self._buffers[name] = (f"INSERT INTO {name} VALUES ({','.join('?' * width)})", [])

    def write(self, sql: str, rows: list[tuple]) -> None:
        """Write rows, charging the file's growth to the budget. Raises StateExhausted when the stage volume is at
        its free-space reserve or a write failed (nothing of a failed batch can be trusted). The hunt's total does
        not stop a write already under way: the sweep stops the rule's records once it is spent."""
        import sqlite3
        reason = self.budget.broken or self.budget.low_space
        if reason:
            raise StateExhausted(reason)
        try:
            self.db.executemany(sql, rows)
        except sqlite3.OperationalError as exc:
            raise self.failed(exc) from exc
        self.grew()

    def failed(self, exc: Exception) -> Exception:
        """The exception to raise for a failed statement: StateExhausted (the budget marked broken) when the stage
        volume could not take the write, else the error itself."""
        text = str(exc).lower()
        if "full" in text or "disk i/o" in text or "no space" in text:
            self.budget.fail(f"writing detector state to the stage volume failed ({exc})")
            return StateExhausted(self.budget.broken)
        return exc

    def check(self) -> None:
        """Charge growth from statements run directly on `db` (finalize's join tables) and stop once the stage
        volume is at its reserve."""
        self.grew()
        self.budget.check_free()
        reason = self.budget.broken or self.budget.low_space
        if reason:
            raise StateExhausted(reason)

    def add(self, name: str, row: tuple) -> None:
        sql, rows = self._buffers[name]
        rows.append(row)
        if len(rows) >= SPILL_BATCH:
            self.write(sql, rows)
            rows.clear()

    def flush(self) -> None:
        for sql, rows in self._buffers.values():
            if rows:
                self.write(sql, rows)
                rows.clear()
        self.db.commit()
        self.touch()

    def grew(self) -> None:
        """Charge the database's growth since the last write to the budget (its pages, written or still in the page
        cache), and mark the spill live."""
        import sqlite3
        try:
            size = self.db.execute("PRAGMA page_count").fetchone()[0] * self._page
        except sqlite3.Error:
            return
        if size > self._size:
            self.budget.grew(size - self._size)
            self._size = size
        self.touch()

    def touch(self) -> None:
        """Mark the spill live, so another hunt's stale-stage cleanup (by directory age) never removes it."""
        with contextlib.suppress(OSError):
            os.utime(self._dir)

    def execute(self, sql: str, params: tuple = ()):
        self.flush()
        return self.db.execute(sql, params)

    def close(self) -> None:
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


# ---- canonical key bytes -------------------------------------------------------------------------------------------
def _norm(value):
    """A value equal keys share whatever their object identity or numeric type (dict equality: 2 == 2.0 == True)."""
    kind = type(value)
    if kind is str or kind is int or value is None or kind is bytes:
        return value
    if kind is bool:
        return int(value)
    if kind is float:
        return int(value) if value.is_integer() else value
    if isinstance(value, tuple):
        return tuple(_norm(item) for item in value)
    if isinstance(value, (frozenset, set)):
        return ("\x00set", tuple(sorted(repr(_norm(item)) for item in value)))
    from datetime import datetime
    if isinstance(value, datetime):
        return ("\x00time", value.timestamp()) if value.tzinfo is not None else ("\x00naive", value.isoformat())
    return ("\x00" + kind.__name__, repr(value))


def key_bytes(key) -> bytes:
    """Canonical bytes of a key: equal keys give equal bytes (no pickle memo, no identity, no numeric type)."""
    kind = type(key)
    if kind is str:
        return b"s" + key.encode("utf-8", "surrogatepass")
    if kind is tuple and all(type(item) is str or type(item) is int or item is None for item in key):
        return b"r" + repr(key).encode("utf-8", "surrogatepass")
    return b"r" + repr(_norm(key)).encode("utf-8", "surrogatepass")


class _KeyFilter:
    """Which keys may be on disk: a Bloom filter over canonical key bytes (no false negatives; about 1% false
    positives at capacity), so looking up a key that was never moved to disk runs no query. Rebuilt larger from the
    table when it passes its capacity; a key read back stays set until then (a false positive costs one query)."""

    __slots__ = ("bits", "capacity", "count", "m")

    def __init__(self, capacity: int = 1 << 16):
        self.capacity = capacity
        self.m = capacity * 10
        self.bits = bytearray((self.m + 7) // 8)
        self.count = 0

    def add(self, kb: bytes) -> None:
        h = hash(kb)
        h1, h2, m, bits = h & 0xFFFFFFFF, ((h >> 32) & 0xFFFFFFFF) | 1, self.m, self.bits
        for i in range(4):
            p = (h1 + i * h2) % m
            bits[p >> 3] |= 1 << (p & 7)
        self.count += 1

    def __contains__(self, kb: bytes) -> bool:
        h = hash(kb)
        h1, h2, m, bits = h & 0xFFFFFFFF, ((h >> 32) & 0xFFFFFFFF) | 1, self.m, self.bits
        for i in range(4):
            p = (h1 + i * h2) % m
            if not bits[p >> 3] & (1 << (p & 7)):
                return False
        return True


class _HotMeasure:
    """The estimate of a hot set's memory: its size times a sampled per-entry cost (pickled size x MEM_FACTOR plus
    KEY_OVERHEAD), sampled again when the hot set has grown or shrunk by a quarter."""

    __slots__ = ("at", "avg")

    def __init__(self):
        self.avg = 0.0
        self.at = 0

    def per_entry(self, values, n: int) -> float:
        if not self.avg or n >= self.at * 1.25 or n <= self.at * 0.75:
            from itertools import islice
            sample = [*islice(values, 16), *islice(reversed(values), 16)]
            sizes = [len(pickle.dumps(state, protocol=4)) for state in sample]
            self.avg = (sum(sizes) / len(sizes)) * MEM_FACTOR + KEY_OVERHEAD if sizes else float(KEY_OVERHEAD)
            self.at = n
        return self.avg


def _hot_limit(store, n: int, values, keep: int | None) -> int:
    """How many entries a hot set keeps at this trim: `keep`, else its count cap lowered to the bytes the hunt's
    memory budget leaves it."""
    if keep is not None:
        return keep
    limit = store.hot_size
    if store.owner is None or n < SAMPLE_MIN:
        return limit
    per = store._measure.per_entry(values, n)
    budget = _budget_of(store.owner)
    allowance = budget.hot_allowance(store, int(n * per))
    if allowance is not None:
        limit = min(limit, max(SAMPLE_MIN, int(allowance // per)))
    return limit


# Per-store disk budget: a store's own share of the hunt's budget, so no one store (a flood of routine records)
# can spend the whole hunt's disk and starve another rule's evidence. Rows are compact pickled per-key states.
DISK_BUDGET = 8 * 2**30
# The count cap of a hot set when its rule names none: memory is governed by the hunt's memory budget (bytes).
HOT_COUNT = 2_000_000
_MISSING = object()


class KeyedStore:
    """Per-key rule state that never forgets: a hot set in memory, least recently used out to a keyed table on disk,
    and brought back when the key is read again. At `trim` (called when a batch ends, so a state read in a batch
    stays valid for the whole batch) memory keeps at most `hot` keys, and fewer when the hunt's memory budget
    (StateBudget) is over its total and this store is above its fair share. Only disk refuses: `put` of a new key
    returns False once the store's rows on disk reach `disk_budget` bytes (the bytes on disk now: a state read back
    leaves the disk until it is moved there again), and the rule refuses that record through its honest coverage
    path; the hunt-level disk budget is enforced by the sweep, which refuses every later record of a rule holding
    state once it is spent.

    Keys are stored as canonical bytes (`key_bytes`), so equal keys meet on disk whatever their object identity. A
    Bloom filter of the keys on disk spares a query for keys that never left memory. Every key keeps the number of
    its first `put`, so `items`, `keys` and `grouped` give first-insertion order (as a dict would) whatever was on
    disk or in memory.

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
        self._seq: dict = {}
        self._next = 0
        self._filter: _KeyFilter | None = None
        self._measure = _HotMeasure()
        self.on_disk = 0
        self.disk_bytes = 0
        self.broken = ""
        self._ready = False
        if owner is not None:
            owner.holds_state = True

    # ---- disk -------------------------------------------------------------------------------------
    def _db(self):
        spill = self.owner.spill()
        if not self._ready:
            spill.db.execute(f"CREATE TABLE IF NOT EXISTS {self.name} (k BLOB PRIMARY KEY, kp BLOB, v BLOB, "
                             f"n INTEGER, c INTEGER, g TEXT, s INTEGER)")
            self._ready = True
        return spill.db

    def _maybe_on_disk(self, key) -> bytes | None:
        """The key's bytes when it may be on disk; None when it certainly is not (no query)."""
        if not self.on_disk:
            return None
        kb = key_bytes(key)
        return kb if self._filter is None or kb in self._filter else None

    def _load(self, key, *, remove: bool):
        """(state, order number) of a key on disk, or None."""
        kb = self._maybe_on_disk(key)
        if kb is None:
            return None
        db = self._db()
        row = db.execute(f"SELECT v, n, s FROM {self.name} WHERE k = ?", (kb,)).fetchone()
        if row is None:
            return None
        if remove:
            db.execute(f"DELETE FROM {self.name} WHERE k = ?", (kb,))
            self.on_disk -= 1
            self.disk_bytes -= row[1]
        return pickle.loads(row[0]), row[2]

    def _rows(self, sql: str):
        if self.broken:
            raise StateExhausted(self.broken)
        cursor = self._db().execute(sql)
        while True:
            batch = cursor.fetchmany(1000)
            if not batch:
                return
            yield from batch

    def _rebuild_filter(self) -> None:
        capacity = 1 << 16
        while capacity < self.on_disk * 2:
            capacity <<= 1
        fresh = _KeyFilter(capacity)
        for (kb,) in self._rows(f"SELECT k FROM {self.name}"):
            fresh.add(kb)
        self._filter = fresh

    # ---- reads and writes ---------------------------------------------------------------------------
    def get(self, key, default=None):
        """The key's state, made hot (read back from disk when it was moved there)."""
        state = self.hot.get(key)
        if state is not None:
            self.hot.move_to_end(key)
            return state
        found = self._load(key, remove=True)
        if found is None:
            return default
        state, self._seq[key] = found
        self.hot[key] = state
        return state

    def peek(self, key, default=None):
        """The key's state without making it hot (for finalize, while iterating)."""
        state = self.hot.get(key)
        if state is not None:
            return state
        found = self._load(key, remove=False)
        return default if found is None else found[0]

    def __contains__(self, key) -> bool:
        return key in self.hot or self._load(key, remove=False) is not None

    def __len__(self) -> int:
        return len(self.hot) + self.on_disk

    def put(self, key, state) -> bool:
        """Hold the key's state (new, or replacing the held one); False when a new key meets the spent disk budget
        (the caller refuses the record). Replacing a key held on disk is not a new key."""
        if key in self.hot:
            self.hot[key] = state
            self.hot.move_to_end(key)
            return True
        found = self._load(key, remove=True)
        if found is not None:
            seq = found[1]
        elif self.disk_bytes >= self.disk_budget:
            return False
        else:
            seq = self._next
            self._next += 1
        self.hot[key] = state
        self._seq[key] = seq
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
        if state is not None:
            self._seq.pop(key, None)
            return state
        found = self._load(key, remove=True)
        return default if found is None else found[0]

    def trim(self, keep: int | None = None) -> None:
        """Write the least recently used states beyond what memory may keep (or beyond `keep`) to disk. When the
        hunt's budget blocks writes, the states stay in memory during consume (the sweep refuses the rule's later
        records, so they grow no more) and finalize stops with StateExhausted."""
        n = len(self.hot)
        if self.owner is None or n == 0:
            return
        limit = _hot_limit(self, n, self.hot.values(), keep)
        if n <= limit:
            return
        budget = _budget_of(self.owner)
        if not budget.may_write():
            if budget.finalizing or keep is not None:
                raise StateExhausted(budget.blocked())
            return
        spill = self.owner.spill()
        self._db()
        if self._filter is None:
            self._filter = _KeyFilter()
        evicted, rows, nbytes = [], [], 0
        while len(self.hot) > limit:
            key, state = self.hot.popitem(last=False)
            seq = self._seq.pop(key)
            evicted.append((key, state, seq))
            kb = key_bytes(key)
            blob = pickle.dumps(state, protocol=4)
            nbytes += len(blob)
            rows.append((kb, pickle.dumps(key, protocol=4), blob, len(blob),
                         1 if self.candidate is None or self.candidate(state) else 0,
                         None if self.group is None else self.group(key), seq))
        try:
            spill.write(f"INSERT OR REPLACE INTO {self.name} VALUES (?, ?, ?, ?, ?, ?, ?)", rows)
        except StateExhausted:
            for key, state, seq in reversed(evicted):      # nothing is dropped: back to memory, oldest first
                self.hot[key] = state
                self.hot.move_to_end(key, last=False)
                self._seq[key] = seq
            if budget.broken:
                self.broken = budget.broken                 # a partial write: the table can no longer be trusted
            if budget.finalizing or keep is not None:
                raise
            return
        for row in rows:
            self._filter.add(row[0])
        self.disk_bytes += nbytes
        self.on_disk += len(rows)
        if self._filter.count > self._filter.capacity:
            self._rebuild_filter()
        if self._measure.avg:
            budget.hot_allowance(self, int(len(self.hot) * self._measure.avg))

    # ---- finalize -------------------------------------------------------------------------------------
    def _hot_ordered(self, candidates: bool):
        return sorted(((self._seq[key], key, state) for key, state in self.hot.items()
                       if not candidates or self.candidate is None or self.candidate(state)), key=_first)

    def items(self, *, candidates: bool = False):
        """Every (key, state) in first-insertion order, from memory and disk a batch at a time (read only)."""
        import heapq
        hot = self._hot_ordered(candidates)
        if not self.on_disk:
            for _seq, key, state in hot:
                yield key, state
            return
        where = " WHERE c = 1" if candidates else ""
        disk = ((s, pickle.loads(kp), pickle.loads(v))
                for kp, v, s in self._rows(f"SELECT kp, v, s FROM {self.name}{where} ORDER BY s"))
        for _seq, key, state in heapq.merge(hot, disk, key=_first):
            yield key, state

    def keys(self, *, candidates: bool = False) -> list:
        """Every key (or every candidate's key) in first-insertion order. Holds the keys, not the states."""
        import heapq
        hot = [(seq, key) for seq, key, _state in self._hot_ordered(candidates)]
        if not self.on_disk:
            return [key for _seq, key in hot]
        where = " WHERE c = 1" if candidates else ""
        disk = ((s, pickle.loads(kp)) for kp, s in self._rows(f"SELECT kp, s FROM {self.name}{where} ORDER BY s"))
        return [key for _seq, key in heapq.merge(hot, disk, key=_first)]

    def grouped(self):
        """Every (key, state) ordered by the group column, then first insertion, so a group's states arrive
        together. With anything on disk, all is moved there first and nothing is held but the group being read."""
        if self.owner is None or not self.on_disk:
            for _order, key, state in sorted(((self.group(key), self._seq.get(key, 0)), key, state)
                                             for key, state in self.hot.items()):
                yield key, state
            return
        self.trim(0)
        for kp, v in self._rows(f"SELECT kp, v FROM {self.name} ORDER BY g, s"):
            yield pickle.loads(kp), pickle.loads(v)

    def clear(self) -> None:
        self.hot.clear()
        self._seq.clear()
        if self.on_disk and self.owner is not None and self._ready and self.owner._spill is not None:
            self._db().execute(f"DELETE FROM {self.name}")
        self.on_disk = self.disk_bytes = 0
        self._filter = None
        self.broken = ""
        self._ready = False             # the spill may be closed and recreated: create the table again on use
        if self.owner is not None and self.owner.budget is not None:
            self.owner.budget.forget(id(self))

    def __eq__(self, other: object) -> bool:
        """Equal to a dict holding the same keys and states (read without making them hot)."""
        if isinstance(other, dict):
            return len(self) == len(other) and all(self.peek(key, _MISSING) == state for key, state in other.items())
        return NotImplemented

    __hash__ = None


class SpillList:
    """An append-only list of compact records that never forgets: in memory up to `hot` (fewer when the hunt's
    memory budget is over its total), the rest on disk, read back in arrival order, or in the order of a
    (number, text) key given at append (`ordered`). Only the disk byte budget refuses (`append` returns False)."""

    def __init__(self, owner, name: str, hot: int, *, disk_budget: int | None = None):
        self.owner = owner
        self.name = name
        self.hot_size = hot
        self.disk_budget = DISK_BUDGET if disk_budget is None else disk_budget
        self.buffer: list = []                  # (order, record)
        self._measure = _HotMeasure()
        self.on_disk = 0
        self.disk_bytes = 0
        self.broken = ""
        self._ready = False
        if owner is not None:
            owner.holds_state = True

    def __len__(self) -> int:
        return len(self.buffer) + self.on_disk

    def append(self, record, order: tuple = (0.0, "")) -> bool:
        if self.disk_bytes >= self.disk_budget:
            return False
        self.buffer.append((order, record))
        return True

    def trim(self, keep: int | None = None) -> None:
        """Write the records beyond what memory may keep (or beyond `keep`) to disk (called when a batch ends)."""
        n = len(self.buffer)
        if self.owner is None or n == 0:
            return
        limit = _hot_limit(self, n, _Records(self.buffer), keep)
        if n <= limit:
            return
        budget = _budget_of(self.owner)
        if not budget.may_write():
            if budget.finalizing or keep is not None:
                raise StateExhausted(budget.blocked())
            return
        spill = self.owner.spill()
        if not self._ready:
            spill.db.execute(f"CREATE TABLE IF NOT EXISTS {self.name} (seq INTEGER PRIMARY KEY, o1, o2, v BLOB)")
            self._ready = True
        rows, nbytes = [], 0
        for i, ((o1, o2), record) in enumerate(self.buffer):
            blob = pickle.dumps(record, protocol=4)
            nbytes += len(blob)
            rows.append((self.on_disk + i, o1, o2, blob))
        try:
            spill.write(f"INSERT INTO {self.name} VALUES (?, ?, ?, ?)", rows)
        except StateExhausted:
            if budget.broken:
                self.broken = budget.broken
            if budget.finalizing or keep is not None:
                raise
            return
        self.disk_bytes += nbytes
        self.on_disk += len(rows)
        self.buffer = []

    def _disk(self, order_by: str):
        if self.broken:
            raise StateExhausted(self.broken)
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
        """Every record in (number, text) order of its append key, then arrival (with anything on disk, all is moved
        there first)."""
        if self.owner is None or not self.on_disk:
            yield from [record for _order, record in sorted(self.buffer, key=lambda item: item[0])]
            return
        self.trim(0)
        yield from self._disk("o1, o2, seq")

    def clear(self) -> None:
        if self.on_disk and self._ready and self.owner._spill is not None:
            self.owner.spill().db.execute(f"DELETE FROM {self.name}")
        self.buffer, self.on_disk, self.disk_bytes = [], 0, 0
        self.broken = ""
        self._ready = False
        if self.owner is not None and self.owner.budget is not None:
            self.owner.budget.forget(id(self))


class _Records:
    """The records of a SpillList buffer as a sized, reversible view (for sampling)."""

    __slots__ = ("buffer",)

    def __init__(self, buffer: list):
        self.buffer = buffer

    def __iter__(self):
        return (record for _order, record in self.buffer)

    def __reversed__(self):
        return (record for _order, record in reversed(self.buffer))


class ExecHistory:
    """Exec records per (host, pid), for lineage. A process's entries are kept in time order (stable), its latest
    `per_key` (pids are reused). Memory holds the most recently used processes (`capacity` at most, fewer under the
    hunt's memory budget); the rest are on disk and read back when a lineage walk reaches them, so a lookup is exact
    however old the process. Without an owner it is memory only (expansion and baseline callers, whose input is
    bounded)."""

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
        insort(held, entry, key=_first)          # updated in place: the store holds this list
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
