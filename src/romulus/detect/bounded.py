"""Bounded detector state.

A hunt can read hundreds of millions of records over weeks from thousands of hosts, so no playbook may keep state
in memory that grows with the number of records it reads, and no memory bound may cost detection. Per-key state
lives in a KeyedStore (or a SpillList, or an ExecHistory): a hot set in memory, sized by the hunt's memory budget,
and everything else on the playbook's private disk spill, read back when needed and never forgotten. Only the hunt's
physical byte ceiling and the free-space reserve can refuse a record. A refusal makes the rule's coverage partial and names what was
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
from functools import wraps

# Ids remembered by the re-delivery guard per generation (two generations are kept). The sweep reads each raw record
# once: partitions are disjoint half-open windows of one time field per target, and a capped fetch is discarded
# before any playbook sees it. The guard therefore protects only against a batch handed over again, which it
# catches whenever fewer than this many other ids arrived in between. Budget: about 100 bytes per id, so at most
# about 13 MB per playbook.
RECENT_IDS = 65_536


def reclaiming_write(method):
    """Give a transactional writer one pressure-plan lifetime across all of its FULL retries."""
    @wraps(method)
    def wrapped(self, *args, **kwargs):
        budget = getattr(self, "budget", None)
        if budget is None:
            owner = getattr(self, "owner", None)
            budget = owner.state_budget() if owner is not None else None
        with budget.reclamation_write() if budget is not None else contextlib.nullcontext():
            return method(self, *args, **kwargs)
    return wrapped


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


class CitationUnavailable(LookupError):
    """A whole-hunt byte refusal left one finding without its compact citation state."""


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
            raise CitationUnavailable(f"{len(missing)} cited event(s) absent from the stage, e.g. {missing[0]}")
        return [item[1] if item[1] is not None else found[item[0][1]] for item in self.items]


SPILL_PREFIX = "romulus-stage-spill-"     # the sweep clears stale stage directories by this prefix
SPILL_BATCH = 5000
SPILL_CACHE_KIB = 4096            # each spill's SQLite page cache (memory beside the hot sets)


# ---- the hunt's state budget -------------------------------------------------------------------------------------
# Defaults; the sweep takes the hunt's values from the settings (romulus.config).
DISK_RESERVE = 2 * 2**30          # the least free space always left on the stage volume
RESERVE_SHARE = 0.15              # ... and at least this share of the volume's size (other services share it)
TOTAL_SHARE = 0.10                # the automatic disk total: at most this share of the volume's size
DISK_TOTAL_FLOOR = 256 * 2**20    # the automatic disk total never goes below this (the reserve still applies)
DISK_TOTAL_FALLBACK = 16 * 2**30  # the hunt's disk total when the stage volume cannot be read
MEMORY_TOTAL = 1536 * 2**20       # the memory every hot set of the hunt shares (an estimate, see KeyedStore)
SAMPLE = 32                       # states sized at each measurement of a hot set, drawn across the whole set
REMEASURE_TRIMS = 16              # a hot set is measured again at least every this many trims
KEY_OVERHEAD = 200                # per hot key: the key, its order number and two table slots
HOT_FLOOR = 16                    # the memory budget never moves a hot set below this many states


class StateExhausted(RuntimeError):
    """Detector state could not be written to disk at finalize (the stage volume is at its free-space reserve, or a
    write failed): the rule publishes what it can without disk (`Playbook.finalize_fallback`) and its window cell
    says what was not computed, instead of the hunt failing."""


def volume_usage(directory) -> tuple[int, int] | None:
    """(size, free bytes) of the volume holding `directory` (its nearest existing parent), or None."""
    import shutil
    import tempfile
    from pathlib import Path
    probe = Path(directory if directory is not None else tempfile.gettempdir())
    try:
        while not probe.exists() and probe.parent != probe:
            probe = probe.parent
        usage = shutil.disk_usage(probe)
    except OSError:
        return None
    return usage.total, usage.free


class Account:
    """One store's bytes on disk (a keyed store, a record list, a join's rows, the event stage)."""

    __slots__ = ("evict", "evict_references", "name", "strong", "used", "weight", "yields")

    def __init__(self, name: str, strong: bool, weight: int = 1, yields: bool = False):
        self.name = name
        self.strong = strong            # a strong-indicator rule's store (see `Playbook.state_slice`)
        self.used = 0
        self.weight = 0 if yields else weight   # floors this store holds: one per rule it serves
        self.yields = yields            # a store no detection needs (see `KeyedStore.yields`): no floor, gives way first
        self.evict = None               # a yielding store's evict(nbytes) -> bytes freed (its oldest records first)
        self.evict_references = None    # mandatory citation references: only after an actual SQLite FULL


class StateBudget:
    """The physical disk ceiling and bounded hot sets shared by every detector.

    Detection uses all physically available space, including idle floors. Citation caches yield first: optional
    bodies, then compact references when necessary. Floors size cache retention and describe owners' shares; they
    never reserve unused bytes or refuse detection based on estimated payload sizes. Each SQLite writer caps its
    pages against the live physical ledger and volume reserve. A refusal affects that store alone; existing states
    remain readable and independently computed positives still publish.

    Every hot set reports estimated bytes. Above the memory budget, its least recently used states spill to disk;
    if physical capacity prevents that write, the accepted states stay bounded in memory and later new keys refuse.
    """

    def __init__(self, directory=None, *, disk_total: int | None = None, reserve: int | None = None,
                 reserve_floor: int = DISK_RESERVE, memory_total: int = MEMORY_TOTAL):
        self.directory = directory
        usage = volume_usage(directory)
        if reserve is None:             # the larger of the floor and RESERVE_SHARE of the volume
            reserve = max(reserve_floor, int(usage[0] * RESERVE_SHARE)) if usage else reserve_floor
        self.reserve = reserve
        self.memory_total = memory_total
        if not disk_total:
            if usage is None:
                disk_total = DISK_TOTAL_FALLBACK
            else:
                disk_total = max(DISK_TOTAL_FLOOR, min((usage[1] - self.reserve) // 2, int(usage[0] * TOTAL_SHARE)))
        self.disk_total = disk_total
        self.accounts: list[Account] = []
        self.stores = 0                 # stores the floors are planned for (0: as many as have accounts)
        self.pool_used = 0              # bytes the detection stores hold above their floors (yielding stores: none)
        self.full: dict[str, str] = {}  # stores that refused a new key, and why
        self.yielding = False           # a yielding store has an account: the budget is watched from half the headroom
        self.yield_used = 0             # the yielding stores' bytes (inside the total, outside the detection test)
        self._evicting = False
        self.forced: list = []          # (predicate on an Account, reason): stores forced into no-growth mode (tests)
        self.calm = True                # no limit reached: the per-record check is one attribute read
        self.disk_used = 0              # the spills' real database growth (for the summary)
        self._physical: dict[tuple, tuple[int, int]] = {}  # live file/owner bytes and guaranteed-floor weights
        self._physical_released = 0
        self._capacity_refusals: set[int] = set()
        self.over_total = ""            # every store in no-growth mode at once (sticky; probes and tests)
        self.low_space = ""             # why the stage volume is at its reserve (sticky)
        self.broken = ""                # a write failed (sticky)
        self.finalizing = False
        self._mem: dict[int, int] = {}
        self.mem_used = 0

    _REASONS = frozenset({"over_total", "low_space", "broken"})

    def __setattr__(self, name, value):
        object.__setattr__(self, name, value)
        if name in StateBudget._REASONS:
            self._recalm()

    def _recalm(self) -> None:
        d = self.__dict__
        calm = not (d.get("over_total") or d.get("low_space") or d.get("broken") or d.get("forced"))
        if calm and "accounts" in d:
            if d.get("yielding"):
                calm = (self.pool_used < self.pool // 2 and self.pool_used + self.yield_used < self.pool
                        and self.yield_used < self.yield_cap)
            else:
                calm = self.pool_used < self.pool
        object.__setattr__(self, "calm", calm)

    # ---- floors ----
    @property
    def floor(self) -> int:
        """The bytes on disk one floor guarantees (a store serving several rules holds one per rule)."""
        return self.disk_total // (2 * max(1, self.stores or sum(a.weight for a in self.accounts)))

    def floor_of(self, account: Account) -> int:
        return self.floor * account.weight

    @property
    def pool(self) -> int:
        """The bytes beyond their floors the stores share."""
        return self.disk_total - self.floor * max(1, self.stores or sum(a.weight for a in self.accounts))

    @property
    def yield_cap(self) -> int:
        """The bytes one yielding store may hold: a quarter of the hunt's total."""
        return int(self.disk_total * YIELD_SHARE)

    def plan(self, stores: int) -> None:
        """Fix the number of floors planned for (the sweep counts its pack's live stores, each by its weight)."""
        self.stores = max(1, stores)
        self._repool()

    def account(self, name: str, strong: bool = False, weight: int = 1, yields: bool = False) -> Account:
        account = Account(name, strong, weight, yields)
        self.accounts.append(account)
        if yields:
            self.yielding = True
            self._recalm()
        if not self.stores:
            self._repool()              # unplanned (a rule driven alone): floors follow the stores seen so far
        return account

    def _repool(self) -> None:
        floor = self.floor
        self.pool_used = sum(max(0, a.used - floor * a.weight) for a in self.accounts if not a.yields)
        self._make_room()
        self._recalm()

    def _make_room(self) -> None:
        """Reclaim citation caches if reported physical growth reaches the ceiling."""
        excess = self.physical_used - self.disk_total
        if excess <= 0 or self._evicting:
            return
        self._evicting = True
        try:
            for account in self.accounts:
                if account.yields and account.evict is not None and account.used > 0:
                    excess -= account.evict(excess)
                    if excess <= 0:
                        break
        finally:
            self._evicting = False

    def charge(self, account: Account, nbytes: int) -> None:
        """A store's bytes on disk changed by `nbytes` (negative when states were read back or cleared). A yielding
        store's bytes are its own account's only: they take nothing from the detection stores' headroom."""
        if not nbytes:
            return
        if account.yields:
            account.used += nbytes
            self.yield_used += nbytes
            self._recalm()
            return
        floor = self.floor * account.weight
        before = max(0, account.used - floor)
        account.used += nbytes
        self.pool_used += max(0, account.used - floor) - before
        if nbytes > 0 and self.yield_used:
            self._make_room()
        self._recalm()

    def force_full(self, reason: str, where) -> None:
        """Put every store whose Account satisfies `where` into no-growth mode (tests and probes)."""
        self.forced.append((where, reason))
        self._recalm()

    def new_key_reason(self, account: Account | None) -> str:
        """Why a record needing a new key in this store is refused now ("" while it is not)."""
        if self.finalizing:
            return self.hard
        reason = self.hard or self.over_total
        if not reason and account is not None:
            reason = next((why for where, why in self.forced if where(account)), "")
            if not reason and account.yields:
                if self.pool_used >= self.pool // 2:
                    reason = (f"the detection stores hold {self.pool_used / 2**20:.1f} MiB of the "
                              f"{self.pool / 2**20:.1f} MiB of headroom they share, and a store no detection reads "
                              f"gives way at half of it")
                elif self.pool_used + self.yield_used >= self.pool:
                    reason = (f"the detection stores' bytes beyond their floors and the yielding stores' "
                              f"{self.yield_used / 2**20:.1f} MiB fill the {self.pool / 2**20:.1f} MiB of headroom")
                elif account.used >= self.yield_cap:
                    reason = (f"it holds {account.used / 2**20:.1f} MiB, its cap of a quarter of the hunt's total "
                              f"({self.yield_cap / 2**20:.1f} MiB)")
            # Logical payload estimates and idle floors cannot refuse detection state.
            # The writing database enforces the physical ceiling after citation eviction.
        if reason and account is not None and account.name not in self.full and not account.yields:
            self.full[account.name] = reason
        return reason

    # ---- disk ----
    def free(self) -> int | None:
        usage = volume_usage(self.directory)
        return None if usage is None else usage[1]

    def headroom(self) -> int | None:
        """Bytes that may still be written before the stage volume reaches its reserve (None: unknown)."""
        free = self.free()
        return None if free is None else max(0, free - self.reserve)

    @property
    def physical_used(self):
        # Legacy compact stores report physical growth without a per-file ledger entry.
        # The cumulative counter conservatively covers them and never understates live bytes.
        return max(self.disk_used-self._physical_released, sum(size for size, _weight in self._physical.values()))

    @property
    def physical_pool_used(self):
        return sum(max(0, size-self.floor*weight) for size, weight in self._physical.values())

    def physical_account(self, account, growth):
        key = ("account", id(account))
        size = self._physical.get(key, (0, account.weight))[0]
        self._physical[key] = (size+growth, account.weight)

    def release_physical_account(self, account):
        size = self._physical.pop(("account", id(account)), (0, 0))[0]
        self._physical_released += size
        self.charge(account, -size)

    def physical_allowance(self, account):
        available = max(0, self.disk_total-self.physical_used)
        headroom = self.headroom()
        return available if headroom is None else min(available, headroom)

    def reclaim_citations(self, needed: int, *, references: bool = False) -> None:
        """Reclaim optional bodies in stable order; references may yield only on an actual FULL retry."""
        if self._evicting or needed <= self.disk_total-self.physical_used:
            return
        self._evicting = True
        try:
            accounts = sorted((account for account in self.accounts if account.yields), key=lambda item: item.name)
            for phase in ("evict", "evict_references") if references else ("evict",):
                for account in accounts:
                    reclaim = getattr(account, phase)
                    if reclaim is not None:
                        reclaim(max(0, needed-(self.disk_total-self.physical_used)))
                        if needed <= self.disk_total-self.physical_used:
                            return
        finally:
            self._evicting = False

    def reclaim_citations_step(self) -> bool:
        """After a rolled-back FULL, release one bounded citation batch and retry the write.

        Optional bodies always precede compact references. A positive result can mean reusable pages inside
        the stage, not just a smaller file, so the writer must retry before asking for another step.
        """
        if self._evicting:
            return False
        self._evicting = True
        try:
            accounts = sorted((a for a in self.accounts if a.yields), key=lambda a: (a.strong, a.name))
            for phase in ("evict", "evict_references"):
                for account in accounts:
                    reclaim = getattr(account, phase)
                    if reclaim is not None and reclaim(4096):
                        return True
            return False
        finally:
            self._evicting = False

    @contextlib.contextmanager
    def reclamation_write(self):
        """One attempted transaction, including its retries; nested writers restore the enclosing scope."""
        previous = getattr(self, "_reclamation_token", None)
        self._reclamation_token = object()
        try:
            yield
        finally:
            self._reclamation_token = previous

    def refuse_capacity(self, account, reason):
        if account is not None and id(account) not in self._capacity_refusals:
            self._capacity_refusals.add(id(account))
            self.force_full(reason, lambda item: item is account)

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
        """A spill database grew (real bytes, for the summary); the volume's free space is read again."""
        if nbytes > 0:
            self.disk_used += nbytes
        self.check_free()

    def fail(self, reason: str) -> None:
        self.broken = self.broken or reason

    @property
    def hard(self) -> str:
        """Why no state may be written to disk now ("" while it may)."""
        return self.broken or self.low_space

    @property
    def spent(self) -> str:
        """Every limit reached so far, for the sweep's summary ("" when none)."""
        reasons = [self.broken, self.low_space, self.over_total]
        if self.full:
            names = sorted(self.full)
            reasons.append(f"{len(names)} store(s) took no new keys after a named storage refusal: "
                           f"{', '.join(names[:10])}{' and others' if len(names) > 10 else ''}")
        return "; ".join(dict.fromkeys(r for r in reasons if r))

    def may_write(self) -> bool:
        """Whether state may be moved to disk now."""
        return not self.hard

    def blocked(self) -> str:
        return self.hard

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


def _strong(owner) -> bool:
    return getattr(owner, "state_slice", "routine") == "strong"


def register_store(owner, store) -> None:
    """Note a store on its owner (weakly), so the sweep can plan one floor per live store."""
    import weakref
    owner.holds_state = True
    stores = owner.__dict__.get("_state_stores")
    if stores is None:
        stores = owner.__dict__["_state_stores"] = []
    stores.append(weakref.ref(store))


def live_stores(pack) -> int:
    """The floors a pack's live stores hold: one per store, a store serving several rules (the exec lineage) one
    per rule it serves (its `weight`), a store shared by several rules counted once."""
    seen = {}
    for pb in pack:
        for ref in pb.__dict__.get("_state_stores", ()):
            store = ref()
            if store is not None:
                seen[id(store)] = 0 if getattr(store, "yields", False) else max(1, int(getattr(store, "weight", 1)))
    return sum(seen.values())


def deep_size(value, depth: int = 0) -> int:
    """An estimate of the memory a value holds: its own size plus what it refers to, recursively for containers and
    slotted or plain objects; a large container is sized from a sample of its items."""
    import sys
    size = sys.getsizeof(value)
    if depth > 6:
        return size
    kind = type(value)
    if kind in (str, bytes, int, float, bool) or value is None:
        return size
    if kind is dict or isinstance(value, dict):
        n = len(value)
        if not n:
            return size
        from itertools import islice
        items = list(islice(value.items(), 16))
        per = sum(deep_size(k, depth + 1) + deep_size(v, depth + 1) for k, v in items) / len(items)
        return size + int(per * n)
    if isinstance(value, (list, tuple, set, frozenset)):
        n = len(value)
        if not n:
            return size
        from itertools import islice
        items = list(islice(value, 16))
        per = sum(deep_size(item, depth + 1) for item in items) / len(items)
        return size + int(per * n)
    slots = getattr(kind, "__slots__", None)
    if slots is not None:
        names = (slots,) if isinstance(slots, str) else slots
        return size + sum(deep_size(getattr(value, name), depth + 1) for name in names if hasattr(value, name))
    attrs = getattr(value, "__dict__", None)
    if attrs is not None:
        return size + deep_size(attrs, depth + 1)
    return size


class Spill:
    """A playbook's private on-disk tables for compact rows it must join over the whole hunt (cross-target joins
    cannot be streamed: one target is read whole before the next). Rows are buffered and written in batches; queries
    flush first. It lives in its own directory (mode 0700) under the sweep's stage directory, holds telemetry-derived
    values, and is removed by `close` (the sweep closes it on every exit path it controls; a killed process leaves it
    to the stale-stage cleanup, which goes by directory age: every write and every sweep heartbeat refreshes it).
    Its database's growth is reported to the hunt's state budget (the stores' own Accounts hold their bytes), and the
    database is capped at the volume's headroom above the reserve, so no statement can run the volume into it."""

    def __init__(self, directory=None, budget: StateBudget | None = None, *, owner=None):
        import sqlite3
        import tempfile
        from pathlib import Path
        if directory is not None:
            Path(directory).mkdir(mode=0o700, parents=True, exist_ok=True)
        self._dir = tempfile.mkdtemp(prefix=SPILL_PREFIX, dir=directory)
        self.path = Path(self._dir) / "spill.db"
        self.db = sqlite3.connect(self.path)
        # The page cache is memory outside the hunt's memory budget: SPILL_CACHE_KIB per spill.
        for pragma in ("journal_mode=MEMORY", "synchronous=OFF", "temp_store=FILE", f"cache_size=-{SPILL_CACHE_KIB}"):
            self.db.execute(f"PRAGMA {pragma}")
        self._page = self.db.execute("PRAGMA page_size").fetchone()[0]
        self.budget = budget if budget is not None else StateBudget(directory)
        self.owner = owner
        self._budget_limited = False
        self._fair_refused = False
        self._size = 0
        self._buffers: dict[str, tuple[str, list[tuple]]] = {}

    def cap(self) -> None:
        """Cap the database at its pages now plus the volume's headroom above the reserve: SQLite then stops any
        statement that would pass it with "database or disk is full"."""
        import sqlite3
        self.grew()
        headroom = self.budget.headroom()
        available = max(0, self.budget.disk_total-self.budget.physical_used)
        self._budget_limited = headroom is None or available <= headroom
        if headroom is not None:
            available = min(available, headroom)
        try:
            pages = self.db.execute("PRAGMA page_count").fetchone()[0]
            self.db.execute(f"PRAGMA max_page_count = {max(1, pages + available // self._page)}")
        except sqlite3.Error:
            pass

    @reclaiming_write
    def table(self, name: str, columns: str) -> None:
        import sqlite3
        self.budget.reclaim_citations(2*self._page)
        self.db.commit()
        while True:
            self.cap()
            try:
                self.db.execute(f"CREATE TABLE {name} ({columns})")
                break
            except sqlite3.OperationalError as exc:
                self.db.rollback()
                if "full" in str(exc).lower():
                    self.grew()
                    if self.budget.reclaim_citations_step():
                        continue
                raise self.failed(exc) from exc
            finally:
                self.grew()
        width = len(columns.split(","))
        self._buffers[name] = (f"INSERT INTO {name} VALUES ({','.join('?' * width)})", [])

    @reclaiming_write
    def write(self, sql: str, rows: list[tuple], *, account: Account | None = None) -> None:
        """Write rows, charging the database's growth to the budget. Raises StateExhausted when the stage volume is
        at its free-space reserve or a write failed (nothing of a failed batch can be trusted). A store past its floor
        does not stop a write already under way: its rule refuses records needing a new key."""
        import sqlite3
        reason = self.budget.hard
        if reason:
            raise StateExhausted(reason)
        if account is None or not account.yields:
            # Physical index/page overhead can spend headroom before logical payload billing does.
            # Citation-only rows give way before a detection batch is refused for that pressure.
            # A new table/index leaf can split its parent as well as allocate its own page.
            needed = 4*self._page + sum(128 + sum(len(value) if isinstance(value, (bytes, str)) else 16
                                              for value in row) for row in rows)
            self.budget.reclaim_citations(needed)
        # Refusing a batch must restore all its rows; older accepted state remains readable.
        self.db.commit()
        while True:
            self.cap()
            try:
                self.db.executemany(sql, rows)
                self.db.commit()
                return
            except sqlite3.OperationalError as exc:
                self.db.rollback()
                self.grew()
                if ("full" in str(exc).lower() and (account is None or not account.yields)
                        and self.budget.reclaim_citations_step()):
                    continue
                raise self.failed(exc, account=account) from exc
            finally:
                self.grew()

    def failed(self, exc: Exception, *, account: Account | None = None, report: bool = True) -> Exception:
        """The exception to raise for a failed statement: StateExhausted (the budget marked broken) when the stage
        volume could not take the write, else the error itself."""
        text = str(exc).lower()
        if "full" in text and self._budget_limited:
            reason = "detector spill reached its hunt byte allowance (physical whole-hunt byte ceiling)"
            if account is not None:
                self.budget.refuse_capacity(account, reason)
                if self.owner is not None and report:
                    self.owner.note_limit("state_disk", reason + "; later records needing new state are not evaluated")
            elif self.owner is not None and not self._fair_refused:
                self._fair_refused = True
                prefix = str(self.owner.id)+":"
                self.budget.force_full(reason, lambda account: account.name.startswith(prefix))
                self.owner.note_limit("state_disk", reason + "; later records needing new state are not evaluated")
            return StateExhausted(reason)
        if "full" in text or "disk i/o" in text or "no space" in text:
            self.budget.fail(f"writing detector state to the stage volume failed ({exc})")
            return StateExhausted(self.budget.broken)
        return exc

    def check(self) -> None:
        """Charge growth from statements run directly on `db` (finalize's join tables), stop once the stage volume is
        at its reserve, and cap the database again for the next statement."""
        self.grew()
        reason = self.budget.hard
        if reason:
            raise StateExhausted(reason)
        self.cap()

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
        weight = max(1, live_stores([self.owner])) if self.owner is not None else 1
        self.budget._physical[("spill", id(self))] = (size, weight)
        if size > self._size:
            self.budget.grew(size - self._size)
        elif size < self._size:
            self.budget._physical_released += self._size - size
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
        released = self.budget._physical.pop(("spill", id(self)), (0, 0))[0]
        self.budget._physical_released += released
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
    """The estimate of a hot set's memory: its size times the mean deep size (`deep_size`, plus KEY_OVERHEAD) of up
    to SAMPLE states drawn at random across the whole set, measured again at least every REMEASURE_TRIMS trims
    (states grow in place) and whenever the set has shrunk by a quarter. When it has grown by a quarter, the new
    entries (the most recently used end) are measured and blended in by count; the whole set is still measured at
    random every REMEASURE_TRIMS trims."""

    __slots__ = ("at", "avg", "rng", "trims")

    def __init__(self):
        import random
        self.avg = 0.0
        self.at = 0
        self.trims = 0
        self.rng = random.Random(0)             # reproducible: the same hunt measures the same states

    def per_entry(self, values, n: int) -> float:
        from itertools import islice
        self.trims += 1
        if self.avg and self.trims < REMEASURE_TRIMS and self.at * 0.75 < n < self.at * 1.25:
            return self.avg
        if self.avg and n >= self.at * 1.25 and self.trims < REMEASURE_TRIMS:
            fresh = list(islice(reversed(values), min(SAMPLE, n - self.at)))
            mean = sum(deep_size(state) for state in fresh) / len(fresh) + KEY_OVERHEAD
            self.avg = (self.avg * self.at + mean * (n - self.at)) / n
            self.at = n
            return self.avg
        picks = sorted(self.rng.sample(range(n), min(SAMPLE, n)))
        sample, it, pos = [], iter(values), 0
        for index in picks:
            if index > pos:
                next(islice(it, index - pos, index - pos), None)        # skip, in C
            sample.append(next(it))
            pos = index + 1
        self.avg = sum(deep_size(state) for state in sample) / len(sample) + KEY_OVERHEAD
        self.at, self.trims = n, 0
        return self.avg


def _hot_limit(store, n: int, values, keep: int | None) -> int:
    """How many entries a hot set keeps at this trim: `keep`, else its count cap lowered to the bytes the hunt's
    memory budget leaves it."""
    if keep is not None:
        return keep
    limit = store.hot_size
    if store.owner is None:
        return limit
    per = store._measure.per_entry(values, n)
    budget = _budget_of(store.owner)
    allowance = budget.hot_allowance(store, int(n * per))
    if allowance is not None:
        limit = min(limit, max(HOT_FLOOR, int(allowance // per)))
    return limit


# Retained as a compatibility setting for callers. Admission follows StateBudget's physical ceiling, not this hint.
DISK_BUDGET = 8 * 2**30
# The share of the hunt's disk total one yielding store may hold (see StateBudget).
YIELD_SHARE = 0.25


def store_refuses(owner, account_of) -> bool:
    """Whether the hunt's state budget refuses a new key in a store now; when it does, the owner's coverage names
    the store and why (the caller refuses the record through its own path); a yielding store's refusal is left to
    its caller to name, as no record goes unevaluated. `account_of()` gives the store's Account (called only when the
    budget is not calm)."""
    budget = None if owner is None else owner.budget
    if budget is None or budget.calm:
        return False
    account = account_of()
    reason = budget.new_key_reason(account)
    if reason and account is not None and account.yields:
        return True
    if reason:
        owner.note_limit(f"state_budget:{account.name if account is not None else ''}",
                         f"the store {account.name if account is not None else ''} took no new key: {reason}; "
                         f"records of this rule that need one are not evaluated")
        return True
    return False


def _held_in_memory(budget: StateBudget, keep: int | None) -> bool:
    """When disk cannot be written: whether a trim may leave its states in memory. During consume it may (the rule
    takes no new state, so they grow no more); at finalize while the hunt's hot sets fit the memory budget."""
    return keep is None and (not budget.finalizing or budget.mem_used <= budget.memory_total)
# The count cap of a hot set when its rule names none: memory is governed by the hunt's memory budget (bytes).
HOT_COUNT = 2_000_000
_MISSING = object()


class KeyedStore:
    """Per-key rule state that never forgets: a hot set in memory, least recently used out to a keyed table on disk,
    and brought back when the key is read again. At `trim` (called when a batch ends, so a state read in a batch
    stays valid for the whole batch) memory keeps at most `hot` keys, and fewer when the hunt's memory budget
    (StateBudget) is over its total and this store is above its fair share. Only disk refuses: `put` of a new key
    returns False after a physical write refusal, and the rule refuses that record through its honest coverage
    path. `disk_budget` is retained as a caller hint, without imposing a separate admission ceiling.
    Below the volume's reserve (or after a failed write) nothing is written to disk, states in
    memory update, and a strong rule's store reads a key held on disk back into memory without writing (a read is
    not growth). A refusal never stops the rule: records that need no new state are still evaluated.

    Keys are stored as canonical bytes (`key_bytes`), so equal keys meet on disk whatever their object identity. A
    Bloom filter of the keys on disk spares a query for keys that never left memory. Every key keeps the number of
    its first `put`, so `items`, `keys` and `grouped` give first-insertion order (as a dict would) whatever was on
    disk or in memory.

    `candidate(state)` (optional) is kept as a column, so finalize can read only states that can still be reported;
    `group(key)` (optional) is kept as a text column, so finalize can read states grouped. Without an owner the
    store is memory only (callers outside the sweep whose input is bounded)."""

    # A store no detection reads (records kept only to be cited): it holds no floor of the hunt's state budget and
    # gives way before any detection store (see `StateBudget`), and its refusals are its owner's to name.
    yields = False
    # Called with how many records `evict_oldest` dropped (a yielding store's owner says they are not cited).
    on_evict = None

    def __init__(self, owner, name: str, hot: int, *, disk_budget: int | None = None, candidate=None, group=None):
        self.owner = owner
        self.name = name
        self.hot_size = hot
        self.disk_budget = disk_budget
        self.candidate = candidate
        self.group = group
        self.hot: OrderedDict = OrderedDict()
        # Until the first eviction the hot set's own order is first-insertion order, and no recency is needed: the
        # order numbers and the LRU order are kept only from then on (`_ordered`).
        self._ordered = False
        self._seq: dict = {}
        self._next = 0
        self._filter: _KeyFilter | None = None
        self._measure = _HotMeasure()
        self.on_disk = 0
        self.disk_bytes = 0
        self.broken = ""
        self._ready = False
        self._account: Account | None = None
        self._shadow: set = set()       # keys read back below the reserve: their row on disk is stale
        # The bytes the store holds for the budget: what is on disk plus what was read back from it and will go back
        # (a read is not growth), so a busy store does not look empty while its states are in memory mid-batch.
        self.held_bytes = 0
        self._held: dict = {}           # key read back from disk -> its bytes there
        if owner is not None:
            register_store(owner, self)

    def account(self) -> Account | None:
        """This store's Account in the hunt's state budget (created on first use)."""
        if self._account is None and self.owner is not None:
            owner = self.owner
            self._account = _budget_of(owner).account(f"{getattr(owner, 'id', type(owner).__name__)}:{self.name}",
                                                     _strong(owner), max(1, int(getattr(self, "weight", 1))),
                                                     yields=getattr(self, "yields", False))
            if self._account.yields:
                self._account.evict = self.evict_oldest
            if self.held_bytes:
                owner.budget.charge(self._account, self.held_bytes)
        return self._account

    def _bill(self, nbytes: int) -> None:
        """The bytes the store holds changed by `nbytes`: charged to its Account."""
        budget = None if self.owner is None else self.owner.budget
        account = self.account() if budget is not None else None
        self.held_bytes += nbytes
        if account is not None:
            budget.charge(account, nbytes)

    # ---- disk -------------------------------------------------------------------------------------
    @reclaiming_write
    def _db(self):
        spill = self.owner.spill()
        if not self._ready:
            import sqlite3
            spill.budget.reclaim_citations(3*spill._page)
            spill.db.commit()
            while True:
                spill.cap()
                try:
                    spill.db.execute(f"CREATE TABLE IF NOT EXISTS {self.name} (k BLOB PRIMARY KEY, kp BLOB, v BLOB, "
                                     f"n INTEGER, c INTEGER, g TEXT, s INTEGER)")
                    break
                except sqlite3.OperationalError as exc:
                    spill.db.rollback()
                    if "full" in str(exc).lower() and not self.yields:
                        spill.grew()
                        if spill.budget.reclaim_citations_step():
                            continue
                    raise spill.failed(exc, account=self.account(), report=False) from exc
                finally:
                    spill.grew()
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
        if kb is None or (self._shadow and key in self._shadow):
            return None
        db = self._db()
        row = db.execute(f"SELECT v, n, s FROM {self.name} WHERE k = ?", (kb,)).fetchone()
        if row is None:
            return None
        if remove:
            db.execute(f"DELETE FROM {self.name} WHERE k = ?", (kb,))
            self.on_disk -= 1
            self.disk_bytes -= row[1]
        return pickle.loads(row[0]), row[2], row[1]

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
            if self._ordered:
                self.hot.move_to_end(key)
            return state
        if not self.on_disk:
            return default
        if self._hard():
            return self._read_in_place(key, default)
        found = self._load(key, remove=True)
        if found is None:
            return default
        state, self._seq[key], self._held[key] = found
        self.hot[key] = state
        return state

    def _read_in_place(self, key, default):
        """Below the reserve: a strong rule's store reads a key held on disk back into memory without writing (its row
        stays, marked stale), so a record on a key it already holds still evaluates; any other store does not."""
        if not _strong(self.owner):
            return default
        found = self._load(key, remove=False)
        if found is None:
            return default
        state, self._seq[key], _size = found
        self.hot[key] = state
        self._shadow.add(key)
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
        return len(self.hot) + self.on_disk - len(self._shadow)

    def put(self, key, state) -> bool:
        """Hold the key's state (new, or replacing the held one); False when a new key meets the spent disk budget
        (the caller refuses the record). Replacing a key held on disk is not a new key."""
        if key in self.hot:
            self.hot[key] = state
            if self._ordered:
                self.hot.move_to_end(key)
            return True
        if not self._ordered:                       # nothing has left memory: no disk, and the dict keeps order
            if store_refuses(self.owner, self.account):
                return False
            self.hot[key] = state
            return True
        if self._hard():
            if self._read_in_place(key, None) is not None:
                self.hot[key] = state               # an existing key of a strong store: replaced in memory
                return True
            store_refuses(self.owner, self.account)
            return False
        found = self._load(key, remove=True)
        if found is not None:
            seq = found[1]
            self._held[key] = found[2]
        elif store_refuses(self.owner, self.account):
            return False
        else:
            seq = self._next
            self._next += 1
        self.hot[key] = state
        self._seq[key] = seq
        return True

    def _hard(self) -> bool:
        budget = None if self.owner is None else self.owner.budget
        return budget is not None and not budget.calm and bool(budget.hard)

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
            if self._ordered:
                self._seq.pop(key, None)
            if key in self._held:
                self._bill(-self._held.pop(key))
            return state
        if self._hard():
            return default
        found = self._load(key, remove=True)
        if found is None:
            return default
        self._bill(-found[2])
        return found[0]

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
            if _held_in_memory(budget, keep):
                return
            raise StateExhausted(budget.blocked())
        spill = self.owner.spill()
        try:
            self._db()
        except StateExhausted:
            if _held_in_memory(budget, keep):
                return
            raise
        if not self._ordered:                       # the first eviction: number the keys in their order so far
            self._seq = {key: i for i, key in enumerate(self.hot)}
            self._next = len(self._seq)
            self._ordered = True
        if self._filter is None:
            self._filter = _KeyFilter()
        evicted, rows, nbytes, before = [], [], 0, {}
        while len(self.hot) > limit:
            key, state = self.hot.popitem(last=False)
            seq = self._seq.pop(key)
            if key in self._held:
                before[key] = self._held.pop(key)
            evicted.append((key, state, seq))
            kb = key_bytes(key)
            blob = pickle.dumps(state, protocol=4)
            nbytes += len(blob)
            rows.append((kb, pickle.dumps(key, protocol=4), blob, len(blob),
                         1 if self.candidate is None or self.candidate(state) else 0,
                         None if self.group is None else self.group(key), seq))
        try:
            self._writing_states = evicted
            spill.write(f"INSERT OR REPLACE INTO {self.name} VALUES (?, ?, ?, ?, ?, ?, ?)", rows, account=self.account())
        except StateExhausted:
            for key, state, seq in reversed(evicted):      # nothing is dropped: back to memory, oldest first
                self.hot[key] = state
                self.hot.move_to_end(key, last=False)
                self._seq[key] = seq
            self._held.update(before)
            if budget.broken:
                self.broken = budget.broken                 # a partial write: the table can no longer be trusted
            if keep is None and (not budget.finalizing
                                 or (not self.broken and budget.mem_used <= budget.memory_total)):
                return                                      # held in memory (see _held_in_memory)
            raise
        finally:
            self._writing_states = ()
        for row in rows:
            self._filter.add(row[0])
        self.disk_bytes += nbytes
        self.on_disk += len(rows)       # counted before billing, which may make room by evicting a yielding store
        self._bill(nbytes - sum(before.values()))
        if self._filter.count > self._filter.capacity:
            self._rebuild_filter()
        if self._measure.avg:
            budget.hot_allowance(self, int(len(self.hot) * self._measure.avg))

    def evict_oldest(self, nbytes: int) -> int:
        """Drop the records written to disk longest ago until `nbytes` are freed (a yielding store giving a detection
        store room); the bytes freed. Rows are read in rowid order (the table's own index, oldest write first), a batch
        at a time, so no table is scanned. A key read back into memory is not on disk and is never dropped; nothing is
        dropped while rows on disk are marked stale (below the reserve) or the table is broken."""
        if self.owner is None or not self.on_disk or self._shadow or self.broken or nbytes <= 0:
            return 0
        import sqlite3
        db = self._db()
        freed = dropped = 0
        try:
            while freed < nbytes and self.on_disk:
                rows = db.execute(f"SELECT rowid, n FROM {self.name} ORDER BY rowid LIMIT 256").fetchall()
                if not rows:
                    break
                take, size_taken = [], 0
                for rowid, size in rows:
                    if freed + size_taken >= nbytes:
                        break
                    take.append((rowid,))
                    size_taken += size
                db.execute("SAVEPOINT citation_eviction")
                db.executemany(f"DELETE FROM {self.name} WHERE rowid = ?", take)
                db.execute("RELEASE citation_eviction")
                freed += size_taken
                self.on_disk -= len(take)
                dropped += len(take)
            if not self.on_disk and dropped:
                # An empty citation-only table must give its index/root pages back too; otherwise
                # its fixed schema footprint would still reduce detection capacity after all rows yielded.
                db.execute(f"DROP TABLE {self.name}")
                self._ready = False
        except sqlite3.Error as exc:
            if db.in_transaction:
                with contextlib.suppress(sqlite3.Error):
                    db.execute("ROLLBACK TO citation_eviction")
                    db.execute("RELEASE citation_eviction")
            # a failed delete (the volume full, for one) stops eviction for good; what was freed is still billed back
            self.broken = f"evicting citation records failed ({exc})"
        self.disk_bytes -= freed
        self._bill(-freed)
        if dropped and self.on_evict is not None:
            self.on_evict(dropped)
        return freed

    # ---- finalize -------------------------------------------------------------------------------------
    def pressure_items(self):
        """Read live states without ordering or copying the bounded hot set during reclamation."""
        yield from self.hot.items()
        if self.on_disk:
            for kp, value in self._rows(f"SELECT kp,v FROM {self.name}"):
                key = pickle.loads(kp)
                if key not in self.hot and key not in self._shadow:
                    yield key, pickle.loads(value)

    def _hot_ordered(self, candidates: bool):
        wanted = ((key, state) for key, state in self.hot.items()
                  if not candidates or self.candidate is None or self.candidate(state))
        if not self._ordered:
            return [(i, key, state) for i, (key, state) in enumerate(wanted)]
        return sorted(((self._seq[key], key, state) for key, state in wanted), key=_first)

    def items(self, *, candidates: bool = False):
        """Every (key, state) in first-insertion order, from memory and disk a batch at a time (read only)."""
        import heapq
        hot = self._hot_ordered(candidates)
        if not self.on_disk:
            for _seq, key, state in hot:
                yield key, state
            return
        where = " WHERE c = 1" if candidates else ""
        disk = ((s, key, pickle.loads(v))
                for kp, v, s in self._rows(f"SELECT kp, v, s FROM {self.name}{where} ORDER BY s")
                if (key := pickle.loads(kp)) not in self._shadow)
        for _seq, key, state in heapq.merge(hot, disk, key=_first):
            yield key, state

    def keys(self, *, candidates: bool = False) -> list:
        """Every key (or every candidate's key) in first-insertion order. Holds the keys, not the states."""
        import heapq
        hot = [(seq, key) for seq, key, _state in self._hot_ordered(candidates)]
        if not self.on_disk:
            return [key for _seq, key in hot]
        where = " WHERE c = 1" if candidates else ""
        disk = ((s, key) for kp, s in self._rows(f"SELECT kp, s FROM {self.name}{where} ORDER BY s")
                if (key := pickle.loads(kp)) not in self._shadow)
        return [key for _seq, key in heapq.merge(hot, disk, key=_first)]

    def grouped(self):
        """Every (key, state) ordered by the group column, then first insertion, so a group's states arrive
        together. With anything on disk, all is moved there first and nothing is held but the group being read."""
        if self.owner is None or not self.on_disk:
            for _order, key, state in sorted((((self.group(key), seq), key, state)
                                              for seq, key, state in self._hot_ordered(False)), key=_first):
                yield key, state
            return
        self.trim(0)
        for kp, v in self._rows(f"SELECT kp, v FROM {self.name} ORDER BY g, s"):
            yield pickle.loads(kp), pickle.loads(v)

    def clear(self) -> None:
        self.hot.clear()
        self._seq = {}
        self._next = 0
        self._ordered = False
        if self.on_disk and self.owner is not None and self._ready and self.owner._spill is not None:
            self._db().execute(f"DELETE FROM {self.name}")
        self._bill(-self.held_bytes)
        self.on_disk = self.disk_bytes = 0
        self._filter = None
        self._shadow = set()
        self._held = {}
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

    def __init__(self, owner, name: str, hot: int, *, disk_budget: int | None = None, refusable: bool = True):
        self.owner = owner
        self.name = name
        self.hot_size = hot
        self.disk_budget = disk_budget
        # False for an index of keys a KeyedStore already accepted (it must stay complete); such a list takes
        # no new record of its own while the budget refuses, since its store takes no new key
        self.refusable = refusable
        self.buffer: list = []                  # (order, record)
        self._measure = _HotMeasure()
        self.on_disk = 0
        self.disk_bytes = 0
        self.broken = ""
        self._ready = False
        self._account: Account | None = None
        self.held_bytes = 0
        if owner is not None:
            register_store(owner, self)

    account = KeyedStore.account
    _bill = KeyedStore._bill

    def _charge(self, nbytes: int) -> None:
        self.disk_bytes += nbytes
        self._bill(nbytes)

    def __len__(self) -> int:
        return len(self.buffer) + self.on_disk

    def append(self, record, order: tuple = (0.0, "")) -> bool:
        """Hold a record; False when the list's disk budget or the hunt's state budget refuses it."""
        if self.refusable and store_refuses(self.owner, self.account):
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
            if _held_in_memory(budget, keep):
                return
            raise StateExhausted(budget.blocked())
        spill = self.owner.spill()
        rows, nbytes = [], 0
        for i, ((o1, o2), record) in enumerate(self.buffer):
            blob = pickle.dumps(record, protocol=4)
            nbytes += len(blob)
            rows.append((self.on_disk + i, o1, o2, blob))
        try:
            if not self._ready:
                import sqlite3
                spill.cap()
                try:
                    spill.db.execute(f"CREATE TABLE IF NOT EXISTS {self.name} (seq INTEGER PRIMARY KEY, o1, o2, v BLOB)")
                except sqlite3.OperationalError as exc:
                    raise spill.failed(exc, account=self.account()) from exc
                finally:
                    spill.grew()
            spill.write(f"INSERT INTO {self.name} VALUES (?, ?, ?, ?)", rows, account=self.account())
        except StateExhausted:
            if budget.broken:
                self.broken = budget.broken
            if not budget.finalizing and keep is None:
                return
            raise
        self._ready = True
        self._charge(nbytes)
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
        self._charge(-self.disk_bytes)
        self.buffer, self.on_disk = [], 0
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
