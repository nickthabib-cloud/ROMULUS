"""Per-hunt disk staging for aggregate playbooks that join large event sets.

A joining playbook keeps only compact join keys in memory. The full typed events it may cite, and the
raw copies those events reference, go to a private SQLite file for the length of the sweep, so memory
stays bounded however much traffic a mission network produces. At finalize the playbook loads back only
the events it actually cites, and the sweep publishes them with their raw copies, so every citation
resolves to a retained record.

Most staged events are kept to the end. A playbook may also hold events it needs only while they bound an
interval (the earliest and the latest record of a group): such a hold is counted per playbook and released when a
later record takes the bound, and an event no playbook keeps or holds any more is removed with the raw copies only
it referenced. SQLite reuses the freed pages, so the file grows with what is held at once, not with every record
that was a bound for a while.

The stage holds raw telemetry, so it lives under the hunt data directory (mode 0700), is removed on
every exit path the process controls, and stages left by a killed process are cleared at the next start.
"""
from __future__ import annotations

import contextlib
import json
import shutil
import sqlite3
import tempfile
import time
import zlib
from collections import OrderedDict, defaultdict
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from romulus.baseline.spec import Pending, exec_serial
from romulus.detect.bounded import Account, StateBudget, reclaiming_write
from romulus.detect.correlation import boot_of
from romulus.evidence.typed import TypedEvent
from romulus.hunt.citations import COMPACT_CITATION_NOTE, compact_event, expand_event

PREFIX = "romulus-stage-"
PCAP_PREFIX = "romulus-pcap-"            # the packet stage's capture directory
STALE_SECONDS = 6 * 3600
WINDOWS_STABLE_ID_MAX_CHARS = 64
REFERENCE_FLAGS_BASE = 1 << 56       # all plan tags occupy the same eight payload bytes, even at FULL


def _citation_epoch(body):
    row = json.loads(zlib.decompress(body) if isinstance(body, bytes) else body)
    stamp = row[2] if isinstance(row, list) else row.get("ts")
    return datetime.fromisoformat(stamp).timestamp() if stamp else None

# Held events. Every statement that releases a hold or keeps a held event looks rows up by a primary key or an index
# (one id or key at a time), so a release costs the same however many holds the stage has; tests check the plans.
HOLD_ADD = "INSERT INTO hold VALUES (?, ?, 1) ON CONFLICT (id, owner) DO UPDATE SET n = n + 1"
HOLD_DECREMENT = "UPDATE hold SET n = n - 1 WHERE id = ? AND owner = ?"
HOLD_DROP = "DELETE FROM hold WHERE id = ? AND owner = ? AND n <= 0"
UNHELD = ("SELECT typeof(body) FROM event WHERE id = ? AND kept = 0 "
          "AND NOT EXISTS (SELECT 1 FROM hold WHERE hold.id = event.id)")
HELD_RAW = "SELECT key FROM event_raw WHERE id = ?"
EVENT_DROP = "DELETE FROM event WHERE id = ?"
EVENT_RAW_DROP = "DELETE FROM event_raw WHERE id = ?"
RAW_DROP = ("DELETE FROM raw WHERE key = ? AND kept = 0 "
            "AND NOT EXISTS (SELECT 1 FROM event_raw WHERE event_raw.key = raw.key)")
EVENT_KEEP = "UPDATE event SET kept = 1 WHERE id = ? AND kept = 0"
RAW_KEEP = "UPDATE raw SET kept = 1 WHERE key = ? AND kept = 0"
INDEXED_STATEMENTS = (HOLD_DECREMENT, HOLD_DROP, UNHELD, HELD_RAW, EVENT_DROP, EVENT_RAW_DROP, RAW_DROP, EVENT_KEEP,
                      RAW_KEEP)


def clear_stale_stages(directory: str | Path, older_than: float = STALE_SECONDS) -> int:
    """Remove stage directories a killed process left behind. Only ones older than any live sweep's
    lease could be are removed; returns how many."""
    root = Path(directory)
    if not root.is_dir():
        return 0
    removed, cutoff = 0, time.time() - older_than
    for child in [*root.glob(f"{PREFIX}*"), *root.glob(f"{PCAP_PREFIX}*")]:
        if child.is_dir() and child.stat().st_mtime < cutoff:
            shutil.rmtree(child, ignore_errors=True)
            removed += 1
    return removed


class EventStage:
    def __init__(self, directory: str | Path | None = None, *, budget: StateBudget | None = None,
                 windows_account: Account | None = None, account: Account | None = None):
        if directory is not None:
            Path(directory).mkdir(mode=0o700, parents=True, exist_ok=True)
        self._dir = tempfile.mkdtemp(prefix=PREFIX, dir=directory)
        self.directory = Path(self._dir)
        self.directory.chmod(0o700)
        self.path = Path(self._dir) / "stage.db"
        self.db: sqlite3.Connection | None = sqlite3.connect(self.path)
        self.db.execute("PRAGMA auto_vacuum=INCREMENTAL")
        # Roll back a refused write atomically without a disk journal outside the hunt byte budget.
        self.db.execute("PRAGMA journal_mode=MEMORY")
        self.db.execute("PRAGMA synchronous=OFF")
        # kept = 1: staged to be kept to the end; 0: present only while a playbook holds it (table hold)
        self.db.create_function("citation_epoch", 1, _citation_epoch, deterministic=True)
        self.db.execute("CREATE TABLE event (id TEXT PRIMARY KEY, body TEXT NOT NULL, kept INTEGER NOT NULL, "
                        f"reclaim INTEGER NOT NULL DEFAULT {REFERENCE_FLAGS_BASE}, "
                        "ts REAL GENERATED ALWAYS AS (citation_epoch(body)) STORED) WITHOUT ROWID")
        self.db.execute("CREATE INDEX event_time ON event(ts,id)")
        self.db.execute("CREATE TABLE raw (key TEXT PRIMARY KEY, body TEXT NOT NULL, kept INTEGER NOT NULL)")
        self._raw_table = True
        # holds by event first, so "is this event still held by anyone" is a primary-key lookup
        self.db.execute("CREATE TABLE hold (id TEXT NOT NULL, owner TEXT NOT NULL, n INTEGER NOT NULL, "
                        "PRIMARY KEY (id, owner))")
        # Native raw keys of both held and kept events support release and optional-cache reclamation.
        self.db.execute("CREATE TABLE event_raw (id TEXT NOT NULL, key TEXT NOT NULL, PRIMARY KEY (id, key))")
        self.db.execute("CREATE INDEX event_raw_key ON event_raw (key)")
        # This shared root belongs to the stage schema, never the first quiet citation owner.
        self.db.execute("CREATE TABLE citation_owner(id TEXT,owner INTEGER,classified INTEGER NOT NULL DEFAULT 0,"
                        "PRIMARY KEY(id,owner)) WITHOUT ROWID")
        self._baseline_ready = False
        # One bounded-width key per normalized Windows event. The row count follows the hunt's retrieved Windows
        # records; unlike aggregate staging this seam never serializes event bodies or raw telemetry. Keeping the
        # table in the stage gives all transient sweep state the same private lifecycle and cleanup behavior.
        self.windows_path = Path(self._dir) / "windows-seen.db"
        self.windows_db: sqlite3.Connection | None = sqlite3.connect(self.windows_path)
        self.windows_db.execute("PRAGMA journal_mode=MEMORY")
        self.windows_db.execute("PRAGMA synchronous=OFF")
        self.windows_db.execute(
            f"CREATE TABLE windows_seen (id TEXT PRIMARY KEY CHECK(length(id) <= "
            f"{WINDOWS_STABLE_ID_MAX_CHARS})) WITHOUT ROWID"
        )
        self.windows_db.commit()
        self._windows_page = self.windows_db.execute("PRAGMA page_size").fetchone()[0]
        self._windows_size = 0
        self.budget = budget
        self.account = account or (budget.account("event_stage") if budget is not None else None)
        self._size = 0
        self._allocations = {}
        self._citation_account = (budget.account("event_stage:optional_citations", yields=True)
                                  if budget is not None else None)
        if self._citation_account is not None:
            self._citation_account.evict = self._evict_citations
            self._citation_account.evict_references = self._evict_references
        self.refusal_reason = ""
        self.refused = 0
        self.owners = {}
        self.owner_accounts = {}
        self._owner_numbers = {}       # one entry per registered account, not per event/group; survives DB reopen
        self.playbooks = ()
        self.finished_owners = set()
        self._reference_plan = None
        self._reference_plan_builds = 0
        self._cache_connection = self.db
        self._text_rows = 0
        self._body_cursor = ""
        self._body_revisions = defaultdict(int)
        self._raw_revisions = defaultdict(int)
        self._cache_passes = OrderedDict()
        self.windows_account = windows_account or self.account
        self.windows_refused = 0
        self.windows_refusal_reason = ""
        self._charge_windows_growth()
        self.charge_growth()
        self.events = 0

    def _create_baseline(self):
        # Window exec-pair state is compact: no typed-event body or raw source copy is written here.
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS baseline_cell (target TEXT NOT NULL, partition TEXT NOT NULL, start TEXT NOT NULL, "
            "end TEXT NOT NULL, target_applicable INTEGER NOT NULL, source_complete INTEGER NOT NULL, "
            "reasons TEXT NOT NULL, task_id TEXT, "
            "PRIMARY KEY (target, partition))"
        )
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS baseline_exec (target TEXT NOT NULL, partition TEXT NOT NULL, ordinal INTEGER NOT NULL, "
            "family TEXT NOT NULL, host TEXT, boot TEXT, pid INTEGER, ppid INTEGER, ts TEXT NOT NULL, "
            "serial INTEGER, session INTEGER, executable TEXT, outcome TEXT NOT NULL, event_id TEXT NOT NULL, "
            "PRIMARY KEY (target, partition, ordinal))"
        )
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS baseline_observation (target TEXT NOT NULL, partition TEXT NOT NULL, "
            "ordinal INTEGER NOT NULL, body TEXT NOT NULL, PRIMARY KEY (target, partition, ordinal))"
        )
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS baseline_pending (target TEXT NOT NULL, partition TEXT NOT NULL, "
            "ordinal INTEGER NOT NULL, body TEXT NOT NULL, PRIMARY KEY (target, partition, ordinal))"
        )
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS baseline_count (target TEXT NOT NULL, partition TEXT NOT NULL, "
            "ordinal INTEGER NOT NULL, body TEXT NOT NULL, PRIMARY KEY (target, partition, ordinal))"
        )
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS baseline_scope_hour (target TEXT NOT NULL, partition TEXT NOT NULL, "
            "ordinal INTEGER NOT NULL, body TEXT NOT NULL, PRIMARY KEY (target, partition, ordinal))"
        )
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS baseline_event_hour (target TEXT NOT NULL, partition TEXT NOT NULL, "
            "ordinal INTEGER NOT NULL, body TEXT NOT NULL, PRIMARY KEY (target, partition, ordinal))"
        )
        self.db.commit()
        self._baseline_ready = True

    def _ensure_baseline(self):
        if not self._baseline_ready:
            self._write(self._create_baseline, 1)
            if not self._baseline_ready:
                raise sqlite3.OperationalError("compact baseline schema refused: " + self.refusal_reason)

    def charge_growth(self, account=None):
        size = self.db.execute("PRAGMA page_count").fetchone()[0] * self.db.execute("PRAGMA page_size").fetchone()[0]
        if self.budget is not None and self.account is not None and size > self._size:
            owner = account or self.account
            self._allocations[owner] = self._allocations.get(owner, 0)+size-self._size
            self.budget.charge(owner, size-self._size)
            self.budget.physical_account(owner, size-self._size)
            self.budget.grew(size-self._size)
        elif self.budget is not None and size < self._size:
            released = self._size-size
            for owner in sorted(self._allocations, key=lambda item: (not item.yields, item.name)):
                amount = min(released, self._allocations[owner])
                self._allocations[owner] -= amount
                self.budget.charge(owner, -amount)
                self.budget.physical_account(owner, -amount)
                self.budget._physical_released += amount
                released -= amount
                if not released:
                    break
        self._size = size

    def _evict_citations(self, needed):
        """Reclaim physical cache pages before any detection store refuses a write."""
        before = self._size
        def shrink():
            self.db.execute("PRAGMA incremental_vacuum").fetchall()
            self.charge_growth()
        changed = False
        if self._raw_table:
            removed = self.db.execute("DELETE FROM raw WHERE key IN (SELECT key FROM raw ORDER BY rowid LIMIT 4)").rowcount
            self.db.commit()
            if removed:
                shrink()
                self._cache_passes.clear()
                return max(1, before-self._size)
        if self._text_rows == 0:
            return 0
        rows = self.db.execute("SELECT id,body,kept FROM event WHERE id>? AND typeof(body)='text' ORDER BY id LIMIT 4",
                               (self._body_cursor,)).fetchall()
        if rows:
            self._body_cursor = rows[-1][0]
            with self.db:
                self.db.executemany("DELETE FROM event WHERE id=?", [(row[0],) for row in rows])
                self.db.executemany("INSERT INTO event(id,body,kept) VALUES(?,?,?)", [
                    (identity, compact_event(TypedEvent.model_validate_json(body)), kept)
                    for identity, body, kept in rows])
            self._reference_plan = None
            shrink()
            if self._text_rows is not None:
                self._text_rows -= len(rows)
            changed = True
        else:
            self._text_rows = 0
        self._cache_passes.clear()
        return max(int(changed), before-self._size)

    def _reference_groups(self):
        """Read existing group state only at physical pressure; no new metadata file or per-group memory."""
        from romulus.detect.bounded import KeyedStore, key_bytes
        from romulus.detect.citing import state_citation_ids

        for playbook in self.playbooks:
            account = self.owner_accounts.get(playbook.id)
            if account is not None and account.name in self.finished_owners:
                continue
            extra = getattr(playbook, "extra_citation_reference_groups", None)
            owner = self._owner_number(account.name) if account is not None else None
            if extra is not None:
                for key, references in extra():
                    yield (owner, id(playbook), key, True), playbook.state_slice == "strong", references
            for ref in playbook.__dict__.get("_state_stores", ()):
                store = ref()
                if not isinstance(store, KeyedStore) or store.yields:
                    continue
                for key, state in store.pressure_items():
                    custom = getattr(playbook, "citation_reference_groups", None)
                    if custom is not None:
                        for index, group in enumerate(custom(store, key, state)):
                            yield (owner, id(store), key_bytes(key), index, True), playbook.state_slice == "strong", group
                    else:
                        identity = store.group(key) if store.group is not None else key
                        refreshes = getattr(playbook, "refreshes_citation_on_next_record", None)
                        protect = (store.candidate is None or store.candidate(state)
                                   or refreshes is None or not refreshes(store, state))
                        yield (owner, id(store), key_bytes(identity), protect), playbook.state_slice == "strong", state_citation_ids(state)
                # A failed spill write has rolled back; its states have not yet returned to the hot set.
                for key, state, _seq in getattr(store, "_writing_states", ()):
                    custom = getattr(playbook, "citation_reference_groups", None)
                    if custom is not None:
                        for index, group in enumerate(custom(store, key, state)):
                            yield (owner, id(store), key_bytes(key), index, True), playbook.state_slice == "strong", group
                    else:
                        identity = store.group(key) if store.group is not None else key
                        refreshes = getattr(playbook, "refreshes_citation_on_next_record", None)
                        protect = (store.candidate is None or store.candidate(state)
                                   or refreshes is None or not refreshes(store, state))
                        yield (owner, id(store), key_bytes(identity), protect), playbook.state_slice == "strong", state_citation_ids(state)

    def _plan_references(self, token):
        """Tag exact eligible/strong references and protected witnesses once per attempted write.

        Tags were allocated at insertion at a fixed width. Each commit changes at most 128 rows, and ordering
        uses the stage's accounted index; there is no unbounded hot-state copy or external temporary sort/file.
        """
        self._reference_plan_builds += 1
        pending = 0
        def write(sql, params):
            nonlocal pending
            self.db.execute(sql, params)
            pending += 1
            if pending == 128:
                self.db.commit()
                pending = 0
        def mark(identity, bits, reset=False):
            sql = "UPDATE event SET reclaim=? WHERE id=?" if reset else "UPDATE event SET reclaim=reclaim|? WHERE id=?"
            write(sql, (bits, identity))
        for (identity,) in self.db.execute("SELECT id FROM event"):
            mark(identity, REFERENCE_FLAGS_BASE, reset=True)
        for identity, owner in self.db.execute("SELECT id,owner FROM citation_owner WHERE classified=1"):
            write("UPDATE citation_owner SET classified=0 WHERE id=? AND owner=?", (identity, owner))
        for group, is_strong, references in self._reference_groups():
            newest = None
            for identity in references:
                row = self.db.execute("SELECT ts,id FROM event WHERE id=?", (identity,)).fetchone()
                if row is not None:
                    mark(identity, 1 | (4 if is_strong else 0))
                    write("UPDATE citation_owner SET classified=1 WHERE id=? AND owner=?", (identity, group[0]))
                    if newest is None or row > newest:
                        newest = row
            if newest is not None and group[-1]:
                mark(newest[1], 2)
        strong_owners = {self._owner_number(a.name) for a in self.owner_accounts.values() if a.strong}
        finished = {self._owner_number(name) for name in self.finished_owners}
        for (identity,) in self.db.execute("SELECT id FROM event"):
            owners = dict(self.db.execute("SELECT owner,classified FROM citation_owner WHERE id=?", (identity,)))
            bits = int(bool(owners and owners.keys() <= finished))
            if owners.keys() & strong_owners:
                bits |= 4
            if any(owner not in finished and not classified for owner, classified in owners.items()):
                bits |= 2
            if bits:
                mark(identity, bits)
        self.db.commit()
        self._reference_plan = [token, 0, None]

    def _evict_references(self, needed):
        """After FULL, advance one bounded chronological batch from this write's exact pressure plan."""
        before = self._size
        token = getattr(self.budget, "_reclamation_token", None) or object()
        if self._reference_plan is None or self._reference_plan[0] is not token:
            self._plan_references(token)
        plan = self._reference_plan
        while plan[1] < 2:
            strength, after = plan[1], plan[2]
            clause = " AND (ts,id)>(?,?)" if after is not None else ""
            rows = self.db.execute("SELECT ts,id FROM event INDEXED BY event_time "
                                   "WHERE (reclaim&3)=1 AND (reclaim&4)=?" + clause + " ORDER BY ts,id LIMIT 4",
                                   (strength*4, *(after or ()))).fetchall()
            if rows:
                plan[2] = rows[-1]
                break
            plan[1], plan[2] = strength+1, None
        else:
            return 0
        # The protected bit was computed across every group before any deletion; a combined batch cannot
        # remove both witnesses of a shared group, even when their times fall in different cursor pages.
        ids = [identity for _stamp, identity in rows]
        with self.db:
            for table in ("event_raw", "hold", "citation_owner", "event"):
                self.db.executemany(f"DELETE FROM {table} WHERE id=?", [(identity,) for identity in ids])
        self.db.execute("PRAGMA incremental_vacuum").fetchall()
        self.charge_growth()
        return max(len(ids), before-self._size)

    def _allowance(self, account):
        if self.budget is None:
            return None
        budget = self.budget
        # Some detector accounts conservatively estimate logical payloads. The total byte ceiling
        # follows reported physical file growth, so those estimates cannot consume a quiet owner's floor.
        available = max(0, budget.disk_total-budget.physical_used)
        if account is not None and account.yields:
            cached = sum(size for owner, size in self._allocations.items() if owner.yields)
            available = min(available, max(0, budget.yield_cap-cached))
        headroom = budget.headroom()
        return available if headroom is None else min(available, headroom)

    @reclaiming_write
    def _write(self, operation, count, accounts=(), estimated_bytes=0, *, retry=True):
        account = self.account
        if self.budget is not None:
            if not accounts:
                self.budget.reclaim_citations(estimated_bytes+16384)
            self.budget.check_free()
            # Shared records may have several owners; one admissible owner retains the physical copy.
            reason = ""
            for account in accounts or (self.account,):
                reason = self.budget.new_key_reason(account)
                if not reason:
                    break
            if reason:
                self.refusal_reason = reason
                self.refused += count
                return
            page = self.db.execute("PRAGMA page_size").fetchone()[0]
            pages = self.db.execute("PRAGMA page_count").fetchone()[0]
            allowance = self._allowance(account)
            self.db.execute(f"PRAGMA max_page_count={pages + allowance//page}")
            free_pages = self.db.execute("PRAGMA freelist_count").fetchone()[0]
            if estimated_bytes > allowance+(free_pages+1)*page:
                self.refusal_reason = "estimated citation batch exceeds its body allowance"
                self.refused += count
                return
        while True:
            try:
                operation()
                return
            except sqlite3.OperationalError as exc:
                self.db.rollback()
                self._raw_table = bool(self.db.execute("SELECT 1 FROM sqlite_master WHERE name='raw'").fetchone())
                if "full" not in str(exc).lower():
                    raise
                self.charge_growth(account)
                if retry and not accounts and self.budget is not None and self.budget.reclaim_citations_step():
                    pages = self.db.execute("PRAGMA page_count").fetchone()[0]
                    self.db.execute(f"PRAGMA max_page_count={pages + self._allowance(account)//page}")
                    continue
                self.refusal_reason = "event stage reached the physical whole-hunt byte ceiling or volume reserve"
                self.refused += count
                return
            finally:
                self.charge_growth(account)

    def _cap_windows(self) -> None:
        if self.budget is None:
            return
        self.budget.reclaim_citations(16384)
        headroom = self._allowance(self.windows_account) if self.windows_account is not None else self.budget.headroom()
        if headroom is None:
            return
        pages = self.windows_db.execute("PRAGMA page_count").fetchone()[0]
        self.windows_db.execute(f"PRAGMA max_page_count = {pages + headroom // self._windows_page}")

    def _charge_windows_growth(self) -> None:
        size = self.windows_db.execute("PRAGMA page_count").fetchone()[0] * self._windows_page
        growth = size - self._windows_size
        if growth > 0 and self.budget is not None and self.windows_account is not None:
            self.budget.charge(self.windows_account, growth)
            self.budget.physical_account(self.windows_account, growth)
            self.budget.grew(growth)
        self._windows_size = size

    @reclaiming_write
    def unique_windows(self, events: list[TypedEvent]) -> tuple[list[TypedEvent], list[TypedEvent]]:
        """Deduplicate only Windows stable ids, storing no event body and no raw telemetry."""
        self.windows_refused = 0
        self.windows_refusal_reason = ""
        windows = [event for event in events if event.normalizer.startswith("windows-")]
        if any(len(event.id) > WINDOWS_STABLE_ID_MAX_CHARS for event in windows):
            raise ValueError("Windows stable event id exceeds the dedup table width")
        ids = sorted({event.id for event in windows})
        seen: set[str] = set()
        for start in range(0, len(ids), 500):
            chunk = ids[start:start + 500]
            if not chunk:
                continue
            marks = ",".join("?" * len(chunk))
            seen.update(row[0] for row in self.windows_db.execute(
                f"SELECT id FROM windows_seen WHERE id IN ({marks})", chunk,
            ))
        fresh, duplicates, inserts = [], [], []
        for event in events:
            if not event.normalizer.startswith("windows-"):
                fresh.append(event)
                continue
            if event.id in seen:
                duplicates.append(event)
            else:
                seen.add(event.id)
                inserts.append((event.id,))
                fresh.append(event)
        for start in range(0, len(inserts), 500):
            chunk = inserts[start:start + 500]
            reason = (self.budget.new_key_reason(self.windows_account)
                      if self.budget is not None and self.windows_account is not None else "")
            if reason:
                self.windows_refused += len(inserts) - start
                self.windows_refusal_reason = reason
                break
            while True:
                try:
                    self._cap_windows()
                    self.windows_db.executemany("INSERT OR IGNORE INTO windows_seen VALUES (?)", chunk)
                    self.windows_db.commit()
                    self._charge_windows_growth()
                    break
                except sqlite3.OperationalError as exc:
                    self.windows_db.rollback()
                    self._charge_windows_growth()
                    if (self.budget is not None and "full" in str(exc).lower()
                            and self.budget.reclaim_citations_step()):
                        continue
                    reason = f"writing the Windows dedup store failed ({exc})"
                    if self.budget is not None:
                        if "full" in str(exc).lower():
                            self.budget.refuse_capacity(self.windows_account, reason)
                        else:
                            self.budget.fail(reason)
                    self.windows_refused += len(inserts) - start
                    self.windows_refusal_reason = reason
                    break
            if self.windows_refusal_reason:
                break
        # An event whose dedup state was refused is still delivered: every rule reads every batch, and a strong
        # indicator must publish on its own. A later partition may then deliver another copy of it as fresh, so
        # the refusal reason says that counts may include such copies.
        return fresh, duplicates

    def put(self, events: list[TypedEvent], raw_sources: dict[str, dict]) -> None:
        self.refusal_reason = ""
        groups = defaultdict(list)
        for event in events:
            accounts = tuple(sorted(set(self.owners.get(event.id, ())), key=lambda account: account.name))
            groups[accounts].append(event)
        for accounts, batch in groups.items():
            prepared = self._prepare(batch, raw_sources)
            estimate = sum(len(value.encode()) for values in prepared for value in values.values())+128*len(batch)
            before = self.refused
            self._write(lambda batch=batch, prepared=prepared: self._put(batch, raw_sources, prepared),
                        len(batch), accounts, estimate)
            if self.refused != before:
                self._put_compact(batch, accounts=accounts, raws=prepared[1])

    def _prepare(self, events, raw_sources):
        first = {event.id: event for event in reversed(events)}
        ids = list(first)
        present = {row[0] for start in range(0, len(ids), 500) for row in self.db.execute(
            f"SELECT id FROM event WHERE id IN ({','.join('?' for _ in ids[start:start+500])})",
            ids[start:start+500])}
        bodies = {identity: event.model_dump_json() for identity, event in first.items() if identity not in present}
        raws = {ref.key: json.dumps(raw_sources[ref.key], sort_keys=True)
                for event in first.values() for ref in event.raw if ref.key in raw_sources}
        return bodies, raws

    def _owner_number(self, name):
        number = self._owner_numbers.get(name)
        if number is None:
            number = self._owner_numbers[name] = len(self._owner_numbers)+1
        return number

    def _record_owners(self, events, accounts):
        accounts = tuple(account for account in accounts if account is not None)
        if not accounts:
            return 0
        return self.db.executemany("INSERT OR IGNORE INTO citation_owner(id,owner) VALUES(?,?)",
                                   [(event.id, self._owner_number(account.name))
                                    for event in events for account in accounts]).rowcount

    def _cache_changed(self, events=(), *, ids=(), body=False, raw=False):
        """Invalidate fixed-owner revisions only after committed cache/ownership changes."""
        if not body and not raw:
            return
        if body:
            self._body_cursor = ""
        ids = sorted({*ids, *(event.id for event in events)})
        body_owners, raw_owners = set(), set()
        for start in range(0, len(ids), 500):
            chunk = ids[start:start+500]
            marks = ",".join("?" for _ in chunk)
            if body:
                body_owners.update(row[0] for row in self.db.execute(
                    f"SELECT c.owner FROM citation_owner c JOIN event e ON e.id=c.id "
                    f"WHERE c.id IN ({marks}) AND typeof(e.body)='text'", chunk))
            if raw:
                # Distinct normalized events can cite one native record (for example rename source/target).
                # A text-body change can therefore relax another owner's shared raw-body pin.
                raw_owners.update(row[0] for row in self.db.execute(
                    "SELECT DISTINCT c.owner FROM event_raw own JOIN event_raw peer ON peer.key=own.key "
                    f"JOIN citation_owner c ON c.id=peer.id WHERE own.id IN ({marks})", chunk))
        for owner in sorted(body_owners):
            self._body_revisions[owner] += 1
        for owner in sorted(raw_owners):
            self._raw_revisions[owner] += 1

    def _compact_cache(self, events, accounts, *, drop_raw=False):
        """Release optional source bodies before refusing a recorded positive's compact witness."""
        if self.db is not self._cache_connection:
            self.db.create_function("citation_epoch", 1, _citation_epoch, deterministic=True)
            self._body_cursor = ""
            # Connection replacement/reopen starts unknown: infer live text state once, never per batch.
            self._cache_connection = self.db
            self._text_rows = None
            self._cache_passes.clear()
        if self._text_rows is None:
            self._text_rows = self.db.execute("SELECT COUNT(*) FROM event WHERE typeof(body)='text'").fetchone()[0]
        if not drop_raw and self._text_rows == 0:
            return
        names = tuple(sorted(self._owner_number(account.name) for account in accounts))
        cache_key = (drop_raw, names)
        def revisions():
            return tuple((self._body_revisions[name], self._raw_revisions[name] if drop_raw else 0) for name in names)
        if names and self._cache_passes.get(cache_key) == revisions():
            self._cache_passes.move_to_end(cache_key)
            return
        compacted = False
        def compact_ids(ids):
            nonlocal compacted
            marks = ",".join("?" for _ in ids)
            rows = self.db.execute(f"SELECT id,body,kept FROM event WHERE id IN ({marks}) AND typeof(body)='text' ORDER BY id", ids).fetchall()
            compacted |= bool(rows)
            packed = [(identity, compact_event(TypedEvent.model_validate_json(body)), kept)
                      for identity, body, kept in rows]
            raw_deleted = 0
            with self.db:
                # Delete/reinsert lets SQLite merge sparse leaves and reuse their pages for hold/index
                # metadata. In-place body shrinking leaves fragments stranded in otherwise live leaves.
                self.db.executemany("DELETE FROM event WHERE id=?", [(identity,) for identity, _, _ in rows])
                self.db.executemany("INSERT INTO event(id,body,kept) VALUES(?,?,?)", packed)
                if self._raw_table and drop_raw:
                    raw_deleted = self.db.execute(
                        f"DELETE FROM raw WHERE key IN (SELECT key FROM event_raw WHERE id IN ({marks})) "
                        "AND NOT EXISTS (SELECT 1 FROM event_raw r JOIN event e ON e.id=r.id "
                        "WHERE r.key=raw.key AND typeof(e.body)='text')", ids).rowcount
            self._text_rows -= len(rows)
            if rows:
                self._reference_plan = None
            if rows or raw_deleted:
                self._cache_changed(ids=ids, raw=True)
        identities = [] if accounts else sorted({event.id for event in events})
        for start in range(0, len(identities), 500):
            compact_ids(identities[start:start+500])
        if accounts and self.db.execute("SELECT 1 FROM sqlite_master WHERE name='citation_owner'").fetchone():
            marks = ",".join("?" for _ in names)
            cursor = self.db.execute(
                f"SELECT c.id FROM citation_owner c WHERE c.owner IN ({marks}) AND NOT EXISTS "
                f"(SELECT 1 FROM citation_owner other WHERE other.id=c.id AND other.owner NOT IN ({marks})) "
                "GROUP BY c.id ORDER BY c.id", names+names)
            while rows := cursor.fetchmany(500):
                compact_ids([row[0] for row in rows])
        at_reserve = self.budget is not None and self.budget.headroom() == 0
        if self._raw_table and (compacted or at_reserve or drop_raw) and self.db.execute("SELECT 1 FROM raw LIMIT 1").fetchone() is None:
            self.db.execute("DROP TABLE raw")
            self._raw_table = False
        self.db.commit()
        if names:
            self._cache_passes[cache_key] = revisions()
            self._cache_passes.move_to_end(cache_key)
            while len(self._cache_passes) > max(8, 4*(len(self.owner_accounts)+1)):
                self._cache_passes.popitem(last=False)

    def _ensure_raw(self):
        if not self._raw_table:
            self.db.execute("CREATE TABLE IF NOT EXISTS raw (key TEXT PRIMARY KEY,body TEXT NOT NULL,kept INTEGER NOT NULL)")
            self._raw_table = True

    def _cache_sources(self, events, raws, accounts, kept):
        """Optional source copies may reuse allocated pages, never grow a compact-reference write."""
        if not raws or not self._raw_table:
            return
        keys = sorted({ref.key for event in events for ref in event.raw if ref.key in raws})
        if not keys:
            return
        pages = self.db.execute("PRAGMA page_count").fetchone()[0]
        self.db.execute(f"PRAGMA max_page_count={pages}")
        try:
            with self.db:
                raw_added = self.db.executemany("INSERT OR IGNORE INTO raw VALUES(?,?,?)",
                                               [(key, raws[key], kept) for key in keys]).rowcount
                if kept:
                    self.db.executemany(RAW_KEEP, [(key,) for key in keys])
                self.db.executemany("INSERT OR IGNORE INTO event_raw VALUES(?,?)",
                                    [(event.id, ref.key) for event in events for ref in event.raw if ref.key in keys])
                owners_added = self._record_owners(events, accounts)
        except sqlite3.OperationalError as exc:
            if "full" not in str(exc).lower():
                raise
            return
        self._cache_changed(events, body=bool(owners_added), raw=bool(raw_added or owners_added))

    @reclaiming_write
    def _put_compact(self, events, held=(), accounts=(), *, raws=None):
        self._insert_compact(events, held, accounts)
        # All mandatory siblings finish before optional copies can reuse any remaining pages.
        if raws and self._raw_table:
            ids = [event.id for event in events]
            present = {row[0] for start in range(0, len(ids), 500) for row in self.db.execute(
                f"SELECT id FROM event WHERE id IN ({','.join('?' for _ in ids[start:start+500])})",
                ids[start:start+500])}
            self._cache_sources([event for event in events if event.id in present], raws, accounts, int(not held))

    def _insert_compact(self, events, held=(), accounts=(), *, cache_ready=False, raw_reclaimed=False):
        if not cache_ready:
            try:
                self._compact_cache(events, accounts)
            except sqlite3.OperationalError as exc:
                if "full" not in str(exc).lower():
                    raise
        # Mandatory references survive optional body limits and retry real FULL under the same physical policy.
        account = self.account
        if self.budget is not None:
            account = max(accounts or (self._citation_account,), key=lambda item: (self._allowance(item), item.name))
        try:
            self._write_compact(events, held, accounts, account)
            self.events += len(events)
        except sqlite3.OperationalError as exc:
            self.db.rollback()
            if "full" not in str(exc).lower():
                raise
            self.charge_growth(account)
            if not raw_reclaimed:
                try:
                    self._compact_cache(events, accounts, drop_raw=True)
                except sqlite3.OperationalError as cache_exc:
                    if "full" not in str(cache_exc).lower():
                        raise
                self._insert_compact(events, held, accounts, cache_ready=True, raw_reclaimed=True)
                return
            if len(events) > 1:
                midpoint = len(events)//2
                for subset in (events[:midpoint], events[midpoint:]):
                    ids = {event.id for event in subset}
                    self._insert_compact(subset, [(owner, event) for owner, event in held if event.id in ids],
                                         accounts, cache_ready=True, raw_reclaimed=True)
            else:
                self.refusal_reason = "compact citation storage reached the physical whole-hunt byte ceiling or volume reserve"
        finally:
            self.charge_growth(account)

    def _write_compact(self, events, held, accounts, account):
        packed = [(event.id, compact_event(event), int(not held)) for event in events]
        while True:
            if self.budget is not None:
                page = self.db.execute("PRAGMA page_size").fetchone()[0]
                pages = self.db.execute("PRAGMA page_count").fetchone()[0]
                room = self.budget.physical_allowance(account)
                self.db.execute(f"PRAGMA max_page_count={pages+room//page}")
            try:
                before = self.db.total_changes
                with self.db:
                    self.db.executemany("INSERT OR IGNORE INTO event(id,body,kept) VALUES(?,?,?)", packed)
                    self._record_owners(events, accounts)
                    if held:
                        self.db.executemany(HOLD_ADD, [(event.id, owner) for owner, event in held])
                        self.db.executemany("INSERT OR IGNORE INTO event_raw VALUES (?, ?)",
                                            [(event.id, ref.key) for event in events for ref in event.raw])
                    else:
                        self.db.executemany(EVENT_KEEP, [(event.id,) for event in events])
                if self.db.total_changes != before:
                    self._reference_plan = None
                return
            except sqlite3.OperationalError as exc:
                self.db.rollback()
                self.charge_growth(account)
                if "full" in str(exc).lower() and self.budget is not None and self.budget.reclaim_citations_step():
                    continue
                raise
            finally:
                self.charge_growth(account)

    def _put(self, events: list[TypedEvent], raw_sources: dict[str, dict], prepared=None) -> None:
        """Stage events to be kept to the end of the sweep: the first event body wins, raw copies are keyed, and an
        event or raw copy staged earlier only as a hold is kept from now on."""
        if not events:
            return
        first: dict[str, TypedEvent] = {}
        for e in events:
            first.setdefault(e.id, e)
        bodies, raws = prepared or self._prepare(events, raw_sources)
        self.db.executemany("INSERT OR IGNORE INTO event(id,body,kept) VALUES (?, ?, 1)",
                            list(bodies.items()))
        # an event or raw copy staged earlier only as a hold is kept from now on: a release never removes it
        self.db.executemany(EVENT_KEEP, [(eid,) for eid in first])
        self.db.executemany("INSERT OR IGNORE INTO event_raw VALUES (?, ?)",
                            [(event.id, ref.key) for event in first.values() for ref in event.raw])
        account_set = sorted({account for event in first.values() for account in self.owners.get(event.id, ())},
                             key=lambda account: account.name)
        owners_added = self._record_owners(list(first.values()), account_set)
        raw_added = 0
        if raws:
            self._ensure_raw()
            raw_added = self.db.executemany("INSERT OR IGNORE INTO raw VALUES (?, ?, 1)", list(raws.items())).rowcount
            self.db.executemany(RAW_KEEP, [(k,) for k in raws])
        self.db.commit()
        if self._text_rows is not None:
            self._text_rows += len(bodies)
        self._cache_changed(list(first.values()), body=bool(bodies or owners_added), raw=bool(raw_added or owners_added))
        self.events += len(events)

    def hold(self, held: list[tuple[str, TypedEvent]], raw_sources: dict[str, dict]) -> None:
        groups = defaultdict(list)
        for pair in held:
            groups[self.owner_accounts.get(pair[0], self.account)].append(pair)
        for account, batch in groups.items():
            prepared = self._prepare([event for _, event in batch], raw_sources)
            estimate = sum(len(value.encode()) for values in prepared for value in values.values())+128*len(batch)
            before = self.refused
            self._write(lambda batch=batch, prepared=prepared, account=account:
                        self._hold(batch, raw_sources, prepared, (account,)), len(batch), (account,), estimate)
            if self.refused != before:
                self._put_compact(list({event.id: event for _, event in batch}.values()), batch, (account,), raws=prepared[1])

    def _hold(self, held: list[tuple[str, TypedEvent]], raw_sources: dict[str, dict], prepared=None, accounts=()) -> None:
        """Stage events that an owner (a playbook) holds until it releases them: one hold per (owner, event) pair
        listed, counted, so an event held twice is released twice. An event also staged by `put` is kept."""
        if not held:
            return
        first: dict[str, TypedEvent] = {}
        for _owner, e in held:
            first.setdefault(e.id, e)
        bodies, raws = prepared or self._prepare(list(first.values()), raw_sources)
        present: set[str] = set()
        ids = list(first)
        for i in range(0, len(ids), 500):
            chunk = ids[i:i + 500]
            marks = ",".join("?" * len(chunk))
            present.update(row[0] for row in self.db.execute(f"SELECT id FROM event WHERE id IN ({marks})", chunk))
        # an event already on the stage (kept, or held before) is not serialized again
        self.db.executemany("INSERT INTO event(id,body,kept) VALUES (?, ?, 0)",
                            [(eid, body) for eid, body in bodies.items() if eid not in present])
        self.db.executemany(HOLD_ADD, [(e.id, owner) for owner, e in held])
        owners_added = self._record_owners(list(first.values()), accounts)
        raw_added = 0
        kept = {row[0] for i in range(0, len(ids), 500) for row in self.db.execute(
            f"SELECT id FROM event WHERE kept = 1 AND id IN ({','.join('?' * len(ids[i:i + 500]))})", ids[i:i + 500])}
        self.db.executemany("INSERT OR IGNORE INTO event_raw VALUES (?, ?)",
                            [(eid, r.key) for eid, e in first.items() if eid not in kept for r in e.raw])
        if raws:
            self._ensure_raw()
            raw_added = self.db.executemany("INSERT OR IGNORE INTO raw VALUES (?, ?, 0)", list(raws.items())).rowcount
        self.db.commit()
        if self._text_rows is not None:
            self._text_rows += len(bodies)
        self._cache_changed(list(first.values()), body=bool(bodies or owners_added), raw=bool(raw_added or owners_added))
        self.events += len(first)

    def release(self, owner: str, ids: list[str]) -> None:
        """The owner no longer needs these held events (one hold each). An event that nobody keeps or holds any more
        is removed, with each raw copy that no kept event and no other held event references."""
        if not ids:
            return
        pairs = [(i, owner) for i in ids]
        self.db.executemany(HOLD_DECREMENT, pairs)
        self.db.executemany(HOLD_DROP, sorted(set(pairs)))
        text_deleted = 0
        raw_changed_owners = set()
        for event_id in sorted(set(ids)):
            unheld = self.db.execute(UNHELD, (event_id,)).fetchone()
            if unheld is None:
                continue                # kept, still held by someone, or already gone
            text_deleted += unheld[0] == "text"
            keys = sorted(row[0] for row in self.db.execute(HELD_RAW, (event_id,)))
            if unheld[0] == "text":
                for start in range(0, len(keys), 500):
                    chunk = keys[start:start+500]
                    marks = ",".join("?" for _ in chunk)
                    raw_changed_owners.update(row[0] for row in self.db.execute(
                        "SELECT DISTINCT c.owner FROM event_raw r JOIN citation_owner c ON c.id=r.id "
                        f"WHERE r.key IN ({marks})", chunk))
            self.db.execute(EVENT_DROP, (event_id,))
            self.db.execute(EVENT_RAW_DROP, (event_id,))
            if self._raw_table:
                self.db.executemany(RAW_DROP, [(k,) for k in keys])
        self.db.commit()
        if self._text_rows is not None:
            self._text_rows -= text_deleted
        for changed_owner in sorted(raw_changed_owners):
            self._raw_revisions[changed_owner] += 1

    def count(self) -> int:
        """Events on the stage now."""
        return self.db.execute("SELECT COUNT(*) FROM event").fetchone()[0]

    def load(self, ids: list[str]) -> list[TypedEvent]:
        out: dict[str, TypedEvent] = {}
        for i in range(0, len(ids), 500):
            chunk = ids[i:i + 500]
            marks = ",".join("?" * len(chunk))
            for eid, body in self.db.execute(f"SELECT id, body FROM event WHERE id IN ({marks})", chunk):
                event = expand_event(body) if isinstance(body, bytes) else TypedEvent.model_validate_json(body)
                if isinstance(body, bytes) and COMPACT_CITATION_NOTE not in event.caveats:
                    event.caveats.append(COMPACT_CITATION_NOTE)
                out[eid] = event
        return [out[i] for i in ids if i in out]

    def raw_sources(self, events: list[TypedEvent]) -> dict[str, dict]:
        if not self._raw_table:
            return {}
        keys = sorted({r.key for e in events for r in e.raw})
        out: dict[str, dict] = {}
        for i in range(0, len(keys), 500):
            chunk = keys[i:i + 500]
            marks = ",".join("?" * len(chunk))
            for key, body in self.db.execute(f"SELECT key, body FROM raw WHERE key IN ({marks})", chunk):
                out[key] = json.loads(body)
        return out

    def load_required(self, ids: list[str]) -> list[TypedEvent]:
        """Finalizers receive a uniform, recoverable failure for refused citation bodies."""
        events = self.load(ids)
        return events

    def record_baseline_cell(self, *, target: str, partition: str, start, end,
                             **kwargs) -> None:
        self.refusal_reason = ""
        self._write(lambda: self._record_baseline_cell(target=target, partition=partition, start=start, end=end,
                                                      **kwargs), 1)
        if self.refusal_reason:
            raise sqlite3.OperationalError("compact baseline stage refused: " + self.refusal_reason)

    def _record_baseline_cell(self, *, target: str, partition: str, start, end,
                             target_applicable: bool, source_complete: bool, reasons: list[str],
                             task_id: str | None, events: list[TypedEvent], observations=(),
                             pendings: tuple[Pending, ...] = (), counts=(), scope_hours=(), event_hours=()) -> None:
        """Stage one exec-pair cell using compact rows only, atomically."""
        self._ensure_baseline()
        def body(value) -> str:
            return json.dumps(value, sort_keys=True, default=lambda item: item.isoformat())

        with self.db:
            self.db.execute(
                "INSERT OR REPLACE INTO baseline_cell VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (target, partition, start.isoformat(), end.isoformat(), int(target_applicable),
                 int(source_complete), json.dumps(sorted(set(reasons))), task_id),
            )
            for table in ("baseline_exec", "baseline_observation", "baseline_pending",
                          "baseline_count", "baseline_scope_hour", "baseline_event_hour"):
                self.db.execute(f"DELETE FROM {table} WHERE target = ? AND partition = ?", (target, partition))
            self.db.executemany(
                "INSERT INTO baseline_exec VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [(
                    target, partition, ordinal, event.family, event.host, boot_of(event),
                    event.get("process.pid") if isinstance(event.get("process.pid"), int) else None,
                    event.get("process.ppid") if isinstance(event.get("process.ppid"), int) else None,
                    event.ts.isoformat(), exec_serial(event),
                    event.get("process.session_id")
                    if isinstance(event.get("process.session_id"), int) else None,
                    event.get("process.executable") if isinstance(event.get("process.executable"), str) else None,
                    event.outcome.value, event.id,
                ) for ordinal, event in enumerate(events)],
            )
            self.db.executemany(
                "INSERT INTO baseline_observation VALUES (?, ?, ?, ?)",
                [(target, partition, ordinal, body(row)) for ordinal, row in enumerate(observations)],
            )
            self.db.executemany(
                "INSERT INTO baseline_pending VALUES (?, ?, ?, ?)",
                [(target, partition, ordinal, body(asdict(pending)))
                 for ordinal, pending in enumerate(pendings)],
            )
            self.db.executemany(
                "INSERT INTO baseline_count VALUES (?, ?, ?, ?)",
                [(target, partition, ordinal, body(row)) for ordinal, row in enumerate(counts)],
            )
            self.db.executemany(
                "INSERT INTO baseline_scope_hour VALUES (?, ?, ?, ?)",
                [(target, partition, ordinal, body(row)) for ordinal, row in enumerate(scope_hours)],
            )
            self.db.executemany(
                "INSERT INTO baseline_event_hour VALUES (?, ?, ?, ?)",
                [(target, partition, ordinal, body(row)) for ordinal, row in enumerate(event_hours)],
            )

    def baseline_cells(self, target: str) -> list[dict]:
        """A target's staged cells newest-first, which is the carry-in writer's processing order."""
        if not self._baseline_ready:
            return []
        rows = self.db.execute(
            "SELECT partition, start, end, target_applicable, source_complete, reasons, task_id "
            "FROM baseline_cell "
            "WHERE target = ? ORDER BY start DESC, partition DESC",
            (target,),
        )
        return [{
            "partition": partition,
            "start": datetime.fromisoformat(start),
            "end": datetime.fromisoformat(end),
            "target_applicable": bool(target_applicable), "source_complete": bool(source_complete),
            "reasons": json.loads(reasons),
            "task_id": task_id,
        } for partition, start, end, target_applicable, source_complete, reasons, task_id in rows]

    def baseline_execs(self, target: str, partition: str) -> list[dict]:
        if not self._baseline_ready:
            return []
        rows = self.db.execute(
            "SELECT family, host, boot, pid, ppid, ts, serial, session, executable, outcome, event_id "
            "FROM baseline_exec "
            "WHERE target = ? AND partition = ? ORDER BY ordinal", (target, partition),
        )
        return [{
            "family": family, "host": host, "boot": boot, "pid": pid, "ppid": ppid,
            "ts": datetime.fromisoformat(ts), "serial": serial, "session": session, "executable": executable,
            "outcome": outcome, "event_id": event_id,
        } for family, host, boot, pid, ppid, ts, serial, session, executable, outcome, event_id in rows]

    def baseline_observations(self, target: str, partition: str) -> list[dict]:
        if not self._baseline_ready:
            return []
        rows = self.db.execute(
            "SELECT body FROM baseline_observation WHERE target = ? AND partition = ? ORDER BY ordinal",
            (target, partition),
        )
        out = []
        for (body,) in rows:
            row = json.loads(body)
            for name in ("first_ts", "last_ts"):
                if row.get(name):
                    row[name] = datetime.fromisoformat(row[name])
            out.append(row)
        return out

    def baseline_pendings(self, target: str, partition: str) -> list[Pending]:
        if not self._baseline_ready:
            return []
        rows = self.db.execute(
            "SELECT body FROM baseline_pending WHERE target = ? AND partition = ? ORDER BY ordinal",
            (target, partition),
        )
        out = []
        for (body,) in rows:
            row = json.loads(body)
            row["ts"] = datetime.fromisoformat(row["ts"])
            row["raw_refs"] = tuple(tuple(ref) for ref in row.get("raw_refs") or ())
            out.append(Pending(**row))
        return out

    def _baseline_counter_rows(self, table: str, target: str, partition: str) -> list[dict]:
        if not self._baseline_ready:
            return []
        rows = self.db.execute(
            f"SELECT body FROM {table} WHERE target = ? AND partition = ? ORDER BY ordinal",
            (target, partition),
        )
        out = []
        for (body,) in rows:
            row = json.loads(body)
            for name in ("bucket", "material_hour", "hour", "first_ts", "last_ts"):
                if row.get(name):
                    row[name] = datetime.fromisoformat(row[name])
            out.append(row)
        return out

    def baseline_counts(self, target: str, partition: str) -> list[dict]:
        return self._baseline_counter_rows("baseline_count", target, partition)

    def baseline_scope_hours(self, target: str, partition: str) -> list[dict]:
        return self._baseline_counter_rows("baseline_scope_hour", target, partition)

    def baseline_event_hours(self, target: str, partition: str) -> list[dict]:
        return self._baseline_counter_rows("baseline_event_hour", target, partition)

    def baseline_compact_bytes(self) -> int:
        """Logical bytes in compact baseline rows, excluding fixed empty-table page overhead."""
        if not self._baseline_ready:
            return 0
        total = 0
        for table in ("baseline_cell", "baseline_exec", "baseline_observation", "baseline_pending",
                      "baseline_count", "baseline_scope_hour", "baseline_event_hour"):
            columns = [row[1] for row in self.db.execute(f"PRAGMA table_info({table})")]
            expression = " + ".join(f"length(coalesce(cast({name} AS TEXT), ''))" for name in columns)
            total += int(self.db.execute(f"SELECT coalesce(sum({expression}), 0) FROM {table}").fetchone()[0])
        return total

    def drop_baseline_cell(self, target: str, partition: str) -> None:
        if not self._baseline_ready:
            return
        with self.db:
            for table in ("baseline_exec", "baseline_observation", "baseline_pending",
                          "baseline_count", "baseline_scope_hour", "baseline_event_hour", "baseline_cell"):
                self.db.execute(f"DELETE FROM {table} WHERE target = ? AND partition = ?", (target, partition))

    def close(self) -> None:
        """Close the database before removing its directory (Windows cannot delete an open file)."""
        if self.windows_db is not None:
            self.windows_db.close()
            self.windows_db = None
        if self.db is not None:
            self.db.close()
            self.db = None
            if self.budget is not None:
                accounts = {id(account): account for account in
                            (self.account, self.windows_account, self._citation_account, *self.owner_accounts.values())
                            if account is not None}
                for account in sorted(accounts.values(), key=lambda item: item.name):
                    self.budget.release_physical_account(account)
                self._citation_account.evict = None
                self._citation_account.evict_references = None
        shutil.rmtree(self._dir, ignore_errors=True)

    def __del__(self):
        with contextlib.suppress(Exception):    # interpreter shutdown: nothing useful to report
            self.close()
