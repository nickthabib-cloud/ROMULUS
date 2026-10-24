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
from datetime import datetime
from pathlib import Path

from romulus.detect.bounded import Account, StateBudget
from romulus.evidence.typed import TypedEvent

PREFIX = "romulus-stage-"
PCAP_PREFIX = "romulus-pcap-"            # the packet stage's capture directory
STALE_SECONDS = 6 * 3600
WINDOWS_STABLE_ID_MAX_CHARS = 64

# Held events. Every statement that releases a hold or keeps a held event looks rows up by a primary key or an index
# (one id or key at a time), so a release costs the same however many holds the stage has; tests check the plans.
HOLD_ADD = "INSERT INTO hold VALUES (?, ?, 1) ON CONFLICT (id, owner) DO UPDATE SET n = n + 1"
HOLD_DECREMENT = "UPDATE hold SET n = n - 1 WHERE id = ? AND owner = ?"
HOLD_DROP = "DELETE FROM hold WHERE id = ? AND owner = ? AND n <= 0"
UNHELD = ("SELECT 1 FROM event WHERE id = ? AND kept = 0 "
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
                 windows_account: Account | None = None):
        if directory is not None:
            Path(directory).mkdir(mode=0o700, parents=True, exist_ok=True)
        self._dir = tempfile.mkdtemp(prefix=PREFIX, dir=directory)
        self.directory = Path(self._dir)
        self.directory.chmod(0o700)
        self.path = Path(self._dir) / "stage.db"
        self.db: sqlite3.Connection | None = sqlite3.connect(self.path)
        self.db.execute("PRAGMA journal_mode=OFF")
        self.db.execute("PRAGMA synchronous=OFF")
        # kept = 1: staged to be kept to the end; 0: present only while a playbook holds it (table hold)
        self.db.execute("CREATE TABLE event (id TEXT PRIMARY KEY, body TEXT NOT NULL, kept INTEGER NOT NULL)")
        self.db.execute("CREATE TABLE raw (key TEXT PRIMARY KEY, body TEXT NOT NULL, kept INTEGER NOT NULL)")
        # holds by event first, so "is this event still held by anyone" is a primary-key lookup
        self.db.execute("CREATE TABLE hold (id TEXT NOT NULL, owner TEXT NOT NULL, n INTEGER NOT NULL, "
                        "PRIMARY KEY (id, owner))")
        # the raw copies a held (not kept) event references, so its release can tell which copies to remove; a held
        # event that becomes kept loses its rows here
        self.db.execute("CREATE TABLE event_raw (id TEXT NOT NULL, key TEXT NOT NULL, PRIMARY KEY (id, key))")
        self.db.execute("CREATE INDEX event_raw_key ON event_raw (key)")
        # Window execs are staged by bounded sweep cell so the baseline carry can replay cells newest-first after
        # the target is complete. Event bodies and raw copies remain in the shared event/raw tables under holds.
        self.db.execute(
            "CREATE TABLE baseline_cell (target TEXT NOT NULL, partition TEXT NOT NULL, start TEXT NOT NULL, "
            "end TEXT NOT NULL, source_complete INTEGER NOT NULL, reasons TEXT NOT NULL, task_id TEXT, "
            "PRIMARY KEY (target, partition))"
        )
        self.db.execute(
            "CREATE TABLE baseline_event (target TEXT NOT NULL, partition TEXT NOT NULL, ordinal INTEGER NOT NULL, "
            "id TEXT NOT NULL, PRIMARY KEY (target, partition, ordinal))"
        )
        self.db.execute("CREATE INDEX baseline_event_id ON baseline_event (id)")
        # One bounded-width key per normalized Windows event. The row count follows the hunt's retrieved Windows
        # records; unlike aggregate staging this seam never serializes event bodies or raw telemetry. Keeping the
        # table in the stage gives all transient sweep state the same private lifecycle and cleanup behavior.
        self.windows_path = Path(self._dir) / "windows-seen.db"
        self.windows_db: sqlite3.Connection | None = sqlite3.connect(self.windows_path)
        self.windows_db.execute("PRAGMA journal_mode=OFF")
        self.windows_db.execute("PRAGMA synchronous=OFF")
        self.windows_db.execute(
            f"CREATE TABLE windows_seen (id TEXT PRIMARY KEY CHECK(length(id) <= "
            f"{WINDOWS_STABLE_ID_MAX_CHARS})) WITHOUT ROWID"
        )
        self.windows_db.commit()
        self._windows_page = self.windows_db.execute("PRAGMA page_size").fetchone()[0]
        self._windows_size = 0
        self.budget = budget
        self.windows_account = windows_account
        self.windows_refused = 0
        self.windows_refusal_reason = ""
        self._charge_windows_growth()
        self.events = 0

    def _cap_windows(self) -> None:
        if self.budget is None:
            return
        headroom = self.budget.headroom()
        if headroom is None:
            return
        pages = self.windows_db.execute("PRAGMA page_count").fetchone()[0]
        self.windows_db.execute(f"PRAGMA max_page_count = {pages + headroom // self._windows_page + 1}")

    def _charge_windows_growth(self) -> None:
        size = self.windows_db.execute("PRAGMA page_count").fetchone()[0] * self._windows_page
        growth = size - self._windows_size
        if growth > 0 and self.budget is not None and self.windows_account is not None:
            self.budget.charge(self.windows_account, growth)
            self.budget.grew(growth)
        self._windows_size = size

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
            try:
                self._cap_windows()
                self.windows_db.executemany("INSERT OR IGNORE INTO windows_seen VALUES (?)", chunk)
                self.windows_db.commit()
                self._charge_windows_growth()
            except sqlite3.OperationalError as exc:
                self.windows_db.rollback()
                reason = f"writing the Windows dedup store failed ({exc})"
                if self.budget is not None:
                    self.budget.fail(reason)
                self.windows_refused += len(inserts) - start
                self.windows_refusal_reason = reason
                break
        # An event whose dedup state was refused is still delivered: every rule reads every batch, and a strong
        # indicator must publish on its own. A later partition may then deliver another copy of it as fresh, so
        # the refusal reason says that counts may include such copies.
        return fresh, duplicates

    def put(self, events: list[TypedEvent], raw_sources: dict[str, dict]) -> None:
        """Stage events to be kept to the end of the sweep: the first event body wins, raw copies are keyed, and an
        event or raw copy staged earlier only as a hold is kept from now on."""
        if not events:
            return
        first: dict[str, TypedEvent] = {}
        for e in events:
            first.setdefault(e.id, e)
        self.db.executemany("INSERT OR IGNORE INTO event VALUES (?, ?, 1)",
                            [(eid, e.model_dump_json()) for eid, e in first.items()])
        # an event or raw copy staged earlier only as a hold is kept from now on: a release never removes it
        self.db.executemany(EVENT_KEEP, [(eid,) for eid in first])
        self.db.executemany(EVENT_RAW_DROP, [(eid,) for eid in first])
        raws = {r.key: raw_sources[r.key] for e in events for r in e.raw if r.key in raw_sources}
        self.db.executemany("INSERT OR IGNORE INTO raw VALUES (?, ?, 1)",
                            [(k, json.dumps(v, sort_keys=True)) for k, v in raws.items()])
        self.db.executemany(RAW_KEEP, [(k,) for k in raws])
        self.db.commit()
        self.events += len(events)

    def hold(self, held: list[tuple[str, TypedEvent]], raw_sources: dict[str, dict]) -> None:
        """Stage events that an owner (a playbook) holds until it releases them: one hold per (owner, event) pair
        listed, counted, so an event held twice is released twice. An event also staged by `put` is kept."""
        if not held:
            return
        first: dict[str, TypedEvent] = {}
        for _owner, e in held:
            first.setdefault(e.id, e)
        present: set[str] = set()
        ids = list(first)
        for i in range(0, len(ids), 500):
            chunk = ids[i:i + 500]
            marks = ",".join("?" * len(chunk))
            present.update(row[0] for row in self.db.execute(f"SELECT id FROM event WHERE id IN ({marks})", chunk))
        # an event already on the stage (kept, or held before) is not serialized again
        self.db.executemany("INSERT INTO event VALUES (?, ?, 0)",
                            [(eid, e.model_dump_json()) for eid, e in first.items() if eid not in present])
        self.db.executemany(HOLD_ADD, [(e.id, owner) for owner, e in held])
        kept = {row[0] for i in range(0, len(ids), 500) for row in self.db.execute(
            f"SELECT id FROM event WHERE kept = 1 AND id IN ({','.join('?' * len(ids[i:i + 500]))})", ids[i:i + 500])}
        self.db.executemany("INSERT OR IGNORE INTO event_raw VALUES (?, ?)",
                            [(eid, r.key) for eid, e in first.items() if eid not in kept for r in e.raw])
        raws = {r.key: raw_sources[r.key] for e in first.values() for r in e.raw if r.key in raw_sources}
        self.db.executemany("INSERT OR IGNORE INTO raw VALUES (?, ?, 0)",
                            [(k, json.dumps(v, sort_keys=True)) for k, v in raws.items()])
        self.db.commit()
        self.events += len(first)

    def release(self, owner: str, ids: list[str]) -> None:
        """The owner no longer needs these held events (one hold each). An event that nobody keeps or holds any more
        is removed, with each raw copy that no kept event and no other held event references."""
        if not ids:
            return
        pairs = [(i, owner) for i in ids]
        self.db.executemany(HOLD_DECREMENT, pairs)
        self.db.executemany(HOLD_DROP, sorted(set(pairs)))
        for event_id in sorted(set(ids)):
            if self.db.execute(UNHELD, (event_id,)).fetchone() is None:
                continue                # kept, still held by someone, or already gone
            keys = [row[0] for row in self.db.execute(HELD_RAW, (event_id,))]
            self.db.execute(EVENT_DROP, (event_id,))
            self.db.execute(EVENT_RAW_DROP, (event_id,))
            self.db.executemany(RAW_DROP, [(k,) for k in keys])
        self.db.commit()

    def count(self) -> int:
        """Events on the stage now."""
        return self.db.execute("SELECT COUNT(*) FROM event").fetchone()[0]

    def load(self, ids: list[str]) -> list[TypedEvent]:
        out: dict[str, TypedEvent] = {}
        for i in range(0, len(ids), 500):
            chunk = ids[i:i + 500]
            marks = ",".join("?" * len(chunk))
            for eid, body in self.db.execute(f"SELECT id, body FROM event WHERE id IN ({marks})", chunk):
                out[eid] = TypedEvent.model_validate_json(body)
        return [out[i] for i in ids if i in out]

    def raw_sources(self, events: list[TypedEvent]) -> dict[str, dict]:
        keys = sorted({r.key for e in events for r in e.raw})
        out: dict[str, dict] = {}
        for i in range(0, len(keys), 500):
            chunk = keys[i:i + 500]
            marks = ",".join("?" * len(chunk))
            for key, body in self.db.execute(f"SELECT key, body FROM raw WHERE key IN ({marks})", chunk):
                out[key] = json.loads(body)
        return out

    def record_baseline_cell(self, *, target: str, partition: str, start, end,
                             source_complete: bool, reasons: list[str], task_id: str | None,
                             events: list[TypedEvent]) -> None:
        """Index held process events under one sweep cell for newest-first baseline replay."""
        self.db.execute(
            "INSERT OR REPLACE INTO baseline_cell VALUES (?, ?, ?, ?, ?, ?, ?)",
            (target, partition, start.isoformat(), end.isoformat(), int(source_complete),
             json.dumps(sorted(set(reasons))), task_id),
        )
        self.db.execute("DELETE FROM baseline_event WHERE target = ? AND partition = ?", (target, partition))
        self.db.executemany(
            "INSERT INTO baseline_event VALUES (?, ?, ?, ?)",
            [(target, partition, ordinal, event.id) for ordinal, event in enumerate(events)],
        )
        self.db.commit()

    def baseline_cells(self, target: str) -> list[dict]:
        """A target's staged cells newest-first, which is the carry-in writer's processing order."""
        rows = self.db.execute(
            "SELECT partition, start, end, source_complete, reasons, task_id FROM baseline_cell "
            "WHERE target = ? ORDER BY start DESC, partition DESC",
            (target,),
        )
        return [{
            "partition": partition,
            "start": datetime.fromisoformat(start),
            "end": datetime.fromisoformat(end),
            "source_complete": bool(source_complete),
            "reasons": json.loads(reasons),
            "task_id": task_id,
        } for partition, start, end, source_complete, reasons, task_id in rows]

    def baseline_events(self, target: str, partition: str) -> list[TypedEvent]:
        rows = self.db.execute(
            "SELECT event.body FROM baseline_event JOIN event ON event.id = baseline_event.id "
            "WHERE baseline_event.target = ? AND baseline_event.partition = ? ORDER BY baseline_event.ordinal",
            (target, partition),
        )
        return [TypedEvent.model_validate_json(body) for (body,) in rows]

    def drop_baseline_cell(self, target: str, partition: str) -> list[str]:
        """Remove the replay index and return the held ids for release by its baseline owner."""
        ids = [row[0] for row in self.db.execute(
            "SELECT id FROM baseline_event WHERE target = ? AND partition = ? ORDER BY ordinal",
            (target, partition),
        )]
        self.db.execute("DELETE FROM baseline_event WHERE target = ? AND partition = ?", (target, partition))
        self.db.execute("DELETE FROM baseline_cell WHERE target = ? AND partition = ?", (target, partition))
        self.db.commit()
        return ids

    def close(self) -> None:
        """Close the database before removing its directory (Windows cannot delete an open file)."""
        if self.windows_db is not None:
            self.windows_db.close()
            self.windows_db = None
        if self.db is not None:
            self.db.close()
            self.db = None
        shutil.rmtree(self._dir, ignore_errors=True)

    def __del__(self):
        with contextlib.suppress(Exception):    # interpreter shutdown: nothing useful to report
            self.close()
