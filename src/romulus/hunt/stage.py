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
from pathlib import Path

from romulus.evidence.typed import TypedEvent

PREFIX = "romulus-stage-"
PCAP_PREFIX = "romulus-pcap-"            # the packet stage's capture directory
STALE_SECONDS = 6 * 3600


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
    def __init__(self, directory: str | Path | None = None):
        if directory is not None:
            Path(directory).mkdir(mode=0o700, parents=True, exist_ok=True)
        self._dir = tempfile.mkdtemp(prefix=PREFIX, dir=directory)
        self.path = Path(self._dir) / "stage.db"
        self.db: sqlite3.Connection | None = sqlite3.connect(self.path)
        self.db.execute("PRAGMA journal_mode=OFF")
        self.db.execute("PRAGMA synchronous=OFF")
        # kept = 1: staged to be kept to the end; 0: present only while a playbook holds it (table hold)
        self.db.execute("CREATE TABLE event (id TEXT PRIMARY KEY, body TEXT NOT NULL, kept INTEGER NOT NULL)")
        self.db.execute("CREATE TABLE raw (key TEXT PRIMARY KEY, body TEXT NOT NULL, kept INTEGER NOT NULL)")
        self.db.execute("CREATE TABLE hold (owner TEXT NOT NULL, id TEXT NOT NULL, n INTEGER NOT NULL, "
                        "PRIMARY KEY (owner, id))")
        # the raw copies a held (not kept) event references, so its release can tell which copies to remove
        self.db.execute("CREATE TABLE event_raw (id TEXT NOT NULL, key TEXT NOT NULL, PRIMARY KEY (id, key))")
        self.db.execute("CREATE INDEX event_raw_key ON event_raw (key)")
        self.events = 0

    def put(self, events: list[TypedEvent], raw_sources: dict[str, dict]) -> None:
        """Stage events and the raw copies they cite. Idempotent: re-reading a partition is safe. The first staged
        copy of an event id is kept; a repeated id is not serialized again."""
        if not events:
            return
        first: dict[str, TypedEvent] = {}
        for e in events:
            first.setdefault(e.id, e)
        self.db.executemany("INSERT OR IGNORE INTO event VALUES (?, ?, 1)",
                            [(eid, e.model_dump_json()) for eid, e in first.items()])
        # an event or raw copy staged earlier only as a hold is kept from now on
        self.db.executemany("UPDATE event SET kept = 1 WHERE id = ? AND kept = 0", [(eid,) for eid in first])
        raws = {r.key: raw_sources[r.key] for e in events for r in e.raw if r.key in raw_sources}
        self.db.executemany("INSERT OR IGNORE INTO raw VALUES (?, ?, 1)",
                            [(k, json.dumps(v, sort_keys=True)) for k, v in raws.items()])
        self.db.executemany("UPDATE raw SET kept = 1 WHERE key = ? AND kept = 0", [(k,) for k in raws])
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
        self.db.executemany("INSERT INTO hold VALUES (?, ?, 1) ON CONFLICT (owner, id) DO UPDATE SET n = n + 1",
                            [(owner, e.id) for owner, e in held])
        self.db.executemany("INSERT OR IGNORE INTO event_raw VALUES (?, ?)",
                            [(eid, r.key) for eid, e in first.items() for r in e.raw])
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
        self.db.executemany("UPDATE hold SET n = n - 1 WHERE owner = ? AND id = ?", [(owner, i) for i in ids])
        self.db.execute("DELETE FROM hold WHERE n <= 0")
        unique = sorted(set(ids))
        for i in range(0, len(unique), 500):
            chunk = unique[i:i + 500]
            marks = ",".join("?" * len(chunk))
            gone = [row[0] for row in self.db.execute(
                f"SELECT id FROM event WHERE id IN ({marks}) AND kept = 0 "
                f"AND NOT EXISTS (SELECT 1 FROM hold WHERE hold.id = event.id)", chunk)]
            if not gone:
                continue
            marks = ",".join("?" * len(gone))
            keys = [row[0] for row in self.db.execute(f"SELECT DISTINCT key FROM event_raw WHERE id IN ({marks})",
                                                      gone)]
            self.db.execute(f"DELETE FROM event WHERE id IN ({marks})", gone)
            self.db.execute(f"DELETE FROM event_raw WHERE id IN ({marks})", gone)
            self.db.executemany("DELETE FROM raw WHERE key = ? AND kept = 0 "
                                "AND NOT EXISTS (SELECT 1 FROM event_raw WHERE event_raw.key = raw.key)",
                                [(k,) for k in keys])
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

    def close(self) -> None:
        """Close the database before removing its directory (Windows cannot delete an open file)."""
        if self.db is not None:
            self.db.close()
            self.db = None
        shutil.rmtree(self._dir, ignore_errors=True)

    def __del__(self):
        with contextlib.suppress(Exception):    # interpreter shutdown: nothing useful to report
            self.close()
