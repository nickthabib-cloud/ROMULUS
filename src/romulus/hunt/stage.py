"""Per-hunt disk staging for aggregate playbooks that join large event sets.

A joining playbook keeps only compact join keys in memory. The full typed events it may cite, and the
raw copies those events reference, go to a private SQLite file for the length of the sweep, so memory
stays bounded however much traffic a mission network produces. At finalize the playbook loads back only
the events it actually cites, and the sweep publishes them with their raw copies, so every citation
resolves to a retained record.

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
        self.db.execute("CREATE TABLE event (id TEXT PRIMARY KEY, body TEXT NOT NULL)")
        self.db.execute("CREATE TABLE raw (key TEXT PRIMARY KEY, body TEXT NOT NULL)")
        self.events = 0

    @staticmethod
    def _merge_raw(first: TypedEvent, later: TypedEvent) -> tuple[TypedEvent, bool]:
        known = {raw.key for raw in first.raw}
        additions = [raw for raw in later.raw if raw.key not in known]
        if not additions:
            return first, False
        return first.model_copy(update={"raw": [*first.raw, *additions]}), True

    def _store(self, events: list[TypedEvent], raw_sources: dict[str, dict], *, classify: bool
               ) -> tuple[list[TypedEvent], list[TypedEvent]]:
        if not events:
            return [], []
        ids = sorted({event.id for event in events})
        stored: dict[str, TypedEvent] = {}
        for start in range(0, len(ids), 500):
            chunk = ids[start:start + 500]
            marks = ",".join("?" * len(chunk))
            for event_id, body in self.db.execute(
                f"SELECT id, body FROM event WHERE id IN ({marks})", chunk,
            ):
                stored[event_id] = TypedEvent.model_validate_json(body)
        fresh: list[TypedEvent] = []
        duplicates: list[TypedEvent] = []
        inserts: list[tuple[str, str]] = []
        updates: list[tuple[str, str]] = []
        for event in events:
            prior = stored.get(event.id)
            if prior is None:
                stored[event.id] = event
                fresh.append(event)
                inserts.append((event.id, event.model_dump_json()))
                continue
            merged, changed = self._merge_raw(prior, event)
            stored[event.id] = merged
            if changed:
                updates.append((merged.model_dump_json(), event.id))
            if classify:
                duplicates.append(merged)
        self.db.executemany("INSERT OR IGNORE INTO event VALUES (?, ?)", inserts)
        self.db.executemany("UPDATE event SET body = ? WHERE id = ?", updates)
        raws = {r.key: raw_sources[r.key] for e in events for r in e.raw if r.key in raw_sources}
        self.db.executemany("INSERT OR IGNORE INTO raw VALUES (?, ?)",
                            [(k, json.dumps(v, sort_keys=True)) for k, v in raws.items()])
        self.db.commit()
        self.events += len(events)
        return fresh, duplicates

    def unique(self, events: list[TypedEvent], raw_sources: dict[str, dict]
               ) -> tuple[list[TypedEvent], list[TypedEvent]]:
        """Return events not seen earlier in this sweep and merge later raw copies on disk."""
        return self._store(events, raw_sources, classify=True)

    def put(self, events: list[TypedEvent], raw_sources: dict[str, dict]) -> None:
        """Stage cited events and raw copies, merging provenance for repeated stable ids."""
        self._store(events, raw_sources, classify=False)

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
