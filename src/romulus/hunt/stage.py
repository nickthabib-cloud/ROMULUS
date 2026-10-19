"""Per-hunt disk staging for aggregate playbooks that join large event sets.

A joining playbook keeps only compact join keys in memory. The full typed events it may cite, and the
raw copies those events reference, go to a private SQLite file for the length of the sweep, so memory
stays bounded however much traffic a mission network produces. At finalize the playbook loads back only
the events it actually cites, and the sweep publishes them with their raw copies, so every citation
resolves to a retained record.
"""
from __future__ import annotations

import json
import sqlite3
import tempfile
from pathlib import Path

from romulus.evidence.typed import TypedEvent


class EventStage:
    def __init__(self, directory: str | Path | None = None):
        self._dir = tempfile.TemporaryDirectory(prefix="romulus-stage-", dir=directory)
        self.path = Path(self._dir.name) / "stage.db"
        self.db = sqlite3.connect(self.path)
        self.db.execute("PRAGMA journal_mode=OFF")
        self.db.execute("PRAGMA synchronous=OFF")
        self.db.execute("CREATE TABLE event (id TEXT PRIMARY KEY, body TEXT NOT NULL)")
        self.db.execute("CREATE TABLE raw (key TEXT PRIMARY KEY, body TEXT NOT NULL)")
        self.events = 0

    def put(self, events: list[TypedEvent], raw_sources: dict[str, dict]) -> None:
        """Stage events and the raw copies they cite. Idempotent: re-reading a partition is safe."""
        if not events:
            return
        self.db.executemany("INSERT OR IGNORE INTO event VALUES (?, ?)",
                            [(e.id, e.model_dump_json()) for e in events])
        raws = {r.key: raw_sources[r.key] for e in events for r in e.raw if r.key in raw_sources}
        self.db.executemany("INSERT OR IGNORE INTO raw VALUES (?, ?)",
                            [(k, json.dumps(v, sort_keys=True)) for k, v in raws.items()])
        self.db.commit()
        self.events += len(events)

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
        self.db.close()
        self._dir.cleanup()
