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

from romulus.detect.bounded import Account, StateBudget
from romulus.evidence.typed import TypedEvent

PREFIX = "romulus-stage-"
PCAP_PREFIX = "romulus-pcap-"            # the packet stage's capture directory
STALE_SECONDS = 6 * 3600
WINDOWS_STABLE_ID_MAX_CHARS = 64


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
        self.db.execute("CREATE TABLE event (id TEXT PRIMARY KEY, body TEXT NOT NULL)")
        self.db.execute("CREATE TABLE raw (key TEXT PRIMARY KEY, body TEXT NOT NULL)")
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
        refused_ids: set[str] = set()
        for start in range(0, len(inserts), 500):
            chunk = inserts[start:start + 500]
            reason = (self.budget.new_key_reason(self.windows_account)
                      if self.budget is not None and self.windows_account is not None else "")
            if reason:
                self.windows_refused += len(inserts) - start
                self.windows_refusal_reason = reason
                refused_ids.update(event_id for event_id, in inserts[start:])
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
                refused_ids.update(event_id for event_id, in inserts[start:])
                break
        # An id whose dedup state was refused cannot be evaluated safely: a later partition would otherwise
        # consume the same event as fresh again and inflate aggregate counts. Coverage retains the exact refusal.
        return ([event for event in fresh if event.id not in refused_ids],
                [event for event in duplicates if event.id not in refused_ids])

    def put(self, events: list[TypedEvent], raw_sources: dict[str, dict]) -> None:
        """Stage aggregate inputs exactly as on main; first event body wins and raw copies are keyed."""
        if not events:
            return
        first: dict[str, TypedEvent] = {}
        for event in events:
            first.setdefault(event.id, event)
        self.db.executemany(
            "INSERT OR IGNORE INTO event VALUES (?, ?)",
            [(event_id, event.model_dump_json()) for event_id, event in first.items()],
        )
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
