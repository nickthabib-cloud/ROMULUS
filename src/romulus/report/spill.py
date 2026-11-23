"""A scratch SQLite file for report aggregation that must stay exact at mission scale with bounded memory.

Distinct counts and per-value groupings over every reportable finding can outgrow memory (a hunt may report a million
findings). They are kept in a temporary database file with a small page cache, deleted when the block ends.
"""
from __future__ import annotations

import sqlite3
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

# the page cache each scratch database may hold in memory (KiB); the rest stays on disk
CACHE_KIB = 16 * 1024


@contextmanager
def scratch_db(directory: Path | None = None) -> Iterator[sqlite3.Connection]:
    """A private SQLite connection on a temporary file (in `directory` when given), removed afterwards."""
    with tempfile.TemporaryDirectory(dir=directory, prefix=".romulus-report-") as root:
        conn = sqlite3.connect(Path(root) / "scratch.db", isolation_level=None)
        try:
            for pragma in (f"cache_size=-{CACHE_KIB}", "temp_store=FILE", "journal_mode=OFF", "synchronous=OFF",
                           "locking_mode=EXCLUSIVE"):
                conn.execute(f"PRAGMA {pragma}")
            conn.execute("BEGIN")
            yield conn
        finally:
            conn.close()
