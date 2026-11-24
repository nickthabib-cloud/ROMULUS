"""A scratch SQLite file for report aggregation that must stay exact at mission scale with bounded memory.

Distinct counts and per-value groupings over every reportable finding can outgrow memory (a hunt may report a million
findings). They are kept in a temporary database file with a small page cache, deleted when the block ends.
"""
from __future__ import annotations

import shutil
import sqlite3
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

# the page cache each scratch database may hold in memory (KiB); the rest stays on disk
CACHE_KIB = 16 * 1024
PREFIX = ".romulus-report-"
# a scratch directory this old was left by a process that ended without cleaning up (no build runs this long)
STALE_SECONDS = 24 * 3600


def _remove_stale(directory: Path) -> None:
    """Remove scratch directories an earlier process left behind (killed mid-build); never a recent one, which
    may belong to a build running now."""
    cutoff = time.time() - STALE_SECONDS
    for path in directory.glob(PREFIX + "*"):
        try:
            if path.is_dir() and path.stat().st_mtime < cutoff:
                shutil.rmtree(path, ignore_errors=True)
        except OSError:
            continue


@contextmanager
def scratch_db(directory: Path | None = None) -> Iterator[sqlite3.Connection]:
    """A private SQLite connection on a temporary file (in `directory` when given), removed afterwards, also on
    error. Stale scratch directories an earlier process left in `directory` are removed first."""
    if directory is not None:
        _remove_stale(Path(directory))
    with tempfile.TemporaryDirectory(dir=directory, prefix=PREFIX) as root:
        conn = sqlite3.connect(Path(root) / "scratch.db", isolation_level=None)
        try:
            for pragma in (f"cache_size=-{CACHE_KIB}", "temp_store=FILE", "journal_mode=OFF", "synchronous=OFF",
                           "locking_mode=EXCLUSIVE"):
                conn.execute(f"PRAGMA {pragma}")
            # `temp_store_directory` is not set: it is process-wide in SQLite and would move every other connection's
            # temporary files into this short-lived directory. Tables live in this file; the queries are indexed so
            # the large passes read in index order rather than sorting in SQLite's own temporary files.
            conn.execute("BEGIN")
            yield conn
        finally:
            conn.close()
