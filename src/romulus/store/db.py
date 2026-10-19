"""Engine creation (SQLite WAL), migrations, integrity check and small helpers."""
from __future__ import annotations

import hashlib
import json
import threading
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import Engine, create_engine, event, text

from romulus.store.schema import metadata

_write_lock = threading.Lock()


def utcnow() -> datetime:
    return datetime.now(UTC)


def digest(obj) -> str:
    """Stable sha256 over canonical JSON."""
    blob = json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(blob).hexdigest()


def make_engine(db_path: Path | str) -> Engine:
    url = "sqlite://" if str(db_path) == ":memory:" else f"sqlite:///{db_path}"
    if str(db_path) != ":memory:":
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(url, future=True, connect_args={"check_same_thread": False, "timeout": 30})

    @event.listens_for(engine, "connect")
    def _pragmas(dbapi_conn, _):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA synchronous=NORMAL")
        cur.execute("PRAGMA foreign_keys=ON")
        cur.execute("PRAGMA busy_timeout=30000")
        # after a checkpoint, shrink the write-ahead log back to this size: one large transaction
        # (deleting a big hunt) must not leave a gigabyte-sized log file behind
        cur.execute(f"PRAGMA journal_size_limit={WAL_SIZE_LIMIT}")
        cur.close()

    return engine


WAL_SIZE_LIMIT = 64 * 1024 * 1024


def space_report(engine: Engine) -> dict:
    """Database file sizes and how much of the main file is free pages (reclaimable by compaction)."""
    path = Path(engine.url.database or "")
    with engine.connect() as c:
        page = c.exec_driver_sql("PRAGMA page_size").scalar()
        free = c.exec_driver_sql("PRAGMA freelist_count").scalar()
    wal = path.with_name(path.name + "-wal")
    return {"file_bytes": path.stat().st_size if path.exists() else 0,
            "wal_bytes": wal.stat().st_size if wal.exists() else 0,
            "free_bytes": int(page) * int(free)}


def compact(engine: Engine) -> dict:
    """Checkpoint and truncate the write-ahead log, then VACUUM to return free pages to the disk.
    VACUUM rewrites the file and blocks writers while it runs, so callers make sure no hunt is active."""
    before = space_report(engine)
    raw = engine.raw_connection()
    try:
        dbapi = raw.driver_connection
        dbapi.isolation_level = None
        dbapi.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        dbapi.execute("VACUUM")
        dbapi.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        raw.close()
    return {"before": before, "after": space_report(engine)}


def migrate(engine: Engine) -> None:
    """Apply Alembic migrations to head (falls back to metadata for :memory: test engines)."""
    if engine.url.database in (None, "", ":memory:"):
        metadata.create_all(engine)
        return
    from alembic import command
    from alembic.config import Config

    here = Path(__file__).resolve().parent
    cfg = Config()
    cfg.set_main_option("script_location", str(here / "migrations"))
    with engine.begin() as conn:
        cfg.attributes["connection"] = conn
        command.upgrade(cfg, "head")


def write_txn(engine: Engine):
    """Serialize writers in-process; SQLite WAL allows one writer at a time."""

    class _Txn:
        def __enter__(self):
            _write_lock.acquire()
            self._cm = engine.begin()
            return self._cm.__enter__()

        def __exit__(self, *exc):
            try:
                return self._cm.__exit__(*exc)
            finally:
                _write_lock.release()

    return _Txn()


def integrity_check(engine: Engine) -> str:
    with engine.connect() as conn:
        return conn.execute(text("PRAGMA integrity_check")).scalar_one()
