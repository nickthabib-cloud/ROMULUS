"""Engine creation (SQLite WAL), migrations, integrity check and small helpers."""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from contextlib import ExitStack, contextmanager
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import Engine, create_engine, event, text

from romulus.store.schema import metadata

_write_lock = threading.Lock()
_memory_maintenance_lock = threading.Lock()
_maintenance_held = threading.local()


@contextmanager
def maintenance_lease(engine: Engine, *, wait_seconds: float = 0, on_wait=None, allow_nested: bool = False):
    """Acquire a bounded maintenance lease, allowing nested calls on this thread."""
    database = engine.url.database
    key = str(Path(database).resolve()) if database and database != ":memory:" else ":memory:"
    held = getattr(_maintenance_held, "keys", None)
    if held is None:
        held = _maintenance_held.keys = {}
    if held.get(key):
        yield
        return
    deadline = time.monotonic() + max(0, wait_seconds)
    notified = False
    with ExitStack() as stack:
        while True:
            try:
                stack.enter_context(_maintenance_lease_once(engine))
                break
            except RuntimeError:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise
                if not notified and on_wait is not None:
                    on_wait()
                notified = True
                time.sleep(min(0.1, remaining))
        held[key] = allow_nested
        try:
            yield
        finally:
            del held[key]


@contextmanager
def _maintenance_lease_once(engine: Engine):
    """Serialize maintenance with hunt claims across processes for this database.

    OS file locks release on process exit. The lock file stays in place to avoid
    replacing a locked inode while another process is opening it.
    """
    database = engine.url.database
    if not database or database == ":memory:":
        if not _memory_maintenance_lock.acquire(blocking=False):
            raise RuntimeError("Database maintenance is active; try again after compaction")
        try:
            yield
        finally:
            _memory_maintenance_lock.release()
        return
    with Path(str(Path(database).resolve()) + ".maintenance.lock").open("a+b") as handle:
        handle.seek(0, 2)
        if handle.tell() == 0:
            handle.write(b"\0")
            handle.flush()
        handle.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            raise RuntimeError("Database maintenance is active; try again after compaction") from error
        try:
            yield
        finally:
            handle.seek(0)
            if os.name == "nt":
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


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
        # SQLite applies this at the next WAL reset. A large final transaction can leave a larger file;
        # explicit compaction checkpoints again after VACUUM to release that allocation immediately.
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
    dbapi = raw.driver_connection
    isolation = dbapi.isolation_level
    try:
        dbapi.isolation_level = None
        dbapi.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        dbapi.execute("VACUUM")
        dbapi.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        try:
            dbapi.isolation_level = isolation
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


@contextmanager
def read_snapshot(engine: Engine):
    """A connection whose reads all see one database snapshot.

    pysqlite's legacy transaction control begins a transaction only before a write, so SELECTs on one connection
    otherwise each see the latest commit: a concurrent delete between two of them can show a header without its
    rows. An explicit deferred BEGIN makes the first read fix the snapshot (WAL), and every later read on the
    connection sees exactly it; the transaction is rolled back (it wrote nothing) when the block ends.
    """
    with engine.connect() as connection:
        connection.exec_driver_sql("BEGIN")
        try:
            yield connection
        finally:
            connection.rollback()


def integrity_check(engine: Engine) -> str:
    with engine.connect() as conn:
        return conn.execute(text("PRAGMA integrity_check")).scalar_one()
