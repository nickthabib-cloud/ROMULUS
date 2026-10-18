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
        cur.close()

    return engine


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
