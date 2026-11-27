"""A write transaction that fails to open never keeps the in-process writer lock."""
from __future__ import annotations

import pytest
from sqlalchemy import text

from romulus.store import db
from romulus.store.db import make_engine, write_txn


class _FailingBegin:
    """An engine whose connection checkout fails (a pool timeout, a file that cannot be opened)."""

    def __init__(self, engine):
        self._engine = engine

    def begin(self):
        class _Cm:
            def __enter__(self):
                raise OSError("unable to open database file")

            def __exit__(self, *exc):
                return False
        return _Cm()


def test_a_failed_begin_releases_the_writer_lock(tmp_path):
    engine = make_engine(tmp_path / "store.db")
    try:
        with pytest.raises(OSError):
            with write_txn(_FailingBegin(engine)):
                pass
        free = db._write_lock.acquire(timeout=1)
        assert free, "the writer lock stayed held after the transaction failed to open"
        db._write_lock.release()
        # and a later write in this process proceeds
        with write_txn(engine) as c:
            c.execute(text("CREATE TABLE IF NOT EXISTS probe (x INTEGER)"))
    finally:
        # never leave the module lock held for the rest of the test session
        if db._write_lock.locked() and not db._write_lock.acquire(blocking=False):
            db._write_lock.release()
        engine.dispose()
