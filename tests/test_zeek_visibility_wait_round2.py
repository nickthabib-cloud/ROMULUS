"""Visibility contention and cleanup failures never fabricate complete coverage."""
import errno
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import event, select
from sqlalchemy.exc import OperationalError

from romulus.config import Settings
from romulus.detect.base import Playbook
from romulus.hunt.sweep import Sweep
from romulus.report.manifest import coverage_for_hunt
from romulus.sources.es import ElasticClient
from romulus.sources.models import Window
from romulus.store import db
from romulus.store import schema as t
from tests.test_zeek_visibility_orphans import insert_chunks, repository, rows  # noqa: F401


class Probe(Playbook):
    id = "test.visibility_wait"
    families = ("net_flow",)


class BlockedLock:
    def acquire(self, *, blocking):
        assert blocking is False
        return False


def test_memory_lease_wait_is_bounded_and_sends_heartbeats(monkeypatch):
    engine = db.make_engine(":memory:")
    ticks = iter([0, 0, 0.1, 5])
    beats, sleeps = [], []
    monkeypatch.setattr(db, "_memory_visibility_lock", BlockedLock())
    monkeypatch.setattr(db.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(db.time, "sleep", sleeps.append)
    try:
        with (pytest.raises(TimeoutError, match="visibility.*lease.*unresolved"),
              db.zeek_visibility_lease(engine, wait_seconds=5, on_wait=lambda: beats.append(1))):
            pytest.fail("blocked lease admitted publication")
        assert beats and sleeps
    finally:
        engine.dispose()


def test_memory_lease_wait_can_acquire_after_heartbeat(monkeypatch):
    engine = db.make_engine(":memory:")
    beats, attempts, released = [], [], []

    class EventuallyAvailable:
        def acquire(self, *, blocking):
            attempts.append(blocking)
            return len(attempts) == 3

        def release(self):
            released.append(True)

    monkeypatch.setattr(db, "_memory_visibility_lock", EventuallyAvailable())
    monkeypatch.setattr(db.time, "sleep", lambda _: None)
    try:
        with db.zeek_visibility_lease(engine, on_wait=lambda: beats.append(1)):
            assert len(beats) == 2
        assert released == [True]
    finally:
        engine.dispose()


def test_real_repo_timeout_does_not_consume_rows_or_insert_pointer(repository):  # noqa: F811
    entered, release = threading.Event(), threading.Event()
    consumed, beats = [], []

    def holder():
        with db.zeek_visibility_lease(repository.engine):
            entered.set()
            assert release.wait(10), "test failed to release publication holder"

    def content():
        consumed.append(True)
        yield from rows("not-published")

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(holder)
        assert entered.wait(10)
        try:
            with pytest.raises(TimeoutError, match="visibility.*lease.*unresolved"):
                repository.save_zeek_visibility("h", content(), wait_seconds=0, heartbeat=lambda: beats.append(1))
        finally:
            release.set()
        future.result(timeout=10)
    assert not consumed and beats
    with repository.engine.connect() as connection:
        assert not connection.execute(select(t.report_zeek_visibility)).first()
    reference = repository.save_zeek_visibility("h", iter(rows("after")))
    assert list(repository.zeek_visibility_rows("h", reference["sha256"])) == rows("after")


def sweep_for(repo, tmp_path, beats):
    start = datetime(2026, 1, 1, tzinfo=UTC)
    sweep = Sweep(repo, ElasticClient(Settings(home=tmp_path)), "h",
                  Window(start=start, end=start + timedelta(minutes=15)), {},
                  stage_dir=tmp_path / "stage", heartbeat=lambda: beats.append(1))
    sweep.pack = [Probe()]
    sweep._zeek_visibility_store().activity("sensor", "net_flow", start.timestamp(), start.timestamp() + 60, 1)
    return sweep


def test_sweep_timeout_records_unresolved_without_second_publication(repository, tmp_path, monkeypatch):  # noqa: F811
    beats, attempts = [], []
    sweep = sweep_for(repository, tmp_path, beats)
    real_save = repository.save_zeek_visibility

    def save(hunt, content, **kwargs):
        attempts.append(kwargs)
        return real_save(hunt, content, **{**kwargs, "wait_seconds": 0})

    def blocked(*args):
        raise OSError(errno.EACCES, "injected held visibility lock")

    # Fault only the OS lock primitive; the real Repo publication path remains active.
    if db.os.name == "nt":
        import msvcrt
        monkeypatch.setattr(msvcrt, "locking", blocked)
    else:
        import fcntl
        monkeypatch.setattr(fcntl, "flock", blocked)
    monkeypatch.setattr(repository, "save_zeek_visibility", save)
    try:
        sweep._prepare_zeek_visibility()
        sweep._prepare_zeek_visibility()
        assert len(attempts) == 1 and attempts[0]["heartbeat"] == sweep.heartbeat
        assert beats
        detail = repository.latest_audit("h", "hunt.zeek_visibility")["detail"]
        assert detail["unresolved"] and "lease" in detail["unresolved"][0]
        assert detail["snapshot"]["published"] is False
        assert detail["snapshot"]["complete"] is False
        assert detail["snapshot"]["count"] == 0
        [cell] = repository.rule_cells("h", rule_id=Probe.id)
        assert cell["state"] == "evaluated_partial"
        assert cell["detail"]["reasons"] == detail["unresolved"]
        visibility = coverage_for_hunt(repository, "h")["zeek_visibility"]
        assert visibility["unresolved"] and visibility["snapshot"]["complete"] is False
        with repository.engine.connect() as connection:
            assert not connection.execute(select(t.report_zeek_visibility)).first()
    finally:
        sweep.close_stage()


def test_prepublication_failure_fallback_never_takes_visibility_lease(repository, tmp_path, monkeypatch):  # noqa: F811
    sweep = sweep_for(repository, tmp_path, [])
    sweep._zeek_visibility_failure = "injected unavailable visibility state"

    def unexpected(*args, **kwargs):
        pytest.fail("failure fallback attempted a visibility publication lease")

    monkeypatch.setattr(repository, "save_zeek_visibility", unexpected)
    try:
        sweep._prepare_zeek_visibility()
        detail = repository.latest_audit("h", "hunt.zeek_visibility")["detail"]
        assert "injected unavailable" in detail["unresolved"][0]
        assert detail["snapshot"]["published"] is False
    finally:
        sweep.close_stage()


@pytest.mark.parametrize("wrapped", [False, True])
@pytest.mark.parametrize("existing", [False, True])
def test_cleanup_failure_returns_committed_snapshot_and_names_failure(repository, wrapped, existing):  # noqa: F811
    content = rows("published", 300)
    if existing:
        repository.save_zeek_visibility("h", iter(content))
    insert_chunks(repository, "h", "pending-orphan", rows("orphan", 300))

    def fail_delete(connection, cursor, statement, parameters, context, executemany):
        if statement.lower().startswith("delete from report_zeek_visibility"):
            error = sqlite3.OperationalError("injected orphan cleanup failure")
            if wrapped:
                raise OperationalError(statement, parameters, error)
            raise error

    event.listen(repository.engine, "before_cursor_execute", fail_delete)
    try:
        reference = repository.save_zeek_visibility("h", iter(content))
    finally:
        event.remove(repository.engine, "before_cursor_execute", fail_delete)
    assert "OperationalError" in reference["cleanup_warning"]
    assert "injected orphan cleanup failure" in reference["cleanup_warning"]
    assert reference["count"] == 300
    assert list(repository.zeek_visibility_rows("h", reference["sha256"])) == content
    after = repository.save_zeek_visibility("h", iter(rows("next")))
    assert "cleanup_warning" not in after
    assert list(repository.zeek_visibility_rows("h", reference["sha256"])) == content


@pytest.mark.parametrize("wait_seconds", [float("inf"), float("nan")])
def test_visibility_lease_rejects_unbounded_wait(wait_seconds):
    engine = db.make_engine(":memory:")
    try:
        with (pytest.raises(ValueError, match="finite"),
              db.zeek_visibility_lease(engine, wait_seconds=wait_seconds)):
            pytest.fail("non-finite wait was admitted")
    finally:
        engine.dispose()


def test_successful_sweep_records_cleanup_warning_without_invalidating_snapshot(repository, tmp_path, monkeypatch):  # noqa: F811
    sweep = sweep_for(repository, tmp_path, [])

    def failed_cleanup(hunt):
        raise OSError("injected orphan cleanup unavailable")

    monkeypatch.setattr(repository, "_clean_zeek_visibility_orphans", failed_cleanup)
    try:
        sweep._prepare_zeek_visibility()
        detail = repository.latest_audit("h", "hunt.zeek_visibility")["detail"]
        assert not detail["unresolved"]
        assert any("cleanup" in note and "OSError" in note for note in detail["notes"])
        reference = detail["snapshot"]
        assert reference["count"] > 0
        assert len(list(repository.zeek_visibility_rows("h", reference["sha256"]))) == reference["count"]
    finally:
        sweep.close_stage()
