"""Database storage hygiene: a capped write-ahead log, compaction, and the doctor warning."""
from datetime import UTC, datetime, timedelta

from sqlalchemy import inspect

from romulus import cli
from romulus.config import Settings
from romulus.doctor import check_db_space
from romulus.store.db import WAL_SIZE_LIMIT, compact, make_engine, migrate, space_report
from romulus.store.repo import Repo


def _bloated(tmp_path):
    db = tmp_path / "db" / "romulus.db"
    engine = make_engine(db)
    migrate(engine)
    repo = Repo(engine)
    for i in range(40):
        repo.audit("test", "bulk", detail={"pad": "x" * 200_000, "i": i})
    with engine.begin() as c:
        c.exec_driver_sql("DELETE FROM audit_event WHERE action = 'bulk'")
    return db, engine, repo


def test_wal_size_limit_is_set_on_every_connection(tmp_path):
    engine = make_engine(tmp_path / "x.db")
    with engine.connect() as c:
        assert c.exec_driver_sql("PRAGMA journal_size_limit").scalar() == WAL_SIZE_LIMIT


def test_latest_migration_adds_durable_expansion_fields(tmp_path):
    engine = make_engine(tmp_path / "migrated.db")
    migrate(engine)

    inspector = inspect(engine)
    assert "source_queries" in {column["name"] for column in inspector.get_columns("task")}
    assert "group_key" in {column["name"] for column in inspector.get_columns("candidate")}


def test_compact_returns_freed_pages_and_truncates_the_log(tmp_path):
    _db, engine, _repo = _bloated(tmp_path)
    before = space_report(engine)
    assert before["free_bytes"] > 1_000_000
    res = compact(engine)
    assert res["after"]["free_bytes"] == 0 and res["after"]["wal_bytes"] == 0
    assert res["after"]["file_bytes"] < before["file_bytes"]


def test_doctor_warns_when_most_of_the_file_is_reclaimable(tmp_path, monkeypatch):
    _bloated(tmp_path)
    s = Settings(home=tmp_path)
    monkeypatch.setattr("romulus.doctor.space_report", lambda _e: {"file_bytes": 1_000_000_000,
                                                                  "wal_bytes": 900_000_000,
                                                                  "free_bytes": 500_000_000})
    check = check_db_space(s)
    assert check.status == "warn" and "romulus db compact" in check.detail


def test_cli_refuses_to_compact_during_an_active_hunt(tmp_path, monkeypatch, capsys):
    _db, _engine, repo = _bloated(tmp_path)
    repo.create_hunt("h1", {}, "d", "t")
    repo.set_hunt_state("h1", "running")
    with repo.engine.begin() as c:
        c.exec_driver_sql("UPDATE hunt SET lease_until = ? WHERE id = 'h1'",
                          ((datetime.now(UTC) + timedelta(minutes=5)).replace(tzinfo=None),))
    monkeypatch.setattr(cli, "load_settings", lambda _p: Settings(home=tmp_path))
    assert cli.main(["db", "compact"]) == cli.EXIT_FAIL
    assert "active lease" in capsys.readouterr().err
    with repo.engine.begin() as c:
        c.exec_driver_sql("UPDATE hunt SET lease_until = NULL WHERE id = 'h1'")
    assert cli.main(["db", "compact"]) == cli.EXIT_OK
