"""Hunt deletion must not leave the VACUUM rewrite in the WAL."""
import secrets

import pytest
from fastapi.testclient import TestClient

from romulus.config import Settings
from romulus.doctor import check_db_space
from romulus.hunt.run import open_repo
from romulus.store.db import compact, space_report
from romulus.web import app as web
from romulus.web.auth import Sessions, create_user


def test_hunt_delete_compacts_and_checkpoints_without_a_followup_write(tmp_path, monkeypatch):
    settings = Settings(home=tmp_path, secret_key=secrets.token_urlsafe(32))
    repo = open_repo(settings)
    try:
        repo.create_hunt("delete-me", {}, "digest", "test")
        repo.audit("test", "retained-data", detail={"payload": "x" * 8_000_000})
        create_user(repo.engine, "lead", secrets.token_urlsafe(24), "lead")
        monkeypatch.setattr(web, "open_repo", lambda _: repo)
        app = web.create_app(settings)
        sessions = Sessions(settings.secret_key.get_secret_value())
        cookie = sessions.issue({"username": "lead", "role": "lead"})
        csrf = sessions.read(cookie)["csrf"]
        with TestClient(app) as client:
            client.cookies.set(web.COOKIE, cookie)
            response = client.post("/hunts/delete-me/delete", data={"csrf": csrf, "confirm": "delete-me"},
                                   follow_redirects=False)
            assert response.status_code == 303
            assert repo.get_hunt("delete-me") is None
            assert space_report(repo.engine)["file_bytes"] > 8_000_000
            assert space_report(repo.engine)["wal_bytes"] == 0
    finally:
        repo.engine.dispose()


def test_doctor_includes_the_wal_size(tmp_path):
    settings = Settings(home=tmp_path)
    repo = open_repo(settings)
    try:
        repo.audit("test", "payload", detail={"payload": "x" * 3_000_000})
        assert space_report(repo.engine)["wal_bytes"] > 0
        check = check_db_space(settings)
        assert "write-ahead log" in check.detail and "MB" in check.detail
    finally:
        repo.engine.dispose()


def test_compaction_restores_pooled_connection_transaction_semantics(tmp_path):
    repo = open_repo(Settings(home=tmp_path))
    try:
        with repo.engine.begin() as connection:
            connection.exec_driver_sql("CREATE TABLE atomic_probe(value INTEGER)")
        compact(repo.engine)
        with pytest.raises(RuntimeError), repo.engine.begin() as connection:
            connection.exec_driver_sql("INSERT INTO atomic_probe VALUES(1)")
            connection.exec_driver_sql("INSERT INTO atomic_probe VALUES(2)")
            raise RuntimeError("abort this transaction")
        with repo.engine.connect() as connection:
            assert connection.exec_driver_sql("SELECT count(*) FROM atomic_probe").scalar_one() == 0
    finally:
        repo.engine.dispose()


@pytest.mark.parametrize("fail", [False, True])
def test_delete_compaction_blocks_claim_for_its_entire_duration_and_reports_failure(tmp_path, monkeypatch, caplog, fail):
    settings = Settings(home=tmp_path, secret_key=secrets.token_urlsafe(32))
    repo = open_repo(settings)
    repo.create_hunt("delete-me", {}, "digest", "test")
    repo.create_hunt("next-hunt", {}, "digest", "test")
    create_user(repo.engine, "lead", secrets.token_urlsafe(24), "lead")
    monkeypatch.setattr(web, "open_repo", lambda _: repo)
    attempted = []

    def checked_compact(engine):
        other = open_repo(settings)
        try:
            try:
                other.claim_hunt("next-hunt", 60)
            except RuntimeError as error:
                attempted.append("blocked" if "maintenance" in str(error) else "other error")
            else:
                attempted.append("claimed")
            try:
                other.create_hunt("concurrent-create", {}, "digest", "test")
            except RuntimeError as error:
                attempted.append("create blocked" if "maintenance" in str(error) else "create other error")
            else:
                attempted.append("created")
        finally:
            other.engine.dispose()
        if fail:
            raise OSError("synthetic disk refusal")
        compact(engine)

    monkeypatch.setattr(web, "compact", checked_compact)
    sessions = Sessions(settings.secret_key.get_secret_value())
    cookie = sessions.issue({"username": "lead", "role": "lead"})
    try:
        with TestClient(web.create_app(settings)) as client:
            client.cookies.set(web.COOKIE, cookie)
            response = client.post("/hunts/delete-me/delete", data={"csrf": sessions.read(cookie)["csrf"],
                "confirm": "delete-me"}, follow_redirects=True)
            assert response.status_code == 200
            assert attempted == ["blocked", "create blocked"]
            if fail:
                assert "compaction failed" in response.text.lower()
                assert repo.latest_audit("delete-me", "hunt.compaction_failed")
                assert "synthetic disk refusal" in caplog.text
            assert repo.claim_hunt("next-hunt", 60)["execution_state"] == "running"
    finally:
        repo.engine.dispose()
