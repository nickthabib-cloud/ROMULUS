"""Detection requests accept the mail and VPN session families after the family-check rebuild."""
import pytest
from alembic import command
from sqlalchemy.exc import IntegrityError

from romulus.catalog.browser import known_families
from romulus.store.db import make_engine
from tests.test_local_content_migration import config

NOW = "2030-01-01 00:00:00.000000"


def _request(connection, request_id, family):
    connection.exec_driver_sql(
        "INSERT INTO detection_request(id,requester,created_at,behavior,telemetry_family,attack_ids,status,"
        "status_reason,updated_by,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
        (request_id, "lead", NOW, "watch this", family, "[]", "requested", "", "lead", NOW))


def _attached(connection):
    return connection.exec_driver_sql(
        "SELECT type, name, sql FROM sqlite_master WHERE tbl_name='detection_request' "
        "AND type IN ('index','trigger') ORDER BY type, name").all()


def _history(connection):
    return connection.exec_driver_sql(
        "SELECT request_id, old_status, new_status FROM detection_request_event ORDER BY id").all()


@pytest.mark.parametrize("foreign_keys", [False, True])
def test_the_rebuild_keeps_rows_history_indexes_and_triggers(tmp_path, foreign_keys):
    engine = make_engine(tmp_path / "requests.sqlite")
    with engine.begin() as connection:
        connection.exec_driver_sql(f"PRAGMA foreign_keys={'ON' if foreign_keys else 'OFF'}")
        command.upgrade(config(connection), "0037")
        _request(connection, "r1", "auth")
        with pytest.raises(IntegrityError), connection.begin_nested():
            _request(connection, "r-mail", "mail_message")
        attached, history = _attached(connection), _history(connection)
        command.upgrade(config(connection), "0038")
        assert _attached(connection) == attached and _history(connection) == history
        assert connection.exec_driver_sql("SELECT id FROM detection_request").scalars().all() == ["r1"]
        for request_id, family in (("r-mail", "mail_message"), ("r-vpn", "vpn_session")):
            _request(connection, request_id, family)
        # the created trigger still records each new request's first status
        assert [row[0] for row in _history(connection)] == ["r1", "r-mail", "r-vpn"]
        with pytest.raises(IntegrityError), connection.begin_nested():
            _request(connection, "r-bad", "not_a_family")
        with pytest.raises(Exception, match="replacement is forbidden"), connection.begin_nested():
            _request(connection, "r1", "auth")
        assert connection.exec_driver_sql("PRAGMA foreign_key_check").all() == []
        assert connection.exec_driver_sql("PRAGMA quick_check").scalar() == "ok"
        # a downgrade cannot strand requests that name a family the older check rejects
        with pytest.raises(RuntimeError, match="mail_message"):
            command.downgrade(config(connection), "0037")
    engine.dispose()


def test_downgrade_and_reupgrade_without_new_family_requests(tmp_path):
    engine = make_engine(tmp_path / "requests.sqlite")
    with engine.begin() as connection:
        command.upgrade(config(connection), "0038")
        _request(connection, "r1", "auth")
        command.downgrade(config(connection), "0037")
        with pytest.raises(IntegrityError), connection.begin_nested():
            _request(connection, "r-mail", "mail_message")
        command.upgrade(config(connection), "0038")
        _request(connection, "r-mail", "mail_message")
        assert [row[0] for row in _history(connection)] == ["r1", "r-mail"]
        assert connection.exec_driver_sql("PRAGMA foreign_key_check").all() == []
    engine.dispose()


def test_every_family_a_normalizer_produces_can_be_requested(tmp_path):
    engine = make_engine(tmp_path / "requests.sqlite")
    with engine.begin() as connection:
        command.upgrade(config(connection), "head")
        for index, family in enumerate((*known_families(), "unknown")):
            _request(connection, f"r{index}", family)
    engine.dispose()


def test_the_rebuild_commits_when_the_caller_already_defers_foreign_keys(tmp_path):
    engine = make_engine(tmp_path / "requests.sqlite")
    with engine.begin() as connection:
        connection.exec_driver_sql("PRAGMA foreign_keys=ON")
        command.upgrade(config(connection), "0037")
        _request(connection, "r1", "auth")
    with engine.begin() as connection:
        connection.exec_driver_sql("PRAGMA foreign_keys=ON")
        connection.exec_driver_sql("BEGIN")
        connection.exec_driver_sql("PRAGMA defer_foreign_keys=ON")
        command.upgrade(config(connection), "0038")
        assert connection.exec_driver_sql("PRAGMA defer_foreign_keys").scalar() == 1
    with engine.begin() as connection:
        assert connection.exec_driver_sql("SELECT version_num FROM alembic_version").scalar() == "0038"
        assert _history(connection) == [("r1", None, "requested")]
    engine.dispose()
