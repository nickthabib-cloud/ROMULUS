"""Rehearse upgrade, downgrade and aborted DDL using temporary databases only."""
from datetime import UTC, datetime
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import inspect

from romulus.store import schema as t
from romulus.store.db import make_engine

LOCAL = {"indicator_list", "indicator_value", "sigma_rule"}


def config(connection):
    cfg = Config()
    cfg.set_main_option("script_location", str(Path(t.__file__).parent / "migrations"))
    cfg.attributes["connection"] = connection
    return cfg


def test_upgrade_downgrade_reupgrade_preserves_existing_database(tmp_path):
    engine = make_engine(tmp_path / "rehearsal.sqlite")
    with engine.begin() as c:
        command.upgrade(config(c), "0031")
        c.execute(t.audit_event.insert().values(at=datetime.now(UTC),
                  actor="test", action="sentinel", detail={"kept": True}))
    with engine.begin() as c:
        command.upgrade(config(c), "0032")
        assert LOCAL <= set(inspect(c).get_table_names())
        assert c.exec_driver_sql("PRAGMA foreign_key_check").all() == []
        assert c.exec_driver_sql("PRAGMA quick_check").scalar() == "ok"
        assert {column["name"] for column in inspect(c).get_columns("sigma_rule")} == {
            column.name for column in t.sigma_rule.columns}
        indexes = {index["name"] for index in inspect(c).get_indexes("indicator_value")}
        assert {"ix_indicator_value_lookup", "ix_indicator_value_version"} <= indexes
    with engine.begin() as c:
        command.downgrade(config(c), "0031")
        assert not LOCAL & set(inspect(c).get_table_names())
        assert c.exec_driver_sql("SELECT action FROM audit_event").scalar() == "sentinel"
    with engine.begin() as c:
        command.upgrade(config(c), "0032")
        assert LOCAL <= set(inspect(c).get_table_names())
        assert c.exec_driver_sql("PRAGMA foreign_key_check").all() == []
    engine.dispose()


@pytest.mark.parametrize("direction", ["upgrade", "downgrade"])
def test_aborted_migration_rolls_back_tables_and_revision(tmp_path, direction):
    engine = make_engine(tmp_path / "rollback.sqlite")
    before, after = ("0031", "0032") if direction == "upgrade" else ("0032", "0031")
    with engine.begin() as c:
        command.upgrade(config(c), before)
    with pytest.raises(RuntimeError, match="aborted rehearsal"), engine.begin() as c:
        getattr(command, direction)(config(c), after)
        raise RuntimeError("aborted rehearsal")
    with engine.connect() as c:
        assert c.exec_driver_sql("SELECT version_num FROM alembic_version").scalar() == before
        assert (LOCAL <= set(inspect(c).get_table_names())) == (before == "0032")
        assert c.exec_driver_sql("PRAGMA quick_check").scalar() == "ok"
    engine.dispose()
