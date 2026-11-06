"""Indicator staging migrations preserve values and roll back atomically."""
from datetime import UTC, datetime

import pytest
from alembic import command
from sqlalchemy import inspect

from romulus.store.db import make_engine
from tests.test_local_content_migration import config


def seed(c, status='active'):
    c.exec_driver_sql("INSERT INTO indicator_list "
        "(id,version,name,source,author,created_at,expires_at,digest,status,notes) "
        "VALUES ('list',1,'name','source','author',?,?, 'digest',?, '')",
        (datetime(2026, 1, 1, tzinfo=UTC).isoformat(), datetime(2027, 1, 1, tzinfo=UTC).isoformat(), status))
    c.exec_driver_sql("INSERT INTO indicator_value "
        "(id,list_id,list_version,kind,value,label,attack,lane,severity) "
        "VALUES ('value','list',1,'ip','192.0.2.1','','[]','lead','medium')")


@pytest.mark.parametrize('foreign_keys', [True, False])
def test_staging_upgrade_downgrade_preserves_populated_versions(tmp_path, foreign_keys):
    engine = make_engine(tmp_path / 'migration.sqlite')
    with engine.begin() as c:
        command.upgrade(config(c), '0032')
        seed(c)
    with engine.connect() as c:
        c.exec_driver_sql('PRAGMA foreign_keys=' + ('ON' if foreign_keys else 'OFF'))
        c.commit()
        for direction, revision in [('upgrade', '0033'), ('downgrade', '0032'), ('upgrade', '0033')]:
            getattr(command, direction)(config(c), revision)
            c.commit()
            assert c.exec_driver_sql('SELECT value FROM indicator_value').scalar() == '192.0.2.1'
            assert c.exec_driver_sql('PRAGMA foreign_key_check').all() == []
            assert c.exec_driver_sql('PRAGMA quick_check').scalar() == 'ok'
        assert {'lane', 'severity'} <= {column['name'] for column in inspect(c).get_columns('indicator_list')}
        assert c.exec_driver_sql('SELECT lane,severity FROM indicator_list').one() == ('lead', 'medium')
    engine.dispose()


@pytest.mark.parametrize('direction', ['upgrade', 'downgrade'])
def test_staging_migration_rollback_preserves_schema_and_content(tmp_path, direction):
    engine = make_engine(tmp_path / 'rollback.sqlite')
    before, after = ('0032', '0033') if direction == 'upgrade' else ('0033', '0032')
    with engine.begin() as c:
        command.upgrade(config(c), before)
        seed(c)
    with engine.connect() as c:
        c.exec_driver_sql('PRAGMA foreign_keys=OFF')
        c.commit()
        with pytest.raises(RuntimeError, match='abort'), c.begin():
            getattr(command, direction)(config(c), after)
            raise RuntimeError('abort')
        assert c.exec_driver_sql('SELECT version_num FROM alembic_version').scalar() == before
        assert c.exec_driver_sql('SELECT value FROM indicator_value').scalar() == '192.0.2.1'
        assert ('lane' in {column['name'] for column in inspect(c).get_columns('indicator_list')}) == (before == '0033')
    engine.dispose()


def test_staging_downgrade_refuses_incomplete_import(tmp_path):
    engine = make_engine(tmp_path / 'incomplete.sqlite')
    with engine.begin() as c:
        command.upgrade(config(c), '0033')
        seed(c, 'importing')
    with pytest.raises(RuntimeError, match='staged'), engine.begin() as c:
        command.downgrade(config(c), '0032')
    with engine.connect() as c:
        assert c.exec_driver_sql('SELECT status FROM indicator_list').scalar() == 'importing'
    engine.dispose()
