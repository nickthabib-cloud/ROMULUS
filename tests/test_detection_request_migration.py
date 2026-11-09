"""Populated-copy rehearsal and transactional rollback for detection-request storage."""
import sqlite3

import pytest
from alembic import command
from sqlalchemy import MetaData, Table, inspect

from romulus.store.db import make_engine
from tests.test_indicator_staging_migration import seed
from tests.test_local_content_migration import config
from tests.test_report import _repo_with_finding

TABLES = {'detection_request', 'detection_request_event'}


def test_populated_copy_rehearsal_up_down_up(tmp_path):
    original = tmp_path / 'populated.sqlite'
    engine = make_engine(original)
    with engine.begin() as c:
        command.upgrade(config(c), '0033')
        seed(c)
    from romulus.store import schema as t
    fixture, _ = _repo_with_finding()
    with fixture.engine.connect() as source, engine.begin() as target:
        for table in (t.hunt, t.raw_record, t.typed_event, t.candidate, t.disposition_event):
            target_columns = {column["name"] for column in inspect(target).get_columns(table.name)}
            rows = [{key: value for key, value in dict(row).items() if key in target_columns}
                    for row in source.execute(table.select()).mappings()]
            if rows:
                target.execute(Table(table.name, MetaData(), autoload_with=target).insert(), rows)
    fixture.engine.dispose()
    engine.dispose()
    copy = tmp_path / 'rehearsal-copy.sqlite'
    with sqlite3.connect(original) as source, sqlite3.connect(copy) as target:
        source.backup(target)
    engine = make_engine(copy)
    for direction, revision in [('upgrade', '0034'), ('downgrade', '0033'), ('upgrade', '0034')]:
        with engine.begin() as c:
            getattr(command, direction)(config(c), revision)
            assert c.exec_driver_sql('SELECT value FROM indicator_value').scalar() == '192.0.2.1'
            assert c.exec_driver_sql('SELECT count(*) FROM candidate').scalar() == 1
            assert c.exec_driver_sql('PRAGMA foreign_key_check').all() == []
            assert c.exec_driver_sql('PRAGMA quick_check').scalar() == 'ok'
            assert TABLES <= set(inspect(c).get_table_names()) if revision == '0034' else not (
                TABLES & set(inspect(c).get_table_names()))
            print(f'{direction} {revision}: seeded local DB backup copy preserved '
                  '(1 candidate, 1 indicator value); foreign_key_check=[]; quick_check=ok')
    engine.dispose()
    with sqlite3.connect(original) as c:
        assert c.execute('SELECT version_num FROM alembic_version').fetchone()[0] == '0033'


@pytest.mark.parametrize('direction', ['upgrade', 'downgrade'])
def test_request_migration_rollback_preserves_populated_store(tmp_path, direction):
    before, after = ('0033', '0034') if direction == 'upgrade' else ('0034', '0033')
    engine = make_engine(tmp_path / 'rollback.sqlite')
    with engine.begin() as c:
        command.upgrade(config(c), before)
        seed(c)
        if before == '0034':
            c.exec_driver_sql("""INSERT INTO detection_request
                (id,requester,created_at,behavior,telemetry_family,attack_ids,status,updated_by,updated_at)
                VALUES('request','analyst','2026-01-01','behavior','unknown','[]','requested','analyst','2026-01-01')""")
    with engine.connect() as c:
        with pytest.raises(RuntimeError, match='abort'), c.begin():
            getattr(command, direction)(config(c), after)
            raise RuntimeError('abort')
        assert c.exec_driver_sql('SELECT version_num FROM alembic_version').scalar() == before
        assert c.exec_driver_sql('SELECT value FROM indicator_value').scalar() == '192.0.2.1'
        assert (TABLES <= set(inspect(c).get_table_names())) == (before == '0034')
        if before == '0034':
            assert c.exec_driver_sql('SELECT behavior FROM detection_request').scalar() == 'behavior'
            assert c.exec_driver_sql('SELECT new_status FROM detection_request_event').scalar() == 'requested'
    engine.dispose()
