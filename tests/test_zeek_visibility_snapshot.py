"""Appendix publication releases writers while retaining complete immutable reads."""
import hashlib

import pytest
from sqlalchemy import select
from sqlalchemy.exc import OperationalError

from romulus.store import schema as t
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo


def test_snapshot_stream_releases_write_lock_between_bounded_chunks(tmp_path):
    path = tmp_path / 'hunt.db'
    engine = make_engine(path)
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt('h', {'targets': []}, 'digest', 'test')
    other = make_engine(path)
    rows = [{'family': 'http_tx', 'sensor': 'sensor', 'interval': i} for i in range(600)]
    digest = hashlib.sha256(''.join(repo.zeek_visibility_line(row) for row in rows).encode()).hexdigest()
    observed = []

    def streamed():
        for i, row in enumerate(rows):
            if i and i % 256 == 0:
                assert list(Repo(other).zeek_visibility_rows('h', digest)) == []
                with other.connect() as connection:
                    private = connection.execute(select(t.report_zeek_visibility.c.snapshot).distinct()).scalars().all()
                assert private
                assert all(list(Repo(other).zeek_visibility_rows('h', name)) == [] for name in private)
                try:
                    with other.begin() as connection:
                        connection.exec_driver_sql('PRAGMA busy_timeout=20')
                        connection.exec_driver_sql("UPDATE hunt SET execution_state=execution_state WHERE id='h'")
                except OperationalError as exc:
                    assert 'locked' in str(exc).lower()
                    available = False
                else:
                    available = True
                assert available, 'streamed appendix retained the write lock across chunks'
                observed.append(i)
            yield row

    try:
        ref = repo.save_zeek_visibility('h', streamed())
        assert observed == [256, 512]
        assert ref['sha256'] == digest
        assert ref['count'] == 600
        assert list(Repo(other).zeek_visibility_rows('h', digest)) == rows
        assert repo.save_zeek_visibility('h', iter(rows)) == ref
        assert list(repo.zeek_visibility_rows('h', digest)) == rows
    finally:
        other.dispose()
        engine.dispose()


def test_failed_stream_does_not_publish_or_retain_an_unfinished_snapshot(tmp_path):
    engine = make_engine(tmp_path / 'hunt.db')
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt('h', {'targets': []}, 'digest', 'test')
    original = [{'family': 'dns_query', 'sensor': 'old'}]
    ref = repo.save_zeek_visibility('h', iter(original))

    def failed():
        for i in range(300):
            yield {'family': 'http_tx', 'sensor': 'new', 'interval': i}
        raise ValueError('source interrupted')

    try:
        with pytest.raises(ValueError, match='source interrupted'):
            repo.save_zeek_visibility('h', failed())
        assert list(repo.zeek_visibility_rows('h', ref['sha256'])) == original
        with engine.connect() as connection:
            snapshots = connection.execute(select(t.report_zeek_visibility.c.snapshot).distinct()).scalars().all()
        assert len(snapshots) <= 2
        assert not any('new' in str(row) for snapshot in snapshots
                       for row in repo.zeek_visibility_rows('h', snapshot))
    finally:
        engine.dispose()


def test_legacy_digest_rows_remain_readable(tmp_path):
    engine = make_engine(tmp_path / 'hunt.db')
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt('h', {'targets': []}, 'digest', 'test')
    row = {'family': 'dns_query', 'sensor': 'legacy'}
    digest = hashlib.sha256(repo.zeek_visibility_line(row).encode()).hexdigest()
    try:
        with engine.begin() as connection:
            connection.execute(t.report_zeek_visibility.insert(),
                               {'hunt_id': 'h', 'snapshot': digest, 'ordinal': 0, 'body': row})
        assert list(repo.zeek_visibility_rows('h', digest)) == [row]
    finally:
        engine.dispose()
