"""Visibility state follows the sensor interval grid, independently of traffic volume."""
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from romulus.hunt.zeek_visibility import VisibilityStore
from romulus.sources.models import Window

T0 = datetime(2025, 1, 1, tzinfo=UTC)


def test_many_distinct_connection_spans_collapse_to_interval_grid(tmp_path):
    store = VisibilityStore(tmp_path)
    try:
        start = T0.timestamp()
        for i in range(10000):
            store.activity('sensor', 'net_flow', start+i/100, start+i/100+1, 1)
        store.health('sensor', start, start+900, 0, 'capture loss')
        rows = list(store.visibility(Window(start=T0, end=T0+timedelta(minutes=15)), 0))
        assert len(rows) == 1
        assert rows[0]['records'] == 10000
        assert rows[0]['partial'] is False
        assert store.db.execute('SELECT count(*) FROM activity').fetchone()[0] == 1
    finally:
        store.close()


@pytest.mark.parametrize('limit', ['page', 'deadline'])
def test_collection_limits_name_partial_visibility(tmp_path, monkeypatch, limit):
    from itertools import count

    from romulus.config import Settings
    from romulus.hunt.zeek_visibility import collect_visibility
    from romulus.site import ZeekPolicy
    from romulus.sources.es import ElasticClient
    from romulus.sources.profile import contract_from_types
    from tests.zeek_source_support import ZeekES
    raw = {'_path':'capture_loss','ts':T0.timestamp()+900,'ts_delta':900,'percent_lost':0}
    contract = contract_from_types('health',{'_path':'keyword','ts':'double','ts_delta':'double',
        'percent_lost':'double'}).model_copy(update={'zeek_sensor':'sensor','time_field':'ts'})
    backend = ZeekES({'health':[{'_index':'health','_id':'health','_source':raw}]},{'health':'ts'})
    store = VisibilityStore(tmp_path)
    if limit == 'deadline':
        ticks = count()
        monkeypatch.setattr('romulus.hunt.zeek_visibility.time', SimpleNamespace(monotonic=lambda:next(ticks)))
    try:
        store.activity('sensor','http_tx',T0.timestamp(),T0.timestamp()+900,1)
        collect_visibility(ElasticClient(Settings(home=tmp_path),transport=backend.transport()),
            {'health':contract},Window(start=T0,end=T0+timedelta(minutes=15)),store,ZeekPolicy(),
            activity=False,max_pages=1,deadline_seconds=.01)
        assert any(('page limit' if limit == 'page' else 'deadline') in reason for reason in store.reasons)
    finally:
        store.close()


def test_declared_first_stats_interval_and_timer_jitter_are_valid(tmp_path):
    store = VisibilityStore(tmp_path)
    try:
        start = T0.timestamp()
        store.activity('sensor', 'http_tx', start, start+600, 1)
        store.stats('sensor', 'worker', start+300, 0, 100)
        store.stats('sensor', 'worker', start+601, 0, 100)
        store.resolve_stats(300, complete=True)
        rows = list(store.visibility(Window(start=T0, end=T0+timedelta(minutes=10)), 1))
        assert all(not row['partial'] for row in rows)
        assert list(store.issues()) == []
    finally:
        store.close()
