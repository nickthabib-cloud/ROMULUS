"""Literal health rows from published Zeek and shipper schemas."""
from datetime import UTC, datetime

import pytest

from romulus.evidence.zeek import normalize_plain_zeek, normalize_zeek, zeek_record
from romulus.site import _facts, _SiteDocument


@pytest.mark.parametrize('shape,source', [
    ('plain', {'_path': 'capture_loss', 'ts': 1735689600, 'ts_delta': 900, 'peer': 'worker-1', 'gaps': 23, 'acks': 1000, 'percent_lost': '2.3'}),
    ('malcolm', {'@timestamp': '2025-01-01T00:00:00Z', 'event': {'provider': 'zeek', 'dataset': 'capture_loss'}, 'node': 'sensor-a', 'zeek': {'capture_loss': {'ts_delta': 900, 'peer': 'worker-1', 'gaps': 23, 'acks': 1000, 'percent_lost': '2.3'}}}),
    ('elastic', {'@timestamp': '2025-01-01T00:00:00Z', 'event': {'dataset': 'zeek.capture_loss'}, 'data_stream': {'dataset': 'zeek.capture_loss'}, 'agent': {'name': 'sensor-a'}, 'zeek': {'capture_loss': {'ts_delta': 900, 'peer': 'worker-1', 'gaps': 23, 'acks': 1000, 'percent_lost': '2.3'}}}),
])
def test_capture_loss_is_health_with_interval_and_worker_separate_from_sensor(shape, source):
    hit = {'_index': 'telemetry', '_id': 'loss', '_source': source}
    if shape == 'plain':
        event = normalize_plain_zeek(hit, sensor='sensor-a')
    else:
        record = zeek_record(source)
        assert record is not None and record.log is not None
        event = normalize_zeek(hit, record)
    assert event.family == 'sensor_health'
    assert event.host == 'sensor-a'
    assert event.get('health.worker') == 'worker-1'
    assert event.get('health.capture_loss_pct') == 2.3
    assert event.get('health.interval_s') == 900
    assert event.get('health.gaps') == 23
    assert event.get('health.acks') == 1000
    assert event.ts == datetime(2025, 1, 1, tzinfo=UTC)
    assert ('host', 'sensor-a', 'observer') in event.entities()


@pytest.mark.parametrize('source', [
    {'_path': 'stats', 'ts': 1735689600, 'peer': 'worker-2', 'pkts_dropped': 12, 'pkts_link': 1000},
    {'@timestamp': '2025-01-01T00:00:00Z', 'event': {'provider': 'zeek', 'dataset': 'stats'}, 'node': 'sensor-a', 'zeek': {'stats': {'peer': 'worker-2', 'pkts_dropped': 12, 'pkts_link': 1000}}},
    {'@timestamp': '2025-01-01T00:00:00Z', 'event': {'dataset': 'zeek.stats'}, 'data_stream': {'dataset': 'zeek.stats'}, 'agent': {'name': 'sensor-a'}, 'zeek': {'stats': {'peer': 'worker-2', 'packets': {'dropped': 12, 'received': 1000}}}},
])
def test_stats_packet_counts_remain_interval_deltas_without_invented_duration(source):
    hit = {'_index': 'telemetry', '_id': 'stats', '_source': source}
    event = (normalize_plain_zeek(hit, sensor='sensor-a') if '_path' in source
             else normalize_zeek(hit, zeek_record(source)))
    assert event.family == 'sensor_health'
    assert event.get('health.packets_dropped') == 12
    assert event.get('health.packets_link') == 1000
    assert event.get('health.interval_s') is None
    assert event.get('health.capture_loss_pct') is None


def test_zeek_policy_defaults_do_not_change_old_site_digest_input():
    facts = _facts(_SiteDocument.model_validate({'schema': 'romulus-site-collection@1'}))
    assert 'zeek' not in facts.content
    assert facts.zeek.capture_loss_threshold_pct == 1.0
    assert facts.zeek.connection_lookback_hours == 24
    changed = _facts(_SiteDocument.model_validate({'schema': 'romulus-site-collection@1', 'zeek': {
        'capture_loss_threshold_pct': 0.5, 'connection_lookback_hours': 48}}))
    assert changed.zeek.connection_lookback_hours == 48
    assert changed.digest != facts.digest


@pytest.mark.parametrize('field,value', [('capture_loss_threshold_pct', -1), ('capture_loss_threshold_pct', float('nan')),
                                        ('capture_loss_threshold_pct', float('inf')), ('connection_lookback_hours', 0)])
def test_invalid_zeek_policy_is_rejected(field, value):
    with pytest.raises(ValueError):
        _SiteDocument.model_validate({'schema': 'romulus-site-collection@1', 'zeek': {field: value}})

def test_declared_plain_source_is_network_and_queries_numeric_epoch_seconds():
    from romulus.evidence.normalize import normalize_hits
    from romulus.sources.compile import compile_es
    from romulus.sources.models import SearchIntent, Window
    from romulus.sources.profile import apply_zeek_declaration, contract_from_types
    facts = _facts(_SiteDocument.model_validate({'schema': 'romulus-site-collection@1', 'zeek': {
        'plain_sources': {'plain-index': {'sensor': 'sensor-a'}}}}))
    original = contract_from_types('plain-index', {'ts': 'double', '_path': 'keyword', 'uid': 'keyword'})
    assert 'zeek_sensor' not in original.model_dump()
    contract = apply_zeek_declaration(original, facts)
    assert contract.role == 'network' and contract.zeek_sensor == 'sensor-a'
    window = Window(start=datetime(2025, 1, 1, tzinfo=UTC), end=datetime(2025, 1, 2, tzinfo=UTC))
    intent = SearchIntent(kind='raw', target='plain-index', window=window, purpose='test')
    query = compile_es(intent, contract)
    assert query.body['query']['bool']['filter'][0] == {'range': {'ts': {'gte': 1735689600.0, 'lt': 1735776000.0}}}
    assert 'format' not in query.body['sort'][0]['ts']
    hit = {'_index': 'plain-index', '_id': 'health', '_source': {'_path': 'capture_loss', 'ts': 1735689600,
           'ts_delta': 900, 'peer': 'worker', 'gaps': 2, 'acks': 100, 'percent_lost': 2}}
    events, skips, errors = normalize_hits([hit], contract=contract)
    assert not skips and not errors
    assert events[0].family == 'sensor_health' and events[0].host == 'sensor-a'
    assert normalize_hits([hit])[0] == []


@pytest.mark.parametrize('declaration_log',[None,'CONN','conn_long'])
def test_plain_declaration_applies_before_create_profile_freeze_and_resume(tmp_path, monkeypatch,declaration_log):
    from romulus.config import Settings
    from romulus.hunt import run
    class Source:
        version = '8.15.0'
        def __init__(self, settings):
            self.settings = settings
        def resolve(self, pattern):
            return ['plain-index']
        def mapping(self, target):
            return {'plain-index': {'mappings': {'properties': {'ts': {'type': 'double'},
                '_path': {'type': 'keyword'}, 'uid': {'type': 'keyword'}}}}}
        def search(self, target, body):
            assert body['aggs']['tmin']['min']['field'] == 'ts'
            assert body['aggs']['ds']['terms']['field'] == '_path'
            return {'hits': {'total': {'value': 2, 'relation': 'eq'}}, 'aggregations': {
                'tmin': {'value': 1735689600}, 'tmax': {'value': 1735689900},
                'ds': {'buckets': [{'key':'conn','doc_count':2}]}}}
    (tmp_path/'site').mkdir()
    (tmp_path/'site'/'collection.yaml').write_text('schema: romulus-site-collection@1\nzeek:\n  plain_sources:\n    plain-index:\n      sensor: sensor-a\n')
    if declaration_log:
        with (tmp_path/'site'/'collection.yaml').open('a') as output:
            output.write(f'      log: {declaration_log}\n')
    monkeypatch.setattr(run, 'ElasticClient', Source)
    settings = Settings(home=tmp_path, es_index_patterns=['plain-index'])
    hunt_id = run.create_hunt(settings, datetime(2025,1,1,tzinfo=UTC), datetime(2025,1,2,tzinfo=UTC), 'test', ai_agent=False)
    repo = run.open_repo(settings)
    hunt = repo.get_hunt(hunt_id)
    profile = hunt['manifest']['source_profiles']['plain-index']
    assert profile['role'] == 'network'
    assert profile['kind'] == 'plain_zeek'
    assert profile['datasets'] == {'zeek:'+(declaration_log or 'conn').lower(): 2}
    assert profile['zeek_sensor'] == 'sensor-a'
    contracts = run._contracts(settings, repo, {**hunt,'_resume_scope_check':True}, Source(settings))
    assert contracts['plain-index'].zeek_sensor == 'sensor-a'
    assert contracts['plain-index'].time_field == 'ts'
    from romulus.evidence.zeek_catalog import CONN
    from romulus.hunt.zeek_sources import source_groups
    assert source_groups(contracts['plain-index'],CONN,'plain')
