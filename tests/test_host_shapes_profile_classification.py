"""Synthetic shared Elastic mappings and source marker counts follow the public exists query specification.

https://www.elastic.co/docs/reference/query-languages/query-dsl/query-dsl-exists-query
No corpus records are used.
"""
import pytest

from romulus.errors import SourceError
from romulus.sources.profile import build_profile, contract_from_types
from tests.test_host_shapes_profile import mapping


class MarkerClient:
    settings = type('Settings', (), {'es_flavor': 'elasticsearch'})()
    version = '8.19.0'

    def __init__(self, *, count=0, failed=False, network=True, shared=True):
        self.count, self.failed, self.network = count, failed, network
        self.fields = {'@timestamp': 'date', 'host.name': 'keyword', 'event.dataset': 'keyword',
                       'event.provider': 'keyword', 'source.ip': 'ip', 'destination.ip': 'ip'}
        if shared:
            self.fields.update({'winlog.channel': 'keyword', 'winlog.provider_name': 'keyword',
                                'winlog.event_id': 'long', 'winlog.computer_name': 'keyword'})

    def mapping(self, target):
        return mapping(self.fields)

    def search(self, target, body):
        if 'query' in body and not body.get('aggs'):
            if self.failed:
                raise SourceError('synthetic marker count failure')
            return {'hits': {'total': {'value': self.count, 'relation': 'eq'}}}
        dataset = 'zeek.connection' if self.network else 'custom.host'
        hosts = body.get('aggs', {}).get('hosts', {})
        host_field = hosts.get('terms', {}).get('field')
        return {'hits': {'total': {'value': 20, 'relation': 'eq'}}, 'aggregations': {
            'ds': {'buckets': [{'key': dataset, 'doc_count': 20}]},
            'hosts': {'buckets': [{'key': 'sensor01', 'doc_count': 20}] if host_field == 'host.name' else []}}}


def test_shared_windows_mapping_does_not_reclassify_or_alias_a_network_index():
    pure, direct = build_profile(MarkerClient(shared=False), 'raw')
    profile, contract = build_profile(MarkerClient(), 'raw')
    assert profile.role == 'network' and profile.os_family == 'unknown'
    assert contract.role == 'network' and contract.os_family == 'unknown'
    assert contract.fields['host.name'] == direct.fields['host.name']
    assert contract.fields['event.provider'].native == 'event.provider'
    assert profile.hosts == pure.hosts == {'sensor01': 20}
    assert profile.notes == pure.notes == []
    assert 'windows_shapes' not in profile.model_dump()


def test_network_windows_records_are_counted_not_assessed():
    profile, contract = build_profile(MarkerClient(count=3), 'raw')
    assert profile.role == contract.role == 'network'
    assert profile.os_family == contract.os_family == 'unknown'
    assert 'Windows event records on a network target: 3, not evaluated' in profile.notes
    assert profile.model_dump()['windows_not_assessed']['records'] == 3
    assert contract.fields['event.provider'].native == 'event.provider'


@pytest.mark.parametrize('network', [False, True])
def test_failed_marker_count_keeps_mapping_windows_but_marks_unverified(network):
    profile, contract = build_profile(MarkerClient(failed=True, network=network), 'raw')
    assert profile.os_family == contract.os_family == 'windows'
    assert any('Windows classification unverified' in note for note in profile.notes)
    if network:
        assert contract.fields['event.provider'].native == 'event.provider'


def test_explicit_network_contract_never_receives_windows_aliases():
    current = contract_from_types('raw', MarkerClient().fields, role='network', os_family='unknown')
    assert current.fields['host.name'].native == 'host.name'
    assert current.fields['event.provider'].native == 'event.provider'


def test_mixed_layout_profile_includes_raw_only_hosts(tmp_path):
    from tests.test_mixed_host_shapes import _mixed_documents, _run_mixed

    rows = _mixed_documents()
    rows[0]['_source']['Event']['System']['Computer'] = 'RAW01.example.test'
    _s, _c, _cells, profile, contract = _run_mixed(tmp_path, rows)
    assert profile.hosts == {'WS01.example.test': 1, 'RAW01.example.test': 1}
    assert set(contract.hosts) == set(profile.hosts) and contract.host_inventory_complete


def test_real_host_link_retrieves_raw_only_host_beside_winlogbeat(tmp_path):
    from copy import deepcopy
    from datetime import timedelta

    from romulus.config import Settings
    from romulus.evidence.windows import normalize_windows
    from romulus.hunt.links import LinkAnchor, LinkFetcher, LinkWindow
    from romulus.hunt.pivot import PivotExecutor
    from romulus.sources.es import ElasticClient
    from tests.test_host_shapes_profile import WINDOW, types
    from tests.test_mixed_host_shapes import _mixed_documents
    from tests.test_sweep import _repo
    from tests.throughput_fixture import MiniES

    rows = _mixed_documents()[:2]
    rows[0]['_source']['Event']['System']['Computer'] = 'RAW01.example.test'
    later = deepcopy(rows[0])
    later['_id'] = 'raw-later'
    later['_source']['Event']['System']['EventRecordID'] = 22
    stamp = WINDOW.start + timedelta(hours=1, seconds=1)
    later['_source']['@timestamp'] = stamp.isoformat()
    later['_source']['Event']['System']['TimeCreated']['#attributes']['SystemTime'] = stamp.isoformat()
    rows.append(later)
    fields = {**types(), 'winlog.channel': 'keyword', 'winlog.provider_name': 'keyword',
              'winlog.event_id': 'long', 'winlog.computer_name': 'keyword', 'winlog.event_data': 'flattened'}
    current = contract_from_types('raw', fields)
    client = ElasticClient(Settings(es_url='http://es.invalid'),
                           transport=MiniES({'raw': rows}, {'raw': '@timestamp'}).transport())
    repo = _repo()
    executor = PivotExecutor(repo, client, 'h1', {'raw': current}, stage_dir=tmp_path)
    root = normalize_windows(rows[0])
    anchor = LinkAnchor(finding_id='anchor', ts=root.ts, host=root.host, event_ids=[root.id], events=[root])
    try:
        result = LinkFetcher(executor, WINDOW.start, WINDOW.end).fetch(anchor, 'host_after_anchor',
            LinkWindow(label='anchor +5 min', start=root.ts, end=root.ts+timedelta(minutes=5)))
        assert result.status == 'complete', result.reasons
        assert normalize_windows(later).id in result.event_ids
    finally:
        repo.engine.dispose()


def test_shared_template_and_unassessed_windows_rows_do_not_change_real_zeek_cells(tmp_path):
    from copy import deepcopy
    from datetime import UTC, datetime, timedelta

    from romulus.config import Settings
    from romulus.detect.zeek_cleartext import CleartextCredentials
    from romulus.hunt.sweep import Sweep
    from romulus.sources.es import ElasticClient
    from romulus.sources.models import Window
    from tests.fixtures import zeek_logs as zl
    from tests.test_evtx_json import raw_hit, twin
    from tests.test_sweep import _repo
    from tests.throughput_fixture import MiniES

    doc = zl.elastic(zl.HTTP.with_(username='alice'))
    doc['_index'] = 'raw'
    stamp = datetime.fromtimestamp(zl.T0, UTC)
    window = Window(start=stamp-timedelta(seconds=1), end=stamp+timedelta(seconds=2))
    snapshots = []
    for shared, count in [(False, 0), (True, 0), (True, 3)]:
        profile, contract = build_profile(MarkerClient(shared=shared, count=count), 'raw')
        rows = [deepcopy(doc)]
        for n in range(count):
            row = twin(raw_hit())
            row['_index'], row['_id'] = 'raw', f'windows-{n}'
            row['_source']['@timestamp'] = stamp.isoformat()
            rows.append(row)
        client = ElasticClient(Settings(es_url='http://es.invalid'),
            transport=MiniES({'raw': rows}, {'raw': '@timestamp'}).transport())
        repo = _repo()
        runner = Sweep(repo, client, 'h1', window, {'raw': contract}, stage_dir=tmp_path / f'{shared}-{count}')
        runner.pack = [CleartextCredentials()]
        runner._profiles = {'raw': profile.model_dump()}
        try:
            runner._prepare_windows_inventory('raw', contract)
            runner.run_partition('raw', contract, [], window, est=len(rows))
            runner.finalize()
            assert not runner.stats.get('windows_inventory')
            assert runner.stats['errors'] == 0
            assert not any('collection not attested' in str(cell['detail']) for cell in repo.rule_cells('h1'))
            snapshots.append([{name: cell[name] for name in ('rule_id', 'partition', 'state', 'matched', 'evaluated', 'detail')}
                              for cell in repo.rule_cells('h1')])
            if count:
                assert runner.stats['skips']['Windows event records on a network target: not evaluated'] == count
        finally:
            runner.close_stage()
            repo.engine.dispose()
    assert snapshots[0] == snapshots[1] == snapshots[2]
