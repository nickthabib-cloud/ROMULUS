"""Query-aware RPC retrieval with the real compiler, normalizer and sweep."""
import json
from datetime import timedelta

import pytest

from romulus.config import Settings
from romulus.hunt import sweep as module
from romulus.hunt.sweep import Sweep
from romulus.sources.compile import compile_es
from romulus.sources.es import ElasticClient
from romulus.sources.models import SearchIntent, Window
from romulus.sources.profile import contract_from_types
from tests.test_sweep import _repo
from tests.test_windows_rpc import EFSR, START, hit, rule
from tests.throughput_fixture import MiniES, _matches

TARGET = 'win-host'
WINDOW = Window(start=START, end=START + timedelta(hours=1))


def contract(*, weak=False, missing=()):
    types = {'@timestamp': 'date', 'winlog.channel': 'keyword', 'winlog.provider_name': 'keyword',
             'winlog.event_id': 'keyword', 'winlog.computer_name': 'keyword', 'winlog.record_id': 'long',
             'winlog.event_data': 'flattened'}
    if weak:
        types.pop('winlog.event_data')
        types['winlog.event_data.Protocol'] = 'text'
        types['winlog.event_data.InterfaceUuid'] = 'text'
    for name in missing:
        types.pop(name)
    return contract_from_types(TARGET, types, role='host', os_family='windows', hosts=('ws01.example.test',))


def query_sweep(mapping):
    instance = Sweep(None, None, 'h1', WINDOW, {TARGET: mapping})
    instance.pack = [rule('RpcCoercionCall'), rule('RpcRemoteAdminCall'), rule('RpcReplicationCall')]
    return instance


def selected(instance, mapping, raw):
    groups = instance._any_of_for(TARGET, mapping)
    body = compile_es(SearchIntent(kind='raw', target=TARGET, window=WINDOW, any_of=groups), mapping).body
    return _matches(body['query'], raw['_source'], '@timestamp')


@pytest.mark.parametrize('uuid', [EFSR, EFSR.upper(), EFSR[:12].upper()+EFSR[12:], ' {'+EFSR.upper()+'} '])
@pytest.mark.parametrize('protocol', ['1', '2', 'ncacn_ip_tcp', 'ncacn_np', ' NCACN_Np '])
def test_strict_retrieval_is_superset_for_accepted_uuid_and_protocol_spellings(uuid, protocol):
    mapping = contract()
    instance = query_sweep(mapping)
    raw = hit(protocol=protocol)
    raw['_source']['winlog']['event_data']['InterfaceUuid'] = uuid
    assert selected(instance, mapping, raw)


def test_strict_query_drops_local_and_unknown_interface_and_other_provider():
    mapping = contract()
    instance = query_sweep(mapping)
    assert not selected(instance, mapping, hit(protocol='3'))
    assert not selected(instance, mapping, hit(uuid='11111111-1111-1111-1111-111111111111'))
    raw = hit()
    raw['_source']['winlog']['provider_name'] = 'Unrelated'
    assert not selected(instance, mapping, raw)


@pytest.mark.parametrize('missing', [(), ('winlog.provider_name',), ('winlog.event_id',),
    ('winlog.provider_name', 'winlog.event_id'), ('winlog.channel',)])
def test_weak_contract_retrieves_rpc_and_preserves_security_fallback(missing):
    mapping = contract(weak=True, missing=missing)
    instance = query_sweep(mapping)
    assert selected(instance, mapping, hit())
    assert selected(instance, mapping, hit(protocol='3'))
    raw = hit()
    raw['_source']['winlog'].update({'channel': 'Security', 'provider_name': 'Microsoft-Windows-Security-Auditing',
                                   'event_id': '4624'})
    assert selected(instance, mapping, raw)
    assert any('RPC' in text for text in instance._windows_inventory_reasons[TARGET])


def run_sweep(raws, mapping, tmp_path, monkeypatch, *, one_batch=False):
    for raw in raws:
        raw['_index'] = TARGET
    class CachedMiniES(MiniES):
        # Immutable fixture rows: cache query execution so PIT paging does not
        # rescan 200k native records for every page. The actual compiled query
        # is still evaluated once for each distinct source request.
        def __init__(self, *args):
            super().__init__(*args)
            self.matching_cache = {}

        def _matching(self, target, query):
            key = (target, json.dumps(query, sort_keys=True))
            if key not in self.matching_cache:
                self.matching_cache[key] = super()._matching(target, query)
            return self.matching_cache[key]

    es = CachedMiniES({TARGET: raws}, {TARGET: '@timestamp'})
    client = ElasticClient(Settings(es_url='http://es.invalid'), transport=es.transport())
    pack = [rule('RpcCoercionCall'), rule('RpcRemoteAdminCall'), rule('RpcReplicationCall')]
    monkeypatch.setattr(module, 'fresh_pack', lambda: pack)
    repo = _repo()
    instance = Sweep(repo, client, 'h1', WINDOW, {TARGET: mapping}, stage_dir=tmp_path)
    if one_batch:
        # A known-size dense source batch exercises the unsplittable partition
        # path without substituting normalization or query execution.
        batch_window = Window(start=START, end=START + timedelta(seconds=3))
        instance._prepare_windows_inventory(TARGET, mapping)
        instance.run_partition(TARGET, mapping, [], batch_window, len(raws),
                               any_of=instance._any_of_for(TARGET, mapping))
    else:
        instance.run_target(TARGET)
    instance.finalize()
    return instance, repo, es


def test_real_query_aware_sweep_retains_client_and_server_calls(tmp_path, monkeypatch):
    instance, repo, _ = run_sweep([hit(code=5, serial=101), hit(code=6, address='NULL', serial=101),
        hit(protocol='3')], contract(), tmp_path, monkeypatch)
    candidates = repo.candidates('h1')
    assert len(candidates) == 2
    assert {item['rule_id'] for item in candidates} == {'win.rpc_coercion_call'}
    assert all(item['lane'] == 'high' for item in candidates)
    assert any('client call to' in item['claim'] for item in candidates)
    assert any('a caller the server-side record does not name' in item['claim'] for item in candidates)
    assert not instance.failed_rules


def test_large_local_fallback_is_counted_before_staging_or_folding(tmp_path, monkeypatch):
    raws = [hit(protocol='3', serial=1000000+i) for i in range(200000)]
    raws.extend(hit(offset=i, serial=2000000+i) for i in range(3))
    instance, repo, _ = run_sweep(raws, contract(weak=True), tmp_path, monkeypatch, one_batch=True)
    assert len(repo.candidates('h1')) == 1, (instance.stats, instance.partial_reasons, repo.rule_cells('h1'))
    [candidate] = repo.candidates('h1')
    assert candidate['rule_id'] == 'win.rpc_coercion_call'
    assert '3 RPC call record(s)' in candidate['claim']
    counts = instance.stats['skips_by_target'][TARGET]
    assert sum(n for reason, n in counts.items() if 'RPC' in reason and 'local' in reason) == 200000
    assert instance.stats['events'] == 3
    assert len(candidate['event_ids']) <= 16

def test_strict_scope_cannot_be_bypassed_by_empty_channel_or_windows_dataset():
    mapping = contract()
    mapping.fields['event.dataset'] = contract_from_types(TARGET, {'event.dataset': 'keyword'}).fields['event.dataset']
    instance = query_sweep(mapping)
    raw = hit(protocol='3')
    raw['_source']['winlog']['channel'] = ''
    raw['_source']['event']['dataset'] = 'windows.forwarded'
    assert not selected(instance, mapping, raw)


def test_missing_native_query_leaves_preserve_tolerantly_parsed_calls():
    mapping = contract()
    instance = query_sweep(mapping)
    raw = hit()
    data = raw['_source']['winlog']['event_data']
    data['interfaceuuid'] = data.pop('InterfaceUuid')
    data['protocol'] = data.pop('Protocol')
    assert selected(instance, mapping, raw)


def test_no_rpc_data_is_honestly_no_data_in_scope(tmp_path, monkeypatch):
    instance, repo, _ = run_sweep([], contract(), tmp_path, monkeypatch)
    assert not repo.candidates('h1')
    cells = repo.rule_cells('h1')
    assert len(cells) >= 3
    assert all(cell['evaluated'] == 0 and cell['matched'] == 0 for cell in cells)
    assert all(cell['state'] != 'no_match_complete' for cell in cells)
    assert not instance.failed_rules

def test_target_scoped_skip_reports_why_rpc_records_were_withheld():
    from romulus.evidence.normalize import RPC_REMOTE_SCOPE_SKIP
    instance = query_sweep(contract(weak=True))
    instance._record_skips(TARGET, {RPC_REMOTE_SCOPE_SKIP: 200000})
    assert instance.stats['skips_by_target'][TARGET][RPC_REMOTE_SCOPE_SKIP] == 200000
    assert instance.stats['skips'][RPC_REMOTE_SCOPE_SKIP] == 200000


def _leaf_clauses(query):
    if isinstance(query, dict) and 'bool' in query:
        return sum(_leaf_clauses(item) for key in ('must', 'should', 'filter', 'must_not')
                   for item in (query['bool'].get(key) or []))
    return 1


@pytest.mark.parametrize('weak', [False, True])
def test_full_pack_windows_query_stays_under_the_engine_clause_limit(weak):
    # OpenSearch 2+ and Lucene 9 count every nested leaf against indices.query.bool.max_clause_count (default 1024);
    # a query over it fails the whole Windows target, so RPC alternatives must not multiply across a group.
    from romulus.detect.registry import fresh_pack
    mapping = contract(weak=weak)
    instance = Sweep(None, None, 'h1', WINDOW, {TARGET: mapping})
    instance.pack = fresh_pack()
    groups = instance._any_of_for(TARGET, mapping)
    rpc = [group for group in groups if any(p.field.startswith('rpc.') for p in group)]
    assert len(rpc) <= 6
    body = compile_es(SearchIntent(kind='raw', target=TARGET, window=WINDOW, any_of=groups), mapping).body
    assert _leaf_clauses(body['query']) < 900
