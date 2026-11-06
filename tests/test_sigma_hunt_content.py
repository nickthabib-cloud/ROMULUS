"""Actual hunt pins and catalog output retain imported Sigma attribution."""
from datetime import timedelta

import pytest

from romulus.catalog.build import build_catalog
from romulus.catalog.export import _rules
from romulus.config import Settings
from romulus.content.sigma_store import SigmaRules
from romulus.hunt import run as hunt_run
from romulus.hunt.sweep import Sweep
from romulus.sources.models import Window
from tests.test_indicator_hunt_content import create_local_hunt
from tests.test_sigma_store import document, fixture


def test_created_hunt_uses_its_active_ast_and_lane_after_retirement(tmp_path, monkeypatch):
    import yaml
    repo, _lists, _meta, _hid, now = create_local_hunt(tmp_path, monkeypatch, [])
    root = tmp_path/'sigma'
    root.mkdir()
    (root/'rule.yml').write_text(yaml.safe_dump(document()), encoding='utf-8')
    store = SigmaRules(repo)
    rid = store.import_directory(root, upstream='Local synthetic', commit='a'*40, actor='analyst')['rules'][0]['id']
    positive = fixture(tmp_path, 'positive.json')
    benign = fixture(tmp_path, 'benign.json', r'C:\Tools\benign.exe')
    store.activate(rid, positive, benign, actor='lead', role='lead')
    hid = hunt_run.create_hunt(Settings(home=tmp_path, es_index_patterns=['idx']),
        now-timedelta(hours=1), now, created_by='analyst', ai_agent=False)
    pin = repo.get_hunt(hid)['manifest']['sigma_rules']
    assert pin['applied'][0]['id'] == rid and pin['applied'][0]['lane'] == 'lead'
    store.retire(rid, actor='lead', role='lead')
    store.activate(rid, positive, benign, actor='lead', role='lead', lane='high', reason='New mission')
    instance = Sweep(repo, None, hid, Window(start=now-timedelta(hours=1), end=now), {'idx': None},
                     stage_dir=tmp_path/'stage')
    try:
        owner = next(rule for rule in instance.pack if rule.id == 'sigma.'+rid)
        assert owner.lane == 'lead' and owner.version == '1+'+pin['applied'][0]['digest']
        assert owner.metadata['activation_reason'] == ''
        catalog = build_catalog(repo=repo)
        [entry] = [row for row in _rules(catalog) if row['id'] == owner.id]
        assert entry['provenance'] == {'author': 'Local author', 'upstream': 'Local synthetic',
            'upstream_path': 'rule.yml', 'upstream_commit': 'a'*40}
        assert entry['coverage_strength'] == 'positive-only'
    finally:
        instance.close_stage()
        repo.engine.dispose()


@pytest.mark.parametrize('lane', ['lead', 'high'])
def test_real_sweep_routes_native_classes_and_publishes_only_positive_coverage(tmp_path, monkeypatch, lane):
    from romulus.content.sigma_parser import parse_rule
    from romulus.detect.sigma import SigmaRule
    from romulus.evidence.windows_catalog import SYSMON, SYSMON_CHANNEL
    from romulus.hunt import sweep as module
    from romulus.sources.es import ElasticClient
    from tests.test_sigma_playbook import row
    from tests.test_sweep import _repo
    from tests.test_windows_rpc_retrieval import TARGET, WINDOW, contract
    from tests.throughput_fixture import MiniES
    from tests.windows_fixtures import LogicalWindowsEvent, windows_hit
    metadata = row()
    metadata.update(lane=lane, activation_reason='Mission reason' if lane == 'high' else '')
    process = SigmaRule(metadata)
    dns_metadata = dict(metadata, id='dns')
    parsed = parse_rule({'title': 'Synthetic DNS', 'logsource': {'product': 'windows', 'category': 'dns_query'},
        'detection': {'selection': {'QueryName': 'missing.example'}, 'condition': 'selection'}})
    assert not parsed['reasons']
    dns_metadata.update(ast=parsed['ast'], mapping=parsed['mapping'])
    dns = SigmaRule(dns_metadata)
    monkeypatch.setattr(module, 'fresh_pack', lambda: [process, dns])
    raws = []
    for serial, code, data in [(1, 1, {'Image': r'C:\Tools\evil.exe'}),
                               (2, 1, {'Image': r'C:\Windows\benign.exe'}),
                               (3, 22, {'QueryName': 'benign.example'})]:
        hit = windows_hit(LogicalWindowsEvent(SYSMON_CHANNEL, SYSMON, code, 'ws01.example.test', serial,
            WINDOW.start.isoformat(), data), 'elastic_agent')
        hit['_index'] = TARGET
        raws.append(hit)
    es = MiniES({TARGET: raws}, {TARGET: '@timestamp'})
    client = ElasticClient(Settings(es_url='http://es.invalid'), transport=es.transport())
    repo = _repo()
    instance = Sweep(repo, client, 'h1', WINDOW, {TARGET: contract()}, stage_dir=tmp_path)
    try:
        instance.run_target(TARGET)
        instance.finalize()
        [candidate] = repo.candidates('h1')
        assert candidate['rule_id'] == process.id and candidate['lane'] == lane
        assert process.match_evaluations == 2 and dns.match_evaluations == 1
        assert not instance.failed_rules
        assert all(cell['state'] != 'no_match_complete' for cell in repo.rule_cells('h1'))
        assert any(cell['state'].startswith('positive_only') for cell in repo.rule_cells('h1') if cell['rule_id'] == dns.id)
    finally:
        instance.close_stage()
        repo.engine.dispose()
