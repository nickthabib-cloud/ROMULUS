"""Pinned local content retains its meaning throughout hunt read views."""
from types import SimpleNamespace

import yaml

from romulus.agent.toolbox import Toolbox
from romulus.content.indicator_import import ImportedIndicator
from romulus.content.sigma_store import SigmaRules
from romulus.report.incidents import build_incident_graph
from romulus.report.manifest import build_manifest, canonical_manifest, coverage_for_hunt
from romulus.store import schema as t
from tests.test_report import _repo_with_finding
from tests.test_sigma_store import document
from tests.test_web import client as client  # noqa: PLC0414 - expose the shared authenticated web fixture.


def sigma_hunt(tmp_path):
    repo, candidate = _repo_with_finding()
    store, rule_id, pins = pin_sigma(repo, tmp_path, candidate)
    return repo, candidate, store, rule_id, pins


def pin_sigma(repo, tmp_path, candidate):
    directory = tmp_path / 'rules'
    directory.mkdir()
    (directory / 'rule.yml').write_text(yaml.safe_dump(document(
        title='Pinned network predicate', tags=['attack.command_and_control', 'attack.t1071'],
        logsource={'product': 'windows', 'category': 'network_connection'})), encoding='utf-8')
    store = SigmaRules(repo)
    [imported] = store.import_directory(directory, upstream='Local', commit='a' * 40, actor='analyst')['rules']
    rule_id = imported['id']
    with repo.engine.begin() as c:
        c.execute(t.sigma_rule.update().where(t.sigma_rule.c.id == rule_id).values(status='active'))
    pins = store.pin()
    hunt = repo.get_hunt('h1')['manifest']
    hunt['sigma_rules'] = pins
    with repo.engine.begin() as c:
        c.execute(t.hunt.update().where(t.hunt.c.id == 'h1').values(manifest=hunt))
        c.execute(t.candidate.update().where(t.candidate.c.id == candidate).values(rule_id='sigma.' + rule_id))
    return store, rule_id, pins


def test_resolver_uses_pinned_fields_and_network_category_without_global_mutation(tmp_path):
    from romulus.detect.metadata import hunt_rule_metadata
    repo, _candidate, _store, rule_id, pins = sigma_hunt(tmp_path)
    try:
        with repo.engine.begin() as c:
            c.execute(t.sigma_rule.update().where(t.sigma_rule.c.id == rule_id).values(
                lane='high', status='retired', title='Changed after pin', tags=[]))
        metadata = hunt_rule_metadata(repo, 'h1')['sigma.' + rule_id]
        assert metadata.title == 'Pinned network predicate'
        assert metadata.lane == 'lead'
        assert metadata.version == '2+' + pins['applied'][0]['digest']
        assert metadata.attack == ('T1071',)
        assert metadata.tactics == ('command-and-control',)
        assert metadata.kind == 'aggregate' and metadata.anchor_class == 'network_observation'
        assert 'sigma.' + rule_id not in hunt_rule_metadata(repo, manifest={})
        assert 'sigma.' + rule_id not in hunt_rule_metadata(repo, 'h1', rule_ids={'sigma.' + 'f' * 64})
        assert hunt_rule_metadata(repo, 'h1', rule_ids={'sigma.' + rule_id})['sigma.' + rule_id].title == metadata.title
    finally:
        repo.engine.dispose()


def test_report_coverage_pads_pinned_sigma_and_uses_its_positive_only_reason(tmp_path):
    repo, _candidate, _store, rule_id, pins = sigma_hunt(tmp_path)
    rid = 'sigma.' + rule_id
    try:
        [unsearched] = [row for row in coverage_for_hunt(repo, 'h1')['rules'] if row['rule_id'] == rid]
        assert 'never evaluated' in unsearched['search_result']
        repo.audit('system', 'hunt.sweep_summary', 'h1', {'finished': True})
        repo.set_rule_cell('h1', rid, pins['applied'][0]['version'], 'idx', 'p0', 'no_match_complete', 0, 10, {})
        [searched] = [row for row in coverage_for_hunt(repo, 'h1')['rules'] if row['rule_id'] == rid]
        assert 'positive-only' in searched['search_result']
        assert 'Local Sigma predicates' in searched['search_result']
        assert 'from argv or text' not in searched['search_result']
    finally:
        repo.engine.dispose()


def test_report_and_canonical_narrative_keep_pinned_sigma_title_and_attack(tmp_path):
    repo, _candidate, _store, rule_id, pins = sigma_hunt(tmp_path)
    try:
        report = build_manifest(repo, 'h1', 'test')
        assert report['versions']['sigma_rules']['digest'] == pins['digest']
        assert report['versions']['sigma_rules']['applied'][0]['id'] == rule_id
        [incident] = report['incident_graph']['incidents']
        assert incident['attack_techniques'] == ['T1071']
        assert incident['attack_tactics'] == ['command-and-control']
        assert 'Pinned network predicate' in str(incident['narrative'])
        assert 'Pinned network predicate' in str(canonical_manifest(repo, 'h1', 'test')['incident_graph'])
    finally:
        repo.engine.dispose()


def test_agent_findings_accept_only_pinned_sigma_ids_and_coverage_includes_them(tmp_path):
    repo, _candidate, _store, rule_id, _pins = sigma_hunt(tmp_path)
    try:
        toolbox = Toolbox(repo, 'h1')
        found = toolbox.execute('list_findings', {'rule': 'sigma.' + rule_id})
        assert found['counts']['total'] == 1
        assert found['data']['findings'][0]['rule_id'] == 'sigma.' + rule_id
        refused = toolbox.execute('list_findings', {'rule': 'sigma.' + 'f' * 64})
        assert refused['status'] == 'refused'
        malformed = toolbox.execute('list_findings', {'rule': 'sigma.' + rule_id + ' OR *'})
        assert malformed['status'] == 'refused'
        coverage = toolbox.execute('list_coverage', {})
        assert coverage['coverage']['counts']['rules'] == 1
    finally:
        repo.engine.dispose()


def test_analyst_indicator_attack_reaches_publication_report_and_incidents(tmp_path, monkeypatch):
    from romulus.detect.indicators import IndicatorMatch, IndicatorSet
    from romulus.hunt.publish import publish_match
    from tests.test_indicator_hunt_content import create_local_hunt
    from tests.test_indicators import net_event
    repo, _lists, meta, hunt_id, _now = create_local_hunt(tmp_path, monkeypatch, [
        ImportedIndicator('sha256', 'ab' * 32, 'Payload', ('T1071', 'T9999'))])
    owner = IndicatorMatch(IndicatorSet())
    try:
        owner.bind_indicators(repo, repo.get_hunt(hunt_id)['manifest']['indicator_lists'])
        owner.consume([net_event('file_transfer', file__hash__sha256='ab' * 32)])
        [match] = list(owner.finalize())
        assert match.attack == ('T1071',)
        published = publish_match(repo, hunt_id, owner, match, None, {})
        assert published['gate_results']['_attack'] == ['T1071']
        report = build_manifest(repo, hunt_id, 'test')
        [finding] = report['findings']
        assert finding['attack'] == ['T1071'] and '_attack' not in finding['gates']
        [incident] = report['incident_graph']['incidents']
        assert incident['attack_techniques'] == ['T1071']
        assert incident['attack_tactics'] == ['command-and-control']
        [version] = report['versions']['indicator_lists']['applied']
        assert (version['id'], version['version'], version['digest'], version['excluded_expired_values']) == (
            meta['id'], 1, meta['digest'], 0)
    finally:
        owner.release_state()
        repo.engine.dispose()


def test_imported_aggregate_remains_a_leaf_between_two_independent_anchors():
    from tests.test_incident_grouping import _finding, _link
    rid = 'sigma.' + 'a' * 64
    pins = {'applied': [{'id': 'a' * 64, 'digest': 'b' * 64, 'title': 'Network predicate',
                        'lane': 'lead', 'tags': [], 'level': 'medium'}]}
    repo = SimpleNamespace(
        get_hunt=lambda _hid: {'manifest': {'sigma_rules': pins}},
        expansion_links=lambda _hid: [_link('L1', 'A1', ['e1']), _link('L2', 'A2', ['e2'])],
        expansion_anchors=lambda _hid: [])
    graph = build_incident_graph(repo, 'hunt', [
        _finding('A1', ['a1']), _finding('A2', ['a2']), _finding('group', ['e1', 'e2'], rule=rid)])
    assert sorted(tuple(incident['finding_ids']) for incident in graph['incidents']) == [
        ('A1',), ('A2',), ('group',)]


def test_web_timeline_shows_pinned_sigma_title_after_retirement(client, tmp_path):
    from romulus.config import Settings
    from romulus.hunt.run import open_repo
    from tests.test_web import _login
    web, password, candidate_id = client
    repo = open_repo(Settings(home=tmp_path))
    try:
        store, rule_id, _pins = pin_sigma(repo, tmp_path, candidate_id)
        store.retire(rule_id, actor='lead', role='lead')
        _login(web, password)
        response = web.get('/hunts/h1/timeline')
        assert response.status_code == 200
        assert 'Pinned network predicate' in response.text
    finally:
        repo.engine.dispose()
