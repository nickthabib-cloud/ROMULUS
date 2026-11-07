"""Imported rule metadata remains useful in analyst and agent read views."""
from romulus.agent.toolbox import Toolbox
from romulus.report.manifest import build_manifest, publish_revision
from romulus.report.markdown import render
from romulus.store import schema as t
from tests.test_hunt_rule_metadata import sigma_hunt


def test_technique_only_sigma_rule_inherits_the_known_tactic_mapping(tmp_path):
    repo, _candidate, _store, _rule_id, _pins = sigma_hunt(tmp_path)
    try:
        manifest = repo.get_hunt('h1')['manifest']
        manifest['sigma_rules']['applied'][0]['tags'] = ['attack.t1071']
        with repo.engine.begin() as connection:
            connection.execute(t.hunt.update().where(t.hunt.c.id == 'h1').values(manifest=manifest))
        [incident] = build_manifest(repo, 'h1', 'test')['incident_graph']['incidents']
        assert incident['attack_techniques'] == ['T1071']
        assert incident['attack_tactics'] == ['command-and-control']
    finally:
        repo.engine.dispose()


def test_markdown_table_and_finding_heading_use_the_pinned_sigma_title(tmp_path):
    repo, _candidate, _store, _rule_id, _pins = sigma_hunt(tmp_path)
    try:
        markdown = render(publish_revision(repo, 'h1', 'test'))
        [heading] = [line for line in markdown.splitlines() if line.startswith('### 1.')]
        [table_row] = [line for line in markdown.splitlines() if line.startswith('| [1]')]
        assert 'Pinned network predicate' in heading and 'Pinned network predicate' in table_row
    finally:
        repo.engine.dispose()


def test_entity_profile_counts_the_missing_pinned_sigma_target(tmp_path):
    repo, candidate_id, _store, _rule_id, _pins = sigma_hunt(tmp_path)
    try:
        toolbox = Toolbox(repo, 'h1')
        finding_alias = toolbox.aliases.alias_for('F', candidate_id)
        finding = toolbox.execute('get_finding', {'finding': finding_alias})
        entity = finding['data']['finding']['entities'][0]['alias']
        profile = toolbox.execute('entity_profile', {'entity': entity})
        assert profile['coverage']['counts']['expected_rule_targets'] == 1
        assert profile['coverage']['counts']['missing_rule_targets'] == 1
    finally:
        repo.engine.dispose()
