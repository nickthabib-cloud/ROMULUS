"""Catalog browsing stays honest and bounded over historical hunts."""
import pytest

from romulus.catalog.browser import CatalogBrowser, applicability, load_tags, readable_ast
from romulus.catalog.build import build_catalog
from tests.test_report import _repo_with_finding


def test_rule_list_pages_filters_and_full_registry():
    repo, _ = _repo_with_finding()
    browser = CatalogBrowser(repo)
    rows, after = browser.rules({}, limit=20)
    assert len(rows) == 20 and after == rows[-1]['id']
    more, _ = browser.rules({}, after=after, limit=20)
    assert rows[-1]['id'] < more[0]['id']
    for key in ('family', 'technique', 'lane', 'assurance', 'source'):
        value = {'family': rows[0]['families'][0], 'technique': rows[0]['attack_ids'][0]
                 if rows[0]['attack_ids'] else 'T1059', 'lane': rows[0]['lane'],
                 'assurance': rows[0]['assurance'], 'source': 'built-in'}[key]
        filtered, _ = browser.rules({key: value})
        assert all(value in row['families'] if key == 'family' else
                   value in row['attack_ids'] if key == 'technique' else row[key] == value
                   for row in filtered)
    assert browser.detail(rows[0]['id'])['id'] == rows[0]['id']
    assert len(browser.catalog().rules) == len(build_catalog().rules)


def test_applicability_requires_family_and_fields_and_fresh_profile():
    rule = {'families': ['exec'], 'required_fields': ['process.executable'], 'required_by_family': {}}
    profile = {'target': 'source', 'families': ['exec'], 'fields': ['process.executable'], 'fresh': True}
    assert applicability(rule, [profile])[0]['state'] == 'runs'
    assert applicability(rule, [{**profile, 'fields': []}])[0]['state'] == 'not applicable'
    assert applicability(rule, [{**profile, 'families': []}])[0]['state'] == 'not applicable'
    assert applicability(rule, [{**profile, 'fresh': False, 'captured_at': '2020-01-01'}])[0]['state'] == 'unknown'
    assert applicability(rule, [])[0]['state'] == 'unknown'


def test_tag_loader_rejects_unregistered_rule(tmp_path):
    path = tmp_path / 'tags.yaml'
    path.write_text('tools: [{name: test, kind: admin, rules: [invented.rule]}]\nlotl: []\nthemes: []\n')
    with pytest.raises(ValueError, match='invented.rule'):
        load_tags(path)


def test_ast_is_readable_typed_conditions():
    ast = {'selectors': {'s': {'type': 'field', 'fields': ['process.executable'], 'all': False,
                             'groups': [[{'type': 'literal', 'value': '/bin/sh'}]]}},
           'condition': {'type': 'selector', 'name': 's'}}
    text = readable_ast(ast)
    assert 'process.executable' in text and '/bin/sh' in text and 'selectors' not in text


def test_public_tags_include_registered_references_and_gaps():
    document = load_tags()
    assert all(document[key] for key in ('tools', 'lotl', 'themes'))
    assert all(any(not row['rules'] for row in document[key]) for key in document)


def test_statistics_at_ten_thousand_hunts_has_constant_query_count():
    from datetime import timedelta

    from sqlalchemy import event, select

    from romulus.store import schema as t
    from tests.test_report import T

    repo, cid = _repo_with_finding()
    candidate = repo.candidate(cid)
    with repo.engine.begin() as c:
        hunt = dict(c.execute(select(t.hunt)).mappings().one())
        c.execute(t.hunt.update().values(created_at=T))
        original = dict(c.execute(select(t.candidate)).mappings().one())
        c.execute(t.candidate.update().values(created_at=T))
        for start in range(0, 10000, 500):
            hunts, candidates = [], []
            for n in range(start, start + 500):
                hunt_id = f'volume-{n:05}'
                stamp = T + timedelta(minutes=n)
                hunts.append({**hunt, 'id': hunt_id, 'created_at': stamp})
                for child in range(2):
                    candidates.append({**original, 'id': f'candidate-{n}-{child}', 'hunt_id': hunt_id,
                                       'created_at': stamp})
            c.execute(t.hunt.insert(), hunts)
            c.execute(t.candidate.insert(), candidates)
    repo.add_disposition(cid, 'analyst', 'benign', None)
    statements = []
    def count(_conn, _cursor, statement, _parameters, _context, _many):
        statements.append(statement)
    event.listen(repo.engine, 'before_cursor_execute', count)
    try:
        stats = CatalogBrowser(repo).statistics([candidate['rule_id']], last_n=10)[candidate['rule_id']]
    finally:
        event.remove(repo.engine, 'before_cursor_execute', count)
    assert stats['hits'] == 20001 and stats['recent_hits'] == 20
    assert stats['last_hunt'] == 'volume-09999' and stats['outcomes'] == {'benign': 1, 'new': 1}
    assert len(statements) == 3


def test_never_fired_and_deleted_hunts_are_honest():
    repo, cid = _repo_with_finding()
    fired = repo.candidate(cid)['rule_id']
    browser = CatalogBrowser(repo)
    rows, _ = browser.rules({'q': fired, 'never_fired': '1'})
    assert not rows
    repo.audit('lead', 'hunt.delete', 'removed', {'candidates': '12'})
    assert browser.deleted_hunts() == 1


def test_export_guards_formula_text_in_both_formats():
    import html
    repo, _ = _repo_with_finding()
    browser = CatalogBrowser(repo)
    browser._rules = [{**browser.base_rules()[0], 'title': '=HYPERLINK("https://example.invalid")'}]
    for format in ('csv', 'md'):
        assert "'=HYPERLINK" in html.unescape(''.join(browser.export({'source': 'built-in'}, format)))


def test_sigma_ast_fields_are_required_for_applicability():
    from romulus.catalog.browser import _document
    from romulus.catalog.build import _rule_metadata
    from romulus.detect.registry import ALL_PLAYBOOKS
    ast = {'selectors': {'a': {'type': 'exists', 'fields': ['process.command_line'], 'value': True}},
           'condition': {'type': 'selector', 'name': 'a'}}
    document = _document(_rule_metadata(ALL_PLAYBOOKS[0]), source='Sigma', ast=ast)
    assert 'process.command_line' in document['required_fields']


def test_manifest_fallback_without_field_contract_is_unknown():
    from romulus.store import schema as t
    repo, _ = _repo_with_finding()
    with repo.engine.begin() as c:
        manifest = repo.get_hunt('h1')['manifest']
        manifest['source_profiles'] = {'idx': {'datasets': {'linux.audit': 1}, 'role': 'host',
                                             'os_family': 'linux', 'datasets_complete': False}}
        c.execute(t.hunt.update().values(manifest=manifest))
    profiles = CatalogBrowser(repo).profiles()
    assert profiles and not profiles[0]['fresh']


def test_known_families_include_normalizer_families():
    from romulus.catalog.browser import known_families
    from romulus.hunt.sweep import DATASET_FAMILIES
    assert set().union(*DATASET_FAMILIES.values()) <= set(known_families())
