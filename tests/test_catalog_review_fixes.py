"""Persistent SQLite regressions for catalog scope, bounded reads, and immutable intake."""
import secrets
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import event, select

from romulus.catalog.browser import CatalogBrowser, _document, applicability
from romulus.catalog.build import _rule_metadata
from romulus.catalog.requests import DetectionRequests
from romulus.detect.registry import ALL_PLAYBOOKS
from romulus.store import schema as t
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo
from romulus.web.auth import create_user
from tests.test_report import _repo_with_finding


@pytest.fixture()
def persistent_repo(tmp_path):
    engine = make_engine(tmp_path / 'catalog.sqlite')
    migrate(engine)
    source, cid = _repo_with_finding()
    with source.engine.connect() as read, engine.begin() as write:
        for table in (t.hunt, t.raw_record, t.typed_event, t.candidate, t.disposition_event):
            rows = [dict(row) for row in read.execute(table.select()).mappings()]
            if rows:
                write.execute(table.insert(), rows)
    source.engine.dispose()
    yield Repo(engine), cid
    engine.dispose()


def profile(**changes):
    return {'target': 'source', 'fresh': True, 'families': ['process_exec'], 'fields': ['process.executable'],
            'os_family': 'linux', 'role': 'host', **changes}


def test_runtime_os_scope_is_preserved(persistent_repo):
    repo, _ = persistent_repo
    browser = CatalogBrowser(repo)
    linux = browser.detail('host.exec_from_temp_dir')
    assert applicability(linux, [profile(os_family='windows')])[0]['state'] == 'not applicable'
    assert applicability(linux, [profile(os_family='unknown')])[0]['state'] == 'unknown'
    assert applicability(linux, [profile()])[0]['state'] == 'runs'
    windows = next(row for row in browser.base_rules() if row.get('os_families') == ['windows'])
    assert applicability(windows, [profile(fields=windows['required_fields'])])[0]['state'] == 'not applicable'


def test_accepted_family_and_family_specific_fields_are_alternatives(persistent_repo):
    repo, _ = persistent_repo
    matcher = CatalogBrowser(repo).detail('ioc.indicator_match')
    supplied = profile(families=['net_flow'], fields=['source.ip', 'destination.ip'], role='network')
    assert applicability(matcher, [supplied])[0]['state'] == 'runs'
    rule = {'families': ['process_exec', 'auth'], 'required_fields': [],
            'required_by_family': {'process_exec': ['process.executable'], 'auth': ['auth.service']}}
    assert applicability(rule, [profile()])[0]['state'] == 'runs'


def field(*names):
    return {'type': 'field', 'fields': list(names), 'all': False,
            'groups': [[{'type': 'literal', 'value': 'value'}]]}


def sigma_document(condition, *, scope=None):
    base = next(rule for rule in ALL_PLAYBOOKS if rule.id == 'host.exec_from_temp_dir')
    ast = {'version': 1, 'selectors': {'s': condition}, 'condition': {'type': 'selector', 'name': 's'}}
    if scope is not None:
        ast['scope'] = scope
    return _document(_rule_metadata(base), source='Sigma', ast=ast)


def test_sigma_boolean_alias_and_absence_capability():
    alias = field('process.executable', 'wfp.application')
    assert applicability(sigma_document(alias), [profile()])[0]['state'] == 'runs'
    either = {'type': 'or', 'children': [field('not.present'), alias]}
    assert applicability(sigma_document(either), [profile()])[0]['state'] == 'runs'
    both = {'type': 'and', 'children': [field('not.present'), alias]}
    assert applicability(sigma_document(both), [profile()])[0]['state'] == 'not applicable'
    negated = {'type': 'not', 'child': field('not.present')}
    assert applicability(sigma_document(negated), [profile()])[0]['state'] == 'unknown'
    absent = {'type': 'exists', 'fields': ['not.present'], 'value': False}
    assert applicability(sigma_document(absent), [profile()])[0]['state'] == 'unknown'
    # A conjunction of alternatives stays structural rather than expanding 2**40 branches.
    wide = {'type': 'and', 'children': [either] * 40}
    assert applicability(sigma_document(wide), [profile()])[0]['state'] == 'runs'
    family_inventory = {'field_inventory': [{'family': 'process_exec', 'fields': ['process.executable']}]}
    assert applicability(sigma_document(alias, scope=family_inventory),
                         [profile(event_classes=None)])[0]['state'] == 'runs'


def test_native_and_sigma_scope_need_positive_inventory_evidence():
    scope = {'families': ['process_exec'], 'os_families': ['windows'],
             'windows_event_classes': [['channel', 'provider', 1]], 'event_codes': ['1'],
             'scope': [{'field': 'process.type', 'values': ['created']}]}
    rule = sigma_document(field('process.executable'), scope=scope)
    windows = profile(os_family='windows')
    assert applicability(rule, [windows])[0]['state'] == 'unknown'
    proven = {**windows, 'event_classes': [['channel', 'provider', 1]],
              'scope_values': {'process.type': ['created']}}
    assert applicability(rule, [proven])[0]['state'] == 'runs'
    assert applicability(rule, [{**proven, 'event_classes': [['other', 'provider', 2]]}])[0]['state'] == 'not applicable'
    assert applicability(rule, [{**proven, 'scope_values': {'process.type': ['deleted']}}])[0]['state'] == 'not applicable'


def test_sigma_capability_does_not_join_fields_across_native_event_classes():
    first, second = ['channel', 'provider', 1], ['channel', 'provider', 2]
    ast_scope = {'os_families': ['windows'], 'windows_event_classes': [first, second],
                 'field_inventory': [{'event_class': first, 'fields': ['first']},
                                     {'event_class': second, 'fields': ['second']}]}
    rule = sigma_document({'type': 'and', 'children': [field('first'), field('second')]}, scope=ast_scope)
    mixed = profile(os_family='windows', fields=['process.executable', 'first', 'second'],
                    event_classes=[first, second])
    assert applicability(rule, [mixed])[0]['state'] == 'not applicable'
    rule['windows_event_classes'] = [first]
    rule['ast']['scope']['windows_event_classes'] = [second]
    assert applicability(rule, [mixed])[0]['state'] == 'not applicable'


def _vm_work(engine, action):
    steps = [0]
    def tick():
        steps[0] += 1
        return 0
    def checkout(driver, _record, _proxy):
        driver.set_progress_handler(tick, 1)
    def checkin(driver, _record):
        driver.set_progress_handler(None, 0)
    event.listen(engine, 'checkout', checkout)
    event.listen(engine, 'checkin', checkin)
    try:
        action()
    finally:
        event.remove(engine, 'checkout', checkout)
        event.remove(engine, 'checkin', checkin)
    return steps[0]


def test_statistics_do_not_scan_unrelated_history(persistent_repo):
    repo, cid = persistent_repo
    action = lambda: CatalogBrowser(repo).statistics(['never.fired'])
    before = _vm_work(repo.engine, action)
    with repo.engine.begin() as c:
        original = dict(c.execute(select(t.candidate).where(t.candidate.c.id == cid)).mappings().one())
        c.execute(t.candidate.insert(), [{**original, 'id': f'unrelated-{n}'} for n in range(5000)])
    statements = []
    def record(_c, _cursor, sql, args, _context, _many):
        statements.append((sql, args))
    event.listen(repo.engine, 'before_cursor_execute', record)
    try:
        after = _vm_work(repo.engine, action)
    finally:
        event.remove(repo.engine, 'before_cursor_execute', record)
    assert after <= before + 100
    with repo.engine.connect() as c:
        plans = [str(c.exec_driver_sql('EXPLAIN QUERY PLAN ' + sql, args).all()) for sql, args in statements]
    assert not any('SCAN candidate' in plan or 'SCAN disposition_event' in plan for plan in plans)
    print('SCOPED_SQL_VM_STEPS', before, after)


def test_profile_latest_seeks_do_not_rank_historical_payloads(persistent_repo):
    repo, _ = persistent_repo
    now = datetime.now(UTC)
    data = {'role': 'host', 'os_family': 'linux', 'field_types': {'process.executable': 'keyword'},
            'datasets': {'linux.audit': 1}}
    with repo.engine.begin() as c:
        c.execute(t.source_profile.insert().values(id='current', target='source', hunt_id='h1',
            kind='es_index', captured_at=now, profile=data))
    action = lambda: CatalogBrowser(repo).profiles()
    before = _vm_work(repo.engine, action)
    with repo.engine.begin() as c:
        c.execute(t.source_profile.insert(), [{'id': f'old-{n}', 'target': 'source', 'hunt_id': 'h1',
            'kind': 'es_index', 'captured_at': now - timedelta(days=1), 'profile': data} for n in range(5000)])
    after = _vm_work(repo.engine, action)
    assert after <= before + 100
    assert CatalogBrowser(repo).profiles()[0]['captured_at'].startswith(str(now.date()))
    print('PROFILE_SQL_VM_STEPS', before, after)


def test_newer_manifest_profile_supersedes_older_stored_profile(persistent_repo):
    repo, _ = persistent_repo
    old = datetime.now(UTC) - timedelta(days=2)
    manifest = repo.get_hunt('h1')['manifest']
    manifest['source_profiles'] = {'source': {'captured_at': datetime.now(UTC).isoformat(), 'role': 'host',
        'os_family': 'windows', 'field_types': {'process.executable': 'keyword'},
        'datasets': {'windows.sysmon_operational': 1}}}
    with repo.engine.begin() as c:
        c.execute(t.source_profile.insert().values(id='older', target='source', hunt_id='h1', kind='es_index',
            captured_at=old, profile={'role': 'host', 'os_family': 'linux', 'datasets': {'linux.audit': 1},
                                     'field_types': {'process.executable': 'keyword'}}))
        c.execute(t.hunt.update().values(manifest=manifest))
    actual = next(row for row in CatalogBrowser(repo).profiles() if row['target'] == 'source')
    assert actual['os_family'] == 'windows'


@pytest.mark.parametrize('migrated', [False, True])
def test_audit_and_request_replacement_is_rejected(tmp_path, migrated):
    engine = make_engine(tmp_path / f'append-{migrated}.sqlite')
    if migrated:
        migrate(engine)
    else:
        t.metadata.create_all(engine)
    repo = Repo(engine)
    create_user(engine, 'lead', secrets.token_urlsafe(20), 'lead')
    store = DetectionRequests(repo)
    row = store.create(actor='lead', behavior='original', family='unknown')
    first = store.history(row['id'])[0][0]
    with engine.connect() as c:
        assert c.exec_driver_sql('PRAGMA recursive_triggers').scalar_one() == 0
    for table, values in [(t.detection_request_event, {**first, 'reason': 'rewrite'}),
                           (t.detection_request, {**row, 'behavior': 'rewrite'})]:
        with pytest.raises(Exception, match='append-only|replacement'), engine.begin() as c:
            c.execute(table.insert().prefix_with('OR REPLACE').values(**values))
        from sqlalchemy.dialects.sqlite import insert
        with pytest.raises(Exception, match='append-only|replacement'), engine.begin() as c:
            c.execute(insert(table).values(**values).on_conflict_do_update(
                index_elements=['id'], set_={key: value for key, value in values.items() if key != 'id'}))
    assert store.history(row['id'])[0][0] == first
    assert store.get(row['id'])['behavior'] == 'original'
    engine.dispose()


def test_authorized_combined_families_pass_service_and_sql(persistent_repo, monkeypatch):
    from romulus.catalog import requests
    repo, _ = persistent_repo
    create_user(repo.engine, 'lead', secrets.token_urlsafe(20), 'lead')
    future = ('kernel_module', 'file_access', 'share_change')
    monkeypatch.setattr(requests, 'known_families', lambda: future)
    for family in future:
        assert DetectionRequests(repo).create(actor='lead', behavior='behavior', family=family)['telemetry_family'] == family


def _active_sigma(repo, tmp_path):
    from tests.test_sigma_store import imported
    source, _, rule_id = imported(tmp_path)
    with source.engine.connect() as read, repo.engine.begin() as write:
        row = dict(read.execute(select(t.sigma_rule).where(t.sigma_rule.c.id == rule_id)).mappings().one())
        write.execute(t.sigma_rule.insert().values(**{**row, 'status': 'active'}))
        for n in range(30):
            write.execute(t.sigma_rule.insert().values(**{**row, 'id': f'draft-{n}', 'status': 'draft'}))
    source.engine.dispose()
    return rule_id


def test_active_sigma_byte_limit_precedes_ast_materialization(persistent_repo, tmp_path, monkeypatch):
    from romulus.catalog import browser
    repo, _ = persistent_repo
    _active_sigma(repo, tmp_path)
    monkeypatch.setattr(browser, 'MAX_ACTIVE_BYTES', 1, raising=False)
    statements = []
    def record(_c, _cursor, sql, _args, _context, _many):
        statements.append(sql)
    event.listen(repo.engine, 'before_cursor_execute', record)
    try:
        with pytest.raises(ValueError, match='Sigma'):
            browser.CatalogBrowser(repo).base_rules()
    finally:
        event.remove(repo.engine, 'before_cursor_execute', record)
    assert not any('sigma_rule.ast,' in sql for sql in statements)


def test_attack_route_reuses_active_sigma_without_history_iteration(persistent_repo, tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from romulus.config import Settings
    from romulus.content.sigma_store import SigmaRules
    from romulus.web import app as web
    from romulus.web.auth import Sessions
    repo, _ = persistent_repo
    sigma_id = _active_sigma(repo, tmp_path)
    def forbidden(_self):
        raise AssertionError('Historical Sigma iteration is not permitted')
    monkeypatch.setattr(SigmaRules, 'iter_rules', forbidden)
    monkeypatch.setattr(web, 'open_repo', lambda _settings: repo)
    create_user(repo.engine, 'reader', secrets.token_urlsafe(20), 'analyst')
    settings = Settings(home=tmp_path, secret_key=secrets.token_urlsafe(32))
    client = TestClient(web.create_app(settings))
    client.cookies.set('romulus_session', Sessions(settings.secret_key.get_secret_value()).issue(
        {'username': 'reader', 'role': 'analyst'}))
    response = client.get('/catalog/attack')
    assert response.status_code == 200
    browser = CatalogBrowser(repo)
    assert 'sigma.' + sigma_id in {row.id for row in browser.catalog().rules}
    assert all(not row.id.startswith('sigma.draft-') for row in browser.catalog().rules)


def test_stored_windows_profile_cannot_claim_linux_scope_in_detail_or_filter(persistent_repo, tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from romulus.config import Settings
    from romulus.web import app as web
    from romulus.web.auth import Sessions
    repo, _ = persistent_repo
    now = datetime.now(UTC)
    with repo.engine.begin() as c:
        c.execute(t.source_profile.insert().values(id='windows-source', hunt_id='h1', target='win',
            kind='es_index', captured_at=now, profile={'role': 'host', 'os_family': 'windows',
                'field_types': {'process.executable': 'keyword'}, 'datasets': {'windows.sysmon_operational': 1}}))
    create_user(repo.engine, 'reader', secrets.token_urlsafe(20), 'analyst')
    monkeypatch.setattr(web, 'open_repo', lambda _settings: repo)
    settings = Settings(home=tmp_path, secret_key=secrets.token_urlsafe(32))
    client = TestClient(web.create_app(settings))
    client.cookies.set('romulus_session', Sessions(settings.secret_key.get_secret_value()).issue(
        {'username': 'reader', 'role': 'analyst'}))
    detail = client.get('/catalog/rules/host.exec_from_temp_dir')
    assert detail.status_code == 200
    assert 'not applicable: OS windows outside rule scope in win' in detail.text
    assert 'runs on win' not in detail.text
    filtered = client.get('/catalog', params={'q': 'host.exec_from_temp_dir', 'applicability': 'runs'})
    assert 'href="/catalog/rules/host.exec_from_temp_dir"' not in filtered.text


def test_profile_budget_refusal_is_unknown_and_named(persistent_repo, monkeypatch):
    from romulus.catalog import browser
    repo, _ = persistent_repo
    with repo.engine.begin() as c:
        c.execute(t.source_profile.insert().values(id='large', hunt_id='h1', target='source',
            kind='es_index', captured_at=datetime.now(UTC), profile={'role': 'host', 'os_family': 'linux',
                'field_types': {'process.executable': 'keyword'}, 'datasets': {'linux.audit': 1}}))
    monkeypatch.setattr(browser, 'MAX_PROFILE_BYTES', 1)
    rows = browser.CatalogBrowser(repo).detail('host.exec_from_temp_dir')['applicability']
    source = next(row for row in rows if row['source'] == 'source')
    assert source['state'] == 'unknown' and 'byte budget exceeded' in source['text']
