"""Local indicator interfaces: authorization, atomic imports and bounded views."""
import json
import secrets

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from romulus import cli
from romulus.config import Settings
from romulus.content.indicator_lists import IndicatorLists
from romulus.hunt.run import open_repo
from romulus.store import schema as t
from romulus.web.app import create_app
from romulus.web.auth import Sessions, create_user

CSV = 'kind,value\ndomain,example.test\n'


@pytest.fixture
def ui(tmp_path):
    settings = Settings(home=tmp_path, secret_key=secrets.token_urlsafe(32))
    repo = open_repo(settings)
    for username, role in [('a', 'analyst'), ('l', 'lead')]:
        create_user(repo.engine, username, secrets.token_urlsafe(18), role)
    client = TestClient(create_app(settings))
    def login(role='analyst'):
        username = 'a' if role == 'analyst' else 'l'
        cookie = Sessions(settings.secret_key.get_secret_value()).issue({'username': username, 'role': role})
        client.cookies.set('romulus_session', cookie)
        return Sessions(settings.secret_key.get_secret_value()).read(cookie)['csrf']
    yield client, repo, login
    repo.engine.dispose()


def upload(client, csrf, **extra):
    return client.post('/indicators', data={'csrf': csrf, 'name': 'Partner list', 'source': 'Partner', **extra},
                       files={'file': ('../../hostile.csv', CSV, 'text/csv')}, follow_redirects=False)


def test_indicators_authentication_before_body_parse(ui):
    client, repo, _ = ui
    assert client.get('/indicators', follow_redirects=False).status_code == 303
    result = client.post('/indicators', content=b'not a form', follow_redirects=False)
    assert result.status_code == 303
    assert IndicatorLists(repo).lists() == []


def test_analyst_upload_report_default_expiry_and_hostile_filename(ui):
    client, repo, login = ui
    csrf = login()
    response = upload(client, csrf)
    assert response.status_code == 303
    row = IndicatorLists(repo).lists()[0]
    assert row['author'] == 'a' and row['import_report']['accepted'] == 1
    from datetime import datetime, timedelta
    assert datetime.fromisoformat(row['expires_at']) - datetime.fromisoformat(row['created_at']) == timedelta(days=90)
    detail = client.get(response.headers['location'])
    assert detail.status_code == 200
    assert 'example.test' in detail.text and 'active' in detail.text
    assert 'Import report' in detail.text and '90 days' in client.get('/indicators').text
    assert detail.headers['x-content-type-options'] == 'nosniff'


def test_csrf_and_lead_only_retirement_with_live_role_check(ui):
    client, repo, login = ui
    csrf = login()
    assert upload(client, 'bad').status_code == 403
    assert IndicatorLists(repo).lists() == []
    upload(client, csrf)
    row = IndicatorLists(repo).lists()[0]
    url = '/indicators/' + row['id'] + '/retire'
    assert client.post(url, data={'csrf': csrf}).status_code == 403
    csrf = login('lead')
    assert client.post(url, data={'csrf': 'bad'}).status_code == 403
    with repo.engine.begin() as c:
        c.execute(t.user.update().where(t.user.c.username == 'l').values(role='analyst'))
    assert client.post(url, data={'csrf': csrf}).status_code == 403
    with repo.engine.begin() as c:
        c.execute(t.user.update().where(t.user.c.username == 'l').values(role='lead'))
    assert client.post(url, data={'csrf': csrf}, follow_redirects=False).status_code == 303
    assert IndicatorLists(repo).get(row['id'])['status'] == 'retired'


def test_old_version_view_and_complete_streaming_exports(ui):
    client, repo, login = ui
    csrf = login()
    upload(client, csrf)
    row = IndicatorLists(repo).lists()[0]
    response = client.post('/indicators', data={'csrf': csrf, 'name': 'Changed', 'source': 'Partner',
        'list_id': row['id'], 'csv_text': 'kind,value\n' + ''.join(f'domain,h{i}.test\n' for i in range(110))},
        follow_redirects=False)
    assert response.status_code == 303
    url = '/indicators/' + row['id']
    assert 'example.test' in client.get(url + '?version=1').text
    latest = client.get(url).text
    assert 'first 100' in latest and 'example.test' not in latest
    for fmt in ('csv', 'yaml'):
        exported = client.get(url + '/export?format=' + fmt)
        assert exported.status_code == 200
        assert 'h109.test' in exported.text
        assert exported.headers['content-disposition'].startswith('attachment;')
    old = client.get(url + '/export?format=csv&version=1')
    assert 'example.test' in old.text and 'h109.test' not in old.text
    assert client.get(url + '?version=0').status_code == 400


@pytest.mark.parametrize('filename,body', [('secret.yaml', CSV), ('bad.csv', 'kind,value\ndomain,ok.test\nwrong'),
    ('bad.json', '{'), ('deep.json', '[' * 50 + '0' + ']' * 50)])
def test_invalid_upload_rolls_back_and_audits_bounded_rejection(ui, filename, body):
    client, repo, login = ui
    csrf = login()
    response = client.post('/indicators', data={'csrf': csrf, 'name': 'Partner', 'source': 'Partner'},
        files={'file': (filename, body)}, follow_redirects=False)
    assert response.status_code == 400
    assert IndicatorLists(repo).lists() == []
    with repo.engine.connect() as c:
        audit = c.execute(select(t.audit_event.c.detail).where(
            t.audit_event.c.action == 'indicator_list.import_rejected')).scalar_one()
    assert len(json.dumps(audit)) < 512 and audit['reason'] in {'invalid_file_or_metadata', 'import_failed'}


def test_skipped_report_and_metadata_validation(ui):
    client, repo, login = ui
    csrf = login()
    response = client.post('/indicators', data={'csrf': csrf, 'name': 'Partner', 'source': 'Partner',
        'csv_text': CSV + 'ip,not-an-ip\n'}, follow_redirects=False)
    assert response.status_code == 303
    detail = client.get(response.headers['location']).text
    assert 'invalid_value' in detail and 'bounded' in detail
    rejected = upload(client, csrf, source='https://user:secret@example.test/')
    assert rejected.status_code == 400 and 'secret' not in rejected.text
    assert len(IndicatorLists(repo).lists()) == 1


def test_body_limit_with_content_length_and_chunked(ui, monkeypatch):
    from romulus.web import indicator_routes
    client, repo, login = ui
    login()
    monkeypatch.setattr(indicator_routes, 'HTTP_MAX_BYTES', 100)
    for content, headers in [(b'x' * 101, {}), (iter([b'x' * 60, b'y' * 60]), {'content-type': 'multipart/form-data; boundary=x'})]:
        response = client.post('/indicators', content=content, headers=headers)
        assert response.status_code == 413
        assert response.headers['x-frame-options'] == 'DENY'
    assert IndicatorLists(repo).lists() == []


def test_cli_import_versions_and_safe_rejection(tmp_path, monkeypatch, capsys):
    settings = Settings(home=tmp_path / 'home', secret_key=secrets.token_urlsafe(32))
    monkeypatch.setattr(cli, 'load_settings', lambda _: settings)
    monkeypatch.setenv('USER', 'tester')
    path = tmp_path / 'input.csv'
    path.write_text(CSV + 'domain,EXAMPLE.TEST\nip,invalid\n', encoding='utf-8')
    args = ['indicators', 'import', str(path), '--name', 'Partner', '--source', 'Local partner']
    assert cli.main(args) == 0
    report = json.loads(capsys.readouterr().out)
    assert report['value_count'] == 1 and report['import_report']['accepted'] == 2
    assert report['author'] == 'cli:tester'
    assert cli.main(args + ['--list-id', report['id']]) == 0
    assert json.loads(capsys.readouterr().out)['version'] == 2
    path.write_text('kind,value\ndomain,ok.test\nbroken', encoding='utf-8')
    assert cli.main(args) == 1
    assert 'rejected' in capsys.readouterr().err
    repo = open_repo(settings)
    assert len(IndicatorLists(repo).lists()) == 1
    with repo.engine.connect() as c:
        assert c.execute(select(t.audit_event.c.action).where(
            t.audit_event.c.action == 'indicator_list.import_rejected')).scalar_one()
    repo.engine.dispose()


def test_cli_export_complete_version_to_stdout_and_local_file(tmp_path, monkeypatch, capsys):
    settings = Settings(home=tmp_path / 'home', secret_key=secrets.token_urlsafe(32))
    monkeypatch.setattr(cli, 'load_settings', lambda _: settings)
    path = tmp_path / 'input.csv'
    path.write_text(CSV, encoding='utf-8')
    assert cli.main(['indicators', 'import', str(path), '--name', 'Local', '--source', 'Partner']) == 0
    row = json.loads(capsys.readouterr().out)
    assert cli.main(['indicators', 'export', row['id'], '--version', '1']) == 0
    assert 'example.test' in capsys.readouterr().out
    output = tmp_path / 'complete.csv'
    assert cli.main(['indicators', 'export', row['id'], '--format', 'csv', '--out', str(output)]) == 0
    assert 'example.test' in output.read_text(encoding='utf-8')
    assert cli.main(['indicators', 'export', row['id'], '--out', '//remote/share/export.csv']) == 1


def test_invalid_form_and_format_limit_are_audited(ui, monkeypatch):
    from romulus.web import indicator_routes
    client, repo, login = ui
    csrf = login()
    monkeypatch.setattr(indicator_routes, 'JSON_MAX_BYTES', 16)
    response = client.post('/indicators', data={'csrf': csrf, 'name': 'Local', 'source': 'Partner'},
        files={'file': ('large.json', '{' + ' ' * 20 + '}')})
    assert response.status_code == 413
    with repo.engine.connect() as c:
        assert c.execute(select(t.audit_event.c.detail).where(
            t.audit_event.c.action == 'indicator_list.import_rejected')).scalar_one()['reason'] == 'request_size_limit'


def test_high_indicator_import_requires_live_lead_reason_and_worker_context(ui, monkeypatch):
    import asyncio
    client, repo, login = ui
    original = IndicatorLists.create_version
    def off_loop(store, *args, **kwargs):
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return original(store, *args, **kwargs)
        pytest.fail('An indicator import blocked the web event loop')
    monkeypatch.setattr(IndicatorLists, 'create_version', off_loop)
    csrf = login()
    assert upload(client, csrf, lane='high', reason='Mission indicator').status_code in (400, 403)
    csrf = login('lead')
    assert upload(client, csrf, lane='high').status_code in (400, 403)
    accepted = upload(client, csrf, lane='high', reason='Mission indicator', severity='high')
    assert accepted.status_code == 303
    [metadata] = IndicatorLists(repo).lists()
    [value] = list(IndicatorLists(repo).values(metadata['id']))
    assert value['lane'] == value['severity'] == 'high'


def test_out_of_range_expiry_is_a_safe_interface_rejection(ui):
    client, repo, login = ui
    response = upload(client, login(), expires='0001-01-01T00:00:00+23:59')
    assert response.status_code == 400
    assert IndicatorLists(repo).lists() == []


def test_cli_high_lane_authenticates_lead_and_audits_reason(tmp_path, monkeypatch, capsys):
    settings = Settings(home=tmp_path / 'home', secret_key=secrets.token_urlsafe(32))
    monkeypatch.setattr(cli, 'load_settings', lambda _: settings)
    password = secrets.token_urlsafe(18)
    repo = open_repo(settings)
    create_user(repo.engine, 'lead-user', password, 'lead')
    create_user(repo.engine, 'analyst-user', password, 'analyst')
    import getpass
    monkeypatch.setattr(getpass, 'getpass', lambda _: password)
    path = tmp_path / 'input.csv'
    path.write_text(CSV, encoding='utf-8')
    args = ['indicators', 'import', str(path), '--name', 'Partner', '--source', 'Local', '--lane', 'high']
    assert cli.main(args + ['--user', 'analyst-user', '--reason', 'Mission indicator']) == 1
    assert cli.main(args + ['--user', 'lead-user']) == 1
    assert cli.main(args + ['--user', 'lead-user', '--reason', 'Mission indicator']) == 0
    capsys.readouterr()
    [row] = IndicatorLists(repo).lists()
    assert row['author'] == 'lead-user' and row['lane'] == 'high'
    with repo.engine.connect() as connection:
        audits = connection.execute(select(t.audit_event.c.detail).where(
            t.audit_event.c.action == 'indicator_list.import')).scalars().all()
    assert any(item.get('reason') == 'Mission indicator' and item.get('high') for item in audits)
    repo.engine.dispose()


def test_retired_list_new_version_requires_live_lead_in_web(ui):
    client, repo, login = ui
    upload(client, login())
    [row] = IndicatorLists(repo).lists()
    csrf = login('lead')
    assert client.post('/indicators/' + row['id'] + '/retire', data={'csrf': csrf}, follow_redirects=False).status_code == 303
    assert upload(client, login(), list_id=row['id']).status_code in (400, 403)
    assert upload(client, login('lead'), list_id=row['id']).status_code == 303
    assert IndicatorLists(repo).get(row['id'])['version'] == 2
