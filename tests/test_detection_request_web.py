"""Detection request routes enforce login, live roles, CSRF, and escaped text."""
import pytest

from tests import test_web as web_helpers
from tests.test_web import _csrf, _login


@pytest.fixture()
def request_client(tmp_path, monkeypatch):
    return web_helpers.client.__wrapped__(tmp_path, monkeypatch)


@pytest.mark.parametrize('route', ['/catalog/requests', '/catalog/requests/new',
                                  '/catalog/requests/export?format=yaml', '/catalog/requests/missing'])
def test_requests_require_login(request_client, route):
    c, _, _ = request_client
    assert c.get(route, follow_redirects=False).status_code == 303


def _create(c, behavior='<script>behavior</script>'):
    token = _csrf(c.get('/catalog/requests/new').text)
    response = c.post('/catalog/requests', data={'behavior': behavior, 'telemetry_family': 'unknown',
                      'csrf': token}, follow_redirects=False)
    assert response.status_code == 303, response.text
    return response.headers['location']


def test_requests_create_own_edit_status_and_export_permissions(request_client, tmp_path):
    from romulus.config import Settings
    from romulus.hunt.run import open_repo
    from romulus.web.auth import create_user
    c, password, _ = request_client
    _login(c, password)
    location = _create(c)
    detail = c.get(location)
    assert '&lt;script&gt;behavior&lt;/script&gt;' in detail.text and '<script>behavior</script>' not in detail.text
    token = _csrf(detail.text)
    assert c.post(location + '/edit', data={'csrf': token, 'behavior': 'edited'},
                  follow_redirects=False).status_code == 303
    assert c.post(location + '/status', data={'csrf': token, 'status': 'accepted'}).status_code == 403
    repo = open_repo(Settings(home=tmp_path))
    create_user(repo.engine, 'other', password, 'analyst')
    c.post('/login', data={'username': 'other', 'password': password})
    token = _csrf(c.get(location).text)
    assert c.get('/catalog/requests?requester=analyst1').status_code == 200
    assert c.post(location + '/edit', data={'csrf': token, 'behavior': 'stolen'}).status_code == 403
    create_user(repo.engine, 'lead', password, 'lead')
    c.post('/login', data={'username': 'lead', 'password': password})
    token = _csrf(c.get(location).text)
    assert c.post(location + '/status', data={'csrf': token, 'status': 'declined'}).status_code == 400
    assert c.post(location + '/status', data={'csrf': token, 'status': 'declined', 'reason': 'Needs telemetry'},
                  follow_redirects=False).status_code == 303
    assert 'Needs telemetry' in c.get(location).text
    for format in ('csv', 'yaml'):
        response = c.get('/catalog/requests/export?format=' + format)
        assert response.status_code == 200 and 'edited' in response.text


def test_every_request_post_needs_csrf(request_client):
    c, password, _ = request_client
    _login(c, password)
    location = _create(c)
    for route, fields in [
        ('/catalog/requests', {'behavior': 'request', 'telemetry_family': 'unknown'}),
        (location + '/edit', {'behavior': 'edit'}),
        (location + '/status', {'status': 'accepted'}),
    ]:
        assert c.post(route, data={**fields, 'csrf': 'forged'}).status_code == 403


def test_flag_more_like_this_prefills_real_cited_reference(request_client):
    c, password, cid = request_client
    _login(c, password)
    finding = c.get('/findings/' + cid)
    assert 'Flag more like this' in finding.text
    draft = c.get('/catalog/requests/new', params={'candidate': cid, 'event': 'ev1'})
    assert draft.status_code == 200
    assert f'value="{cid}"' in draft.text and 'value="ev1"' in draft.text
    assert 'process_exec' in draft.text and 'T1003.008' in draft.text
    assert '&lt;script&gt;' in draft.text and '<script>alert(1)' not in draft.text
    token = _csrf(draft.text)
    response = c.post('/catalog/requests', data={'csrf': token, 'behavior': 'new request',
        'telemetry_family': 'process_exec', 'attack_ids': 'T1552.001', 'example_candidate_id': cid,
        'example_event_id': 'ev1'}, follow_redirects=False)
    assert response.status_code == 303
    assert f'/findings/{cid}' in c.get(response.headers['location']).text


def test_request_body_limit_and_repeated_fields(request_client):
    c, password, _ = request_client
    _login(c, password)
    token = _csrf(c.get('/catalog/requests/new').text)
    assert c.post('/catalog/requests', content='behavior=' + 'x' * 40000,
                  headers={'content-type': 'application/x-www-form-urlencoded'}).status_code == 413
    assert c.post('/catalog/requests', content=f'csrf={token}&behavior=a&behavior=b&telemetry_family=unknown',
                  headers={'content-type': 'application/x-www-form-urlencoded'}).status_code == 400
    assert c.post('/catalog/requests', content=iter([b'behavior=' + b'x' * 40000]),
                  headers={'content-type': 'application/x-www-form-urlencoded'}).status_code == 413
