"""All catalog surfaces require login and escape operator-facing metadata."""
import pytest

from tests import test_web as web_helpers
from tests.test_web import _login


@pytest.fixture()
def catalog_client(tmp_path, monkeypatch):
    return web_helpers.client.__wrapped__(tmp_path, monkeypatch)

ROUTES = ['/catalog', '/catalog/attack', '/catalog/attack?domain=ics', '/catalog/tags/tools',
          '/catalog/tags/lotl', '/catalog/tags/themes', '/catalog/families',
          '/catalog/rules/host.credential_store_read', '/catalog/export?format=csv', '/catalog/export?format=md']


@pytest.mark.parametrize('route', ROUTES)
def test_catalog_login_required(catalog_client, route):
    c, _, _ = catalog_client
    response = c.get(route, follow_redirects=False)
    assert response.status_code == 303 and response.headers['location'] == '/login'


@pytest.mark.parametrize('route', ROUTES)
def test_catalog_all_views_render_at_full_registry(catalog_client, route):
    c, password, _ = catalog_client
    _login(c, password)
    response = c.get(route)
    assert response.status_code == 200, response.text


def test_catalog_title_is_escaped(catalog_client, monkeypatch):
    from romulus.detect.registry import ALL_PLAYBOOKS
    c, password, _ = catalog_client
    _login(c, password)
    monkeypatch.setattr(ALL_PLAYBOOKS[0], 'title', '<script>alert(1)</script>')
    response = c.get('/catalog?q=' + ALL_PLAYBOOKS[0].id)
    assert '&lt;script&gt;alert(1)&lt;/script&gt;' in response.text
    assert '<script>alert(1)</script>' not in response.text


def test_lead_can_browse(catalog_client, tmp_path):
    from romulus.config import Settings
    from romulus.hunt.run import open_repo
    from romulus.web.auth import create_user
    c, password, _ = catalog_client
    repo = open_repo(Settings(home=tmp_path))
    create_user(repo.engine, 'lead1', password, 'lead')
    c.post('/login', data={'username': 'lead1', 'password': password})
    assert c.get('/catalog').status_code == 200
