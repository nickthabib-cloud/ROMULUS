import pytest

from romulus.config import Settings
from romulus.hunt.run import open_repo
from romulus.report.bundle import write_reports
from romulus.report.manifest import publish_revision
from tests.test_web import _login, client  # noqa: F401


@pytest.mark.parametrize('revisions,bundled', [(0, False), (1, False), (3, False), (1, True), (3, True)])
def test_visibility_appendix_link_requires_file_and_is_unique(client, tmp_path, revisions, bundled):  # noqa: F811
    web, password, _ = client
    settings = Settings(home=tmp_path)
    repo = open_repo(settings)
    ref = repo.save_zeek_visibility('h1', iter([{
        'sensor': 'sensor-a', 'family': 'net_flow', 'partial': True,
        'reason': 'sensor-a missing health',
    }]))
    repo.audit('system', 'hunt.zeek_visibility', 'h1', {
        'snapshot': ref, 'notes': [], 'unresolved': [],
    })
    for _ in range(revisions):
        manifest = publish_revision(repo, 'h1', 'test')
    if bundled:
        write_reports(repo, manifest, settings.reports_dir / 'h1')
    _login(web, password)
    page = web.get('/hunts/h1')
    assert page.status_code == 200
    assert page.text.count('href="/reports/h1/' + ref['filename'] + '"') == int(bundled)
    if bundled:
        assert web.get('/reports/h1/' + ref['filename']).status_code == 200
