"""Directory roles survive the actual lead-only site form."""
import re

import pytest

from romulus.site import COLLECTION_SCHEMA, load_site_facts, save_site_facts
from tests import test_web_site_setup as site_support

site = site_support.site


@pytest.mark.parametrize('empty', [False, True])
def test_directory_role_controls_preserve_saved_facts_on_http_roundtrip(site, empty):
    settings, _repo, login = site
    values = {'management_hosts': ['sccm.example.test', '10.0.0.8'],
              'domain_controller_addresses': ['10.0.0.1'],
              'directory_sync_hosts': ['sync01.example.test'],
              'directory_sync_addresses': ['10.0.0.2']}
    content = {'schema': COLLECTION_SCHEMA, **{k: [] if empty else v for k, v in values.items()}}
    _before, saved = save_site_facts(settings.home, content, '')
    lead = login('lead1')
    page = lead.get('/site')
    assert page.status_code == 200
    data = {'csrf': site_support._csrf(page.text), 'digest': site_support._digest(page.text), 'group_count': '0'}
    for key, value in values.items():
        control = re.search(r'<textarea[^>]*name="' + key + r'"[^>]*>(.*?)</textarea>', page.text, re.DOTALL)
        assert control is not None
        assert control.group(1).strip() == '\n'.join([] if empty else value)
        assert re.search(r'<input[^>]*name="' + key + r'_declared"[^>]*value="1"', page.text)
        data[key], data[key+'_declared'] = '\n'.join([] if empty else value), '1'
    response = lead.post('/site', data=data)
    assert response.status_code == 200
    assert load_site_facts(settings.home).digest == saved.digest
