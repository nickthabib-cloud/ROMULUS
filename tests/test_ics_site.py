"""Address-only ICS control declarations survive validation and snapshotting."""
import re

import pytest

from romulus.site import (
    COLLECTION_SCHEMA,
    SiteValidationError,
    role_address_warnings,
    save_site_facts,
    validate_site_content,
)
from tests import test_web_site_setup as site_support

site = site_support.site


def test_ics_control_addresses_are_canonical_frozen_facts(tmp_path):
    content = {'schema': COLLECTION_SCHEMA, 'ics_control_hosts': ['::ffff:10.0.0.8', '10.2.0.0/24']}
    facts = validate_site_content(content)
    assert facts.ics_control_hosts == ('10.0.0.8', '10.2.0.0/24')
    _, saved = save_site_facts(tmp_path, facts.content, '')
    assert saved == facts
    assert 'ics_control_hosts' not in validate_site_content({'schema': COLLECTION_SCHEMA}).content
    assert validate_site_content({'schema': COLLECTION_SCHEMA, 'ics_control_hosts': []}).content[
        'ics_control_hosts'] == []


@pytest.mark.parametrize('entries', [['engineering.example'], ['10.0.0.4/24'],
                                   ['10.0.0.8', '::ffff:10.0.0.8']])
def test_ics_control_declaration_rejects_names_host_bits_and_alias_duplicates(entries):
    with pytest.raises(SiteValidationError):
        validate_site_content({'schema': COLLECTION_SCHEMA, 'ics_control_hosts': entries})


def test_ics_control_broad_ranges_have_the_existing_role_warning():
    facts = validate_site_content({'schema': COLLECTION_SCHEMA, 'ics_control_hosts': ['10.0.0.0/8']})
    [warning] = role_address_warnings(facts.content)
    assert 'ICS control' in warning and 'broad' in warning


@pytest.mark.parametrize('hosts', [[], ['10.0.0.8']])
def test_existing_site_form_preserves_the_ics_authorization_declaration(site,hosts):
    settings,_repo,login=site
    _,saved=save_site_facts(settings.home,{'schema':COLLECTION_SCHEMA,'ics_control_hosts':hosts},'')
    client=login('lead1')
    page=client.get('/site')
    control=re.search(r'<textarea[^>]*name="ics_control_hosts"[^>]*>(.*?)</textarea>',page.text,re.DOTALL)
    assert control is not None
    assert control.group(1).strip()=='\n'.join(hosts)
    result=client.post('/site',data={'csrf':site_support._csrf(page.text),
        'digest':site_support._digest(page.text),'group_count':'0',
        'ics_control_hosts':'\n'.join(hosts),'ics_control_hosts_declared':'1'})
    assert result.status_code==200
    from romulus.site import load_site_facts
    assert load_site_facts(settings.home).digest==saved.digest
