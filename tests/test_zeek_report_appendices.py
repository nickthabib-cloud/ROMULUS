import pytest

from romulus.report.manifest import publish_revision
from romulus.report.markdown import render
from tests.test_report import _repo_with_finding


@pytest.mark.parametrize('with_zeek', [False, True])
@pytest.mark.parametrize('with_fleet', [False, True])
def test_closing_banner_follows_every_appendix(with_zeek, with_fleet):
    repo, _ = _repo_with_finding()
    manifest = publish_revision(repo, 'h1', 'test')
    if with_zeek:
        manifest['coverage']['zeek_visibility'] = {
            'snapshot': {'filename': 'visibility.jsonl', 'count': 1},
            'preview': [{'reason': 'sensor missing health'}],
        }
        manifest['investigations']['link_accounting'] = [{
            'id': 'test-link', 'link_type': 'zeek_uid', 'strength': 'direct', 'status': 'complete',
            'reasons': [], 'evidence_ids': ['conn-evidence'],
        }]
    if with_fleet:
        manifest['findings'][0]['fleet_hosts'] = {
            'filename': 'fleet.jsonl', 'count': 1, 'expected_count': 1, 'complete': True,
        }
    text = render(manifest, banner='REPORT BANNER',
                  host_rows=lambda ref: iter([{'host': 'endpoint-a', 'first_event_id': 'host-evidence'}]))
    assert text.rstrip().endswith('REPORT BANNER')
    assert text.count('REPORT BANNER') == 2
    middle = text.split('REPORT BANNER')[1]
    assert ('Zeek evidence links' in middle) is with_zeek
    assert ('Zeek sensor visibility' in middle) is with_zeek
    assert ('Fleet host appendix' in middle) is with_fleet
