"""HTTP authority reconstruction and packet-body indicators preserve typed roles."""
import pytest

from romulus.report.manifest import _coverage
from tests.fixtures import zeek_logs as zl
from tests.test_indicator_content_matching import rule
from tests.test_indicator_interfaces import ui  # noqa: F401 -- shared pytest fixture
from tests.test_indicators import net_event, run
from tests.test_network_normalizers import arkime, eve, one
from tests.test_zeek_windows_protocols import normalize


@pytest.mark.parametrize('shape', tuple(zl.WRITERS))
def test_cleartext_zeek_http_reconstructs_authority_without_changing_target(shape):
    event = normalize(zl.WRITERS[shape](zl.HTTP.with_(host='Example.TEST', uri='/Keep?q=1'), 'url'))
    owner = rule('url', 'http://example.test/Keep?q=1')
    try:
        [match] = run(owner, event)
        assert 'reconstruct' in match.claim.lower()
        assert {field.field for field in match.predicate} >= {'http.hostname', 'url.original'}
    finally:
        owner.release_state()


@pytest.mark.parametrize('event', [one(eve('url', {'event_type':'http','http':{'hostname':'example.test:8080','url':'/Keep'}})),
    one(arkime(http={'host':['example.test:8080'],'uri':['/Keep']}))])
def test_network_http_retains_nondefault_host_port(event):
    owner = rule('url','http://example.test:8080/Keep')
    try:
        assert len(run(owner,event)) == 1
    finally:
        owner.release_state()


def test_one_searchable_record_cannot_hide_another_records_missing_url():
    owner = rule('url','http://example.test/Keep')
    try:
        owner.consume([net_event('http_tx', 'one', url__original='http://example.test/Other'),
                       net_event('http_tx', 'two', url__original='/Keep')])
        [note] = owner.partition_coverage_notes()
        assert '1 delivered record' in note and 'cannot be searched' in note
        cell={'rule_id':owner.id,'target':'network','partition':'window','state':'positive_only',
              'matched':0,'evaluated':2,'detail':{'reasons':[note]}}
        coverage=_coverage([cell],targets=['network'],rule_ids=[owner.id],sweep_finished=True)
        assert note in coverage['rules'][0]['search_result']
    finally:
        owner.release_state()


def test_report_and_web_render_positive_only_indicator_search_gaps(request):
    from romulus.report.manifest import publish_revision
    from romulus.report.markdown import render
    from tests.test_report import _repo_with_finding
    client, repo, login = request.getfixturevalue('ui')
    source, _ = _repo_with_finding()
    repo.create_hunt('h1', source.get_hunt('h1')['manifest'], 'digest', 'test')
    source.engine.dispose()
    repo.set_hunt_state('h1', 'running')
    repo.set_hunt_state('h1', 'completed_within_scope', detection_result='no_reportable_findings')
    owner = rule('url', 'http://example.test/Keep')
    try:
        owner.consume([net_event('http_tx', 'missing-host', url__original='/Keep')])
        [note] = owner.partition_coverage_notes()
        repo.set_rule_cell('h1', owner.id, owner.version, 'idx', 'window', 'positive_only', 1, 0,
                           {'reasons': [note]})
        assert note in render(publish_revision(repo, 'h1', 'test'))
        login()
        response = client.get('/hunts/h1')
        assert response.status_code == 200 and note in response.text
    finally:
        owner.release_state()


@pytest.mark.parametrize('kind,value,fields,phrase',[('sha256','ab'*32,{'file__sha256':'ab'*32},'response body'),
    ('url','http://example.test/Body',{'url__original':'http://example.test/Body'},'URL')])
def test_packet_body_indicators_are_observations_of_response_bytes(kind,value,fields,phrase):
    owner=rule(kind,value)
    try:
        [match]=run(owner,net_event('http_body',**fields))
        assert phrase in match.claim and 'ran' not in match.claim
    finally:
        owner.release_state()
