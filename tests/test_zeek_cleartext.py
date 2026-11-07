"""Cleartext credentials are hygiene observations with exact connection counts and no secret values."""
import importlib
import json
from dataclasses import asdict, replace
from xml.etree import ElementTree
from zipfile import ZipFile

import pytest

from romulus.detect.netdef import SiteNetworks, install
from romulus.evidence.typed import fv
from tests.fixtures import zeek_logs as zl
from tests.test_zeek_windows_protocols import every_shape, normalize


def detector():
    return importlib.import_module('romulus.detect.zeek_cleartext').CleartextCredentials()


def run(events):
    owner = detector()
    found = {}
    try:
        for event in events:
            for match in owner.consume([event]):
                found[match.group_key] = match
        for match in owner.finalize():
            found[match.group_key] = match
        return list(found.values())
    finally:
        owner.release_state()


@pytest.mark.parametrize('shape', ('malcolm', 'elastic', 'security_onion', 'plain'))
@pytest.mark.parametrize('row', [zl.HTTP.with_(username='alice'), zl.FTP.with_(command='PASS', arg=zl.SECRET),
                                zl.SOCKS.with_(user='alice', password=zl.SECRET),
                                zl.SNMP.with_(community=zl.SECRET)])
def test_all_carried_shapes_use_only_normalized_credential_presence(shape, row):
    event = every_shape(row)[shape]
    [match] = run([event])
    assert match.proposed_lane == 'lead'
    assert '1 connection' in match.claim
    assert zl.SECRET not in json.dumps(asdict(match), default=str)
    assert match.attack == ('T1078', 'T1040')
    assert any('direction assumed' in note for note in match.notes)


def test_every_existing_normalizer_presence_flag_is_consumed_without_protocol_allowlist():
    normalized = [normalize(hit) for _name, hit in zl.secret_rows()]
    events = [event for event in normalized
              if event.get('auth.cleartext_credentials_present') is True
              and all(event.get(name) for name in ('source.ip', 'destination.ip', 'zeek.uid'))]
    assert {'http', 'ftp', 'ldap', 'socks', 'snmp', 'mysql', 'postgresql', 'redis', 'irc'} <= {
        event.get('zeek.log') for event in events}
    assert len(run(events)) == len({(event.get('source.ip'), event.get('destination.ip'),
                                    event.get('zeek.log')) for event in events})


def test_distinct_uid_sensor_connections_not_duplicate_rows():
    one = every_shape(zl.FTP.with_(command='PASS', arg=zl.SECRET))['plain']
    duplicate = one.model_copy(update={'id': 'another-row', 'ts': one.ts})
    another = replace(zl.FTP.with_(uid='Canother', command='PASS', arg=zl.SECRET), ts=zl.T0+5)
    other_sensor = one.model_copy(deep=True)
    other_sensor.id = 'other-sensor'
    other_sensor.fields['observer.name'] = fv('sensor-two', 'test:sensor')
    [match] = run([one, duplicate, every_shape(another)['plain'], other_sensor, one])
    assert '3 connections' in match.claim and len(match.events) <= 2


@pytest.mark.parametrize('client,server,lane', [('10.0.0.5', '10.0.0.9', 'context'),
                                              ('203.0.113.1', '10.0.0.9', 'lead'),
                                              ('10.0.0.5', '203.0.113.1', 'lead')])
def test_internal_hygiene_and_both_boundary_directions(client, server, lane):
    row = zl.HTTP.with_(username='alice', **{'id.orig_h': client, 'id.resp_h': server})
    [match] = run([every_shape(row)['plain']])
    assert match.proposed_lane == lane and 'alice' in match.claim
    assert 'hygiene' in ' '.join(match.notes).lower()


def test_configured_networks_do_not_carry_assumed_direction_note():
    install(SiteNetworks.from_lists(['10.0.0.0/8']))
    [match] = run([every_shape(zl.HTTP.with_(username='alice'))['plain']])
    assert match.proposed_lane == 'lead'
    assert not any('direction assumed' in note for note in match.notes)


@pytest.mark.parametrize('flag', [False, None, 'true', 1])
def test_only_a_typed_true_boolean_is_evidence(flag):
    event = every_shape(zl.HTTP)['plain']
    event.fields['auth.cleartext_credentials_present'] = fv(flag, 'test:flag')
    assert run([event]) == []


@pytest.mark.parametrize('field', ['zeek.uid', 'observer.name', 'source.ip', 'destination.ip'])
def test_missing_connection_or_endpoints_is_unresolved(field):
    event = every_shape(zl.HTTP.with_(username='alice'))['plain']
    event.fields.pop(field)
    owner = detector()
    try:
        assert list(owner.consume([event])) == []
        assert owner.missing_required == 1
    finally:
        owner.release_state()


def test_report_and_finding_never_contain_the_credential(tmp_path):
    from romulus.hunt.publish import publish_match
    from romulus.report.bundle import write_reports
    from romulus.report.manifest import publish_revision
    from tests.test_report import _repo_with_finding

    native = zl.plain(zl.FTP.with_(command='PASS', arg=zl.SECRET, password=zl.SECRET))
    event = normalize(native)
    [match] = run([event])
    assert zl.SECRET not in event.model_dump_json()
    assert zl.SECRET not in json.dumps(asdict(match), default=str)
    repo, _ = _repo_with_finding()
    rule = detector()
    try:
        sources = {native['_index'] + '/' + native['_id']: native['_source']}
        published = publish_match(repo, 'h1', rule, match, None, sources)
        assert published and zl.SECRET not in json.dumps(published, default=str)
        manifest = publish_revision(repo, 'h1', 'test')
        assert zl.SECRET not in json.dumps(manifest, default=str)
        paths = write_reports(repo, manifest, tmp_path)
        with ZipFile(paths['docx']) as archive:
            doc = ElementTree.fromstring(archive.read('word/document.xml'))
        assert match.claim in paths['md'].read_text(encoding='utf-8')
        assert zl.SECRET not in paths['md'].read_text(encoding='utf-8')
        assert zl.SECRET not in ' '.join(doc.itertext())
    finally:
        rule.release_state()


def test_disk_refusal_is_named(monkeypatch):
    owner = detector()
    try:
        owner.rows.store()
        monkeypatch.setattr(owner.rows, 'room', lambda: False)
        assert list(owner.consume([every_shape(zl.HTTP.with_(username='alice'))['plain']])) == []
        assert owner.capped and 'disk' in ' '.join(owner.limit_reasons()).lower()
    finally:
        owner.release_state()


def test_internal_context_is_published_once_at_finalize():
    owner = detector()
    one = zl.HTTP.with_(username='alice', **{'id.resp_h': '10.0.0.9'})
    two = one.with_(uid='Csecond')
    try:
        assert not list(owner.consume([every_shape(one)['plain'], every_shape(two)['plain']]))
        [match] = list(owner.finalize())
        assert match.proposed_lane == 'context' and '2 connections' in match.claim
        assert not match.revision_reason
    finally:
        owner.release_state()


def test_real_physical_disk_budget_refusal_is_partial(tmp_path):
    from romulus.detect.bounded import StateBudget
    owner = detector()
    owner.spill_dir = tmp_path
    owner.budget = StateBudget(tmp_path, disk_total=1, reserve=0, reserve_floor=0)
    try:
        assert not list(owner.consume([every_shape(zl.HTTP.with_(username='alice'))['plain']]))
        assert owner.limit_reasons()
    finally:
        owner.release_state()


def test_many_distinct_connections_use_disk_facts_and_two_witnesses():
    owner = detector()
    latest = None
    try:
        for i in range(700):
            row = replace(zl.HTTP.with_(uid=f'Cvolume{i}', username='alice'), ts=zl.T0+i)
            [latest] = list(owner.consume([every_shape(row)['plain']]))
            assert len(latest.events) <= 2
        assert '700 connections' in latest.claim
        assert owner.rows.store().execute('SELECT COUNT(*) FROM clear_connections').fetchone()[0] == 700
        assert owner.rows.store().execute('SELECT COUNT(*) FROM clear_groups').fetchone()[0] == 1
        assert not getattr(owner, 'groups', {})
    finally:
        owner.release_state()
