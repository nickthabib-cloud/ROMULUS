"""Partner imports stay useful, bounded, and isolated from live hunt writes."""
import csv
import io
import json
from datetime import datetime, timedelta

import pytest
from sqlalchemy import select

from romulus.content.indicator_export import export_indicators
from romulus.content.indicator_import import ImportedIndicator, parse_indicator_file
from romulus.content.indicator_lists import IndicatorLists
from romulus.store import schema as t
from tests.test_indicator_lists import NOW, create
from tests.test_indicator_lists import repo as repo  # noqa: PLC0414 - expose the shared pytest fixture.


def parse(tmp_path, payload, suffix='.json'):
    path = tmp_path / ('feed' + suffix)
    path.write_text(payload if isinstance(payload, str) else json.dumps(payload), encoding='utf-8')
    result = parse_indicator_file(path, now=NOW)
    return list(result.rows), result.summary()


@pytest.mark.parametrize(('path', 'kind', 'value'), [
    ('file:hashes.MD5', 'md5', 'a' * 32),
    ("file:'hashes'.'SHA1'", 'sha1', 'a' * 40),
    ('file:hashes.SHA256', 'sha256', 'a' * 64),
    ('ipv4-addr:value', 'cidr', '192.0.2.0/24'),
    ("ipv6-addr:'value'", 'cidr', '2001:db8::/32'),
])
def test_stix_equivalent_hash_paths_and_network_values(tmp_path, path, kind, value):
    rows, report = parse(tmp_path, {'type': 'bundle', 'objects': [{
        'type': 'indicator', 'spec_version': '2.1', 'pattern_type': 'stix',
        'pattern': f"[{path} = '{value}']"}]})
    assert [(r.kind, r.value) for r in rows] == [(kind, value)]
    assert report['accepted'] == 1


def test_misp_composites_and_deleted_values(tmp_path):
    rows, report = parse(tmp_path, {'Attribute': [
        {'type': 'filename|md5', 'value': 'payload.exe|' + 'a' * 32},
        {'type': 'filename|sha1', 'value': '/tmp/payload|' + 'b' * 40},
        {'type': 'filename|sha256', 'value': 'loader.dll|' + 'c' * 64},
        {'type': 'domain|ip', 'value': 'Example.COM|192.0.2.1'},
        {'type': 'ip-dst', 'value': '192.0.3.9/24'},
        {'type': 'domain', 'value': 'deleted.example', 'deleted': True},
    ]})
    assert {(r.kind, r.value) for r in rows} == {
        ('md5', 'a' * 32), ('sha1', 'b' * 40), ('sha256', 'c' * 64),
        ('domain', 'example.com'), ('ip', '192.0.2.1'), ('cidr', '192.0.3.0/24')}
    assert report['skipped_by_reason'] == {'deleted': 1}
    assert report['noted_by_reason'] == {'filename_not_imported': 3}


@pytest.mark.parametrize('address', ['not-an-address', '999.2.3.4', '192.0.2.1/99'])
def test_misp_domain_survives_an_invalid_composite_address(tmp_path, address):
    rows, report = parse(tmp_path, {'Attribute': [
        {'type': 'domain|ip', 'value': 'Example.COM|' + address}]})
    assert [(r.kind, r.value) for r in rows] == [('domain', 'example.com')]
    assert report['counts_by_kind'] == {'domain': 1}
    assert report['skipped_by_reason'] == {'invalid_value': 1}


@pytest.mark.parametrize('deleted', [True, 1, '1'])
def test_misp_deleted_flags_exclude_the_attribute(tmp_path, deleted):
    rows, report = parse(tmp_path, {'Attribute': [
        {'type': 'domain', 'value': 'deleted.example', 'deleted': deleted}]})
    assert rows == []
    assert report['skipped_by_reason'] == {'deleted': 1}


def test_misp_filename_hash_does_not_flag_a_genuine_executable(repo, tmp_path):
    from romulus.detect.indicators import IndicatorMatch, IndicatorSet
    from romulus.evidence.typed import fv
    from tests.test_indicators import exec_event

    rows, report = parse(tmp_path, {'Attribute': [
        {'type': 'filename|sha256', 'value': 'svchost.exe|' + 'c' * 64}]})
    store = IndicatorLists(repo)
    create(repo, rows, report=report, lane='high', severity='critical', role='lead',
           reason='Confirmed sample hash')
    owner = IndicatorMatch(IndicatorSet())
    owner.bind_indicators(repo, store.pin(NOW))
    genuine = exec_event([r'C:\Windows\System32\svchost.exe', '-k', 'netsvcs'],
                         r'C:\Windows\System32\svchost.exe', 'genuine')
    genuine.fields['process.hash.sha256'] = fv('d' * 64, 'fixture:hash')
    malicious = exec_event([r'C:\Temp\renamed.exe'], r'C:\Temp\renamed.exe', 'malicious')
    malicious.fields['process.hash.sha256'] = fv('c' * 64, 'fixture:hash')
    try:
        owner.consume([genuine, malicious])
        matches = list(owner.finalize())
        assert len(matches) == 1
        assert matches[0].proposed_lane == 'high'
        assert [event.id for event in matches[0].events] == ['malicious']
    finally:
        owner.release_state()


@pytest.mark.parametrize('format', ['csv', 'misp', 'stix'])
def test_sensitive_label_is_redacted_without_losing_value(tmp_path, format):
    label = 'sample zip password: infected'
    if format == 'csv':
        payload, suffix = 'kind,value,label\nsha256,' + 'a' * 64 + ',' + label + '\n', '.csv'
    elif format == 'misp':
        payload, suffix = {'Attribute': [{'type': 'sha256', 'value': 'a' * 64, 'comment': label}]}, '.json'
    else:
        payload, suffix = {'type': 'bundle', 'objects': [{
            'type': 'indicator', 'spec_version': '2.1', 'pattern_type': 'stix',
            'pattern': "[file:hashes.SHA256 = '" + 'a' * 64 + "']", 'name': label}]}, '.json'
    rows, report = parse(tmp_path, payload, suffix)
    assert [(r.kind, r.value, r.label) for r in rows] == [('sha256', 'a' * 64, '')]
    assert report['accepted'] == 1
    assert report['noted_by_reason'] == {'label_redacted': 1}
    assert label not in json.dumps(report)


def test_expiry_rejections_are_per_object(tmp_path):
    def obj(domain, expiry):
        return {'type': 'indicator', 'spec_version': '2.1', 'pattern_type': 'stix',
                'pattern': f"[domain-name:value = '{domain}']", 'valid_until': expiry}
    rows, report = parse(tmp_path, {'type': 'bundle', 'objects': [
        obj('good.example', '2027-01-01T00:00:00Z'),
        obj('overflow.example', '9999-12-31T23:00:00-12:00'),
        obj('expired.example', '2025-01-01T00:00:00Z')]})
    assert [r.value for r in rows] == ['good.example']
    assert report['skipped_by_reason'] == {'invalid_expiry': 1, 'expired_at_import': 1}


def test_attack_tags_drop_unknown_and_revoked_with_replacement(tmp_path):
    rows, report = parse(tmp_path, 'kind,value,attack\nip,192.0.2.1,T1059;T9999;T0855\n', '.csv')
    assert rows[0].attack == ('T1059',)
    assert report['noted_by_reason'] == {'attack_unknown': 1, 'attack_revoked': 1}
    assert any(n.get('replacement') == 'T1692.001' for n in report['notes'])


@pytest.mark.parametrize('prefix', ['=', '+', '-', '@'])
def test_csv_formula_cells_roundtrip_with_lane_and_severity(repo, tmp_path, prefix):
    store = IndicatorLists(repo)
    meta = create(repo, [ImportedIndicator('program_name', prefix + 'payload.exe', prefix + 'label')],
                  lane='context', severity='low')
    text = ''.join(export_indicators(store, meta['id'], format='csv'))
    [exported] = list(csv.DictReader(io.StringIO(text)))
    assert exported['value'] == "'" + prefix + 'payload.exe'
    assert exported['label'] == "'" + prefix + 'label'
    rows, _ = parse(tmp_path, text, '.csv')
    assert (rows[0].value, rows[0].label, rows[0].lane, rows[0].severity) == (
        prefix + 'payload.exe', prefix + 'label', 'context', 'low')


def test_csv_unquotes_exactly_one_formula_guard(tmp_path):
    rows, _ = parse(tmp_path, "kind,value,label\nprogram_name,'=x.exe,''=label\n", '.csv')
    assert rows[0].value == '=x.exe'
    assert rows[0].label == "''=label"


def test_import_commits_batches_and_hides_staging_from_readers(repo):
    store = IndicatorLists(repo)
    previous = create(repo)
    def rows():
        for i in range(1000):
            yield ImportedIndicator('sha256', f'{i:064x}')
        # This barrier runs after a complete batch, before the next row exists.
        with repo.engine.begin() as c:
            c.exec_driver_sql('PRAGMA busy_timeout=0')
            c.execute(t.audit_event.insert().values(at=NOW, actor='hunt', action='heartbeat', detail={}))
        assert store.pin(now=NOW)['applied'][0]['version'] == 1
        assert store.lists()[0]['version'] == 1
        assert store.get(previous['id'])['version'] == 1
        assert store.get(previous['id'], 2) is None
        assert list(store.values(previous['id'], 2)) == []
        with pytest.raises(ValueError, match='import'):
            create(repo, list_id=previous['id'])
        # Another list may import without reclaiming this live version.
        create(repo)
        yield ImportedIndicator('ip', '192.0.2.2')
    result = create(repo, rows(), list_id=previous['id'])
    assert result['value_count'] == 1001
    assert result['version'] == 2


def test_failed_staging_is_removed_and_rejection_audited(repo):
    store = IndicatorLists(repo)
    def rows():
        for i in range(1001):
            yield ImportedIndicator('sha256', f'{i:064x}')
        raise RuntimeError('source failed')
    with pytest.raises(RuntimeError, match='source failed') as caught:
        create(repo, rows())
    assert caught.value.audit_recorded is True
    assert store.lists() == []
    with repo.engine.connect() as c:
        assert c.execute(select(t.indicator_value)).first() is None
        assert c.execute(select(t.indicator_list)).first() is None
        assert c.execute(select(t.audit_event.c.action)).all() == [('indicator_list.import_rejected',)]


@pytest.mark.parametrize('lane', ['urgent', 'invented'])
def test_service_refuses_unbounded_lanes(repo, lane):
    with pytest.raises(ValueError, match='lane'):
        create(repo, [ImportedIndicator('ip', '192.0.2.1', lane=lane)])


def test_high_requires_lead_reason_and_audit(repo):
    with pytest.raises(PermissionError):
        create(repo, lane='high', reason='confirmed payload')
    with pytest.raises(ValueError, match='reason'):
        create(repo, lane='high', role='lead')
    meta = create(repo, lane='high', severity='high', role='lead', reason='confirmed payload')
    assert (meta['lane'], meta['severity']) == ('high', 'high')
    with repo.engine.connect() as c:
        detail = c.execute(select(t.audit_event.c.detail).where(
            t.audit_event.c.action == 'indicator_list.import')).scalar()
    assert detail['reason'] == 'confirmed payload' and detail['role'] == 'lead'


def test_retired_list_reactivation_requires_lead_and_is_audited(repo):
    store = IndicatorLists(repo)
    meta = create(repo)
    store.retire(meta['id'], actor='lead', role='lead')
    with pytest.raises(PermissionError) as caught:
        create(repo, list_id=meta['id'])
    assert getattr(caught.value, 'audit_recorded', False)
    with repo.engine.connect() as c:
        rejection = c.execute(select(t.audit_event.c.actor, t.audit_event.c.detail).where(
            t.audit_event.c.action == 'indicator_list.import_rejected')).one()
    assert rejection.actor == 'analyst'
    assert rejection.detail['id'] == meta['id']
    assert rejection.detail['reason'] == 'retired_list_reactivation_requires_lead'
    assert store.get(meta['id'])['status'] == 'retired'
    revived = create(repo, list_id=meta['id'], role='lead')
    assert revived['version'] == 2
    with repo.engine.connect() as c:
        detail = c.execute(select(t.audit_event.c.detail).where(
            t.audit_event.c.action == 'indicator_list.import',
            t.audit_event.c.detail['version'].as_integer() == 2)).scalar()
    assert detail['reactivated_retired'] is True


def test_retirement_during_import_has_one_specific_rejection_and_removes_staging(repo):
    store = IndicatorLists(repo)
    meta = create(repo)
    def rows():
        yield ImportedIndicator('sha256', 'a' * 64)
        store.retire(meta['id'], actor='lead', role='lead')
    with pytest.raises(PermissionError) as caught:
        create(repo, rows(), list_id=meta['id'])
    assert getattr(caught.value, 'audit_recorded', False)
    with repo.engine.connect() as c:
        details = c.execute(select(t.audit_event.c.detail).where(
            t.audit_event.c.action == 'indicator_list.import_rejected')).scalars().all()
        assert c.execute(select(t.indicator_value).where(
            t.indicator_value.c.list_version == 2)).first() is None
        assert c.execute(select(t.indicator_list).where(
            t.indicator_list.c.version == 2)).first() is None
    assert len(details) == 1
    assert details[0]['reason'] == 'retired_list_reactivation_requires_lead'
    assert store.get(meta['id'])['status'] == 'retired'


def test_service_converts_out_of_range_expiry_to_validation_error(repo):
    with pytest.raises(ValueError, match='time|Expiry'):
        create(repo, expires_at=datetime.fromisoformat('9999-12-31T23:00:00-12:00'))


def _paused_import(database, channel, list_id):
    import os

    from romulus.store.db import make_engine
    from romulus.store.repo import Repo
    engine = make_engine(database)
    try:
        def rows():
            for i in range(1000):
                yield ImportedIndicator('sha256', f'{i:064x}')
            channel.send('batch_committed')
            if channel.recv() == 'crash':
                os._exit(23)
            yield ImportedIndicator('ip', '192.0.2.9')
        create(Repo(engine), rows(), list_id=list_id)
    finally:
        engine.dispose()


def test_live_process_lease_protects_staging_and_crash_releases_it(repo):
    import queue
    import subprocess
    import sys
    import threading
    from pathlib import Path
    store = IndicatorLists(repo)
    previous = create(repo)
    script = """
import sys
from types import SimpleNamespace
sys.path[:0] = [sys.argv[1], sys.argv[1] + '/src']
from tests.test_indicator_ingestion_safety import _paused_import
channel = SimpleNamespace(send=lambda value: print(value, flush=True), recv=input)
_paused_import(sys.argv[2], channel, sys.argv[3])
"""
    process = subprocess.Popen([sys.executable, '-X', 'utf8', '-I', '-c', script,
        str(Path(__file__).resolve().parents[1]), repo.engine.url.database, previous['id']],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    output = queue.Queue()
    threading.Thread(target=lambda: output.put(process.stdout.readline()), daemon=True).start()
    try:
        assert output.get(timeout=30).strip() == 'batch_committed'
        with repo.engine.begin() as c:
            c.exec_driver_sql('PRAGMA busy_timeout=0')
            c.execute(t.audit_event.insert().values(at=NOW, actor='hunt', action='heartbeat', detail={}))
        create(repo)
        store.cleanup_imports()
        with repo.engine.connect() as c:
            assert c.execute(select(t.indicator_list.c.status).where(
                t.indicator_list.c.id == previous['id'], t.indicator_list.c.version == 2)).scalar() == 'importing'
            assert c.execute(select(t.indicator_value.c.id).where(
                t.indicator_value.c.list_version == 2)).first() is not None
        with pytest.raises(ValueError, match='import'):
            create(repo, list_id=previous['id'])
        assert store.pin(now=NOW)['applied'][0]['version'] == 1
    finally:
        # Ask the actual interpreter to exit without cleanup; Windows venv launchers may be a parent process.
        if process.poll() is None:
            process.stdin.write('crash\n')
            process.stdin.flush()
        process.wait(timeout=30)
        process.stdin.close()
        process.stdout.close()
        process.stderr.close()
    store.cleanup_imports()
    assert store.get(previous['id'])['version'] == 1
    with repo.engine.connect() as c:
        assert c.execute(select(t.indicator_value.c.id).where(t.indicator_value.c.list_version == 2)).first() is None
    recreated = create(repo, list_id=previous['id'])
    assert recreated['version'] == 2


def test_cleanup_does_not_delete_version_completed_before_lease_acquisition(repo, monkeypatch):
    from contextlib import contextmanager

    from romulus.content import indicator_lists
    meta = create(repo)
    with repo.engine.begin() as c:
        c.execute(t.indicator_list.update().where(t.indicator_list.c.id == meta['id']).values(status='importing'))
    lease = indicator_lists._import_lease
    @contextmanager
    def completed(engine, list_id):
        with engine.begin() as c:
            c.execute(t.indicator_list.update().where(t.indicator_list.c.id == list_id).values(status='active'))
        with lease(engine, list_id) as acquired:
            yield acquired
    monkeypatch.setattr(indicator_lists, '_import_lease', completed)
    IndicatorLists(repo).cleanup_imports()
    assert IndicatorLists(repo).get(meta['id'])['value_count'] == 1


@pytest.mark.parametrize('prefix', ['\t', '\r'])
def test_csv_neutralizes_control_prefixes_in_legacy_cells(repo, prefix):
    store = IndicatorLists(repo)
    meta = create(repo)
    with repo.engine.begin() as c:
        c.execute(t.indicator_value.update().values(label=prefix + 'legacy formula'))
    [exported] = list(csv.DictReader(io.StringIO(''.join(
        export_indicators(store, meta['id'], format='csv')))))
    assert exported['label'] == "'" + prefix + 'legacy formula'


def test_pin_names_expired_values_and_preserves_previous_pin(repo):
    from romulus.content.indicator_lists import PinnedIndicators
    store = IndicatorLists(repo)
    meta = create(repo, [ImportedIndicator('ip', '192.0.2.1', expires_at=NOW + timedelta(days=1)),
                         ImportedIndicator('ip', '192.0.2.2')])
    original = store.pin(now=NOW)
    later = store.pin(now=NOW + timedelta(days=1))
    assert original['applied'][0]['excluded_expired_values'] == 0
    assert later['applied'][0]['excluded_expired_values'] == 1
    assert later['applied'][0]['version'] == meta['version']
    assert list(PinnedIndicators(repo, later).find('ip', '192.0.2.1')) == []
    assert len(list(PinnedIndicators(repo, original).find('ip', '192.0.2.1'))) == 1


def test_direct_service_redacts_labels_and_validates_attack_without_losing_value(repo):
    meta = create(repo, [ImportedIndicator('ip', '192.0.2.1', 'zip password: infected', ('T1059', 'T9999'))])
    [value] = list(IndicatorLists(repo).values(meta['id']))
    assert (value['value'], value['label'], value['attack']) == ('192.0.2.1', '', ['T1059'])
    assert meta['import_report']['noted_by_reason'] == {'label_redacted': 1, 'attack_unknown': 1}


def test_row_high_requires_lead_reason_and_failure_removes_prior_batches(repo):
    def rows():
        for i in range(1000):
            yield ImportedIndicator('sha256', f'{i:064x}')
        yield ImportedIndicator('ip', '192.0.2.1', lane='high')
    with pytest.raises(PermissionError) as caught:
        create(repo, rows())
    assert caught.value.audit_recorded is True
    assert IndicatorLists(repo).lists() == []
    with repo.engine.connect() as c:
        assert c.execute(select(t.indicator_value)).first() is None
