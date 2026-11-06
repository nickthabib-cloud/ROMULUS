"""Offline Sigma activation preserves provenance and exact hunt snapshots."""
import json

import pytest
import yaml
from sqlalchemy import select

from romulus.evidence.windows_catalog import SYSMON, SYSMON_CHANNEL
from romulus.store import schema as t
from tests.test_sweep import _repo
from tests.windows_fixtures import LogicalWindowsEvent, windows_hit


def document(**changes):
    return {'title': 'Synthetic image observation', 'id': 'synthetic-1', 'author': 'Local author',
        'status': 'experimental', 'level': 'high', 'tags': ['attack.t1059', 'attack.g0001', 'attack.s0002'],
        'logsource': {'product': 'windows', 'category': 'process_creation'},
        'detection': {'selection': {'Image|endswith': r'\mission.exe'}, 'condition': 'selection'}, **changes}


def fixture(tmp_path, name, image=r'C:\Tools\mission.exe', *, raw=False):
    hit = windows_hit(LogicalWindowsEvent(SYSMON_CHANNEL, SYSMON, 1, 'ws1', 12,
        '2026-01-02T03:04:05Z', {'Image': image, 'ProcessId': '123',
        'ProcessGuid': '{00000000-0000-0000-0000-000000000001}',
        'UtcTime': '2026-01-02T03:04:05Z'}), 'elastic_agent')
    path = tmp_path / name
    path.write_text(json.dumps(hit['_source'] if raw else hit), encoding='utf-8')
    return path


def imported(tmp_path, doc=None):
    from romulus.content.sigma_store import SigmaRules
    repo = _repo()
    root = tmp_path / 'sigma'
    root.mkdir()
    (root / 'rule.yml').write_text(yaml.safe_dump(doc or document()), encoding='utf-8')
    store = SigmaRules(repo)
    report = store.import_directory(root, upstream='Local synthetic corpus', commit='a'*40, actor='analyst')
    return repo, store, report['rules'][0]['id']


def test_import_is_draft_preserves_attribution_and_reimport_does_not_reset_state(tmp_path):
    repo, store, rid = imported(tmp_path)
    try:
        row = store.get(rid)
        assert row['status'] == 'draft' and row['author'] == 'Local author'
        assert row['upstream_path'] == 'rule.yml' and row['upstream_commit'] == 'a'*40
        assert store.pin()['applied'] == []
        positive = fixture(tmp_path, 'positive.json')
        benign = fixture(tmp_path, 'benign.json', r'C:\Windows\benign.exe', raw=True)
        activated = store.activate(rid, positive, benign, actor='lead', role='lead')
        assert activated['status'] == 'active' and activated['lane'] == 'lead'
        report = store.import_directory(tmp_path/'sigma', upstream='Local synthetic corpus', commit='a'*40, actor='analyst')
        assert report['unchanged'] == 1 and store.get(rid)['status'] == 'active'
        assert len(store.list()) == 1
    finally:
        repo.engine.dispose()


def test_activation_rejects_bad_fixtures_nonlead_and_unjustified_high(tmp_path):
    repo, store, rid = imported(tmp_path)
    try:
        positive = fixture(tmp_path, 'positive.json')
        benign = fixture(tmp_path, 'benign.json', r'C:\Tools\benign.exe')
        for role in ('analyst', '', 'admin'):
            with pytest.raises(PermissionError):
                store.activate(rid, positive, benign, actor='person', role=role)
        with pytest.raises(ValueError, match='reason'):
            store.activate(rid, positive, benign, actor='lead', role='lead', lane='high')
        for yes, no in ((benign, positive), (positive, positive), (benign, benign)):
            with pytest.raises(ValueError, match='fixture'):
                store.activate(rid, yes, no, actor='lead', role='lead')
        bad = tmp_path/'bad.json'
        for text in ('{', '[]', '{"event": {"dataset": "unknown"}}', '['*50+'0'+']'*50):
            bad.write_text(text, encoding='utf-8')
            with pytest.raises(ValueError):
                store.activate(rid, positive, bad, actor='lead', role='lead')
        assert store.get(rid)['status'] == 'draft'
    finally:
        repo.engine.dispose()


def test_high_override_audit_and_pin_survive_retirement_and_reactivation(tmp_path):
    from romulus.content.sigma_store import load_pinned
    repo, store, rid = imported(tmp_path)
    try:
        positive = fixture(tmp_path, 'positive.json')
        benign = fixture(tmp_path, 'benign.json', r'C:\Tools\benign.exe')
        store.activate(rid, positive, benign, actor='lead', role='lead', lane='high', reason='Mission-approved predicate')
        pins = store.pin()
        with pytest.raises(PermissionError):
            store.retire(rid, actor='analyst', role='analyst')
        store.retire(rid, actor='lead', role='lead')
        assert store.pin()['applied'] == []
        [old] = load_pinned(repo, pins)
        assert old['lane'] == 'high' and old['activation_reason'] == 'Mission-approved predicate'
        store.activate(rid, positive, benign, actor='lead', role='lead')
        assert load_pinned(repo, pins)[0]['lane'] == 'high'
        with repo.engine.connect() as c:
            audit = c.execute(select(t.audit_event.c.detail).where(
                t.audit_event.c.action == 'sigma.activate').order_by(t.audit_event.c.id)).scalars().first()
        assert audit['lane'] == 'high' and audit['reason'] == 'Mission-approved predicate'
        assert audit['positive']['matched'] and not audit['benign']['matched']
        assert 'mission.exe' not in json.dumps(audit) and 'sha256' in audit['positive']
        with repo.engine.begin() as c:
            c.execute(t.sigma_rule.update().where(t.sigma_rule.c.id == rid).values(ast={}))
        with pytest.raises(ValueError, match='digest'):
            load_pinned(repo, pins)
    finally:
        repo.engine.dispose()


def test_unsupported_rule_is_reference_only_and_attack_drops_are_named(tmp_path):
    doc = document(tags=['attack.t1059', 'attack.t9999', 'attack.t1064', 'attack.g0001', 'attack.s0002'],
        detection={'selection': {'UnmappedField': 'value'}, 'condition': 'selection'})
    repo, store, rid = imported(tmp_path, doc)
    try:
        row = store.get(rid)
        assert row['status'] == 'reference-only'
        assert 'attack.t1059' in row['tags'] and 'attack.g0001' in row['tags']
        assert 'attack.t9999' not in row['tags'] and 'attack.t1064' not in row['tags']
        assert any('UnmappedField' in reason for reason in row['mapping']['reasons'])
        assert {drop['tag'] for drop in row['mapping']['tag_drops']} == {'attack.t9999', 'attack.t1064'}
        with pytest.raises(ValueError, match='reference-only'):
            store.activate(rid, fixture(tmp_path, 'yes.json'), fixture(tmp_path, 'no.json'), actor='lead', role='lead')
    finally:
        repo.engine.dispose()


def test_directory_limits_are_atomic_and_paths_are_local(tmp_path, monkeypatch):
    from romulus.content import sigma_store
    repo, store, rid = imported(tmp_path)
    try:
        assert rid
        with pytest.raises(ValueError):
            store.import_directory('//remote/share', upstream='Local', commit='a'*40, actor='analyst')
        (tmp_path/'sigma'/'other.yml').write_text(yaml.safe_dump(document(id='other')), encoding='utf-8')
        monkeypatch.setattr(sigma_store, 'MAX_RULE_FILES', 1)
        with pytest.raises(ValueError, match='limit'):
            store.import_directory(tmp_path/'sigma', upstream='Another source', commit='b'*40, actor='analyst')
        assert len(store.list()) == 1
    finally:
        repo.engine.dispose()


def test_credential_like_predicate_is_rejected_without_persisting_the_literal(tmp_path):
    doc = document(detection={'selection': {'CommandLine|contains': 'password=private-value'},
                              'condition': 'selection'})
    from romulus.content.sigma_store import SigmaRules
    repo = _repo()
    root = tmp_path/'sigma'
    root.mkdir()
    (root/'rule.yml').write_text(yaml.safe_dump(doc), encoding='utf-8')
    try:
        store = SigmaRules(repo)
        report = store.import_directory(root, upstream='Local', commit='a'*40, actor='analyst')
        assert report['skipped'] == 1 and store.list() == []
        with repo.engine.connect() as c:
            assert 'private-value' not in json.dumps(list(c.execute(select(t.audit_event.c.detail)).scalars()))
    finally:
        repo.engine.dispose()


def test_hostile_fixture_limits_never_activate(tmp_path, monkeypatch):
    from romulus.content import sigma_store
    repo, store, rid = imported(tmp_path)
    try:
        positive = fixture(tmp_path, 'positive.json')
        bad = tmp_path/'bad.json'
        for text in ('{"a":1,"a":2}', '{"value":NaN}', '{"_source":[]}'):
            bad.write_text(text, encoding='utf-8')
            with pytest.raises(ValueError):
                store.activate(rid, positive, bad, actor='lead', role='lead')
        monkeypatch.setattr(sigma_store, 'MAX_FIXTURE_BYTES', 8)
        with pytest.raises(ValueError, match='size limit'):
            store.activate(rid, positive, bad, actor='lead', role='lead')
        assert store.get(rid)['status'] == 'draft'
    finally:
        repo.engine.dispose()


@pytest.mark.parametrize('wrappers', [False, True])
def test_linux_companion_fixture_group_activates_after_joint_real_normalization(tmp_path, wrappers):
    from tests.test_evidence import EXECVE_HEX, SYSCALL, hit
    doc = document(logsource={'product': 'linux', 'category': 'process_creation'},
        detection={'selection': {'Image': '/usr/bin/mission'}, 'condition': 'selection'})
    repo, store, rid = imported(tmp_path, doc)
    try:
        paths = []
        for name, executable in [('positive', '/usr/bin/mission'), ('benign', '/usr/bin/benign')]:
            records = [hit('exec', 'linux.audit', EXECVE_HEX),
                       hit('syscall', 'linux.audit', SYSCALL.replace('/usr/bin/dash', executable))]
            path = tmp_path/f'{name}.json'
            path.write_text(json.dumps(records if wrappers else [row['_source'] for row in records]),
                            encoding='utf-8')
            paths.append(path)
        assert store.activate(rid, *paths, actor='lead', role='lead')['status'] == 'active'
        with repo.engine.connect() as c:
            audit = c.execute(select(t.audit_event.c.detail).where(
                t.audit_event.c.action == 'sigma.activate')).scalar_one()
        assert audit['positive']['records'] == audit['benign']['records'] == 2
        assert audit['positive']['typed_events'] == audit['benign']['typed_events'] == 1
        assert audit['positive']['matched'] and not audit['benign']['matched']
        assert 'sha256' in audit['positive'] and '/usr/bin/mission' not in json.dumps(audit)
    finally:
        repo.engine.dispose()


def test_fixture_groups_reject_duplicate_native_identities_before_normalization(tmp_path):
    repo, store, rid = imported(tmp_path)
    try:
        positive = fixture(tmp_path, 'positive.json')
        same = json.loads(positive.read_text(encoding='utf-8'))
        duplicate = tmp_path/'duplicate.json'
        duplicate.write_text(json.dumps([same, same]), encoding='utf-8')
        with pytest.raises(ValueError, match='identity'):
            store.activate(rid, duplicate, positive, actor='lead', role='lead')
        assert store.get(rid)['status'] == 'draft'
    finally:
        repo.engine.dispose()


def test_fixture_group_count_and_member_types_are_bounded(tmp_path):
    from romulus.content import sigma_store
    repo, store, rid = imported(tmp_path)
    try:
        positive = fixture(tmp_path, 'positive.json')
        group = tmp_path/'group.json'
        group.write_text(json.dumps([{}]*(sigma_store.MAX_FIXTURE_RECORDS+1)), encoding='utf-8')
        with pytest.raises(ValueError, match='limit'):
            store.activate(rid, group, positive, actor='lead', role='lead')
        for values in ([], [None], [{} , 'raw string']):
            group.write_text(json.dumps(values), encoding='utf-8')
            with pytest.raises(ValueError):
                store.activate(rid, group, positive, actor='lead', role='lead')
        assert store.get(rid)['status'] == 'draft'
    finally:
        repo.engine.dispose()


@pytest.mark.parametrize('field,value', [('upstream','https://user:secret@example.test/'),
    ('author','token=private'), ('commit','not a commit'), ('title','bad\x00title')])
def test_unsafe_metadata_does_not_enter_store_or_audit(tmp_path, field, value):
    from romulus.content.sigma_store import SigmaRules
    repo = _repo()
    try:
        root = tmp_path/'sigma'
        root.mkdir()
        doc = document(**{field: value}) if field in {'author','title'} else document()
        (root/'rule.yml').write_text(yaml.safe_dump(doc), encoding='utf-8')
        store = SigmaRules(repo)
        kwargs = {'upstream':'Local','commit':'a'*40,'actor':'analyst'}
        if field in kwargs:
            kwargs[field] = value
            with pytest.raises(ValueError):
                store.import_directory(root, **kwargs)
        else:
            assert store.import_directory(root, **kwargs)['skipped'] == 1
        assert store.list() == []
        with repo.engine.connect() as c:
            assert not any(value in json.dumps(detail) for detail in c.execute(select(t.audit_event.c.detail)).scalars())
    finally:
        repo.engine.dispose()
