"""Detection requests are attributed, audited references independent of hunt decisions."""
import secrets

import pytest

from romulus.catalog.requests import DetectionRequests, validate_attack
from romulus.store import schema as t
from romulus.web.auth import create_user
from tests.test_report import _repo_with_finding


@pytest.fixture()
def requests_repo():
    repo, cid = _repo_with_finding()
    for name, role in [('analyst', 'analyst'), ('other', 'analyst'), ('lead', 'lead')]:
        create_user(repo.engine, name, secrets.token_urlsafe(20), role)
    return repo, DetectionRequests(repo), cid


def test_create_edit_permissions_and_references_only(requests_repo):
    _, store, cid = requests_repo
    row = store.create(actor='analyst', behavior='<script>flag this</script>', family='process_exec',
                       attack_ids=['T1059'], candidate_id=cid, event_id='ev1')
    assert row['requester'] == 'analyst' and row['status'] == 'requested'
    assert row['example_candidate_id'] == cid and row['example_event_id'] == 'ev1'
    assert not {'record', 'source', 'event', 'raw'} & set(row)
    assert store.edit(row['id'], actor='analyst', behavior='edited')['behavior'] == 'edited'
    with pytest.raises(PermissionError):
        store.edit(row['id'], actor='other', behavior='steal')
    store.change_status(row['id'], actor='lead', status='accepted')
    with pytest.raises(PermissionError):
        store.edit(row['id'], actor='analyst', behavior='too late')


def test_status_requires_lead_rule_or_decline_reason_and_is_audited(requests_repo):
    repo, store, _ = requests_repo
    row = store.create(actor='analyst', behavior='behavior', family='unknown')
    with pytest.raises(PermissionError):
        store.change_status(row['id'], actor='analyst', status='accepted')
    for status, arguments in [('declined', {}), ('active', {}), ('active', {'rule_id': 'invented'})]:
        with pytest.raises(ValueError):
            store.change_status(row['id'], actor='lead', status=status, **arguments)
    store.change_status(row['id'], actor='lead', status='in_progress', reason='researching')
    store.change_status(row['id'], actor='lead', status='active', rule_id='host.credential_store_read')
    events, after = store.history(row['id'])
    assert after is None
    assert [(event['old_status'], event['new_status']) for event in events] == [
        (None, 'requested'), ('requested', 'in_progress'), ('in_progress', 'active')]
    assert events[-1]['actor'] == 'lead' and events[-1]['rule_id'] == 'host.credential_store_read'
    with repo.engine.begin() as c, pytest.raises(Exception, match='append-only'):
        c.execute(t.detection_request_event.update().values(reason='rewrite'))
    with repo.engine.begin() as c, pytest.raises(Exception, match='append-only'):
        c.execute(t.detection_request_event.delete())


def test_request_attack_validation_enterprise_ics_unknown_and_revoked():
    from romulus.catalog.attack import ICS_ATTACK_BUNDLE, ICS_PINNED_JSON_SHA256, load_attack_bundle
    assert validate_attack(['T1059', 'T0815']) == ['T0815', 'T1059']
    with pytest.raises(ValueError, match='Unknown'):
        validate_attack(['T999999'])
    for knowledge in (load_attack_bundle(), load_attack_bundle(
            ICS_ATTACK_BUNDLE, expected_sha256=ICS_PINNED_JSON_SHA256)):
        revoked = next(item for item in knowledge.techniques if item.revoked)
        with pytest.raises(ValueError, match='revoked') as error:
            validate_attack([revoked.id])
        assert (knowledge.replacement(revoked.id) or 'not recorded') in str(error.value)


@pytest.mark.parametrize('arguments', [
    {'behavior': ''}, {'behavior': 'x' * 4001}, {'family': 'invented'},
    {'candidate_id': 'invented'}, {'event_id': 'ev1'},
])
def test_invalid_request_fields_are_refused(requests_repo, arguments):
    _, store, _ = requests_repo
    with pytest.raises(ValueError):
        store.create(**({'actor': 'analyst', 'behavior': 'a behavior', 'family': 'unknown'} | arguments))


def test_example_event_must_be_cited_by_the_selected_finding(requests_repo):
    _, store, cid = requests_repo
    with pytest.raises(ValueError, match='cited'):
        store.create(actor='analyst', behavior='behavior', family='process_exec',
                     candidate_id=cid, event_id='not-cited')


def test_prefill_from_real_finding_and_hunt_independence(requests_repo):
    from romulus.report.manifest import canonical_manifest
    repo, store, cid = requests_repo
    before = canonical_manifest(repo, 'h1', 'test')
    candidate_before = repo.candidate(cid)
    draft = store.prefill(cid, 'ev1')
    assert draft['family'] == 'process_exec' and draft['candidate_id'] == cid
    assert draft['event_id'] == 'ev1' and draft['behavior'] == candidate_before['claim']
    assert draft['attack_ids']
    store.create(actor='analyst', **{key: draft[key] for key in (
        'behavior', 'family', 'attack_ids', 'candidate_id', 'event_id')})
    assert repo.candidate(cid) == candidate_before
    assert canonical_manifest(repo, 'h1', 'test') == before


def test_requests_paginate_filter_and_exports_guard_formulas(requests_repo):
    import csv
    import io

    import yaml
    _, store, _ = requests_repo
    for n in range(53):
        store.create(actor='analyst', behavior=f'=formula{n}', family='unknown')
    page, after = store.list(requester='analyst')
    assert len(page) == 50 and after is not None
    more, _ = store.list(requester='analyst', after=after)
    assert len(more) == 3 and {row['id'] for row in page}.isdisjoint(row['id'] for row in more)
    assert not store.list(status='declined')[0]
    csv_rows = list(csv.DictReader(io.StringIO(''.join(store.export('csv', {})))))
    assert len(csv_rows) == 53 and all(row['behavior'].startswith("'=") for row in csv_rows)
    exported = yaml.safe_load(''.join(store.export('yaml', {})))
    assert len(exported['requests']) == 53 and exported['requests'][0]['behavior'].startswith('=')


def test_disabled_and_demoted_accounts_lose_write_rights(requests_repo):
    repo, store, _ = requests_repo
    row = store.create(actor='analyst', behavior='behavior', family='unknown')
    with repo.engine.begin() as c:
        c.execute(t.user.update().where(t.user.c.username == 'lead').values(role='analyst'))
    with pytest.raises(PermissionError):
        store.change_status(row['id'], actor='lead', status='accepted')
    with repo.engine.begin() as c:
        c.execute(t.user.update().where(t.user.c.username == 'analyst').values(disabled=True))
    with pytest.raises(PermissionError):
        store.edit(row['id'], actor='analyst', behavior='changed')


def test_database_requires_rule_and_decline_reason(requests_repo):
    repo, store, _ = requests_repo
    row = store.create(actor='analyst', behavior='behavior', family='unknown')
    for status in ('active', 'declined'):
        with pytest.raises(Exception, match='CHECK constraint'), repo.engine.begin() as c:
            c.execute(t.detection_request.update().where(t.detection_request.c.id == row['id']).values(status=status))
    with pytest.raises(Exception, match='CHECK constraint'), repo.engine.begin() as c:
        c.execute(t.detection_request.update().where(t.detection_request.c.id == row['id']).values(
            telemetry_family='invented'))


def test_request_references_survive_source_hunt_deletion(requests_repo):
    repo, store, cid = requests_repo
    row = store.create(actor='analyst', behavior='behavior', family='process_exec',
                       candidate_id=cid, event_id='ev1')
    repo.delete_hunt('h1', 'lead')
    assert store.get(row['id'])['example_candidate_id'] == cid
    assert store.get(row['id'])['example_event_id'] == 'ev1'
    assert repo.candidate(cid) is None


def test_active_sigma_rule_required_for_status_link(tmp_path):
    from tests.test_sigma_store import imported
    repo, _, sigma_id = imported(tmp_path)
    create_user(repo.engine, 'lead', secrets.token_urlsafe(20), 'lead')
    store = DetectionRequests(repo)
    row = store.create(actor='lead', behavior='behavior', family='unknown')
    with pytest.raises(ValueError, match='active Sigma'):
        store.change_status(row['id'], actor='lead', status='active', rule_id='sigma.' + sigma_id)
    with repo.engine.begin() as c:
        c.execute(t.sigma_rule.update().where(t.sigma_rule.c.id == sigma_id).values(status='active'))
    updated = store.change_status(row['id'], actor='lead', status='active', rule_id='sigma.' + sigma_id)
    assert updated['rule_id'] == 'sigma.' + sigma_id
