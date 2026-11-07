"""Saved import diagnostics remain visible and audit rejection reasons stay specific."""
from sqlalchemy import select

from romulus.content.indicator_lists import IndicatorLists
from romulus.store import schema as t
from tests.test_indicator_interfaces import ui as ui  # noqa: PLC0414 - shared authenticated UI fixture.
from tests.test_indicator_interfaces import upload


def test_import_detail_shows_note_totals_and_attack_replacement(ui):
    client, repo, login = ui
    secret = 'sample zip password: SECRET_SENTINEL'
    result = client.post('/indicators', data={
        'csrf': login(), 'name': 'Partner', 'source': 'Partner',
        'csv_text': 'kind,value,label,attack\ndomain,example.test,' + secret + ',T9999;T0855\n',
    }, follow_redirects=False)
    assert result.status_code == 303
    [item] = IndicatorLists(repo).lists()
    assert item['import_report']['noted_by_reason'] == {
        'label_redacted': 1, 'attack_unknown': 1, 'attack_revoked': 1}
    detail = client.get(result.headers['location'])
    assert detail.status_code == 200
    for reason in ('label_redacted', 'attack_unknown', 'attack_revoked'):
        assert reason + ': 1' in detail.text
    for expected in ('Position 2', 'T9999', 'T0855', 'T1692.001'):
        assert expected in detail.text
    assert secret not in detail.text and 'SECRET_SENTINEL' not in detail.text


def test_web_retired_list_rejection_has_one_named_audit(ui):
    client, repo, login = ui
    assert upload(client, login()).status_code == 303
    [item] = IndicatorLists(repo).lists()
    assert client.post('/indicators/' + item['id'] + '/retire', data={
        'csrf': login('lead')}, follow_redirects=False).status_code == 303
    assert upload(client, login(), list_id=item['id']).status_code == 400
    with repo.engine.connect() as connection:
        audits = connection.execute(select(t.audit_event.c.actor, t.audit_event.c.detail).where(
            t.audit_event.c.action == 'indicator_list.import_rejected')).all()
    assert len(audits) == 1
    assert audits[0].actor == 'a'
    assert audits[0].detail['reason'] == 'retired_list_reactivation_requires_lead'
    assert IndicatorLists(repo).get(item['id'])['status'] == 'retired'
