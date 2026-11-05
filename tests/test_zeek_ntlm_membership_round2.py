"""An unrelated successful account cannot strengthen a password spray to HIGH."""
from dataclasses import replace

import pytest

from romulus.detect.zeek_rates import NtlmPasswordSpray
from tests.fixtures import zeek_logs as zl
from tests.test_zeek_rate_rules import evaluate, rows_for
from tests.test_zeek_windows_protocols import normalize
from tests.windows_process_support import run


@pytest.mark.parametrize('shape', tuple(zl.WRITERS))
@pytest.mark.parametrize('reverse', [False, True])
@pytest.mark.parametrize('account,expected', [('user0','high'),('unrelated','lead'),('','lead')])
def test_success_requires_a_sprayed_account_and_names_it(shape, reverse, account, expected):
    rows=rows_for('NtlmPasswordSpray',10)
    rows.append(replace(zl.NTLM.with_(uid='CmembershipSuccess',username=account,success=True),ts=zl.T0+11))
    [match]=evaluate('NtlmPasswordSpray',rows,shape,reverse=reverse)
    lane,claim,notes=match
    assert lane==expected
    if expected=='high':
        assert 'user0' in claim.casefold()
    else:
        assert 'later recorded authentication success for' not in claim.casefold()
        assert any('success' in note.casefold() and ('unrelated' in note.casefold() or 'not among' in note.casefold()) for note in notes)


@pytest.mark.parametrize('shape', tuple(zl.WRITERS))
def test_success_for_expired_account_does_not_strengthen_a_later_spray(shape):
    rows=[replace(zl.NTLM.with_(uid='ColdAttempt',username='olduser',success=False),ts=zl.T0)]
    rows += [replace(row,ts=row.ts+700) for row in rows_for('NtlmPasswordSpray',10)]
    rows.append(replace(zl.NTLM.with_(uid='ColdSuccess',username='olduser',success=True),ts=zl.T0+711))
    [match]=evaluate('NtlmPasswordSpray',rows,shape)
    assert match[0]=='lead'


@pytest.mark.parametrize('shape', tuple(zl.WRITERS))
def test_matching_account_in_a_different_domain_is_unrelated(shape):
    rows=rows_for('NtlmPasswordSpray',10)
    rows.append(replace(zl.NTLM.with_(uid='CdomainSuccess',username='user0',domainname='OTHER',success=True),ts=zl.T0+11))
    [match]=evaluate('NtlmPasswordSpray',rows,shape)
    assert match[0]=='lead'


@pytest.mark.parametrize('shape', tuple(zl.WRITERS))
def test_matching_success_keeps_native_typed_account_and_outcome_in_citations(shape):
    events=[normalize(zl.WRITERS[shape](row,f'proof-{n}'))
            for n,row in enumerate(rows_for('NtlmPasswordSpray',10,success=True))]
    rule=NtlmPasswordSpray()
    try:
        [match]=run(rule,[[event] for event in reversed(events)])
        [success]=[event for event in match.events if event.get('ntlm.success') is True]
        assert success.get('ntlm.username')=='user0' and success.raw
        original=next(event for event in events if event.id==success.id)
        assert success.fields['ntlm.success']==original.fields['ntlm.success']
        assert success.fields['ntlm.username']==original.fields['ntlm.username']
        assert {'ntlm.success','ntlm.username'}<={p.field for p in match.predicate}
    finally:
        rule.release_state()
