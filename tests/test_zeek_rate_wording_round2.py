"""Ticket encryption is an issued value; SPN breadth alone is not an RC4 observation."""
from dataclasses import replace

import pytest

from romulus.detect.zeek_lateral import HttpWinrm
from tests.fixtures import zeek_logs as zl
from tests.test_zeek_rate_rules import evaluate, rows_for
from tests.test_zeek_windows_protocols import normalize
from tests.windows_process_support import run


@pytest.mark.parametrize('shape', tuple(zl.WRITERS))
def test_rc4_wording_names_issued_ticket_encryption_not_requested_cipher(shape):
    observations=evaluate('Rc4TgsFanout',rows_for('Rc4TgsFanout',10),shape)
    assert observations
    claim=observations[-1][1].casefold()
    assert 'tgs exchanges with rc4 ticket encryption' in claim
    assert 'requested rc4' not in claim


@pytest.mark.parametrize('shape', tuple(zl.WRITERS))
def test_workstation_logon_many_aes_spns_cannot_become_rc4_fanout(shape):
    rows=[replace(zl.KERBEROS.with_(uid=f'Cworkstation{n:08d}',client='workstation$/EXAMPLE.TEST',
            service=f'{service}/dc01.example.test',cipher='aes256-cts-hmac-sha1-96'),ts=zl.T0+n)
          for n,service in enumerate(('host','cifs','ldap','gc','rpcss','restrictedkrbhost','http',
                                     'termsrv','wsman','mssqlsvc','dns','kadmin'))]
    assert not evaluate('Rc4TgsFanout',rows,shape)


@pytest.mark.parametrize('shape', tuple(zl.WRITERS))
@pytest.mark.parametrize('path,positive',[('/WsMaN',True),('/WSMAN?resource=one',True),
                                         ('/wsman-extra',False),('/other?path=/WSMAN',False)])
def test_winrm_casefolds_only_the_typed_request_path(shape,path,positive):
    raw=zl.HTTP.with_(uri=path,**{'id.resp_p':5985})
    event=normalize(zl.WRITERS[shape](raw,'winrm-case'))
    rule=HttpWinrm()
    try:
        observations=run(rule,[event])
        assert bool(observations) is positive
    finally:
        rule.release_state()
