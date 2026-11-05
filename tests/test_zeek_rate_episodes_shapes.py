"""Every rate keeps later peaks and episodes through each supported shipper."""
import importlib
from dataclasses import replace

import pytest

from tests.fixtures import zeek_logs as zl
from tests.test_zeek_rate_rules import rows_for
from tests.test_zeek_windows_protocols import normalize
from tests.windows_process_support import run


@pytest.mark.parametrize('shape',tuple(zl.WRITERS))
@pytest.mark.parametrize('name,count,distinct,seconds',[
    ('ZerologonRate',50,True,60),('Rc4TgsFanout',10,True,300),
    ('KerberosPrincipalEnumeration',20,True,600),('NtlmPasswordSpray',10,True,600),
    ('NtlmPasswordGuessing',20,False,600)])
@pytest.mark.parametrize('reverse',[False,True])
def test_all_rate_contracts_keep_two_bursts_and_a_growing_peak(shape,name,count,distinct,seconds,reverse):
    first=[replace(row,ts=zl.T0+n/100) for n,row in enumerate(rows_for(name,count,distinct=distinct))]
    later=[replace(row.with_(uid=f'Csecond{n:010d}'),ts=zl.T0+seconds+30+n/100)
           for n,row in enumerate(rows_for(name,count+5,distinct=distinct))]
    events=[normalize(zl.WRITERS[shape](row,f'episodes-{n}')) for n,row in enumerate([*first,*later])]
    owner=getattr(importlib.import_module('romulus.detect.zeek_rates'),name)()
    try:
        [match]=run(owner,[[e] for e in reversed(events)] if reverse else [[e] for e in events])
        assert '2 qualifying episodes' in match.claim
        assert f'peak {count+5} ' in match.claim
        assert match.bounded_revision
        assert len(match.events)<=3
        assert not list(owner.finalize())
    finally:
        owner.release_state()
