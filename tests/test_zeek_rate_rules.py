"""Each network rate uses the same typed evidence in every Zeek shipper format."""
import importlib
from dataclasses import replace

import pytest

from tests.fixtures import zeek_logs as zl
from tests.test_zeek_windows_protocols import normalize
from tests.windows_process_support import run


def rows_for(name, count, *, success=False, unknown=False, distinct=True):
    rows = []
    for n in range(count):
        if name == 'ZerologonRate':
            row = zl.DCE_RPC.with_(endpoint='netlogon', operation='NetrServerAuthenticate3', uid=f'Czero{n:010d}')
        elif name == 'Rc4TgsFanout':
            row = zl.KERBEROS.with_(uid=f'Ckrb{n:010d}', service=f'cifs/server{n if distinct else 0}',
                                    till=zl.T0+3600)
        elif name == 'KerberosPrincipalEnumeration':
            row = zl.KERBEROS.with_(uid=f'Cenum{n:010d}', client=f'user{n if distinct else 0}/EXAMPLE.TEST',
                                    success=False, error_msg='KDC_ERR_C_PRINCIPAL_UNKNOWN', till=zl.T0+3600)
        else:
            row = zl.NTLM.with_(uid=f'Cntlm{n:010d}', username=f'user{n if distinct else 0}', success=False)
            if unknown:
                row = row.without('success')
        rows.append(replace(row, ts=zl.T0+n))
    if success:
        rows.append(replace(zl.NTLM.with_(uid='CntlmSuccess00001', username='user0', success=True), ts=zl.T0+count+1))
    return rows


def evaluate(name, rows, shape, *, reverse=False):
    cls = getattr(importlib.import_module('romulus.detect.zeek_rates'), name)
    observations = [normalize(zl.WRITERS[shape](row, f'r{n}')) for n, row in enumerate(rows)]
    rule = cls()
    try:
        matches = run(rule, [[e] for e in reversed(observations)] if reverse else [[e] for e in observations])
        return sorted((m.proposed_lane, m.claim, tuple(sorted(m.notes))) for m in matches)
    finally:
        rule.release_state()


@pytest.mark.parametrize('name,count,distinct,lane', [
    ('ZerologonRate', 50, True, 'high'),
    ('Rc4TgsFanout', 10, True, 'lead'),
    ('KerberosPrincipalEnumeration', 20, True, 'lead'),
    ('NtlmPasswordSpray', 10, True, 'lead'),
    ('NtlmPasswordGuessing', 20, False, 'lead'),
])
def test_each_rate_positive_and_below_threshold_negative_are_equal_in_four_shapes(name, count, distinct, lane):
    positive, negative = [], []
    for shape in zl.WRITERS:
        positive.append(evaluate(name, rows_for(name, count, distinct=distinct), shape))
        negative.append(evaluate(name, rows_for(name, count-1, distinct=distinct), shape))
    assert all(result == positive[0] for result in positive)
    assert {m[0] for m in positive[0]} == {lane}
    assert negative == [[], [], [], []]


@pytest.mark.parametrize('name,count', [('Rc4TgsFanout', 20), ('KerberosPrincipalEnumeration', 30)])
def test_repeated_service_or_principal_does_not_become_distinct_discovery(name, count):
    for shape in zl.WRITERS:
        assert not evaluate(name, rows_for(name, count, distinct=False), shape)


def test_zerologon_does_not_combine_different_clients_or_count_challenges():
    for shape in zl.WRITERS:
        many = [row.with_(**{'id.orig_h': f'10.2.0.{n+1}'}) for n, row in
                enumerate(rows_for('ZerologonRate', 60))]
        challenges = [row.with_(operation='NetrServerReqChallenge') for row in rows_for('ZerologonRate', 60)]
        assert not evaluate('ZerologonRate', many, shape)
        assert not evaluate('ZerologonRate', challenges, shape)


@pytest.mark.parametrize('reverse', [False, True])
def test_ntlm_success_after_spray_promotes_one_stable_observation_in_every_shape(reverse):
    results = [evaluate('NtlmPasswordSpray', rows_for('NtlmPasswordSpray', 10, success=True), shape,
                        reverse=reverse) for shape in zl.WRITERS]
    assert all(result == results[0] for result in results)
    assert len(results[0]) == 1 and results[0][0][0] == 'high'
    assert 'success' in results[0][0][1].lower()


def test_unrecorded_ntlm_outcomes_count_attempts_and_are_never_called_failures():
    for shape in zl.WRITERS:
        results = evaluate('NtlmPasswordGuessing',
                           rows_for('NtlmPasswordGuessing', 20, distinct=False, unknown=True), shape)
        assert results and results[0][0] == 'lead'
        assert 'attempt' in results[0][1].lower()
        assert any('unrecorded' in note.lower() for note in results[0][2])


def test_zerologon_normalizes_both_peer_spellings_before_keying():
    for shape in zl.WRITERS:
        same_host = [row.with_(**{'id.orig_h': '10.0.0.1', 'id.resp_h': '::ffff:10.0.0.1'})
                     for row in rows_for('ZerologonRate', 50)]
        assert not evaluate('ZerologonRate', same_host, shape)
        one_server = [row.with_(**{'id.resp_h': '::ffff:10.0.0.2' if n % 2 else '10.0.0.2'})
                      for n, row in enumerate(rows_for('ZerologonRate', 50))]
        assert evaluate('ZerologonRate', one_server, shape)


def _rpc(endpoint, operation, n, *, destination=None, seconds=1):
    row = zl.DCE_RPC.with_(endpoint=endpoint, operation=operation, uid=f'Cenumrpc{n:09d}',
                           **({'id.resp_h': destination} if destination else {}))
    return replace(row, ts=zl.T0 + n * seconds)


@pytest.mark.parametrize('shape', ['malcolm', 'plain'])
def test_session_enumeration_on_ten_hosts_is_a_lead_and_nine_is_not(shape):
    sweep = [_rpc('srvsvc', 'NetrSessionEnum', n, destination=f'10.0.1.{n}') for n in range(10)]
    [(lane, claim, _notes)] = evaluate('RpcHostEnumerationFanout', sweep, shape)
    assert lane == 'lead' and 'at least 10 distinct hosts' in claim
    assert evaluate('RpcHostEnumerationFanout', sweep[:9], shape) == []


def test_host_enumeration_counts_hosts_not_calls_and_mixes_collection_calls():
    assert evaluate('RpcHostEnumerationFanout', [_rpc('srvsvc', 'NetrShareEnum', n) for n in range(50)], 'plain') == []
    mixed = [_rpc(*call, n, destination=f'10.0.1.{n}') for n, call in enumerate(
        [('srvsvc', 'NetrShareEnum'), ('wkssvc', 'NetrWkstaUserEnum'), ('samr', 'SamrGetMembersInAlias')] * 4)]
    assert [lane for lane, *_ in evaluate('RpcHostEnumerationFanout', mixed, 'plain')] == ['lead']


def test_routine_single_object_reads_and_slow_sweeps_are_not_host_enumeration():
    reads = [_rpc('srvsvc', 'NetrShareGetInfo', n, destination=f'10.0.1.{n}') for n in range(30)]
    assert evaluate('RpcHostEnumerationFanout', reads, 'plain') == []
    slow = [_rpc('srvsvc', 'NetrSessionEnum', n, destination=f'10.0.1.{n}', seconds=120) for n in range(10)]
    assert evaluate('RpcHostEnumerationFanout', slow, 'plain') == []


@pytest.mark.parametrize('shape', ['malcolm', 'plain'])
def test_three_distinct_bulk_sam_listings_to_one_server_are_a_lead(shape):
    calls = ['SamrEnumerateUsersInDomain', 'SamrEnumerateGroupsInDomain', 'SamrGetMembersInGroup']
    rows = [_rpc('samr', name, n) for n, name in enumerate(calls)]
    [(lane, claim, _notes)] = evaluate('RpcDirectoryListing', rows, shape)
    assert lane == 'lead' and f'to {zl.DC}' in claim
    assert evaluate('RpcDirectoryListing', rows[:2] * 20, shape) == []


def test_name_translation_and_logon_membership_reads_are_not_directory_listing():
    routine = ['SamrLookupNamesInDomain', 'SamrLookupIdsInDomain', 'SamrGetAliasMembership', 'SamrGetGroupsForUser',
               'SamrQueryInformationDomain']
    rows = [_rpc('samr', name, n) for n, name in enumerate(routine)]
    rows += [_rpc('lsarpc', name, 10 + n) for n, name in enumerate(['LsarLookupSids', 'LsarLookupNames', 'LsarLookupSids2'])]
    assert evaluate('RpcDirectoryListing', rows, 'plain') == []


def test_a_large_volume_of_routine_rpc_stays_quiet_and_one_sweep_inside_it_is_found():
    noise = [_rpc('lsarpc', 'LsarLookupSids', n, destination=f'10.0.{n % 200}.{n % 250}') for n in range(5000)]
    sweep = [_rpc('srvsvc', 'NetrSessionEnum', 6000 + n, destination=f'10.9.0.{n}') for n in range(12)]
    found = evaluate('RpcHostEnumerationFanout', noise + sweep, 'plain')
    assert [lane for lane, *_ in found] == ['lead'] and 'at least 1' in found[0][1]
