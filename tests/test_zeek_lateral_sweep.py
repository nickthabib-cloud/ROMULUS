"""The registered pack publishes every new Zeek analytic through the actual sweep."""
from datetime import timedelta

from romulus.detect.zeek_lateral import RULES as LATERAL
from romulus.detect.zeek_rates import RULES as RATES
from romulus.detect.zeek_smb import RULES as SMB
from romulus.hunt import sweep as sw
from romulus.site import COLLECTION_SCHEMA, validate_site_content
from romulus.sources.models import Window
from romulus.sources.profile import contract_from_types
from tests import test_sweep as ts
from tests.fixtures import zeek_logs as zl
from tests.test_zeek_admin_share_pe import FILES, PE
from tests.test_zeek_admin_share_pe import SMB as SHARE
from tests.test_zeek_rate_rules import rows_for
from tests.test_zeek_sweep_e2e import _repo


def test_registered_pack_publishes_the_complete_lateral_slice_with_resolvable_sources(tmp_path, monkeypatch):
    rows = [zl.DCE_RPC, zl.DCE_RPC.with_(uid='Creplication000001', endpoint='drsuapi', operation='DRSGetNCChanges'),
            zl.DCE_RPC.with_(uid='Ccoercion00000001', endpoint='efsrpc', operation='EfsRpcOpenFileRaw'),
            zl.RDP.with_(**{'id.orig_h': '203.0.113.25'}), zl.RDP.with_(uid='CrdpInside0000001'), zl.RFB,
            zl.HTTP.with_(uid='Cwinrm00000001', uri='/wsman', **{'id.resp_p': 5985, 'id.resp_h': zl.DC}),
            zl.KERBEROS, SHARE, FILES, PE]
    for name, count, distinct in [('ZerologonRate', 50, True), ('Rc4TgsFanout', 10, True),
                                 ('KerberosPrincipalEnumeration', 20, True), ('NtlmPasswordSpray', 10, True),
                                 ('NtlmPasswordGuessing', 20, False)]:
        rows.extend(rows_for(name, count, distinct=distinct, success=name == 'NtlmPasswordSpray'))
    rows.extend(zl.DCE_RPC.with_(uid=f'Csessenum{n:08d}', endpoint='srvsvc', operation='NetrSessionEnum', **{'id.resp_h': f'10.0.7.{n}'}) for n in range(25))
    rows.extend(zl.DCE_RPC.with_(uid=f'Csamlist{n:08d}', endpoint='samr', operation=operation)
                for n, operation in enumerate(['SamrEnumerateUsersInDomain', 'SamrEnumerateGroupsInDomain', 'SamrGetMembersInGroup']))
    hits = [zl.malcolm(row, f'row{n}') for n, row in enumerate(rows)]
    monkeypatch.setattr(sw, 'execute', lambda client, intent, contract: ts._complete(intent, hits))
    class NativeSource:
        def search(self, index, body):
            wanted = body['query']['bool']['filter'][0]['ids']['values']
            return {'hits': {'hits': [hit for hit in hits if hit['_index'] == index and hit['_id'] in wanted]}}
    contract = contract_from_types('net', {'@timestamp': 'date', 'event.dataset': 'keyword',
                                          'event.provider': 'keyword'}, role='network', os_family='unknown')
    facts = validate_site_content({'schema': COLLECTION_SCHEMA, 'internal_networks': ['10.0.0.0/8'],
                                   'domain_controller_addresses': [zl.DC], 'management_hosts': [zl.WS]})
    repo = _repo()
    window = Window(start=ts.START, end=ts.START+timedelta(minutes=10))
    hunt = sw.Sweep(repo, NativeSource(), 'h1', window, {'net': contract}, stage_dir=tmp_path, site_facts=facts)
    hunt._profiles = {'net': {'role': 'network', 'datasets': {}}}
    try:
        hunt.run_partition('net', contract, [], window, est=len(hits), any_of=[])
        hunt.finalize()
        expected = {cls.id for cls in (*LATERAL, *RATES, *SMB)}
        found = {candidate['rule_id'] for candidate in repo.candidates('h1')}
        assert expected <= found, expected-found
        assert hunt.stats['errors'] == 0
        for candidate in repo.candidates('h1'):
            if candidate['rule_id'] in expected:
                assert candidate['event_ids']
                assert 'Citation body not retrieved' not in candidate['claim']
                for event in repo.citation_events('h1', candidate['event_ids']):
                    assert event['raw_ids']
                    assert len(repo.raw_records(event['raw_ids'])) == len(event['raw_ids'])
    finally:
        hunt.close_stage()


def test_the_encrypted_traffic_rules_publish_through_the_sweep_with_resolvable_sources_across_partitions(
        tmp_path, monkeypatch):
    """The endpoint-mapper leg is read in one partition and the high-port leg in the next: the held leg is still
    cited with its raw record."""
    from romulus.detect.zeek_encrypted import RULES as ENCRYPTED
    from tests.fixtures import zeek_factory as zf
    from tests.test_zeek_encrypted_rules import conn, epm_pair, shells, smb, tgs

    epm_first, epm_second = epm_pair(900, '10.5.0.7', ts=290.0, delay=20.0)       # 14:04:50 and 14:05:10
    from dataclasses import replace
    # distinct Zeek uids: records sharing one are the same connection to the normalizer
    early = [*shells(4), *(replace(row, uid=f'CencSmb{n:010d}', orig_p=40000 + n) for n, row in enumerate(smb(10))),
             conn(950, zl.DC, 389, src='10.7.0.5', received=6_000_000), epm_first]
    tickets = [tgs(n, f'MSSQLSvc/sql{n:02d}.example.test:1433') for n in range(10)]
    first = [zf.malcolm(row, f'enc-early-{n}') for n, row in enumerate(early)]
    first += [zl.malcolm(row, f'enc-krb-{n}') for n, row in enumerate(tickets)]
    second = [zf.malcolm(epm_second, 'enc-late-0')]
    hits = first + second
    current = {'hits': first}
    monkeypatch.setattr(sw, 'execute', lambda client, intent, contract: ts._complete(intent, current['hits']))

    class NativeSource:
        def search(self, index, body):
            wanted = body['query']['bool']['filter'][0]['ids']['values']
            return {'hits': {'hits': [hit for hit in hits if hit['_index'] == index and hit['_id'] in wanted]}}
    contract = contract_from_types('net', {'@timestamp': 'date', 'event.dataset': 'keyword',
                                          'event.provider': 'keyword'}, role='network', os_family='unknown')
    facts = validate_site_content({'schema': COLLECTION_SCHEMA, 'internal_networks': ['10.0.0.0/8'],
                                   'domain_controller_addresses': [zl.DC]})
    repo = _repo()
    hunt = sw.Sweep(repo, NativeSource(), 'h1', Window(start=ts.START, end=ts.START + timedelta(minutes=10)),
                    {'net': contract}, stage_dir=tmp_path, site_facts=facts)
    hunt._profiles = {'net': {'role': 'network', 'datasets': {}}}
    try:
        hunt.run_partition('net', contract, [], Window(start=ts.START, end=ts.START + timedelta(minutes=5)),
                           est=len(first), any_of=[])
        current['hits'] = second
        hunt.run_partition('net', contract, [], Window(start=ts.START + timedelta(minutes=5),
                                                       end=ts.START + timedelta(minutes=10)),
                           est=len(second), any_of=[])
        hunt.finalize()
        expected = {cls.id for cls in ENCRYPTED}
        found = {candidate['rule_id'] for candidate in repo.candidates('h1')}
        assert expected <= found, expected - found
        assert hunt.stats['errors'] == 0
        for candidate in repo.candidates('h1'):
            if candidate['rule_id'] not in expected:
                continue
            assert candidate['event_ids'] and 'Citation body not retrieved' not in candidate['claim']
            events = repo.citation_events('h1', candidate['event_ids'])
            for event in events:
                assert event['raw_ids'] and len(repo.raw_records(event['raw_ids'])) == len(event['raw_ids'])
            if candidate['rule_id'] == 'net.epm_dynamic_rpc':
                assert len(events) == 2, events
        # every coverage cell carries the rule's bounded cost: wall time, records offered, and rows selected where
        # the rule keeps selected rows; the window cell sums the partitions and adds the finalize time
        cells = repo.rule_cells('h1', set(expected) | {'net.port_scan'})
        partition_cells = [cell for cell in cells if cell['target'] != '*']
        assert partition_cells and all(set(cell['detail']['timing']) <= {'wall_ms', 'records', 'selected'}
                                       and cell['detail']['timing']['wall_ms'] >= 0 for cell in partition_cells)
        fanout = [cell for cell in partition_cells if cell['rule_id'] == 'net.smb_rpc_fanout']
        assert sum(cell['detail']['timing']['records'] for cell in fanout) == len(early) + len(second)
        assert sum(cell['detail']['timing']['selected'] for cell in fanout) == 11       # ten SMB, one mapper
        [window] = [cell for cell in cells if cell['rule_id'] == 'net.smb_rpc_fanout' and cell['target'] == '*']
        assert set(window['detail']['timing']) == {'consume_wall_ms', 'finalize_wall_ms', 'records', 'selected'}
        assert window['detail']['timing']['selected'] == 11
    finally:
        hunt.close_stage()
