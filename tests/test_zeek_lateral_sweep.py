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
