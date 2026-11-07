"""Native ICS evidence through sweep normalization, staging, publication and coverage."""
from romulus.detect.ics import WriteOrControlCommand
from tests.fixtures import zeek_ics as zi
from tests.test_zeek_sweep_e2e import sweep


def test_request_and_paired_response_publish_one_honest_ics_finding(monkeypatch,tmp_path):
    request=zi.hit(zi.ROWS['modbus'],'malcolm',nid='ics-request')
    response=zi.hit(zi.ROWS['modbus'].with_(pdu_type='RESP'),'malcolm',nid='ics-response')
    repo,run=sweep(monkeypatch,tmp_path,[[request],[response]],pack=[WriteOrControlCommand()])
    try:
        [candidate]=list(repo.candidates('h1'))
        assert candidate['rule_id']=='ics.write_or_control_command'
        assert candidate['lane']=='lead'
        assert '1 request record(s)' in candidate['claim']
        assert 'write acknowledged without exception' in candidate['claim']
        assert run.stats['errors']==0
        assert all(cell['state']!='no_match_complete' for cell in repo.rule_cells('h1'))
        assert candidate['event_ids']
        for record in repo.citation_events('h1',candidate['event_ids']):
            assert record['raw_ids']
            assert len(repo.raw_records(record['raw_ids']))==len(record['raw_ids'])
    finally:
        run.close_stage()
