"""Episode checkpoints stay internal; reconstructed continuity leads the claim."""
from romulus.store import schema as t
from tests import test_web
from tests.test_report import _repo_with_finding
from tests.test_web import _login
from tests.test_zeek_rate_state import event, toy

client = test_web.client


def test_report_does_not_render_internal_aggregate_summary():
    from romulus.report.manifest import build_manifest
    repo, cid = _repo_with_finding()
    try:
        row = repo.candidate(cid)
        with repo.engine.begin() as conn:
            conn.execute(t.candidate.update().where(t.candidate.c.id == cid).values(
                gate_results={**row['gate_results'], 'aggregate_summary': {'peak': 300}}))
        report = build_manifest(repo, 'h1', 'test')
        assert 'aggregate_summary' not in report['findings'][0]['gates']
        assert repo.candidate(cid)['gate_results']['aggregate_summary'] == {'peak': 300}
    finally:
        repo.engine.dispose()


def test_finding_page_does_not_expose_internal_aggregate_summary(client, tmp_path):
    from romulus.config import Settings
    from romulus.hunt.run import open_repo
    c, pw, cid = client
    repo = open_repo(Settings(home=tmp_path))
    try:
        row = repo.candidate(cid)
        with repo.engine.begin() as conn:
            conn.execute(t.candidate.update().where(t.candidate.c.id == cid).values(
                gate_results={**row['gate_results'], 'aggregate_summary': {'peak': 300}}))
        _login(c, pw)
        response = c.get(f'/findings/{cid}')
        assert response.status_code == 200
        assert 'aggregate_summary' not in response.text
        assert 'Admission gates' in response.text
    finally:
        repo.engine.dispose()


def test_completed_reconstruction_leads_headline_and_keeps_historical_bound_internal():
    owner = toy()
    try:
        list(owner.consume([event(f'a{n}', n) for n in range(3)]))
        [old] = list(owner.consume([event(f'b{n}', 20+n) for n in range(3)]))
        assert old.aggregate_summary['episodes'] == 2
        list(owner.consume([event(f'bridge{n}', n) for n in range(3, 20)]))
        [reconstructed] = list(owner.finalize())
        assert 'Across 1 reconstructed qualifying episode' in reconstructed.claim
        assert reconstructed.aggregate_summary['episodes'] == 2
        assert reconstructed.aggregate_summary['continuity_episodes'] == 1
        assert any('historical' in note.lower() and '2' in note for note in reconstructed.notes)
    finally:
        owner.release_state()
