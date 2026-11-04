"""Native uncited positives remain visible without guessed agent time bounds."""
from types import SimpleNamespace

import pytest
from sqlalchemy import update

import romulus.agent.dossier as dossier_module
from romulus.agent.cases import cluster_seed_candidates, seed_partition_families
from romulus.agent.dossier import build_dossier
from romulus.agent.tools import EntityTimelineRequest
from romulus.hunt.agent_tools import HuntToolExecutor
from romulus.store import schema as t
from tests.test_missing_citation_time_round7 import publish_untimed
from tests.test_report import T, _repo_with_finding


def test_native_untimed_seed_is_visible_without_chronological_correlation():
    repo, dated_id = _repo_with_finding()
    untimed = publish_untimed(repo)
    with repo.engine.begin() as conn:
        conn.execute(update(t.candidate).where(t.candidate.c.id == untimed['id']).values(
            entities=repo.candidate(dated_id)['entities']))
    candidates = repo.candidates('h1')
    clusters = cluster_seed_candidates(candidates)
    assert sorted(cid for c in clusters for cid in c.seed_candidate_ids) == sorted([dated_id, untimed['id']])
    own = next(c for c in clusters if untimed['id'] in c.seed_candidate_ids)
    assert own.seed_candidate_ids == [untimed['id']]
    assert own.first_ts is own.last_ts is None
    assert next(c for c in clusters if dated_id in c.seed_candidate_ids).first_ts == repo.candidate(dated_id)['ts']
    assert [c.model_dump() for c in clusters] == [c.model_dump() for c in cluster_seed_candidates(list(reversed(candidates)))]
    steps = [{'n': 0, 'decision': {'action': 'seed', 'seed_candidate_ids': [untimed['id']]}}]
    assert seed_partition_families(own.id, steps, candidates) == (own.id,)


@pytest.mark.parametrize('large', [False, True])
def test_native_untimed_positive_survives_each_dossier_path(monkeypatch, large):
    repo, dated_id = _repo_with_finding()
    untimed = publish_untimed(repo)
    with repo.engine.begin() as conn:
        conn.execute(update(t.candidate).where(t.candidate.c.id == untimed['id']).values(
            priority=repo.candidate(dated_id)['priority']))
    if large:
        monkeypatch.setattr(dossier_module, 'MATERIALIZE_FINDING_LIMIT', 1)
    dossier = build_dossier(repo, 'h1', token_budget=50_000)
    findings = [f for page in dossier.pages for f in page.get('findings', [])]
    assert len(findings) == 2
    assert sorted(f['time'] is None for f in findings) == [False, True]
    assert {f['lane'] for f in findings} == {'high'}
    assert '"time":null' in b''.join(dossier.json_bytes(i+1) for i in range(len(dossier.pages))).decode()
    assert repo.candidate(untimed['id'])['ts'] is None


class _NoSources:
    source_queries = 0

    def run(self, *args, **kwargs):
        pytest.fail('an untimed anchor must not issue a source query')

    def fetch(self, *args, **kwargs):
        pytest.fail('an untimed anchor must not issue a link query')


def test_native_untimed_follow_link_returns_named_partial_without_query():
    repo, _ = _repo_with_finding()
    untimed = publish_untimed(repo)
    executor = HuntToolExecutor(repo, 'h1', _NoSources(), _NoSources(), T, T.replace(hour=16))
    result = executor.follow_link('session', untimed['id'], 'process_lineage', None)
    assert result.status == 'partial'
    assert any('observation time unavailable' in reason for reason in result.reasons)
    assert not result.event_ids and not result.coverage
    assert repo.expansion_links('h1') == []
    assert repo.candidate(untimed['id'])['lane'] == 'high'


@pytest.mark.parametrize('anchor_time', [None, T])
def test_native_untimed_direct_pivot_cannot_assume_an_anchor_time(anchor_time):
    repo, _ = _repo_with_finding()
    untimed = publish_untimed(repo)
    executor = HuntToolExecutor(repo, 'h1', _NoSources(), SimpleNamespace(), T, T.replace(hour=16))
    request = EntityTimelineRequest(tool='entity_timeline', arguments={
        'entity': {'kind': 'host', 'value': 'web01', 'role': 'host'}, 'start': T, 'end': T.replace(hour=16)})
    result = executor.run('session', untimed['id'], request, anchor_ts=anchor_time)
    assert result.status == 'partial'
    assert any('observation time unavailable' in reason for reason in result.reasons)
    assert not result.task_ids and repo.candidate(untimed['id'])['ts'] is None
