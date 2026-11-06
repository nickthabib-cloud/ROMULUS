"""Partial replay and steady qualifying traffic preserve published episode evidence."""
import sqlite3

import pytest

from romulus.hunt.publish import bind_aggregate_history, publish_match
from tests.test_sweep import _repo
from tests.test_zeek_rate_state import event, toy


class ReplayFull:
    def __init__(self,connection,at):
        self.connection,self.at,self.active=connection,at,0

    def __getattr__(self,name):
        return getattr(self.connection,name)

    def execute(self,statement,parameters=()):
        if statement.upper().startswith('INSERT INTO ACTIVE '):
            self.active+=1
            if self.active==self.at:
                raise sqlite3.OperationalError('database or disk is full')
        return self.connection.execute(statement,parameters)


@pytest.mark.parametrize('at',[2,6,15,31])
def test_refused_finalize_never_emits_a_smaller_published_episode_summary(at):
    owner=toy()
    rows=[event(f'a{n}',n/100) for n in range(3)]+[event(f'b{n}',30+n/100) for n in range(30)]
    try:
        matches=list(owner.consume(rows))
        assert '2 qualifying episodes' in matches[-1].claim and 'peak 30' in matches[-1].claim
        spill=owner.rows.store();spill._budget_limited=True
        spill.db=ReplayFull(spill.db,at)
        assert not list(owner.finalize())
        assert owner.limit_reasons()
    finally:
        owner.release_state()


def test_two_hundred_steady_batches_revise_only_real_changes_then_one_final_window():
    owner=toy()
    try:
        matches=[]
        for n in range(200):
            matches.extend(owner.consume([event(str(n),n,refs=[f'{n}-{copy}' for copy in range(3)])]))
        # Initial peak3, ten real peak increases through33, and one final last-window update.
        assert len(matches)<=11
        final=list(owner.finalize())
        assert len(final)<=1
        [latest]=final or matches[-1:]
        assert 'peak 33' in latest.claim and '1 qualifying episode' in latest.claim
        assert latest.aggregate_summary['last']==event('last',199).ts.timestamp()
        assert all('peak' in row.revision_reason.casefold() for row in matches[1:])
        if final:
            assert 'last' in final[0].revision_reason.casefold()
        assert not list(owner.finalize())
    finally:
        owner.release_state()


def persist(repo, owner, match, rows):
    sources={ref.key:{'native':ref.native_id} for row in rows for ref in row.raw}
    publish_match(repo,'h1',owner,match,None,sources)


def test_first_resumed_partition_never_lowers_stored_high_peak_or_episode_count():
    repo=_repo()
    rows=[event(f'a{n}',n/100) for n in range(12)]+[event(f'b{n}',30+n/100) for n in range(50)]
    rows.append(event('hit',31,role='success'))
    original=toy();original.success_fields=original.citation_fields
    resumed=toy();resumed.success_fields=resumed.citation_fields
    bind_aggregate_history(repo,'h1',resumed)
    try:
        for match in [*original.consume(rows),*original.finalize()]:
            persist(repo,original,match,rows)
        [before]=repo.candidates('h1')
        assert before['lane']=='high'
        assert before['gate_results']['aggregate_summary']['peak']==50
        assert before['gate_results']['aggregate_summary']['episodes']==2
        for match in resumed.consume(rows[:12]):
            persist(repo,resumed,match,rows)
            assert repo.candidates('h1')==[before]
        for match in [*resumed.consume(rows[12:]),*resumed.finalize()]:
            persist(repo,resumed,match,rows)
        assert repo.candidates('h1')==[before]
    finally:
        original.release_state();resumed.release_state();repo.engine.dispose()


def test_resume_with_bound_published_checkpoint_can_immediately_raise_the_stored_peak():
    repo=_repo()
    original,resumed=toy(),toy()
    rows=[event(f'a{n}',n/100) for n in range(3)]+[event(f'b{n}',30+n/100) for n in range(30)]
    later=event('larger',30.5,refs=[f'larger{n}' for n in range(30)])
    try:
        for match in [*original.consume(rows),*original.finalize()]:
            persist(repo,original,match,rows)
        bind_aggregate_history(repo,'h1',resumed)
        for match in resumed.consume([*rows,later]):
            persist(repo,resumed,match,[*rows,later])
        [candidate]=repo.candidates('h1')
        assert candidate['gate_results']['aggregate_summary']['peak']==60
        assert 'peak 60' in candidate['claim']
    finally:
        original.release_state();resumed.release_state();repo.engine.dispose()


def test_two_hundred_steady_partitions_do_not_rewrite_the_candidate_for_each_last_window():
    repo,owner=_repo(),toy()
    rows=[event(str(n),n,refs=[f'{n}-{copy}' for copy in range(3)]) for n in range(200)]
    try:
        for row in rows:
            for match in owner.consume([row]):
                persist(repo,owner,match,rows)
        [candidate]=repo.candidates('h1')
        assert candidate['gate_results']['_revision']['count']<=10
        for match in owner.finalize():
            persist(repo,owner,match,rows)
        [candidate]=repo.candidates('h1')
        assert candidate['gate_results']['_revision']['count']<=11
        assert candidate['gate_results']['aggregate_summary']['last']==rows[-1].ts.timestamp()
    finally:
        owner.release_state();repo.engine.dispose()
