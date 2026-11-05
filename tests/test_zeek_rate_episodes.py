"""A later attack window must revise its source finding rather than disappear."""
from datetime import timedelta

import pytest

from romulus.hunt.publish import publish_match
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo
from tests.test_zeek_rate_state import START, event, final_matches, toy


def test_two_disjoint_bursts_keep_episode_count_peak_and_both_witnesses():
    rule = toy()
    try:
        [match] = final_matches(rule, [event('a', 0), event('b', 1), event('first', 2),
                                      event('peak', 30, refs=[f'p{n}' for n in range(6)])])
        assert '2 qualifying episodes' in match.claim
        assert 'peak 6' in match.claim
        assert {'first', 'peak'} <= {row.id for row in match.events}
        assert any((START+timedelta(seconds=2)).isoformat() in note for note in match.notes)
        assert any((START+timedelta(seconds=30)).isoformat() in note for note in match.notes)
    finally:
        rule.release_state()


def test_growing_window_revises_same_identity_and_never_freezes_the_first_count():
    rule = toy()
    try:
        published = []
        for row in (event('first', 0, refs=['a','b','c']), event('next', 1, refs=['d','e']),
                    event('peak', 2, refs=['f','g','h','i','j'])):
            published.extend(rule.consume([row]))
        published.extend(rule.finalize())
        assert len(published) >= 2 and len({m.group_key for m in published}) == 1
        assert 'peak 10' in published[-1].claim and '1 qualifying episode' in published[-1].claim
        assert all(m.bounded_revision and m.revision_reason for m in published[1:])
        assert {'first','peak'} <= {row.id for row in published[-1].events}
    finally:
        rule.release_state()


@pytest.mark.parametrize('same_time',[False,True])
def test_reversed_partition_starts_with_earliest_qualifying_window(same_time):
    rule=toy(threshold=1)
    try:
        rows=[event('z',1),event('a',1 if same_time else 0)]
        matches=list(rule.consume(rows))
        assert matches and matches[0].events[0].id=='a'
        assert not rule.capped
    finally:
        rule.release_state()


@pytest.mark.parametrize('batches', [[(0,1,2),(30,31,32)], [(30,31,32),(2,1,0)], [(32,0),(31,1),(30,2)]])
def test_episode_summary_is_equal_after_late_arrival_and_replay(batches):
    rule = toy()
    try:
        matches=[]
        for times in batches:
            matches.extend(rule.consume([event(str(n),n) for n in times]))
        matches.extend(rule.finalize())
        assert '2 qualifying episodes' in matches[-1].claim
        assert 'peak 3' in matches[-1].claim
        assert not list(rule.finalize())
    finally:
        rule.release_state()


def test_fresh_resume_mid_episode_revises_one_persisted_finding():
    engine=make_engine(':memory:');migrate(engine);repo=Repo(engine)
    repo.create_hunt('rates',{'targets':[]},'digest','test')
    rows=[event(str(n),n) for n in range(8)]
    for accepted in (rows[:4],rows):
        rule=toy()
        try:
            for match in [*rule.consume(accepted),*rule.finalize()]:
                sources={ref.key:{'native':ref.native_id} for row in accepted for ref in row.raw}
                publish_match(repo,'rates',rule,match,None,sources)
        finally:
            rule.release_state()
    findings=[row for row in repo.candidates('rates') if row['rule_id']=='test.zeek_window']
    assert len(findings)==1 and 'peak 8' in findings[0]['claim']
    assert not list(repo.engine.connect().exec_driver_sql('PRAGMA foreign_key_check'))
    engine.dispose()
