"""A resumed prefix cannot overwrite the published evidence of a stronger episode."""
from dataclasses import replace

import pytest

from romulus.hunt.publish import publish_match
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo
from tests.test_zeek_rate_state import START, event, final_matches, toy


@pytest.mark.parametrize('change',[
    {'peak':12}, {'episodes':1}, {'lane':'lead'}, {'first':1}, {'last':20}, {'missing':True}])
def test_persisted_summary_refuses_a_weaker_resume_without_candidate_or_audit_rewrite(change):
    engine=make_engine(':memory:');migrate(engine);repo=Repo(engine)
    repo.create_hunt('r3',{'targets':[]},'digest','test')
    rule=toy()
    rows=[event('first',0,refs=['a','b','c']),event('peak',20,refs=[f'p{n}' for n in range(30)]),
          event('hit',21,role='success')]
    rule.success_fields=rule.citation_fields
    try:
        [match]=final_matches(rule,rows)
        stamp=START.timestamp()
        summary={'episodes':2,'peak':30,'first':stamp,'last':stamp+21,
                 'peak_start':stamp+10,'peak_end':stamp+20}
        match.aggregate_summary=summary
        sources={ref.key:{'native':ref.native_id} for row in rows for ref in row.raw}
        publish_match(repo,'r3',rule,match,None,sources)
        [before]=repo.candidates('r3')
        assert before['gate_results'].get('aggregate_summary')==summary
        incoming=replace(match,claim='A smaller resumed prefix',proposed_lane=change.get('lane','high'),
                         revision_reason='A replay prefix is not new attack evidence')
        incoming.aggregate_summary={} if change.get('missing') else {**summary,**{
            key:stamp+value if key in {'first','last'} else value for key,value in change.items() if key!='lane'}}
        publish_match(repo,'r3',rule,incoming,None,sources)
        [after]=repo.candidates('r3')
        assert after==before
        assert not repo.latest_audit('r3','candidate.revised')
    finally:
        rule.release_state();engine.dispose()


@pytest.mark.parametrize('ownership',['source_anchor_id','source_case_id'])
def test_linked_evaluator_does_not_borrow_the_sweeps_published_window_or_witnesses(ownership):
    engine=make_engine(':memory:');migrate(engine);repo=Repo(engine)
    repo.create_hunt('r3',{'targets':[]},'digest','test')
    sweep,linked=toy(),toy()
    broad=[event(f'sweep{n}',n) for n in range(10)]
    reached=[event(f'linked{n}',100+n) for n in range(5)]
    sources={ref.key:{'native':ref.native_id} for row in [*broad,*reached] for ref in row.raw}
    try:
        for match in sweep.consume(broad):
            publish_match(repo,'r3',sweep,match,None,sources)
        emitted=[]
        for match in linked.consume(reached):
            emitted.append(match)
            publish_match(repo,'r3',linked,match,None,sources,**{ownership:'separate-window'})
        assert emitted and emitted[-1].aggregate_summary['peak']==5
        assert all(row.id.startswith('linked') for match in emitted for row in match.events)
        assert not getattr(linked,'published_aggregate',None)
    finally:
        sweep.release_state();linked.release_state();engine.dispose()
