"""Cross-record gap witnesses retain stable event identity and finding priority."""
from dataclasses import replace
from types import SimpleNamespace
from typing import ClassVar

import pytest

from romulus.config import Settings
from romulus.detect.base import Match
from romulus.hunt.zeek_gaps import enrich
from romulus.site import absent_site_facts
from romulus.sources.es import ElasticClient
from tests.fixtures import zeek_factory as zf
from tests.fixtures import zeek_logs as zl
from tests.test_zeek_links import NativePivot, normalize
from tests.zeek_source_support import ZeekES


@pytest.mark.parametrize('shape',zf.SHAPES)
@pytest.mark.parametrize('gap',[{'missed_bytes':10},{'history':'Shg'},{'history':'Shx'}])
def test_analyzer_finding_cites_later_cross_target_connection_gap_without_changing_event(tmp_path,shape,gap):
    analyzer=getattr(zl,shape)(zl.HTTP,'http')
    conn=getattr(zf,shape)(replace(zf.Conn(),uid=zl.UID_HTTP,ts=zl.HTTP.ts-10,**gap),'conn')
    pivot=NativePivot(shape,[analyzer,conn])
    contract=pivot.contracts['network'].model_copy(update={'time_field':'ts' if shape=='plain' else '@timestamp'})
    backend=ZeekES({'network':[conn]},{'network':contract.time_field})
    sweep=SimpleNamespace(contracts={'network':contract},site_facts=absent_site_facts(),
                          client=ElasticClient(Settings(home=tmp_path),transport=backend.transport()))
    event=normalize(shape,analyzer); before=event.model_dump(mode='json')
    match=Match('test','positive','network_observation',[event],[],event.ts,'high','urgent','high')
    raw={};enrich(sweep,match,raw)
    assert event.model_dump(mode='json')==before
    assert match.proposed_lane=='urgent'
    assert match.notes and any('supporting record' in note for note in match.notes)
    assert len(match.events)==2
    assert all(ref.key in raw for item in match.events[1:] for ref in item.raw)

@pytest.mark.parametrize('shape',zf.SHAPES)
@pytest.mark.parametrize('gap',[{'missing_bytes':10},{'overflow_bytes':10},{'timedout':True}])
def test_analyzer_file_gap_is_cited_without_lowering_lane(tmp_path,shape,gap):
    analyzer=getattr(zl,shape)(zl.HTTP,'http')
    file=getattr(zl,shape)(zl.FILES.with_(**gap),'file')
    native=NativePivot(shape,[analyzer,file])
    contract=native.contracts['network'].model_copy(update={'time_field':'ts' if shape=='plain' else '@timestamp'})
    backend=ZeekES({'network':[file]},{'network':contract.time_field})
    sweep=SimpleNamespace(contracts={'network':contract},site_facts=absent_site_facts(),
                          client=ElasticClient(Settings(home=tmp_path),transport=backend.transport()))
    event=normalize(shape,analyzer);before=event.model_dump(mode='json')
    match=Match('test','positive','network_observation',[event],[],event.ts,'high','urgent','high')
    raw={};enrich(sweep,match,raw)
    assert event.model_dump(mode='json')==before and match.proposed_lane=='urgent'
    assert len(match.events)==2 and match.context_ids=={normalize(shape,file).id}
    assert any('supporting record' in note for note in match.notes)
    assert all(ref.key in raw for item in match.events[1:] for ref in item.raw)


@pytest.mark.parametrize('shape',zf.SHAPES)
def test_file_gap_later_in_hunt_is_still_cited_on_earlier_analyzer(tmp_path,shape):
    from datetime import timedelta

    from romulus.sources.models import Window
    analyzer=getattr(zl,shape)(zl.HTTP,'http')
    file=getattr(zl,shape)(replace(zl.FILES.with_(missing_bytes=10),ts=zl.HTTP.ts+600),'late-file')
    native=NativePivot(shape,[analyzer,file])
    contract=native.contracts['network'].model_copy(update={'time_field':'ts' if shape=='plain' else '@timestamp'})
    backend=ZeekES({'network':[file]},{'network':contract.time_field})
    event=normalize(shape,analyzer)
    sweep=SimpleNamespace(contracts={'network':contract},site_facts=absent_site_facts(),
        window=Window(start=event.ts,end=event.ts+timedelta(minutes=20)),
        client=ElasticClient(Settings(home=tmp_path),transport=backend.transport()))
    match=Match('test','positive','network_observation',[event],[],event.ts,'high','urgent','high')
    raw={};enrich(sweep,match,raw)
    assert normalize(shape,file).id in match.context_ids
    assert any('missing_bytes' in note for note in match.notes)


@pytest.mark.parametrize('shape',zf.SHAPES)
@pytest.mark.parametrize('legacy',[False,True])
def test_file_only_anchor_follows_clean_file_to_gapped_carrier(tmp_path,shape,legacy):
    anchor=getattr(zl,shape)(zl.PE,'pe')
    file=getattr(zl,shape)(zl.FILES_50 if legacy else zl.FILES,'file')
    conn=getattr(zf,shape)(replace(zf.Conn(),uid=zl.UID_HTTP,ts=zl.HTTP.ts-10,missed_bytes=99),'conn')
    native=NativePivot(shape,[anchor,file,conn])
    contract=native.contracts['network'].model_copy(update={'time_field':'ts' if shape=='plain' else '@timestamp'})
    backend=ZeekES({'network':[file,conn]},{'network':contract.time_field})
    sweep=SimpleNamespace(contracts={'network':contract},site_facts=absent_site_facts(),
        client=ElasticClient(Settings(home=tmp_path),transport=backend.transport()))
    event=normalize(shape,anchor);before=event.model_dump(mode='json')
    match=Match('test','positive','network_observation',[event],[],event.ts,'high','urgent','high')
    raw={};enrich(sweep,match,raw)
    assert any('missed_bytes' in note for note in match.notes)
    assert {normalize(shape,file).id,normalize(shape,conn).id}<=match.context_ids
    assert event.model_dump(mode='json')==before and match.proposed_lane=='urgent'
    assert all(ref.key in raw for item in match.events[1:] for ref in item.raw)


@pytest.mark.parametrize('shape,publication',[(shape,publication) for shape in zf.SHAPES
    for publication in ('expansion','agent','context','pivot') if not (shape=='plain' and publication=='pivot')])
def test_link_discovered_analyzer_publication_cites_separate_gap_witness(tmp_path,monkeypatch,shape,publication):
    from datetime import timedelta

    from romulus.detect.base import ContextPlaybook, Playbook, pf
    from romulus.hunt import agent_tools
    from romulus.hunt import context as context_module
    from romulus.hunt import expansion as expansion_module
    from romulus.hunt import pivot as pivot_module
    from romulus.hunt.expansion import ExpansionEngine
    from romulus.hunt.links import LinkAnchor, LinkFetcher, LinkWindow
    from romulus.hunt.pivot import PivotExecutor
    from romulus.hunt.publish import publish_match
    from romulus.store.db import make_engine, migrate
    from romulus.store.repo import Repo
    class Positive(Playbook):
        id='test.link_http';families=('http_tx',);required_fields=('http.request.method',)
        def match(self,event):
            return [Match(self.id,'HTTP request directly recorded','network_observation',[event],
                [pf(event,'http.request.method')],event.ts,'high','high','high',group_key='http-positive')]
    class Root(Positive):
        id='test.root';families=('net_flow',);required_fields=()
    class Linked(ContextPlaybook):
        id='test.context_http';families=('http_tx',);link_types=('zeek_uid',)
        required_by_family: ClassVar = {'http_tx':('http.request.method',)}
        def match_linked(self,anchor,link,events):
            return [Match(self.id,'HTTP request directly recorded','network_observation',[event],
                [pf(event,'http.request.method')],event.ts,'high','high','high',group_key='context-http')
                for event in self.eligible_records(events)]
    conn=getattr(zf,shape)(replace(zf.Conn(),uid=zl.UID_HTTP,ts=zl.HTTP.ts,duration=60,missed_bytes=99),'conn')
    http=getattr(zl,shape)(zl.HTTP,'http')
    native=NativePivot(shape,[conn,http]);contract=native.contracts['network']
    backend=ZeekES({'network':[conn,http]},{'network':contract.time_field})
    engine=make_engine(tmp_path/'hunt.db');migrate(engine);repo=Repo(engine)
    repo.create_hunt('h',{'targets':['network']},'digest','test')
    root=normalize(shape,conn);original=normalize(shape,http);before=original.model_dump(mode='json')
    raw={f"{hit['_index']}/{hit['_id']}":hit['_source'] for hit in (conn,http)}
    candidate=publish_match(repo,'h',Root(),Match(Root.id,'connection observed','network_observation',[root],[],
        root.ts,'high','high','high'),None,raw)
    pivot=PivotExecutor(repo,ElasticClient(Settings(home=tmp_path),transport=backend.transport()),'h',{'network':contract},
        stage_dir=tmp_path/'stage')
    window=LinkWindow(label='test',start=root.ts-timedelta(minutes=1),end=root.ts+timedelta(minutes=5))
    fetcher=LinkFetcher(pivot,window.start,window.end)
    anchor=LinkAnchor(finding_id=candidate['id'],ts=root.ts,events=[root],event_ids=[root.id])
    result=fetcher.fetch(anchor,'zeek_uid',window)
    controller=ExpansionEngine(repo,'h',window,fetcher)
    controller._persist_link(result)
    monkeypatch.setattr(expansion_module,'fresh_direct_pack',lambda:[Positive()])
    monkeypatch.setattr(agent_tools,'fresh_direct_pack',lambda:[Positive()])
    if publication=='expansion':
        controller._evaluate(candidate,result)
    elif publication=='agent':
        tools=agent_tools.HuntToolExecutor(repo,'h',pivot,fetcher,window.start,window.end)
        tools._publish_direct('case-1',candidate,result,controller._events(result.event_ids))
    elif publication=='pivot':
        from romulus.agent.models import EntityRef
        from romulus.agent.tools import EntityTimelineArgs, EntityTimelineRequest
        monkeypatch.setattr(pivot_module,'fresh_direct_pack',lambda:[Positive()])
        request=EntityTimelineRequest(tool='entity_timeline',arguments=EntityTimelineArgs(
            entity=EntityRef(kind='ip',value=root.get('source.ip')),start=window.start,end=window.end))
        pivot.run('case-1',request,anchor_ts=root.ts)
    else:
        repo.mark_expansion_link_evaluated(result.id)
        monkeypatch.setattr(context_module,'fresh_context_pack',lambda:[Linked()])
        context_module.finalize_context(repo,'h')
    rows=[row for row in repo.candidates('h') if row['rule_id']==(Linked.id if publication=='context' else Positive.id)]
    assert len(rows)==1
    final=rows[0]
    assert final['lane']=='high'
    assert any('missed_bytes' in note and 'supporting record' in note for note in final['gate_results'].get('_notes',[]))
    assert root.id in final['event_ids'] and original.id in final['event_ids']
    assert repo.events_by_ids([original.id])[0]['event']==before
    from romulus.store.repo import raw_id
    assert list(repo.raw_records([raw_id(ref.target,ref.native_id) for ref in root.raw]))
    engine.dispose()

@pytest.mark.parametrize('bound',['queries','rows','keys'])
def test_file_only_second_hop_shares_first_hop_budgets(tmp_path,monkeypatch,bound):
    from romulus.hunt import zeek_gaps
    anchor=zl.malcolm(zl.PE,'pe');file=zl.malcolm(zl.FILES_50,'file')
    conn=zf.malcolm(replace(zf.Conn(),uid=zl.UID_HTTP,ts=zl.HTTP.ts-10,missed_bytes=99),'conn')
    native=NativePivot('malcolm',[anchor,file,conn]);contract=native.contracts['network']
    backend=ZeekES({'network':[file,conn]},{'network':contract.time_field})
    sweep=SimpleNamespace(contracts={'network':contract},site_facts=absent_site_facts(),
        client=ElasticClient(Settings(home=tmp_path),transport=backend.transport()))
    monkeypatch.setattr(zeek_gaps,{'queries':'MAX_QUERIES','rows':'MAX_ROWS','keys':'MAX_KEYS'}[bound],1)
    event=normalize('malcolm',anchor)
    match=Match('test','positive','network_observation',[event],[],event.ts,'high','urgent','high')
    raw={};enrich(sweep,match,raw)
    assert any('limit' in note or 'bound' in note or 'incomplete' in note for note in match.notes)
    assert not any('missed_bytes' in note for note in match.notes)
    assert normalize('malcolm',conn).id not in match.context_ids
    assert len(backend.queries)<=1
    assert match.proposed_lane=='urgent'


@pytest.mark.parametrize('shape',zf.SHAPES)
def test_file_only_second_hop_does_not_cross_sensor(tmp_path,shape):
    anchor=getattr(zl,shape)(zl.PE,'pe');file=getattr(zl,shape)(zl.FILES,'file')
    record=replace(zf.Conn(),uid=zl.UID_HTTP,ts=zl.HTTP.ts-10,missed_bytes=99)
    conn=zf.plain(record,'conn') if shape=='plain' else getattr(zf,shape)(record,'conn',sensor='other-sensor')
    native=NativePivot(shape,[anchor,file,conn]);contract=native.contracts['network']
    other=contract.model_copy(update={'target':'other','zeek_sensor':'other-sensor' if shape=='plain' else None})
    backend=ZeekES({'network':[file],'other':[conn]},
        {'network':contract.time_field,'other':contract.time_field})
    sweep=SimpleNamespace(contracts={'network':contract,'other':other},site_facts=absent_site_facts(),
        client=ElasticClient(Settings(home=tmp_path),transport=backend.transport()))
    event=normalize(shape,anchor);before=event.model_dump(mode='json')
    match=Match('test','positive','network_observation',[event],[],event.ts,'high','urgent','high')
    raw={};enrich(sweep,match,raw)
    assert not any('missed_bytes' in note for note in match.notes)
    assert match.events==[event] and event.model_dump(mode='json')==before


def test_context_carrier_key_workspace_is_bounded_before_collection():
    import tracemalloc

    from romulus.hunt.zeek_context import related
    event=normalize('malcolm',zl.malcolm(zl.FILES_50,'file'))
    event.fields['file.conn_uids'].value=[f'uid-{n:08d}' for n in range(100000)]
    match=Match('test','positive','network_observation',[event],[],event.ts,'high','urgent','high')
    tracemalloc.start()
    try:
        assert related(match,[event])==[event]
        _,peak=tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert any('join key limit' in note for note in match.notes)
    assert peak<1_000_000

@pytest.mark.parametrize('reader',['canonical','gaps'])
def test_shared_readers_name_unsearchable_source_markers(tmp_path,reader):
    from datetime import timedelta

    from romulus.hunt.sweep import Sweep
    from romulus.sources.models import Window
    from romulus.store.db import make_engine, migrate
    from romulus.store.repo import Repo

    anchor=(zf.malcolm(replace(zf.Conn(),uid=zl.UID_HTTP,ts=zl.HTTP.ts,duration=30),'interim',interim=True)
            if reader=='canonical' else zl.elastic(zl.HTTP,'http'))
    shape='malcolm' if reader=='canonical' else 'elastic'
    omitted=zf.elastic(replace(zf.Conn(),uid=zl.UID_HTTP,ts=zl.HTTP.ts,duration=60,missed_bytes=99),'omitted')
    second=NativePivot('elastic',[omitted]).contracts['network']
    fields=dict(second.fields)
    for path in ('event.dataset','data_stream.dataset'):
        fields[path]=fields[path].model_copy(update={'type':'text','ops':['exists','missing']})
    contracts={'network':NativePivot(shape,[anchor]).contracts['network'],
               'omitted-conn':second.model_copy(update={'target':'omitted-conn','fields':fields})}
    backend=ZeekES({'network':[anchor],'omitted-conn':[omitted]},
        {name:contract.time_field for name,contract in contracts.items()})
    event=normalize(shape,anchor);before=event.model_dump(mode='json')
    engine=make_engine(tmp_path/'hunt.db');migrate(engine);repo=Repo(engine)
    repo.create_hunt('h',{'targets':list(contracts)},'digest','test')
    sweep=Sweep(repo,ElasticClient(Settings(home=tmp_path),transport=backend.transport()),'h',
        Window(start=event.ts-timedelta(seconds=1),end=event.ts+timedelta(minutes=5)),contracts,
        stage_dir=tmp_path/'stage')
    try:
        if reader=='canonical':
            reasons=[];result=sweep._canonical_zeek([event],{},reasons)
            assert result and result[0].id==event.id
            notes=[reason for reason,_ in reasons]
        else:
            match=Match('test','positive','network_observation',[event],[],event.ts,'high','urgent','high')
            enrich(sweep,match,{})
            notes=match.notes
            assert match.proposed_lane=='urgent' and event.model_dump(mode='json')==before
        assert any('omitted-conn' in reason and 'source markers not searchable' in reason for reason in notes)
        assert not any('missed_bytes' in reason for reason in notes)
        assert all(target!='omitted-conn' for target,_ in backend.queries)
    finally:
        sweep.close_stage();engine.dispose()
