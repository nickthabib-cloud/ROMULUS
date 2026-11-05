"""Selective cumulative-flow canonicalization must precede rule consumption."""
from dataclasses import replace
from datetime import UTC, datetime, timedelta

from romulus.config import Settings
from romulus.hunt.sweep import Sweep
from romulus.sources.es import ElasticClient
from romulus.sources.models import Window
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo
from tests.fixtures import zeek_factory as zf
from tests.test_zeek_links import NativePivot, normalize
from tests.zeek_source_support import ZeekES


def test_interim_resolves_final_across_target_before_first_consumption(tmp_path):
    interim=zf.malcolm(replace(zf.Conn(),orig_bytes=600_000_000,duration=1),'interim',interim=True)
    final=zf.malcolm(replace(zf.Conn(),orig_bytes=700_000_000,duration=2),'final')
    pivot=NativePivot('malcolm',[interim,final])
    contract=pivot.contracts['network'].model_copy(update={'time_field':'@timestamp'})
    contracts={'a':contract.model_copy(update={'target':'a'}),'b':contract.model_copy(update={'target':'b'})}
    backend=ZeekES({'a':[interim],'b':[final]},{'a':'@timestamp','b':'@timestamp'})
    client=ElasticClient(Settings(home=tmp_path),transport=backend.transport())
    engine=make_engine(tmp_path/'hunt.db');migrate(engine);repo=Repo(engine)
    repo.create_hunt('h',{'targets':['a','b']},'digest','test')
    now=datetime.fromtimestamp(zf.T0,UTC)
    sweep=Sweep(repo,client,'h',Window(start=now-timedelta(minutes=1),end=now+timedelta(minutes=5)),contracts,stage_dir=tmp_path)
    try:
        raw={}; reasons=[]
        first=sweep._canonical_zeek([normalize('malcolm',interim)],raw,reasons)
        assert len(first)==1 and first[0].get('conn.interim') is not True
        assert first[0].get('flow.bytes_toserver')==700_000_000
        assert any(ref.native_id=='final' for ref in first[0].raw)
        assert sweep._canonical_zeek([normalize('malcolm',final)],raw,reasons)==[]
        assert len(backend.queries)==2
    finally:
        sweep.close_stage()

import pytest


@pytest.mark.parametrize('shape',zf.SHAPES)
@pytest.mark.parametrize('inventory',['absent','complete','stale_empty','partial','partial_empty','unknown'])
def test_real_sweep_connection_lookback_is_bounded_and_does_not_pull_old_analyzers(tmp_path,shape,inventory):
    from tests.fixtures import zeek_logs as zl
    writer=getattr(zf,shape)
    now=datetime.fromtimestamp(zf.T0,UTC)
    hits=[writer(replace(zf.Conn(),uid='inside',ts=zf.T0-23*3600,duration=23*3600+30),'inside'),
          writer(replace(zf.Conn(),uid='outside',ts=zf.T0-25*3600,duration=25*3600+30),'outside'),
          writer(replace(zf.Conn(),uid='boundary',ts=zf.T0-3600,duration=3600),'boundary'),
          getattr(zl,shape)(replace(zl.HTTP,ts=zf.T0-3600),'old-http')]
    if inventory=='stale_empty':
        hits.append(writer(replace(zf.Conn(),uid='newly-observed',duration=30),'newly-observed'))
    pivot=NativePivot(shape,hits)
    contract=pivot.contracts['network'].model_copy(update={'time_field':'ts' if shape=='plain' else '@timestamp'})
    backend=ZeekES({'network':hits},{'network':contract.time_field})
    client=ElasticClient(Settings(home=tmp_path),transport=backend.transport())
    engine=make_engine(tmp_path/'hunt.db');migrate(engine);repo=Repo(engine)
    repo.create_hunt('h',{'targets':['network']},'digest','test')
    if inventory!='absent':
        repo.save_profile('h',{'id':'profile','kind':'es_index','target':'network','doc_count':None if inventory=='unknown' else 0 if inventory in ('stale_empty','partial_empty') else len(hits),
            'datasets':{'zeek:conn':3} if inventory=='complete' else {},
            'notes':['ds inventory truncated'] if inventory in ('partial','partial_empty') else []})
    sweep=Sweep(repo,client,'h',Window(start=now,end=now+timedelta(minutes=5)),{'network':contract},stage_dir=tmp_path)
    seen=[]
    original=sweep._canonical_zeek
    def observe(events,raw,reasons):
        result=original(events,raw,reasons);seen.extend(result);return result
    sweep._canonical_zeek=observe
    try:
        sweep.run_target('network')
        expected={'inside','newly-observed'} if inventory=='stale_empty' else {'inside'}
        assert {event.get('zeek.uid') for event in seen if event.get('zeek.log')=='conn'}==expected
        assert not any(event.get('zeek.log')=='http' for event in seen)
    finally:
        sweep.close_stage()

@pytest.mark.parametrize('canonical_refused',[False,True])
@pytest.mark.parametrize('final_first',[False,True])
@pytest.mark.parametrize('final_present',[False,True])
def test_real_rules_consume_one_cumulative_flow_and_publish_strong_ioc_immediately(tmp_path,final_first,final_present,canonical_refused):
    from romulus.detect.indicators import IndicatorMatch, load_indicators
    first=zf.malcolm(replace(zf.Conn(),orig_bytes=30*2**20,resp_bytes=1,duration=1),'earlier',interim=True)
    last=zf.malcolm(replace(zf.Conn(),orig_bytes=40*2**20,resp_bytes=1,duration=2),'latest',interim=not final_present)
    rows=[last,first] if final_first else [first,last]
    native=NativePivot('malcolm',rows)
    contract=native.contracts['network'].model_copy(update={'time_field':'@timestamp'})
    contracts={key:contract.model_copy(update={'target':key}) for key in ('a','b')}
    backend=ZeekES({'a':[rows[0]],'b':[rows[1]]},{'a':'@timestamp','b':'@timestamp'})
    client=ElasticClient(Settings(home=tmp_path),transport=backend.transport())
    engine=make_engine(tmp_path/'hunt.db');migrate(engine);repo=Repo(engine)
    repo.create_hunt('h',{'targets':['a','b']},'digest','test')
    now=datetime.fromtimestamp(zf.T0,UTC)
    sweep=Sweep(repo,client,'h',Window(start=now-timedelta(seconds=1),end=now+timedelta(minutes=5)),contracts,stage_dir=tmp_path/'stage')
    indicator_dir=tmp_path/'indicators';indicator_dir.mkdir()
    (indicator_dir/'list.yaml').write_text('schema_version: 1\nindicators:\n  - {id: test.ip, kind: ip, '
        'values: [203.0.113.10], label: synthetic address, severity: high, lane: high}\n',encoding='utf-8')
    rule=IndicatorMatch(load_indicators(indicator_dir));rule.spill_dir=tmp_path/'stage';rule.budget=sweep.budget
    rule.window_start=sweep.window.start
    sweep.pack=[rule if pb.id==rule.id else pb for pb in sweep.pack]
    from romulus.detect.base import Match, Playbook
    class ImmediateProbe(Playbook):
        id='test.zeek_immediate'
        families=('net_flow',)
        required_fields=()
        def consume(self,events):
            self.evaluated+=len(events)
            return [Match(self.id,'recorded direct test positive','network_observation',[event],[],event.ts,
                          'high','high','high') for event in events]
    probe=ImmediateProbe();sweep.pack.append(probe)
    if canonical_refused:
        stage=sweep._event_stage();bounded_write=stage._write
        def refuse_identity(operation,count,*args,**kwargs):
            if operation.__name__ in ('create','remember'):
                stage.refused+=count
                stage.refusal_reason='test canonical identity byte ceiling'
                return
            return bounded_write(operation,count,*args,**kwargs)
        stage._write=refuse_identity
    try:
        sweep.run_target('a')
        assert rule.evaluated==1
        if canonical_refused:
            assert any(row['rule_id']==rule.id for row in repo.candidates('h'))
        assert any(row['rule_id']==probe.id for row in repo.candidates('h'))
        sweep.run_target('b');sweep.finalize()
        assert not any(row['rule_id']=='net.outbound_volume_asymmetry' for row in repo.candidates('h'))
        cells=repo.rule_cells('h',rule_id='net.outbound_volume_asymmetry')
        assert sum(row['evaluated'] for row in cells if row['target'] in ('a','b'))==(0 if canonical_refused else 1)
        if canonical_refused:
            assert any('canonical-flow disk state' in reason for row in cells for reason in row['detail'].get('reasons',[]))
        candidates=[row for row in repo.candidates('h') if row['rule_id']==rule.id]
        evidence=[item['event'] for row in candidates for item in repo.events_by_ids(row['event_ids'])]
        expected_bytes=(40 if final_first else 30)*2**20 if canonical_refused else 40*2**20
        assert any(event['fields']['flow.bytes_toserver']['value']==expected_bytes for event in evidence)
        if canonical_refused:
            assert all(row['claim'].startswith('1 net_flow record') for row in candidates)
            assert any('canonical-flow disk state' in note for row in candidates for note in row['gate_results'].get('_notes',[]))
    finally:
        sweep.close_stage()

def test_old_interim_recovered_by_verified_malcolm_end_timestamp(tmp_path):
    now=datetime.fromtimestamp(zf.T0,UTC)
    row=zf.malcolm(replace(zf.Conn(),ts=zf.T0-25*3600,duration=25*3600+60),'old-open',interim=True)
    native=NativePivot('malcolm',[row]);contract=native.contracts['network']
    backend=ZeekES({'network':[row]},{'network':'firstPacket'})
    client=ElasticClient(Settings(home=tmp_path),transport=backend.transport())
    engine=make_engine(tmp_path/'hunt.db');migrate(engine);repo=Repo(engine)
    repo.create_hunt('h',{'targets':['network']},'digest','test')
    sweep=Sweep(repo,client,'h',Window(start=now,end=now+timedelta(minutes=5)),{'network':contract},stage_dir=tmp_path)
    seen=[];original=sweep._canonical_zeek
    def observe(events,raw,reasons):
        result=original(events,raw,reasons);seen.extend(result);return result
    sweep._canonical_zeek=observe
    try:
        sweep.run_target('network')
        assert len(seen)==1 and seen[0].get('conn.interim') is True
        assert seen[0].ts<now-timedelta(hours=24)
        assert any('lastPacket' in str(body['query']) for _,body in backend.queries)
    finally:
        sweep.close_stage()


def test_canonical_state_budget_refusal_is_named_and_does_not_delay_positive(tmp_path):
    hit=zf.malcolm(zf.Conn(),'conn')
    native=NativePivot('malcolm',[hit])
    engine=make_engine(tmp_path/'hunt.db');migrate(engine);repo=Repo(engine)
    repo.create_hunt('h',{'targets':['network']},'digest','test')
    now=datetime.fromtimestamp(zf.T0,UTC)
    sweep=Sweep(repo,None,'h',Window(start=now-timedelta(seconds=1),end=now+timedelta(minutes=5)),
                native.contracts,stage_dir=tmp_path/'stage')
    try:
        sweep._event_stage()
        sweep.budget.disk_total=1
        reasons=[]
        events=sweep._canonical_zeek([normalize('malcolm',hit)],{},reasons)
        assert len(events)==1
        assert any('canonical-flow disk state' in reason for reason,_ in reasons)
    finally:
        sweep.close_stage()


def test_unaggregated_ioc_refusal_preserves_retained_group_count_and_exact_record(tmp_path):
    from romulus.detect.indicators import IndicatorMatch, load_indicators
    indicator_dir=tmp_path/'indicators';indicator_dir.mkdir()
    (indicator_dir/'list.yaml').write_text('schema_version: 1\nindicators:\n  - {id: test.ip, kind: ip, '
        'values: [203.0.113.10], label: synthetic address, severity: high, lane: high}\n',encoding='utf-8')
    rule=IndicatorMatch(load_indicators(indicator_dir));rule.spill_dir=tmp_path
    first=normalize('malcolm',zf.malcolm(replace(zf.Conn(),orig_bytes=30*2**20),'first',interim=True))
    last=normalize('malcolm',zf.malcolm(replace(zf.Conn(),orig_bytes=40*2**20),'last'))
    try:
        assert rule.consume([first])==[]
        keys=list(rule.groups.keys())
        assert len(keys)==1 and rule.groups.peek(keys[0])[0]==1
        findings=rule.consume_unaggregated([last],'canonical-flow disk state unavailable; totals withheld')
        assert len(findings)==1 and findings[0].claim.startswith('1 net_flow record')
        assert findings[0].events[0].id==last.id and findings[0].proposed_lane=='high'
        assert 'totals withheld' in findings[0].notes[-1]
        assert rule.groups.peek(keys[0])[0]==1
        assert list(rule.groups.keys())==keys
    finally:
        rule.close_spill()


@pytest.mark.parametrize('declared',['CONN','conn_long'])
def test_fixed_plain_alias_queries_and_normalizes_native_connection(tmp_path,declared):
    from romulus.hunt.zeek_visibility import VisibilityStore, collect_visibility
    from romulus.site import _facts, _SiteDocument
    from romulus.sources.profile import apply_zeek_declaration, contract_from_types
    from tests.test_zeek_links import types_of
    hit=zf.plain(replace(zf.Conn(),ts=zf.T0-3600,duration=3700),'conn')
    hit['_source'].pop('_path',None)
    facts=_facts(_SiteDocument.model_validate({'schema':'romulus-site-collection@1','zeek':{
        'plain_sources':{'native':{'sensor':zf.SENSOR,'log':declared}}}}))
    contract=apply_zeek_declaration(contract_from_types('native',types_of(hit['_source'])),facts)
    backend=ZeekES({'native':[hit]},{'native':'ts'})
    client=ElasticClient(Settings(home=tmp_path),transport=backend.transport())
    engine=make_engine(tmp_path/'hunt.db');migrate(engine);repo=Repo(engine)
    repo.create_hunt('h',{'targets':['native']},'digest','test')
    now=datetime.fromtimestamp(zf.T0,UTC);window=Window(start=now,end=now+timedelta(minutes=5))
    sweep=Sweep(repo,client,'h',window,{'native':contract},stage_dir=tmp_path/'stage')
    seen=[];original=sweep._canonical_zeek
    def observe(events,raw,reasons):
        result=original(events,raw,reasons);seen.extend(result);return result
    sweep._canonical_zeek=observe
    try:
        sweep.run_target('native')
        assert len(seen)==1
        assert (seen[0].get('conn.interim') is True)==(declared=='conn_long')
        store=VisibilityStore(tmp_path/'visibility')
        try:
            store.observe(seen,window)
            collect_visibility(client,{'native':contract},window,store,facts.zeek,activity=False)
            rows=list(store.visibility(window,1))
            assert len(rows)==1 and rows[0]['family']=='net_flow' and rows[0]['records']==1
            assert rows[0]['start']==now.isoformat()
            assert datetime.fromisoformat(rows[0]['end'])>=now+timedelta(seconds=100)
            assert {(row['family'],row['connections']) for row in store.analyzer_gaps()}=={('tls_session',1)}
        finally:
            store.close()
    finally:
        sweep.close_stage();engine.dispose()

@pytest.mark.parametrize('inventory_representation',['dataset_terms','provider_inventory'])
def test_profile_cannot_hide_stream_only_pre_window_connection(tmp_path,inventory_representation):
    from collections import Counter

    import httpx

    from romulus.sources.profile import build_profile
    from tests.test_zeek_links import types_of
    from tests.zeek_source_support import value

    now=datetime.fromtimestamp(zf.T0,UTC)
    hit=zf.elastic(replace(zf.Conn(),ts=zf.T0-3600,duration=3700),'stream-only')
    field_types=types_of(hit['_source'])
    del hit['_source']['event']['dataset']
    assert normalize('elastic',hit).get('zeek.log')=='conn'
    properties={}
    for field,kind in field_types.items():
        parent=properties;parts=field.split('.')
        for part in parts[:-1]:
            parent=parent.setdefault(part,{'properties':{}})['properties']
        parent[parts[-1]]={'type':kind}

    class ProfileSource(ZeekES):
        def __call__(self,request):
            if request.method=='GET' and request.url.path=='/network/_mapping':
                return httpx.Response(200,json={'network':{'mappings':{'properties':properties}}})
            return super().__call__(request)
        def aggregate(self,spec,docs):
            if 'terms' in spec:
                cfg=spec['terms'];counts=Counter()
                for row in docs:
                    raw=value(row['_source'],cfg['field'])
                    counts.update(set(raw if isinstance(raw,list) else [raw])-{None})
                items=sorted(counts.items(),key=lambda pair:(-pair[1],pair[0]))
                size=cfg.get('size',10)
                return {'buckets':[{'key':key,'doc_count':count} for key,count in items[:size]],
                        'sum_other_doc_count':sum(count for _,count in items[size:])}
            return super().aggregate(spec,docs)

    backend=ProfileSource({'network':[hit]},{'network':'@timestamp'})
    client=ElasticClient(Settings(home=tmp_path),transport=backend.transport())
    profile,contract=build_profile(client,'network')
    assert profile.doc_count==1 and profile.datasets=={} and profile.notes==[]
    assert 'event.dataset' in contract.fields and 'data_stream.dataset' in contract.fields
    assert any(body.get('aggs',{}).get('ds',{}).get('terms',{}).get('field')=='event.dataset'
               for _,body in backend.queries)
    frozen=profile.model_dump(mode='json')
    if inventory_representation=='provider_inventory':
        # The same missing dataset can occupy a null provider/dataset inventory bucket.
        frozen['inventory']=[{'provider':None,'dataset':None,'records':1}]
    engine=make_engine(tmp_path/'hunt.db');migrate(engine);repo=Repo(engine)
    repo.create_hunt('h',{'targets':['network']},'digest','test');repo.save_profile('h',frozen)
    sweep=Sweep(repo,client,'h',Window(start=now,end=now+timedelta(minutes=5)),
                {'network':contract},stage_dir=tmp_path/'stage')
    seen=[];original=sweep._canonical_zeek
    def observe(events,raw,reasons):
        selected=original(events,raw,reasons);seen.extend(selected);return selected
    sweep._canonical_zeek=observe
    try:
        sweep.run_target('network')
        assert [(event.get('zeek.uid'),event.get('zeek.log')) for event in seen]==[(zf.Conn().uid,'conn')]
        assert seen[0].ts<now and datetime.fromisoformat(seen[0].get('flow.end'))>now
        assert any(cell['evaluated']>0 for cell in repo.rule_cells('h'))
    finally:
        sweep.close_stage();engine.dispose()

@pytest.mark.parametrize('mapped_stream',[False,True])
def test_native_exclusive_dataset_only_connection_lookback(tmp_path,mapped_stream):
    hit=zf.elastic(replace(zf.Conn(),ts=zf.T0-3600,duration=3700),'old-conn')
    original=NativePivot('elastic',[hit]).contracts['network']
    hit['_source'].pop('data_stream')
    contract=NativePivot('elastic',[hit]).contracts['network']
    if mapped_stream:
        contract.fields['data_stream.dataset']=original.fields['data_stream.dataset']
    backend=ZeekES({'network':[hit]},{'network':'@timestamp'})
    engine=make_engine(tmp_path/'hunt.db');migrate(engine);repo=Repo(engine)
    repo.create_hunt('h',{'targets':['network']},'digest','test')
    now=datetime.fromtimestamp(zf.T0,UTC)
    sweep=Sweep(repo,ElasticClient(Settings(home=tmp_path),transport=backend.transport()),'h',
        Window(start=now,end=now+timedelta(minutes=5)),{'network':contract},stage_dir=tmp_path/'stage')
    seen=[];original_canonical=sweep._canonical_zeek
    def observe(events,raw,reasons):
        selected=original_canonical(events,raw,reasons);seen.extend(selected);return selected
    sweep._canonical_zeek=observe
    try:
        sweep.run_target('network')
        assert len(seen)==1 and seen[0].get('zeek.uid')==zf.Conn().uid
        assert seen[0].ts<now and any(cell['evaluated']>0 for cell in repo.rule_cells('h'))
    finally:
        sweep.close_stage();engine.dispose()
