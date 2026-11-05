"""Visibility uses complete streamed source aggregates, with bounded Python state."""
import tracemalloc
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from romulus.sources.models import Window

T0 = datetime(2025, 1, 1, tzinfo=UTC)


def _observe(store, hits, contract, window):
    from romulus.evidence.normalize import normalize_hits
    events, _, errors = normalize_hits(hits, contract=contract)
    assert not errors
    store.observe(events, window)
    return events


def _conn(uid, service, *, sensor='sensor', interim=False, native_id=None, **fields):
    from tests.fixtures import zeek_factory as zf
    return zf.malcolm(replace(zf.Conn(),uid=uid,service=service,ts=T0.timestamp()+10,**fields),
                      native_id or uid,sensor=sensor,interim=interim)


@contextmanager
def _canonical_visibility(tmp_path, docs):
    from romulus.config import Settings
    from romulus.hunt.sweep import Sweep
    from romulus.sources.es import ElasticClient
    from romulus.store.db import make_engine, migrate
    from romulus.store.repo import Repo
    from tests.test_zeek_links import NativePivot
    from tests.zeek_source_support import ZeekES
    contracts={target:NativePivot('malcolm',hits).contracts['network'].model_copy(
        update={'target':target,'time_field':'@timestamp'}) for target,hits in docs.items()}
    backend=ZeekES(docs,{target:'@timestamp' for target in docs})
    engine=make_engine(tmp_path/'hunt.db');migrate(engine);repo=Repo(engine)
    repo.create_hunt('h',{'targets':list(docs)},'digest','test')
    window=Window(start=T0,end=T0+timedelta(minutes=15))
    sweep=Sweep(repo,ElasticClient(Settings(home=tmp_path),transport=backend.transport()),'h',window,
                contracts,stage_dir=tmp_path/'stage')
    sweep.pack=[]
    try:
        for target in docs:
            sweep.run_target(target)
        yield sweep._zeek_visibility_store()
    finally:
        sweep.close_stage();engine.dispose()


def test_sensor_health_threshold_missing_health_and_health_only(tmp_path):
    from romulus.hunt.zeek_visibility import VisibilityStore
    store = VisibilityStore(tmp_path)
    try:
        for sensor in ('good', 'lossy', 'missing'):
            store.activity(sensor, 'http_tx', T0.timestamp(), (T0 + timedelta(minutes=15)).timestamp(), 3)
        store.health('good', T0.timestamp(), (T0 + timedelta(minutes=15)).timestamp(), .99, 'capture loss')
        store.health('lossy', T0.timestamp(), (T0 + timedelta(minutes=15)).timestamp(), 1.01, 'capture loss')
        store.health('idle', T0.timestamp(), (T0 + timedelta(minutes=15)).timestamp(), 50, 'capture loss')
        rows = list(store.visibility(Window(start=T0, end=T0 + timedelta(minutes=15)), 1.0))
        assert {r['sensor']: r['partial'] for r in rows} == {'good': False, 'lossy': True, 'missing': True}
        assert '0.99 %' in next(r['reason'] for r in rows if r['sensor'] == 'good')
        assert 'no health record' in next(r['reason'] for r in rows if r['sensor'] == 'missing')
    finally:
        store.close()


def test_health_straddles_window_and_adjacent_intervals_merge(tmp_path):
    from romulus.hunt.zeek_visibility import VisibilityStore
    store = VisibilityStore(tmp_path)
    try:
        t = T0.timestamp()
        store.activity('sensor', 'dns_query', t, t+900, 2)
        store.activity('sensor', 'dns_query', t+900, t+1800, 3)
        store.health('sensor', t-120, t+2000, 2.3, 'capture loss')
        rows = list(store.visibility(Window(start=T0, end=T0+timedelta(minutes=30)), 1.0))
        assert len(rows) == 1
        assert rows[0]['start'] == T0.isoformat()
        assert rows[0]['end'] == (T0+timedelta(minutes=30)).isoformat()
        assert rows[0]['records'] == 5
    finally:
        store.close()


def test_analyzer_presence_joins_targets_and_conn_services_count_once(tmp_path):
    from tests.fixtures import zeek_logs as zl
    docs={f'copy-{i}':[_conn('uid1','gssapi,smb,krb,dce_rpc,ntlm',sensor='a',native_id=f'copy-{i}')]
          for i in range(3)}
    docs['other']=[_conn('uid2','smb,smb',sensor='b')]
    docs['analyzer']=[zl.malcolm(replace(zl.SMB_FILES,ts=T0.timestamp()+20),'smb',sensor='a')]
    with _canonical_visibility(tmp_path,docs) as store:
        gaps = list(store.analyzer_gaps())
        assert not any(g['sensor'] == 'a' and g['family'] == 'smb_tx' for g in gaps)
        assert {(g['sensor'], g['family'], g['connections']) for g in gaps} == {
            ('a', 'kerberos_tx', 1), ('a', 'rpc_tx', 1), ('b', 'smb_tx', 1)}


def test_million_distinct_spans_collapse_to_sensor_family_grid(tmp_path):
    from romulus.hunt.zeek_visibility import VisibilityStore
    store=VisibilityStore(tmp_path)
    tracemalloc.start()
    count=0
    try:
        for n in range(1_000_000):
            sensor=f'sensor-{n//1000:04d}'; offset=n%1000
            start=T0.timestamp()+offset*.5
            if offset==0:
                store.health(sensor,T0.timestamp(),T0.timestamp()+900,.5 if n%2000 else 2.3,'capture loss')
            store.activity(sensor,'http_tx' if offset%2 else 'net_flow',start,start+.25,1)
            count+=1
        store.checkpoint()
        assert store.db.execute('SELECT count(*) FROM activity').fetchone()[0]==2000
        rows=records=0
        for row in store.visibility(Window(start=T0,end=T0+timedelta(minutes=15)),1.0):
            rows+=1
            records+=row['records']
        assert rows==2000
        assert records==1_000_000
        _,peak=tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
        store.close()
    assert count == 1_000_000
    assert not store.reasons
    assert peak < 8_000_000


def test_composite_exhaustion_is_named_and_never_complete():
    from romulus.hunt.zeek_visibility import composite_pages
    class Source:
        def search(self, target, body):
            return {'aggregations': {'visibility': {'buckets': [{'key': {'n': 1}, 'doc_count': 4}], 'after_key': {'n': 1}}}}
    reasons = []
    assert len(list(composite_pages(Source(), 'network', {'aggs': {'visibility': {'composite': {}}}}, reasons,
                                    max_pages=1))) == 1
    assert any('page limit' in reason for reason in reasons)

@pytest.mark.parametrize('shape', ['malcolm','elastic','security_onion','plain'])
def test_streamed_facts_join_source_health_per_sensor(tmp_path, shape):
    from dataclasses import replace

    from romulus.config import Settings
    from romulus.hunt.zeek_visibility import VisibilityStore, collect_visibility
    from romulus.site import ZeekPolicy
    from romulus.sources.es import ElasticClient
    from tests.fixtures import zeek_factory as zf
    from tests.test_zeek_links import NativePivot
    from tests.zeek_source_support import ZeekES
    conn = getattr(zf,shape)(replace(zf.Conn(),ts=T0.timestamp()+60,service='smb,dns',duration=10), 'conn')
    hits=[conn]
    if shape=='plain':
        health={'_path':'capture_loss','ts':T0.timestamp()+900,'peer':'worker','ts_delta':900,'gaps':23,'acks':1000,'percent_lost':'2.3'}
    elif shape=='malcolm':
        health={'@timestamp':'2025-01-01T00:15:00Z','event':{'provider':'zeek','dataset':'capture_loss'},'node':zf.SENSOR,
                'zeek':{'capture_loss':{'peer':'worker','ts_delta':900,'gaps':23,'acks':1000,'percent_lost':'2.3'}}}
    elif shape=='elastic':
        health={'@timestamp':'2025-01-01T00:15:00Z','event':{'dataset':'zeek.capture_loss'},'data_stream':{'dataset':'zeek.capture_loss'},
                'agent':{'name':zf.SENSOR},'zeek':{'capture_loss':{'peer':'worker','ts_delta':900,'gaps':23,'acks':1000,'percent_lost':'2.3'}}}
    else:
        health=None
    if health:
        hits.append({'_index':'network','_id':'health','_source':health})
    pivot=NativePivot(shape,hits)
    contract=pivot.contracts['network'].model_copy(update={'time_field':'ts' if shape=='plain' else '@timestamp'})
    backend=ZeekES({'network':hits},{'network':contract.time_field})
    client=ElasticClient(Settings(home=tmp_path),transport=backend.transport())
    store=VisibilityStore(tmp_path)
    try:
        window=Window(start=T0,end=T0+timedelta(minutes=15))
        _observe(store,hits,contract,window)
        collect_visibility(client,{'network':contract},window,store,ZeekPolicy(),activity=False)
        rows=list(store.visibility(window,1.0))
        assert rows and all(row['partial'] for row in rows)
        assert any(('no health record' if shape=='security_onion' else '2.3 % capture loss') in row['reason'] for row in rows)
        assert {row['family'] for row in store.analyzer_gaps()} == {'smb_tx','dns_query'}
        assert all('visibility' in body['aggs'] and body['size']==0 for _,body in backend.queries)
    finally:
        store.close()


def test_visibility_snapshot_is_durable_streamed_and_immutable_after_stage_close(tmp_path):
    from romulus.store.db import make_engine, migrate
    from romulus.store.repo import Repo
    engine=make_engine(tmp_path/'hunt.db'); migrate(engine); repo=Repo(engine)
    repo.create_hunt('h', {'targets':[]}, 'digest', 'test')
    rows=({'sensor':f'sensor-{i:06}', 'family':'http_tx', 'partial':True, 'start':T0.isoformat(),
           'end':(T0+timedelta(minutes=15)).isoformat(), 'reason':f'sensor {i} missing health', 'records':1}
          for i in range(10001))
    descriptor=repo.save_zeek_visibility('h',rows)
    assert descriptor['count']==10001
    fresh=Repo(engine)
    assert sum(1 for _ in fresh.zeek_visibility_rows('h',descriptor['sha256']))==10001
    second=repo.save_zeek_visibility('h',iter([{'sensor':'later','family':'http_tx','partial':False,'reason':'later'}]))
    assert second['sha256']!=descriptor['sha256']
    assert next(fresh.zeek_visibility_rows('h',descriptor['sha256']))['sensor']=='sensor-000000'


def test_real_sweep_writes_sensor_scoped_cells_and_durable_interval_reference(tmp_path):
    from dataclasses import replace

    from romulus.config import Settings
    from romulus.hunt.sweep import Sweep
    from romulus.sources.es import ElasticClient
    from romulus.store.db import make_engine, migrate
    from romulus.store.repo import Repo
    from tests.fixtures import zeek_factory as zf
    from tests.test_zeek_links import NativePivot
    from tests.zeek_source_support import ZeekES
    hits=[]
    for sensor,loss in [('healthy',.99),('lossy',1.01)]:
        hits.append(zf.malcolm(replace(zf.Conn(),ts=T0.timestamp()+60,duration=10,uid='C'+sensor),sensor,sensor=sensor))
        hits.append({'_index':'network','_id':'health-'+sensor,'_source':{'@timestamp':'2025-01-01T00:15:00Z',
            'event':{'provider':'zeek','dataset':'capture_loss'},'node':sensor,'zeek':{'capture_loss':{
                'peer':'worker','ts_delta':900,'gaps':1,'acks':1000,'percent_lost':loss}}}})
    native=NativePivot('malcolm',hits)
    contract=native.contracts['network'].model_copy(update={'time_field':'@timestamp'})
    backend=ZeekES({'network':hits},{'network':'@timestamp'})
    client=ElasticClient(Settings(home=tmp_path),transport=backend.transport())
    engine=make_engine(tmp_path/'hunt.db'); migrate(engine); repo=Repo(engine)
    repo.create_hunt('h',{'targets':['network']},'digest','test')
    sweep=Sweep(repo,client,'h',Window(start=T0,end=T0+timedelta(minutes=15)),{'network':contract},stage_dir=tmp_path)
    try:
        sweep.run_target('network')
        sweep.finalize()
        cells=repo.rule_cells('h',rule_id='net.outbound_volume_asymmetry')
        sensor_cells={cell['detail']['sensor']:cell for cell in cells if cell['detail'].get('sensor')}
        assert sensor_cells['healthy']['state']=='evaluated_complete'
        assert sensor_cells['lossy']['state']=='evaluated_partial'
        ref=repo.latest_audit('h','hunt.zeek_visibility')['detail']['snapshot']
    finally:
        sweep.close_stage()
    rows=list(repo.zeek_visibility_rows('h',ref['sha256']))
    assert any('0.99 %' in row['reason'] for row in rows)
    assert any(row['sensor']=='lossy' and row['partial'] for row in rows)

@pytest.mark.parametrize('final_first',[False,True])
def test_analyzer_counts_final_service_even_empty_supersedes_interim_across_sources(tmp_path,final_first):
    earlier=[_conn('one','smb',interim=True,duration=1,missed_bytes=8,native_id='one-interim'),
             _conn('two','dns',interim=True,duration=1,missed_bytes=9,native_id='two-interim')]
    later=[_conn('one','',duration=2,missed_bytes=0,native_id='one-final'),
           _conn('two','ssh',interim=True,duration=2,missed_bytes=12,native_id='two-latest')]
    docs={'first':later if final_first else earlier,'second':earlier if final_first else later}
    with _canonical_visibility(tmp_path,docs) as store:
        gaps=list(store.analyzer_gaps())
        assert [(row['family'],row['connections']) for row in gaps]==[('ssh_session',1)]
        assert [(row['family'],row['connections']) for row in store.content_gaps()]==[('ssh_session',1)]
        assert sum(row['records'] for row in store.visibility(Window(start=T0,end=T0+timedelta(minutes=15)),1))==2

def test_content_gap_counts_are_separate_from_analyzer_absence(tmp_path):
    from tests.fixtures import zeek_logs as zl
    docs={'flows':[_conn('one','http',sensor='s',missed_bytes=8),
                   _conn('two','http,dns',sensor='s',history='ShADg')],
          'duplicate':[_conn('one','http',sensor='s',missed_bytes=8,native_id='copy')],
          'http':[zl.malcolm(replace(zl.HTTP,ts=T0.timestamp()+20),'http',sensor='s')]}
    with _canonical_visibility(tmp_path,docs) as store:
        gaps=list(store.content_gaps())
        http=next(row for row in gaps if row['family']=='http_tx')
        assert http['connections']==2
        assert '2 connections had content gaps' in http['reason']
        assert not http['partial']
        assert not any(row['family']=='http_tx' for row in store.analyzer_gaps())

def test_stats_interval_deltas_need_declared_cadence_and_complete_continuity(tmp_path):
    from romulus.hunt.zeek_visibility import VisibilityStore
    store=VisibilityStore(tmp_path)
    try:
        start=T0.timestamp()
        store.activity('s','http_tx',start,start+300,1)
        store.stats('s','worker',start,100,1000)
        store.stats('s','worker',start+300,1,1000)
        store.resolve_stats(300,complete=True)
        row=next(store.visibility(Window(start=T0,end=T0+timedelta(seconds=300)),1.0))
        assert not row['partial']
        assert '0.1 % packet drop' in row['reason']
        assert 'capture loss' not in row['reason']
    finally:
        store.close()

@pytest.mark.parametrize('shape',['malcolm','elastic','plain'])
@pytest.mark.parametrize('mode',['valid','no_cadence','missing_interval','other_worker','lossy'])
def test_native_stats_only_health_requires_complete_same_worker_interval(tmp_path,shape,mode):
    from dataclasses import replace

    from romulus.config import Settings
    from romulus.hunt.zeek_visibility import VisibilityStore, collect_visibility
    from romulus.site import ZeekPolicy
    from romulus.sources.es import ElasticClient
    from tests.fixtures import zeek_factory as zf
    from tests.test_zeek_links import NativePivot
    from tests.zeek_source_support import ZeekES
    hits=[getattr(zf,shape)(replace(zf.Conn(),ts=T0.timestamp()+30,duration=5),'conn')]
    for i,offset in enumerate([0,600 if mode=='missing_interval' else 300]):
        worker='other' if i and mode=='other_worker' else 'worker'
        dropped=20 if mode=='lossy' else 1
        raw={'peer':worker,'pkts_dropped':dropped,'pkts_link':1000}
        stamp=(T0+timedelta(seconds=offset)).isoformat()
        if shape=='plain':
            source={'_path':'stats','ts':T0.timestamp()+offset,**raw}
        elif shape=='malcolm':
            source={'@timestamp':stamp,'event':{'provider':'zeek','dataset':'stats'},'node':zf.SENSOR,'zeek':{'stats':raw}}
        else:
            source={'@timestamp':stamp,'event':{'dataset':'zeek.stats'},'data_stream':{'dataset':'zeek.stats'},
                    'agent':{'name':zf.SENSOR},'zeek':{'stats':{'peer':worker,'packets':{'dropped':dropped,'received':1000}}}}
        hits.append({'_index':'network','_id':str(i),'_source':source})
    native=NativePivot(shape,hits)
    contract=native.contracts['network'].model_copy(update={'time_field':'ts' if shape=='plain' else '@timestamp'})
    backend=ZeekES({'network':hits},{'network':contract.time_field})
    client=ElasticClient(Settings(home=tmp_path),transport=backend.transport())
    store=VisibilityStore(tmp_path)
    window=Window(start=T0,end=T0+timedelta(seconds=300))
    try:
        _observe(store,hits,contract,window)
        collect_visibility(client,{'network':contract},window,store,
            ZeekPolicy(stats_interval_seconds=None if mode=='no_cadence' else 300),activity=False)
        rows=list(store.visibility(window,1))
        assert rows and all(row['partial']==(mode!='valid') for row in rows)
        if mode in ('valid','lossy'):
            assert any(('2 % packet drop' if mode=='lossy' else '0.1 % packet drop') in row['reason'] for row in rows)
            assert not any('no health record' in row['reason'] for row in rows)
        else:
            assert any('no health record' in row['reason'] for row in rows)
    finally:
        store.close()

def test_incomplete_analyzer_inventory_never_claims_absence(tmp_path):
    with _canonical_visibility(tmp_path,{'flows':[_conn('uid','smb',sensor='s')]}) as store:
        store.reasons.append('source composite page limit reached')
        row=next(store.analyzer_gaps())
        assert 'have no smb_* records in scope' not in row['reason']
        assert 'unresolved' in row['reason'] and row['partial']


def test_custom_security_onion_native_health_target_uses_explicit_site_declaration(tmp_path):
    from dataclasses import replace

    from romulus.config import Settings
    from romulus.evidence.normalize import normalize_hits
    from romulus.hunt.zeek_visibility import VisibilityStore, collect_visibility
    from romulus.site import _facts, _SiteDocument
    from romulus.sources.es import ElasticClient
    from romulus.sources.profile import apply_zeek_declaration, contract_from_types
    from tests.fixtures import zeek_factory as zf
    from tests.test_zeek_links import NativePivot, types_of
    from tests.zeek_source_support import ZeekES
    data=zf.security_onion(replace(zf.Conn(),ts=T0.timestamp()+10,duration=20),'conn')
    # A custom collector writes the ORIGINAL Zeek JSON; no SO indexed metrics fields are invented.
    raw={'ts':T0.timestamp()+900,'peer':'worker','ts_delta':900,'percent_lost':0.5,'gaps':5,'acks':1000}
    health={'_index':'original-health','_id':'health','_source':raw}
    site=_facts(_SiteDocument.model_validate({'schema':'romulus-site-collection@1','zeek':{
        'plain_sources':{'original-health':{'sensor':zf.SENSOR,'log':'capture_loss'}}}}))
    native=NativePivot('security_onion',[data])
    contracts={**native.contracts,'original-health':apply_zeek_declaration(
        contract_from_types('original-health',types_of(raw)),site)}
    backend=ZeekES({'network':[data],'original-health':[health]},
                   {'network':'@timestamp','original-health':'ts'})
    client=ElasticClient(Settings(home=tmp_path),transport=backend.transport())
    store=VisibilityStore(tmp_path)
    window=Window(start=T0,end=T0+timedelta(minutes=15))
    try:
        _observe(store,[data],contracts['network'],window)
        collect_visibility(client,contracts,window,store,site.zeek,activity=False)
        rows=list(store.visibility(window,1))
        assert rows and all(not row['partial'] for row in rows)
        assert all('0.5 % capture loss' in row['reason'] for row in rows)
        assert normalize_hits([health],contract=contracts['original-health'])[0][0].family=='sensor_health'
        assert normalize_hits([health])[0]==[]
    finally:
        store.close()


@pytest.mark.parametrize('log,field',[('conn','duration'),('files','missing_bytes')])
def test_malformed_stream_measurement_is_named_instead_of_aborting_visibility(tmp_path,log,field):
    from romulus.config import Settings
    from romulus.hunt.zeek_visibility import VisibilityStore, collect_visibility
    from romulus.site import ZeekPolicy
    from romulus.sources.es import ElasticClient
    from romulus.sources.profile import contract_from_types
    from tests.zeek_source_support import ZeekES
    source={'_path':log,'ts':T0.timestamp()+10,'uid':'uid','fuid':'file','service':'smb',field:'invalid'}
    contract=contract_from_types('native',{'_path':'keyword','ts':'double','uid':'keyword','fuid':'keyword',
        'service':'keyword',field:'keyword'}).model_copy(update={'zeek_sensor':'sensor','time_field':'ts','role':'network'})
    backend=ZeekES({'native':[{'_index':'native','_id':'bad','_source':source}]},{'native':'ts'})
    store=VisibilityStore(tmp_path)
    try:
        window=Window(start=T0,end=T0+timedelta(minutes=15))
        events=_observe(store,backend.docs['native'],contract,window)
        assert field in events[0].get('parse.malformed')
        collect_visibility(ElasticClient(Settings(home=tmp_path),transport=backend.transport()),{'native':contract},
            window,store,ZeekPolicy(),activity=False)
        assert any('malformed' in reason for reason in store.reasons)
        assert all('have no' not in row['reason'] for row in store.analyzer_gaps())
    finally:
        store.close()


def test_visibility_disk_ceiling_is_named(tmp_path):
    from romulus.detect.bounded import StateBudget
    from romulus.hunt.zeek_visibility import VisibilityStore
    budget=StateBudget(tmp_path,disk_total=200000)
    store=VisibilityStore(tmp_path,budget=budget)
    try:
        for i in range(5000):
            store.activity(f'sensor-{i:06d}','http_tx',T0.timestamp(),T0.timestamp()+900,1)
        store.checkpoint()
        assert store.path.stat().st_size<=200000
        assert any('disk state incomplete' in reason for reason in store.reasons)
    finally:
        store.close()


@pytest.mark.parametrize('case',['long_loss','long_missing','rdp_rfb','separate_logs','filebeat'])
def test_native_sweep_visibility_preserves_span_log_and_shipper_identity(tmp_path,case):
    from dataclasses import replace

    from romulus.config import Settings
    from romulus.detect.base import Playbook
    from romulus.hunt.sweep import Sweep
    from romulus.sources.es import ElasticClient
    from romulus.store.db import make_engine, migrate
    from romulus.store.repo import Repo
    from tests.fixtures import zeek_factory as zf
    from tests.fixtures import zeek_logs as zl
    from tests.test_zeek_links import NativePivot
    from tests.zeek_source_support import ZeekES
    class Probe(Playbook):
        id='test.visibility';families=('net_flow','http_tx','remote_session')
        def match(self,event):
            return []
    window=Window(start=T0,end=T0+timedelta(minutes=45))
    conn=zf.elastic(replace(zf.Conn(),ts=T0.timestamp()+60,duration=1800 if case.startswith('long') else 30,
                           service='rdp' if case=='rdp_rfb' else 'smb'),'conn')
    http=zl.elastic(replace(zl.HTTP,ts=T0.timestamp()+60),'http',filebeat=case=='filebeat')
    health=[]
    for i in range(1,4):
        if case=='long_missing' and i==2:
            continue
        health.append(zl.elastic(replace(zl.CAPTURE_LOSS.with_(percent_lost=2.3 if case=='long_loss' and i==2 else 0),
            ts=T0.timestamp()+i*900),f'health-{i}',filebeat=case=='filebeat'))
    docs={'http':[http],'health':health} if case in ('filebeat','separate_logs') else {'conn':[conn],'health':health}
    if case=='separate_logs':
        docs['conn']=[conn]
    if case=='rdp_rfb':
        docs['rfb']=[zl.elastic(replace(zl.RFB,ts=T0.timestamp()+60),'rfb')]
    contracts={target:NativePivot('elastic',hits).contracts['network'].model_copy(update={'target':target})
               for target,hits in docs.items()}
    backend=ZeekES(docs,{target:'@timestamp' for target in docs})
    engine=make_engine(tmp_path/'hunt.db');migrate(engine);repo=Repo(engine)
    repo.create_hunt('h',{'targets':list(docs)},'digest','test')
    sweep=Sweep(repo,ElasticClient(Settings(home=tmp_path),transport=backend.transport()),'h',window,contracts,
                stage_dir=tmp_path/'stage');sweep.pack=[Probe()]
    try:
        for target in docs:
            sweep.run_target(target)
        sweep.finalize()
        cells=repo.rule_cells('h',rule_id=Probe.id)
        detail=repo.latest_audit('h','hunt.zeek_visibility')['detail']
        rows=list(repo.zeek_visibility_rows('h',detail['snapshot']['sha256']))
        assert not detail['unresolved']
        assert {row['sensor'] for row in rows}=={zf.SENSOR}
        if case.startswith('long'):
            flow=[row for row in rows if row['family']=='net_flow']
            assert any(row['partial'] for row in flow)
            assert any(('2.3 %' if case=='long_loss' else 'no health record') in row['reason'] for row in flow)
            assert max(datetime.fromisoformat(row['end']) for row in flow)>=T0+timedelta(minutes=31)
            assert any(cell['state']=='evaluated_partial' and cell['detail'].get('sensor')==zf.SENSOR for cell in cells)
        elif case=='rdp_rfb':
            assert any('have no rdp records' in row['reason'] for row in rows)
            assert any(cell['state']=='evaluated_partial' and cell['detail'].get('sensor')==zf.SENSOR for cell in cells)
        else:
            http_rows=[row for row in rows if row['family']=='http_tx']
            assert sum(row.get('records',0) for row in http_rows)==1
            assert all(not row['partial'] for row in http_rows)
            if case=='filebeat':
                assert all(cell['state']=='evaluated_complete' for cell in cells if cell['detail'].get('sensor'))
    finally:
        sweep.close_stage();engine.dispose()


def test_zeek_capable_empty_target_adds_no_queries_state_or_expansion_slots(tmp_path):
    from romulus.config import Settings
    from romulus.hunt.expansion import ExpansionEngine
    from romulus.hunt.links import LinkFetcher
    from romulus.hunt.pivot import PivotExecutor
    from romulus.hunt.sweep import Sweep
    from romulus.sources.es import ElasticClient
    from romulus.sources.profile import contract_from_types
    from romulus.store.db import make_engine, migrate
    from romulus.store.repo import Repo
    from tests.zeek_source_support import ZeekES
    traces=[]
    for mapped in (False,True):
        home=tmp_path/str(mapped);home.mkdir()
        fields={'@timestamp':'date','event.dataset':'keyword','event.provider':'keyword','node':'keyword'}
        if mapped:
            fields.update({'zeek.uid':'keyword','zeek.conn.duration':'double','network.protocol':'keyword'})
        contract=contract_from_types('network',fields,role='network',os_family='unknown')
        backend=ZeekES({'network':[]},{'network':'@timestamp'})
        client=ElasticClient(Settings(home=home),transport=backend.transport())
        engine=make_engine(home/'hunt.db');migrate(engine);repo=Repo(engine)
        window=Window(start=T0,end=T0+timedelta(hours=1))
        repo.create_hunt('h',{'targets':['network']},'digest','test')
        repo.save_profile('h',{'id':'empty','target':'network','kind':'elastic','role':'network',
                               'datasets':{},'doc_count':0,'notes':[]})
        sweep=Sweep(repo,client,'h',window,{'network':contract},stage_dir=home/'stage')
        try:
            sweep.run_target('network')
            assert getattr(sweep,'_stage',None) is None
            assert repo.latest_audit('h','hunt.zeek_visibility') is None
            pivot=PivotExecutor(repo,client,'h',{'network':contract},stage_dir=home/'pivot')
            controller=ExpansionEngine(repo,'h',window,LinkFetcher(pivot,window.start,window.end))
            assert controller._tier_slots([],{},1)==[]
            traces.append(backend.queries)
        finally:
            sweep.close_stage();engine.dispose()
    assert traces[0]==traces[1]

@pytest.mark.parametrize('layout',['filebeat','filebeat_mapped','agent_both','stream_only','stream_only_mapped','mixed','mixed_health'])
def test_native_mixed_markers_keep_http_loss_and_analyzer_presence(tmp_path,layout):
    from dataclasses import replace

    from romulus.config import Settings
    from romulus.detect.base import Playbook
    from romulus.hunt.sweep import Sweep
    from romulus.sources.es import ElasticClient
    from romulus.store.db import make_engine, migrate
    from romulus.store.repo import Repo
    from tests.fixtures import zeek_factory as zf
    from tests.fixtures import zeek_logs as zl
    from tests.test_zeek_links import NativePivot
    from tests.zeek_source_support import ZeekES

    class Probe(Playbook):
        id='test.marker_visibility';families=('http_tx',)
        def match(self,event):
            return []
    filebeat=layout.startswith(('filebeat','mixed'))
    http=zl.elastic(replace(zl.HTTP,ts=T0.timestamp()+60),'http',filebeat=filebeat)
    health=zl.elastic(replace(zl.CAPTURE_LOSS.with_(percent_lost=2.3),ts=T0.timestamp()+900),'health',
                      filebeat=filebeat and layout!='mixed_health')
    hits=[http,health]
    if layout=='mixed':
        hits.append(zf.elastic(replace(zf.Conn(),uid=zl.UID_HTTP,ts=T0.timestamp()+60,service='http',duration=30),'conn'))
    original=NativePivot('elastic',hits).contracts['network']
    if layout.startswith('stream_only'):
        for hit in hits:
            hit['_source']['event'].pop('dataset')
    contract=NativePivot('elastic',hits).contracts['network']
    if layout=='stream_only_mapped':
        contract.fields['event.dataset']=original.fields['event.dataset']
    if layout=='filebeat_mapped':
        agent=NativePivot('elastic',[zl.elastic(zl.HTTP,'agent')]).contracts['network']
        contract.fields['data_stream.dataset']=agent.fields['data_stream.dataset']
    backend=ZeekES({'network':hits},{'network':'@timestamp'})
    engine=make_engine(tmp_path/'hunt.db');migrate(engine);repo=Repo(engine)
    repo.create_hunt('h',{'targets':['network']},'digest','test')
    window=Window(start=T0,end=T0+timedelta(minutes=15))
    sweep=Sweep(repo,ElasticClient(Settings(home=tmp_path),transport=backend.transport()),'h',window,
                {'network':contract},stage_dir=tmp_path/'stage');sweep.pack=[Probe()]
    try:
        sweep.run_target('network')
        sweep.finalize()
        detail=repo.latest_audit('h','hunt.zeek_visibility')['detail']
        rows=list(repo.zeek_visibility_rows('h',detail['snapshot']['sha256']))
        http_rows=[row for row in rows if row['family']=='http_tx']
        assert sum(row.get('records',0) for row in http_rows)==1
        assert any(row['partial'] and '2.3 %' in row['reason'] for row in http_rows)
        assert not any('have no http records' in row['reason'] for row in rows)
        assert not detail['unresolved']
        cells=repo.rule_cells('h',rule_id=Probe.id)
        assert any(cell['state']=='evaluated_partial' and cell['detail'].get('sensor')==zf.SENSOR for cell in cells)
        assert sum(cell['evaluated'] for cell in cells)>=1
    finally:
        sweep.close_stage();engine.dispose()


@pytest.mark.parametrize('mapped_stream',[False,True])
@pytest.mark.parametrize('with_health',[False,True])
def test_native_exclusive_dataset_only_conn_and_health_are_collected(tmp_path,mapped_stream,with_health):
    from dataclasses import replace

    from romulus.config import Settings
    from romulus.hunt.zeek_visibility import VisibilityStore, collect_visibility
    from romulus.site import ZeekPolicy
    from romulus.sources.es import ElasticClient
    from tests.fixtures import zeek_factory as zf
    from tests.fixtures import zeek_logs as zl
    from tests.test_zeek_links import NativePivot, normalize
    from tests.zeek_source_support import ZeekES

    hits=[zf.elastic(replace(zf.Conn(),ts=T0.timestamp()+60,duration=30),'conn')]
    if with_health:
        hits.append(zl.elastic(replace(zl.CAPTURE_LOSS.with_(percent_lost=2.3),ts=T0.timestamp()+900),'health'))
    original=NativePivot('elastic',hits).contracts['network']
    for hit in hits:
        hit['_source'].pop('data_stream')
        assert normalize('elastic',hit) is not None
    contract=NativePivot('elastic',hits).contracts['network']
    if mapped_stream:
        contract.fields['data_stream.dataset']=original.fields['data_stream.dataset']
    backend=ZeekES({'network':hits},{'network':'@timestamp'})
    store=VisibilityStore(tmp_path/'stage');window=Window(start=T0,end=T0+timedelta(minutes=15))
    try:
        _observe(store,hits,contract,window)
        collect_visibility(ElasticClient(Settings(home=tmp_path),transport=backend.transport()),
                           {'network':contract},window,store,ZeekPolicy(),activity=False)
        rows=list(store.visibility(window,1.0))
        assert rows and all(row['partial'] for row in rows)
        assert any(('2.3 %' if with_health else 'no health record') in row['reason'] for row in rows)
        assert not store.reasons
    finally:
        store.close()
