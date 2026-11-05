"""Observed Zeek joins and lease-backed host hypotheses in native shipper shapes."""
from dataclasses import replace
from datetime import timedelta

import pytest

from romulus.evidence.normalize import normalize_hits
from romulus.evidence.zeek import normalize_plain_zeek
from romulus.hunt.links import LinkAnchor, LinkFetcher, LinkWindow, is_agent_reach
from romulus.hunt.pivot import PivotEventBatch
from romulus.sources.compile import build_query
from romulus.sources.profile import contract_from_types
from tests.fixtures import zeek_factory as zf
from tests.fixtures import zeek_logs as zl


def normalize(shape, hit):
    return normalize_plain_zeek(hit, sensor=zl.SENSOR) if shape == 'plain' else normalize_hits([hit])[0][0]


def types_of(source, prefix=''):
    out = {}
    for key, value in source.items():
        name = prefix+key
        if isinstance(value, dict):
            out.update(types_of(value, name+'.'))
        else:
            out[name] = ('date' if name == '@timestamp' else 'boolean' if isinstance(value, bool)
                         else 'double' if isinstance(value, float) else 'long' if isinstance(value, int) else 'keyword')
    return out


class NativePivot:
    def __init__(self, shape, hits):
        self.shape, self.hits = shape, hits
        native = {'@timestamp': 'date'}
        for hit in hits:
            native.update(types_of(hit['_source']))
        self.contracts = {'network': contract_from_types('network', native, role='network')}
        if shape == 'plain':
            self.contracts['network'] = self.contracts['network'].model_copy(update={
                'zeek_sensor': zl.SENSOR, 'time_field': 'ts'})
        self.events = [normalize(shape, hit) for hit in hits]
        self.source_queries = 0
        self.calls = []
        self.saved = []

    def fetch_intents(self, owner, fetch_key, intents, retain, **options):
        events = {}
        returned = 0
        for intent in intents:
            build_query(intent, self.contracts[intent.target])
            self.calls.append(intent)
            self.source_queries += 1
            for event in self.events:
                if intent.window.start <= event.ts < intent.window.end and retain(event):
                    events[event.id] = event
                    returned += 1
        return PivotEventBatch('complete', ['task'], list(events.values()), {}, [], [], 1)

    def save_batch_selection(self, batch, events):
        self.saved.extend(events)


def fetch(pivot, root, kind):
    anchor = LinkAnchor(finding_id='finding', ts=root.ts, events=[root], event_ids=[root.id])
    window = LinkWindow(label='test', start=root.ts-timedelta(minutes=5), end=root.ts+timedelta(minutes=5))
    return LinkFetcher(pivot, window.start, window.end).fetch(anchor, kind, window)


@pytest.mark.parametrize('shape', zl.SHAPES)
def test_certificate_uses_first_fingerprint_and_looks_back_for_deduplicated_x509(shape):
    writer = getattr(zl, shape)
    ssl = writer(zl.SSL, 'ssl')
    cert = writer(replace(zl.X509, ts=zl.SSL.ts-86400), 'cert')
    pivot = NativePivot(shape, [ssl, cert])
    root = normalize(shape, ssl)
    result = fetch(pivot, root, 'certificate')
    assert normalize(shape, cert).id in result.event_ids
    assert result.strength == 'observed'
    assert not is_agent_reach(result.link_type, result.strength)
    assert any(intent.window.start <= root.ts-timedelta(days=1) for intent in pivot.calls)
    assert all(intent.max_records <= 10000 for intent in pivot.calls)


@pytest.mark.parametrize('shape', zl.SHAPES)
def test_missing_certificate_is_unresolved_not_an_absence_claim(shape):
    pivot = NativePivot(shape, [getattr(zl, shape)(zl.SSL, 'ssl')])
    result = fetch(pivot, pivot.events[0], 'certificate')
    assert result.status == 'partial'
    assert 'certificate details not in scope' in result.reasons


@pytest.mark.parametrize('shape', zl.SHAPES)
def test_uid_join_is_sensor_scoped_and_includes_analyzer_records(shape):
    row = zl.HTTP
    writer = getattr(zl, shape)
    conn = getattr(zf, shape)(replace(zf.Conn(), uid=row.zeek['uid'], ts=row.ts, duration=60), 'conn')
    http = writer(row, 'http')
    pivot = NativePivot(shape, [conn, http])
    root = normalize(shape, conn)
    foreign = normalize(shape, http).model_copy(deep=True)
    foreign.id = 'foreign-sensor'
    foreign.host = 'other-sensor'
    foreign.fields['observer.name'].value = 'other-sensor'
    pivot.events.append(foreign)
    result = fetch(pivot, root, 'zeek_uid')
    assert normalize(shape, http).id in result.event_ids
    assert 'foreign-sensor' not in result.event_ids
    assert result.strength == 'observed'

@pytest.mark.parametrize('shape', zl.SHAPES)
@pytest.mark.parametrize('legacy', [False, True])
def test_file_join_reaches_pe_and_every_carrying_connection(shape, legacy):
    writer = getattr(zl, shape)
    row = zl.FILES_50.with_(conn_uids=[zl.UID_HTTP, 'Csecond']) if legacy else zl.FILES
    hits = [writer(row, 'file'), writer(zl.PE, 'pe')]
    hits += [getattr(zf, shape)(replace(zf.Conn(), uid=uid, ts=row.ts, duration=60), uid)
             for uid in ([zl.UID_HTTP, 'Csecond'] if legacy else [zl.UID_HTTP])]
    pivot = NativePivot(shape, hits)
    result = fetch(pivot, pivot.events[0], 'zeek_file')
    assert {e.id for e in pivot.events[1:]} <= set(result.event_ids)
    assert result.strength == 'observed'


def host_event(name, when):
    from romulus.evidence.typed import RawRef, TypedEvent, fv
    return TypedEvent(id='host-'+name, family='process_exec', ts=when, host=name,
        fields={'host.name': fv(name, 'host.name'), 'process.name': fv('bash', 'process.name')},
        raw=[RawRef(target='hosts', native_id=name)], normalizer='linux-ecs@1')


@pytest.mark.parametrize('shape', zl.SHAPES)
def test_dhcp_lease_at_anchor_maps_only_a_host_telemetry_witness_as_hypothesis(shape):
    writer = getattr(zl, shape)
    lease = zl.DHCP.with_(assigned_addr=zf.Conn().orig_h, host_name='workstation', lease_time=1800)
    conn = getattr(zf, shape)(replace(zf.Conn(), ts=lease.ts+60), 'anchor')
    pivot = NativePivot(shape, [writer(lease, 'lease'), conn])
    witness = host_event('workstation', pivot.events[-1].ts)
    pivot.events.append(witness)
    pivot.contracts['hosts'] = contract_from_types('hosts', {'@timestamp':'date', 'event.dataset':'keyword',
        'host.name':'keyword'}, role='host', os_family='linux', hosts=('workstation',))
    result = fetch(pivot, normalize(shape, conn), 'address_host')
    assert witness.id in result.event_ids
    assert pivot.events[0].id in result.evidence_ids
    assert result.strength == 'inferred'
    assert any('hypothesis' in reason.lower() for reason in result.reasons)
    assert not is_agent_reach(result.link_type, result.strength)


@pytest.mark.parametrize('shape', zl.SHAPES)
def test_overlapping_conflicting_leases_remain_unresolved_with_both_cited(shape):
    writer = getattr(zl, shape)
    first = zl.DHCP.with_(assigned_addr=zf.Conn().orig_h, host_name='first', lease_time=1800)
    second = first.with_(host_name='second', mac='02:00:00:00:00:22')
    conn = getattr(zf, shape)(replace(zf.Conn(), ts=first.ts+60), 'anchor')
    pivot = NativePivot(shape, [writer(first, 'one'), writer(second, 'two'), conn])
    result = fetch(pivot, normalize(shape, conn), 'address_host')
    assert result.status == 'partial'
    assert {pivot.events[0].id,pivot.events[1].id} <= set(result.evidence_ids)
    assert any('conflicting' in reason and 'first' in reason and 'second' in reason for reason in result.reasons)


def test_real_pivot_shared_row_bound_does_not_split_or_rescan_100000_files(tmp_path, monkeypatch):
    from romulus.hunt.pivot import PivotExecutor
    from romulus.sources.models import Completeness, SearchIntent, SearchOutcome, Window
    from romulus.store.db import make_engine, migrate
    from romulus.store.repo import Repo
    engine = make_engine(tmp_path/'hunt.db')
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt('h', {'targets': []}, 'digest', 'test')
    template = zl.malcolm(zl.FILES, 'file')
    native = NativePivot('malcolm', [template])
    executor = PivotExecutor(repo, None, 'h', native.contracts, stage_dir=tmp_path)
    calls = []
    root = normalize('malcolm', template)
    def execute(intent, contract, **kwargs):
        calls.append(intent)
        executor.source_queries += 1
        rows = [zl.malcolm(zl.FILES.with_(fuid=f'F{i}'), str(i)) for i in range(intent.max_records)]
        return SearchOutcome(target='network', fingerprint='query', started_at=root.ts, ended_at=root.ts,
            completeness=Completeness.partial, reasons=[f'cap:{len(rows)}<total:100000'], total=100000,
            total_relation='eq', returned=len(rows), records=rows)
    monkeypatch.setattr(executor, '_execute', execute)
    intent = SearchIntent(kind='raw', target='network', window=Window(start=root.ts-timedelta(seconds=1),
        end=root.ts+timedelta(seconds=1)), max_records=10000, purpose='test')
    batch = executor.fetch_intents('anchor', 'key', [intent,intent], lambda event: True,
                                  persist=False, max_total_records=10000)
    assert len(calls) == 1
    assert len(batch.events) <= 10000
    assert sum(c.returned for c in batch.coverage) <= 10000
    assert batch.status == 'partial'
    assert any('shared' in reason and '10000' in reason for reason in batch.reasons)

def test_expansion_derives_zeek_keys_only_from_explicit_zeek_observers():
    from romulus.hunt.expansion import ExpansionEngine
    event=normalize('malcolm',zl.malcolm(zl.SSL,'ssl'))
    assert ExpansionEngine._event_link_keys(event,'certificate')==[
        {'sensor':zl.SENSOR,'fingerprint':event.get('tls.server.cert_chain_fps')[0]}]
    other=event.model_copy(update={'fields':{key:value for key,value in event.fields.items() if key!='observer.product'}})
    assert ExpansionEngine._event_link_keys(other,'certificate')==[]

@pytest.mark.parametrize('shape',zl.SHAPES)
@pytest.mark.parametrize('kind',['zeek_uid','zeek_file','certificate'])
def test_real_pivot_applies_native_sensor_key_time_queries_for_each_observed_link(tmp_path,shape,kind):
    from romulus.config import Settings
    from romulus.hunt.pivot import PivotExecutor
    from romulus.sources.es import ElasticClient
    from romulus.store.db import make_engine, migrate
    from romulus.store.repo import Repo
    from tests.zeek_source_support import ZeekES
    writer=getattr(zl,shape)
    if kind=='certificate':
        hits=[writer(zl.SSL,'ssl'),writer(replace(zl.X509,ts=zl.SSL.ts-86400),'cert')]
    elif kind=='zeek_file':
        hits=[writer(zl.FILES_50.with_(conn_uids=[zl.UID_HTTP,'Csecond']),'files'),writer(zl.PE,'pe')]
        hits += [getattr(zf,shape)(replace(zf.Conn(),uid=uid,ts=zl.FILES.ts,duration=60),uid)
                 for uid in (zl.UID_HTTP,'Csecond')]
    else:
        hits=[getattr(zf,shape)(replace(zf.Conn(),uid=zl.UID_HTTP,ts=zl.HTTP.ts,duration=60),'conn'),writer(zl.HTTP,'http')]
    native=NativePivot(shape,hits)
    contract=native.contracts['network'].model_copy(update={'time_field':'ts' if shape=='plain' else '@timestamp'})
    backend=ZeekES({'network':hits},{'network':contract.time_field})
    client=ElasticClient(Settings(home=tmp_path),transport=backend.transport())
    engine=make_engine(tmp_path/'hunt.db');migrate(engine);repo=Repo(engine)
    repo.create_hunt('h',{'targets':['network']},'digest','test')
    pivot=PivotExecutor(repo,client,'h',{'network':contract},stage_dir=tmp_path)
    result=fetch(pivot,native.events[0],kind)
    assert {event.id for event in native.events[1:]}<=set(result.event_ids)
    assert result.status=='complete',result.reasons
    assert backend.queries and result.query_spend>0
    assert all('bool' in body['query'] for _,body in backend.queries)

@pytest.mark.parametrize('shape',zl.SHAPES)
def test_real_dhcp_half_open_lease_changes_and_host_witness(tmp_path,shape):
    from romulus.config import Settings
    from romulus.hunt.pivot import PivotExecutor
    from romulus.sources.es import ElasticClient
    from romulus.store.db import make_engine, migrate
    from romulus.store.repo import Repo
    from tests.zeek_source_support import ZeekES
    first=zl.DHCP.with_(assigned_addr=zf.Conn().orig_h,host_name='first',lease_time=60)
    second=replace(first.with_(host_name='second',mac='02:00:00:00:00:22'),ts=first.ts+60)
    writer=getattr(zl,shape)
    conns=[getattr(zf,shape)(replace(zf.Conn(),ts=first.ts+seconds,uid='C'+str(seconds)),str(seconds)) for seconds in (59,60)]
    hits=[writer(first,'first'),writer(second,'second'),*conns]
    native=NativePivot(shape,hits)
    network=native.contracts['network'].model_copy(update={'time_field':'ts' if shape=='plain' else '@timestamp'})
    hosts=[]
    for name in ('first','second'):
        stamp=first.ts+30
        raw=f'type=USER_LOGIN msg=audit({stamp}:1): pid=900 uid=0 auid=1001 ses=42 acct="alice" exe="/usr/sbin/sshd" addr=203.0.113.8 res=success'
        hosts.append({'_index':'hosts','_id':name,'_source':{'@timestamp':zf.iso_ms(stamp),'host':{'name':name},
                     'event':{'dataset':'linux.audit','original':raw}}})
    host=contract_from_types('hosts',{'@timestamp':'date','event.dataset':'keyword','host.name':'keyword'},
                             role='host',os_family='linux',hosts=('first','second'))
    backend=ZeekES({'network':hits,'hosts':hosts},{'network':network.time_field,'hosts':'@timestamp'})
    client=ElasticClient(Settings(home=tmp_path),transport=backend.transport())
    engine=make_engine(tmp_path/'hunt.db');migrate(engine);repo=Repo(engine)
    repo.create_hunt('h',{'targets':['network','hosts']},'digest','test')
    pivot=PivotExecutor(repo,client,'h',{'network':network,'hosts':host},stage_dir=tmp_path)
    for conn,name in zip(conns,('first','second'),strict=True):
        result=fetch(pivot,normalize(shape,conn),'address_host')
        assert result.status=='complete',result.reasons
        events=[item['event'] for item in repo.events_by_ids(result.event_ids)]
        assert any(item['host']==name and item['family']=='auth' for item in events)
        assert not any(item['host']!=name and item['family']=='auth' for item in events)
        assert any('hypothesis' in reason for reason in result.reasons)

@pytest.mark.parametrize('query_limit',[1,2])
def test_native_link_budget_counts_physical_pages_and_stops_before_next_page(tmp_path,query_limit):
    from romulus.config import Settings
    from romulus.hunt.pivot import PivotExecutor
    from romulus.sources.es import ElasticClient
    from romulus.store.db import make_engine, migrate
    from romulus.store.repo import Repo
    from tests.zeek_source_support import ZeekES
    conn=zf.malcolm(replace(zf.Conn(),uid=zl.UID_HTTP,ts=zl.FILES.ts,duration=60),'conn')
    hits=[conn]+[zl.malcolm(zl.FILES.with_(fuid=f'F{i}'),str(i)) for i in range(6000)]
    native=NativePivot('malcolm',hits)
    contract=native.contracts['network'].model_copy(update={'time_field':'@timestamp'})
    backend=ZeekES({'network':hits},{'network':'@timestamp'})
    client=ElasticClient(Settings(home=tmp_path),transport=backend.transport())
    engine=make_engine(tmp_path/'hunt.db');migrate(engine);repo=Repo(engine)
    repo.create_hunt('h',{'targets':['network']},'digest','test')
    pivot=PivotExecutor(repo,client,'h',{'network':contract},stage_dir=tmp_path)
    root=normalize('malcolm',conn)
    anchor=LinkAnchor(finding_id='finding',ts=root.ts,events=[root],event_ids=[root.id])
    window=LinkWindow(label='test',start=root.ts-timedelta(minutes=1),end=root.ts+timedelta(minutes=5))
    result=LinkFetcher(pivot,window.start,window.end).fetch(anchor,'zeek_uid',window,query_cap=query_limit)
    assert len(backend.queries)<=query_limit
    assert result.status=='partial'
    assert any('query' in reason and ('budget' in reason or 'limit' in reason) for reason in result.reasons)

@pytest.mark.parametrize('shape',zl.SHAPES)
def test_agreeing_renewals_without_host_witness_remain_named_unresolved(shape):
    writer=getattr(zl,shape)
    lease=zl.DHCP.with_(assigned_addr=zf.Conn().orig_h,host_name='workstation',lease_time=1800)
    conn=getattr(zf,shape)(replace(zf.Conn(),ts=lease.ts+60),'conn')
    pivot=NativePivot(shape,[writer(lease,'one'),writer(replace(lease,ts=lease.ts+30),'renewal'),conn])
    result=fetch(pivot,normalize(shape,conn),'address_host')
    assert result.status=='partial'
    assert not any('conflicting' in reason for reason in result.reasons)
    # no host telemetry is searchable here, so the witness never ran: no absence is stated
    assert any('not searched to completion' in reason for reason in result.reasons)
    assert not any('matches no host-telemetry host' in reason for reason in result.reasons)
    assert {pivot.events[0].id,pivot.events[1].id}<=set(result.evidence_ids)


def test_conflicting_partial_lease_identity_is_unresolved_instead_of_sort_failure():
    lease=zl.DHCP.with_(assigned_addr=zf.Conn().orig_h,host_name='same',lease_time=1800)
    conn=zf.malcolm(replace(zf.Conn(),ts=lease.ts+60),'conn')
    pivot=NativePivot('malcolm',[zl.malcolm(lease,'one'),zl.malcolm(lease.with_(mac=None),'missing'),conn])
    result=fetch(pivot,normalize('malcolm',conn),'address_host')
    assert result.status=='partial'
    assert any('unknown MAC' in reason for reason in result.reasons)


def test_native_multihop_file_link_caps_distinct_carrier_keys(tmp_path):
    from romulus.config import Settings
    from romulus.hunt.pivot import PivotExecutor
    from romulus.sources.es import ElasticClient
    from romulus.store.db import make_engine, migrate
    from romulus.store.repo import Repo
    from tests.zeek_source_support import ZeekES
    carriers=[f'carrier-{i:04d}' for i in range(1002)]
    file=zl.malcolm(zl.FILES.with_(uid=None,conn_uids=carriers),'file')
    hits=[file]+[zf.malcolm(replace(zf.Conn(),uid=uid),'conn-'+uid) for uid in carriers]
    native=NativePivot('malcolm',hits)
    backend=ZeekES({'network':hits},{'network':'@timestamp'})
    client=ElasticClient(Settings(home=tmp_path),transport=backend.transport())
    engine=make_engine(tmp_path/'hunt.db');migrate(engine);repo=Repo(engine)
    repo.create_hunt('h',{'targets':['network']},'digest','test')
    pivot=PivotExecutor(repo,client,'h',native.contracts,stage_dir=tmp_path/'stage')
    result=fetch(pivot,normalize('malcolm',file),'zeek_file')
    assert result.status=='partial'
    assert any('hop-key limit 1000' in reason for reason in result.reasons)
    # The first FUID consumes one shared key; no more than999 carrier UIDs reach the source.
    def terms(query):
        if isinstance(query,dict):
            if 'terms' in query and 'zeek.uid' in query['terms']:
                yield query['terms']['zeek.uid']
            for value in query.values():
                yield from terms(value)
        elif isinstance(query,list):
            for value in query:
                yield from terms(value)
    queried=[values for _,body in backend.queries for values in terms(body)]
    assert queried and max(map(len,queried))<=999


@pytest.mark.parametrize('shape,unsearchable',[(shape,field) for shape in zl.SHAPES
    for field in ('sensor','uid','markers') if not (shape=='plain' and field=='sensor')])
def test_native_uid_link_names_relevant_unsearchable_target(tmp_path,shape,unsearchable):
    from romulus.config import Settings
    from romulus.evidence.zeek_catalog import HTTP
    from romulus.hunt.pivot import PivotExecutor
    from romulus.sources.es import ElasticClient
    from romulus.store.db import make_engine, migrate
    from romulus.store.repo import Repo
    from tests.zeek_source_support import ZeekES
    conn=getattr(zf,shape)(replace(zf.Conn(),uid=zl.UID_HTTP,ts=zl.HTTP.ts,duration=60),'conn')
    http=getattr(zl,shape)(zl.HTTP,'http')
    native=NativePivot(shape,[conn]);second=NativePivot(shape,[http])
    paths=HTTP.sensor_paths[shape] if unsearchable=='sensor' else HTTP.spec('zeek.uid').paths[shape]
    if unsearchable=='markers':
        paths=('_path',) if shape=='plain' else ('event.provider','event.dataset','data_stream.dataset','event.module','fileset.name')
    fields=dict(second.contracts['network'].fields)
    for path in paths:
        if path in fields:
            fields[path]=fields[path].model_copy(update={'type':'text','ops':['exists','missing']})
    contracts={'a':native.contracts['network'].model_copy(update={'target':'a'}),
        'omitted-http':second.contracts['network'].model_copy(update={'target':'omitted-http','fields':fields}),
        'unrelated':contract_from_types('unrelated',{'@timestamp':'date','host.name':'keyword',
                                                   'event.dataset':'text','data_stream.dataset':'text'})}
    backend=ZeekES({'a':[conn],'omitted-http':[http],'unrelated':[]},
        {target:'ts' if shape=='plain' and target!='unrelated' else '@timestamp' for target in contracts})
    engine=make_engine(tmp_path/'hunt.db');migrate(engine);repo=Repo(engine)
    repo.create_hunt('h',{'targets':list(contracts)},'digest','test')
    pivot=PivotExecutor(repo,ElasticClient(Settings(home=tmp_path),transport=backend.transport()),'h',contracts,
                        stage_dir=tmp_path/'stage')
    result=fetch(pivot,normalize(shape,conn),'zeek_uid')
    assert result.status=='partial'
    assert any('omitted-http' in reason and 'not searchable' in reason for reason in result.reasons)
    assert not any('unrelated' in reason for reason in result.reasons)
    engine.dispose()

@pytest.mark.parametrize('mapped_stream',[False,True])
def test_native_pivot_joins_exclusive_dataset_only_file(tmp_path,mapped_stream):
    from romulus.config import Settings
    from romulus.hunt.pivot import PivotExecutor
    from romulus.sources.es import ElasticClient
    from romulus.store.db import make_engine, migrate
    from romulus.store.repo import Repo
    from tests.zeek_source_support import ZeekES

    conn=zf.elastic(replace(zf.Conn(),uid=zl.UID_HTTP,ts=zl.HTTP.ts,duration=60),'conn')
    file=zl.elastic(zl.FILES,'file');original=NativePivot('elastic',[file]).contracts['network']
    file['_source'].pop('data_stream')
    second=NativePivot('elastic',[file]).contracts['network'].model_copy(update={'target':'files'})
    if mapped_stream:
        second.fields['data_stream.dataset']=original.fields['data_stream.dataset']
    contracts={'network':NativePivot('elastic',[conn]).contracts['network'],'files':second}
    backend=ZeekES({'network':[conn],'files':[file]},{'network':'@timestamp','files':'@timestamp'})
    engine=make_engine(tmp_path/'hunt.db');migrate(engine);repo=Repo(engine)
    repo.create_hunt('h',{'targets':list(contracts)},'digest','test')
    try:
        pivot=PivotExecutor(repo,ElasticClient(Settings(home=tmp_path),transport=backend.transport()),'h',contracts,
                            stage_dir=tmp_path/'stage')
        result=fetch(pivot,normalize('elastic',conn),'zeek_uid')
        assert result.status=='complete'
        assert normalize('elastic',file).id in result.event_ids
        assert result.strength=='observed'
    finally:
        engine.dispose()
