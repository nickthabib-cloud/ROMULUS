"""Stats without a declared cadence and connection-selection notes never make healthy Zeek coverage partial."""
import tempfile
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

from romulus.config import Settings
from romulus.detect.base import Playbook
from romulus.hunt.sweep import Sweep
from romulus.sources.es import ElasticClient
from romulus.sources.models import Window
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo
from tests.fixtures import zeek_factory as zf
from tests.fixtures import zeek_logs as zl
from tests.test_zeek_links import NativePivot
from tests.zeek_source_support import ZeekES


class Probe(Playbook):
    id='test.zeek_r3';families=('net_flow','http_tx')
    def match(self,event):
        return []


def run(docs, contracts, window, tf='@timestamp'):
    tmp=Path(tempfile.mkdtemp())
    backend=ZeekES(docs,{t:tf for t in docs})
    engine=make_engine(tmp/'hunt.db');migrate(engine);repo=Repo(engine)
    repo.create_hunt('h',{'targets':list(docs)},'digest','test')
    sweep=Sweep(repo,ElasticClient(Settings(home=tmp),transport=backend.transport()),'h',window,contracts,
                stage_dir=tmp/'stage');sweep.pack=[Probe()]
    try:
        for t in docs:
            sweep.run_target(t)
        sweep.finalize()
        cells=repo.rule_cells('h',rule_id=Probe.id)
        a=repo.latest_audit('h','hunt.zeek_visibility')
        rows=list(repo.zeek_visibility_rows('h',a['detail']['snapshot']['sha256'])) if a else []
        return cells,(a or {}).get('detail'),rows
    finally:
        sweep.close_stage()
        engine.dispose()

T0 = datetime.fromtimestamp(zf.T0, UTC).replace(minute=0, second=0, microsecond=0)
window=Window(start=T0,end=T0+timedelta(minutes=15))



def _zeek_cells(cells):
    return {c['target']: c['state'] for c in cells if c['target'].startswith('zeek')}


def test_stats_without_declared_cadence_leave_capture_loss_in_charge():
    conn=zf.elastic(replace(zf.Conn(),ts=T0.timestamp()+60,duration=30),'conn')
    loss=zl.elastic(replace(zl.CAPTURE_LOSS.with_(percent_lost=0.0),ts=T0.timestamp()+900),'cl')
    stats=zl.elastic(replace(zl.STATS,ts=T0.timestamp()+300),'st')
    for hits in ([conn,loss],[conn,loss,stats]):
        contract=NativePivot('elastic',hits).contracts['network']
        cells,detail,rows=run({'network':hits},{'network':contract},window)
        assert _zeek_cells(cells)=={'zeek:sensor-zeek-01':'evaluated_complete'} and detail['unresolved']==[]
        assert not any('no health record covers' in row['reason'] for row in rows)
    assert any('without declared cadence' in row['reason'] and not row['partial'] for row in rows)


def test_an_open_connection_at_window_end_is_not_an_inventory_gap():
    open_conn=zf.malcolm(replace(zf.Conn(),uid='Copen',ts=T0.timestamp()+60,duration=120),'open',interim=True,
                         sensor='sensor-a')
    done=zf.malcolm(replace(zf.Conn(),uid='Cdone',ts=T0.timestamp()+60,duration=30,service='smb'),'done',
                    sensor='sensor-b')
    health=[{'_index':'network','_id':'h-'+s,'_source':{
        '@timestamp':(T0+timedelta(minutes=15)).isoformat().replace('+00:00','Z'),
        'event':{'provider':'zeek','dataset':'capture_loss'},'node':s,'zeek':{'capture_loss':{
            'peer':'worker','ts_delta':900,'gaps':0,'acks':1000,'percent_lost':0.0}}}} for s in ('sensor-a','sensor-b')]
    hits=[open_conn,done,*health]
    contract=NativePivot('malcolm',hits).contracts['network'].model_copy(update={'time_field':'@timestamp'})
    cells,detail,rows=run({'network':hits},{'network':contract},window)
    assert _zeek_cells(cells)=={'zeek:sensor-a':'evaluated_complete','zeek:sensor-b':'evaluated_complete'}
    assert detail['unresolved']==[] and not any('presence unresolved' in row['reason'] for row in rows)
