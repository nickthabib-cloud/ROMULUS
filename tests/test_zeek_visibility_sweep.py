"""The real sweep publishes positives before bounded, partition-scoped visibility."""
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from romulus.config import Settings
from romulus.detect.base import Match, Playbook
from romulus.hunt.sweep import Sweep
from romulus.sources.es import ElasticClient
from romulus.sources.models import Window
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo
from tests.fixtures import zeek_factory as zf
from tests.fixtures import zeek_logs as zl
from tests.test_zeek_links import NativePivot
from tests.zeek_source_support import ZeekES, matches


class DirectProbe(Playbook):
    id = 'test.visibility_direct'
    families = ('net_flow', 'http_tx', 'remote_session')
    def consume(self, events):
        first = not self.evaluated
        self.evaluated += len(events)
        return [Match(self.id, 'direct observation', 'network_observation', [events[0]], [],
                      events[0].ts, 'high', 'high', 'high')] if first and events else []


class CountingSource(ZeekES):
    visibility_scanned = 0
    def _search(self, target, body):
        if 'visibility' in body.get('aggs', {}):
            # Time-range pruning models an indexed partition. Count every
            # candidate document reconsidered by every composite page, even
            # documents rejected by the log marker, not just returned buckets.
            time_filter = body['query']['bool']['filter'][0]
            self.visibility_scanned += sum(matches(time_filter, row['_source']) for row in self.docs[target])
        return super()._search(target, body)


def test_visibility_scans_are_linear_and_findings_publish_before_collection(tmp_path):
    count = 2000
    start = datetime.fromtimestamp(zf.T0, UTC)
    hits = [zf.plain(replace(zf.Conn(), uid=f'C{i}', ts=zf.T0+i/10, duration=.01), str(i))
            for i in range(count)]
    contract = NativePivot('plain', hits).contracts['network'].model_copy(update={'time_field':'ts'})
    backend = CountingSource({'network':hits}, {'network':'ts'})
    engine = make_engine(tmp_path/'hunt.db'); migrate(engine); repo = Repo(engine)
    repo.create_hunt('h', {'targets':['network']}, 'digest', 'test')
    sweep = Sweep(repo, ElasticClient(Settings(home=tmp_path), transport=backend.transport()), 'h',
        Window(start=start, end=start+timedelta(seconds=200)), {'network':contract}, stage_dir=tmp_path/'stage')
    probe = DirectProbe(); sweep.pack = [probe]
    sweep._zeek_visibility_enabled = True
    parts = [Window(start=start+timedelta(seconds=i*20), end=start+timedelta(seconds=(i+1)*20))
             for i in range(10)]
    sweep._zeek_visibility_ranges = {'network':parts}
    try:
        for part in parts:
            sweep.run_partition('network', contract, [], part, 200)
        assert probe.evaluated == count
        assert repo.candidates('h')
        assert backend.visibility_scanned == 0
        assert sweep._zeek_visibility.budget is not sweep.budget
        assert not any(account.name == 'zeek_visibility' for account in sweep.budget.accounts)
        sweep.finalize()
        assert backend.visibility_scanned <= 3*count
        snapshot = repo.latest_audit('h', 'hunt.zeek_visibility')['detail']['snapshot']
        rows = list(repo.zeek_visibility_rows('h', snapshot['sha256']))
        assert len(rows) <= 2  # one grid row and one SSL analyzer-presence statement
        assert sum('start' in row for row in rows) == 1
        assert sum(row.get('records',0) for row in rows) == count
        print(f'visibility: {count} connections, 10 partitions, {backend.visibility_scanned} scanned documents, {len(rows)} snapshot rows')
    finally:
        sweep.close_stage(); engine.dispose()


@pytest.mark.parametrize('interruption', ['lookback', 'partition'])
def test_resumed_partition_replay_rebuilds_visibility_without_double_counting(tmp_path, interruption):
    start = datetime.fromtimestamp(zf.T0,UTC)
    conn = replace(zf.Conn(),uid='Cresume',ts=zf.T0-3600,duration=3900,service='http')
    hits = [zf.malcolm(conn,'interim',interim=True),
            zf.malcolm(replace(conn,duration=4000),'final'),
            zl.malcolm(replace(zl.HTTP.with_(uid='Cresume'),ts=zf.T0+100),'http1'),
            zl.malcolm(replace(zl.HTTP.with_(uid='Cresume'),ts=zf.T0+700),'http2'),
            zl.malcolm(replace(zl.CAPTURE_LOSS.with_(percent_lost=0),ts=zf.T0+900),'health')]
    contract = NativePivot('malcolm',hits).contracts['network'].model_copy(update={'time_field':'@timestamp'})
    backend = ZeekES({'network':hits},{'network':'@timestamp'})
    client = ElasticClient(Settings(home=tmp_path),transport=backend.transport())
    engine = make_engine(tmp_path/'hunt.db'); migrate(engine); repo = Repo(engine)
    window = Window(start=start,end=start+timedelta(minutes=15))
    def create(hunt):
        instance = Sweep(repo,client,hunt,window,{'network':contract},stage_dir=tmp_path/'stage')
        instance.pack = [DirectProbe()]
        return instance
    snapshots = []
    try:
        for hunt in ('continuous','resumed'):
            repo.create_hunt(hunt,{'targets':['network']},'digest','test')
            sweep = create(hunt)
            try:
                if hunt == 'resumed':
                    sweep._zeek_visibility_enabled = True
                    sweep._zeek_lookback('network',contract)
                    if interruption == 'partition':
                        sweep.run_partition('network',contract,[],Window(start=start,
                            end=start+timedelta(minutes=5)),1)
                    sweep.close_stage()
                    sweep = create(hunt)
                sweep.run_target('network')
                sweep.finalize()
                ref = repo.latest_audit(hunt,'hunt.zeek_visibility')['detail']['snapshot']
                snapshots.append((ref,list(repo.zeek_visibility_rows(hunt,ref['sha256']))))
            finally:
                sweep.close_stage()
        assert snapshots[0] == snapshots[1]
        assert sum(row.get('records',0) for row in snapshots[1][1]) == 3
    finally:
        engine.dispose()


@pytest.mark.parametrize('phase', ['allocation', 'accumulation', 'collection', 'disk_ceiling'])
def test_visibility_infrastructure_failure_cannot_prevent_a_direct_finding(tmp_path, monkeypatch, phase):
    start = datetime.fromtimestamp(zf.T0, UTC)
    hits = [zf.plain(zf.Conn(), 'conn')]
    contract = NativePivot('plain', hits).contracts['network'].model_copy(update={'time_field':'ts'})
    backend = ZeekES({'network':hits},{'network':'ts'})
    engine = make_engine(tmp_path/'hunt.db'); migrate(engine); repo = Repo(engine)
    repo.create_hunt('h', {'targets':['network']}, 'digest', 'test')
    sweep = Sweep(repo,ElasticClient(Settings(home=tmp_path,zeek_visibility_disk_mb=.19),transport=backend.transport()),'h',
        Window(start=start,end=start+timedelta(minutes=15)),{'network':contract},stage_dir=tmp_path/'stage')
    probe=DirectProbe(); sweep.pack=[probe]
    def unavailable(*args, **kwargs):
        if phase == 'accumulation':
            assert repo.candidates('h'), 'visibility accumulation ran before the direct finding'
        raise OSError('synthetic visibility volume unavailable')
    if phase != 'disk_ceiling':
        monkeypatch.setattr('romulus.hunt.zeek_visibility.'+(
            'VisibilityStore' if phase=='allocation' else 'VisibilityStore.observe' if phase=='accumulation'
            else 'collect_visibility'), unavailable)
    try:
        sweep.run_target('network')
        assert probe.evaluated == 1
        assert repo.candidates('h')
        if phase == 'disk_ceiling':
            detection_bytes = sweep.budget.disk_used
            store = sweep._zeek_visibility
            for i in range(5000):
                store.activity(f'sensor-{i}', 'http_tx', zf.T0, zf.T0+1, 1)
            store.checkpoint()
            assert any('disk state incomplete' in reason for reason in store.reasons)
            assert sweep.budget.disk_used == detection_bytes
        sweep.finalize()
        assert not sweep.budget.spent
        expected = 'disk state incomplete' if phase == 'disk_ceiling' else 'visibility volume unavailable'
        assert any(expected in ' '.join(c['detail'].get('reasons',[]))
                   for c in repo.rule_cells('h',rule_id=probe.id))
    finally:
        sweep.close_stage(); engine.dispose()


@pytest.mark.parametrize('loss', [25, None])
def test_sensor_health_reaches_rules_even_when_their_analyzers_are_absent(tmp_path, loss):
    start = datetime.fromtimestamp(zf.T0, UTC)
    def rows(sensor, measured):
        result = [zf.plain(replace(zf.Conn(),uid='C'+sensor,ts=zf.T0+10,duration=1), sensor)]
        if measured is not None:
            result.append({'_index':'network','_id':'health-'+sensor,'_source':{
                '_path':'capture_loss','ts':zf.T0+900,'ts_delta':900,'percent_lost':measured,'peer':'worker'}})
        return result
    docs = {'affected':rows('affected',loss),'healthy':rows('healthy',0)}
    docs['idle'] = [docs['healthy'][-1]]
    contracts = {name:NativePivot('plain',hits).contracts['network'].model_copy(update={
        'target':name,'time_field':'ts','zeek_sensor':name}) for name,hits in docs.items()}
    engine = make_engine(tmp_path/'hunt.db'); migrate(engine); repo = Repo(engine)
    repo.create_hunt('h', {'targets':list(docs)}, 'digest', 'test')
    sweep = Sweep(repo,ElasticClient(Settings(home=tmp_path),transport=ZeekES(docs,
        {name:'ts' for name in docs}).transport()),'h',Window(start=start,end=start+timedelta(minutes=15)),
        contracts,stage_dir=tmp_path/'stage')
    class HTTPProbe(DirectProbe):
        id='test.http_coverage'; families=('http_tx',)
    class RemoteProbe(DirectProbe):
        id='test.remote_coverage'; families=('remote_session',)
    sweep.pack = [HTTPProbe(), RemoteProbe()]
    try:
        for target in docs:
            sweep.run_target(target)
        sweep.finalize()
        for rule in sweep.pack:
            cells = {c['target']:c for c in repo.rule_cells('h',rule_id=rule.id) if c['target'].startswith('zeek:')}
            assert cells['zeek:affected']['state']=='evaluated_partial'
            assert cells['zeek:healthy']['state']=='evaluated_complete'
            assert 'zeek:idle' not in cells
            reason = ' '.join(cells['zeek:affected']['detail']['reasons'])
            assert ('25 %' if loss else 'no health record') in reason
            assert start.isoformat() in reason
    finally:
        sweep.close_stage(); engine.dispose()
