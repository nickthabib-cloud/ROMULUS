"""Stream source-owned Zeek visibility aggregates into compact disk-backed interval state."""
from __future__ import annotations

import copy
import sqlite3
import time
from datetime import UTC, datetime
from pathlib import Path

from romulus.detect.bounded import StateBudget
from romulus.errors import SourceError

SERVICES = {
    'smb': ('smb_tx', 'SMB', 'smb_*'), 'krb': ('kerberos_tx', 'Kerberos', 'kerberos'),
    'kerberos': ('kerberos_tx', 'Kerberos', 'kerberos'), 'dce_rpc': ('rpc_tx', 'DCE/RPC', 'dce_rpc'),
    'rdp': ('remote_session', 'RDP', 'rdp'), 'ldap': ('ldap_tx', 'LDAP', 'ldap'),
    'ssl': ('tls_session', 'SSL', 'ssl'), 'http': ('http_tx', 'HTTP', 'http'),
    'dns': ('dns_query', 'DNS', 'dns'), 'ssh': ('ssh_session', 'SSH', 'ssh'),
}


def composite_pages(client, target, body, reasons, *, max_pages=None, deadline=None, heartbeat=None):
    """Yield buckets one page at a time; source limits and interrupted pagination are explicit.

    Unlike a raw-event fallback this retains only one bounded source page. The
    caller owns the fixed aggregation, never telemetry or an agent-generated DSL.
    """
    body = copy.deepcopy(body)
    previous = None
    pages = 0
    while True:
        if max_pages is not None and pages >= max_pages:
            reasons.append(f'{target}: visibility composite page limit {max_pages} reached')
            return
        if deadline is not None and time.monotonic() >= deadline:
            reasons.append(f'{target}: visibility deadline reached')
            return
        if heartbeat:
            heartbeat()
        try:
            response = client.search(target, body)
        except SourceError as exc:
            reasons.append(f'{target}: visibility source failed: {exc}')
            return
        pages += 1
        if response.get('timed_out') or response.get('terminated_early') or response.get('_shards', {}).get('failed'):
            reasons.append(f'{target}: visibility source response incomplete')
        aggregate = response.get('aggregations', {}).get('visibility')
        if not isinstance(aggregate, dict) or not isinstance(aggregate.get('buckets'), list):
            reasons.append(f'{target}: visibility aggregation unavailable')
            return
        buckets = aggregate['buckets']
        yield from buckets
        after = aggregate.get('after_key')
        if not buckets or not after:
            return
        if after == previous:
            reasons.append(f'{target}: visibility composite cursor did not advance')
            return
        previous = after
        body['aggs']['visibility']['composite']['after'] = after


def _iso(value):
    return datetime.fromtimestamp(value, UTC).isoformat()


class _Reasons(list):
    """Bound malformed-source diagnostics without losing the fact of overflow."""
    def append(self, reason):
        if reason in self:
            return
        if len(self) < 256:
            super().append(reason)
        elif len(self) == 256:
            super().append('additional Zeek visibility failure categories omitted after 256; coverage incomplete')


class VisibilityStore:
    """One hunt's sensor intervals, service identities and analyzer presence.

    SQL joins combine every target before absence is stated. The shared physical
    state budget bounds storage; SQLite's page cache bounds Python-independent
    working memory, and all report rows are streamed in sensor/time order.
    """
    def __init__(self, directory, *, budget=None):
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        self.path = directory / 'zeek-visibility.db'
        self.db = sqlite3.connect(self.path)
        self.db.execute('PRAGMA journal_mode=DELETE')
        self.db.execute('PRAGMA cache_size=-2048')
        self.db.execute('PRAGMA temp_store=FILE')
        self.db.executescript('''
            CREATE TABLE IF NOT EXISTS activity(sensor TEXT, family TEXT, start REAL, end REAL, n INTEGER,
                PRIMARY KEY(sensor,family,start,end)) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS health(sensor TEXT, start REAL, end REAL, loss REAL, kind TEXT,
                PRIMARY KEY(sensor,start,end,kind,loss)) WITHOUT ROWID;
            CREATE INDEX IF NOT EXISTS health_span ON health(sensor,end,start);
            CREATE TABLE IF NOT EXISTS analyzer(sensor TEXT, log TEXT, n INTEGER,
                PRIMARY KEY(sensor,log)) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS stats(sensor TEXT,worker TEXT,time REAL,dropped REAL,link REAL,
                PRIMARY KEY(sensor,worker,time,dropped,link)) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS issue(sensor TEXT,reason TEXT,PRIMARY KEY(sensor,reason)) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS content_gap(sensor TEXT, identity TEXT, kind TEXT,
                PRIMARY KEY(sensor,identity,kind)) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS summary(sensor TEXT, family TEXT, partial INTEGER, intervals INTEGER,
                PRIMARY KEY(sensor,family)) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS flow(sensor TEXT, uid TEXT, final INTEGER, duration REAL, start REAL, end REAL,
                PRIMARY KEY(sensor,uid)) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS service(sensor TEXT, uid TEXT, service TEXT, final INTEGER, duration REAL,
                PRIMARY KEY(sensor,service,uid,final,duration)) WITHOUT ROWID;
        ''')
        self.budget = budget or StateBudget(directory)
        self.account = self.budget.account('zeek_visibility')
        self.reasons = _Reasons()
        self._size = 0
        self._writes = 0
        self.checkpoint()

    def checkpoint(self):
        self.db.commit()
        page = self.db.execute('PRAGMA page_size').fetchone()[0]
        size = self.db.execute('PRAGMA page_count').fetchone()[0] * page
        growth = size - self._size
        self.budget.charge(self.account, growth)
        self.budget.physical_account(self.account, growth)
        if growth > 0:
            self.budget.grew(growth)
        self._size = size
        allowance = self.budget.physical_allowance(self.account)
        ceiling = self.budget.disk_total if allowance is None else size + allowance
        self.db.execute(f'PRAGMA max_page_count={max(1, ceiling // page)}')

    def _write(self, sql, values):
        try:
            self.db.execute(sql, values)
            self._writes += 1
            if self._writes % 256 == 0:
                self.checkpoint()
        except sqlite3.OperationalError as exc:
            self.db.rollback()
            reason = f'Zeek visibility disk state incomplete: {exc}'
            if reason not in self.reasons:
                self.reasons.append(reason)

    def activity(self, sensor, family, start, end, count):
        self._write('INSERT INTO activity VALUES (?,?,?,?,?) ON CONFLICT(sensor,family,start,end) '
                    'DO UPDATE SET n=n+excluded.n', (sensor, family, start, end, count))

    def health(self, sensor, start, end, loss, kind):
        if end > start:
            self._write('INSERT OR IGNORE INTO health VALUES (?,?,?,?,?)', (sensor, start, end, loss, kind))

    def analyzer(self, sensor, log, count):
        group='smb' if log.startswith('smb_') else 'ldap' if log=='ldap_search' else log
        self._write('INSERT INTO analyzer VALUES (?,?,?) ON CONFLICT(sensor,log) DO UPDATE SET n=n+excluded.n',
                    (sensor, group, count))

    def connection(self, sensor, uid, services, *, interim=False, duration=0, start=None, end=None):
        final = int(not interim)
        self._write('INSERT INTO flow VALUES (?,?,?,?,?,?) ON CONFLICT(sensor,uid) DO UPDATE SET '
                    'final=excluded.final,duration=excluded.duration,start=excluded.start,end=excluded.end '
                    'WHERE excluded.final>final OR (excluded.final=final AND excluded.duration>=duration)',
                    (sensor,uid,final,duration,start,end))
        names = services if isinstance(services, list) else str(services or '').split(',')
        for name in {str(name).strip().lower() for name in names} & SERVICES.keys():
            self._write('INSERT OR IGNORE INTO service VALUES (?,?,?,?,?)', (sensor, uid, name,final,duration))

    def connection_activity(self,window):
        """Stream canonical clipped spans once; conn timestamps are not independent activity buckets."""
        for sensor,start,end,count in self.db.execute(
                'SELECT sensor,start,end,count(*) FROM flow WHERE start<? AND end>=? '
                'GROUP BY sensor,start,end ORDER BY sensor,start,end',
                (window.end.timestamp(),window.start.timestamp())):
            if end==start:
                end=start+0.000001
            self.activity(sensor,'net_flow',max(start,window.start.timestamp()),min(end,window.end.timestamp()),count)

    def stats(self,sensor,worker,time,dropped,link):
        self._write('INSERT OR IGNORE INTO stats VALUES (?,?,?,?,?)',(sensor,worker,time,dropped,link))

    def issue(self,sensor,reason):
        self._write('INSERT OR IGNORE INTO issue VALUES (?,?)',(sensor,reason))

    def resolve_stats(self,cadence,*,complete):
        previous=None
        for sensor,worker,stamp,dropped,link in self.db.execute('SELECT * FROM stats ORDER BY sensor,worker,time'):
            valid=(complete and cadence and previous and previous[:2]==(sensor,worker)
                   and abs(stamp-previous[2]-cadence)<0.001 and link>0 and 0<=dropped<=link)
            if valid:
                self.health(sensor,previous[2],stamp,100*dropped/link,'packet drop')
            else:
                self.issue(sensor,'stats packet counters are interval deltas; interval boundaries unknown '
                           'without declared cadence and complete same-worker measurement continuity')
            previous=(sensor,worker,stamp)

    def issues(self):
        for sensor,family,reason in self.db.execute('SELECT DISTINCT i.sensor,a.family,i.reason FROM issue i '
                'JOIN activity a ON i.sensor=a.sensor ORDER BY i.sensor,a.family,i.reason'):
            yield {'sensor':sensor,'family':family,'partial':False,'reason':f'sensor {sensor}: {reason}'}

    def content_gap(self, sensor, identity, kind):
        self._write('INSERT OR IGNORE INTO content_gap VALUES (?,?,?)',(sensor,identity,kind))

    def content_gaps(self):
        self.checkpoint()
        for sensor,service,count in self.db.execute(
                "SELECT s.sensor,s.service,count(DISTINCT g.identity) FROM service s JOIN flow f "
                "ON s.sensor=f.sensor AND s.uid=f.uid AND s.final=f.final AND s.duration=f.duration "
                "JOIN content_gap g ON s.sensor=g.sensor AND s.uid=g.identity AND g.kind='connection' "
                "GROUP BY s.sensor,s.service ORDER BY s.sensor,s.service"):
            family=SERVICES[service][0]
            yield {'sensor':sensor,'family':family,'connections':count,'partial':False,
                   'reason':f'sensor {sensor}: {count} connections had content gaps; {family} content checks '
                            'describe only the bytes the sensor analyzed; positive findings retain their lane'}
        for sensor,count in self.db.execute("SELECT sensor,count(*) FROM content_gap WHERE kind='file' "
                                            'GROUP BY sensor ORDER BY sensor'):
            yield {'sensor':sensor,'family':'file_transfer','files':count,'partial':False,
                   'reason':f'sensor {sensor}: {count} files had content gaps; file checks describe only '
                            'the bytes the sensor analyzed; positive findings retain their lane'}

    def analyzer_gaps(self):
        self.checkpoint()
        for sensor, service, count in self.db.execute(
                'SELECT s.sensor,s.service,count(DISTINCT s.uid) FROM service s JOIN flow f '
                'ON s.sensor=f.sensor AND s.uid=f.uid AND s.final=f.final AND s.duration=f.duration '
                'GROUP BY s.sensor,s.service ORDER BY s.sensor,s.service'):
            family, label, log = SERVICES[service]
            group='smb' if log=='smb_*' else log
            row = self.db.execute('SELECT n FROM analyzer WHERE sensor=? AND log=?', (sensor, group)).fetchone()
            if row and row[0]:
                continue
            reason=(f'sensor {sensor}: {count} connections recorded as {label} by conn.log have no '
                    f'{log} records in scope')
            if self.reasons:
                reason=(f'sensor {sensor}: {count} connections recorded as {label} by conn.log; '
                        f'{log} presence unresolved because source visibility inventory is incomplete')
            yield {'sensor': sensor, 'family': family, 'connections': count,'reason':reason, 'partial': True}

    def visibility(self, window, threshold):
        self.checkpoint()
        pending = None
        for sensor, family, start, end, count in self.db.execute(
                'SELECT sensor,family,start,end,n FROM activity WHERE end>? AND start<? '
                'ORDER BY sensor,family,start,end', (window.start.timestamp(), window.end.timestamp())):
            start, end = max(start, window.start.timestamp()), min(end, window.end.timestamp())
            covered = start
            partial = False
            missing = False
            losses = {}
            for hstart, hend, loss, kind in self.db.execute(
                    'SELECT start,end,loss,kind FROM health WHERE sensor=? AND end>? AND start<? ORDER BY start,end',
                    (sensor, start, end)):
                if hstart > covered:
                    missing = True
                covered = max(covered, hend)
                if loss > 0:
                    losses[kind] = max(losses.get(kind, 0), loss)
                partial |= loss >= threshold
            missing |= covered < end
            partial |= missing
            statements = [f'estimated {loss:g} % {kind}' for kind, loss in sorted(losses.items())]
            if missing:
                statements.append('no health record covers the complete interval in which the sensor wrote data')
            if not statements:
                statements.append('health records cover this data interval')
            signature = (sensor, family, partial, tuple(statements))
            if pending and pending['_signature'] == signature and pending['_end'] == start:
                pending['_end'] = end
                pending['records'] += count
            else:
                if pending:
                    yield self._row(pending)
                pending = {'sensor': sensor, 'family': family, 'partial': partial, 'records': count,
                           '_start': start, '_end': end, '_signature': signature, '_statements': statements}
        if pending:
            yield self._row(pending)

    def snapshot_rows(self, window, threshold):
        from itertools import chain
        for row in chain(self.visibility(window, threshold), self.analyzer_gaps(), self.content_gaps(), self.issues()):
            self._write('INSERT INTO summary VALUES (?,?,?,1) ON CONFLICT(sensor,family) '
                        'DO UPDATE SET partial=max(partial,excluded.partial),intervals=intervals+1',
                        (row['sensor'], row['family'], row['partial']))
            yield row
        self.checkpoint()

    def summaries(self):
        yield from self.db.execute('SELECT sensor,family,partial,intervals FROM summary ORDER BY sensor,family')

    @staticmethod
    def _row(row):
        sensor, start, end = row['sensor'], _iso(row['_start']), _iso(row['_end'])
        reason = f"sensor {sensor} during {start}–{end}: {'; '.join(row['_statements'])}"
        if row['partial'] or any('estimated' in text for text in row['_statements']):
            reason += '; traffic it did not see was not searched'
        return {k: v for k, v in row.items() if not k.startswith('_')} | {
            'start': start, 'end': end, 'reason': reason}

    def close(self):
        self.db.close()
        self.budget.charge(self.account, -self._size)
        self.budget.physical_account(self.account, -self._size)
        self.path.unlink(missing_ok=True)


def collect_visibility(client, contracts, window, store, policy, *, heartbeat=None):
    """Read fixed sensor/time/log composites; never fall back to a raw traffic scan."""
    from datetime import timedelta

    from romulus.evidence.zeek_catalog import HEALTH_LOGS, PLAIN, SHAPES, ZEEK_LOGS, lookup_log
    from romulus.hunt.zeek_sources import native_field, source_groups
    from romulus.sources.compile import build_query
    from romulus.sources.models import Predicate, SearchIntent, Window

    def stamp(value, plain):
        if isinstance(value, str):
            return datetime.fromisoformat(value).timestamp()
        return float(value) if plain else float(value)/1000

    def key(name, field):
        return {name: {'terms': {'field': field, 'missing_bucket': True}}}

    for target, contract in sorted(contracts.items()):
        for shape in SHAPES:
            logs = [log for log in ZEEK_LOGS if source_groups(contract, log, shape)]
            if not logs:
                continue
            plain = shape == PLAIN
            sensor_fields = list(dict.fromkeys(native_field(contract, path, 'exists')
                                 for path in logs[0].sensor_paths.get(shape, ())
                                 if native_field(contract, path, 'exists')))
            # Shared dataset mappings do not prove that this shipper has rows.
            # An actual bucket without a sensor is named by sensor() below.
            sensor_names = ['sensor' if i==0 else f'sensor{i}' for i in range(len(sensor_fields))]
            sensor_sources = [] if plain else [key(name,contract.fields[field].native)
                                                for name,field in zip(sensor_names,sensor_fields,strict=True)]
            dataset_fields=[field for field in (('_path',) if plain else
                ('event.dataset','data_stream.dataset') if shape=='elastic' else ('event.dataset',))
                if contract.supports(field,'in')]
            dataset=dataset_fields[0] if dataset_fields else ('_path' if plain else 'event.dataset')
            log_keys=['log' if i==0 else f'log{i}' for i in range(len(dataset_fields))]
            declared = contract.zeek_log if plain else None
            def read(selected, sources, scope=window, metrics=None, filters=(), query_contract=None,
                     contract=contract, shape=shape, target=target, sensor_sources=sensor_sources):
                groups = [group for log in selected for group in source_groups(contract, log, shape)]
                intent = SearchIntent(kind='raw', target=target, window=scope, any_of=groups, filters=list(filters),
                                      purpose='sweep:zeek-visibility')
                body = {'size':0, 'query':build_query(intent,query_contract or contract), 'aggs':{'visibility':{
                    'composite':{'size':1000,'sources':[*sensor_sources,*sources]}}}}
                if metrics:
                    body['aggs']['visibility']['aggs']=metrics
                yield from composite_pages(client,target,body,store.reasons,heartbeat=heartbeat)
            def sensor(bucket, contract=contract, plain=plain, sensor_names=sensor_names, target=target):
                result = contract.zeek_sensor if plain else next(
                    (bucket['key'].get(name) for name in sensor_names if bucket['key'].get(name)),None)
                if not result:
                    if f'{target}: Zeek records missing sensor identity' not in store.reasons:
                        store.reasons.append(f'{target}: Zeek records missing sensor identity')
                    return f'unidentified sensor in {target}'
                return result
            clock = {'histogram':{'field':contract.time_field,'interval':900}} if plain else {
                'date_histogram':{'field':contract.time_field,'fixed_interval':'900s'}}
            observed_conn=False
            data_logs=[log for log in logs if log.family!='sensor_health']
            if data_logs and (declared or dataset_fields):
                sources=[] if declared else [key(name,contract.fields[field].native)
                    for name,field in zip(log_keys,dataset_fields,strict=True)]
                sources.append({'time':clock})
                for bucket in read(data_logs,sources):
                    # Event dataset wins when present; stream-only Agent rows use the fallback.
                    name=declared or next((bucket['key'].get(key) for key in log_keys
                                          if bucket['key'].get(key)), '')
                    name=name.removeprefix('zeek.')
                    log=lookup_log(shape,name)
                    if log is None:
                        store.reasons.append(f'{target}: selected Zeek activity lacks a recognized log marker; coverage unresolved')
                        continue
                    if log.family=='sensor_health':
                        continue
                    who=sensor(bucket); start=stamp(bucket['key']['time'],plain)
                    if log.name=='conn':
                        observed_conn=True
                    else:
                        store.activity(who,log.family,max(window.start.timestamp(),start),
                                       min(window.end.timestamp(),start+900),bucket['doc_count'])
                        store.analyzer(who,log.name,bucket['doc_count'])
            for log in [item for item in logs if item in HEALTH_LOGS]:
                paths={spec.typed:next((native_field(contract,path,'exists') for path in spec.paths.get(shape,())
                                       if native_field(contract,path,'exists')),None) for spec in log.fields}
                if log.name=='capture_loss' and paths.get('health.interval_s') and paths.get('health.capture_loss_pct'):
                    sources=[key('time',contract.time_field), key('interval',contract.fields[paths['health.interval_s']].native),
                             key('loss',contract.fields[paths['health.capture_loss_pct']].native)]
                    # A health row timestamps the end of its interval. Bounded lookahead
                    # retrieves intervals straddling the hunt's end; missing coverage remains partial.
                    scope=Window(start=window.start,end=window.end+timedelta(hours=24))
                    for bucket in read([log],sources,scope):
                        data=bucket['key']
                        try:
                            end=stamp(data['time'],plain); duration=float(data['interval']); loss=float(data['loss'])
                            if not (0<duration<float('inf') and 0<=loss<float('inf')):
                                raise ValueError('invalid health interval')
                        except (TypeError,ValueError,OverflowError):
                            store.reasons.append(f'{target}: malformed capture-loss interval; visibility unresolved')
                            continue
                        store.health(sensor(bucket),end-duration,end,loss,'capture loss')
                elif log.name=='stats' and paths.get('health.packets_dropped') and paths.get('health.packets_link'):
                    # Counts are interval deltas, but the native row does not carry
                    # its duration. A source inventory alone cannot establish cadence.
                    sources=[key('time',contract.time_field),
                             key('dropped',contract.fields[paths['health.packets_dropped']].native),
                             key('link',contract.fields[paths['health.packets_link']].native)]
                    worker=paths.get('health.worker')
                    if worker:
                        sources.insert(0,key('worker',contract.fields[worker].native))
                    cadence=policy.stats_interval_seconds
                    scope=Window(start=window.start-timedelta(seconds=cadence or 0),
                                 end=window.end+timedelta(seconds=cadence or 0))
                    for bucket in read([log],sources,scope):
                        who=sensor(bucket); data=bucket['key']
                        try:
                            dropped=float(data['dropped']); link=float(data['link'])
                            if not (0<=dropped<=link<float('inf')) or not data.get('worker'):
                                raise ValueError('invalid stats measurement')
                            store.stats(who,data['worker'],stamp(data['time'],plain),dropped,link)
                        except (TypeError,ValueError,OverflowError):
                            store.issue(who,'stats measurement missing worker or valid packet counters; interval unknown')
            conn=next((item for item in data_logs if item.name=='conn'),None)
            if conn:
                uid=next((native_field(contract,path,'in') for path in conn.spec('zeek.uid').paths.get(shape,())
                          if native_field(contract,path,'in')),None)
                service=next((native_field(contract,path,'in') for path in conn.spec('network.protocols').paths.get(shape,())
                              if native_field(contract,path,'in')),None)
                if uid and service:
                    duration_path=next((path for path in conn.spec('session.duration_s').paths.get(shape,())
                                        if native_field(contract,path,'exists')),None)
                    duration_field=native_field(contract,duration_path,'exists') if duration_path else None
                    interim_field=native_field(contract,'zeek.conn.long','exists') if shape=='malcolm' else None
                    sources=[key('uid',contract.fields[uid].native),key('service',contract.fields[service].native),
                             key('time',contract.time_field)]
                    if not declared and contract.supports(dataset,'exists'):
                        sources.append(key('conn_log',contract.fields[dataset].native))
                    if duration_field:
                        sources.append(key('duration',contract.fields[duration_field].native))
                    if interim_field:
                        sources.append(key('interim',contract.fields[interim_field].native))
                    for typed,label in [('conn.missed_bytes','missed'),('conn.history','history')]:
                        field=next((native_field(contract,path,'exists') for path in conn.spec(typed).paths.get(shape,())
                                    if native_field(contract,path,'exists')),None)
                        if field:
                            sources.append(key(label,contract.fields[field].native))
                    scope=Window(start=window.start-timedelta(hours=policy.connection_lookback_hours),end=window.end)
                    from itertools import chain
                    streams=[read([conn],sources,scope)]
                    if (shape=='malcolm' and interim_field and contract.supports('lastPacket','exists')
                            and contract.supports('firstPacket','lt')):
                        cutoff=(scope.start.isoformat() if contract.fields['firstPacket'].type.startswith('date')
                                else scope.start.timestamp()*1000)
                        streams.append(read([conn],sources,window,
                            filters=[Predicate(field=interim_field,op='in',value=[True,'true']),
                                     Predicate(field='firstPacket',op='lt',value=cutoff)],
                            query_contract=contract.model_copy(update={'time_field':'lastPacket'})))
                    for bucket in chain.from_iterable(streams):
                        data=bucket['key']
                        if not data.get('uid'):
                            continue
                        start=stamp(data['time'],plain)
                        try:
                            duration=float(data.get('duration') or 0)
                            missed=float(data.get('missed') or 0)
                            if not (0<=duration<float('inf') and 0<=missed<float('inf')):
                                raise ValueError('invalid connection measurements')
                        except (TypeError,ValueError,OverflowError):
                            store.reasons.append(f'{target}: malformed connection measurements; coverage unresolved')
                            continue
                        if duration_path and duration_path.endswith(':ns'):
                            duration/=1e9
                        elif duration_path and duration_path.endswith(':ms'):
                            duration/=1000
                        if start+duration<=window.start.timestamp() and start<window.start.timestamp():
                            continue
                        who=sensor(bucket)
                        if missed>0 or any(char in str(data.get('history') or '').lower()
                                                               for char in 'gx'):
                            store.content_gap(who,data['uid'],'connection')
                        store.connection(who,data['uid'],data.get('service'),
                                         interim=(data.get('interim') in (True,'true','T') or
                                                  (declared or data.get('conn_log'))=='conn_long'),duration=duration,
                                         start=start,end=start+duration)
                elif observed_conn:
                    store.reasons.append(f'{target}: conn service/UID not aggregatable; analyzer cross-check unresolved')
            files=next((item for item in data_logs if item.name=='files'),None)
            if files:
                fields={typed:next((native_field(contract,path,'exists') for path in files.spec(typed).paths.get(shape,())
                                   if native_field(contract,path,'exists')),None)
                        for typed in ('file.fuid','file.missing_bytes','file.overflow_bytes','file.timedout')}
                if fields['file.fuid']:
                    sources=[key(typed,contract.fields[field].native) for typed,field in fields.items() if field]
                    for bucket in read([files],sources):
                        data=bucket['key']
                        try:
                            missing=float(data.get('file.missing_bytes') or 0)
                            overflow=float(data.get('file.overflow_bytes') or 0)
                            if not (0<=missing<float('inf') and 0<=overflow<float('inf')):
                                raise ValueError('invalid file measurements')
                        except (TypeError,ValueError,OverflowError):
                            store.reasons.append(f'{target}: malformed file measurements; coverage unresolved')
                            continue
                        if missing>0 or overflow>0 or data.get('file.timedout') in (True,'true','T'):
                            store.content_gap(sensor(bucket),data['file.fuid'],'file')
    store.connection_activity(window)
    store.resolve_stats(policy.stats_interval_seconds,complete=not store.reasons)
    store.checkpoint()
