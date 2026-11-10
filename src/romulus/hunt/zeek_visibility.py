"""Stream source-owned Zeek visibility aggregates into compact disk-backed interval state."""
from __future__ import annotations

import copy
import json
import math
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
    """One hunt's sensor intervals, service counts and analyzer presence.

    SQL joins combine every target before absence is stated. An independent
    physical state budget bounds storage; SQLite's page cache bounds Python-independent
    working memory, and all report rows are streamed in sensor/time order.
    """
    def __init__(self, directory, *, budget=None):
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        self.path = directory / 'zeek-visibility.db'
        self.stats_cadence = None    # declared stats cadence; without it stats rows are notes, never health
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
            CREATE TABLE IF NOT EXISTS summary(sensor TEXT, family TEXT, partial INTEGER, intervals INTEGER,
                PRIMARY KEY(sensor,family)) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS stream_service(sensor TEXT, service TEXT, start REAL, n INTEGER, gaps INTEGER,
                PRIMARY KEY(sensor,service,start)) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS stream_file(sensor TEXT, start REAL, n INTEGER,
                PRIMARY KEY(sensor,start)) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS partition(target TEXT,start REAL,end REAL,
                PRIMARY KEY(target,start,end)) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS assessment(sensor TEXT,start REAL,end REAL,partial INTEGER,statements TEXT,
                PRIMARY KEY(sensor,start,end)) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS sensor_health_summary(sensor TEXT PRIMARY KEY,partial INTEGER,
                intervals INTEGER,reason TEXT) WITHOUT ROWID;
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
        # A span touches grid intervals; its record count belongs to the first.
        # This keeps counts independent of duration and rows independent of UIDs.
        first = math.floor(start / 900) * 900
        stop = max(first + 900, math.ceil(end / 900) * 900)
        for stamp in range(first, stop, 900):
            self._write('INSERT INTO activity VALUES (?,?,?,?,?) ON CONFLICT(sensor,family,start,end) '
                        'DO UPDATE SET n=n+excluded.n', (sensor, family, stamp, stamp+900,
                                                       count if stamp == first else 0))

    def observe(self, events, window):
        """Consume the sweep's canonical, deduplicated stream exactly once."""
        lower, upper = window.start.timestamp(), window.end.timestamp()
        for event in events:
            if event.get('observer.product') != 'zeek' or event.family == 'sensor_health':
                continue
            sensor = event.host or 'unidentified sensor'
            if event.get('parse.malformed'):
                self.reasons.append('malformed Zeek measurements in the canonical stream; visibility unresolved')
            start = datetime.fromisoformat(event.get('flow.start')).timestamp() if event.has('flow.start') else event.ts.timestamp()
            end = datetime.fromisoformat(event.get('flow.end')).timestamp() if event.has('flow.end') else start
            if start >= upper or end < lower or end == lower and start < lower:
                continue
            start, end = max(lower, start), min(upper, end)
            self.activity(sensor, event.family, start, end, 1)
            log = event.get('zeek.log')
            if log != 'conn':
                self.analyzer(sensor, log or '', 1)
            stamp = math.floor(start/900)*900
            if log == 'conn':
                services = event.get('network.protocols') or []
                services = services if isinstance(services, list) else str(services).split(',')
                gap = bool((event.get('conn.missed_bytes') or 0) > 0 or
                           any(c in str(event.get('conn.history') or '').lower() for c in 'gx'))
                for name in {str(s).strip().lower() for s in services} & SERVICES.keys():
                    self._write('INSERT INTO stream_service VALUES (?,?,?,?,?) ON CONFLICT(sensor,service,start) '
                                'DO UPDATE SET n=n+1,gaps=gaps+excluded.gaps', (sensor,name,stamp,1,int(gap)))
            elif log == 'files' and ((event.get('file.missing_bytes') or 0) > 0 or
                    (event.get('file.overflow_bytes') or 0) > 0 or event.get('file.timedout') is True):
                self._write('INSERT INTO stream_file VALUES (?,?,1) ON CONFLICT(sensor,start) '
                            'DO UPDATE SET n=n+1', (sensor,stamp))

    def health(self, sensor, start, end, loss, kind):
        if end > start:
            self._write('INSERT OR IGNORE INTO health VALUES (?,?,?,?,?)', (sensor, start, end, loss, kind))

    def analyzer(self, sensor, log, count):
        group='smb' if log.startswith('smb_') else 'ldap' if log=='ldap_search' else log
        self._write('INSERT INTO analyzer VALUES (?,?,?) ON CONFLICT(sensor,log) DO UPDATE SET n=n+excluded.n',
                    (sensor, group, count))

    def stats(self,sensor,worker,time,dropped,link):
        self._write('INSERT OR IGNORE INTO stats VALUES (?,?,?,?,?)',(sensor,worker,time,dropped,link))

    def issue(self,sensor,reason):
        self._write('INSERT OR IGNORE INTO issue VALUES (?,?)',(sensor,reason))

    def resolve_stats(self,cadence,*,complete):
        self.stats_cadence=cadence
        previous=None
        for sensor,worker,stamp,dropped,link in self.db.execute('SELECT * FROM stats ORDER BY sensor,worker,time'):
            first = previous is None or previous[:2] != (sensor, worker)
            valid=(complete and cadence and (first or
                   abs(stamp-previous[2]-cadence) <= max(1, .1*cadence)) and link>0 and 0<=dropped<=link)
            if valid:
                self.health(sensor,stamp-cadence if first else previous[2],stamp,
                            100*dropped/link,'packet drop:'+worker)
            else:
                self.issue(sensor,'stats packet counters are interval deltas; interval boundaries unknown '
                           'without declared cadence and complete same-worker measurement continuity')
            previous=(sensor,worker,stamp)

    def issues(self):
        for sensor,family,reason in self.db.execute('SELECT DISTINCT i.sensor,a.family,i.reason FROM issue i '
                'JOIN activity a ON i.sensor=a.sensor ORDER BY i.sensor,a.family,i.reason'):
            yield {'sensor':sensor,'family':family,'partial':False,'reason':f'sensor {sensor}: {reason}'}

    def content_gaps(self):
        self.checkpoint()
        for sensor,service,count in self.db.execute('SELECT sensor,service,sum(gaps) FROM stream_service '
                'GROUP BY sensor,service HAVING sum(gaps)>0 ORDER BY sensor,service'):
            family = SERVICES[service][0]
            yield {'sensor':sensor,'family':family,'connections':count,'partial':False,
                   'reason':f'sensor {sensor}: {count} connections had content gaps; {family} content checks '
                            'describe only the bytes the sensor analyzed; positive findings retain their lane'}
        for sensor,count in self.db.execute('SELECT sensor,sum(n) FROM stream_file GROUP BY sensor ORDER BY sensor'):
            yield {'sensor':sensor,'family':'file_transfer','files':count,'partial':False,
                   'reason':f'sensor {sensor}: {count} files had content gaps; file checks describe only '
                            'the bytes the sensor analyzed; positive findings retain their lane'}

    def analyzer_gaps(self):
        self.checkpoint()
        for sensor, service, count in self.db.execute(
                'SELECT sensor,service,sum(n) FROM stream_service GROUP BY sensor,service ORDER BY sensor,service'):
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
        self.db.execute('DELETE FROM assessment')
        for sensor,start,end in self.db.execute('SELECT DISTINCT sensor,start,end FROM activity ORDER BY sensor,start'):
            start, end = max(start, window.start.timestamp()), min(end, window.end.timestamp())
            if start >= end:
                continue
            groups = {}
            for hstart,hend,loss,kind in self.db.execute(
                    'SELECT start,end,loss,kind FROM health WHERE sensor=? AND end>? AND start<? ORDER BY start,end',
                    (sensor,start,end)):
                groups.setdefault(kind, []).append((hstart,hend,loss))
            # Workers must each cover the interval only when stats can be health (a declared cadence); otherwise
            # capture loss governs and stats rows stay notes.
            workers = [row[0] for row in self.db.execute('SELECT DISTINCT worker FROM stats WHERE sensor=?',
                                                         (sensor,))] if self.stats_cadence else []
            missing, partial, losses = not groups, False, {}
            # Every observed worker must cover the interval. A healthy worker
            # cannot conceal a missing measurement from its peer.
            required = ['packet drop:'+worker for worker in workers] if workers else list(groups)
            gaps = []
            for kind in required:
                covered, gap = start, False
                for hstart,hend,loss in groups.get(kind, []):
                    gap |= hstart > covered
                    covered = max(covered, hend)
                    partial |= loss > 0 and loss >= threshold
                    if loss > 0:
                        label = kind.split(':',1)[0]
                        losses[label] = max(losses.get(label,0),loss)
                gap |= covered < end
                missing |= gap
                if gap and kind.startswith('packet drop:'):
                    gaps.append(kind.split(':',1)[1])
            # Capture-loss measurements remain relevant alongside worker stats.
            for kind, measurements in groups.items():
                for _,_,loss in measurements:
                    partial |= loss > 0 and loss >= threshold
                    if loss > 0:
                        label = kind.split(':',1)[0]
                        losses[label] = max(losses.get(label,0),loss)
            statements = [f'estimated {loss:g} % {kind}' for kind,loss in sorted(losses.items())]
            unreadable = self.db.execute("SELECT 1 FROM issue WHERE sensor=? AND reason LIKE '%health unreadable%' LIMIT 1", (sensor,)).fetchone()
            if unreadable:
                missing = True
                statements.append('health unreadable; complete health coverage could not be established')
            elif gaps:
                statements.append(f'stats worker(s) {", ".join(sorted(gaps))} have no packet-drop measurement for part '
                                  'of the interval in which the sensor wrote data')
            elif missing:
                statements.append('no health record covers the complete interval in which the sensor wrote data')
            if not statements:
                statements.append('health records cover this data interval')
            self._write('INSERT OR REPLACE INTO assessment VALUES (?,?,?,?,?)',
                        (sensor,start,end,int(partial or missing),json.dumps(statements)))
        pending = None
        for sensor, family, start, end, count in self.db.execute(
                'SELECT sensor,family,start,end,n FROM activity WHERE end>? AND start<? '
                'ORDER BY sensor,family,start,end', (window.start.timestamp(), window.end.timestamp())):
            start, end = max(start, window.start.timestamp()), min(end, window.end.timestamp())
            assessed = self.db.execute('SELECT partial,statements FROM assessment WHERE sensor=? AND start=? AND end=?',
                                      (sensor,start,end)).fetchone()
            partial, statements = (bool(assessed[0]),json.loads(assessed[1])) if assessed else (
                True,['health assessment unavailable; visibility state incomplete'])
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
            if 'start' in row:
                self._write('INSERT INTO sensor_health_summary VALUES (?,?,1,?) ON CONFLICT(sensor) '
                            'DO UPDATE SET partial=max(partial,excluded.partial),intervals=intervals+1, '
                            'reason=CASE WHEN excluded.partial>partial THEN excluded.reason ELSE reason END',
                            (row['sensor'],row['partial'],row['reason']))
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


def collect_visibility(client, contracts, window, store, policy, *, heartbeat=None,
                       activity=True, max_pages=32, deadline_seconds=30, resolve=True,
                       health_lookahead=True):
    """Read fixed sensor/time/log composites; never fall back to a raw traffic scan."""
    from datetime import timedelta

    from romulus.evidence.zeek_catalog import HEALTH_LOGS, PLAIN, SHAPES, ZEEK_LOGS, lookup_log
    from romulus.hunt.zeek_sources import native_field, source_groups, widened_reason
    from romulus.sources.compile import build_query
    from romulus.sources.models import SearchIntent, Window

    def stamp(value, plain):
        if isinstance(value, str):
            return datetime.fromisoformat(value).timestamp()
        return float(value) if plain else float(value)/1000

    def key(name, field):
        return {name: {'terms': {'field': field, 'missing_bucket': True}}}

    for target, contract in sorted(contracts.items()):
        for shape in SHAPES:
            logs, widened = [], {}
            for log in ZEEK_LOGS:
                markers = []
                if source_groups(contract, log, shape, widened=markers):
                    logs.append(log)
                    if markers:
                        widened[log] = list(dict.fromkeys(markers))
            if not logs:
                continue
            def exact(log, target=target, shape=shape, widened=widened):
                # An aggregate counts every record its groups select, with no record-level layout check: groups wider
                # than their layout (widened_markers) would count other layouts' rows as this one's, so the log is
                # not counted and visibility says why.
                if log not in widened:
                    return True
                store.reasons.append(widened_reason(target, log, shape, widened[log]))
                return False
            plain = shape == PLAIN
            sensor_fields = list(dict.fromkeys(native_field(contract, path, 'exists')
                                 for path in logs[0].sensor_paths.get(shape, ())
                                 if native_field(contract, path, 'exists')))
            # Shared dataset mappings do not prove that this shipper has rows.
            # An actual bucket without a sensor is named by sensor() below.
            sensor_names = ['sensor' if i==0 else f'sensor{i}' for i in range(len(sensor_fields))]
            sensor_sources = [] if plain else [key(name,contract.fields[field].native)
                                                for name,field in zip(sensor_names,sensor_fields,strict=True)]
            dataset_fields=[field for path in (('_path',) if plain else
                ('event.dataset','data_stream.dataset') if shape=='elastic' else ('event.dataset',))
                if (field := native_field(contract, path, 'in'))]
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
                yield from composite_pages(client,target,body,store.reasons,heartbeat=heartbeat,
                    max_pages=max_pages, deadline=time.monotonic()+deadline_seconds)
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
            reads_activity = activity and bool(declared or dataset_fields)
            data_logs=[log for log in logs if log.family!='sensor_health' and (not reads_activity or exact(log))]
            if reads_activity and data_logs:
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
                    store.activity(who,log.family,max(window.start.timestamp(),start),
                                   min(window.end.timestamp(),start+900),bucket['doc_count'])
                    if log.name != 'conn':
                        store.analyzer(who,log.name,bucket['doc_count'])
            for log in [item for item in logs if item in HEALTH_LOGS and exact(item)]:
                paths={spec.typed:next((native_field(contract,path,'exists') for path in spec.paths.get(shape,())
                                       if native_field(contract,path,'exists')),None) for spec in log.fields}
                required = (('health.interval_s','health.capture_loss_pct') if log.name=='capture_loss' else
                            ('health.packets_dropped','health.packets_link','health.worker'))
                # Numeric doc values are aggregatable even when the general
                # contract advertises only numeric range predicates.
                def readable(field, contract=contract):
                    return field and (contract.fields[field].aggregatable or
                                      contract.fields[field].type in {'float','double'})
                if not all(readable(paths.get(typed)) for typed in required):
                    for bucket in read([log],[key('time',contract.time_field)]):
                        store.issue(sensor(bucket),f'{target}: health unreadable: {log.name} measurement fields not aggregatable')
                    continue
                if log.name=='capture_loss' and paths.get('health.interval_s') and paths.get('health.capture_loss_pct'):
                    sources=[key('time',contract.time_field), key('interval',contract.fields[paths['health.interval_s']].native),
                             key('loss',contract.fields[paths['health.capture_loss_pct']].native)]
                    # A health row timestamps the end of its interval. Bounded lookahead
                    # retrieves intervals straddling the hunt's end; missing coverage remains partial.
                    scope=Window(start=window.start,end=window.end+timedelta(hours=24 if health_lookahead else 0))
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
    if resolve:
        store.resolve_stats(policy.stats_interval_seconds,complete=not store.reasons)
    store.checkpoint()
