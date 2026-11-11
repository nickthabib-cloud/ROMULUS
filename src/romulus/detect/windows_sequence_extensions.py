"""Indexed Windows sequences; replay reconstructs rows and stable publication identities."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import sqlite3
from datetime import UTC, datetime

from romulus.detect.base import Match, pf
from romulus.detect.bounded import StateExhausted
from romulus.detect.netdef import current
from romulus.detect.windows_compact_rows import CompactWindowsRows
from romulus.detect.windows_ecar import class_discriminator
from romulus.detect.windows_events import WindowsEventRule, basename, integer
from romulus.detect.windows_path_data import installation_parts
from romulus.detect.windows_registry_events import _target
from romulus.detect.windows_rows import row_key
from romulus.evidence.typed import Outcome
from romulus.evidence.windows import windows_path_key
from romulus.evidence.windows_catalog import SECURITY, SYSMON, SYSMON_CHANNEL
from romulus.hunt.citations import COMPACT_CITATION_NOTE, compact_event, expand_event

# The handle and process start are adjacent operations; ten seconds allows scheduling/logging delay,
# without treating an old handle to a long-lived parent as evidence of this creation.
PPID_SECONDS = 10
AUDIT_CONTEXT_SECONDS = 300
# An interactive RDP action is a lead only within the next ten minutes, not the whole logon lifetime.
RDP_ACTION_SECONDS = 600
SMB_DISCOVERY_SECONDS, SMB_DISCOVERY_HOSTS = 600, 25
_FIELDS = frozenset({
    'event.code', 'event.channel', 'event.provider', 'host.os.family',
    'source.guid', 'source.pid', 'source.executable', 'target.guid', 'target.pid', 'target.executable',
    'process.guid', 'process.parent.guid', 'process.access.mask', 'process.executable',
    'registry.path_key', 'registry.action', 'registry.event_type', 'registry.value_name',
    'auth.logon_type', 'source.ip', 'destination.ip', 'destination.port', 'network.direction',
    'network.transport',
    'account.group_id', 'account.member_id', 'account.member_name',
})
_DOC = 'https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon'


def _packed(event):
    compact = event.model_copy(update={
        'fields': {name: fact for name, fact in event.fields.items() if name in _FIELDS},
        'caveats': list(dict.fromkeys([*event.caveats, COMPACT_CITATION_NOTE]))})
    return compact_event(compact).hex()


class _Rows(CompactWindowsRows):
    schema = (
        'CREATE TABLE IF NOT EXISTS windows_rows(k TEXT,id TEXT,ts REAL,value TEXT,event TEXT,raw TEXT,PRIMARY KEY(k,id))',
        'CREATE INDEX IF NOT EXISTS windows_rows_time ON windows_rows(k,ts,id)',
        'CREATE INDEX IF NOT EXISTS windows_rows_value ON windows_rows(k,value,ts)',
        'CREATE TABLE IF NOT EXISTS windows_marks(k TEXT PRIMARY KEY,value TEXT)',
    )

    def compact_fields(self, key):
        return _FIELDS

    def store(self):
        spill = self.owner.spill()
        if not self.ready:
            self.account = self.owner.state_budget().account(f'{self.owner.id}:windows_rows', strong=True)
            spill.cap()
            try:
                spill.db.execute('SAVEPOINT sequence_schema')
                for sql in self.schema:
                    spill.db.execute(sql)
                spill.db.execute('RELEASE sequence_schema')
                self.ready = True
            except sqlite3.OperationalError as error:
                spill.db.rollback()
                raise spill.failed(error, account=self.account) from error
            finally:
                spill.grew()
        return spill


class _SmbRows(_Rows):
    schema = (*_Rows.schema,
        'CREATE TABLE IF NOT EXISTS smb_active(k TEXT,value TEXT,ts REAL,PRIMARY KEY(k,value))',
        'CREATE INDEX IF NOT EXISTS smb_active_time ON smb_active(k,ts)',
        'CREATE TABLE IF NOT EXISTS smb_progress(k TEXT PRIMARY KEY,body TEXT)')

    def progress(self, key):
        row = self.store().execute('SELECT body FROM smb_progress WHERE k=?', (key,)).fetchone()
        return json.loads(row[0]) if row else None

    def advance(self, key, event, destination):
        store = self.store()
        prior = store.execute('SELECT body FROM smb_progress WHERE k=?', (key,)).fetchone()
        state = json.loads(prior[0]) if prior else _smb_state()
        stamp = event.ts.timestamp()
        if stamp < state.get('watermark', stamp):
            return
        expired, expired_bytes = store.execute(
            'SELECT COUNT(*),COALESCE(SUM(LENGTH(k)+LENGTH(value)+96),0) FROM smb_active WHERE k=? AND ts<?',
            (key, stamp-SMB_DISCOVERY_SECONDS)).fetchone()
        count = state.get('count', 0)-expired
        if count < SMB_DISCOVERY_HOSTS:
            state['open'] = False
        existing = store.execute('SELECT 1 FROM smb_active WHERE k=? AND value=? AND ts>=?',
            (key, destination, stamp-SMB_DISCOVERY_SECONDS)).fetchone()
        if not existing:
            count += 1
        state.update(watermark=stamp, count=count)
        if count >= SMB_DISCOVERY_HOSTS:
            _smb_qualify(state, count, stamp, _packed(event))
        body = json.dumps(state, separators=(',', ':'))
        delta = (-expired_bytes + (0 if existing else len(key.encode())+len(destination.encode())+96)
                 + len(body.encode())-(len(prior[0].encode()) if prior else 0)
                 + (0 if prior else len(key.encode())+96))
        if delta > 0 and not self.room():
            raise StateExhausted('The disk budget refused derived SMB episode state.')
        store.cap()
        try:
            store.db.execute('SAVEPOINT smb_advance')
            store.db.execute('DELETE FROM smb_active WHERE k=? AND ts<?', (key, stamp-SMB_DISCOVERY_SECONDS))
            store.db.execute('INSERT INTO smb_active VALUES(?,?,?) ON CONFLICT(k,value) DO UPDATE SET ts=excluded.ts',
                (key, destination, stamp))
            store.db.execute('INSERT INTO smb_progress VALUES(?,?) ON CONFLICT(k) DO UPDATE SET body=excluded.body', (key, body))
            store.db.execute('RELEASE smb_advance')
        except sqlite3.OperationalError as error:
            store.db.rollback()
            raise store.failed(error, account=self.account) from error
        finally:
            store.grew()
        self.owner.state_budget().charge(self.account, delta)
        return state

    def scan(self):
        return self.store().execute('SELECT b.k,b.ts,b.delta,b.id,m.last_ts FROM ('
            'SELECT k,ts,1 AS delta,id FROM windows_rows UNION ALL '
            'SELECT k,CAST(raw AS REAL) AS ts,-1 AS delta,id FROM windows_rows) b '
            'JOIN (SELECT k,MAX(CAST(raw AS REAL))-? AS last_ts FROM windows_rows GROUP BY k) m ON m.k=b.k '
            'ORDER BY b.k,b.ts,b.delta DESC,b.id', (SMB_DISCOVERY_SECONDS,))

    def coalesce(self, key, event, destination):
        """Union the window-end intervals [connection time, time + window] per destination.

        Repeated connections extend an interval; separated intervals stay on disk
        so later/out-of-order rows cannot erase an older qualifying window.
        """
        store = self.store()
        start, end = event.ts.timestamp(), event.ts.timestamp() + SMB_DISCOVERY_SECONDS
        fields = {name: fact for name, fact in event.fields.items() if name in _FIELDS}
        payload = compact_event(event.model_copy(update={'fields': fields,
            'caveats': list(dict.fromkeys([*event.caveats, COMPACT_CITATION_NOTE]))}))
        identity, old_bytes = event.id, 0
        # Disjoint retained intervals mean each row can be merged at most once.
        for prior_id, left, right, prior_payload in store.execute(
                'SELECT id,ts,raw,event FROM windows_rows WHERE k=? AND value=? AND ts<=? '
                'AND CAST(raw AS REAL)>=? ORDER BY ts,id', (key, destination, end, start)):
            old_bytes += len(key.encode()) + len(destination.encode()) + len(prior_payload) + len(right.encode()) + 256
            end = max(end, float(right))
            if left < start or (left == start and prior_id < identity):
                start, identity, payload = left, prior_id, prior_payload
        raw = str(end)
        size = len(key.encode()) + len(destination.encode()) + len(payload) + len(raw.encode()) + 256
        if size > old_bytes and not self.room():
            self.owner.refuse('smb_distinct_hosts', 'The disk budget refused growth of the coalesced SMB window history.')
            return
        store.cap()
        try:
            store.db.execute('SAVEPOINT smb_interval')
            store.db.execute('DELETE FROM windows_rows WHERE k=? AND value=? AND ts<=? AND CAST(raw AS REAL)>=?',
                             (key, destination, event.ts.timestamp()+SMB_DISCOVERY_SECONDS, event.ts.timestamp()))
            store.db.execute('INSERT INTO windows_rows VALUES(?,?,?,?,?,?)', (key, identity, start, destination, payload, raw))
            store.db.execute('RELEASE smb_interval')
        except sqlite3.OperationalError as error:
            store.db.rollback()
            raise store.failed(error, account=self.account) from error
        finally:
            store.grew()
        self.owner.state_budget().charge(self.account, size-old_bytes)


def _smb_state():
    return {'episodes': 0, 'peak': 0, 'first': None, 'last': None,
            'peak_start': 0., 'peak_end': 0., 'open': False}


def _smb_qualify(state, count, stamp, proof):
    if not state['open']:
        state['episodes'] += 1
        state['open'] = True
        state['episode_start'] = stamp
    if state['first'] is None:
        state.update(first=stamp, first_event=proof)
    state['last'] = stamp
    if count > state['peak']:
        state.update(peak=count, peak_start=stamp-SMB_DISCOVERY_SECONDS, peak_end=stamp, peak_event=proof)


class _ParentRows(_Rows):
    schema = (*_Rows.schema, 'CREATE TABLE IF NOT EXISTS ppid_pending(k TEXT,id TEXT,ts REAL,PRIMARY KEY(k,id))',
              'CREATE INDEX IF NOT EXISTS ppid_pending_time ON ppid_pending(k,ts,id)',
              'CREATE TABLE IF NOT EXISTS ppid_broker_children(k TEXT,id TEXT,ts REAL,PRIMARY KEY(k,id))',
              'CREATE INDEX IF NOT EXISTS ppid_broker_time ON ppid_broker_children(k,ts,id)',
              'CREATE INDEX IF NOT EXISTS ppid_access_priority ON windows_rows(k,raw,ts,id)',
              ('CREATE TABLE IF NOT EXISTS ppid_members(shape TEXT,id TEXT,host TEXT,target TEXT,source TEXT,'
               'access_id TEXT,high INTEGER,valid INTEGER,PRIMARY KEY(shape,id))'),
              'CREATE INDEX IF NOT EXISTS ppid_member_target ON ppid_members(host,target,source,valid,shape)',
              'CREATE INDEX IF NOT EXISTS ppid_member_high ON ppid_members(shape,valid,high,id)')

    def put(self, key, event, value=''):
        compact = event.model_copy(update={
            'fields': {name: fact for name, fact in event.fields.items() if name in _FIELDS},
            'caveats': list(dict.fromkeys([*event.caveats, COMPACT_CITATION_NOTE]))})
        # Compact payloads do not use the raw-body column; an indexed priority
        # avoids rescanning many broker accesses when judging each new child.
        priority = '1' if self.owner._broker(event.get('source.executable')) else '0'
        return self._insert(key, event, value, compact_event(compact), priority)

    def queue(self, key, event):
        store = self.store()
        if self.marked(self.owner.id + ':' + event.id) or store.execute(
                'SELECT 1 FROM ppid_pending WHERE k=? AND id=?', (key, event.id)).fetchone():
            return
        if not self.room():
            self.owner.refuse('ppid_pending', 'The disk budget refused a pending parent-sequence child.')
            return
        store.write('INSERT INTO ppid_pending VALUES(?,?,?)', [(key, event.id, event.ts.timestamp())])
        self.owner.state_budget().charge(self.account, len(key)+len(event.id)+96)

    def forget(self, child, tables=('ppid_pending', 'ppid_broker_children')):
        key = row_key('child', child.host, str(child.get('process.parent.guid')).casefold())
        for table in tables:
            if self.store().execute(f'SELECT 1 FROM {table} WHERE k=? AND id=?', (key, child.id)).fetchone():
                self.store().write(f'DELETE FROM {table} WHERE k=? AND id=?', [(key, child.id)])
                self.owner.state_budget().charge(self.account, -(len(key)+len(child.id)+96))

    def provisional(self, child):
        key = row_key('child', child.host, str(child.get('process.parent.guid')).casefold())
        if not self.store().execute('SELECT 1 FROM ppid_broker_children WHERE k=? AND id=?', (key, child.id)).fetchone():
            self.store().write('INSERT INTO ppid_broker_children VALUES(?,?,?)', [(key, child.id, child.ts.timestamp())])
            self.owner.state_budget().charge(self.account, len(key)+len(child.id)+96)
        self.forget(child, ('ppid_pending',))

    def remove(self, key, identity):
        store = self.store()
        row = store.execute('SELECT value,event,raw FROM windows_rows WHERE k=? AND id=?', (key, identity)).fetchone()
        if row:
            size = sum(len(value if isinstance(value, bytes) else value.encode()) for value in (key, *row)) + 256
            store.write('DELETE FROM windows_rows WHERE k=? AND id=?', [(key, identity)])
            self.owner.state_budget().charge(self.account, -size)


class _Sequence(WindowsEventRule):
    direct_eligible = False
    claim_type = 'correlated_observation'
    research = (_DOC,)
    benign = ('Authorized administration and software diagnostics can produce these observations.',)
    next_checks = ('Inspect the cited native records, actor and adjacent activity.',)
    rows_type = _Rows

    def __init__(self):
        super().__init__()
        self.rows = self.rows_type(self)

    def release_state(self):
        self.rows.close()
        super().release_state()

    def consume(self, events):
        for event in self.scope_partition(events):
            if not self._events_pre_scoped:
                self.os_applicable += 1
            self.evaluated += 1
            try:
                yield from self.observe(event) or ()
            except StateExhausted as error:
                self.refuse('sequence_rows', f'Indexed sequence growth is incomplete: {error}')

    def observation(self, subject, context, claim, *, lane='lead', severity='low', notes=(), identity=None):
        identity = identity or self.id + ':' + subject.id
        if not self.rows.first(identity):
            return None
        records = [subject, *context]
        return Match(self.id, claim, self.claim_type, records,
                     [pf(e, name) for e in records for name in sorted(_FIELDS) if e.has(name)],
                     subject.ts, severity, lane, 'medium', subject.entities(),
                     [*notes, 'ATT&CK context (not proof): ' + ', '.join(self.attack)], group_key=identity,
                     context_ids={e.id for e in context})


class ParentProcessSpoofing(_Sequence):
    id, title = 'win.parent_process_spoofing', 'Parent-process creation rights followed by a child of that parent'
    families = ('process_access', 'process_exec')
    windows_event_classes = tuple((SYSMON_CHANNEL, SYSMON, n) for n in (1, 10))
    attack = ('T1134.004',)
    rows_type = _ParentRows
    version = '3'

    def consume(self, events):
        # Current-partition children are not yet in the shared event stage.
        self._current_children = {event.id: event for event in events if event.family == 'process_exec'}
        self._current_events = {event.id: event for event in events}
        self._current_parents = {}
        for event in events:
            if event.family == 'process_exec' and event.get('process.guid') and event.get('process.parent.guid'):
                key = (event.host, str(event.get('process.guid')).casefold())
                parents = self._current_parents.setdefault(key, {})
                if len(parents) < 2:
                    parents.setdefault(str(event.get('process.parent.guid')).casefold(), event)
        try:
            yield from super().consume(events)
        finally:
            self._current_children = {}
            self._current_events = {}
            self._current_parents = {}

    def _target_parent(self, host, guid):
        parents = {row[0] for row in self.rows.store().execute(
            "SELECT DISTINCT value FROM windows_rows WHERE k=? AND value!='' LIMIT 2",
            (row_key('creation', host, str(guid).casefold()),))}
        live = getattr(self, '_current_parents', {}).get((host, str(guid).casefold()))
        if live:
            parents.update(live)
        if len(parents) > 1:
            self.note_limit('parent_creation_conflict', 'Conflicting recorded target parents leave the creator-handle comparison unresolved.')
        return next(iter(parents)) if len(parents) == 1 else None

    def _parent_conflicts(self, host, guid):
        """At most two native witnesses for the conflicting recorded parents."""
        key = row_key('creation', host, guid)
        records = dict(getattr(self, '_current_parents', {}).get((host, guid), {}))
        for (parent,) in self.rows.store().execute(
                "SELECT DISTINCT value FROM windows_rows WHERE k=? AND value!='' LIMIT 2", (key,)):
            if parent in records:
                continue
            row = self.rows.store().execute('SELECT id FROM windows_rows WHERE k=? AND value=? ORDER BY ts,id LIMIT 1',
                (key, parent)).fetchone()
            if row:
                event = self._record(row[0])
                if event is not None:
                    records[parent] = event
        return [_packed(event) for event in list(records.values())[:2]]

    def _accept(self, access):
        target = str(access.get('target.guid')).casefold()
        parent = self._target_parent(access.host, target)
        if parent is not None and parent == str(access.get('source.guid')).casefold():
            return
        key = row_key('access' if parent is not None else 'pending_access', access.host, target)
        inserted = self.rows.put(key, access, str(access.get('source.guid')).casefold())
        yield from self._children(access, retained_access=access if parent is None or not inserted else None)

    def _children(self, access, *, retained_access=None):
        stamp = access.ts.timestamp()
        args = (row_key('child', access.host, str(access.get('target.guid')).casefold()), stamp, stamp+PPID_SECONDS)
        statement = 'SELECT id,ts FROM ppid_pending WHERE k=? AND ts>=? AND ts<=?'
        if not self._broker(access.get('source.executable')):
            # A broker lead is provisional: a later non-broker access must still
            # expose the stronger sequence, without rescanning completed highs.
            statement += ' UNION SELECT id,ts FROM ppid_broker_children WHERE k=? AND ts>=? AND ts<=?'
            args += args
        cursor = self.rows.store().execute(statement + ' ORDER BY ts,id', args)
        for identity, _stamp in cursor:
            child = getattr(self, '_current_children', {}).get(identity) or self._load_one(identity)
            if child is not None:
                match = self._judge_child(child, retained_access=retained_access)
                if match:
                    yield match

    def observe(self, event):
        if event.family == 'process_access' and event.get('event.code') == 10:
            mask, pid = integer(event.get('process.access.mask')), integer(event.get('source.pid'))
            source, target = event.get('source.guid'), event.get('target.guid')
            image = basename(event.get('source.executable'))
            if (mask is not None and mask & 0x80 and pid is not None and pid != 4
                    and image and image != 'system' and source and target
                    and str(source).casefold() != str(target).casefold()):
                yield from self._accept(event)
        elif event.family == 'process_exec' and class_discriminator(event, 1, 'process_exec'):
            parent, child = event.get('process.parent.guid'), event.get('process.guid')
            if child:
                known = row_key('creation', event.host, str(child).casefold())
                self.rows.fingerprint(known, event, str(parent or '').casefold())
                if parent:
                    yield from self._correct_creator(event)
                pending = row_key('pending_access', event.host, str(child).casefold())
                resolved = self._target_parent(event.host, child) is not None
                for _key, access, _raw, _value in self.rows.iterate(pending):
                    yield from self._accept(access)
                    # Ambiguous target parents retain the access under this same
                    # pending key; a later child still needs that positive witness.
                    if resolved:
                        self.rows.remove(pending, access.id)
            if parent and child:
                key = row_key('child', event.host, str(parent).casefold())
                if self.rows.fingerprint(key, event, str(child).casefold()):
                    self._pending.append(event)
                self.rows.queue(key, event)
                match = self._judge_child(event)
                if match:
                    yield match

    def _judge_child(self, child, *, retained_access=None):
        parent = str(child.get('process.parent.guid')).casefold()
        access = None
        for priority in ('0', '1'):
            for kind in ('access', 'pending_access'):
                row = self.rows.store().execute(
                    'SELECT event,raw FROM windows_rows WHERE k=? AND raw=? AND ts>=? AND ts<=? '
                    'AND value!=? ORDER BY ts DESC,id LIMIT 1',
                    (row_key(kind, child.host, parent), priority,
                     child.ts.timestamp()-PPID_SECONDS, child.ts.timestamp(),
                     str(child.get('process.guid')).casefold())).fetchone()
                if row:
                    candidate, _copies = self.rows.hydrate(row)
                    if access is None or candidate.ts > access.ts:
                        access = candidate
            if access is not None:
                break
        if (retained_access is not None
                and str(retained_access.get('source.guid')).casefold() != str(child.get('process.guid')).casefold()
                and (access is None or self._broker(access.get('source.executable'))
                     and not self._broker(retained_access.get('source.executable')))):
            access = retained_access
        if access is not None:
            match = self._observation(child, access)
            try:
                if self._broker(access.get('source.executable')):
                    self.rows.provisional(child)
                else:
                    self.rows.forget(child)
            except StateExhausted as error:
                self.note_limit('ppid_pending', f'Completed-child bookkeeping is partial: {error}')
            return match

    @staticmethod
    def _broker(source):
        parts = installation_parts(source)
        return (len(parts) == 3 and parts[:2] == ('windows', 'system32')
                and parts[-1] in {'svchost.exe', 'csrss.exe', 'conhost.exe', 'services.exe', 'wininit.exe'})

    def _observation(self, child, access):
        broker = self._broker(access.get('source.executable'))
        completed = self.id + ':' + child.id
        if self.rows.marked(completed) or not self.rows.first(completed + (':broker' if broker else '')):
            return None
        source = str(access.get('source.executable') or 'unrecorded source image')
        target = str(access.get('target.executable') or 'unrecorded target image')
        image = str(child.get('process.executable') or 'unrecorded child image')
        canonical = windows_path_key(source)
        identity = self.id + ':fold:' + hashlib.sha256(row_key(child.host, canonical, windows_path_key(target)).encode()).hexdigest()
        previous = self.rows.marker(identity)
        state = json.loads(previous) if previous else {
            'count': 0, 'high': 0, 'corrected': 0, 'first': [_packed(child), _packed(access)],
            'source': source, 'target': target, 'broker': broker, 'host': child.host}
        pair = [_packed(child), _packed(access)]
        unknown = self._target_parent(child.host, access.get('target.guid')) is None
        if unknown and not state.get('conflicts'):
            conflicts = self._parent_conflicts(child.host, str(access.get('target.guid')).casefold())
            if len(conflicts) == 2:
                state['conflicts'] = conflicts
        first = expand_event(bytes.fromhex(state['first'][0]))
        if (child.ts, child.id) < (first.ts, first.id):
            state['first'] = pair
        latest = expand_event(bytes.fromhex(state['latest'][0])) if 'latest' in state else None
        if latest is None or (child.ts, child.id) > (latest.ts, latest.id):
            state.update(latest=pair, image=image, ts=child.ts.timestamp(), unknown=unknown)
        state.update(count=state['count']+1, high=state['high']+int(not broker))
        self.rows.remember(identity, json.dumps(state, separators=(',', ':')))
        values = (identity, child.id, child.host, str(access.get('target.guid')).casefold(),
                  str(access.get('source.guid')).casefold(), access.id, int(not broker), 1)
        try:
            if self.rows.room():
                self.rows.store().write('INSERT OR IGNORE INTO ppid_members VALUES(?,?,?,?,?,?,?,?)', [values])
                self.state_budget().charge(self.rows.account, sum(len(str(value).encode()) for value in values)+128)
            else:
                self.note_limit('ppid_corrections', 'Creator-handle correction membership could not grow; later corrections are partial.')
        except StateExhausted as error:
            self.note_limit('ppid_corrections', f'Creator-handle correction membership is partial: {error}')
        self._pending.append(access)
        return self._fold_match(identity, state, reason='The matching-child count and latest sequence changed.' if state['count'] > 1 else '')

    def _record(self, identity):
        return (getattr(self, '_current_events', {}).get(identity)
                or next((event for event in self.load([identity]) if event.id == identity), None))

    def _fold_match(self, identity, state, *, reason='', correction=None):
        records = {event.id: event for pair in (state['first'], state['latest'])
                   for event in (expand_event(bytes.fromhex(payload)) for payload in pair)}
        conflicts = [expand_event(bytes.fromhex(payload)) for payload in state.get('conflicts', ())]
        records.update((event.id, event) for event in conflicts)
        if correction is not None:
            records[correction.id] = correction
        unavailable = False
        if state['high']:
            row = self.rows.store().execute('SELECT id,access_id FROM ppid_members '
                'WHERE shape=? AND valid=1 AND high=1 LIMIT 1', (identity,)).fetchone()
            if row:
                for event_id in row:
                    if event_id not in records:
                        event = self._record(event_id)
                        if event is None:
                            unavailable = True
                        else:
                            records[event.id] = event
        notes = ['The access source differs from the claimed parent and child GUIDs. The actual creator is not independently recorded; this is a parent-spoofing sequence for review, not proof of spoofing.',
                 'Citations retain the first and latest sequences; counts cover retained matching children.']
        if state['broker']:
            notes.append('A canonical System32 broker can legitimately reparent processes; review the reparenting context.')
        if state.get('conflicts'):
            notes.append('Conflicting recorded target parents leave a creator-handle comparison unresolved; affected sequences remain candidates for review.')
        elif correction is None and state.get('unknown'):
            notes.append('The target creation record is outside the retained context; its recorded parent could not be checked.')
        if state['corrected']:
            notes.append(f"Later target creation records establish {state['corrected']} creator-handle sequence(s); those no longer support a spoofing HIGH.")
        if unavailable:
            self.note_limit('ppid_citations', 'A remaining high sequence could not be loaded for its bounded citation sample.')
            notes.append('A retained high sequence remains in the count, but its optional citation could not be loaded.')
        claim = (f"Process '{state['source']}' opened target '{state['target']}' with PROCESS_CREATE_PROCESS (0x80); "
                 f"child '{state['image']}' was recorded under that target within {PPID_SECONDS} seconds. "
                 f"{state['count']} matching child sequence(s) on {state['host']}.")
        if state['corrected']:
            claim += (f" {state['corrected']} later established as creator handles, "
                      f"with {state['high']} remaining non-broker sequence(s).")
        records = list(records.values())
        latest = expand_event(bytes.fromhex(state['latest'][0]))
        return Match(self.id, claim, self.claim_type, records,
            [pf(e, name) for e in records for name in sorted(_FIELDS) if e.has(name)], latest.ts,
            'high' if state['high'] else 'low', 'high' if state['high'] else 'lead', 'medium', latest.entities(),
            [*notes, 'ATT&CK context (not proof): T1134.004'], group_key=identity, bounded_revision=True,
            revision_reason=reason, citation_unavailable=unavailable,
            context_ids={event.id for event in records if event.family != 'process_exec' or event is correction
                         or event.id in {record.id for record in conflicts}})

    def _correct_creator(self, creation):
        target = str(creation.get('process.guid')).casefold()
        source = self._target_parent(creation.host, target)
        conflict = source is None
        proofs = self._parent_conflicts(creation.host, target) if conflict else []
        if conflict:
            # Previously excluded members become unresolved again. Include unchanged
            # folds once so the contradiction is visible even when no lane changes.
            cursor = self.rows.store().execute('SELECT shape,SUM(CASE WHEN valid=0 THEN high ELSE 0 END),'
                'SUM(CASE WHEN valid=0 THEN 1 ELSE 0 END) FROM ppid_members '
                'WHERE host=? AND target=? GROUP BY shape', (creation.host, target))
        else:
            cursor = self.rows.store().execute('SELECT shape,SUM(high),COUNT(*) FROM ppid_members '
                'WHERE host=? AND target=? AND source=? AND valid=1 GROUP BY shape', (creation.host, target, source))
        for identity, high, count in cursor:
            raw = self.rows.marker(identity)
            if raw is None:
                continue
            state = json.loads(raw)
            if conflict:
                if not count and state.get('conflicts'):
                    continue
                self.rows.store().write('UPDATE ppid_members SET valid=1 WHERE shape=? AND host=? AND target=? AND valid=0',
                    [(identity, creation.host, target)])
                state['high'] += high
                state['corrected'] = max(0, state['corrected']-count)
                state['conflicts'] = state.get('conflicts') or proofs
                if len(state['conflicts']) < 2:
                    self.note_limit('ppid_citations', 'Both conflicting target creation witnesses could not be loaded.')
                reason = 'Conflicting target creation records leave creator-handle filtering unresolved; previously excluded sequences are restored for review.'
            else:
                self.rows.store().write('UPDATE ppid_members SET valid=0 WHERE shape=? AND host=? AND target=? AND source=? AND valid=1',
                    [(identity, creation.host, target, source)])
                state['high'] = max(0, state['high']-high)
                state['corrected'] += count
                reason = 'A later target creation record establishes a creator handle; the fold lane reflects the remaining high sequences.'
            self.rows.remember(identity, json.dumps(state, separators=(',', ':')))
            yield self._fold_match(identity, state, correction=creation, reason=reason)

    def finalize(self):
        if not self.rows.ready:
            return
        # Only unresolved target creations wait for finalization. Completed children
        # are never rescanned; unknown long-lived targets retain their positive lead/high.
        for key, access, _raw, _value in self.rows.iterate(prefix='["pending_access",'):
            # The access is already retained. No new index allocation is needed
            # to publish it when its target creation remained outside the hunt.
            yield from self._children(access, retained_access=access)
            try:
                self.rows.remove(key, access.id)
            except StateExhausted as error:
                self.note_limit('ppid_pending_access', f'Unresolved-access bookkeeping is partial: {error}')


class SamAdminRegistryWithoutAudit(_Sequence):
    id, title = 'win.sam_admin_registry_without_audit', 'SAM Administrators membership registry value written'
    families = ('registry_change', 'account_change')
    windows_event_classes = ((SYSMON_CHANNEL, SYSMON, 13), ('Security', SECURITY, 4732))
    attack = ('T1098',)
    version = '2'

    def observe(self, event):
        if (event.family == 'account_change' and event.get('event.code') == 4732
                and event.outcome != Outcome.failure
                and str(event.get('account.group_id') or '').casefold() == 's-1-5-32-544'):
            self.rows.put(row_key('audit', event.host), event)
        elif event.family == 'registry_change' and class_discriminator(event, 13, 'registry_change'):
            target = _target(event)
            if (target and target.root == 'hkey_local_machine' and target.action == 'written'
                    and target.key == ('sam', 'sam', 'domains', 'builtin', 'aliases', '00000220')
                    and target.name == 'c'):
                self.rows.put(row_key('sam', event.host), event)

    def finalize(self):
        for key, event, _raw, _value in self.rows.iterate():
            if not key.startswith('["sam",'):
                continue
            stamp = event.ts.timestamp()
            audits = self.rows.store().execute(
                'SELECT event,raw FROM windows_rows WHERE k=? AND ts>=? AND ts<=?',
                (row_key('audit', event.host), stamp-AUDIT_CONTEXT_SECONDS,
                 stamp+AUDIT_CONTEXT_SECONDS))
            if any(self._same_member(event, self.rows.hydrate(row)[0]) for row in audits):
                continue
            site = getattr(self, 'site_facts', None)
            attested = (site and site.attests(event.host, 'event_channel', channel='Security')
                        and site.attests(event.host, 'audit_policy', subcategory='security group management',
                                         outcome='success'))
            notes = [('A corresponding Administrators 4732 membership audit was not established in the retained ±5-minute context; '
                      'this does not prove the account was created without an audit.')]
            if not attested:
                notes.append('4732 audit collection is not attested for this host; missing audit context is unresolved.')
            match = self.observation(event, [], 'A SAM Administrators membership registry value was written.',
                                     notes=notes)
            if match:
                yield match

    @staticmethod
    def _same_member(write, audit):
        for field in ('account.member_id', 'account.member_name'):
            left, right = write.get(field), audit.get(field)
            if left and right:
                return str(left).casefold() == str(right).casefold()
        return True


def runmru_write(event):
    target = _target(event)
    return bool(target and target.action == 'written' and target.root == 'hkey_current_user'
                and target.key == ('software', 'microsoft', 'windows', 'currentversion', 'explorer', 'runmru'))


class RdpRunMruWrite(_Sequence):
    id, title = 'win.rdp_runmru_write', 'Run dialog history written after inbound RDP logon'
    families = ('auth', 'registry_change')
    windows_event_classes = (('Security', SECURITY, 4624), (SYSMON_CHANNEL, SYSMON, 13))
    attack = ('T1021.001',)

    def observe(self, event):
        if (event.family == 'auth' and event.get('event.code') == 4624
                and event.get('auth.logon_type') == 10 and event.outcome == Outcome.success):
            self.rows.put(row_key('rdp', event.host), event)
        elif event.family == 'registry_change' and class_discriminator(event, 13, 'registry_change') and runmru_write(event):
            self.rows.put(row_key('mru', event.host), event)

    def finalize(self):
        for key, event, _raw, _value in self.rows.iterate():
            if key.startswith('["mru",'):
                prior = self.rows.prior(row_key('rdp', event.host), event.ts.timestamp(), RDP_ACTION_SECONDS)
                if prior:
                    match = self.observation(event, [prior[0]],
                        'A RunMRU value was written on a host within ten minutes after a recorded inbound RDP logon.',
                        notes=('Same-host timing is a hypothesis; it does not establish who made the registry write.',))
                    if match:
                        yield match


class SmbHostDiscovery(_Sequence):
    ecar_compatible = True
    id, title = 'win.smb_host_discovery', 'One host connected to many internal SMB hosts'
    families = ('net_socket',)
    windows_event_classes = ((SYSMON_CHANNEL, SYSMON, 3),)
    attack = ('T1135', 'T1018')
    rows_type = _SmbRows
    version = '3'

    def consume(self, events):
        # Dirty membership is partition-sized; all historical summaries live on disk.
        self._dirty_smb = set()
        try:
            yield from super().consume(sorted(events, key=lambda event: (event.ts, event.id)))
            for key in sorted(self._dirty_smb):
                state = self.rows.progress(key)
                if state and state['episodes']:
                    match = self._emit_summary(key, state)
                    if match:
                        yield match
        finally:
            self._dirty_smb = set()

    def observe(self, event):
        if (not class_discriminator(event, 3, 'net_socket') or event.get('destination.port') != 445
                or event.get('network.direction') != 'egress'
                or event.get('network.transport') != 'tcp'):
            return
        try:
            address = ipaddress.ip_address(str(event.get('destination.ip')))
        except ValueError:
            return
        if address.is_loopback or not current().is_internal(address):
            return
        if event.get('source.ip') == str(address):
            return
        key = row_key('smb', event.host)
        self.rows.coalesce(key, event, str(address))
        state = self.rows.advance(key, event, str(address))
        if state and state['episodes']:
            self._dirty_smb.add(key)

    def _published_summary(self, key):
        """Load one bounded publication checkpoint, including native citation witnesses."""
        marker = self.id + ':published:' + key
        raw = self.rows.marker(marker)
        previous = json.loads(raw) if raw else None
        proofs = self.rows.marker(marker + ':events')
        cached = json.loads(proofs) if proofs else {}
        lane = cached.get('lane', 'lead') if isinstance(cached, dict) else 'lead'
        payloads = cached.get('events', []) if isinstance(cached, dict) else cached
        events = [expand_event(bytes.fromhex(value)) for value in payloads]
        lookup = getattr(self, 'published_aggregate', None)
        if previous is None and callable(lookup) and not self.rows.marked(marker + ':checked'):
            published = lookup(self.id + ':' + key)
            if published and published.get('summary'):
                previous = dict(published['summary'])
                events = list(published.get('events') or ())[:4]
                lane = published.get('lane', 'lead')
                self.rows.remember(marker, json.dumps(previous, separators=(',', ':')))
                self.rows.remember(marker + ':events', json.dumps({'lane': lane, 'events': [_packed(event) for event in events]}))
            self.rows.remember(marker + ':checked', '1')
        return marker, previous, events, lane

    @staticmethod
    def _summary_witness(events, stamp):
        return next((event for event in events if event.ts.timestamp() == stamp), None)

    def _emit_summary(self, key, state, *, final=False):
        summary = {name: state[name] for name in ('episodes', 'peak', 'first', 'last', 'peak_start', 'peak_end')}
        computed_episodes = summary['episodes']
        current_first = expand_event(bytes.fromhex(state['first_event']))
        current_peak = expand_event(bytes.fromhex(state['peak_event']))
        first_proof, peak_proof = current_first, current_peak
        marker, previous, previous_events, previous_lane = self._published_summary(key)
        lane = previous_lane if previous_lane in {'urgent', 'high'} else 'lead'
        complete_continuity = final and (not previous or (
            state['first'] <= previous['first'] and state['last'] >= previous['last']))
        forward = self.rows.progress(key) if final else None
        # A completed replay can connect previously observed episodes. Retain the
        # historical observations while reporting reconstructed continuity separately.
        if forward and forward['episodes']:
            summary['episodes'] = max(summary['episodes'], forward['episodes'])
            if forward['peak'] > summary['peak']:
                summary.update(peak=forward['peak'], peak_start=forward['peak_start'], peak_end=forward['peak_end'])
                peak_proof = expand_event(bytes.fromhex(forward['peak_event']))
            if forward['first'] < summary['first']:
                summary['first'] = forward['first']
                first_proof = expand_event(bytes.fromhex(forward['first_event']))
            summary['last'] = max(summary['last'], forward['last'])
        new_start = False
        if previous:
            new_start = not final and state.get('episode_start', state['first']) > previous['last']
            summary['episodes'] = max(summary['episodes'], previous['episodes'])
            if previous['peak'] >= summary['peak']:
                summary.update(peak=previous['peak'], peak_start=previous['peak_start'], peak_end=previous['peak_end'])
                peak_proof = self._summary_witness(
                    [*previous_events, peak_proof, current_peak], previous['peak_end'])
            if previous['first'] <= summary['first']:
                summary['first'] = previous['first']
                first_proof = self._summary_witness(
                    [*previous_events, first_proof, current_first], previous['first'])
            summary['last'] = max(summary['last'], previous['last'])
            if not complete_continuity and 'continuity_episodes' in previous:
                summary['continuity_episodes'] = previous['continuity_episodes']
        if complete_continuity and (computed_episodes < summary['episodes'] or previous and 'continuity_episodes' in previous):
            summary['continuity_episodes'] = computed_episodes
        summary['current_episode_start'] = (state.get('episode_start', state['first']) if complete_continuity or not previous or new_start
            else previous.get('current_episode_start', previous['first']))
        if previous:
            changed = [name for name in ('episodes', 'peak') if summary[name] > previous[name]]
            if new_start:
                changed.append('later qualifying window')
            if final and summary['last'] > previous['last']:
                changed.append('last qualifying window')
            if final and summary['first'] < previous['first']:
                changed.append('first qualifying window')
            if complete_continuity and (summary.get('continuity_episodes') != previous.get('continuity_episodes')
                    or summary['current_episode_start'] != previous.get('current_episode_start', previous['first'])):
                changed.append('continuity reconstruction')
            if not changed:
                return None
            reason = 'Updated SMB ' + ', '.join(changed) + '.'
        else:
            reason = ''
        encoded = json.dumps(summary, separators=(',', ':'))
        self.rows.remember(marker, encoded)
        retained = self.rows.marker(marker) == encoded
        if not retained:
            self.note_limit('smb_published_summary', 'The published SMB summary checkpoint could not be retained; forced replay revisions require a durable checkpoint.')
            if final:
                return None
        # A restored peak and first window keep their actual published witnesses;
        # the current window is an extra bounded example when historical bounds win.
        records = {event.id: event for event in (first_proof, peak_proof, current_peak) if event is not None}
        unavailable = first_proof is None or peak_proof is None
        peak = peak_proof or current_peak
        self.rows.remember(marker + ':events', json.dumps({'lane': lane, 'events': [_packed(event) for event in records.values()]}))
        first, last = (datetime.fromtimestamp(summary[name], UTC).isoformat() for name in ('first', 'last'))
        peak_start, peak_end = (datetime.fromtimestamp(summary[name], UTC).isoformat()
                               for name in ('peak_start', 'peak_end'))
        notes = ['Distinct destination window intervals are coalesced and disk-backed; the shared disk budget is the named cap.',
                 'Citations retain bounded real examples from the first and peak qualifying windows; counts and last-window bounds use all retained interval facts.',
                 'Software deployment, inventory and scanners can produce this discovery lead.',
                 'ATT&CK context (not proof): T1135, T1018']
        continuity = ''
        if 'continuity_episodes' in summary:
            continuity = (f' Previously observed episodes connected by late records; current continuity {summary["continuity_episodes"]}.'
                if complete_continuity else f' Last completed continuity reconstruction: {summary["continuity_episodes"]}; later qualifying windows await ordered reconstruction.')
            notes.append(continuity.strip())
        retained_history = bool(continuity) or summary['episodes'] > computed_episodes
        if retained_history and not complete_continuity:
            notes.append('Episode count retains historical observations; current continuity awaits complete ordered reconstruction.')
        if unavailable:
            self.note_limit('smb_published_witnesses', 'A historical SMB first/peak witness could not be restored; citation coverage is partial.')
            notes.append('A historical first/peak window remains in the summary, but its native witness could not be restored.')
        if not current().configured:
            notes.append('Internal direction uses the default site network ranges; internal networks are not declared.')
        if lane in {'urgent', 'high'}:
            notes.append('Lane retained from the previously published observation; this SMB analytic otherwise emits a lead.')
        return Match(self.id,
            f'Host {peak.host} {"retains" if retained_history else "has"} {summary["episodes"]} qualifying episodes '
            f'{"previously observed " if retained_history else ""}of internal SMB discovery; '
            f'peak {summary["peak"]} distinct TCP port 445 destinations in ten minutes. '
            f'Peak window {peak_start} – {peak_end}. '
            f'First qualifying window ended {first}; last qualifying window ended {last}.' + continuity,
            self.claim_type, list(records.values()),
            [pf(event, name) for event in records.values() for name in sorted(_FIELDS) if event.has(name)],
            peak.ts, 'high' if lane in {'urgent', 'high'} else 'low', lane, 'medium', peak.entities(), notes,
            group_key=self.id + ':' + key, bounded_revision=True, revision_reason=reason,
            aggregate_summary=summary, citation_unavailable=unavailable)

    def finalize(self):
        if not self.rows.ready:
            return
        store, previous, state, count = self.rows.store(), None, None, 0
        try:
            for key, stamp, delta, identity, last_ts in self.rows.scan():
                if key != previous:
                    if state and state['episodes']:
                        match = self._emit_summary(previous, state, final=True)
                        if match:
                            yield match
                    previous, state, count = key, _smb_state(), 0
                if delta < 0 and count >= SMB_DISCOVERY_HOSTS:
                    state['last'] = max(state['last'], min(stamp, last_ts))
                count += delta
                if count < SMB_DISCOVERY_HOSTS:
                    state['open'] = False
                elif delta > 0:
                    row = store.execute('SELECT event FROM windows_rows WHERE k=? AND id=?', (key, identity)).fetchone()
                    _smb_qualify(state, count, stamp, bytes(row[0]).hex())
            if state and state['episodes']:
                match = self._emit_summary(previous, state, final=True)
                if match:
                    yield match
        except (StateExhausted, sqlite3.Error) as error:
            # No forced emit for the interrupted key: its previously published
            # summary and citations remain intact, rather than becoming a prefix.
            self.note_limit('smb_episode_replay', f'SMB episode replay is partial; the interrupted key was not revised: {error}')


RULES = (ParentProcessSpoofing, SamAdminRegistryWithoutAudit, RdpRunMruWrite, SmbHostDiscovery)
