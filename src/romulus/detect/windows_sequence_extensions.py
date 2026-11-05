"""Indexed Windows sequences; replay reconstructs rows and stable publication identities."""
from __future__ import annotations

import hashlib
import ipaddress
import sqlite3

from romulus.detect.base import Match, pf
from romulus.detect.bounded import StateExhausted
from romulus.detect.netdef import current
from romulus.detect.windows_compact_rows import CompactWindowsRows
from romulus.detect.windows_events import WindowsEventRule, basename, integer
from romulus.detect.windows_path_data import installation_parts
from romulus.detect.windows_registry_events import _target
from romulus.detect.windows_rows import row_key
from romulus.evidence.typed import Outcome
from romulus.evidence.windows import windows_path_key
from romulus.evidence.windows_catalog import SECURITY, SYSMON, SYSMON_CHANNEL
from romulus.hunt.citations import COMPACT_CITATION_NOTE, compact_event

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


class _ParentRows(_Rows):
    schema = (*_Rows.schema, 'CREATE TABLE IF NOT EXISTS ppid_pending(k TEXT,id TEXT,ts REAL,PRIMARY KEY(k,id))',
              'CREATE INDEX IF NOT EXISTS ppid_pending_time ON ppid_pending(k,ts,id)',
              'CREATE TABLE IF NOT EXISTS ppid_broker_children(k TEXT,id TEXT,ts REAL,PRIMARY KEY(k,id))',
              'CREATE INDEX IF NOT EXISTS ppid_broker_time ON ppid_broker_children(k,ts,id)',
              'CREATE INDEX IF NOT EXISTS ppid_access_priority ON windows_rows(k,raw,ts,id)')

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
    version = '2'

    def consume(self, events):
        # Current-partition children are not yet in the shared event stage.
        self._current_children = {event.id: event for event in events if event.family == 'process_exec'}
        self._current_parents = {(event.host, str(event.get('process.guid')).casefold()):
            str(event.get('process.parent.guid')).casefold() for event in events
            if event.family == 'process_exec' and event.get('process.guid') and event.get('process.parent.guid')}
        try:
            yield from super().consume(events)
        finally:
            self._current_children = {}
            self._current_parents = {}

    def _target_parent(self, host, guid):
        parents = {row[0] for row in self.rows.store().execute(
            "SELECT DISTINCT value FROM windows_rows WHERE k=? AND value!='' LIMIT 2",
            (row_key('creation', host, str(guid).casefold()),))}
        live = getattr(self, '_current_parents', {}).get((host, str(guid).casefold()))
        if live:
            parents.add(live)
        if len(parents) > 1:
            self.note_limit('parent_creation_conflict', 'Conflicting recorded target parents leave the creator-handle comparison unresolved.')
        return next(iter(parents)) if len(parents) == 1 else None

    def _accept(self, access):
        target = str(access.get('target.guid')).casefold()
        parent = self._target_parent(access.host, target)
        if parent is not None and parent == str(access.get('source.guid')).casefold():
            return
        key = row_key('access' if parent is not None else 'pending_access', access.host, target)
        inserted = self.rows.put(key, access, str(access.get('source.guid')).casefold())
        if parent is not None:
            yield from self._children(access, retained_access=None if inserted else access)

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
        elif event.family == 'process_exec' and event.get('event.code') == 1:
            parent, child = event.get('process.parent.guid'), event.get('process.guid')
            if child:
                known = row_key('creation', event.host, str(child).casefold())
                self.rows.fingerprint(known, event, str(parent or '').casefold())
                pending = row_key('pending_access', event.host, str(child).casefold())
                for _key, access, _raw, _value in self.rows.iterate(pending):
                    yield from self._accept(access)
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
            row = self.rows.store().execute(
                'SELECT event,raw FROM windows_rows WHERE k=? AND raw=? AND ts>=? AND ts<=? '
                'AND value!=? ORDER BY ts DESC,id LIMIT 1',
                (row_key('access', child.host, parent), priority,
                 child.ts.timestamp()-PPID_SECONDS, child.ts.timestamp(),
                 str(child.get('process.guid')).casefold())).fetchone()
            if row:
                access, _copies = self.rows.hydrate(row)
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
        count = int(self.rows.marker(identity) or 0) + 1
        self.rows.remember(identity, str(count))
        notes = ['The access source differs from the claimed parent and child GUIDs. The actual creator is not independently recorded; this is a parent-spoofing sequence for review, not proof of spoofing.',
                 'Citations are bounded examples of the latest matching sequence; the count covers retained matching children.']
        if broker:
            notes.append('A canonical System32 broker can legitimately reparent processes; review the reparenting context.')
        if self._target_parent(child.host, access.get('target.guid')) is None:
            notes.append('The target creation record is outside the retained context; its recorded parent could not be checked.')
        claim = (f"Process '{source}' opened target '{target}' with PROCESS_CREATE_PROCESS (0x80); child '{image}' "
                 f"was recorded under that target within {PPID_SECONDS} seconds. {count} matching child sequence(s) on {child.host}.")
        records = [child, access]
        return Match(self.id, claim, self.claim_type, records,
            [pf(e, name) for e in records for name in sorted(_FIELDS) if e.has(name)], child.ts,
            'low' if broker else 'high', 'lead' if broker else 'high', 'medium', child.entities(),
            [*notes, 'ATT&CK context (not proof): T1134.004'], group_key=identity, bounded_revision=True,
            revision_reason='The bounded sequence count and latest citation sample are updated.' if count > 1 else '',
            context_ids={access.id})

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
        elif event.family == 'registry_change' and event.get('event.code') == 13:
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
        elif event.family == 'registry_change' and event.get('event.code') == 13 and runmru_write(event):
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
    id, title = 'win.smb_host_discovery', 'One host connected to many internal SMB hosts'
    families = ('net_socket',)
    windows_event_classes = ((SYSMON_CHANNEL, SYSMON, 3),)
    attack = ('T1135', 'T1018')
    rows_type = _SmbRows
    version = '2'

    def observe(self, event):
        if (event.get('event.code') != 3 or event.get('destination.port') != 445
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
        self.rows.coalesce(row_key('smb', event.host), event, str(address))

    def finalize(self):
        if not self.rows.ready:
            return
        store = self.rows.store()
        previous, count = None, 0
        cursor = store.execute('SELECT k,ts,delta,id FROM ('
            'SELECT k,ts,1 AS delta,id FROM windows_rows UNION ALL '
            'SELECT k,CAST(raw AS REAL) AS ts,-1 AS delta,id FROM windows_rows) '
            'ORDER BY k,ts,delta DESC,id')
        for key, end, delta, identity in cursor:
            if self.rows.marked(self.id + ':' + key):
                continue
            if key != previous:
                previous, count = key, 0
            count += delta
            if delta < 0 or count < SMB_DISCOVERY_HOSTS:
                continue
            row = store.execute('SELECT event,raw FROM windows_rows WHERE k=? AND id=?', (key, identity)).fetchone()
            event, _raw = self.rows.hydrate(row)
            witnesses = self.rows.witnesses(key, end, SMB_DISCOVERY_SECONDS, 3, distinct=True)
            notes = ['Distinct destination window intervals are coalesced and disk-backed; the shared disk budget is the named cap.',
                     'Citations are bounded examples; interval unions retain counts without retaining every repeated connection body.',
                     'Software deployment, inventory and scanners can produce this discovery lead.']
            if not current().configured:
                notes.append('Internal direction uses the default site network ranges; internal networks are not declared.')
            match = self.observation(event, [e for e, _ in witnesses if e.id != event.id],
                f'Host {event.host} opened TCP port 445 connections to at least {count} distinct internal hosts '
                'within ten minutes.', notes=notes, identity=self.id + ':' + key)
            if match:
                yield match


RULES = (ParentProcessSpoofing, SamAdminRegistryWithoutAudit, RdpRunMruWrite, SmbHostDiscovery)
