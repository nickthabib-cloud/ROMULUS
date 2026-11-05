"""Indexed Windows sequences; replay reconstructs rows and stable publication identities."""
from __future__ import annotations

import ipaddress
import sqlite3

from romulus.detect.base import Match, pf
from romulus.detect.bounded import StateExhausted
from romulus.detect.netdef import current
from romulus.detect.windows_compact_rows import CompactWindowsRows
from romulus.detect.windows_events import WindowsEventRule, basename, integer
from romulus.detect.windows_registry_events import _target
from romulus.detect.windows_rows import row_key
from romulus.evidence.typed import Outcome
from romulus.evidence.windows_catalog import SECURITY, SYSMON, SYSMON_CHANNEL

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
    schema = (*_Rows.schema, 'CREATE TABLE IF NOT EXISTS smb_active(value TEXT PRIMARY KEY,ts REAL)',
              'CREATE INDEX IF NOT EXISTS smb_active_time ON smb_active(ts)')


class _ParentRows(_Rows):
    schema = (*_Rows.schema, 'CREATE TABLE IF NOT EXISTS ppid_pending(k TEXT,id TEXT,ts REAL,PRIMARY KEY(k,id))',
              'CREATE INDEX IF NOT EXISTS ppid_pending_time ON ppid_pending(k,ts,id)')

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

    def forget(self, child):
        key = row_key('child', child.host, str(child.get('process.parent.guid')).casefold())
        if self.store().execute('SELECT 1 FROM ppid_pending WHERE k=? AND id=?', (key, child.id)).fetchone():
            self.store().write('DELETE FROM ppid_pending WHERE k=? AND id=?', [(key, child.id)])
            self.owner.state_budget().charge(self.account, -(len(key)+len(child.id)+96))


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

    def observe(self, event):
        if event.family == 'process_access' and event.get('event.code') == 10:
            mask, pid = integer(event.get('process.access.mask')), integer(event.get('source.pid'))
            source, target = event.get('source.guid'), event.get('target.guid')
            image = basename(event.get('source.executable'))
            if (mask is not None and mask & 0x80 and pid is not None and pid != 4
                    and image and image != 'system' and source and target
                    and str(source).casefold() != str(target).casefold()
                    and self.rows.put(row_key('access', event.host, str(target).casefold()), event, str(source).casefold())):
                cursor = self.rows.store().execute(
                    'SELECT w.event,w.raw FROM ppid_pending p JOIN windows_rows w ON w.k=p.k AND w.id=p.id '
                    'WHERE p.k=? AND p.ts>=? AND p.ts<=? ORDER BY p.ts,p.id',
                    (row_key('child', event.host, str(target).casefold()),
                     event.ts.timestamp(), event.ts.timestamp()+PPID_SECONDS))
                for row in cursor:
                    match = self._judge_child(self.rows.hydrate(row)[0])
                    if match:
                        yield match
        elif event.family == 'process_exec' and event.get('event.code') == 1:
            parent, child = event.get('process.parent.guid'), event.get('process.guid')
            if parent and child:
                key = row_key('child', event.host, str(parent).casefold())
                self.rows.put(key, event)
                self.rows.queue(key, event)
                match = self._judge_child(event)
                if match:
                    yield match

    def _judge_child(self, child):
        parent = str(child.get('process.parent.guid')).casefold()
        row = self.rows.store().execute(
            'SELECT event,raw FROM windows_rows WHERE k=? AND ts>=? AND ts<=? AND value!=? ORDER BY ts DESC,id LIMIT 1',
            (row_key('access', child.host, parent), child.ts.timestamp()-PPID_SECONDS, child.ts.timestamp(),
             str(child.get('process.guid')).casefold())).fetchone()
        if row:
            access, _copies = self.rows.hydrate(row)
            match = self.observation(child, [access],
                f"A non-System process opened parent GUID {parent} with PROCESS_CREATE_PROCESS (0x80), "
                f"then a different process was recorded with that parent GUID within {PPID_SECONDS} seconds.",
                lane='high', severity='high',
                notes=(('The access source differs from the claimed parent and child GUIDs. The actual creator is '
                        'not independently recorded; this is a parent-spoofing sequence for review, not proof of spoofing.'),))
            self.rows.forget(child)
            return match

    def finalize(self):
        if not self.rows.ready:
            return
        cursor = self.rows.store().execute(
            'SELECT w.event,w.raw FROM ppid_pending p JOIN windows_rows w ON w.k=p.k AND w.id=p.id ORDER BY p.k,p.ts,p.id')
        for row in cursor:
            match = self._judge_child(self.rows.hydrate(row)[0])
            if match:
                yield match


class SamAdminRegistryWithoutAudit(_Sequence):
    id, title = 'win.sam_admin_registry_without_audit', 'SAM Administrators membership registry value written'
    families = ('registry_change', 'account_change')
    windows_event_classes = ((SYSMON_CHANNEL, SYSMON, 13), ('Security', SECURITY, 4720),
                            ('Security', SECURITY, 4732))
    attack = ('T1098',)

    def observe(self, event):
        if event.family == 'account_change' and event.get('event.code') in {4720, 4732}:
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
            found = self.rows.store().execute(
                'SELECT 1 FROM windows_rows WHERE k=? AND ts>=? AND ts<=? LIMIT 1',
                (row_key('audit', event.host), stamp-AUDIT_CONTEXT_SECONDS,
                 stamp+AUDIT_CONTEXT_SECONDS)).fetchone()
            if found:
                continue
            site = getattr(self, 'site_facts', None)
            attested = (site and site.attests(event.host, 'event_channel', channel='Security')
                        and site.attests(event.host, 'audit_policy', subcategory='security group management',
                                         outcome='success'))
            notes = [('A corresponding 4720/4732 audit was not established in the retained ±5-minute context; '
                      'this does not prove the account was created without an audit.')]
            if not attested:
                notes.append('4732 audit collection is not attested for this host; missing audit context is unresolved.')
            match = self.observation(event, [], 'A SAM Administrators membership registry value was written.',
                                     notes=notes)
            if match:
                yield match


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
        self.rows.put(row_key('smb', event.host), event, str(address))

    def finalize(self):
        if not self.rows.ready:
            return
        store = self.rows.store()
        previous, count, active_bytes = None, 0, getattr(self, '_active_bytes', 0)
        store.write('DELETE FROM smb_active', [()])
        self.state_budget().charge(self.rows.account, -active_bytes)
        active_bytes = 0
        for key, event, _raw, _value in self.rows.iterate():
            if not key.startswith('["smb",'):
                continue
            if self.rows.marked(self.id + ':' + key):
                continue
            if key != previous:
                store.write('DELETE FROM smb_active', [()])
                self.state_budget().charge(self.rows.account, -active_bytes)
                previous, count, active_bytes = key, 0, 0
            end = event.ts.timestamp()
            expired, expired_bytes = store.execute(
                'SELECT COUNT(*),COALESCE(SUM(LENGTH(value)+96),0) FROM smb_active WHERE ts<?',
                (end-SMB_DISCOVERY_SECONDS,)).fetchone()
            if expired:
                store.write('DELETE FROM smb_active WHERE ts<?', [(end-SMB_DISCOVERY_SECONDS,)])
                count -= expired
                active_bytes -= expired_bytes
                self.state_budget().charge(self.rows.account, -expired_bytes)
            exists = store.execute('SELECT 1 FROM smb_active WHERE value=?', (_value,)).fetchone()
            if not exists and not self.rows.room():
                self.note_limit('smb_distinct_hosts', 'The disk budget refused growth of the SMB distinct-host window.')
                continue
            store.write('INSERT INTO smb_active VALUES(?,?) ON CONFLICT(value) DO UPDATE SET ts=excluded.ts',
                        [(_value, end)])
            if not exists:
                size = len(_value) + 96
                active_bytes += size
                self.state_budget().charge(self.rows.account, size)
                count += 1
            self._active_bytes = active_bytes
            if count < SMB_DISCOVERY_HOSTS:
                continue
            witnesses = self.rows.witnesses(key, end, SMB_DISCOVERY_SECONDS, 3, distinct=True)
            notes = ['Distinct membership and deduplication are disk-backed; the shared disk budget is the named cap.',
                     'Software deployment, inventory and scanners can produce this discovery lead.']
            if not current().configured:
                notes.append('Internal direction uses the default site network ranges; internal networks are not declared.')
            match = self.observation(event, [e for e, _ in witnesses if e.id != event.id],
                f'Host {event.host} opened TCP port 445 connections to at least {count} distinct internal hosts '
                'within ten minutes.', notes=notes, identity=self.id + ':' + key)
            if match:
                yield match


RULES = (ParentProcessSpoofing, SamAdminRegistryWithoutAudit, RdpRunMruWrite, SmbHostDiscovery)
