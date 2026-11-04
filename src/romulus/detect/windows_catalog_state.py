"""Positive SQL, RDP, filtering-platform and SAM observations with budgeted history."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import sqlite3
from datetime import UTC, datetime
from typing import ClassVar

from romulus.detect.base import Match, Playbook, pf
from romulus.detect.bounded import StateExhausted
from romulus.detect.windows_behavior import BehaviorFleetRule
from romulus.detect.windows_burst_rows import BurstRows, _event_id
from romulus.detect.windows_cmdline import is_user_writable
from romulus.detect.windows_events import basename, signal
from romulus.detect.windows_rows import WindowsRows, row_key
from romulus.evidence.typed import Outcome
from romulus.evidence.windows_catalog import SECURITY

RDP = 'Microsoft-Windows-RemoteDesktopServices-RdpCoreTS'
RDP_CHANNEL = RDP + '/Operational'


class MssqlLoginBruteforce(Playbook):
    id = 'win.mssql_login_bruteforce'
    version = "2"
    title = 'SQL Server failed login concentration'
    families = ('database_audit',)
    os_families = ('windows',)
    windows_event_classes = tuple(('Application', 'MSSQLSERVER', code) for code in (18456,))
    kind = 'aggregate'
    assures_negative = False
    positive_only_reason = "SQL login concentration is positive-only; absent or incomplete audit records cannot establish no guessing."
    seconds = 300
    attack = ('T1110.001', 'T1110.003')
    citation_fields = ('event.code', 'event.channel', 'event.provider', 'db.instance', 'db.action',
                       'db.login.name', 'db.login.client_ip', 'host.full_name')
    required_fields = ('db.action', 'db.login.name', 'db.instance')
    rationale = ('Ten failed-login records or eight distinct login names in five minutes flags concentration, '
                 'not proven guessing. A stale application password or legitimate test can produce this shape.')
    card: ClassVar[dict] = {'behavior': title, 'telemetry': 'SQL Server Application login auditing',
            'fidelity': rationale, 'query_cost': 'Indexed disk-backed five-minute windows; bounded citation examples.',
            'benign_and_cost': 'Stale credentials, maintenance and legitimate tests.',
            'next_pivot': 'Review SQL audit reason, client ownership and successful logins.',
            'research_basis': 'https://learn.microsoft.com/sql/relational-databases/errors-events/mssqlserver-18456-database-engine-error'}

    def __init__(self):
        super().__init__()
        self.rows = BurstRows(self)

    def _key(self, event):
        client = event.get('db.login.client_ip')
        return row_key(event.host, event.get('db.instance'), client or ['login', event.get('db.login.name')])

    def _state(self, key):
        return json.loads(self.rows.marker('state:' + key) or '{}')

    def _evaluate(self, key, event_id, stamp, state):
        witnesses = self.rows.witnesses(key, stamp, self.seconds, 10, latest=True)
        breadth = False
        if len(witnesses) < 10:
            distinct = self.rows.witnesses(key, stamp, self.seconds, 8, distinct=True, latest=True)
            if len(distinct) == 8:
                witnesses = distinct
                breadth = True
        strong = len(witnesses) >= 10 or breadth
        distinct = self.rows.witnesses(key, stamp, self.seconds, 3, distinct=True, latest=True)
        interval = (self.rows._lookup(key), self.rows._lookup('sa'), stamp-self.seconds, stamp)
        sa = self.rows._execute(
            'SELECT id,ts FROM windows_rows WHERE k=? AND value=? AND ts>=? AND ts<=? UNION ALL '
            'SELECT id,ts FROM windows_archive WHERE k=? AND value=? AND ts>=? AND ts<=? '
            'ORDER BY ts DESC,id DESC LIMIT 1',
            (*interval, *interval)).fetchone()
        strong = strong and (len(distinct) >= 3 or sa is not None)
        state['count'] = max(state.get('count', 0), len(witnesses))
        # A missing client address cannot establish one remote source's burst.
        remote = json.loads(key)[2]
        strong = strong and isinstance(remote, str)
        if strong:
            # Keep the native rows deciding the additional gate, even when they
            # precede the latest ten failures. Replace redundant count examples:
            # ten total records (or all eight distinct names) still prove the burst.
            deciding = distinct if len(distinct) >= 3 else [(_event_id(sa[0]), sa[1])]
            deciding_ids = {identity for identity, _stamp in deciding}
            redundant = [item for item in witnesses if item[0] not in deciding_ids]
            witnesses = sorted([*deciding, *redundant[:len(witnesses)-len(deciding)]],
                               key=lambda item: (item[1], item[0]), reverse=True)
        if witnesses and (strong > state.get('high', False) or
                          strong == state.get('high', False) and stamp >= state.get('stamp', float('-inf'))):
            state.update(high=strong, stamp=stamp, ids=[item[0] for item in witnesses],
                         start=min(item[1] for item in witnesses))
        return state

    def _match(self, key, state):
        events = [event.model_copy(update={'family': 'database_audit'}) for event in self.rows.compact(state['ids'])]
        if not events:
            self.note_limit('sql_citations', 'SQL login concentration was computed but no native witness could be retained.')
            return Match(self.id,
                         f'SQL Server failed-login concentration was computed from retained history '
                         f'({state["count"]} retained records across this key, not a single-window count); '
                         'native witness citations are unavailable. '
                         + ('A 300-second concentration threshold had qualified.' if state.get('high') else
                            'The concentration threshold was not established.'),
                         'aggregate_observation', [], [], datetime.fromtimestamp(state['stamp'], UTC),
                         'high' if state.get('high') else 'medium', 'high' if state.get('high') else 'lead',
                         'medium', [], ['citation_unavailable: Native SQL witness references could not be read.', self.rationale],
                         group_key='sql-login:' + hashlib.sha256(key.encode()).hexdigest(),
                         bounded_revision=True, citation_unavailable=True,
                         revision_reason='Computed concentration retained with unavailable native witness citations.')
        anchor = max(events, key=lambda event: (event.ts, event.id))
        host, instance, client = json.loads(key)
        text = (f'SQL Server retained {state["count"]} failed-login record(s) on {host}, instance {instance}; '
                f'client {client if isinstance(client, str) else "not recorded; grouped only by login"}. '
                'The cumulative retained count spans the key history, not only the following window. '
                f'The cited {len(events)} record(s) support a 300-second window ending '
                f'{anchor.ts.isoformat()}; '
                + ('at least ten failures or eight distinct login names qualified, with at least three distinct logins or the privileged sa login. ' if state.get('high') else
                   'the concentration threshold with login breadth or privileged sa has not been established. ')
                + 'These are recorded failures, not proof that guessing succeeded.')
        return Match(self.id, text, 'aggregate_observation', events,
                     [pf(event, name) for event in events for name in self.citation_fields if event.has(name)],
                     anchor.ts, 'high' if state.get('high') else 'medium', 'high' if state.get('high') else 'lead',
                     'high', anchor.entities(), [self.rationale, 'Citations are bounded window examples, not every retained login.'],
                     group_key='sql-login:' + hashlib.sha256(key.encode()).hexdigest(), bounded_revision=True,
                     revision_reason='Retained failures revised the bounded concentration observation.')

    def consume(self, events):
        scoped = self.applicable(events)
        selected = [event for event in scoped if event.get('db.action') == 'login_failed']
        if not selected:
            return []
        out = []
        try:
            with self.rows.batch():
                for event in sorted(selected, key=lambda item: (item.ts, item.id)):
                    key = self._key(event)
                    if not self.rows.put(key, event, str(event.get('db.login.name')).casefold()):
                        self.note_limit('sql_history', 'A failed-login record could not enter correlation history; its single observation is retained.')
                        out.append(self._single(event))
                        continue
                    state = self._state(key)
                    old_high = state.get('high', False)
                    state['count'] = state.get('count', 0) + 1
                    self._evaluate(key, event.id, event.ts.timestamp(), state)
                    self.rows.remember('state:' + key, json.dumps(state, sort_keys=True))
                    count = state['count']
                    if count == 1 or state.get('high', False) != old_high or not count & (count - 1):
                        match = self._match(key, state)
                        if match:
                            out.append(match)
        except StateExhausted as error:
            self.note_limit('sql_history', f'Correlation history could not be allocated: {error}')
            out.extend(self._single(event) for event in selected)
        return out

    def _single(self, event):
        return Match(self.id, 'SQL Server recorded a failed login; correlation history could not be retained.',
                     'observed_action', [event],
                     [pf(event, name) for name in self.citation_fields if event.has(name)], event.ts,
                     'medium', 'lead', 'high', event.entities(),
                     ['The disk refusal prevents a complete concentration assessment.'],
                     group_key='sql-login-refused:' + event.id)

    def finalize(self):
        if not self.rows.ready:
            return
        with self.rows.batch():
            current, state = None, None
            for key, event_id, stamp, _value, _host in self.rows.iterate():
                if key != current:
                    if current is not None:
                        self.rows.remember('state:' + current, json.dumps(state, sort_keys=True))
                        match = self._match(current, state)
                        if match:
                            yield match
                    current, state = key, self._state(key)
                self._evaluate(key, event_id, stamp, state)
            if current is not None:
                self.rows.remember('state:' + current, json.dumps(state, sort_keys=True))
                match = self._match(current, state)
                if match:
                    yield match

    def release_state(self):
        self.rows.close()
        super().release_state()


class _ConnectionRows(WindowsRows):
    """Apply the physical cap before allocating optional connection-context schema."""

    def store(self):
        spill = self.owner.spill()
        if not self.ready:
            self.account = self.owner.state_budget().account(f'{self.owner.id}:windows_rows', strong=True)
            spill.cap()
            try:
                spill.db.execute('SAVEPOINT connection_schema')
                spill.db.execute('CREATE TABLE IF NOT EXISTS windows_rows(k TEXT,id TEXT,ts REAL,value TEXT,event TEXT,raw TEXT,PRIMARY KEY(k,id))')
                spill.db.execute('CREATE INDEX IF NOT EXISTS windows_rows_time ON windows_rows(k,ts,id)')
                spill.db.execute('CREATE INDEX IF NOT EXISTS windows_rows_value ON windows_rows(k,value,ts)')
                spill.db.execute('CREATE TABLE IF NOT EXISTS windows_marks(k TEXT PRIMARY KEY,value TEXT)')
                spill.db.execute('RELEASE connection_schema')
                self.ready = True
            except sqlite3.OperationalError as error:
                spill.db.rollback()
                raise spill.failed(error, account=self.account) from error
            finally:
                spill.grew()
        return spill


class _RdpObservation(BehaviorFleetRule):
    families = ('remote_access',)
    required_fields = ()
    attack = ('T1021.001',)

    def __init__(self):
        super().__init__()
        self.connections = _ConnectionRows(self)

    def consume(self, events):
        for event in self.scope_partition(events):
            if event.get('remote.action') == 'rdp_connection_accepted' and event.get('remote.connection_activity'):
                try:
                    self.connections.put(row_key(event.host, event.get('remote.connection_activity')), event)
                except StateExhausted as error:
                    self.note_limit('rdp_context', f'Connection context could not be retained: {error}')
        return super().consume(events)

    def _connection(self, event):
        activity = event.get('remote.connection_activity')
        if not activity or not self.connections.ready:
            return None
        return self.connections.prior(row_key(event.host, activity), event.ts.timestamp(), float('inf'))

    def describe_signal(self, event, text, fields, lane):
        activity = event.get('remote.connection_activity')
        context = self._connection(event)
        peer = context[0].get('source.ip') if context else None
        sentence = text + (f'; connection-activity correlation names client {peer}' if peer else
                           '; client IP was not established from a connection-activity record')
        hit = signal(event, self.id, sentence, self.attack, fields, lane=lane,
                     content=row_key(event.host, peer or activity or event.id, text), common=sentence)
        if context:
            hit.context.append(context[0])
            hit.raw_copies.update(context[1])
        return hit

    def release_state(self):
        self.connections.close()
        super().release_state()

    def _fleet_match(self, shape, group, *, final):
        match = super()._fleet_match(shape, group, final=final)
        if match is None:
            return None
        for event in list(match.events):
            activity = event.get('remote.connection_activity')
            if not activity:
                continue
            context = self._connection(event)
            if context and context[0].get('source.ip'):
                connection, raw = context
                peer = connection.get('source.ip')
                match.claim = match.claim.replace(
                    'client IP was not established from a connection-activity record',
                    f'connection-activity correlation names client {peer}')
                if connection.id not in {item.id for item in match.events}:
                    match.events.append(connection)
                    match.context_ids.add(connection.id)
                    match.raw_copies.update(raw)
                    match.predicate.extend([pf(connection, name) for name in ('source.ip', 'remote.connection_activity')
                                            if connection.has(name)])
                    match.notes.append('The additional connection record is supporting context, not a counted channel/display record.')
                break
        return match

    def finalize(self):
        # Even a single immediately published observation can gain connection context later.
        for shape in self.order.keys():  # noqa: SIM118 (streaming KeyedStore)
            group = self.groups.peek(shape)
            if group is not None:
                match = self._fleet_match(shape, group, final=True)
                if match is not None:
                    yield match


class RdpBluekeepChannel(_RdpObservation):
    id = 'win.rdp_bluekeep_channel'
    title = 'Internal RDP channel observed on the base tunnel'
    windows_event_classes = tuple((RDP_CHANNEL, RDP, code) for code in (131, 132, 148))
    attack = ('T1210',)
    benign = ('An observed channel is not proof that exploitation succeeded.',)
    next_checks = ('Inspect the correlated connection source and session outcome.',)
    research = ('https://msrc.microsoft.com/update-guide/vulnerability/CVE-2019-0708',)

    def judge(self, event):
        if event.get('remote.action') not in {'rdp_channel_created', 'rdp_channel_closed'}:
            return []
        channel = event.get('remote.channel_name')
        if channel is None or event.get('remote.tunnel_id') is None:
            self.missing_required += 1
            return []
        if str(channel).casefold() != 'ms_t120' or str(event.get('remote.tunnel_id')) != '0':
            return []
        return [self.describe_signal(event, 'RDP recorded the internal ms_t120 virtual channel on tunnel 0',
                                    ('remote.channel_name', 'remote.tunnel_id', 'remote.connection_activity'), 'high')]


class RdpHeadlessClient(_RdpObservation):
    id = 'win.rdp_headless_client'
    title = 'RDP client requested a small display'
    windows_event_classes = tuple((RDP_CHANNEL, RDP, code) for code in (131, 168))
    benign = ('Thin clients, minimized desktops and automated legitimate RDP clients can request small displays.',)
    next_checks = ('Review the connection source and commands in the session.',)
    research = ('https://learn.microsoft.com/openspecs/windows_protocols/ms-rdpbcgr/',)

    def judge(self, event):
        if event.get('remote.action') != 'rdp_client_resolution':
            return []
        width, height = event.get('remote.monitor_width'), event.get('remote.monitor_height')
        if not all(isinstance(value, int) and not isinstance(value, bool) and value > 0 for value in (width, height)):
            self.missing_required += 1
            return []
        if width > 320 or height > 320:
            return []
        return [self.describe_signal(event, f'RDP client requested a {width}x{height} display',
                                    ('remote.monitor_width', 'remote.monitor_height', 'remote.connection_activity'), 'lead')]


class RdpLoopbackTunnel(BehaviorFleetRule):
    id = 'win.rdp_loopback_tunnel'
    title = 'Non-RDP application connected over loopback to RDP'
    families = ('network_filter',)
    windows_event_classes = (('Security', SECURITY, 5156),)
    required_fields = ('wfp.application',)
    attack = ('T1572', 'T1090.001')
    benign = ('Local forwarding and legitimate proxy software can create this connection.',)
    next_checks = ('Inspect the application lineage and forwarding configuration.',)
    research = ('https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5156',)

    def fleet_eligible(self, event, hit):
        return False

    def judge(self, event):
        if event.get('event.code') != 5156:
            return []
        app = event.get('wfp.application_key') or event.get('wfp.application')
        if basename(app) in {'mstsc.exe', 'svchost.exe', 'system'}:
            return []
        for endpoint in ('source', 'destination'):
            try:
                loopback = ipaddress.ip_address(str(event.get(endpoint + '.ip'))).is_loopback
            except ValueError:
                continue
            if loopback and event.get(endpoint + '.port') == 3389:
                return [signal(event, 'loopback_rdp', f'WFP permitted a loopback port 3389 connection by {app}',
                               self.attack, ('wfp.application', endpoint + '.ip', endpoint + '.port'), lane='high',
                               content=row_key(event.host, app, endpoint),
                               notes=('A loopback connection is observed; a remote tunnel or its success is not established.',))]
        return []


class SamAdminEnumeration(BehaviorFleetRule):
    id = 'win.sam_admin_enumeration'
    title = 'Privileged SAM membership or handles enumerated'
    families = ('object_access', 'security_enumeration')
    windows_event_classes = tuple(('Security', SECURITY, code) for code in (4661, 4798, 4799))
    attack = ('T1087.001', 'T1087.002', 'T1069.001', 'T1069.002')
    benign = ('Administrative consoles, monitoring and authorized directory tools enumerate these objects.',)
    next_checks = ('Review subject identity, caller process and adjacent directory operations.',)
    research = ('https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4799',)

    def fleet_eligible(self, event, hit):
        return not any(is_user_writable(str(event.get(name) or '')) for name in
                       ('enum.caller_process', 'process.executable'))

    def judge(self, event):
        user = event.get('user.name')
        if not user:
            self.missing_required += 1
            return []
        if str(user).endswith('$'):
            return []
        if event.family == 'object_access':
            if str(event.get('object.server')).casefold() != 'security account manager':
                return []
            if str(event.get('object.type')).upper() not in {'SAM_USER', 'SAM_GROUP', 'SAM_ALIAS'}:
                return []
            target = event.get('object.name')
        else:
            target = event.get('enum.target_sid')
        if not target:
            self.missing_required += 1
            return []
        if not re.fullmatch(r'S-1-5-(?:[0-9]+-){1,14}(?:500|502|512|519|520|544|551|555)',
                            str(target), re.IGNORECASE):
            return []
        if event.family == 'object_access':
            action = 'made a refused handle request for' if event.outcome == Outcome.failure else 'requested a handle for'
        else:
            action = 'made a refused enumeration request for' if event.outcome == Outcome.failure else 'enumerated'
        text = f'Account {user} {action} privileged SAM object {target}'
        return [signal(event, 'sam_enumeration', text,
                       self.attack, ('user.name', 'object.type', 'object.name', 'enum.target_sid', 'enum.caller_process'),
                       content=row_key(user, target, action), common=text)]


RULES = (MssqlLoginBruteforce, RdpBluekeepChannel, RdpHeadlessClient, RdpLoopbackTunnel, SamAdminEnumeration)
