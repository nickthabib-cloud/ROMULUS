"""Cleartext credential presence without retaining any credential-bearing text.

Distinct (sensor, UID) connection facts are disk-backed and folded per client,
server and protocol. Repeated credential rows never inflate the connection count.
"""
from __future__ import annotations

import hashlib
import ipaddress
from typing import ClassVar

from romulus.detect.base import Match, Playbook, pf
from romulus.detect.bounded import StateExhausted
from romulus.detect.netdef import DIRECTION_ASSUMED_REASON, assume_direction, current
from romulus.detect.windows_rows import row_key
from romulus.detect.windows_sequence_extensions import _Rows
from romulus.evidence.typed import NETWORK_OBSERVER_FAMILIES
from romulus.hunt.citations import COMPACT_CITATION_NOTE, compact_event, expand_event

_FIELDS = frozenset({'observer.name', 'observer.product', 'zeek.log', 'zeek.uid', 'source.ip',
                     'destination.ip', 'auth.cleartext_credentials_present', 'user.name', 'auth.target_account'})
_POSITIVE = ('Only positively typed cleartext credential presence is assessed; this observation does not '
             'establish account compromise or whether authentication succeeded.')


class _CredentialRows(_Rows):
    schema = (*_Rows.schema,
        ('CREATE TABLE IF NOT EXISTS clear_connections(k TEXT,sensor TEXT,uid TEXT,first REAL,last REAL,'
         'first_event BLOB,last_event BLOB,PRIMARY KEY(k,sensor,uid))'),
        'CREATE INDEX IF NOT EXISTS clear_connections_group ON clear_connections(k,first,last)',
        ('CREATE TABLE IF NOT EXISTS clear_groups(k TEXT PRIMARY KEY,n INTEGER,first REAL,last REAL,'
         'first_event BLOB,last_event BLOB)'),
    )

    def add(self, key, sensor, uid, event):
        store = self.store()
        previous = store.execute('SELECT first,last,LENGTH(first_event),LENGTH(last_event) FROM clear_connections WHERE k=? AND sensor=? AND uid=?',
                                 (key, sensor, uid)).fetchone()
        stamp = event.ts.timestamp()
        if previous and previous[0] <= stamp <= previous[1]:
            return False
        caveats = [*event.caveats, COMPACT_CITATION_NOTE]
        if len(event.raw) > 3:
            note = 'Only three native references per credential witness are retained; citation reference coverage is partial.'
            caveats.append(note)
            self.owner.note_limit('cleartext_references', note)
        payload = compact_event(event.model_copy(update={
            'fields': {k: v for k, v in event.fields.items() if k in _FIELDS},
            'raw': event.raw[:3], 'caveats': list(dict.fromkeys(caveats))}))
        delta = (len(payload) - previous[2 if stamp < previous[0] else 3] if previous else
                 len(payload)*2 + len(key.encode()) + len(sensor.encode()) + len(uid.encode()) + 256)
        if delta > 0 and not self.room():
            self.owner.refuse('cleartext_disk', 'The disk budget refused distinct cleartext-credential connection facts.')
            return False
        if previous:
            side = 'first' if stamp < previous[0] else 'last'
            store.write(f'UPDATE clear_connections SET {side}=?,{side}_event=? WHERE k=? AND sensor=? AND uid=?',
                        [(stamp, payload, key, sensor, uid)], account=self.account)
        else:
            store.write('INSERT INTO clear_connections VALUES(?,?,?,?,?,?,?)',
                        [(key, sensor, uid, stamp, stamp, payload, payload)], account=self.account)
        self.owner.state_budget().charge(self.account, delta)
        group = store.execute('SELECT n,first,last,first_event,last_event FROM clear_groups WHERE k=?', (key,)).fetchone()
        if group is None:
            store.write('INSERT INTO clear_groups VALUES(?,?,?,?,?,?)',
                        [(key, 1, stamp, stamp, payload, payload)], account=self.account)
            self.owner.state_budget().charge(self.account, len(key.encode()) + len(payload)*2 + 128)
        else:
            count, first, last, first_event, last_event = group
            earlier, later = stamp < first, stamp > last
            store.write('UPDATE clear_groups SET n=?,first=?,last=?,first_event=?,last_event=? WHERE k=?',
                        [(count + int(previous is None), min(first, stamp), max(last, stamp),
                          payload if earlier else first_event, payload if later else last_event, key)], account=self.account)
            self.owner.state_budget().charge(self.account,
                (len(payload)-len(first_event) if earlier else 0) + (len(payload)-len(last_event) if later else 0))
        return True


class CleartextCredentials(Playbook):
    id = 'net.cleartext_credentials'
    title = 'A credential sent in cleartext'
    families = tuple(sorted(NETWORK_OBSERVER_FAMILIES))
    kind = 'aggregate'
    direct_eligible = False
    claim_type = 'network_observation'
    assures_negative = False
    positive_only_reason = _POSITIVE
    direction_dependent = True
    attack = ('T1078', 'T1040')
    benign = ('Legacy applications and device management can send credentials in cleartext; this is a hygiene issue.',)
    next_checks = ('Review the authentication protocol and remove cleartext credentials from the network.',)
    research = ('https://attack.mitre.org/techniques/T1078/', 'https://attack.mitre.org/techniques/T1040/')
    card: ClassVar[dict] = {
        'behavior': title, 'telemetry': 'Typed Zeek credential-presence boolean, endpoints, protocol and connection UID.',
        'fidelity': 'Credential sent in cleartext; no credential value is retained or claimed.',
        'benign_and_cost': benign[0], 'query_cost': 'Indexed disk-backed distinct sensor/UID connection counts.',
        'next_pivot': next_checks[0], 'adds': title, 'research_basis': '; '.join(research),
        'lanes': 'Boundary crossing lead at most; internal-only observations context.', 'retrieval': _POSITIVE,
    }

    def __init__(self):
        super().__init__()
        self.rows = _CredentialRows(self)
        self.note_coverage('cleartext_presence', _POSITIVE)

    def _emit(self, key, *, final=False):
        store = self.rows.store()
        count, first, last, first_event, last_event = store.execute(
            'SELECT n,first,last,first_event,last_event FROM clear_groups WHERE k=?', (key,)).fetchone()
        events = {event.id: event for payload in (first_event, last_event) for event in [expand_event(payload)]}
        selected = sorted(events.values(), key=lambda event: (event.ts, event.id))
        event = selected[0]
        client, server, protocol = (event.get(name) for name in ('source.ip', 'destination.ip', 'zeek.log'))
        boundary = current().is_internal(ipaddress.ip_address(client)) != current().is_internal(ipaddress.ip_address(server))
        lane = 'lead' if boundary else 'context'
        # Ordinary candidate revisions cannot revise a context item. Wait until
        # the hunt is complete before publishing its complete hygiene count.
        if lane == 'context' and not final:
            return None
        marker = 'cleartext-published:' + key
        signature = row_key(count, first, last)
        previous = self.rows.marker(marker)
        if previous == signature:
            return None
        self.rows.remember(marker, signature)
        account = event.get('user.name') or event.get('auth.target_account')
        account_text = f' for account {account}' if isinstance(account, str) and account else ''
        notes = [_POSITIVE, 'This is a credential-transport hygiene observation, not attack evidence by itself.',
                 'Counts are distinct (connection UID, sensor); first and last credential witnesses are cited.',
                 'ATT&CK context (not proof): T1078; T1040 is exposure context.']
        if not current().configured:
            notes.append(DIRECTION_ASSUMED_REASON)
        return Match(self.id,
            f'A credential was sent in cleartext over {protocol.upper()} from {client} to {server}{account_text} '
            f'({count} connection' + ('s' if count != 1 else '') + ').',
            self.claim_type, selected,
            [pf(ev, name) for ev in selected for name in sorted(_FIELDS) if ev.has(name)],
            selected[-1].ts, 'low', lane, 'medium', event.entities(), notes,
            group_key=self.id + ':' + hashlib.sha256(key.encode()).hexdigest(), bounded_revision=True,
            revision_reason='Updated distinct connection count or first/last credential witnesses.' if previous else '',
            aggregate_summary={'peak': count, 'episodes': 1, 'first': first, 'last': last}, attack=self.attack)

    def consume(self, events):
        for event in self.scope_partition(events):
            if not event.normalizer.startswith('zeek-ecs@') or event.get('observer.product') != 'zeek':
                continue
            if not self._events_pre_scoped:
                self.os_applicable += 1
            self.evaluated += 1
            if event.get('auth.cleartext_credentials_present') is not True:
                continue
            names = ('source.ip', 'destination.ip', 'zeek.log', 'observer.name', 'zeek.uid')
            values = [event.get(name) for name in names]
            if any(not isinstance(value, str) or not value.strip() for value in values):
                self.missing_required += 1
                self.evaluated -= 1
                continue
            client, server, protocol, sensor, uid = values
            try:
                ipaddress.ip_address(client)
                ipaddress.ip_address(server)
            except ValueError:
                self.missing_required += 1
                self.evaluated -= 1
                continue
            assume_direction(self)
            key = row_key(client, server, protocol)
            try:
                if self.rows.add(key, sensor, uid, event):
                    match = self._emit(key)
                    if match:
                        yield match
            except StateExhausted as error:
                self.refuse('cleartext_disk', f'Cleartext-credential connection state was refused by the disk budget: {error}')

    def finalize(self):
        if not self.rows.ready:
            return
        for (key,) in self.rows.store().execute('SELECT k FROM clear_groups ORDER BY k'):
            match = self._emit(key, final=True)
            if match:
                yield match

    def release_state(self):
        self.rows.close()


RULES = (CleartextCredentials,)
