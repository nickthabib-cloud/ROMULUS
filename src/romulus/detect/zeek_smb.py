"""Executable bytes linked to an administrative-share file by sensor, FUID and SMB peers."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from typing import ClassVar

from romulus.detect.base import Match, Playbook, pf
from romulus.detect.bounded import StateExhausted
from romulus.detect.windows_rows import row_key
from romulus.detect.windows_sequence_extensions import _Rows
from romulus.hunt.citations import COMPACT_CITATION_NOTE, compact_event, expand_event

_FIELDS = frozenset({
    'observer.product', 'observer.name', 'zeek.log', 'zeek.uid', 'file.fuid', 'file.conn_uids',
    'source.ip', 'destination.ip', 'smb.path', 'smb.share', 'smb.name', 'smb.action',
    'file.tx_hosts', 'file.rx_hosts', 'file.source', 'file.is_orig', 'file.seen_bytes',
    'file.mime_type', 'file.missing_bytes', 'file.overflow_bytes', 'file.timedout', 'pe.is_exe',
})
_MIME = frozenset({'application/x-dosexec', 'application/vnd.microsoft.portable-executable',
                   'application/x-portable-executable'})
_REF_LIMIT = 3
_REF_NOTE = 'Only the first three native references of this proof are retained; citation reference coverage is partial.'
_OLD_NOTE = ('Old-layout file endpoints establish recorded singleton membership only; shippers may retain just '
             'the first sending and receiving hosts. Original endpoint-set coverage is partial.')
_LOGGING = ('files.log is required to establish direction and observed executable bytes; SMB FILE_WRITE is not '
            'logged by default. This positive-only analytic never establishes a full search or an absence.')
_PENDING_COLUMNS = 'identity,sensor,fuid,uid,client,server,proof'


def _text(value):
    return value if isinstance(value, str) and value.strip() else ''


def _address(value):
    if not isinstance(value, str):
        return None
    try:
        address = ipaddress.ip_address(value)
    except (ValueError, TypeError):
        return None
    address = getattr(address, 'ipv4_mapped', None) or address
    return None if address.is_loopback or address.is_unspecified or address.is_multicast else str(address)


def _size(values):
    return 96 + sum(len(value.encode()) if isinstance(value, str) else len(value)
                    if isinstance(value, bytes) else 16 for value in values)


class _ProofRows(_Rows):
    schema = (*_Rows.schema,
        'CREATE TABLE IF NOT EXISTS smb_pe_proofs(k TEXT PRIMARY KEY,event BLOB NOT NULL)',
        ('CREATE TABLE IF NOT EXISTS smb_pe_pending(identity TEXT PRIMARY KEY,sensor TEXT,fuid TEXT,uid TEXT,'
         'client TEXT,server TEXT,proof TEXT)'),
        'CREATE INDEX IF NOT EXISTS smb_pe_pending_uid ON smb_pe_pending(sensor,fuid,uid,client,server,identity)',
        'CREATE INDEX IF NOT EXISTS smb_pe_pending_fuid ON smb_pe_pending(sensor,fuid,identity)',
        'CREATE INDEX IF NOT EXISTS smb_pe_pending_peers ON smb_pe_pending(sensor,fuid,client,server,identity)',
        ('CREATE TABLE IF NOT EXISTS smb_pe_files(sensor TEXT,fuid TEXT,uid TEXT,client TEXT,server TEXT,'
         'is_pe INTEGER,proof TEXT,PRIMARY KEY(sensor,fuid,uid,client,server,is_pe))'),
        'CREATE INDEX IF NOT EXISTS smb_pe_files_peers ON smb_pe_files(sensor,fuid,client,server,uid,is_pe)',
        'CREATE TABLE IF NOT EXISTS smb_pe_pe(sensor TEXT,fuid TEXT,proof TEXT,PRIMARY KEY(sensor,fuid))',
    )

    def insert(self, sql, values):
        if not self.room():
            self.owner.refuse('smb_pe_rows', 'The disk budget refused new administrative-share correlation state.')
            return False
        self.store().write(sql, [values], account=self.account)
        self.owner.state_budget().charge(self.account, _size(values))
        return True

    def proof(self, event):
        key = row_key(event.get('observer.name'), event.id)
        if self.store().execute('SELECT 1 FROM smb_pe_proofs WHERE k=?', (key,)).fetchone():
            return key
        payload = compact_event(self.owner.compact(event))
        return key if self.insert('INSERT INTO smb_pe_proofs VALUES(?,?)', (key, payload)) else None

    def load(self, key):
        row = self.store().execute('SELECT event FROM smb_pe_proofs WHERE k=?', (key,)).fetchone()
        return expand_event(row[0]) if row else None

    def drop(self, pending):
        try:
            self.store().write('DELETE FROM smb_pe_pending WHERE identity=?', [(pending[0],)], account=self.account)
            self.owner.state_budget().charge(self.account, -_size(pending))
        except StateExhausted as error:
            self.owner.note_limit('smb_pe_pending', f'Published pending identities could not be removed: {error}')


class AdminSharePeWrite(Playbook):
    id = 'net.smb_admin_share_pe'
    title = 'Executable bytes sent to an SMB administrative-share file'
    families = ('smb_tx', 'file_transfer')
    os_families = ('linux', 'windows')
    kind = 'aggregate'
    direct_eligible = False
    assures_negative = False
    state_slice = 'strong'
    claim_type = 'network_observation'
    attack = ('T1021.002', 'T1570')
    positive_only_reason = _LOGGING
    benign = ('Authorized software deployment can send executable files to administrative shares.',)
    next_checks = ('Review the linked file records, source authorization and endpoint execution evidence.',)
    research = ('https://docs.zeek.org/en/master/scripts/base/protocols/smb/main.zeek.html',
                'https://docs.zeek.org/en/master/scripts/base/frameworks/files/main.zeek.html',
                'https://docs.zeek.org/en/master/scripts/base/files/pe/main.zeek.html',
                'https://attack.mitre.org/techniques/T1021/002/', 'https://attack.mitre.org/techniques/T1570/')
    card: ClassVar[dict] = {
        'behavior': title,
        'telemetry': 'Zeek smb_files plus files; PE evidence from files MIME or pe.',
        'fidelity': 'Typed file bytes and direction; completion and execution are not established.',
        'benign_and_cost': benign[0],
        'query_cost': 'Indexed disk-backed sensor/FUID/UID/peer joins; equivalent file proofs are retained once.',
        'next_pivot': next_checks[0],
        'adds': title,
        'research_basis': '; '.join(research),
        'lanes': 'high when administrative-share metadata and client-directed executable bytes are linked.',
        'retrieval': _LOGGING,
    }

    def __init__(self):
        super().__init__()
        self.rows = _ProofRows(self)
        self.note_coverage('smb_pe_file_logging', _LOGGING)

    def compact(self, event):
        caveats = [*event.caveats, COMPACT_CITATION_NOTE]
        if len(event.raw) > _REF_LIMIT:
            caveats.append(_REF_NOTE)
            self.note_limit('smb_pe_citation_refs', _REF_NOTE)
        return event.model_copy(update={
            'fields': {name: value for name, value in event.fields.items() if name in _FIELDS},
            'raw': event.raw[:_REF_LIMIT], 'caveats': list(dict.fromkeys(caveats))})

    def _partial(self, what):
        self.note_limit('smb_pe_unresolved', what)

    def _identity(self, event):
        sensor, fuid = _text(event.get('observer.name')), _text(event.get('file.fuid'))
        if not sensor or not fuid:
            self._partial('An SMB/file proof lacks its observer name or FUID; that link is unresolved.')
            return None
        return sensor, fuid

    def _peers(self, event, *, old=False):
        source, destination = event.get('source.ip'), event.get('destination.ip')
        tx, rx = event.get('file.tx_hosts'), event.get('file.rx_hosts')
        if old and (tx is not None or rx is not None):
            if not isinstance(tx, list) or not isinstance(rx, list) or len(tx) != 1 or len(rx) != 1:
                self._partial('Old-layout files endpoint sets are not unambiguous singletons; no endpoint pairs were inferred.')
                return None
            if ((source is not None and _address(source) != _address(tx[0]))
                    or (destination is not None and _address(destination) != _address(rx[0]))):
                self._partial('Scalar and old-layout files endpoints disagree; file direction is unresolved.')
                return None
            source, destination = tx[0], rx[0]
            self.note_limit('smb_pe_old_layout', _OLD_NOTE)
        client, server = _address(source), _address(destination)
        if not client or not server:
            self._partial('File or SMB endpoints are missing, invalid or nonremote; endpoint association is unresolved.')
            return None
        return (client, server) if client != server else None

    def _uids(self, event):
        scalar, carrying = event.get('zeek.uid'), event.get('file.conn_uids')
        if scalar is not None and not _text(scalar):
            self._partial('A files connection UID is malformed; its SMB association is unresolved.')
            return ()
        if carrying is not None:
            if not isinstance(carrying, list) or not carrying or any(not _text(value) for value in carrying):
                self._partial('A files carrying-UID list is empty or malformed; its SMB association is unresolved.')
                return ()
            if scalar is not None:
                if scalar not in carrying:
                    self._partial('The files scalar UID is absent from its carrying-UID list; the link is unresolved.')
                    return ()
                return (scalar,)
            return carrying
        return (scalar or '',)

    def _pe_proof(self, sensor, fuid):
        row = self.rows.store().execute('SELECT proof FROM smb_pe_pe WHERE sensor=? AND fuid=?', (sensor, fuid)).fetchone()
        return self.rows.load(row[0]) if row else None

    def _files_proof(self, sensor, fuid, uid, client, server, *, pe=False):
        row = self.rows.store().execute(
            'SELECT proof,is_pe FROM smb_pe_files WHERE sensor=? AND fuid=? AND client=? AND server=? '
            "AND (uid=? OR uid='') AND (is_pe=1 OR ?=1) ORDER BY is_pe DESC,uid LIMIT 1",
            (sensor, fuid, client, server, uid, int(pe))).fetchone()
        return (self.rows.load(row[0]), bool(row[1])) if row else None

    def _emit(self, identity, smb, files, pe=None):
        if not self.rows.first(identity):
            return None
        events = [self.compact(event) for event in (smb, files, pe) if event is not None]
        notes = [self.positive_only_reason, 'ATT&CK context (not proof): T1021.002, T1570']
        if any(_REF_NOTE in event.caveats for event in events):
            notes.append(_REF_NOTE)
        if files.has('file.tx_hosts') or files.has('file.rx_hosts'):
            notes.append(_OLD_NOTE)
        path = str(smb.get('smb.path')).rstrip('\\') + '\\' + str(smb.get('smb.name')).lstrip('\\')
        peers = self._peers(smb)
        return Match(self.id,
            f"Executable file bytes were observed sent from {peers[0]} to {peers[1]} for administrative-share file '{path}'.",
            self.claim_type, events,
            [pf(event, name) for event in events for name in sorted(_FIELDS) if event.has(name)],
            smb.ts, 'high', 'high', 'medium', smb.entities(), notes, group_key=identity,
            context_ids={event.id for event in events[1:]})

    def _smb(self, event, sensor, fuid):
        share = _text(event.get('smb.share')).casefold()
        if share not in {'admin$', 'ipc$'} and re.fullmatch(r'[a-z]\$', share) is None:
            return
        if not _text(event.get('smb.path')) or not _text(event.get('smb.name')):
            self._partial('An administrative SMB share record lacks its file path/name; the file is unresolved.')
            return
        uid, peers = _text(event.get('zeek.uid')), self._peers(event)
        if not uid or not peers:
            self._partial('An administrative SMB file lacks its connection UID or endpoint identity; the link is unresolved.')
            return
        client, server = peers
        content = (sensor, fuid, uid, client, server,
                   str(event.get('smb.path')).casefold(), str(event.get('smb.name')).casefold())
        identity = self.id + ':' + hashlib.sha256(json.dumps(content).encode()).hexdigest()
        if self.rows.marked(identity):
            return
        pe = self._pe_proof(sensor, fuid)
        found = self._files_proof(sensor, fuid, uid, client, server, pe=pe is not None)
        if found:
            match = self._emit(identity, event, found[0], None if found[1] else pe)
            if match:
                yield match
            return
        if self.rows.store().execute('SELECT 1 FROM smb_pe_pending WHERE identity=?', (identity,)).fetchone():
            return
        proof = self.rows.proof(event)
        if proof:
            self.rows.insert('INSERT INTO smb_pe_pending VALUES(?,?,?,?,?,?,?)',
                             (identity, sensor, fuid, uid, client, server, proof))

    def _drain_files(self, sensor, fuid, uid, client, server, files, pe=None):
        last = ''
        while True:
            clause = ' AND uid=?' if uid else ''
            args = (sensor, fuid, client, server, last, uid) if uid else (sensor, fuid, client, server, last)
            pending = self.rows.store().execute(
                f'SELECT {_PENDING_COLUMNS} FROM smb_pe_pending WHERE sensor=? AND fuid=? AND client=? '
                'AND server=? AND identity>?' + clause + ' ORDER BY identity LIMIT 1', args).fetchone()
            if not pending:
                return
            last = pending[0]
            smb = self.rows.load(pending[-1])
            match = self._emit(pending[0], smb, files, pe)
            if match:
                yield match
            self.rows.drop(pending)

    def _files(self, event, sensor, fuid):
        seen = event.get('file.seen_bytes')
        if (event.get('file.source') != 'SMB' or event.get('file.is_orig') is not True
                or not isinstance(seen, int) or isinstance(seen, bool) or seen <= 0):
            return
        peers = self._peers(event, old=True)
        if not peers:
            return
        client, server = peers
        is_pe = str(event.get('file.mime_type') or '').split(';', 1)[0].strip().casefold() in _MIME
        pe = None if is_pe else self._pe_proof(sensor, fuid)
        proof = None
        for uid in self._uids(event):
            key = (sensor, fuid, uid, client, server, int(is_pe))
            if self.rows.store().execute(
                    'SELECT 1 FROM smb_pe_files WHERE sensor=? AND fuid=? AND uid=? AND client=? AND server=? AND is_pe=?',
                    key).fetchone():
                continue
            # Compute the positive using the live proof even if optional retention
            # is refused; publication deduplication still uses the stable identity.
            if is_pe or pe is not None:
                yield from self._drain_files(sensor, fuid, uid, client, server, event, pe)
            proof = proof or self.rows.proof(event)
            if proof:
                self.rows.insert('INSERT OR IGNORE INTO smb_pe_files VALUES(?,?,?,?,?,?,?)', (*key, proof))

    def _pe(self, event, sensor, fuid):
        if event.get('pe.is_exe') is not True:
            return
        if self.rows.store().execute('SELECT 1 FROM smb_pe_pe WHERE sensor=? AND fuid=?', (sensor, fuid)).fetchone():
            return
        # Only the first PE flag visits this FUID's indexed pending rows. A keyset
        # cursor stays bounded while published rows are removed from the queue.
        last = ''
        while True:
            pending = self.rows.store().execute(
                f'SELECT {_PENDING_COLUMNS} FROM smb_pe_pending WHERE sensor=? AND fuid=? '
                'AND identity>? ORDER BY identity LIMIT 1', (sensor, fuid, last)).fetchone()
            if not pending:
                break
            last = pending[0]
            identity, _sensor, _fuid, uid, client, server, proof = pending
            found = self._files_proof(sensor, fuid, uid, client, server, pe=True)
            if found:
                match = self._emit(identity, self.rows.load(proof), found[0], None if found[1] else event)
                if match:
                    yield match
                self.rows.drop(pending)
        proof = self.rows.proof(event)
        if proof:
            self.rows.insert('INSERT INTO smb_pe_pe VALUES(?,?,?)', (sensor, fuid, proof))

    def consume(self, events):
        for event in self.scope_partition(events):
            if (not event.normalizer.startswith('zeek-ecs@') or event.get('observer.product') != 'zeek'
                    or (event.family, event.get('zeek.log')) not in {
                        ('smb_tx', 'smb_files'), ('file_transfer', 'files'), ('file_transfer', 'pe')}):
                continue
            if not self._events_pre_scoped:
                self.os_applicable += 1
            self.evaluated += 1
            identity = self._identity(event)
            if identity is None:
                continue
            try:
                yield from {'smb_files': self._smb, 'files': self._files, 'pe': self._pe}[
                    event.get('zeek.log')](event, *identity)
            except StateExhausted as error:
                self.refuse('smb_pe_state', f'Administrative-share correlation is partial after a state refusal: {error}')

    def release_state(self):
        self.rows.close()


RULES = (AdminSharePeWrite,)
