"""Executable and script bytes transferred over HTTP, FTP or SMB.

The MIME table transcribes Zeek's shipped magic signatures, verified at commit
5862ccc5e13e6127cda5932a7f18aaf070c8b63b in scripts/base/frameworks/files/magic/:
executable.sig (PE, ELF executable/shared library, Mach-O, Emacs bytecode),
programming.sig (all its script types), python.sig (Python bytecode), and
libmagic.sig (setup scripts). ELF objects and core dumps are not executable images.
https://github.com/zeek/zeek/tree/5862ccc5e13e6127cda5932a7f18aaf070c8b63b/scripts/base/frameworks/files/magic

Every file, analyzer join and fold is indexed on disk. Memory holds one file and
its bounded citation witnesses at a time; only the shared disk budget refuses facts.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
from typing import ClassVar
from urllib.parse import unquote, urlsplit

from romulus.detect.base import Match, Playbook, pf
from romulus.detect.bounded import StateExhausted
from romulus.detect.netdef import DIRECTION_ASSUMED_REASON, assume_direction, current
from romulus.detect.windows_rows import row_key
from romulus.detect.windows_sequence_extensions import _Rows
from romulus.detect.zeek_smb import _MIME
from romulus.hunt.citations import COMPACT_CITATION_NOTE, compact_event, expand_event

CONTENT_TYPES = {
    **dict.fromkeys(_MIME, 'PE'),
    'application/x-executable': 'ELF executable', 'application/x-sharedlib': 'ELF shared library',
    'application/x-mach-o-executable': 'Mach-O', 'application/x-elc': 'Emacs bytecode',
    **{mime: mime for mime in (
        'text/x-shellscript', 'text/x-perl', 'text/x-ruby', 'text/x-python', 'text/x-awk',
        'text/x-tcl', 'text/x-lua', 'application/javascript', 'text/x-php', 'text/x-msdos-batch',
        'text/x-m4', 'application/x-python-bytecode', 'application/x-setupscript')},
}
# These suffixes advertise passive media/documents, plain data or containers;
# executable bytes under them are a positive mismatch. Unknown suffixes and no
# suffix make no assertion. Script/executable suffixes are deliberately absent.
PASSIVE_EXTENSIONS = {
    'image': frozenset({'jpg', 'jpeg', 'png', 'gif', 'bmp', 'tif', 'tiff', 'webp', 'ico', 'svg'}),
    'document': frozenset({'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'odt', 'ods', 'odp', 'rtf'}),
    'text': frozenset({'txt', 'csv', 'tsv', 'log', 'json', 'xml', 'yaml', 'yml', 'ini'}),
    'archive': frozenset({'zip', 'gz', 'gzip', 'bz2', 'xz', 'tar', 'tgz', '7z', 'rar', 'cab'}),
}
_PASSIVE = frozenset().union(*PASSIVE_EXTENSIONS.values())
_FIELDS = frozenset({
    'observer.name', 'observer.product', 'zeek.log', 'zeek.uid', 'source.ip', 'destination.ip',
    'source.port', 'destination.port', 'file.fuid', 'file.conn_uids', 'file.tx_hosts', 'file.rx_hosts',
    'file.source', 'file.is_orig', 'file.mime_type', 'file.name', 'file.seen_bytes', 'pe.is_exe',
    'file.missing_bytes', 'file.overflow_bytes', 'file.timedout', 'http.hostname', 'url.original',
    'http.orig_fuids', 'http.resp_fuids', 'smb.share', 'smb.path', 'smb.name',
})
_LOGGING = ('Only observed sniffed executable or script content is assessed. File completion and execution '
            'are not established; missing analyzer context cannot establish a negative.')
_REF_NOTE = 'Only three native references per transfer witness are retained; citation reference coverage is partial.'
_RANK = {'context': 0, 'lead': 1, 'high': 2}


def _text(value):
    return value.strip() if isinstance(value, str) else ''


def _address(value):
    try:
        address = ipaddress.ip_address(value) if isinstance(value, str) else None
    except ValueError:
        return None
    address = getattr(address, 'ipv4_mapped', None) or address
    return str(address) if address and not (address.is_unspecified or address.is_multicast) else None


def _masquerade(value, *, uri=False):
    if not _text(value):
        return False
    try:
        value = unquote(urlsplit(value).path) if uri else value
    except ValueError:
        return False
    name = value.replace('\\', '/').rsplit('/', 1)[-1]
    return '.' in name and name.rsplit('.', 1)[-1].casefold() in _PASSIVE


def _literal_host(value):
    host = _text(value)
    if not host:
        return False
    if _address(host):
        return True
    try:
        return _address(urlsplit('//' + host).hostname) is not None
    except ValueError:
        return False


class _TransferRows(_Rows):
    schema = (*_Rows.schema,
        ('CREATE TABLE IF NOT EXISTS transfer_files(k TEXT PRIMARY KEY,sensor TEXT,fuid TEXT,uid TEXT,'
         'sender TEXT,receiver TEXT,protocol TEXT,event BLOB)'),
        'CREATE INDEX IF NOT EXISTS transfer_files_fuid ON transfer_files(sensor,fuid,k)',
        ('CREATE TABLE IF NOT EXISTS transfer_context(k TEXT PRIMARY KEY,sensor TEXT,fuid TEXT,uid TEXT,'
         'sender TEXT,receiver TEXT,protocol TEXT,event BLOB)'),
        'CREATE INDEX IF NOT EXISTS transfer_context_fuid ON transfer_context(sensor,fuid,protocol,k)',
        'CREATE TABLE IF NOT EXISTS transfer_pe(sensor TEXT,fuid TEXT,event BLOB,PRIMARY KEY(sensor,fuid))',
        ('CREATE TABLE IF NOT EXISTS transfer_verdict(k TEXT PRIMARY KEY,gkey TEXT,lane TEXT,category TEXT,'
         'content TEXT,sender TEXT,receiver TEXT,ts REAL,event BLOB,context BLOB,pe BLOB)'),
        'CREATE INDEX IF NOT EXISTS transfer_verdict_group ON transfer_verdict(gkey,ts,k)',
        ('CREATE TABLE IF NOT EXISTS transfer_groups(gkey TEXT PRIMARY KEY,n INTEGER,first REAL,last REAL,'
         'first_key TEXT,last_key TEXT,witness_key TEXT,lane TEXT)'),
    )

    def insert(self, sql, values):
        self.store()
        if not self.room():
            self.owner.refuse('transfer_disk', 'The disk budget refused executable-transfer facts or correlation state.')
            return False
        self.store().write(sql, [values], account=self.account)
        self.owner.state_budget().charge(self.account, 256 + sum(
            len(v.encode()) if isinstance(v, str) else len(v) if isinstance(v, bytes) else 16 for v in values))
        return True


class ExecutableTransfer(Playbook):
    id = 'net.executable_transfer'
    title = 'Executable or script content transferred over HTTP, FTP or SMB'
    families = ('file_transfer', 'http_tx', 'smb_tx')
    context_families = ('http_tx', 'smb_tx')
    claim_type = 'network_observation'
    kind = 'aggregate'
    direct_eligible = False
    assures_negative = False
    positive_only_reason = _LOGGING
    direction_dependent = True
    state_slice = 'strong'
    attack = ('T1036.008', 'T1105', 'T1570')
    benign = ('Software updates and authorized software distribution transfer executable content.',)
    next_checks = ('Review source authorization, the linked file and endpoint execution evidence.',)
    research = ('https://docs.zeek.org/en/master/scripts/base/frameworks/files/main.zeek.html',
                'https://attack.mitre.org/techniques/T1036/008/',
                'https://attack.mitre.org/techniques/T1105/', 'https://attack.mitre.org/techniques/T1570/')
    card: ClassVar[dict] = {
        'behavior': title, 'telemetry': 'Zeek files/pe with HTTP and SMB context.',
        'fidelity': 'Sniffed content and typed sender/receiver; completion and execution unknown.',
        'benign_and_cost': benign[0], 'query_cost': 'Disk-backed sensor/FUID/UID/peer joins and folded counts.',
        'next_pivot': next_checks[0], 'adds': title, 'research_basis': '; '.join(research),
        'lanes': 'Masquerade high; unusual ingress or nonadministrative SMB lateral transfer lead; other downloads context.',
        'retrieval': _LOGGING,
    }

    def __init__(self):
        super().__init__()
        self.rows = _TransferRows(self)
        self.note_coverage('transfer_positive_only', _LOGGING)

    def _pack(self, event):
        caveats = [*event.caveats, COMPACT_CITATION_NOTE]
        if len(event.raw) > 3:
            caveats.append(_REF_NOTE)
            self.note_limit('transfer_references', _REF_NOTE)
        return compact_event(event.model_copy(update={
            'fields': {k: v for k, v in event.fields.items() if k in _FIELDS},
            'raw': event.raw[:3], 'caveats': list(dict.fromkeys(caveats))}))

    def _direction(self, event):
        tx, rx = event.get('file.tx_hosts'), event.get('file.rx_hosts')
        if tx is not None or rx is not None:
            if isinstance(tx, list) and isinstance(rx, list) and len(tx) == len(rx) == 1:
                sender, receiver = _address(tx[0]), _address(rx[0])
            else:
                return None
        else:
            orig = event.get('file.is_orig')
            if not isinstance(orig, bool):
                return None
            source, destination = _address(event.get('source.ip')), _address(event.get('destination.ip'))
            sender, receiver = (source, destination) if orig else (destination, source)
        return (sender, receiver) if sender and receiver and sender != receiver else None

    def _file(self, event, sensor, fuid):
        protocol = _text(event.get('file.source')).upper()
        if protocol not in {'HTTP', 'FTP', 'SMB'}:
            return
        peers = self._direction(event)
        if peers is None:
            self.missing_required += 1
            self.evaluated -= 1
            self.note_coverage('transfer_direction', 'Files without an unambiguous typed sender and receiver were not evaluated for direction.')
            return
        uid = _text(event.get('zeek.uid'))
        key = row_key(sensor, fuid, *peers)
        if (not self.rows.store().execute('SELECT 1 FROM transfer_files WHERE k=?', (key,)).fetchone()
                and not self.rows.insert('INSERT INTO transfer_files VALUES(?,?,?,?,?,?,?,?)',
                                         (key, sensor, fuid, uid, *peers, protocol, self._pack(event)))):
            return
        yield from self._evaluate_fuid(sensor, fuid)

    def _context(self, event, sensor):
        uid = _text(event.get('zeek.uid'))
        source, destination = _address(event.get('source.ip')), _address(event.get('destination.ip'))
        if not uid or not source or not destination:
            return
        if event.family == 'smb_tx':
            fuids = [(event.get('file.fuid'), source, destination, 'SMB')]
        else:
            fuids = []
            for name, sender, receiver in (('http.orig_fuids', source, destination),
                                           ('http.resp_fuids', destination, source)):
                values = event.get(name)
                if isinstance(values, list):
                    fuids.extend((fuid, sender, receiver, 'HTTP') for fuid in values if _text(fuid))
        for fuid, sender, receiver, protocol in fuids:
            if not _text(fuid):
                continue
            key = row_key(sensor, fuid, uid, event.id)
            if not self.rows.store().execute('SELECT 1 FROM transfer_context WHERE k=?', (key,)).fetchone():
                self.rows.insert('INSERT INTO transfer_context VALUES(?,?,?,?,?,?,?,?)',
                                 (key, sensor, fuid, uid, sender, receiver, protocol, self._pack(event)))
            yield from self._evaluate_fuid(sensor, fuid)

    def _classify(self, row):
        _key, sensor, fuid, uid, sender, receiver, protocol, payload = row
        event = expand_event(payload)
        mime = _text(event.get('file.mime_type')).split(';', 1)[0].strip().casefold()
        content, pe = CONTENT_TYPES.get(mime), b''
        if content is None:
            proof = self.rows.store().execute('SELECT event FROM transfer_pe WHERE sensor=? AND fuid=?', (sensor, fuid)).fetchone()
            if not proof:
                return None
            content, pe = 'PE', proof[0]
        contexts = self.rows.store().execute(
            'SELECT uid,sender,receiver,event FROM transfer_context WHERE sensor=? AND fuid=? AND protocol=? ORDER BY k',
            (sensor, fuid, protocol))
        best, available = None, False
        carrying = event.get('file.conn_uids')
        uids = {uid} if uid else {v for v in carrying if _text(v)} if isinstance(carrying, list) else set()
        internal_sender = current().is_internal(ipaddress.ip_address(sender))
        internal_receiver = current().is_internal(ipaddress.ip_address(receiver))
        mismatch = _masquerade(event.get('file.name'))
        for cuid, csender, creceiver, context in contexts:
            if uids and cuid not in uids:
                continue
            if protocol == 'HTTP' and (csender, creceiver) != (sender, receiver):
                continue
            if protocol == 'SMB' and {csender, creceiver} != {sender, receiver}:
                continue
            meta = expand_event(context)
            if protocol == 'SMB':
                share = _text(meta.get('smb.share')).casefold()
                if not share:
                    continue
                if share in {'admin$', 'ipc$'} or re.fullmatch(r'[a-z]\$', share):
                    seen = event.get('file.seen_bytes')
                    covered = (content == 'PE' and event.get('file.is_orig') is True
                               and isinstance(seen, int) and not isinstance(seen, bool) and seen > 0
                               and _text(meta.get('smb.path')) and _text(meta.get('smb.name'))
                               and (csender, creceiver) == (sender, receiver))
                    if covered:
                        return 'admin'
                    if not (mismatch or _masquerade(meta.get('smb.name'))):
                        continue
            available = True
            hidden = mismatch or _masquerade(meta.get('url.original'), uri=True) or _masquerade(meta.get('smb.name'))
            if hidden:
                lane, category = 'high', 'masquerade'
            elif protocol == 'SMB' and internal_sender and internal_receiver:
                lane, category = 'lead', 'lateral'
            elif (protocol == 'HTTP' and not internal_sender and internal_receiver
                  and (_literal_host(meta.get('http.hostname')) or
                       (meta.get('destination.port') is not None and meta.get('destination.port') != 80))):
                lane, category = 'lead', 'ingress'
            elif protocol == 'HTTP' and (not _text(meta.get('http.hostname')) or meta.get('destination.port') is None):
                continue
            else:
                lane, category = 'context', 'download'
            candidate = (lane, category, content, payload, context, pe)
            if best is None or _RANK[lane] > _RANK[best[0]]:
                best = candidate
        if protocol == 'SMB':
            return best
        if mismatch and (best is None or best[0] != 'high'):
            return 'high', 'masquerade', content, payload, b'', pe
        if protocol == 'FTP':
            return ('lead', 'ingress', content, payload, b'', pe) if not internal_sender and internal_receiver else (
                'context', 'download', content, payload, b'', pe)
        return best if available else None

    def _evaluate_fuid(self, sensor, fuid):
        for row in self.rows.store().execute('SELECT * FROM transfer_files WHERE sensor=? AND fuid=? ORDER BY k', (sensor, fuid)):
            result = self._classify(row)
            if not result or result == 'admin':
                continue
            lane, category, content, payload, context, pe = result
            old = self.rows.store().execute('SELECT gkey,lane FROM transfer_verdict WHERE k=?', (row[0],)).fetchone()
            if old and _RANK[old[1]] >= _RANK[lane]:
                continue
            sender, receiver = row[4:6]
            gkey = row_key(receiver) if lane == 'context' else row_key(receiver, sender, content)
            event = expand_event(payload)
            if self.rows.insert('INSERT OR REPLACE INTO transfer_verdict VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                                (row[0], gkey, lane, category, content, sender, receiver,
                                 event.ts.timestamp(), payload, context, pe)):
                self._group(row[0], gkey, lane, event.ts.timestamp(), old)
                assume_direction(self)
                if lane != 'context':
                    match = self._emit(gkey)
                    if match:
                        yield match

    def _group(self, file_key, key, lane, stamp, old):
        store = self.rows.store()
        if old and old[0] != key:
            # A deferred context member can acquire stronger ingress or
            # masquerade evidence. Repair only that receiver's disk index.
            old_key = old[0]
            store.write('UPDATE transfer_groups SET n=n-1 WHERE gkey=?', [(old_key,)], account=self.rows.account)
            first = store.execute('SELECT k,ts FROM transfer_verdict WHERE gkey=? ORDER BY ts,k LIMIT 1', (old_key,)).fetchone()
            last = store.execute('SELECT k,ts FROM transfer_verdict WHERE gkey=? ORDER BY ts DESC,k DESC LIMIT 1', (old_key,)).fetchone()
            if first:
                store.write('UPDATE transfer_groups SET first=?,last=?,first_key=?,last_key=?,witness_key=? WHERE gkey=?',
                            [(first[1], last[1], first[0], last[0], first[0], old_key)], account=self.rows.account)
        group = store.execute('SELECT n,first,last,first_key,last_key,witness_key,lane FROM transfer_groups WHERE gkey=?', (key,)).fetchone()
        if group is None or group[0] == 0:
            self.rows.insert('INSERT OR REPLACE INTO transfer_groups VALUES(?,?,?,?,?,?,?,?)',
                             (key, 1, stamp, stamp, file_key, file_key, file_key, lane))
            return
        count, first, last, first_key, last_key, witness_key, prior_lane = group
        earlier, later = (stamp, file_key) < (first, first_key), (stamp, file_key) > (last, last_key)
        stronger = _RANK[lane] > _RANK[prior_lane]
        store.write('UPDATE transfer_groups SET n=?,first=?,last=?,first_key=?,last_key=?,witness_key=?,lane=? WHERE gkey=?',
                    [(count + int(old is None or old[0] != key), min(first, stamp), max(last, stamp),
                      file_key if earlier else first_key, file_key if later else last_key,
                      file_key if stronger else witness_key, lane if stronger else prior_lane, key)], account=self.rows.account)

    def _emit(self, key):
        store = self.rows.store()
        group = store.execute('SELECT n,first,last,first_key,last_key,witness_key FROM transfer_groups WHERE gkey=?', (key,)).fetchone()
        if not group or not group[0]:
            return None
        count, first, last, first_key, last_key, witness_key = group
        strongest = store.execute('SELECT * FROM transfer_verdict WHERE k=?', (witness_key,)).fetchone()
        lane, category, content, sender, receiver = strongest[2:7]
        signature = row_key(count, first, last, lane)
        marker = 'transfer-published:' + key
        previous = self.rows.marker(marker)
        if signature == previous:
            return None
        self.rows.remember(marker, signature)
        bounds = [store.execute('SELECT event,context,pe FROM transfer_verdict WHERE k=?', (bound,)).fetchone()
                  for bound in (first_key, last_key)]
        proofs = [*bounds, strongest[8:11]]
        events = {event.id: event for values in proofs for payload in values if payload for event in [expand_event(payload)]}
        # First, last and the strongest supporting fact each need at most a files
        # row plus HTTP/SMB and PE. The same support is naturally deduplicated.
        selected = sorted(events.values(), key=lambda e: (e.ts, e.id))
        lateral = current().is_internal(ipaddress.ip_address(sender)) and current().is_internal(ipaddress.ip_address(receiver))
        techniques = (('T1036.008', 'T1570' if lateral else 'T1105') if category == 'masquerade' else
                      ('T1570',) if category == 'lateral' else ('T1105',) if category == 'ingress' else ())
        count_text = f'{count} file' + ('s' if count != 1 else '')
        claim = (f'Executable or script transfers were observed to receiver {receiver} ({count_text}).' if lane == 'context' else
                 f'{content} content was observed sent from {sender} to {receiver} ({count_text}; {category}).')
        notes = [_LOGGING, 'Counts use distinct sensor/file/sender/receiver identities; citations retain first, last and strongest witnesses.']
        if not current().configured:
            notes.append(DIRECTION_ASSUMED_REASON)
        if techniques:
            notes.append('ATT&CK context (not proof): ' + ', '.join(techniques))
        return Match(self.id, claim, self.claim_type, selected,
                     [pf(event, name) for event in selected for name in sorted(_FIELDS) if event.has(name)],
                     expand_event(strongest[8]).ts, 'high' if lane == 'high' else 'low', lane, 'medium',
                     expand_event(strongest[8]).entities(), notes,
                     group_key=self.id + ':' + hashlib.sha256(key.encode()).hexdigest(),
                     bounded_revision=True, revision_reason='Updated transfer count, span or evidence lane.' if previous else '',
                     aggregate_summary={'peak': count, 'episodes': 1, 'first': first, 'last': last},
                     context_ids={event.id for event in selected if event.family != 'file_transfer'}, attack=techniques)

    def consume(self, events):
        for event in self.scope_partition(events):
            if not event.normalizer.startswith('zeek-ecs@') or event.get('observer.product') != 'zeek':
                continue
            if not self._events_pre_scoped:
                self.os_applicable += 1
            self.evaluated += 1
            sensor = _text(event.get('observer.name'))
            if not sensor:
                self.missing_required += 1
                self.evaluated -= 1
                continue
            try:
                if event.family in {'http_tx', 'smb_tx'}:
                    yield from self._context(event, sensor)
                    continue
                fuid = _text(event.get('file.fuid'))
                if not fuid:
                    self.missing_required += 1
                    self.evaluated -= 1
                    continue
                if event.get('zeek.log') == 'pe':
                    if event.get('pe.is_exe') is True and not self.rows.store().execute(
                            'SELECT 1 FROM transfer_pe WHERE sensor=? AND fuid=?', (sensor, fuid)).fetchone():
                        self.rows.insert('INSERT INTO transfer_pe VALUES(?,?,?)', (sensor, fuid, self._pack(event)))
                        yield from self._evaluate_fuid(sensor, fuid)
                elif event.get('zeek.log') == 'files':
                    yield from self._file(event, sensor, fuid)
            except StateExhausted as error:
                self.refuse('transfer_disk', f'Executable-transfer state was refused by the disk budget: {error}')

    def finalize(self):
        if not self.rows.ready:
            return
        for row in self.rows.store().execute('SELECT * FROM transfer_files ORDER BY k'):
            if self._classify(row) is None:
                event = expand_event(row[7])
                mime = _text(event.get('file.mime_type')).split(';', 1)[0].strip().casefold()
                pe = self.rows.store().execute('SELECT 1 FROM transfer_pe WHERE sensor=? AND fuid=?', (row[1], row[2])).fetchone()
                if mime in CONTENT_TYPES or pe:
                    self.note_limit('transfer_context_' + row[6].lower(), f'Executable {row[6]} files lack matching typed analyzer host, URI, port or share context; those direction/lane decisions are unresolved.')
        for (key,) in self.rows.store().execute('SELECT gkey FROM transfer_groups WHERE n>0 ORDER BY gkey'):
            match = self._emit(key)
            if match:
                yield match

    def release_state(self):
        self.rows.close()


RULES = (ExecutableTransfer,)
