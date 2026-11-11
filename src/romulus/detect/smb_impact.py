"""SMB impact observations over distinct names in complete five-minute windows.

The existing Zeek window store supplies canonical history, native-reference
idempotence, bounded transaction recovery and the hunt's physical disk ceiling.
Private SQLite membership tables replay one client/server/share at a time. No
hunt-sized Python collection is retained. Expired working members leave disk;
history stays until finalization so late input cannot disappear from a decision.

Unlike monotone count thresholds, an extension ratio can fall as late records
arrive. Publication therefore waits for ordered finalization, including every
record at a timestamp before testing its window. Accepted count lower bounds
survive history refusal; ratios do not claim completeness after such refusal.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import ntpath
import re
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path

from romulus.detect.base import Match, Playbook, pf
from romulus.detect.bounded import StateExhausted
from romulus.detect.network_producers import protocol_record
from romulus.detect.zeek_rate_state import _WindowRows
from romulus.hunt.citations import COMPACT_CITATION_NOTE, expand_event

_FIELDS = frozenset({'source.ip', 'destination.ip', 'smb.action', 'smb.name', 'smb.prev_name',
                     'smb.path', 'smb.share', 'smb.tree', 'observer.name', 'zeek.log', 'suricata.event_type'})
_WORD_TEMP = re.compile(r'~wrl[0-9a-f]{4,}\.tmp\Z', re.IGNORECASE)
_WORD_DOCUMENTS = frozenset({'.doc', '.docx', '.docm'})
_TEMP_SUFFIXES = frozenset({'.tmp', '.temp', '.part', '.partial', '.filepart', '.crdownload',
                          '.download', '.!ut', '.swp'})
# Ordinary data, document and image extensions a transfer, pipeline or application gives a finished file. Ransomware
# marks what it encrypted with an extension of its own, never one of these, so a temporary name completed to one of
# them is a finished file, not an encrypted one.
_ORDINARY_FINALS = frozenset({'.pdf', '.tif', '.tiff', '.jpg', '.jpeg', '.png', '.gif', '.bmp',
                              '.xml', '.json', '.csv', '.tsv', '.txt', '.log', '.dat', '.edi', '.x12',
                              '.zip', '.gz', '.7z', '.tar', '.rtf', '.html', '.htm', '.eml', '.msg',
                              '.doc', '.docx', '.xls', '.xlsx', '.xlsm', '.ppt', '.pptx', '.odt', '.ods',
                              '.parquet', '.avro'})
# Extensionless temporary names applications write first: Python's tempfile (tmp + random characters), Office's
# eight hexadecimal digits, and tilde-prefixed lock and save names.
_TEMP_NAME = re.compile(r'(?:tmp|temp)[0-9a-z_-]{3,}|[0-9a-f]{8}|~[^~].*', re.IGNORECASE)
_ACTIONS = frozenset({'FILE_RENAME', 'FILE_DELETE', 'FILE_CREATE', 'FILE_OPEN'})


@lru_cache(maxsize=1)
def note_names():
    path = Path(__file__).resolve().parents[3] / 'content/network/ransom_notes.json'
    content = json.loads(path.read_text(encoding='utf-8'))
    return (frozenset(item['name'].casefold() for item in content['entries'] if 'pattern' not in item),
            tuple((item['suffix'], re.compile(item['pattern'])) for item in content['entries'] if 'pattern' in item))


def _note_name(value):
    # Avoid address parsing and state work for ordinary FILE_OPEN traffic. Only
    # catalogued whole basenames are admitted; Unicode lookalikes stay distinct.
    name = value.replace('\\', '/').rsplit('/', 1)[-1].casefold()
    exact, patterns = note_names()
    return name in exact or any(name.endswith(suffix) and pattern.fullmatch(name) for suffix, pattern in patterns)


def _temporary_completion(previous, name, old_ext, new_ext):
    if (old_ext and name == ntpath.splitext(previous)[0]) or (previous.endswith('~') and name == previous[:-1]):
        return True
    if new_ext.lower() not in _ORDINARY_FINALS:
        return False                    # x.tmp -> x.locked and appended victim extensions stay eligible
    # Transfer tools and pipelines may replace a temporary suffix with the final one rather than append it: the same
    # full path and stem. An application may also write an extensionless temporary name and rename it into place.
    return ((old_ext.lower() in _TEMP_SUFFIXES and ntpath.splitext(previous)[0] == ntpath.splitext(name)[0])
            or (not old_ext and bool(_TEMP_NAME.fullmatch(ntpath.basename(previous)))))


def _text(event, name):
    fact = event.fields.get(name)
    if fact is None or not isinstance(fact.value, str) or not fact.value or '\x00' in fact.value:
        return ''
    if not any(ref.target and ref.native_id and fact.origin.startswith(ref.native_id + ':') for ref in event.raw):
        return ''
    return fact.value


def _ip(value):
    try:
        address = ipaddress.ip_address(value)
        return str(getattr(address, 'ipv4_mapped', None) or address)
    except ValueError:
        return ''


def _parts(value):
    """Normalize SMB separators/dots/case without escaping the observed share."""
    value = value.replace('/', '\\')
    parts = []
    minimum = 2 if value.startswith('\\\\') else 0
    for part in value.split('\\'):
        if part in ('', '.'):
            continue
        if part == '..':
            if len(parts) <= minimum:
                return None
            parts.pop()
        elif ':' in part:
            return None
        else:
            parts.append(part.casefold())
    return parts


def _location(event):
    share = _text(event, 'smb.share') or _text(event, 'smb.tree') or _text(event, 'smb.path')
    parts = _parts(share)
    if not parts:
        return None
    unc = share.replace('/', '\\').startswith('\\\\')
    if unc and len(parts) < 2:
        return None
    root = parts[1] if unc else parts[0]
    path = _text(event, 'smb.path')
    path_parts = _parts(path)
    prefix = path_parts[2:] if path.replace('/', '\\').startswith('\\\\') and path_parts else []
    if path_parts and path.replace('/', '\\').startswith('\\\\') and (len(path_parts) < 2 or path_parts[1] != root):
        return None
    return root, prefix


def _name(value, root, prefix):
    parts = _parts(value)
    if not parts:
        return ''
    if value.replace('/', '\\').startswith('\\\\'):
        if len(parts) < 3 or parts[1] != root:
            return ''
        parts = parts[2:]
    else:
        parts = [*prefix, *parts]
    return '\\'.join(parts)


class _ImpactRows(_WindowRows):
    schema = (*_WindowRows.schema,
              'CREATE TABLE impact_refused(k TEXT PRIMARY KEY)',
              'CREATE TABLE impact_active(id TEXT,ts REAL,kind TEXT,name TEXT,ext TEXT,PRIMARY KEY(id,kind))',
              'CREATE INDEX impact_active_time ON impact_active(ts,id,kind)',
              'CREATE TABLE impact_members(kind TEXT,name TEXT,ext TEXT,n INTEGER,PRIMARY KEY(kind,name))',
              'CREATE TABLE impact_counts(kind TEXT,ext TEXT,n INTEGER,PRIMARY KEY(kind,ext))',
              'CREATE INDEX impact_count_rank ON impact_counts(kind,n DESC,ext)')

    def __init__(self, owner):
        super().__init__(owner)
        self.untracked_refusal = False

    def store(self):
        if not self.ready:
            spill = self.owner.spill()
            if spill.db.execute("SELECT 1 FROM sqlite_master WHERE name='history'").fetchone():
                # A recovered database has no durable proof that a refusal
                # immediately before process death was recorded. Keep positives,
                # but never reconstruct complete ratios from that uncertainty.
                self.ready = True
                self.untracked_refusal = True
                self.account = self.owner.state_budget().account(self.owner.id + ':zeek_window', strong=True)
                self.owner.note_limit('smb_impact_recovery', 'Recovered SMB history has uncertain refusal '
                                      'accounting; every group is treated as incomplete.')
        return super().store()

    def refused(self, key):
        try:
            def record(db):
                added = db.execute('INSERT OR IGNORE INTO impact_refused VALUES(?)', (key,)).rowcount
                return None, (96 + len(key.encode())) if added else 0
            # Loss bookkeeping must still be attempted after member admission
            # closes. The same physical SQLite byte ceiling bounds this table.
            self.write('refused', record, growing=False)
        except StateExhausted as error:
            self.untracked_refusal = True
            self.owner.note_limit('smb_impact_refused_keys', 'SMB refused-key accounting is incomplete; '
                                  f'every group is treated as incomplete: {error}')

    def complete(self, key):
        db = self.store().db
        return not self.untracked_refusal and not db.execute(
            'SELECT 1 FROM impact_refused WHERE k=?', (key,)).fetchone()

    def put(self, key, event, member, role):
        before = self.owner.capped
        try:
            accepted = super().put(key, event, member, role)
        except StateExhausted:
            try:
                previous = self.store().db.execute(
                    'SELECT ts,member,role FROM history WHERE k=? AND id=?',
                    (key, event.id)).fetchone() if self.ready else None
            except StateExhausted:
                self.untracked_refusal = True
                self.owner.note_limit('smb_impact_member_recovery', 'SMB canonical member retention could not '
                                      'be checked during recovery; every group is treated as incomplete.')
                raise
            # An existing canonical member can lose additional citations without
            # losing a counted filename. A new or conflicting member cannot.
            if previous != (event.ts.timestamp(), member, role):
                self.refused(key)
            raise
        if accepted is None and self.owner.capped > before:
            self.refused(key)
        return accepted

    def reset(self):
        def clear(db):
            for table in ('impact_active', 'impact_members', 'impact_counts'):
                db.execute('DELETE FROM ' + table)
            return None, -self.derived_bytes
        self.write('derived', clear, growing=False)

    @staticmethod
    def _counter(db, kind, ext, change):
        row = db.execute('SELECT n FROM impact_counts WHERE kind=? AND ext=?', (kind, ext)).fetchone()
        if row:
            if row[0] + change:
                db.execute('UPDATE impact_counts SET n=n+? WHERE kind=? AND ext=?', (change, kind, ext))
            else:
                db.execute('DELETE FROM impact_counts WHERE kind=? AND ext=?', (kind, ext))
                return -96 - len(kind.encode()) - len(ext.encode())
        else:
            db.execute('INSERT INTO impact_counts VALUES(?,?,?)', (kind, ext, change))
            return 96 + len(kind.encode()) + len(ext.encode())
        return 0

    def add(self, identity, stamp, entries):
        def insert(db):
            delta = 0
            for kind, name, ext in entries:
                db.execute('INSERT INTO impact_active VALUES(?,?,?,?,?)', (identity, stamp, kind, name, ext))
                delta += 128 + sum(len(v.encode()) for v in (identity, kind, name, ext))
                row = db.execute('SELECT n FROM impact_members WHERE kind=? AND name=?', (kind, name)).fetchone()
                if row:
                    db.execute('UPDATE impact_members SET n=n+1 WHERE kind=? AND name=?', (kind, name))
                else:
                    db.execute('INSERT INTO impact_members VALUES(?,?,?,1)', (kind, name, ext))
                    delta += 96 + sum(len(v.encode()) for v in (kind, name, ext))
                    delta += self._counter(db, kind, ext, 1)
                    if kind == 'extension':
                        delta += self._counter(db, 'renames', '', 1)
            return None, delta
        self.write('derived', insert)

    def expire(self, stamp):
        while True:
            old = self.store().db.execute(
                'SELECT id,kind,name,ext FROM impact_active WHERE ts<? ORDER BY ts,id,kind LIMIT 32',
                (stamp - self.owner.seconds,)).fetchall()
            if not old:
                return

            def remove(db, old=old):
                delta = 0
                for identity, kind, name, ext in old:
                    db.execute('DELETE FROM impact_active WHERE id=? AND kind=?', (identity, kind))
                    delta -= 128 + sum(len(v.encode()) for v in (identity, kind, name, ext))
                    [count] = db.execute('SELECT n FROM impact_members WHERE kind=? AND name=?', (kind, name)).fetchone()
                    if count > 1:
                        db.execute('UPDATE impact_members SET n=n-1 WHERE kind=? AND name=?', (kind, name))
                    else:
                        db.execute('DELETE FROM impact_members WHERE kind=? AND name=?', (kind, name))
                        delta -= 96 + sum(len(v.encode()) for v in (kind, name, ext))
                        delta += self._counter(db, kind, ext, -1)
                        if kind == 'extension':
                            delta += self._counter(db, 'renames', '', -1)
                return None, delta
            self.write('derived', remove, growing=False)

    def counts(self):
        db = self.store().db
        def count(kind):
            row = db.execute('SELECT n FROM impact_counts WHERE kind=? AND ext=?', (kind, '')).fetchone()
            return row[0] if row else 0
        top = db.execute("SELECT ext,n FROM impact_counts WHERE kind='extension' ORDER BY n DESC,ext LIMIT 1").fetchone()
        return count('volume'), count('renames'), count('notes'), *(top or ('', 0))


class SmbImpact(Playbook):
    id = 'network.smb_impact'
    version = '2'
    title = 'Ransomware-shaped SMB rename, deletion or note activity'
    families = ('smb_tx',)
    required_fields = ('source.ip', 'destination.ip', 'smb.action', 'smb.name')
    kind = 'aggregate'
    claim_type = 'aggregate_observation'
    anchor_class = 'network_observation'
    state_slice = 'strong'
    severity = 'high'
    lane = 'lead'
    attack = ('T1486',)
    seconds = 300
    assures_negative = False
    positive_only_reason = ('SMB rename/delete/note observations are positive-only; partial sensor visibility and '
                            'missing previous names cannot establish the absence of impact.')
    benign = ('Robocopy /MOV and archive jobs', 'Build systems, synchronization and user bulk renames')
    next_checks = ('Confirm the operations and affected data on the client and server.',
                   'Check approved migration, backup and document-save activity before attributing ransomware.')

    def __init__(self):
        super().__init__()
        self.rows = _ImpactRows(self)
        self._generation = 0
        self._finalized = -1
        self._word_temps = 0

    def compact(self, event):
        return event.model_copy(update={'fields': {k: v for k, v in event.fields.items() if k in _FIELDS},
                                        'raw': [], 'caveats': [*event.caveats, COMPACT_CITATION_NOTE]})

    def _select(self, event, action):
        client, server = _ip(_text(event, 'source.ip')), _ip(_text(event, 'destination.ip'))
        location = _location(event)
        if not client or not server or not location:
            self.missing_required += 1
            return None
        share, prefix = location
        name = _name(_text(event, 'smb.name'), share, prefix)
        if not name:
            self.missing_required += 1
            return None
        entries = []
        if action in {'FILE_RENAME', 'FILE_DELETE'}:
            entries.append(('volume', name, ''))
        if action == 'FILE_RENAME':
            previous = _name(_text(event, 'smb.prev_name'), share, prefix)
            if not previous:
                self.missing_required += 1
                self.note_coverage('smb_previous_name', 'smb.prev_name is absent or unsupported on some renames; '
                                   'their extension-change predicate is unsupported, but volume remains eligible.')
            else:
                old_ext, new_ext = ntpath.splitext(previous)[1], ntpath.splitext(name)[1]
                # Word save-via-temp replacements remain volume-only.
                # Only same-directory Word destinations
                # qualify; ~WRL*.tmp -> .locked and ordinary .tmp stay eligible.
                word_save = (bool(_WORD_TEMP.fullmatch(ntpath.basename(previous)))
                             and new_ext in _WORD_DOCUMENTS
                             and ntpath.dirname(previous) == ntpath.dirname(name))
                if word_save:
                    self._word_temps += 1
                    self.note_coverage('smb_word_save', 'Word ~WRL hexadecimal .tmp replacements of same-directory '
                                       '.doc/.docx/.docm names are volume-only; their expected extension change '
                                       'does not establish uniform destructive renaming.')
                elif _temporary_completion(previous, name, old_ext, new_ext):
                    self.note_coverage('smb_temporary_completion', 'Last-extension or trailing-tilde removal, and a '
                                       'temporary name completed to an ordinary data or document extension, are '
                                       'volume-only; final-file completion does not establish destructive '
                                       'extension changes.')
                elif not new_ext and name != previous:
                    self.note_coverage('smb_extensionless_rename', 'Some changed names have no extension; '
                                       'these renames are volume-only and their encryption status is unresolved.')
                elif new_ext and old_ext != new_ext:
                    entries.append(('extension', name, new_ext))
        elif action in {'FILE_OPEN', 'FILE_CREATE'} and _note_name(name):
            entries.append(('notes', ntpath.dirname(name), ''))
        if not entries:
            return None
        key = json.dumps((client, server, share), separators=(',', ':'))
        return key, json.dumps(entries, separators=(',', ':'))

    def consume(self, events):
        try:
            for event in events:
                if not protocol_record(event, 'smb_tx'):
                    continue
                if not self._events_pre_scoped:
                    self.os_applicable += 1
                action = _text(event, 'smb.action').removeprefix('SMB::')
                if not action:
                    self.missing_required += 1
                    continue
                self.evaluated += 1
                if action not in _ACTIONS:
                    continue
                if action in {'FILE_OPEN', 'FILE_CREATE'} and not _note_name(_text(event, 'smb.name')):
                    continue
                selected = self._select(event, action)
                if selected is None:
                    continue
                try:
                    refused_before = self.capped
                    if (self.rows.put(selected[0], event, selected[1], 'attempt') is not None
                            or self.capped > refused_before):
                        self._generation += 1
                except StateExhausted as error:
                    self._generation += 1
                    self.refuse('smb_impact_history', f'SMB impact history is incomplete: {error}')
        finally:
            self.rows.flush()
        return []

    def _best(self, stamp, previous):
        volume, renames, directories, extension, dominant = self.rows.counts()
        # Retain two bounded winners for the current group: the complete ratio
        # observation and the independently valid retained-evidence lower bound.
        # A later replay loss must not let a now-invalid ratio winner hide an
        # earlier or later qualifying volume, directory or extension window.
        best = dict(previous or {'complete': None, 'partial': None})
        for coverage in ('complete', 'partial'):
            if ((coverage == 'complete' and renames >= 100 and dominant * 5 >= renames * 4)
                    or (coverage == 'partial' and dominant >= 100)):
                arm, score = 'extension', (2, dominant, renames)
            elif volume >= 200:
                arm, score = 'volume', (1, volume, 0)
            elif directories >= 10:
                arm, score = 'notes', (1, 0, directories)
            else:
                continue
            if best[coverage] is not None and score <= best[coverage]['score']:
                continue
            start = self.rows.store().db.execute('SELECT MIN(ts) FROM impact_active').fetchone()[0]
            best[coverage] = {'stamp': stamp, 'start': start, 'arm': arm, 'score': score, 'volume': volume,
                              'renames': renames, 'directories': directories, 'extension': extension,
                              'dominant': dominant}
        return best if any(best.values()) else None

    def _expire_before(self, key, following, end, best):
        # A ratio can cross upward when an older minority leaves. Test these
        # starts as well as arrivals. The witness interval still ends at the
        # latest actual event; do not invent a future observation timestamp.
        while True:
            oldest = self.rows.store().db.execute('SELECT MIN(ts) FROM impact_active').fetchone()[0]
            if oldest is None or oldest + self.seconds >= following:
                return best
            try:
                self.rows.expire(oldest + self.seconds + 0.000001)
            except StateExhausted as error:
                self._replay_refused(key, error)
                self.rows.reset()
                return best
            best = self._best(end, best)

    def _replay_refused(self, key, error):
        self.rows.refused(key)
        self.note_limit('smb_impact_replay', f'SMB impact ordered replay is incomplete: {error}')

    def _publish(self, key, best):
        if best is None:
            return None
        complete = self.rows.complete(key)
        best = best['complete' if complete else 'partial']
        if best is None:
            return None
        client, server, share = json.loads(key)
        stamp = best['stamp']
        kind = best['arm']
        if kind == 'extension':
            if not complete:
                claim = (f"SMB client {client} renamed at least {best['dominant']} retained distinct filenames "
                         f"on {server}/{share} to {best['extension']} within five minutes; the ratio is unresolved "
                         'because records for this group were refused or recovery was incomplete.')
            else:
                claim = (f"SMB client {client} renamed {best['renames']} distinct filenames on {server}/{share} "
                     f"with changed extensions within five minutes; {best['dominant']} "
                     f"({100 * best['dominant'] / best['renames']:.1f}%) ended in {best['extension']}.")
        elif kind == 'volume':
            claim = (f"SMB client {client} renamed or deleted {best['volume']} distinct filenames on "
                     f"{server}/{share} within five minutes.")
        else:
            claim = (f"SMB client {client} opened or created curated ransom-note filenames in "
                     f"{best['directories']} distinct directories on {server}/{share} within five minutes.")
        filter_kind = {'extension': 'extension', 'volume': 'volume', 'notes': 'notes'}[kind]
        condition = "json_extract(value,'$[0]')=?"
        args = [key, best['start'], stamp, filter_kind]
        if kind == 'extension':
            condition += " AND json_extract(value,'$[2]')=?"
            args.append(best['extension'])
        query = ('SELECT payload FROM history WHERE k=? AND ts>=? AND ts<=? AND '
                 f'EXISTS(SELECT 1 FROM json_each(history.member) WHERE {condition}) '
                 'ORDER BY ts {order},id {order} LIMIT 2')
        db = self.rows.store().db
        samples = {}
        for order in ('ASC', 'DESC'):
            for [payload] in db.execute(query.format(order=order), args):
                event = expand_event(payload)
                samples[event.id] = event
        events = sorted(samples.values(), key=lambda e: (e.ts, e.id))
        notes = [
            'These are observed SMB operations, not proof of encryption, successful destruction or ransomware attribution.',
            'Distinct canonical destination/current filenames are counted, never actions or raw-record multiplicity.',
            'Zeek recent_files deduplicates repeated operations for approximately 3 minutes; recorded counts can understate activity.',
            'Robocopy /MOV, archive jobs, build systems, synchronization and user bulk renames are plausible benign causes.',
            'Ransom-note names can also be opened or copied legitimately during incident response; names do not prove contents.',
            'Only up to four compact events and three native references per event are cited; citation sampling is partial.',
            'Intervals of at most five minutes include entire timestamp groups; late records and interval starts are replayed in time order.',
            *self.coverage_notes(),
        ]
        if kind == 'extension':
            notes.append('The denominator is distinct extension-changing filenames with recorded previous names; '
                         'temporary-file completion and same-directory Word temporary save replacements are volume-only.')
        if not complete:
            notes.append('Partial coverage: retention or replay for this group was incomplete; all published '
                         'counts are retained lower bounds and the extension ratio is unresolved.')
        return Match(self.id, claim, self.claim_type, events,
                     [pf(event, field) for event in events for field in sorted(_FIELDS) if field in event.fields],
                     datetime.fromtimestamp(stamp, UTC), 'critical' if kind == 'extension' else 'high',
                     'high' if kind == 'extension' else 'lead', 'high',
                     entities=[('ip', client, 'client'), ('ip', server, 'server')], notes=notes,
                     group_key=self.id + '|' + hashlib.sha256(key.encode()).hexdigest(), bounded_revision=True,
                     revision_reason='Complete ordered SMB impact windows replace the earlier group summary.'
                     if self._finalized >= 0 else '')

    def finalize(self):
        if not self.rows.ready and self._spill is not None:
            self.rows.store()
        if not self.rows.ready or self._finalized == self._generation:
            return
        self.rows.flush()
        current, stamp, best = None, None, None
        try:
            self.rows.reset()
            cursor = self.rows.store().db.execute('SELECT k,id,ts,member FROM history ORDER BY k,ts,id')
            for key, identity, new_stamp, member in cursor:
                if key != current:
                    if current is not None:
                        best = self._best(stamp, best)
                        best = self._expire_before(current, float('inf'), stamp, best)
                        match = self._publish(current, best)
                        if match:
                            self.rows.flush()
                            yield match
                    self.rows.reset()
                    current, stamp, best = key, new_stamp, None
                elif new_stamp != stamp:
                    best = self._best(stamp, best)
                    best = self._expire_before(current, new_stamp, stamp, best)
                    stamp = new_stamp
                try:
                    self.rows.expire(new_stamp)
                except StateExhausted as error:
                    self._replay_refused(key, error)
                    self.rows.reset()
                try:
                    self.rows.add(identity, new_stamp, json.loads(member))
                except StateExhausted as error:
                    self._replay_refused(key, error)
            if current is not None:
                best = self._best(stamp, best)
                best = self._expire_before(current, float('inf'), stamp, best)
                match = self._publish(current, best)
                if match:
                    self.rows.flush()
                    yield match
            self.rows.reset()
            self._finalized = self._generation
        except StateExhausted as error:
            self.note_limit('smb_impact_replay', f'SMB impact ordered replay is incomplete: {error}')
            # best was captured only after a complete timestamp. A later refusal
            # cannot invalidate that already computed positive.
            if current is not None and best is not None:
                match = self._publish(current, best)
                if match:
                    match.notes.append('Later ordered replay was incomplete; this completed window remains supported.')
                    yield match
        finally:
            self.rows.flush()

    def retained_events(self):
        return []

    def release_state(self):
        self.rows.close()
        super().release_state()


RULES = [SmbImpact]
