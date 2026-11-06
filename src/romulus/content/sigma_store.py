"""Offline Sigma imports, fixture-gated activation, and immutable hunt pins."""
from __future__ import annotations

import hashlib
import json
import os
import re
from functools import lru_cache
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.dialects.sqlite import insert

from romulus.catalog.attack import load_attack_bundle
from romulus.content.indicator_import import _json_depth
from romulus.content.indicator_lists import _audit, _json, _serial, _text
from romulus.content.indicator_values import _safe_text
from romulus.evidence.normalize import normalize_hits
from romulus.store import schema as t
from romulus.store.db import read_snapshot, utcnow, write_txn

MAX_RULE_FILES = 10000
MAX_DIRECTORY_BYTES = 128 * 1024 * 1024
MAX_FIXTURE_BYTES = 16 * 1024 * 1024
MAX_FIXTURE_RECORDS = 10000
MAX_ACTIVE_RULES = 10000
MAX_ACTIVE_BYTES = 32 * 1024 * 1024
MAX_REPORT_DETAILS = 1000
_PIN_FIELDS = ('id', 'digest', 'rule_id', 'upstream', 'upstream_commit', 'upstream_path',
               'title', 'author', 'level', 'sigma_status', 'tags', 'lane', 'activation_reason',
               'activated_at', 'created_at', 'created_by')


def content_digest(ast, mapping):
    return hashlib.sha256(_json({'ast': ast, 'mapping': mapping}).encode()).hexdigest()


def _local_path(path):
    value = str(path)
    if value.startswith(('\\\\', '//')) or '://' in value or '\x00' in value:
        raise ValueError('A local filesystem path is required')
    return Path(path)


def _files(root):
    """Bound traversal as well as accepted YAML files; never follow links."""
    if not root.is_dir() or root.is_symlink():
        raise ValueError('A local Sigma directory is required')
    count = entries = directories = 0
    total = 0
    resolved = root.resolve()
    for current, dirs, names in os.walk(root, followlinks=False):
        directories += 1
        entries += len(dirs) + len(names)
        if directories > MAX_RULE_FILES or entries > MAX_RULE_FILES * 10:
            raise ValueError('Sigma directory traversal limit exceeded')
        if any((Path(current)/name).is_symlink() for name in dirs):
            raise ValueError('Sigma directory links are refused')
        dirs.sort()
        for name in sorted(names):
            path = Path(current)/name
            if path.suffix.lower() not in {'.yml', '.yaml'}:
                continue
            if path.is_symlink() or not path.resolve().is_relative_to(resolved):
                raise ValueError('Sigma file links are refused')
            count += 1
            total += path.stat().st_size
            if count > MAX_RULE_FILES or total > MAX_DIRECTORY_BYTES:
                raise ValueError('Sigma directory size or file limit exceeded')
            yield path, path.relative_to(root).as_posix()


@lru_cache(maxsize=1)
def _techniques():
    return {technique.id.lower() for technique in load_attack_bundle().techniques
            if not technique.revoked and not technique.deprecated}


def _tags(values):
    if not isinstance(values, list) or len(values) > 256:
        raise ValueError('Invalid Sigma tag list')
    kept, dropped = [], []
    for value in values:
        tag = _text(value, 'Sigma tag', 256)
        lower = tag.lower()
        if lower.startswith('attack.t') and lower.removeprefix('attack.') not in _techniques():
            dropped.append({'tag': tag, 'reason': 'unknown_revoked_or_deprecated_enterprise_technique'})
        elif tag not in kept:
            kept.append(tag)
    return kept, dropped


def _row(document, parsed, *, upstream, commit, path, actor):
    tags, dropped = _tags(document.get('tags', []))
    mapping = {**parsed['mapping'], 'reasons': list(parsed['reasons']), 'tag_drops': dropped}
    row = {
        'rule_id': _text(document.get('id', ''), 'Sigma rule id', 256),
        'title': _text(document.get('title', ''), 'Sigma title', 2048),
        'author': _text(document.get('author', ''), 'Sigma author', 2048),
        'level': _text(document.get('level', 'informational'), 'Sigma level', 64),
        'sigma_status': _text(document.get('status', 'experimental'), 'Sigma status', 64),
        'tags': tags, 'ast': parsed['ast'], 'mapping': mapping,
        'upstream': upstream, 'upstream_commit': commit, 'upstream_path': _text(path, 'Sigma path', 2048),
    }
    if row['level'] not in {'informational', 'low', 'medium', 'high', 'critical'}:
        raise ValueError('Invalid Sigma level')
    row['digest'] = content_digest(row['ast'], mapping)
    row['id'] = hashlib.sha256(_json(row).encode()).hexdigest()
    return {**row, 'status': 'reference-only' if parsed['reasons'] else 'draft',
            'created_at': utcnow(), 'created_by': actor, 'activated_at': None,
            'lane': 'lead', 'activation_reason': ''}


def _credential_free(value):
    """Refuse credential-like rule literals as well as metadata before storing either."""
    if isinstance(value, str):
        _safe_text(value.replace('\r', ' ').replace('\n', ' ').replace('\t', ' '), limit=1024 * 1024)
    elif isinstance(value, dict):
        for key, child in value.items():
            _credential_free(key)
            _credential_free(child)
    elif isinstance(value, list):
        for child in value:
            _credential_free(child)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate fixture JSON key')
        result[key] = value
    return result


def _constant(_value):
    raise ValueError('Nonfinite fixture JSON number')


def _fixture(path, ast):
    from romulus.content.sigma_parser import evaluate_ast
    path = _local_path(path)
    if path.is_symlink():
        raise ValueError('Fixture links are refused')
    with path.open('rb') as handle:
        raw = handle.read(MAX_FIXTURE_BYTES + 1)
    if len(raw) > MAX_FIXTURE_BYTES:
        raise ValueError('Sigma fixture size limit exceeded')
    try:
        text = raw.decode('utf-8-sig')
        _json_depth(text)
        value = json.loads(text, object_pairs_hook=_pairs, parse_constant=_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise ValueError('Invalid Sigma fixture JSON') from None
    records = [value] if isinstance(value, dict) else value
    if not isinstance(records, list) or not records:
        raise ValueError('Sigma fixture must contain raw source records or hits')
    if len(records) > MAX_FIXTURE_RECORDS:
        raise ValueError('Sigma fixture record limit exceeded')
    hits, identities = [], set()
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise ValueError('Invalid Sigma fixture group member')  # noqa: TRY004 - public validation API
        native_id = f'fixture-{index}'
        if '_source' in record:
            if not isinstance(record['_source'], dict):
                raise ValueError('Invalid Sigma fixture source record')
            hit = {**record, '_id': str(record.get('_id', native_id)),
                   '_index': str(record.get('_index', 'fixture'))}
        else:
            source = record
            # EVE and audit records may be saved before the shipper adds its routing envelope.
            if 'event' not in source and isinstance(source.get('event_type'), str):
                source = {**source, 'event': {'dataset': 'suricata.eve'}}
            elif ('event' not in source and isinstance(source.get('message'), str)
                    and source['message'].startswith('type=')):
                source = {**source, 'event': {'dataset': 'linux.audit'}}
            hit = {'_source': source, '_id': native_id, '_index': 'fixture'}
        identity = (hit['_index'], hit['_id'])
        if identity in identities:
            raise ValueError('Duplicate Sigma fixture native identity')
        identities.add(identity)
        hits.append(hit)
    events, skips, errors = normalize_hits(hits)
    if errors or skips or not events:
        raise ValueError('Sigma fixture did not normalize completely')
    matched = any(evaluate_ast(ast, event)[0] for event in events)
    return {'sha256': hashlib.sha256(raw).hexdigest(), 'matched': matched,
            'typed_events': len(events), 'records': len(hits)}


def _verified(row, expected=None):
    actual = content_digest(row['ast'], row['mapping'])
    if actual != row['digest'] or expected is not None and actual != expected:
        raise ValueError('Sigma content digest differs from the pinned AST and mapping')


class SigmaRules:
    def __init__(self, repo):
        self.engine = repo.engine

    def import_directory(self, directory, *, upstream, commit, actor):
        from romulus.content.sigma_parser import load_rule, parse_rule
        upstream = _text(upstream, 'Sigma upstream', 2048)
        actor = _text(actor, 'Sigma actor', 256)
        if not isinstance(commit, str) or re.fullmatch(r'[0-9a-fA-F]{7,64}', commit) is None:
            raise ValueError('Sigma upstream commit must be a hexadecimal commit id')
        commit = commit.lower()
        root = _local_path(directory)
        report = {'imported': 0, 'unchanged': 0, 'draft': 0, 'reference-only': 0, 'skipped': 0,
                  'rules': [], 'errors': [], 'details_truncated': False}
        with write_txn(self.engine) as c:
            c.exec_driver_sql('BEGIN IMMEDIATE')
            for path, relative in _files(root):
                try:
                    relative = _text(relative, 'Sigma path', 2048)
                    doc = load_rule(path)
                    _credential_free(doc)
                    parsed = parse_rule(doc)
                    row = _row(doc, parsed, upstream=upstream, commit=commit, path=relative, actor=actor)
                except (ValueError, OSError, TypeError, KeyError):
                    report['skipped'] += 1
                    if len(report['errors']) < MAX_REPORT_DETAILS:
                        try:
                            safe_path = _text(relative, 'Sigma path', 2048)
                        except ValueError:
                            safe_path = '<invalid path>'
                        report['errors'].append({'path': safe_path, 'reason': 'invalid_rule_or_metadata'})
                    else:
                        report['details_truncated'] = True
                    continue
                created = c.execute(insert(t.sigma_rule).values(**row).on_conflict_do_nothing(
                    index_elements=['id'])).rowcount
                report['imported' if created else 'unchanged'] += 1
                report[row['status']] += 1
                if len(report['rules']) < MAX_REPORT_DETAILS:
                    report['rules'].append({key: row[key] for key in ('id', 'digest', 'status', 'upstream_path')} | {
                        'reasons': row['mapping']['reasons'], 'tag_drops': row['mapping']['tag_drops']})
                else:
                    report['details_truncated'] = True
                if created:
                    _audit(c, at=utcnow(), actor=actor, action='sigma.import', detail={
                        key: row[key] for key in ('id', 'digest', 'upstream', 'upstream_commit', 'upstream_path',
                                                 'author', 'status')})
            _audit(c, at=utcnow(), actor=actor, action='sigma.import_summary', detail=report)
        return report

    def get(self, rule_id):
        with read_snapshot(self.engine) as c:
            row = c.execute(select(t.sigma_rule).where(t.sigma_rule.c.id == rule_id)).mappings().first()
            return _serial(row) if row else None

    def list(self, *, limit=100, offset=0, status=None):
        if not isinstance(limit, int) or not 0 <= limit <= 10000 or not isinstance(offset, int) or offset < 0:
            raise ValueError('Invalid Sigma pagination')
        query = select(t.sigma_rule)
        if status is not None:
            if status not in {'draft', 'reference-only', 'active', 'retired'}:
                raise ValueError('Invalid Sigma status')
            query = query.where(t.sigma_rule.c.status == status)
        with read_snapshot(self.engine) as c:
            return [_serial(row) for row in c.execute(query.order_by(t.sigma_rule.c.id).limit(limit).offset(offset)).mappings()]

    def iter_rules(self):
        """Stream catalog rows without imposing a result-count cutoff."""
        with read_snapshot(self.engine) as c:
            for row in c.execute(select(t.sigma_rule).order_by(t.sigma_rule.c.id)).mappings():
                yield _serial(row)

    def activate(self, rule_id, positive, benign, *, actor, role, lane='lead', reason=''):
        if role != 'lead':
            raise PermissionError('Only a lead may activate Sigma rules')
        actor = _text(actor, 'Sigma actor', 256)
        reason = _text(reason, 'activation reason', 2048, empty=True)
        if lane not in {'lead', 'high'}:
            raise ValueError('Sigma lane must be lead or high')
        if lane == 'high' and not reason.strip():
            raise ValueError('A high lane requires an activation reason')
        row = self.get(rule_id)
        if row is None:
            raise ValueError('Unknown Sigma rule')
        if row['status'] == 'reference-only' or row['mapping'].get('reasons'):
            raise ValueError('A reference-only Sigma rule cannot be activated')
        _verified(row)
        yes, no = _fixture(positive, row['ast']), _fixture(benign, row['ast'])
        if not yes['matched'] or no['matched']:
            raise ValueError('Sigma fixtures require a positive match and a benign non-match')
        now = utcnow()
        with write_txn(self.engine) as c:
            c.exec_driver_sql('BEGIN IMMEDIATE')
            current = c.execute(select(t.sigma_rule).where(t.sigma_rule.c.id == rule_id)).mappings().first()
            if current is None:
                raise ValueError('Unknown Sigma rule')
            _verified(current, row['digest'])
            c.execute(t.sigma_rule.update().where(t.sigma_rule.c.id == rule_id).values(
                status='active', lane=lane, activation_reason=reason, activated_at=now))
            _audit(c, at=now, actor=actor, action='sigma.activate', detail={
                'id': rule_id, 'digest': row['digest'], 'lane': lane, 'reason': reason,
                'positive': yes, 'benign': no})
        return self.get(rule_id)

    def retire(self, rule_id, *, actor, role):
        if role != 'lead':
            raise PermissionError('Only a lead may retire Sigma rules')
        actor = _text(actor, 'Sigma actor', 256)
        with write_txn(self.engine) as c:
            c.exec_driver_sql('BEGIN IMMEDIATE')
            row = c.execute(select(t.sigma_rule).where(t.sigma_rule.c.id == rule_id)).mappings().first()
            if row is None:
                raise ValueError('Unknown Sigma rule')
            if row['status'] != 'retired':
                c.execute(t.sigma_rule.update().where(t.sigma_rule.c.id == rule_id).values(status='retired'))
                _audit(c, at=utcnow(), actor=actor, action='sigma.retire', detail={
                    'id': rule_id, 'digest': row['digest'], 'previous_status': row['status']})
        return self.get(rule_id)

    def pin(self):
        pins = {'as_of': utcnow().isoformat(), 'applied': []}
        total = 0
        with read_snapshot(self.engine) as c:
            query = select(t.sigma_rule).where(t.sigma_rule.c.status == 'active').order_by(
                t.sigma_rule.c.id).limit(MAX_ACTIVE_RULES + 1)
            for row in c.execute(query).mappings():
                _verified(row)
                total += len(_json({'ast': row['ast'], 'mapping': row['mapping']}).encode())
                if len(pins['applied']) >= MAX_ACTIVE_RULES or total > MAX_ACTIVE_BYTES:
                    raise ValueError('Active Sigma set exceeds the bounded hunt content limit')
                data = _serial(row)
                pins['applied'].append({key: data[key] for key in _PIN_FIELDS} | {
                    'version': row['digest'], 'status': 'active'})
        pins['digest'] = hashlib.sha256(_json(pins['applied']).encode()).hexdigest()
        return pins


def load_pinned(repo, pins):
    if not pins:
        return []
    selected = pins.get('applied', [])
    if not isinstance(selected, list) or len(selected) > MAX_ACTIVE_RULES:
        raise ValueError('Invalid pinned Sigma set')
    if pins.get('digest') != hashlib.sha256(_json(selected).encode()).hexdigest():
        raise ValueError('Pinned Sigma set digest differs')
    result, seen, total = [], set(), 0
    with read_snapshot(repo.engine) as c:
        for pin in selected:
            if pin['id'] in seen or pin['lane'] not in {'lead', 'high'}:
                raise ValueError('Invalid pinned Sigma identity or lane')
            seen.add(pin['id'])
            row = c.execute(select(t.sigma_rule).where(t.sigma_rule.c.id == pin['id'])).mappings().first()
            if row is None:
                raise ValueError('Pinned Sigma rule is missing')
            _verified(row, pin['digest'])
            total += len(_json({'ast': row['ast'], 'mapping': row['mapping']}).encode())
            if total > MAX_ACTIVE_BYTES:
                raise ValueError('Pinned Sigma set exceeds content memory limit')
            data = _serial(row)
            data.update({key: pin[key] for key in _PIN_FIELDS})
            data['status'] = 'active'
            data['version'] = pin['digest']
            result.append(data)
    return result
