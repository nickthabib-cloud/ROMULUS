"""Detection intake changes only request rows, never hunt evidence or detection policy."""
from __future__ import annotations

import csv
import io
from functools import lru_cache
from uuid import uuid4

import yaml
from sqlalchemy import select

from romulus.catalog.attack import ICS_ATTACK_BUNDLE, ICS_PINNED_JSON_SHA256, load_attack_bundle
from romulus.catalog.browser import known_families
from romulus.content.indicator_export import _csv_cell
from romulus.detect.registry import ALL_PLAYBOOKS
from romulus.store import schema as t
from romulus.store.db import utcnow, write_txn

STATUSES = ('requested', 'accepted', 'in_progress', 'active', 'declined')
BEHAVIOR_MAX = 4000


@lru_cache(maxsize=1)
def _attack_knowledge():
    return (load_attack_bundle(), load_attack_bundle(ICS_ATTACK_BUNDLE, expected_sha256=ICS_PINNED_JSON_SHA256))


def validate_attack(values):
    if not isinstance(values, (list, tuple)) or len(values) > 64:
        raise ValueError('Invalid ATT&CK identifier list')
    result = set()
    for value in values:
        if not isinstance(value, str) or len(value) > 32:
            raise ValueError('Invalid ATT&CK identifier')
        value = value.strip().upper()
        found = False
        for knowledge in _attack_knowledge():
            try:
                technique = knowledge.technique(value)
            except KeyError:
                continue
            found = True
            if technique.revoked or technique.deprecated:
                state = 'revoked' if technique.revoked else 'deprecated'
                raise ValueError(f'{value} is {state}; replacement: {knowledge.replacement(value) or "not recorded"}')
            break
        if not found:
            raise ValueError(f'Unknown ATT&CK identifier: {value}')
        result.add(value)
    return sorted(result)


def _text(value, name, maximum, *, required=False):
    if not isinstance(value, str) or len(value) > maximum or '\x00' in value:
        raise ValueError(f'Invalid {name}')
    value = value.strip()
    if required and not value:
        raise ValueError(f'{name} is required')
    return value


class DetectionRequests:
    def __init__(self, repo):
        self.repo = repo
        self.engine = repo.engine

    def _account(self, connection, actor, *, lead=False):
        account = connection.execute(select(t.user.c.role, t.user.c.disabled).where(
            t.user.c.username == actor)).first()
        if not account or account.disabled or account.role not in {'analyst', 'lead'} or lead and account.role != 'lead':
            raise PermissionError('An active lead account is required' if lead else 'An active account is required')

    def _example(self, connection, candidate_id, event_id):
        candidate_id = _text(candidate_id or '', 'example finding', 256)
        event_id = _text(event_id or '', 'example event', 256)
        if not candidate_id and event_id:
            raise ValueError('An example event requires a finding reference')
        if candidate_id:
            candidate = connection.execute(select(t.candidate.c.event_ids).where(
                t.candidate.c.id == candidate_id)).first()
            if candidate is None:
                raise ValueError('Unknown example finding')
            if event_id and event_id not in candidate.event_ids:
                raise ValueError('Example event must be cited by the selected finding')
        return candidate_id or None, event_id or None

    def _get(self, connection, request_id):
        row = connection.execute(select(t.detection_request).where(
            t.detection_request.c.id == request_id)).mappings().first()
        if row is None:
            raise KeyError(request_id)
        return dict(row)

    def get(self, request_id):
        with self.engine.connect() as c:
            return self._get(c, request_id)

    def create(self, *, actor, behavior, family, attack_ids=(), candidate_id=None, event_id=None):
        behavior = _text(behavior, 'Behavior', BEHAVIOR_MAX, required=True)
        if family not in {*known_families(), 'unknown'}:
            raise ValueError('Unknown telemetry family')
        attack_ids = validate_attack(attack_ids)
        with write_txn(self.engine) as c:
            c.exec_driver_sql('BEGIN IMMEDIATE')
            self._account(c, actor)
            candidate_id, event_id = self._example(c, candidate_id, event_id)
            now = utcnow()
            request_id = uuid4().hex
            c.execute(t.detection_request.insert().values(
                id=request_id, requester=actor, created_at=now, behavior=behavior, telemetry_family=family,
                attack_ids=attack_ids, example_candidate_id=candidate_id, example_event_id=event_id,
                status='requested', rule_id=None, decline_reason=None, updated_by=actor, updated_at=now))
            return self._get(c, request_id)

    def edit(self, request_id, *, actor, behavior):
        behavior = _text(behavior, 'Behavior', BEHAVIOR_MAX, required=True)
        with write_txn(self.engine) as c:
            c.exec_driver_sql('BEGIN IMMEDIATE')
            self._account(c, actor)
            row = self._get(c, request_id)
            if row['requester'] != actor or row['status'] != 'requested':
                raise PermissionError('Only the requester can edit text while a request is requested')
            c.execute(t.detection_request.update().where(t.detection_request.c.id == request_id).values(
                behavior=behavior, updated_by=actor, updated_at=utcnow()))
            return self._get(c, request_id)

    def change_status(self, request_id, *, actor, status, rule_id='', reason=''):
        if status not in STATUSES:
            raise ValueError('Unknown request status')
        rule_id = _text(rule_id, 'rule id', 256)
        reason = _text(reason, 'reason', BEHAVIOR_MAX, required=status == 'declined')
        if status == 'active' and not rule_id:
            raise ValueError('An active request requires a rule id')
        with write_txn(self.engine) as c:
            c.exec_driver_sql('BEGIN IMMEDIATE')
            self._account(c, actor, lead=True)
            row = self._get(c, request_id)
            if status == 'active':
                registered = any(rule.id == rule_id for rule in ALL_PLAYBOOKS)
                sigma = rule_id.startswith('sigma.') and c.execute(select(t.sigma_rule.c.id).where(
                    t.sigma_rule.c.id == rule_id.removeprefix('sigma.'),
                    t.sigma_rule.c.status == 'active')).first()
                if not registered and not sigma:
                    raise ValueError('rule_id must name a registered rule or active Sigma rule')
            if row['status'] == status:
                raise ValueError('Request already has that status')
            # The trigger copies this reason and linked rule into the immutable event.
            c.execute(t.detection_request.update().where(t.detection_request.c.id == request_id).values(
                status=status, rule_id=rule_id or None, decline_reason=reason if status == 'declined' else None,
                status_reason=reason,
                updated_by=actor, updated_at=utcnow()))
            return self._get(c, request_id)

    def list(self, *, status='', requester='', after='', limit=50):
        if status and status not in STATUSES:
            raise ValueError('Unknown request status')
        if not isinstance(limit, int) or not 1 <= limit <= 50:
            raise ValueError('Invalid request page size')
        requester = _text(requester, 'requester', 256)
        after = _text(after, 'page cursor', 256)
        query = select(t.detection_request).where(t.detection_request.c.id > after)
        if status:
            query = query.where(t.detection_request.c.status == status)
        if requester:
            query = query.where(t.detection_request.c.requester == requester)
        with self.engine.connect() as c:
            rows = [dict(row) for row in c.execute(query.order_by(
                t.detection_request.c.id).limit(limit + 1)).mappings()]
        return rows[:limit], rows[limit - 1]['id'] if len(rows) > limit else None

    def history(self, request_id, *, after=0):
        if not isinstance(after, int) or after < 0:
            raise ValueError('Invalid history cursor')
        with self.engine.connect() as c:
            rows = [dict(row) for row in c.execute(select(t.detection_request_event).where(
                t.detection_request_event.c.request_id == request_id, t.detection_request_event.c.id > after
            ).order_by(t.detection_request_event.c.id).limit(51)).mappings()]
        return rows[:50], rows[49]['id'] if len(rows) > 50 else None

    def prefill(self, candidate_id, event_id=''):
        with self.engine.connect() as c:
            self._example(c, candidate_id, event_id)
            candidate = c.execute(select(t.candidate.c.claim, t.candidate.c.rule_id,
                t.candidate.c.event_ids, t.candidate.c.gate_results).where(t.candidate.c.id == candidate_id)).mappings().one()
            event_id = event_id or next(iter(candidate['event_ids']), '')
            event = c.execute(select(t.typed_event.c.family).where(t.typed_event.c.id == event_id)).first()
        mapped = candidate['gate_results'].get('_attack')
        if not mapped:
            mapped = next((list(rule.attack) for rule in ALL_PLAYBOOKS if rule.id == candidate['rule_id']), [])
        try:
            attack_ids = validate_attack(mapped)
        except ValueError:
            attack_ids = []
        return {'behavior': candidate['claim'][:BEHAVIOR_MAX], 'family': event.family if event else 'unknown',
                'attack_ids': attack_ids, 'candidate_id': candidate_id, 'event_id': event_id,
                'event_choices': candidate['event_ids'][:20]}

    def export(self, format, filters):
        if format not in {'yaml', 'csv'}:
            raise ValueError('Unsupported request export format')
        fields = ['id', 'behavior', 'telemetry_family', 'attack_ids', 'example_candidate_id', 'example_event_id', 'status']
        buffer = io.StringIO(newline='')
        writer = csv.writer(buffer, lineterminator='\n')
        if format == 'csv':
            writer.writerow(fields)
            yield buffer.getvalue()
        else:
            yield 'requests:\n'
        after, written = '', False
        while True:
            rows, next_after = self.list(**filters, after=after)
            for row in rows:
                written = True
                values = {key: row[key] for key in fields}
                if format == 'csv':
                    buffer.seek(0)
                    buffer.truncate(0)
                    writer.writerow([_csv_cell(', '.join(value) if isinstance(value, list) else str(value or ''))
                                     for value in values.values()])
                    yield buffer.getvalue()
                else:
                    yield ''.join('  '+line+'\n' for line in yaml.safe_dump([values], sort_keys=False).splitlines())
            if not next_after:
                break
            after = next_after
        if format == 'yaml' and not written:
            yield '  []\n'
