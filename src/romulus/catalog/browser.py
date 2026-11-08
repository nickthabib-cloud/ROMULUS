"""Read-only catalog views with bounded overlays and SQL historical statistics."""
from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime, timedelta
from itertools import chain, islice
from pathlib import Path

import yaml
from sqlalchemy import LargeBinary, cast, func, select, text

from romulus.catalog.applicability import applicability
from romulus.catalog.build import _rule_metadata, build_catalog, strength_for_rule
from romulus.catalog.models import COVERAGE_STRENGTH_LEGEND
from romulus.content.indicator_export import _csv_cell
from romulus.content.sigma_store import MAX_ACTIVE_BYTES, MAX_ACTIVE_RULES
from romulus.detect.registry import ALL_PLAYBOOKS
from romulus.store import schema as t
from romulus.store.db import read_snapshot

TAGS = Path(__file__).resolve().parents[3] / 'content/catalog/rule_tags.yaml'
PAGE_SIZE = 50
PROFILE_MAX_AGE = timedelta(days=30)
PROFILE_LIMIT = 1000
MAX_PROFILE_BYTES = 8 * 1024 * 1024


class CatalogLimitError(ValueError):
    """Catalog content cannot be materialized within its explicit byte or row budget."""


def known_families():
    """Normalizer inventory includes families with no registered detection yet."""
    from romulus.hunt.sweep import DATASET_FAMILIES
    return tuple(sorted(set().union(*DATASET_FAMILIES.values(),
                                   *(rule.families for rule in ALL_PLAYBOOKS))))


def load_tags(path=TAGS):
    """Public tags contain names and registered rule references, including empty gaps."""
    document = yaml.safe_load(Path(path).read_text(encoding='utf-8'))
    registered = {rule.id for rule in ALL_PLAYBOOKS}
    if not isinstance(document, dict) or set(document) != {'tools', 'lotl', 'themes'}:
        raise ValueError('Invalid catalog tag table')
    for kind, rows in document.items():
        if not isinstance(rows, list):
            raise ValueError('Invalid catalog tag rows')  # noqa: TRY004 - public validation API
        for row in rows:
            allowed = {'name', 'rules', 'kind'} if kind == 'tools' else (
                {'name', 'platform', 'rules'} if kind == 'lotl' else {'name', 'description', 'rules'})
            if not isinstance(row, dict) or set(row) != allowed or not isinstance(row['rules'], list):
                raise ValueError('Invalid catalog tag entry')
            if any(not isinstance(value, str) for key, value in row.items() if key != 'rules'):
                raise ValueError('Invalid catalog tag name')
            if kind == 'tools' and row['kind'] not in {'offensive', 'dual-use', 'admin'}:
                raise ValueError('Invalid tool kind')
            for rule_id in row['rules']:
                if rule_id not in registered:
                    raise ValueError(f'Unregistered catalog rule: {rule_id}')
    return document


def readable_ast(ast):
    """Render compiled typed Sigma nodes as conditions, never executable syntax."""
    def term(node):
        kind = node.get('type')
        if kind in {'and', 'or'}:
            return '(' + f' {kind.upper()} '.join(term(child) for child in node['children']) + ')'
        if kind == 'not':
            return 'NOT ' + term(node['child'])
        if kind == 'selector':
            return term(ast.get('selectors', {}).get(node['name'], {}))
        if kind == 'exists':
            return f"{' or '.join(node['fields'])} {'exists' if node['value'] else 'is missing'}"
        if kind == 'field':
            groups = ['(' + ' OR '.join(term(item) for item in group) + ')' for group in node.get('groups', ())]
            converted = (' after typed conversion ' + str(node['conversion']['type'])) if node.get('conversion') else ''
            return (' or '.join(node['fields']) + converted + ' matches ' +
                    (' AND ' if node.get('all') else ' OR ').join(groups))
        if kind == 'string':
            pattern = ''.join(token.removeprefix('=') for token in node['pattern'])
            return repr(pattern) + (' (case-sensitive)' if node.get('cased') else ' (case-insensitive)')
        if kind == 'number':
            return f"{node['operator']} {node['value']}"
        if kind == 'cidr':
            return f"in network {node['value']}"
        if kind == 'literal':
            return repr(node['value'])
        return 'not recorded'
    scope = ast.get('scope', {})
    restrictions = [f'{key}: {value}' for key, value in scope.items() if key != 'field_inventory']
    return ('Scope: ' + '; '.join(restrictions) + '\n' if restrictions else '') + term(ast.get('condition', {}))


def _document(rule, metadata=None, *, source='built-in', ast=None):
    card = getattr(metadata, 'card', {}) or {}
    strength = strength_for_rule(rule).value
    research = getattr(metadata, 'research', ()) or card.get('research', ()) or ()
    if isinstance(research, str):
        research = [research]
    required = set(rule.required_fields)
    def fields(node):
        if isinstance(node, dict):
            if node.get('type') in {'field', 'exists'}:
                required.update(node.get('fields', ()))
            for value in node.values():
                fields(value)
        elif isinstance(node, list):
            for value in node:
                fields(value)
    if ast:
        fields(ast)
    return {
        'id': rule.id, 'title': rule.title, 'version': rule.version, 'families': list(rule.families),
        'attack_ids': list(rule.attack_ids), 'lane': rule.lane, 'severity': rule.severity,
        'assurance': strength, 'source': source, 'required_fields': list(rule.required_fields),
        'referenced_fields': sorted(required), 'ast': ast,
        'os_families': list(getattr(metadata, 'os_families', ())),
        'windows_event_classes': list(getattr(metadata, 'windows_event_classes', ())),
        'context_families': list(getattr(metadata, 'context_families', ())),
        'required_families': list(getattr(metadata, 'required_families', ())), 'datasets': list(rule.datasets),
        'required_by_family': dict(rule.required_by_family), 'behavior': rule.behavior or rule.title,
        'fidelity': rule.fidelity or dict(COVERAGE_STRENGTH_LEGEND)[strength],
        'positive_only_reason': rule.positive_only_reason or 'not recorded',
        'benign': list(getattr(metadata, 'benign', ()) or card.get('benign', ())),
        'next_checks': list(getattr(metadata, 'next_checks', ()) or card.get('next_checks', ())),
        'research': [url for url in research if isinstance(url, str) and url.startswith(('https://', 'http://'))],
        'license': str(card.get('license') or 'not recorded'),
        'thresholds': str(card.get('thresholds') or getattr(metadata, 'thresholds', '') or 'not recorded'),
        'predicate': readable_ast(ast) if ast else 'predicate implemented in code',
        'provenance': dict(rule.provenance),
    }


class CatalogBrowser:
    """Request-local state: registry size and active Sigma bytes have explicit pack bounds.

    Indicator overlays and historical data remain in SQL; pages load at most 51
    indicator metadata rows and never load candidate or disposition records.
    """
    def __init__(self, repo):
        self.repo = repo
        self.engine = repo.engine
        self._catalog = {}
        self._rules = None
        self._profiles = None
        self._sigma = None

    def catalog(self, domain='enterprise'):
        if domain not in self._catalog:
            self._catalog[domain] = build_catalog(
                playbooks=[*ALL_PLAYBOOKS, *(metadata for metadata, _ in self._active_sigma())], domain=domain)
        return self._catalog[domain]

    def _active_sigma(self):
        if self._sigma is not None:
            return self._sigma
        from romulus.detect.sigma import SigmaRule
        size = sum(func.coalesce(func.length(cast(column, LargeBinary)), 0) for column in t.sigma_rule.c)
        result, total = [], 0
        with read_snapshot(self.engine) as c:
            headers = c.execute(select(t.sigma_rule.c.id, size.label('bytes')).where(
                t.sigma_rule.c.status == 'active').order_by(t.sigma_rule.c.id).limit(MAX_ACTIVE_RULES + 1))
            for header in headers:
                total += header.bytes
                if len(result) >= MAX_ACTIVE_RULES or total > MAX_ACTIVE_BYTES:
                    raise CatalogLimitError('Active Sigma catalog exceeds its row or byte memory limit')
                # The same snapshot makes the byte preflight apply to the AST subsequently decoded.
                row = dict(c.execute(select(t.sigma_rule).where(
                    t.sigma_rule.c.id == header.id)).mappings().one())
                rule = SigmaRule(row)
                metadata = _rule_metadata(rule)
                result.append((metadata, _document(metadata, rule, source='Sigma', ast=row['ast'])))
        self._sigma = result
        return result

    def profiles(self):
        if self._profiles is not None:
            return self._profiles
        from romulus.hunt.sweep import _dataset_families
        from romulus.sources.profile import contract_from_types
        # Each recursive step seeks the next distinct target through its leading index.
        # Millions of old rows for one target cost one latest-row seek, never a rank/sort.
        query = text("""WITH RECURSIVE targets(target,n) AS (
            SELECT MIN(target),1 FROM source_profile
            UNION ALL
            SELECT (SELECT MIN(target) FROM source_profile WHERE target > targets.target), n+1
            FROM targets WHERE target IS NOT NULL AND n < :limit)
            SELECT p.id,p.target,p.captured_at,length(CAST(p.profile AS BLOB)) AS bytes
            FROM targets JOIN source_profile p ON p.id=(
                SELECT id FROM source_profile WHERE target=targets.target
                ORDER BY captured_at DESC,id DESC LIMIT 1)
            JOIN hunt h ON h.id=p.hunt_id WHERE targets.target IS NOT NULL ORDER BY p.target""")
        def stamp_of(value):
            if isinstance(value, str):
                try:
                    value = datetime.fromisoformat(value)
                except ValueError:
                    return None
            return value.replace(tzinfo=UTC) if value is not None and value.tzinfo is None else value
        with read_snapshot(self.engine) as c:
            latest = c.execute(select(t.hunt.c.id, t.hunt.c.created_at,
                func.length(cast(t.hunt.c.manifest, LargeBinary)).label('bytes')).order_by(
                t.hunt.c.created_at.desc(), t.hunt.c.id.desc()).limit(1)).first()
            manifest, total = {}, 0
            if latest and latest.bytes <= MAX_PROFILE_BYTES:
                total = latest.bytes
                manifest = c.execute(select(t.hunt.c.manifest).where(t.hunt.c.id == latest.id)).scalar_one()
            rows = []
            for header in c.execute(query, {'limit': PROFILE_LIMIT + 1}).mappings():
                profile = {}
                unknown_reason = 'profile byte budget exceeded'
                if total + header['bytes'] <= MAX_PROFILE_BYTES:
                    total += header['bytes']
                    profile = c.execute(select(t.source_profile.c.profile).where(
                        t.source_profile.c.id == header['id'])).scalar_one()
                    unknown_reason = ''
                rows.append({'target': header['target'], 'captured_at': header['captured_at'], 'profile': profile,
                             'unknown_reason': unknown_reason})
        recorded = {row['target']: index for index, row in enumerate(rows)}
        manifest_profiles = manifest.get('source_profiles', {})
        for target in islice(chain(manifest_profiles, manifest.get('targets', ())), PROFILE_LIMIT * 2):
            profile = manifest_profiles.get(target, {})
            captured = profile.get('captured_at', latest.created_at if latest else None)
            if target in recorded:
                previous = stamp_of(rows[recorded[target]]['captured_at'])
                current = stamp_of(captured)
                if profile and current and (previous is None or current > previous):
                    rows[recorded[target]] = {'target': target, 'captured_at': captured, 'profile': profile}
                continue
            rows.append({'target': target, 'captured_at': captured, 'profile': profile})
            recorded[target] = len(rows) - 1
            if len(rows) > PROFILE_LIMIT:
                break
        result = []
        for row in rows[:PROFILE_LIMIT]:
            profile, stamp = row['profile'], stamp_of(row['captured_at'])
            complete = (profile.get('datasets_complete', True) and bool(profile.get('field_types')) and
                        not any('truncat' in str(note).lower() or 'incomplete' in str(note).lower()
                                for note in profile.get('notes', ())))
            datasets = profile.get('datasets', {})
            known = bool(datasets) and all(_dataset_families(dataset) for dataset in datasets)
            families = sorted(set().union(*(_dataset_families(dataset) for dataset in datasets))) if known else None
            contract = contract_from_types(row['target'], profile.get('field_types', {}),
                                           role=profile.get('role'), os_family=profile.get('os_family'),
                                           datasets=datasets)
            result.append({'target': row['target'], 'captured_at': str(stamp or 'not recorded'),
                           'families': families, 'fields': sorted(contract.fields), 'datasets': list(datasets),
                           'unknown_reason': row.get('unknown_reason', ''),
                           'os_family': profile.get('os_family', 'unknown'), 'role': profile.get('role'),
                           'event_classes': profile.get('event_classes', profile.get('windows_event_classes')),
                           'scope_values': profile.get('scope_values', {}),
                           'absence_fields': profile.get('absence_fields', ()),
                           'fields_by_family': profile.get('fields_by_family', {}),
                           'fresh': bool(stamp and datetime.now(UTC) - stamp <= PROFILE_MAX_AGE and complete)})
        if len(rows) > PROFILE_LIMIT or latest and latest.bytes > MAX_PROFILE_BYTES:
            result.append({'target': 'additional source profiles', 'fresh': False,
                           'captured_at': 'profile row or byte budget exceeded'})
        self._profiles = result
        return result

    def base_rules(self):
        if self._rules is None:
            rows = [_document(_rule_metadata(rule), rule) for rule in ALL_PLAYBOOKS]
            rows.extend(document for _, document in self._active_sigma())
            self._rules = sorted(rows, key=lambda row: row['id'])
        return self._rules

    def _indicator_query(self):
        latest = select(t.indicator_list.c.id, func.max(t.indicator_list.c.version).label('version')).where(
            t.indicator_list.c.status != 'importing').group_by(t.indicator_list.c.id).subquery()
        return select(t.indicator_list).join(latest, (latest.c.id == t.indicator_list.c.id) &
            (latest.c.version == t.indicator_list.c.version)).where(
                t.indicator_list.c.status == 'active', t.indicator_list.c.expires_at > datetime.now(UTC))

    def _indicator_document(self, row):
        base = next(item for item in self.base_rules() if item['id'] == 'ioc.indicator_match')
        return {**base, 'id': 'indicator.' + row['id'], 'title': row['name'], 'version': str(row['version']),
                'source': 'indicator list', 'attack_ids': [], 'behavior': row['notes'] or row['name'],
                'lane': row['lane'], 'severity': row['severity'], 'research': [],
                'predicate': 'Typed indicator matching; values are available on the indicator list page.',
                'indicator_id': row['id'], 'provenance': {'author': row['author'], 'source': row['source']}}

    def statistics(self, rule_ids, last_n=10):
        last_n = max(1, min(100, last_n))
        wanted = {rid for rid in rule_ids if not rid.startswith('indicator.')}
        # Indicator matching findings record the shared matcher identity, not one list's identity.
        result = {rid: {'hits': 0, 'recent_hits': 0, 'last_hunt': None, 'last_at': None, 'outcomes': {}}
                  for rid in wanted}
        if not wanted:
            return result
        recent = select(t.hunt.c.id).order_by(t.hunt.c.created_at.desc(), t.hunt.c.id.desc()).limit(last_n)
        from sqlalchemy import case
        with self.engine.connect() as c:
            totals = c.execute(select(t.candidate.c.rule_id, func.count().label('hits'),
                func.sum(case((t.candidate.c.hunt_id.in_(recent), 1), else_=0)).label('recent_hits')).join(
                    t.hunt, t.hunt.c.id == t.candidate.c.hunt_id).where(
                    t.candidate.c.rule_id.in_(wanted)).group_by(t.candidate.c.rule_id)).mappings()
            for row in totals:
                result[row['rule_id']].update(hits=row['hits'], recent_hits=row['recent_hits'])
            wanted_rows = func.json_each(json.dumps(sorted(wanted))).table_valued('value')
            def last(column):
                return select(column).where(t.candidate.c.rule_id == wanted_rows.c.value).order_by(
                    t.candidate.c.created_at.desc(), t.candidate.c.id.desc()).limit(1).scalar_subquery()
            for row in c.execute(select(wanted_rows.c.value.label('rule_id'),
                last(t.candidate.c.hunt_id).label('hunt_id'), last(t.candidate.c.created_at).label('created_at'))).mappings():
                result[row['rule_id']].update(last_hunt=row['hunt_id'], last_at=row['created_at'])
            outcomes = c.execute(select(t.candidate.c.rule_id, t.disposition_event.c.status,
                func.count().label('n')).join(t.disposition_event, t.disposition_event.c.candidate_id == t.candidate.c.id
                ).join(t.hunt, t.hunt.c.id == t.candidate.c.hunt_id).where(
                    t.candidate.c.rule_id.in_(wanted)).group_by(t.candidate.c.rule_id, t.disposition_event.c.status))
            for rule_id, outcome, count in outcomes:
                result[rule_id]['outcomes'][outcome] = count
        return result

    def deleted_hunts(self):
        with self.engine.connect() as c:
            return c.execute(select(func.count(func.distinct(t.audit_event.c.hunt_id))).where(
                t.audit_event.c.action == 'hunt.delete')).scalar_one()

    def rules(self, filters, *, after='', limit=PAGE_SIZE):
        limit = max(1, min(PAGE_SIZE, limit))
        technique = filters.get('technique', '')
        tactic = filters.get('tactic', '')
        technique_ids = {item.technique.id for domain in ('enterprise', 'ics')
                         for item in self.catalog(domain).coverage_by_technique
                         if tactic in item.technique.tactics} if tactic else None
        def matches(row):
            if filters.get('q', '').casefold() not in (row['id'] + ' ' + row['title']).casefold():
                return False
            if filters.get('family') and filters['family'] not in row['families']:
                return False
            if technique and technique not in row['attack_ids']:
                return False
            if technique_ids is not None and not technique_ids.intersection(row['attack_ids']):
                return False
            if any(filters.get(key) and filters[key] != row[key] for key in ('lane', 'assurance', 'source')):
                return False
            return not (filters.get('applicability') and filters['applicability'] not in {
                item['state'] for item in applicability(row, self.profiles())})
        rows = [row for row in self.base_rules() if row['id'] > after and matches(row)]
        if filters.get('never_fired') == '1':
            wanted_rows = func.json_each(json.dumps([row['id'] for row in rows])).table_valued('value')
            fired = select(t.candidate.c.id).where(t.candidate.c.rule_id == wanted_rows.c.value).exists()
            with self.engine.connect() as c:
                fired_ids = set(c.execute(select(wanted_rows.c.value).where(fired)).scalars())
            rows = [row for row in rows if row['id'] not in fired_ids]
        if (not technique and not tactic and filters.get('never_fired') != '1'
                and filters.get('source', '') in {'', 'indicator list'}):
            # Overlay lists do not own candidates: never attribute the matcher's hits to every list.
            with self.engine.connect() as c:
                query = self._indicator_query().where(('indicator.' + t.indicator_list.c.id) > after)
                if filters.get('q'):
                    needle = '%' + filters['q'].replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_') + '%'
                    query = query.where((t.indicator_list.c.name.ilike(needle, escape='\\')) |
                                       (('indicator.' + t.indicator_list.c.id).ilike(needle, escape='\\')))
                for key in ('lane', 'severity'):
                    if filters.get(key):
                        query = query.where(getattr(t.indicator_list.c, key) == filters[key])
                sample = {**next(item for item in self.base_rules() if item['id'] == 'ioc.indicator_match'),
                          'id': '', 'title': filters.get('q', ''), 'source': 'indicator list',
                          'lane': filters.get('lane') or 'lead'}
                if matches(sample):
                    for row in c.execute(query.order_by(t.indicator_list.c.id).limit(limit + 1)).mappings():
                        rows.append(self._indicator_document(row))
        rows.sort(key=lambda row: row['id'])
        selected = rows[:limit]
        stats = self.statistics([row['id'] for row in selected])
        selected = [{**row, 'applicability': applicability(row, self.profiles()),
                     'performance': stats.get(row['id'])} for row in selected]
        return selected, selected[-1]['id'] if len(rows) > limit else None

    def detail(self, rule_id):
        row = next((item for item in self.base_rules() if item['id'] == rule_id), None)
        if row is None and rule_id.startswith('indicator.'):
            with self.engine.connect() as c:
                indicator = c.execute(self._indicator_query().where(
                    t.indicator_list.c.id == rule_id.removeprefix('indicator.'))).mappings().first()
            if indicator:
                row = self._indicator_document(indicator)
        if row is None:
            raise KeyError(rule_id)
        return {**row, 'applicability': applicability(row, self.profiles()),
                'performance': self.statistics([rule_id]).get(rule_id), 'suppressions': []}

    def export(self, filters, format):
        if format not in {'csv', 'md'}:
            raise ValueError('Unsupported catalog export format')
        fields = ['id', 'title', 'version', 'source', 'families', 'attack_ids', 'lane', 'severity', 'assurance']
        buffer = io.StringIO(newline='')
        writer = csv.writer(buffer, lineterminator='\n')
        if format == 'csv':
            writer.writerow(fields)
            yield buffer.getvalue()
        else:
            yield '| ' + ' | '.join(fields) + ' |\n|' + '---|' * len(fields) + '\n'
        after = ''
        while True:
            rows, next_after = self.rules(filters, after=after)
            for row in rows:
                values = [_csv_cell(', '.join(row[key]) if isinstance(row[key], list) else str(row[key])) for key in fields]
                if format == 'csv':
                    buffer.seek(0)
                    buffer.truncate(0)
                    writer.writerow(values)
                    yield buffer.getvalue()
                else:
                    import html
                    yield '| ' + ' | '.join(html.escape(value).replace('|', '\\|').replace('\n', ' ')
                                             for value in values) + ' |\n'
            if not next_after:
                break
            after = next_after
