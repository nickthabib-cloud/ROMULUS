"""Read-only catalog views with bounded overlays and SQL historical statistics."""
from __future__ import annotations

import csv
import io
from datetime import UTC, datetime, timedelta
from pathlib import Path

import yaml
from sqlalchemy import func, select

from romulus.catalog.build import _rule_metadata, build_catalog, strength_for_rule
from romulus.catalog.models import COVERAGE_STRENGTH_LEGEND
from romulus.content.indicator_export import _csv_cell
from romulus.content.sigma_store import MAX_ACTIVE_RULES
from romulus.detect.registry import ALL_PLAYBOOKS
from romulus.store import schema as t

TAGS = Path(__file__).resolve().parents[3] / 'content/catalog/rule_tags.yaml'
PAGE_SIZE = 50
PROFILE_MAX_AGE = timedelta(days=30)
PROFILE_LIMIT = 1000


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


def applicability(rule, profiles):
    """Only current, complete profiles can establish family and field availability."""
    rows = []
    for profile in profiles:
        source = profile['target']
        captured = profile.get('captured_at', 'not recorded')
        state = 'unknown'
        text = f'unknown: no source profile since {captured} for {source}'
        if profile.get('fresh') and profile.get('families') is not None:
            missing_families = set(rule['families']) - set(profile['families'])
            required = set(rule['required_fields'])
            for family in rule['families']:
                required.update(rule['required_by_family'].get(family, ()))
            missing_fields = required - set(profile.get('fields', ()))
            if missing_families or missing_fields:
                state = 'not applicable'
                missing = ', '.join(sorted(missing_fields or missing_families))
                text = f'not applicable: {missing} missing in {source}'
            elif rule['families']:
                state, text = 'runs', f'runs on {source}'
        rows.append({'source': source, 'state': state, 'text': text})
    return rows or [{'source': 'unknown', 'state': 'unknown', 'text': 'unknown: no profile'}]


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
            groups = [' AND '.join(term(item) for item in group) for group in node.get('groups', ())]
            return (' or '.join(node['fields']) + ' matches ' +
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
    return term(ast.get('condition', {}))


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
        'assurance': strength, 'source': source, 'required_fields': sorted(required),
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

    def catalog(self, domain='enterprise'):
        if domain not in self._catalog:
            self._catalog[domain] = build_catalog(playbooks=ALL_PLAYBOOKS, domain=domain)
        return self._catalog[domain]

    def profiles(self):
        if self._profiles is not None:
            return self._profiles
        from romulus.hunt.sweep import _dataset_families
        from romulus.sources.profile import contract_from_types
        ranked = select(t.source_profile, func.row_number().over(
            partition_by=t.source_profile.c.target,
            order_by=(t.source_profile.c.captured_at.desc(), t.source_profile.c.id.desc())).label('n')).join(
                t.hunt, t.hunt.c.id == t.source_profile.c.hunt_id).subquery()
        with self.engine.connect() as c:
            rows = c.execute(select(ranked).where(ranked.c.n == 1).order_by(
                ranked.c.target).limit(PROFILE_LIMIT + 1)).mappings().all()
            latest = c.execute(select(t.hunt.c.manifest, t.hunt.c.created_at).order_by(
                t.hunt.c.created_at.desc(), t.hunt.c.id.desc()).limit(1)).first()
        result = []
        if not rows and latest:
            rows = [{'target': target, 'profile': profile,
                     'captured_at': profile.get('captured_at', latest.created_at)}
                    for target, profile in list(latest.manifest.get('source_profiles', {}).items())[:PROFILE_LIMIT]]
        for row in rows[:PROFILE_LIMIT]:
            profile = row['profile']
            stamp = row['captured_at']
            if isinstance(stamp, str):
                try:
                    stamp = datetime.fromisoformat(stamp)
                except ValueError:
                    stamp = None
            if stamp is not None and stamp.tzinfo is None:
                stamp = stamp.replace(tzinfo=UTC)
            complete = (profile.get('datasets_complete', True) and bool(profile.get('field_types')) and
                        not any('truncat' in str(note).lower() or 'incomplete' in str(note).lower()
                                for note in profile.get('notes', ())))
            datasets = profile.get('datasets', {})
            known = bool(datasets) and all(_dataset_families(dataset) for dataset in datasets)
            families = sorted(set().union(*(_dataset_families(dataset) for dataset in datasets))) if known else None
            contract = contract_from_types(row['target'], profile.get('field_types', {}),
                                           role=profile.get('role'), os_family=profile.get('os_family'))
            result.append({'target': row['target'], 'captured_at': str(stamp or 'not recorded'),
                           'families': families, 'fields': sorted(contract.fields),
                           'fresh': bool(stamp and datetime.now(UTC) - stamp <= PROFILE_MAX_AGE and complete)})
        if len(rows) > PROFILE_LIMIT:
            result.append({'target': 'additional sources', 'fresh': False, 'captured_at': 'profile page limit'})
        self._profiles = result
        return result

    def base_rules(self):
        if self._rules is None:
            metadata = {rule.id: rule for rule in ALL_PLAYBOOKS}
            rows = [_document(rule, metadata[rule.id]) for rule in self.catalog().rules]
            from romulus.detect.sigma import SigmaRule
            with self.engine.connect() as c:
                sigma = c.execute(select(t.sigma_rule).where(t.sigma_rule.c.status == 'active').order_by(
                    t.sigma_rule.c.id).limit(MAX_ACTIVE_RULES + 1)).mappings().all()
            if len(sigma) > MAX_ACTIVE_RULES:
                raise ValueError('Active Sigma catalog limit exceeded')
            for row in sigma:
                rule = SigmaRule(dict(row))
                rows.append(_document(_rule_metadata(rule), rule, source='Sigma', ast=row['ast']))
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
            ranked = select(t.candidate.c.rule_id, t.candidate.c.hunt_id, t.candidate.c.created_at,
                func.row_number().over(partition_by=t.candidate.c.rule_id,
                    order_by=(t.candidate.c.created_at.desc(), t.candidate.c.id.desc())).label('n')).join(
                    t.hunt, t.hunt.c.id == t.candidate.c.hunt_id).where(t.candidate.c.rule_id.in_(wanted)).subquery()
            for row in c.execute(select(ranked).where(ranked.c.n == 1)).mappings():
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
            stats = self.statistics([row['id'] for row in rows])
            rows = [row for row in rows if not stats[row['id']]['hits']]
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
                          'id': '', 'title': filters.get('q', ''), 'source': 'indicator list'}
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
