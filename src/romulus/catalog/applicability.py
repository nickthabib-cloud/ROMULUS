"""Conservative source capability checks without expanding Sigma boolean expressions."""
from __future__ import annotations

from romulus.evidence.linux_catalog import with_logical


def _combine(kind, states):
    if kind == 'or':
        return 'runs' if 'runs' in states else 'unknown' if 'unknown' in states else 'not applicable'
    return 'not applicable' if 'not applicable' in states else 'unknown' if 'unknown' in states else 'runs'


def _classes(values):
    return {(str(channel).casefold(), str(provider).casefold(), str(code)) for channel, provider, code in values or ()}


def _scope(rule, profile):
    ast_scope = (rule.get('ast') or {}).get('scope', {})
    for allowed in (rule.get('os_families', ()), ast_scope.get('os_families', ())):
        actual = profile.get('os_family', 'unknown')
        if allowed and actual != 'unknown' and actual not in allowed:
            return 'not applicable', f'OS {actual} outside rule scope'
        if allowed and actual == 'unknown' and set(allowed) != {'linux', 'windows'} and 'unknown' not in allowed:
            return 'unknown', 'source OS scope is not recorded'
    if rule.get('datasets'):
        # a Linux shipper's dataset delivers the logical dataset rules name
        delivered = with_logical(profile.get('datasets', ()))
        if not delivered:
            return 'unknown', 'native dataset inventory is not recorded'
        if not delivered.intersection(rule['datasets']):
            return 'not applicable', 'native datasets outside rule scope'
    actual_classes = profile.get('event_classes')
    for required in (rule.get('windows_event_classes', ()), ast_scope.get('windows_event_classes', ())):
        if required:
            if actual_classes is None:
                return 'unknown', 'native event class inventory is not recorded'
            if not _classes(actual_classes).intersection(_classes(required)):
                return 'not applicable', 'native event classes outside rule scope'
    values = dict(profile.get('scope_values', {}))
    if actual_classes is not None:
        values.setdefault('event.code', [str(row[2]) for row in actual_classes])
    if ast_scope.get('event_codes'):
        if 'event.code' not in values:
            return 'unknown', 'native event code inventory is not recorded'
        if not set(map(str, values['event.code'])).intersection(map(str, ast_scope['event_codes'])):
            return 'not applicable', 'native event codes outside Sigma scope'
    fields = set(profile.get('fields', ()))
    for clause in ast_scope.get('scope', ()):
        name = clause['field']
        if 'exists' in clause:
            if clause['exists'] and name not in fields:
                return 'not applicable', f'{name} missing'
            if not clause['exists'] and name not in profile.get('absence_fields', ()):
                return 'unknown', f'absence capability for {name} is not recorded'
        if 'values' in clause:
            if name not in values:
                return 'unknown', f'value inventory for {name} is not recorded'
            if not set(values[name]).intersection(clause['values']):
                return 'not applicable', f'{name} values outside Sigma scope'
    return 'runs', ''


def _ast_capability(ast, profile, family):
    fields = set(profile.get('fields_by_family', {}).get(family, profile.get('fields', ())))
    absence = set(profile.get('absence_fields', ()))
    inventory = ast.get('scope', {}).get('field_inventory')
    if inventory is not None:
        delivered_classes = _classes(profile.get('event_classes', ()))
        matching = [row for row in inventory if row.get('family') == family or
                    'event_class' in row and _classes([row['event_class']]).intersection(delivered_classes)]
        if not matching:
            return 'unknown'
        fields.intersection_update(set().union(*(set(row['fields']) for row in matching)))
        absence.update(set().union(*(set(row.get('absence_fields', ())) for row in matching)) & fields)
    memo, active = {}, set()
    def visit(node):
        kind = node.get('type')
        if kind in {'and', 'or'}:
            return _combine(kind, [visit(child) for child in node['children']])
        if kind == 'selector':
            name = node['name']
            if name in active:
                return 'unknown'
            if name not in memo:
                active.add(name)
                memo[name] = visit(ast.get('selectors', {}).get(name, {}))
                active.remove(name)
            return memo[name]
        if kind == 'not':
            return 'runs' if visit(node['child']) == 'runs' else 'unknown'
        aliases = set(node.get('fields', ()))
        if kind == 'exists' and not node['value']:
            return 'runs' if aliases.intersection(absence) else 'unknown'
        if kind not in {'field', 'exists'}:
            return 'unknown'
        if not aliases.intersection(fields):
            null = any(term.get('type') == 'literal' and term.get('value') is None
                       for group in node.get('groups', ()) for term in group)
            if null:
                return 'runs' if aliases.intersection(absence) else 'unknown'
            return 'not applicable'
        conversion = node.get('conversion', {})
        if conversion.get('event_classes'):
            if profile.get('event_classes') is None:
                return 'unknown'
            if _classes(profile['event_classes']).intersection(_classes(conversion['event_classes'])):
                if conversion.get('type') != 'security_registry_target':
                    return 'unknown'
                if 'registry.value_name' not in fields:
                    return 'not applicable'
        return 'runs'
    return visit(ast.get('condition', {}))


def applicability(rule, profiles):
    """A positive capability needs an accepted family, scoped inventory, and evaluable fields."""
    rows = []
    for profile in profiles:
        source = profile['target']
        native = profile.get('event_classes') or ()
        if len(native) > 1:
            # All predicate branches must be evaluable on one native class, not on
            # an invented union of fields from different event classes.
            variants = applicability(rule, [{**profile, 'event_classes': [item]} for item in native])
            selected = _combine('or', [item['state'] for item in variants])
            rows.append(next(item for item in variants if item['state'] == selected))
            continue
        if native:
            channel, provider, code = native[0]
            profile = {**profile, 'scope_values': {**profile.get('scope_values', {}),
                'event.channel': [channel], 'event.provider': [provider], 'event.code': [str(code)]}}
        state, reason = 'unknown', profile.get('unknown_reason') or (
            f"no source profile since {profile.get('captured_at', 'not recorded')}")
        if profile.get('fresh') and profile.get('families') is not None:
            state, reason = _scope(rule, profile)
            accepted = set(rule['families']) - set(rule.get('context_families', ()))
            supplied = accepted.intersection(profile['families'])
            explicit_required = set(rule.get('required_families', ()))
            if state == 'runs' and explicit_required - set(profile['families']):
                state, reason = 'not applicable', 'required family missing: ' + ', '.join(sorted(
                    explicit_required - set(profile['families'])))
            elif state == 'runs' and not supplied:
                state, reason = 'not applicable', 'accepted telemetry family missing'
            elif state == 'runs':
                states, missing, unrecorded = [], set(), False
                for family in supplied:
                    present = set(profile.get('fields_by_family', {}).get(family, profile.get('fields', ())))
                    required = set(rule['required_fields']) | set(rule['required_by_family'].get(family, ()))
                    absent = required - present
                    missing.update(absent)
                    capability = 'not applicable' if absent else 'runs'
                    if capability == 'runs' and rule.get('ast'):
                        capability = _ast_capability(rule['ast'], profile, family)
                    elif capability == 'runs' and not required:
                        # A supplied family alone does not show the predicate's fields are searchable.
                        capability, unrecorded = 'unknown', True
                    states.append(capability)
                state = _combine('or', states)
                reason = ('required fields are not recorded for this rule' if state == 'unknown' and unrecorded else
                          'typed predicate or field capability is not recorded' if state == 'unknown' else
                          ', '.join(sorted(missing)) + ' missing' if missing else 'predicate fields unavailable')
        text = f'runs on {source}' if state == 'runs' else f'{state}: {reason} in {source}'
        rows.append({'source': source, 'state': state, 'text': text})
    return rows or [{'source': 'unknown', 'state': 'unknown', 'text': 'unknown: no profile'}]
