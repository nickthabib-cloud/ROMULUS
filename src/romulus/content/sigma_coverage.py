"""Bounded imported-rule coverage detail and conservative native-class reason scope."""
from __future__ import annotations

from copy import copy

REASON_LIMIT = 8
REASON_TEXT = 256
SUMMARY_PREFIX = 'Sigma coverage detail budget:'


def visible_reasons(detail):
    return [reason for reason in detail.get('reasons', ()) if not reason.startswith(SUMMARY_PREFIX)]


def bounded_details(detail):
    """Keep eight bounded reasons; exact counts describe omitted and overlength source texts."""
    result = dict(detail or {})
    reasons = visible_reasons(result)
    omitted = int(result.pop('_sigma_reason_omitted', 0))+int(result.pop('reason_omitted', 0))
    long_texts = int(result.pop('_sigma_reason_truncated', 0))+int(result.pop('reason_truncated', 0))
    total = len(reasons)+omitted
    kept = [str(reason)[:REASON_TEXT] for reason in reasons[:REASON_LIMIT]]
    long_texts += sum(len(str(reason)) > REASON_TEXT for reason in reasons)
    omitted = total-len(kept)
    if omitted or long_texts:
        kept.append(f'{SUMMARY_PREFIX} {total} reason(s) total; {omitted} omitted; '
                    f'{long_texts} source text(s) exceeded {REASON_TEXT} characters.')
    result.update(reasons=kept, reason_total=total, reason_omitted=omitted, reason_truncated=long_texts)
    return result


def _literal_code(expected):
    if expected.get('type') == 'literal':
        value = expected.get('value')
        if type(value) is int or type(value) is float and value.is_integer():
            return str(int(value))
    elif expected.get('type') == 'string':
        pattern = expected.get('pattern', ())
        if all(token.startswith('=') for token in pattern):
            value = ''.join(token[1:] for token in pattern)
            if value and value.isascii() and value.isdigit():
                return value
    return None


def positive_event_ids(ast):
    """Finite EventIDs required by every positive branch; negations never narrow collection reasons."""
    selectors = ast.get('selectors', {})
    def ids(node):
        kind = node.get('type')
        if kind == 'selector':
            return ids(selectors[node['name']])
        if kind in {'and', 'or'}:
            values = [ids(child) for child in node['children']]
            known = [value for value in values if value is not None]
            if not known or kind == 'or' and len(known) != len(values):
                return None
            return frozenset.union(*known) if kind == 'or' else frozenset.intersection(*known)
        if kind != 'field' or node.get('fields') != ['event.code']:
            return None
        groups = []
        for alternatives in node.get('groups', ()):
            codes = [_literal_code(expected) for expected in alternatives]
            if not codes or any(code is None for code in codes):
                return None
            groups.append(frozenset(codes))
        if not groups:
            return None
        return frozenset.intersection(*groups) if node.get('all') else frozenset.union(*groups)
    return ids(ast.get('condition', {}))


def coverage_view(rule):
    """A shallow metadata view narrows required classes for reasons, leaving runtime scope untouched."""
    result = copy(rule)
    wanted = positive_event_ids(rule.ast)
    if wanted is not None and rule.windows_event_classes:
        result.windows_event_classes = tuple(item for item in rule.windows_event_classes if str(item[2]) in wanted)
        if not result.windows_event_classes:
            result.families = ()
    return result


def reason_signature(rule):
    return (tuple(sorted(rule.families)), tuple(sorted(rule.os_families)),
            tuple(sorted(rule.windows_event_classes)))


def exclusion_reasons(rule):
    wanted = positive_event_ids(rule.ast)
    for excluded in rule.metadata.get('mapping', {}).get('exclusions', ()):
        channel, provider, code = excluded['event_class']
        if wanted is not None and str(code) not in wanted:
            continue
        fields = ', '.join(excluded.get('fields', ()))
        yield (f"Sigma mapping exclusion: {channel}|{provider}|{code}: {excluded['reason']} "
               f'({fields}); this native class is not evaluated.')
