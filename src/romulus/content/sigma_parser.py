"""Bounded offline Sigma parsing and a JSON-only typed predicate evaluator.

Only the explicitly supported language is runnable. Unsupported clauses make the
whole rule reference-only; raw messages and backend query strings are never used.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import math
from decimal import Decimal, InvalidOperation
from pathlib import Path

import yaml

from romulus.evidence.typed import event_os_family

MAX_FILE_BYTES = 1024 * 1024
MAX_NODES = 20000
MAX_DEPTH = 32
MAX_STRING = 16384
MAX_CONDITION_TOKENS = 2048
MAX_ENCODINGS = 256
DASHES = '-/\u2013\u2014\u2015'
MODIFIERS = frozenset(('contains', 'startswith', 'endswith', 'all', 'cased', 'windash',
                       'exists', 'cidr', 'gt', 'gte', 'lt', 'lte', 'base64', 'base64offset'))
NUMERIC = frozenset(('gt', 'gte', 'lt', 'lte'))


class _RuleLoader(yaml.SafeLoader):
    def __init__(self, stream):
        super().__init__(stream)
        self._node_count = 0
        self._node_depth = 0

    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent):
            raise ValueError('Sigma YAML aliases are not supported')
        self._node_count += 1
        self._node_depth += 1
        try:
            if self._node_count > MAX_NODES or self._node_depth > MAX_DEPTH:
                raise ValueError('Sigma YAML exceeds node or depth bound')
            return super().compose_node(parent, index)
        finally:
            self._node_depth -= 1

    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in result:
                raise ValueError('Sigma YAML has a non-string or duplicate mapping key')
            result[key] = self.construct_object(value_node, deep=deep)
        return result


_RuleLoader.add_constructor('tag:yaml.org,2002:timestamp', lambda loader, node: loader.construct_scalar(node))


def _validate_tree(value):
    count = 0
    ancestors = set()

    def walk(item, depth):
        nonlocal count
        count += 1
        if count > MAX_NODES or depth > MAX_DEPTH:
            raise ValueError('Sigma document exceeds node or depth bound')
        if isinstance(item, str):
            if len(item) > MAX_STRING or any(0xD800 <= ord(c) <= 0xDFFF for c in item):
                raise ValueError('Sigma string exceeds bound or contains invalid Unicode')
        elif item is None or type(item) in (bool, int):
            pass
        elif isinstance(item, float):
            if not math.isfinite(item):
                raise ValueError('Sigma numbers must be finite')
        elif isinstance(item, (list, dict)):
            if id(item) in ancestors:
                raise ValueError('Sigma document contains a recursive structure')
            ancestors.add(id(item))
            try:
                if isinstance(item, dict):
                    for key, child in item.items():
                        if not isinstance(key, str):
                            raise ValueError('Sigma mapping keys must be strings')  # noqa: TRY004 - validation API
                        walk(key, depth + 1)
                        walk(child, depth + 1)
                else:
                    for child in item:
                        walk(child, depth + 1)
            finally:
                ancestors.remove(id(item))
        else:
            raise ValueError('Sigma document contains an unsupported value type')
    walk(value, 0)


def load_rule(path):
    """Read one local YAML document without aliases, custom objects or expansion."""
    path = Path(path)
    if str(path).startswith(('\\\\', '//')):
        raise ValueError('Sigma imports require a local path')
    if path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError('Sigma file exceeds byte size bound')
    with path.open('rb') as handle:
        data = handle.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise ValueError('Sigma file exceeds byte size bound')
    loader = None
    try:
        loader = _RuleLoader(data.decode('utf-8-sig'))
        document = loader.get_single_data()
        _validate_tree(document)
        if not isinstance(document, dict):
            raise ValueError('Sigma rule must be a mapping')  # noqa: TRY004 - validation API
        return document
    except (yaml.YAMLError, UnicodeError, RecursionError) as exc:
        raise ValueError('Invalid or unsupported Sigma YAML') from exc
    finally:
        if loader is not None:
            loader.dispose()


def ast_digest(ast):
    return hashlib.sha256(json.dumps(ast, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=True, allow_nan=False).encode()).hexdigest()


def _tokens(value, *, cased=False, windash=False):
    value = value if cased else value.casefold()
    result = []
    index = 0
    while index < len(value):
        char = value[index]
        if char == '\\' and index + 1 < len(value) and value[index + 1] in '*?\\':
            index += 1
            result.append('='+value[index])
        elif char in '*?':
            if char != '*' or not result or result[-1] != '*':
                result.append(char)
        elif windash and char in DASHES:
            result.append('dash')
        else:
            result.append('='+char)
        index += 1
    return result


def _wildcard(pattern, value):
    """Greedy glob matching, with no regex compilation or regex backtracking."""
    p = v = 0
    star = -1
    restart = 0
    while v < len(value):
        token = pattern[p] if p < len(pattern) else None
        if token == '?' or token == 'dash' and value[v] in DASHES or token == '='+value[v]:
            p += 1
            v += 1
        elif token == '*':
            star, restart = p, v
            p += 1
        elif star >= 0:
            restart += 1
            v = restart
            p = star + 1
        else:
            return False
    while p < len(pattern) and pattern[p] == '*':
        p += 1
    return p == len(pattern)


def _placeholder(value):
    if not isinstance(value, str):
        return False
    opened = False
    index = 0
    while index < len(value):
        if value[index] == '\\' and index + 1 < len(value) and value[index + 1] == '%':
            index += 2
            continue
        if value[index] == '%':
            if opened:
                return True
            opened = True
        index += 1
    return False


def _number(value):
    if type(value) not in (int, float, str):
        raise ValueError('Numeric modifier requires a finite number')
    try:
        result = Decimal(str(value))
    except (InvalidOperation, ValueError, OverflowError) as exc:
        raise ValueError('Numeric modifier requires a finite number') from exc
    if not result.is_finite():
        raise ValueError('Numeric modifier requires a finite number')
    return result


def _strings(value, modifiers):
    if not isinstance(value, str):
        raise ValueError('String modifier requires a string')  # noqa: TRY004 - validation API
    if _placeholder(value):
        raise ValueError('Unsupported placeholder value')
    cased = 'cased' in modifiers
    encoding = next((name for name in ('base64', 'base64offset') if name in modifiers), None)
    if encoding:
        tokens = _tokens(value, cased=True, windash='windash' in modifiers)
        if any(token in ('*', '?') for token in tokens):
            raise ValueError('Base64 modifier cannot encode wildcards')
        variants = ['']
        for token in tokens:
            options = DASHES if token == 'dash' else (token[1:],)
            if len(variants) * len(options) > MAX_ENCODINGS:
                raise ValueError('Fixed encoding expansion exceeds bound')
            variants = [prefix + suffix for prefix in variants for suffix in options]
        encoded = []
        for variant in variants:
            raw = variant.encode('utf-8')
            if encoding == 'base64':
                encoded.append(base64.b64encode(raw).decode())
            else:
                for index, start in enumerate((0, 2, 3)):
                    end = (None, -3, -2)[(len(raw) + index) % 3]
                    piece = base64.b64encode(b' ' * index + raw)[start:end].decode()
                    if not piece:
                        raise ValueError('Base64offset value is too short for fixed encoding')
                    encoded.append(piece)
        patterns = [_tokens(text, cased=cased) for text in dict.fromkeys(encoded)]
    else:
        patterns = [_tokens(value, cased=cased, windash='windash' in modifiers)]
    for pattern in patterns:
        if ('contains' in modifiers or 'endswith' in modifiers) and (not pattern or pattern[0] != '*'):
            pattern.insert(0, '*')
        if ('contains' in modifiers or 'startswith' in modifiers) and (not pattern or pattern[-1] != '*'):
            pattern.append('*')
    return [{'type': 'string', 'pattern': pattern, 'cased': cased} for pattern in patterns]


def _value(value, modifiers):
    numeric = NUMERIC.intersection(modifiers)
    if numeric:
        return [{'type': 'number', 'operator': next(iter(numeric)), 'value': str(_number(value))}]
    if 'cidr' in modifiers:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except (ValueError, TypeError) as exc:
            raise ValueError('Invalid cidr network value') from exc
        return [{'type': 'cidr', 'value': str(network)}]
    if value is None or isinstance(value, bool) or type(value) in (int, float):
        if modifiers:
            raise ValueError('String modifier requires a string value')
        return [{'type': 'literal', 'value': value}]
    return _strings(value, modifiers)


def _hash(value, modifiers, mapping):
    if not isinstance(value, str) or set(modifiers) - {'contains', 'all', 'cased'}:
        raise ValueError('Unsupported hash value or hash modifier')
    terms = []
    aliases = {key.replace('-', '').upper(): field for key, field in mapping.items()}
    lengths = {'MD5': 32, 'SHA1': 40, 'SHA256': 64, 'IMPHASH': 32}
    for part in value.split(','):
        name, sep, digest = part.strip().partition('=')
        name = name.replace('-', '').upper()
        field = aliases.get(name)
        if not sep or not field or name not in lengths or len(digest) != lengths[name] or any(
                char not in '0123456789abcdefABCDEF' for char in digest):
            raise ValueError('Unsupported hash algorithm or malformed hash comparison')
        terms.append({'type': 'field', 'fields': [field], 'all': False,
                      'groups': [[{'type': 'string', 'pattern': _tokens(digest), 'cased': False}]]})
    return {'type': 'and', 'children': terms}


def _field(key, value, mapping):
    if not isinstance(key, str):
        raise ValueError('Selection field names must be strings')  # noqa: TRY004 - validation API
    field, *modifiers = key.split('|')
    unsupported = [name for name in modifiers if name not in MODIFIERS]
    if unsupported:
        raise ValueError('Unsupported modifier: '+', '.join(unsupported))
    if len(set(modifiers)) != len(modifiers):
        raise ValueError('Duplicate modifier')
    target = mapping.get('fields', {}).get(field)
    if not target:
        raise ValueError('Unmapped field: '+field)
    if 'all' in modifiers and not isinstance(value, list):
        raise ValueError('The all modifier requires a list')
    mode = set(modifiers) - {'all', 'cased', 'windash'}
    if len(mode & {'contains', 'startswith', 'endswith'}) > 1 or len(mode & NUMERIC) > 1 or (
            mode & {'exists', 'cidr'} and len(mode) > 1) or (
            mode & NUMERIC and len(mode) > 1) or ('base64' in mode and 'base64offset' in mode):
        raise ValueError('Unsupported modifier combination')
    values = value if isinstance(value, list) else [value]
    if not values:
        raise ValueError('Selection values must not be an empty list')
    if isinstance(target, dict) and 'hashes' in target:
        return {'type': 'and' if 'all' in modifiers else 'or',
                'children': [_hash(item, modifiers, target['hashes']) for item in values]}
    fields = target if isinstance(target, list) else [target]
    if not all(isinstance(item, str) for item in fields):
        raise ValueError('Invalid typed field mapping')
    if NUMERIC.intersection(modifiers) and not set(fields) <= set(mapping.get('numeric_fields', [])):
        raise ValueError('Numeric modifier requires a numeric typed field')
    if 'exists' in modifiers:
        if type(value) is not bool or set(modifiers) != {'exists'}:
            raise ValueError('The exists modifier requires one boolean value')
        return {'type': 'exists', 'fields': fields, 'value': value}
    if any(_placeholder(item) for item in values):
        raise ValueError('Unsupported placeholder value')
    return {'type': 'field', 'fields': fields, 'all': 'all' in modifiers,
            'groups': [_value(item, [mod for mod in modifiers if mod != 'all']) for item in values]}


def _selection(value, mapping):
    if isinstance(value, list):
        if not value or any(not isinstance(item, dict) for item in value):
            raise ValueError('Unsupported untyped keyword selection')
        return {'type': 'or', 'children': [_selection(item, mapping) for item in value]}
    if not isinstance(value, dict) or not value:
        raise ValueError('Selection must contain a nonempty typed field mapping')
    return {'type': 'and', 'children': [_field(key, item, mapping) for key, item in value.items()]}


class _Condition:
    def __init__(self, text, names):
        if not isinstance(text, str) or not text.strip():
            raise ValueError('Condition must be a nonempty string')
        if '|' in text:
            raise ValueError('Unsupported aggregation condition')
        self.tokens = []
        index = 0
        while index < len(text):
            char = text[index]
            if char.isspace():
                index += 1
                continue
            if char in '()':
                self.tokens.append(char)
                index += 1
            elif char.isalnum() or char in '_*?':
                end = index + 1
                while end < len(text) and (text[end].isalnum() or text[end] in '_*?'):
                    end += 1
                self.tokens.append(text[index:end])
                index = end
            else:
                raise ValueError('Unsupported condition token')
            if len(self.tokens) > MAX_CONDITION_TOKENS:
                raise ValueError('Condition exceeds token bound')
        self.index = 0
        self.names = names

    def take(self, expected=None):
        value = self.tokens[self.index] if self.index < len(self.tokens) else None
        if expected is not None and value != expected:
            raise ValueError('Invalid condition: expected '+expected)
        self.index += 1
        return value

    def peek(self):
        return self.tokens[self.index] if self.index < len(self.tokens) else None

    def parse(self):
        result = self.expression('or', 0)
        if self.index != len(self.tokens):
            raise ValueError('Unsupported condition expression')
        return result

    def expression(self, operator, depth):
        if depth > MAX_DEPTH:
            raise ValueError('Condition exceeds depth bound')
        child = self.expression('and', depth + 1) if operator == 'or' else self.atom(depth + 1)
        children = [child]
        while self.peek() == operator:
            self.take()
            children.append(self.expression('and', depth + 1) if operator == 'or' else self.atom(depth + 1))
        return {'type': operator, 'children': children} if len(children) > 1 else child

    def atom(self, depth):
        if depth > MAX_DEPTH:
            raise ValueError('Condition exceeds depth bound')
        token = self.take()
        if token == 'not':
            return {'type': 'not', 'child': self.atom(depth + 1)}
        if token == '(':
            value = self.expression('or', depth + 1)
            self.take(')')
            return value
        if token in ('1', 'all'):
            self.take('of')
            pattern = self.take()
            if pattern == 'them':
                names = [name for name in self.names if not name.startswith('_')]
            elif isinstance(pattern, str):
                names = [name for name in self.names if _wildcard(_tokens(pattern, cased=True), name)]
            else:
                names = []
            if not names:
                raise ValueError('Condition pattern matched no selectors: '+str(pattern))
            return {'type': 'or' if token == '1' else 'and',
                    'children': [{'type': 'selector', 'name': name} for name in names]}
        if token in self.names:
            return {'type': 'selector', 'name': token}
        raise ValueError('Unsupported condition or unknown selector: '+str(token))


def parse_rule(document, mapping=None):
    """Produce a complete JSON predicate or explicit whole-rule refusal reasons."""
    reasons = []
    try:
        _validate_tree(document)
        if not isinstance(document, dict):
            raise ValueError('Sigma rule must be a mapping')  # noqa: TRY004 - validation API
        if 'correlation' in document:
            reasons.append('Unsupported correlation rule')
        if document.get('taxonomy', 'sigma') != 'sigma':
            reasons.append('Unsupported non-Sigma taxonomy')
        detection = document.get('detection')
        if not isinstance(detection, dict) or not detection:
            raise ValueError('Detection must be a nonempty mapping')
        if 'timeframe' in detection:
            reasons.append('Unsupported aggregation timeframe')
        selectors = {name: value for name, value in detection.items() if name not in ('condition', 'timeframe')}
        if not selectors:
            raise ValueError('Detection has no selectors')
        if mapping is None:
            from romulus.content.sigma_mapping import map_rule
            mapping = map_rule(document.get('logsource'), selectors)
        reasons.extend(mapping.get('reasons', []))
        compiled = {}
        for name, value in selectors.items():
            if not name or any(not (char.isalnum() or char == '_') for char in name):
                reasons.append('Unsupported selector name: '+name)
                continue
            try:
                compiled[name] = _selection(value, mapping)
            except ValueError as exc:
                reasons.append(name+': '+str(exc))
        conditions = detection.get('condition')
        conditions = conditions if isinstance(conditions, list) else [conditions]
        if not conditions:
            reasons.append('Condition list must not be empty')
        parsed_conditions = []
        for condition in conditions:
            try:
                parsed_conditions.append(_Condition(condition, selectors).parse())
            except ValueError as exc:
                reasons.append(str(exc))
        if reasons:
            return {'ast': {}, 'mapping': mapping, 'reasons': list(dict.fromkeys(reasons))}
        scope_keys = ('families', 'event_codes', 'os_families', 'windows_event_classes', 'scope')
        ast = {'version': 1, 'selectors': compiled,
               'condition': {'type': 'or', 'children': parsed_conditions},
               'scope': {key: mapping[key] for key in scope_keys if key in mapping}}
        return {'ast': ast, 'mapping': mapping, 'reasons': []}
    except (ValueError, TypeError, RecursionError) as exc:
        return {'ast': {}, 'mapping': mapping or {}, 'reasons': [str(exc) or 'Invalid Sigma rule']}


def _combine(operator, results):
    values = [result[0] for result in results]
    fields = set().union(*(result[1] for result in results))
    if operator == 'and':
        result = False if False in values else None if None in values else True
    else:
        result = True if True in values else None if None in values else False
    return result, fields


def _matches(expected, actual):
    kind = expected['type']
    if kind == 'literal':
        wanted = expected['value']
        if wanted is None:
            return actual is None
        if isinstance(wanted, bool):
            return actual == wanted if type(actual) is bool else None
        try:
            return _number(actual) == _number(wanted)
        except ValueError:
            return None
    if actual is None:
        return None
    if kind == 'number':
        try:
            value = _number(actual)
        except ValueError:
            return None
        operator, wanted = expected['operator'], _number(expected['value'])
        return {'gt': value > wanted, 'gte': value >= wanted,
                'lt': value < wanted, 'lte': value <= wanted}[operator]
    if kind == 'cidr':
        try:
            return ipaddress.ip_address(actual) in ipaddress.ip_network(expected['value'])
        except (TypeError, ValueError):
            return None
    if kind == 'string':
        if type(actual) not in (str, int, float, bool):
            return None
        value = str(actual)
        if not expected['cased']:
            value = value.casefold()
        return _wildcard(expected['pattern'], value)
    raise ValueError('Unsupported stored Sigma value')


def _in_scope(scope, event):
    if scope.get('families') and event.family not in scope['families']:
        return False
    if scope.get('os_families') and event_os_family(event) not in scope['os_families']:
        return False
    if scope.get('event_codes') and str(event.get('event.code')) not in {str(x) for x in scope['event_codes']}:
        return False
    classes = scope.get('windows_event_classes')
    if classes and not any(
            str(event.get('event.channel', '')).casefold() == str(channel).casefold()
            and str(event.get('event.provider', '')).casefold() == str(provider).casefold()
            and str(event.get('event.code')) == str(code) for channel, provider, code in classes):
        return False
    for clause in scope.get('scope', []):
        field = clause['field']
        if 'exists' in clause and (field in event.fields) != clause['exists']:
            return False
        if 'values' in clause and event.get(field) not in clause['values']:
            return False
    return True


def evaluate_ast(ast, event):
    """Evaluate typed fields only; unknown comparisons cannot become NOT positives."""
    if ast.get('version') != 1 or not _in_scope(ast.get('scope', {}), event):
        return False, []
    selectors = ast['selectors']
    cache = {}

    def evaluate(node):
        kind = node['type']
        if kind in ('and', 'or'):
            return _combine(kind, [evaluate(child) for child in node['children']])
        if kind == 'not':
            value, fields = evaluate(node['child'])
            return (None if value is None else not value), fields
        if kind == 'selector':
            name = node['name']
            if name not in cache:
                cache[name] = evaluate(selectors[name])
            return cache[name]
        fields = node['fields']
        present = {name for name in fields if name in event.fields}
        if kind == 'exists':
            return bool(present) == node['value'], present
        groups = []
        for alternatives in node['groups']:
            results = []
            for field in fields:
                values = (None if event.get('process.argv_complete') is False
                          and field in ('process.command_line', 'process.argv') else event.get(field))
                values = values if isinstance(values, list) else [values]
                outcomes = [_matches(expected, actual) for expected in alternatives for actual in values]
                # Empty observed lists contain no match, not a missing scalar.
                outcome = True if True in outcomes else None if None in outcomes else False
                results.append((outcome, {field} if field in present else set()))
            groups.append(_combine('or', results))
        return _combine('and' if node['all'] else 'or', groups)

    matched, fields = evaluate(ast['condition'])
    return matched is True, sorted(fields) if matched is True else []
