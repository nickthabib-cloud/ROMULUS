"""Offline CSV, STIX 2.1 and MISP indicator imports with bounded diagnostics."""
from __future__ import annotations

import csv
import json
import math
import re
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from romulus.content.attack_tags import validate_attack
from romulus.content.indicator_values import _safe_text, normalize_value

CSV_MAX_BYTES = 128 * 1024 * 1024
JSON_MAX_BYTES = 16 * 1024 * 1024
JSON_MAX_DEPTH = 32
MAX_ROW_BYTES = 65536
MAX_FIELD_CHARS = 16384
MAX_SKIPPED_EXAMPLES = 1000
MAX_ATTACK = 64
MAX_PATTERN_COMPARISONS = 1024


@dataclass(frozen=True)
class ImportedIndicator:
    kind: str
    value: str
    label: str = ''
    attack: tuple[str, ...] = ()
    expires_at: datetime | None = None
    lane: str | None = None
    severity: str | None = None


@dataclass
class ImportResult:
    """Rows are a one-shot iterator; counts describe the rows consumed so far."""
    rows: Iterable[ImportedIndicator] = ()
    counts_by_kind: Counter[str] = field(default_factory=Counter)
    skipped_by_reason: Counter[str] = field(default_factory=Counter)
    skipped: list[dict] = field(default_factory=list)
    noted_by_reason: Counter[str] = field(default_factory=Counter)
    notes: list[dict] = field(default_factory=list)

    def _skip(self, reason: str, position: int) -> None:
        self.skipped_by_reason[reason] += 1
        if len(self.skipped) < MAX_SKIPPED_EXAMPLES:
            self.skipped.append({'position': position, 'reason': reason})

    def _accept(self, row: ImportedIndicator) -> ImportedIndicator:
        self.counts_by_kind[row.kind] += 1
        return row

    def _note(self, reason, position, **detail):
        self.noted_by_reason[reason] += 1
        if len(self.notes) < MAX_SKIPPED_EXAMPLES:
            self.notes.append({'position': position, 'reason': reason, **detail})

    def summary(self) -> dict:
        skipped_count = sum(self.skipped_by_reason.values())
        return {
            'accepted': sum(self.counts_by_kind.values()),
            'counts_by_kind': dict(self.counts_by_kind),
            'skipped_count': skipped_count,
            'skipped_by_reason': dict(self.skipped_by_reason),
            'skipped': list(self.skipped),
            'details_truncated': skipped_count - len(self.skipped),
            'noted_by_reason': dict(self.noted_by_reason),
            'notes': list(self.notes),
        }


def _text(value, *, limit=MAX_FIELD_CHARS) -> str:
    return _safe_text(value, limit=limit)


def _attack(value, result, position) -> tuple[str, ...]:
    if isinstance(value, str):
        values = [v for v in re.split(r'[;,\s]+', value) if v]
    elif isinstance(value, list):
        values = value
    else:
        raise ValueError('invalid attack metadata')  # noqa: TRY004 - import failures use ValueError.
    if len(values) > MAX_ATTACK:
        raise ValueError('attack metadata size limit exceeded')
    if any(not isinstance(v, str) or not re.fullmatch(r'T\d{4}(?:\.\d{3})?', v, re.IGNORECASE) for v in values):
        raise ValueError('invalid attack metadata')
    accepted, notes = validate_attack(v.upper() for v in values)
    for note in notes:
        result._note(note['reason'], position, **{k: v for k, v in note.items() if k != 'reason'})
    return accepted


def _label(value, result, position):
    try:
        return _text(value, limit=1024)
    except ValueError:
        result._note('label_redacted', position)
        return ''


def _unquote_cell(value):
    # Remove only the single guard emitted by the spreadsheet-safe CSV exporter.
    return value[1:] if value.startswith("'") and value[1:2] in {'=', '+', '-', '@', '\t', '\r'} else value


class _CSVLines:
    def __init__(self, stream):
        self.stream = stream
        self.total = 0
        self.row_bytes = 0

    def __iter__(self):
        return self

    def __next__(self):
        line = self.stream.readline(MAX_ROW_BYTES + 1)
        if not line:
            raise StopIteration
        size = len(line.encode('utf-8'))
        self.total += size
        self.row_bytes += size
        if self.total > CSV_MAX_BYTES:
            raise ValueError('CSV file size limit exceeded')
        if self.row_bytes > MAX_ROW_BYTES:
            raise ValueError('CSV row size limit exceeded')
        return line


def _csv_rows(path: Path, result: ImportResult) -> Iterator[ImportedIndicator]:
    try:
        with path.open(encoding='utf-8-sig', newline='') as stream:
            lines = _CSVLines(stream)
            reader = csv.reader(lines, strict=True)
            headers = next(reader, None)
            if (not headers or len(set(headers)) != len(headers)
                    or not {'kind', 'value'} <= set(headers)
                    or set(headers) - {'kind', 'value', 'label', 'attack', 'lane', 'severity'}):
                raise ValueError('CSV requires kind,value and optional label,attack,lane,severity columns')
            position = 1
            while True:
                lines.row_bytes = 0
                cells = next(reader, None)
                if cells is None:
                    return
                position += 1
                if len(cells) != len(headers):
                    raise ValueError('CSV row has wrong number of columns')
                row = dict(zip(headers, map(_unquote_cell, cells)))
                try:
                    kind = row['kind'].strip()
                    value = normalize_value(kind, row['value'])
                except ValueError:
                    result._skip('invalid_value', position)
                    continue
                label = _label(row.get('label', ''), result, position)
                try:
                    attack = _attack(row.get('attack', ''), result, position)
                    lane = row.get('lane') or None
                    severity = row.get('severity') or None
                    if lane is not None and lane not in {'high', 'lead', 'context'}:
                        raise ValueError('invalid lane')
                    if severity is not None and severity not in {'critical', 'high', 'medium', 'low', 'info'}:
                        raise ValueError('invalid severity')
                except ValueError:
                    result._skip('invalid_metadata', position)
                    continue
                yield result._accept(ImportedIndicator(kind, value, label, attack, lane=lane, severity=severity))
    except (csv.Error, UnicodeError):
        raise ValueError('malformed CSV encoding or structure') from None


def _json_depth(raw: str) -> None:
    depth = 0
    quoted = escaped = False
    for char in raw:
        if quoted:
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in '[{':
            depth += 1
            if depth > JSON_MAX_DEPTH:
                raise ValueError('JSON nesting depth limit exceeded')
        elif char in ']}':
            depth -= 1


def _pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError('duplicate JSON key')
        out[key] = value
    return out


def _constant(_):
    raise ValueError('nonfinite JSON number')


def _float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError('nonfinite JSON number')
    return number


def _load_json(path: Path):
    try:
        with path.open('rb') as stream:
            raw = stream.read(JSON_MAX_BYTES + 1)
        if len(raw) > JSON_MAX_BYTES:
            raise ValueError('JSON file size limit exceeded')
        raw = raw.decode('utf-8-sig')
        _json_depth(raw)
        return json.loads(raw, object_pairs_hook=_pairs, parse_constant=_constant, parse_float=_float)
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise ValueError('malformed JSON encoding or structure') from None


_STIX_PATHS = {
    'file:hashes.MD5': 'md5', 'file:hashes.SHA1': 'sha1',
    'file:hashes.SHA256': 'sha256',
    'ipv4-addr:value': 'ip', 'ipv6-addr:value': 'ip',
    'domain-name:value': 'domain', 'url:value': 'url',
    'x509-certificate:hashes.SHA1': 'x509_sha1',
    'x509-certificate:hashes.SHA256': 'x509_sha256',
    'network-traffic:extensions.ja3-ext.ja3_hash': 'ja3',
    'network-traffic:extensions.ja3.ja3_hash': 'ja3',
}
_STIX_PATH = re.compile(r"[a-z][a-z0-9-]*:(?:[a-zA-Z_][a-zA-Z0-9_-]*|'[a-zA-Z0-9_-]+')"
                        r"(?:\.(?:[a-zA-Z_][a-zA-Z0-9_-]*|'[a-zA-Z0-9_-]+'))*")
_STIX_STRING = re.compile(r"'((?:[^'\\]|\\['\\])*)'")


class _PatternError(ValueError):
    pass


def _pattern(pattern) -> list[tuple[str, str]]:
    """Parse only equality comparisons joined by OR; reject the entire remainder."""
    if not isinstance(pattern, str):
        raise _PatternError('invalid_pattern_type')
    try:
        _text(pattern)
    except ValueError:
        raise _PatternError('invalid_pattern_size_or_text') from None
    tokens = []
    i = 0
    while i < len(pattern):
        if pattern[i].isspace():
            i += 1
            continue
        if pattern[i] in '[]()=':
            tokens.append((pattern[i], pattern[i]))
            i += 1
        elif match := _STIX_PATH.match(pattern, i):
            tokens.append(('path', match.group()))
            i = match.end()
        elif match := _STIX_STRING.match(pattern, i):
            value = re.sub(r"\\(['\\])", r'\1', match.group(1))
            tokens.append(('value', value))
            i = match.end()
        elif pattern.startswith('OR', i) and (i + 2 == len(pattern) or not pattern[i + 2].isalnum()):
            tokens.append(('OR', 'OR'))
            i += 2
        else:
            raise _PatternError('unsupported_pattern_operator_or_path')
    index = 0
    values = []

    def take(token):
        nonlocal index
        if index >= len(tokens) or tokens[index][0] != token:
            raise _PatternError('unsupported_pattern_structure')
        value = tokens[index][1]
        index += 1
        return value

    def expression(depth=0, *, observation=False):
        nonlocal index
        if depth > JSON_MAX_DEPTH:
            raise _PatternError('pattern_depth_limit')
        term(depth, observation=observation)
        while index < len(tokens) and tokens[index][0] == 'OR':
            take('OR')
            term(depth, observation=observation)

    def term(depth, *, observation=False):
        if index < len(tokens) and tokens[index][0] == '(':
            take('(')
            expression(depth + 1, observation=observation)
            take(')')
            return
        if observation:
            take('[')
            expression(depth + 1)
            take(']')
            return
        path = take('path').replace("'", '')
        if ':hashes.' in path:
            head, algorithm = path.rsplit('.', 1)
            path = head + '.' + algorithm.upper().replace('-', '')
        take('=')
        value = take('value')
        kind = _STIX_PATHS.get(path)
        if not kind:
            raise _PatternError('unsupported_pattern_path')
        try:
            if kind == 'ip' and '/' in value:
                kind = 'cidr'
            value = normalize_value(kind, value)
            if path == 'ipv4-addr:value' and ':' in value or path == 'ipv6-addr:value' and ':' not in value:
                raise ValueError('address version does not match observable')
        except ValueError:
            raise _PatternError('invalid_pattern_value') from None
        values.append((kind, value))
        if len(values) > MAX_PATTERN_COMPARISONS:
            raise _PatternError('pattern_comparison_limit')

    if not tokens or tokens[0][0] not in {'[', '('}:
        raise _PatternError('unsupported_pattern_structure')
    expression(observation=True)
    if index != len(tokens) or not values:
        raise _PatternError('unsupported_pattern_structure')
    return values


def _expiry(value) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError('invalid expiry')
    try:
        expiry = datetime.fromisoformat(value)
    except ValueError:
        raise ValueError('invalid expiry') from None
    if expiry.tzinfo is None:
        raise ValueError('expiry requires timezone')
    try:
        return expiry.astimezone(UTC)
    except (OverflowError, ValueError):
        raise ValueError('invalid expiry') from None


def _stix_rows(objects: list, result: ImportResult, now) -> Iterator[ImportedIndicator]:
    for position, obj in enumerate(objects, 1):
        if not isinstance(obj, dict):
            result._skip('invalid_stix_object', position)
            continue
        if obj.get('type') != 'indicator':
            result._skip('unsupported_stix_object', position)
            continue
        if obj.get('revoked') is True:
            result._skip('revoked', position)
            continue
        if 'revoked' in obj and not isinstance(obj['revoked'], bool):
            result._skip('invalid_revoked_flag', position)
            continue
        if obj.get('spec_version') != '2.1' or obj.get('pattern_type') != 'stix':
            result._skip('unsupported_stix_version_or_pattern_type', position)
            continue
        try:
            values = _pattern(obj.get('pattern'))
        except _PatternError as error:
            result._skip(str(error), position)
            continue
        label = _label(obj.get('name', ''), result, position)
        try:
            expiry = _expiry(obj.get('valid_until'))
        except ValueError:
            result._skip('invalid_expiry', position)
            continue
        if expiry is not None and expiry <= now:
            for _ in values:
                result._skip('expired_at_import', position)
            continue
        try:
            references = obj.get('external_references', [])
            if not isinstance(references, list) or len(references) > MAX_ATTACK:
                raise ValueError('invalid attack references')
            attack = []
            for ref in references:
                if not isinstance(ref, dict):
                    raise ValueError('invalid reference')  # noqa: TRY004 - import failures use ValueError.
                if ref.get('source_name') == 'mitre-attack' and 'external_id' in ref:
                    attack.extend(_attack([ref['external_id']], result, position))
        except ValueError:
            result._skip('invalid_stix_metadata', position)
            continue
        for kind, value in values:
            yield result._accept(ImportedIndicator(kind, value, label, tuple(attack), expiry))


_MISP_KINDS = {
    'ip-src': 'ip', 'ip-dst': 'ip', 'ip-src|port': 'ip', 'ip-dst|port': 'ip',
    'domain': 'domain', 'hostname': 'domain', 'url': 'url', 'md5': 'md5', 'sha1': 'sha1',
    'sha256': 'sha256', 'ja3-fingerprint-md5': 'ja3',
    'x509-fingerprint-sha1': 'x509_sha1', 'x509-fingerprint-sha256': 'x509_sha256',
    'filename|md5': 'md5', 'filename|sha1': 'sha1', 'filename|sha256': 'sha256',
    'domain|ip': 'domain',
}


def _misp_attributes(doc) -> Iterable[dict]:
    if isinstance(doc, list):
        if any(not isinstance(item, dict) for item in doc):
            raise ValueError('MISP attribute list must contain objects')
        # Search exports may wrap attributes or events.
        for item in doc:
            if 'Event' in item:
                yield from _misp_attributes(item)
            elif isinstance(item.get('Attribute'), dict):
                yield item['Attribute']
            else:
                yield item
        return
    if not isinstance(doc, dict):
        raise ValueError('indicator JSON must be a STIX bundle or MISP object/list')  # noqa: TRY004
    if 'response' in doc:
        yield from _misp_attributes(doc['response'])
        return
    if 'Event' in doc:
        event = doc['Event']
        if not isinstance(event, dict):
            raise ValueError('MISP Event must be an object')
        yield from _misp_attributes(event)
        return
    if 'Attribute' not in doc and 'Object' not in doc:
        raise ValueError('MISP Attribute must be a list')
    attributes = doc.get('Attribute', [])
    if not isinstance(attributes, list):
        raise ValueError('MISP Attribute must be a list')  # noqa: TRY004 - import failures use ValueError.
    if any(not isinstance(item, dict) for item in attributes):
        raise ValueError('MISP attribute list must contain objects')
    yield from attributes
    objects = doc.get('Object', [])
    if not isinstance(objects, list) or any(not isinstance(item, dict) for item in objects):
        raise ValueError('MISP Object must be a list of objects')
    for obj in objects:
        yield from _misp_attributes(obj)


def _misp_rows(attributes: Iterable[dict], result: ImportResult, include_non_ids: bool) -> Iterator[ImportedIndicator]:
    for position, attr in enumerate(attributes, 1):
        if not isinstance(attr, dict):
            result._skip('invalid_misp_attribute', position)
            continue
        if attr.get('deleted') is True:
            result._skip('deleted', position)
            continue
        attr_type = attr.get('type')
        kind = _MISP_KINDS.get(attr_type) if isinstance(attr_type, str) else None
        if not kind:
            result._skip('unsupported_misp_type', position)
            continue
        to_ids = attr.get('to_ids', True)
        if not isinstance(to_ids, bool):
            result._skip('invalid_to_ids_flag', position)
            continue
        if not to_ids and not include_non_ids:
            result._skip('non_ids', position)
            continue
        try:
            value = _text(attr.get('value'))
            values = []
            if attr_type.startswith('filename|'):
                pieces = value.rsplit('|', 1)
                if len(pieces) != 2:
                    raise ValueError('invalid filename and hash')
                value = pieces[1]
                try:
                    program = normalize_value('program_name', pieces[0])
                except ValueError:
                    pass
                else:
                    values.append(('program_name', program))
            elif attr_type == 'domain|ip':
                pieces = value.split('|')
                if len(pieces) != 2:
                    raise ValueError('invalid domain and address')
                value = pieces[0]
                address_kind = 'cidr' if '/' in pieces[1] else 'ip'
                values.append((address_kind, normalize_value(address_kind, pieces[1])))
            if attr_type in {'ip-src|port', 'ip-dst|port'}:
                pieces = value.split('|')
                if (len(pieces) != 2 or not pieces[1].isascii() or not pieces[1].isdigit()
                        or not 0 <= int(pieces[1]) <= 65535):
                    raise ValueError('invalid address and port')
                value = pieces[0]
            if kind == 'ip' and '/' in value:
                kind = 'cidr'
            value = normalize_value(kind, value)
        except ValueError:
            result._skip('invalid_value', position)
            continue
        label = _label(attr.get('comment', ''), result, position)
        values.append((kind, value))
        for value_kind, value in values:
            yield result._accept(ImportedIndicator(value_kind, value, label))


def parse_indicator_file(path: Path, *, include_non_ids: bool = False, now=None) -> ImportResult:
    """Parse a local CSV/JSON file. Exhaust rows before storing summary/audit data."""
    now = (now or datetime.now(UTC)).astimezone(UTC)
    path = Path(path)
    if path.as_posix().startswith('//'):
        raise ValueError('indicator import requires a local file')
    suffix = path.suffix.lower()
    if suffix not in {'.csv', '.json'}:
        raise ValueError('only offline CSV and JSON indicator files are supported')
    limit = CSV_MAX_BYTES if suffix == '.csv' else JSON_MAX_BYTES
    if path.stat().st_size > limit:
        raise ValueError('indicator file size limit exceeded')
    result = ImportResult()
    if suffix == '.csv':
        result.rows = _csv_rows(path, result)
    else:
        doc = _load_json(path)
        if isinstance(doc, dict) and doc.get('type') == 'bundle':
            objects = doc.get('objects')
            if not isinstance(objects, list):
                raise ValueError('STIX bundle objects must be a list')
            result.rows = _stix_rows(objects, result, now)
        else:
            result.rows = _misp_rows(_misp_attributes(doc), result, include_non_ids)
    return result
