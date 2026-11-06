"""Synthetic local Sigma rules preserve complete typed predicates without regexes."""
from __future__ import annotations

import base64
import json
from datetime import UTC, datetime

import pytest

from romulus.content.sigma_parser import ast_digest, evaluate_ast, load_rule, parse_rule
from romulus.evidence.typed import TypedEvent, fv

MAPPING = {'families': ['process_exec'], 'event_codes': [], 'os_families': ['windows'],
           'fields': {'Image': 'process.executable', 'CommandLine': 'process.command_line',
                      'EventID': 'event.code', 'DestinationPort': 'destination.port',
                      'DestinationIp': 'destination.ip',
                      'Hashes': {'hashes': {'MD5': 'file.hash.md5', 'SHA1': 'file.hash.sha1',
                                            'SHA256': 'file.hash.sha256'}}},
           'numeric_fields': ['destination.port', 'event.code'], 'reasons': [], 'rationale': []}


def event(**fields):
    return TypedEvent(id='e', family='process_exec', ts=datetime.now(UTC), host='host',
                      fields={name.replace('__', '.'): fv(value, 'native.'+name)
                              for name, value in fields.items()}, raw=[], normalizer='windows-test')


def rule(detection):
    return {'title': 'Synthetic local test', 'logsource': {'product': 'windows',
            'category': 'process_creation'}, 'detection': detection}


def compiled(selection, condition='selection'):
    parsed = parse_rule(rule({'selection': selection, 'condition': condition}), MAPPING)
    assert parsed['reasons'] == []
    assert json.loads(json.dumps(parsed['ast'])) == parsed['ast']
    return parsed['ast']


@pytest.mark.parametrize(('condition', 'expected'), [
    ('a', True), ('a and b', False), ('a or b', True), ('a and not b', True),
    ('not (a or b)', False), ('not b and (a or c)', True),
    ('a or b and c', True), ('(a or b) and c', False),
    ('1 of them', True), ('all of them', False), ('1 of a*', True),
    ('all of a*', True), ('a and not 1 of b*', True), (['b', 'a'], True),
])
def test_condition_forms_and_precedence(condition, expected):
    parsed = parse_rule(rule({'a': {'Image': 'evil.exe'}, 'b': {'Image': 'benign.exe'},
        'c': {'Image': 'other.exe'}, '_disabled': {'Image': 'ignored'}, 'condition': condition}), MAPPING)
    assert parsed['reasons'] == []
    assert evaluate_ast(parsed['ast'], event(process__executable='evil.exe'))[0] is expected


@pytest.mark.parametrize(('key', 'value', 'positive', 'benign'), [
    ('Image', r'C:\Windows\\*.exe', r'c:\WINDOWS\evil.exe', r'C:\Windows\evil.dll'),
    ('Image', 'evil?.exe', 'EVIL1.EXE', 'evil12.exe'),
    ('Image', r'evil\*.exe', 'evil*.exe', 'evil123.exe'),
    ('Image', r'c:\\*.exe', r'c:\evil.exe', 'c:evil.exe'),
    ('Image|contains', 'evil', 'xEVILx', 'safe'),
    ('Image|startswith', 'evil', 'EVIL.exe', 'xevil'),
    ('Image|endswith', 'evil', 'xEVIL', 'evilx'),
    ('Image|cased', 'Evil.exe', 'Evil.exe', 'evil.exe'),
    ('CommandLine|contains|windash', ' -flag-name ', 'x /flag\u2014name y', 'x +flag+name y'),
    ('CommandLine|base64', 'command', base64.b64encode(b'command').decode(), 'command'),
    ('CommandLine|base64|contains', 'command', 'x'+base64.b64encode(b'command').decode()+'y', 'command'),
    ('DestinationIp|cidr', '192.0.2.0/24', '192.0.2.3', '192.0.3.3'),
    ('DestinationIp|cidr', '2001:db8::/32', '2001:db8::3', '2001:db9::3'),
    ('DestinationPort|gt', 1024, 1025, 1024), ('DestinationPort|gte', 1024, 1024, 1023),
    ('DestinationPort|lt', 1024, 1023, 1024), ('DestinationPort|lte', 1024, 1024, 1025),
])
def test_supported_modifiers_have_positive_and_benign(key, value, positive, benign):
    ast = compiled({key: value})
    name = MAPPING['fields'][key.split('|')[0]].replace('.', '__')
    assert evaluate_ast(ast, event(**{name: positive}))[0]
    assert not evaluate_ast(ast, event(**{name: benign}))[0]


@pytest.mark.parametrize('prefix', ['', 'x', 'xy', 'long prefix '])
def test_base64offset_matches_each_byte_alignment(prefix):
    ast = compiled({'CommandLine|base64offset|contains': 'sensitive token'})
    encoded = base64.b64encode((prefix+'sensitive token'+' suffix').encode()).decode()
    assert evaluate_ast(ast, event(process__command_line=encoded))[0]
    assert not evaluate_ast(ast, event(process__command_line='unrelated'))[0]


def test_all_is_and_across_values_but_or_across_each_encoding_expansion():
    ast = compiled({'CommandLine|contains|all': ['first', 'second']})
    assert evaluate_ast(ast, event(process__command_line='SECOND then FIRST'))[0]
    assert not evaluate_ast(ast, event(process__command_line='first'))[0]
    ast = compiled({'CommandLine|base64offset|contains|all': ['first', 'second']})
    assert evaluate_ast(ast, event(process__command_line=base64.b64encode(b'xfirst second').decode()))[0]


def test_map_list_or_map_and_and_array_field_matching():
    ast = compiled([{'Image': 'evil.exe', 'CommandLine|contains': 'run'}, {'Image': 'other.exe'}])
    assert evaluate_ast(ast, event(process__executable='other.exe'))[0]
    assert not evaluate_ast(ast, event(process__executable='evil.exe', process__command_line='safe'))[0]
    assert evaluate_ast(compiled({'Image': ['evil.exe', 'other.exe']}),
                        event(process__executable=['safe.exe', 'EVIL.EXE']))[0]


@pytest.mark.parametrize('present,value', [(False, None), (True, None), (True, '')])
def test_exists_tests_presence_even_for_null_or_empty(present, value):
    ev = event(**({'process__executable': value} if present else {}))
    assert evaluate_ast(compiled({'Image|exists': True}), ev)[0] is present
    assert evaluate_ast(compiled({'Image|exists': False}), ev)[0] is not present


def test_null_and_empty_are_distinct_and_unknown_comparisons_do_not_turn_into_negated_positives():
    assert evaluate_ast(compiled({'Image': None}), event())[0]
    assert evaluate_ast(compiled({'Image': None}), event(process__executable=None))[0]
    assert not evaluate_ast(compiled({'Image': ''}), event())[0]
    assert evaluate_ast(compiled({'Image': ''}), event(process__executable=''))[0]
    assert not evaluate_ast(compiled({'Image': 'evil.exe'}, 'not selection'), event())[0]


def test_hashes_are_split_into_explicit_typed_fields_and_citations_are_typed():
    ast = compiled({'Hashes|contains': ['SHA256='+'ab'*32, 'SHA1='+'cd'*20]})
    matched, fields = evaluate_ast(ast, event(file__hash__sha256='ab'*32))
    assert matched and fields == ['file.hash.sha256']
    assert not evaluate_ast(ast, event(process__command_line='SHA256='+'ab'*32))[0]


@pytest.mark.parametrize(('selection', 'condition', 'reason'), [
    ({'Image|re': 'evil.*'}, 'selection', 're'),
    ({'Image|expand': '%secret%'}, 'selection', 'expand'),
    ({'Image|fieldref': 'ParentImage'}, 'selection', 'fieldref'),
    ({'Image': '%MACHINES%'}, 'selection', 'placeholder'),
    ({'NotMapped': 'evil'}, 'selection', 'NotMapped'),
    ({'Image|unknown': 'evil'}, 'selection', 'unknown'),
    ({'Image': 'evil'}, 'selection | count() by User > 1', 'aggregation'),
    ({'Image': 'evil'}, 'selection and missing', 'missing'),
    ({'Image': 'evil'}, '2 of them', 'condition'),
    ({'Image': 'evil'}, '1 of missing*', 'missing'),
    (['evil'], 'selection', 'untyped'),
    ({'Image|gt': 3}, 'selection', 'numeric'),
    ({'Image|exists': 'true'}, 'selection', 'boolean'),
    ({'Image|all': 'evil'}, 'selection', 'list'),
    ({'DestinationIp|cidr': 'broken'}, 'selection', 'cidr'),
    ({'Hashes': 'FOOHASH=1234'}, 'selection', 'hash'),
    ({'Hashes': 'SHA256=short'}, 'selection', 'hash'),
    ({'Image|contains|startswith': 'evil'}, 'selection', 'modifier'),
])
def test_unsupported_rule_is_wholly_reference_only(selection, condition, reason):
    parsed = parse_rule(rule({'selection': selection, 'condition': condition}), MAPPING)
    assert parsed['reasons'] and any(reason.lower() in item.lower() for item in parsed['reasons'])
    assert parsed['ast'] == {}


def test_unsupported_unused_selector_and_correlation_are_not_dropped():
    doc = rule({'selection': {'Image': 'evil'}, 'unused': {'Unknown': 'x'}, 'condition': 'selection'})
    assert parse_rule(doc, MAPPING)['reasons']
    doc = rule({'selection': {'Image': 'evil'}, 'condition': 'selection'})
    doc['correlation'] = {'type': 'event_count'}
    assert 'correlation' in ' '.join(parse_rule(doc, MAPPING)['reasons'])


def test_ast_digest_is_canonical_and_changes_with_predicate():
    ast = compiled({'Image': 'evil.exe'})
    assert ast_digest(ast) == ast_digest(json.loads(json.dumps(ast)))
    assert ast_digest(ast) != ast_digest(compiled({'Image': 'other.exe'}))


def test_numeric_matching_preserves_large_integer_precision_and_string_event_codes():
    ast = compiled({'DestinationPort|gt': 9007199254740992})
    assert evaluate_ast(ast, event(destination__port=9007199254740993))[0]
    assert not evaluate_ast(ast, event(destination__port=9007199254740992))[0]
    assert evaluate_ast(compiled({'EventID': 1}), event(event__code='1'))[0]


def test_unknown_or_mistyped_values_cannot_satisfy_negated_predicates():
    ast = compiled({'DestinationPort|gt': 1024}, 'not selection')
    for value in (None, True, 'not a port', {'bad': 'type'}):
        assert not evaluate_ast(ast, event(destination__port=value))[0]


def test_mapping_scope_is_preserved_in_the_ast_and_enforced():
    mapping = dict(MAPPING, event_codes=['1'], windows_event_classes=[['Sysmon', 'Provider', 1]],
                   scope=[{'field': 'process.audit', 'exists': True}])
    parsed = parse_rule(rule({'selection': {'Image': 'evil.exe'}, 'condition': 'selection'}), mapping)
    good = event(process__executable='evil.exe', event__code=1, event__channel='Sysmon',
                 event__provider='Provider', process__audit=True)
    assert evaluate_ast(parsed['ast'], good)[0]
    for field in ('event.code', 'event.channel', 'event.provider', 'process.audit'):
        changed = good.model_copy(deep=True)
        del changed.fields[field]
        assert not evaluate_ast(parsed['ast'], changed)[0]
    changed = good.model_copy(update={'family': 'image_load'})
    assert not evaluate_ast(parsed['ast'], changed)[0]


def test_them_excludes_underscored_selectors_but_explicit_names_are_supported():
    doc = rule({'selection': {'Image': 'evil.exe'}, '_filter': {'Image': 'benign.exe'},
                'condition': 'all of them'})
    assert evaluate_ast(parse_rule(doc, MAPPING)['ast'], event(process__executable='evil.exe'))[0]
    doc['detection']['condition'] = 'selection and _filter'
    assert not evaluate_ast(parse_rule(doc, MAPPING)['ast'], event(process__executable='evil.exe'))[0]


def test_condition_and_encoding_expansion_bounds_are_reference_only():
    for selection, condition in (({'Image': 'evil'}, 'not '*40+'selection'),
                                  ({'Image': 'evil'}, ' or '.join(['selection']*2050)),
                                  ({'CommandLine|base64|windash': '-a-b-c-d'}, 'selection')):
        parsed = parse_rule(rule({'selection': selection, 'condition': condition}), MAPPING)
        assert parsed['reasons'] and parsed['ast'] == {}


@pytest.mark.parametrize('text', [
    'title: first\ntitle: second\n', 'title: &x [*x]\n', 'title: !custom value\n',
    '---\ntitle: one\n---\ntitle: two\n', '- not\n- a\n- mapping\n',
    'x: '+('['*40)+'1'+(']'*40), 'x: .nan\n', 'x: {a: 1, a: 2}\n',
])
def test_yaml_hostile_inputs_rejected_without_object_construction(tmp_path, text):
    path = tmp_path/'rule.yml'
    path.write_text(text, encoding='utf-8')
    with pytest.raises(ValueError):
        load_rule(path)


def test_yaml_size_cap_and_plain_dates(tmp_path):
    path = tmp_path/'rule.yml'
    path.write_text('title: synthetic\ndate: 2026-01-01\n', encoding='utf-8')
    assert load_rule(path)['date'] == '2026-01-01'
    path.write_bytes(b'#'+b'x'*(1024*1024+1))
    with pytest.raises(ValueError, match='size|byte'):
        load_rule(path)


def test_direct_parse_is_bounded_and_rejects_wrong_types():
    recursive = {}
    recursive['self'] = recursive
    for value in ([], {'detection': []}, recursive):
        assert parse_rule(value, MAPPING)['reasons']


@pytest.mark.parametrize('shape', ['winlogbeat_8', 'elastic_agent'])
def test_default_mapping_and_real_windows_normalizer_evaluate_the_same_ast(shape):
    from romulus.evidence.windows_catalog import SYSMON, SYSMON_CHANNEL
    from tests.test_network_normalizers import one
    from tests.windows_fixtures import LogicalWindowsEvent, windows_hit
    doc = rule({'selection': {'Image|endswith': r'\probe.exe', 'EventID': 1}, 'condition': 'selection'})
    parsed = parse_rule(doc)
    assert parsed['reasons'] == []
    for executable, expected in ((r'C:\Tools\probe.exe', True), (r'C:\Tools\safe.exe', False)):
        raw = LogicalWindowsEvent(SYSMON_CHANNEL, SYSMON, 1, 'ws01', 1, '2026-01-02T03:04:05Z',
                                  {'Image': executable, 'ProcessId': '123'})
        assert evaluate_ast(parsed['ast'], one(windows_hit(raw, shape)))[0] is expected
