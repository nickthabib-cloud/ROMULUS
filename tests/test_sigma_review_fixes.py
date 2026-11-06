"""Regression proofs for the single final review's material Sigma findings."""
import pytest

from romulus.content.sigma_parser import evaluate_ast, parse_rule
from romulus.detect.sigma import SigmaRule
from romulus.evidence.normalize import normalize_hits
from romulus.evidence.windows import normalize_windows
from romulus.evidence.windows_catalog import SYSMON, SYSMON_CHANNEL
from tests.test_evidence import EXECVE_HEX, SYSCALL, hit
from tests.test_network_normalizers import eve, one
from tests.test_sigma_playbook import row
from tests.windows_fixtures import LogicalWindowsEvent, windows_hit


@pytest.mark.parametrize('wanted', [True, False])
@pytest.mark.parametrize('actual', [None, 'true', 'false', 0])
def test_negated_boolean_is_unknown_when_native_boolean_is_missing_or_mistyped(wanted, actual):
    parsed = parse_rule({'title': 'Synthetic boolean', 'logsource': {'product': 'windows', 'category': 'image_load'},
        'detection': {'s': {'Signed': wanted}, 'condition': 'not s'}})
    assert not parsed['reasons']
    data = {'ImageLoaded': r'C:\Library.dll'}
    if actual is not None:
        data['Signed'] = actual
    event = normalize_windows(windows_hit(LogicalWindowsEvent(SYSMON_CHANNEL, SYSMON, 7, 'ws01', 1,
        '2026-01-02T03:04:05Z', data), 'elastic_agent'))
    # The normalizer can safely parse native true/false strings. Inject malformed
    # typed values only to exercise persisted AST input validation as well.
    if actual is not None:
        from romulus.evidence.typed import fv
        event.fields['image.signed'] = fv(actual, 'native:Signed')
    assert evaluate_ast(parsed['ast'], event) == (False, [])


@pytest.mark.parametrize('product', ['windows', 'linux', 'unsupported'])
def test_explicit_product_never_matches_an_observer_dns_record(product):
    parsed = parse_rule({'title': 'Synthetic product', 'logsource': {'product': product, 'category': 'dns'},
        'detection': {'s': {'QueryName': 'probe.example'}, 'condition': 's'}})
    observed = one(eve('dns', {'event_type': 'dns', 'dns': {'type': 'query', 'rrname': 'probe.example'}}))
    if product == 'unsupported':
        assert parsed['reasons']
    else:
        assert parsed['mapping']['os_families'] == [product]
        assert evaluate_ast(parsed['ast'], observed) == (False, [])


def test_explicit_windows_dns_keeps_its_supported_native_positive_and_benign():
    parsed = parse_rule({'title': 'Synthetic endpoint DNS', 'logsource': {'product': 'windows', 'category': 'dns'},
        'detection': {'s': {'QueryName': 'probe.example'}, 'condition': 's'}})
    assert not parsed['reasons']
    for name, expected in [('probe.example', True), ('benign.example', False)]:
        event = normalize_windows(windows_hit(LogicalWindowsEvent(SYSMON_CHANNEL, SYSMON, 22, 'ws01', 1,
            '2026-01-02T03:04:05Z', {'QueryName': name}), 'winlogbeat_8'))
        assert evaluate_ast(parsed['ast'], event)[0] is expected


def test_incomplete_command_line_is_unknown_but_an_intact_or_branch_survives():
    from tests.test_sigma_parser import MAPPING, event, rule
    observed = event(process__argv_complete=False, process__command_line='partial', process__executable='evil.exe')
    for condition, expected in [('not text', False), ('image or not text', True)]:
        parsed = parse_rule(rule({'text': {'CommandLine|contains': 'missing'}, 'image': {'Image': 'evil.exe'},
                                  'condition': condition}), MAPPING)
        assert not parsed['reasons']
        assert evaluate_ast(parsed['ast'], observed)[0] is expected


@pytest.mark.parametrize('source', [{'product': 'linux', 'category': 'process_creation'},
                                  {'product': 'linux', 'service': 'auditd'}])
@pytest.mark.parametrize('field,value', [('type', 'EXECVE'), ('syscall', 'execve'), ('key', 'probe')])
def test_group_fields_not_preserved_on_exec_are_wholly_reference_only(source, field, value):
    parsed = parse_rule({'title': 'Synthetic grouped source', 'logsource': source,
        'detection': {'supported': {'Image': '/usr/bin/dash'}, 'unsupported': {field: value},
                      'condition': 'supported or unsupported'}})
    assert parsed['ast'] == {} and any(field in reason for reason in parsed['reasons'])


def test_incomplete_argv_does_not_hide_intact_executable_predicate():
    parsed = parse_rule({'title': 'Synthetic intact image',
        'logsource': {'product': 'linux', 'category': 'process_creation'},
        'detection': {'s': {'Image': '/usr/bin/dash'}, 'condition': 's'}})
    events, _skips, errors = normalize_hits([hit('exec', 'linux.audit', EXECVE_HEX.replace('a1="-c" ', '')),
                                            hit('sys', 'linux.audit', SYSCALL)])
    assert errors and events[0].get('process.argv_complete') is False
    assert evaluate_ast(parsed['ast'], events[0])[0]
    metadata = dict(row(), ast=parsed['ast'], mapping=parsed['mapping'])
    owner = SigmaRule(metadata)
    [match] = list(owner.consume(events))
    assert 'incomplete' in match.claim
    assert any('argument' in note for note in owner.limit_reasons())
    assert any(field.field == 'process.executable' for field in match.predicate)
