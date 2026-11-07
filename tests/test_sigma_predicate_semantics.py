"""Native telemetry proves class-aware Sigma comparison and category semantics."""
import pytest

from romulus.content.sigma_parser import evaluate_ast, parse_rule
from romulus.evidence.windows_catalog import (
    LEGACY_POWERSHELL_CHANNEL,
    LEGACY_POWERSHELL_PROVIDER,
    POWERSHELL_CHANNEL,
    POWERSHELL_PROVIDER,
    SECURITY,
    SYSMON,
    SYSMON_CHANNEL,
)
from tests.test_network_normalizers import eve, one
from tests.windows_fixtures import LogicalWindowsEvent, windows_hit


def windows(code, data, *, security=False, shape='elastic_agent'):
    raw = LogicalWindowsEvent('Security' if security else SYSMON_CHANNEL,
        SECURITY if security else SYSMON, code, 'ws01', 1, '2026-01-02T03:04:05Z', data)
    return one(windows_hit(raw, shape))


def parsed(logsource, selection, filters=None):
    detection = {'selection': selection, **(filters or {}),
                 'condition': 'selection and not 1 of filter_*' if filters else 'selection'}
    result = parse_rule({'logsource': logsource, 'detection': detection})
    assert result['reasons'] == []
    return result


@pytest.mark.parametrize('shape', ['winlogbeat_8', 'elastic_agent'])
@pytest.mark.parametrize('image,matched', [(r'C:\Tools\probe.exe', True),
                                         (r'C:\Tools\chrome.exe', False)])
def test_sysmon_connection_negated_image_filter_ignores_untyped_alternative(shape, image, matched):
    rule = parsed({'product': 'windows', 'category': 'network_connection'},
        {'DestinationPort': 443}, {'filter_image': {'Image|endswith': r'\chrome.exe'}})
    event = windows(3, {'Image': image, 'DestinationPort': '443'}, shape=shape)
    assert 'wfp.application' not in event.fields
    assert evaluate_ast(rule['ast'], event)[0] is matched


@pytest.mark.parametrize('shape', ['winlogbeat_8', 'elastic_agent'])
@pytest.mark.parametrize('service,matched', [('MissionProbe', True), ('Benign', False)])
def test_security_service_negated_name_filter_ignores_untyped_auth_alternative(shape, service, matched):
    rule = parsed({'product': 'windows', 'service': 'security'}, {'EventID': 4697},
        {'filter_service': {'ServiceName': 'Benign'}})
    event = windows(4697, {'ServiceName': service}, security=True, shape=shape)
    assert 'auth.service_name' not in event.fields
    assert evaluate_ast(rule['ast'], event)[0] is matched


@pytest.mark.parametrize('uri,matched', [('/probe', True), ('/benign', False)])
def test_http_transaction_negated_uri_filter_ignores_absent_path_alternative(uri, matched):
    rule = parsed({'category': 'proxy'}, {'cs-method': 'POST'},
        {'filter_uri': {'c-uri|contains': '/benign'}})
    event = one(eve('http', {'event_type': 'http', 'http': {'http_method': 'POST',
                                                     'url': uri, 'hostname': 'example.test'}}))
    assert 'url.original' in event.fields and 'url.path' not in event.fields
    assert evaluate_ast(rule['ast'], event)[0] is matched


def test_alternative_null_comparison_does_not_invent_an_absent_second_value():
    rule = parsed({'category': 'proxy'}, {'cs-method': 'POST'}, {'filter_uri': {'c-uri': None}})
    event = one(eve('http', {'event_type': 'http', 'http': {'http_method': 'POST', 'url': '/probe'}}))
    assert evaluate_ast(rule['ast'], event)[0]


@pytest.mark.parametrize('field', ['OriginalFileName', 'ParentImage'])
@pytest.mark.parametrize('test', ['null', 'missing', 'not_present'])
def test_security_process_unobservable_absence_never_matches(field, test):
    selection = {'Image|endswith': r'\probe.exe'}
    if test == 'not_present':
        rule = parsed({'product': 'windows', 'category': 'process_creation'}, selection,
                      {'filter_presence': {field+'|exists': True}})
    else:
        selection[field if test == 'null' else field+'|exists'] = None if test == 'null' else False
        rule = parsed({'product': 'windows', 'category': 'process_creation'}, selection)
    event = windows(4688, {'NewProcessName': r'C:\Tools\probe.exe'}, security=True)
    assert not evaluate_ast(rule['ast'], event)[0]


@pytest.mark.parametrize('field', ['OriginalFileName', 'ParentImage'])
def test_legacy_ast_uses_native_class_inventory_when_no_inventory_was_stored(field):
    rule = parsed({'product': 'windows', 'category': 'process_creation'}, {field: None})
    del rule['ast']['scope']['field_inventory']
    event = windows(4688, {'NewProcessName': r'C:\Tools\probe.exe'}, security=True)
    assert not evaluate_ast(rule['ast'], event)[0]


def test_sysmon_process_absence_is_known_only_for_its_declared_native_fields():
    rule = parsed({'product': 'windows', 'category': 'process_creation'}, {'OriginalFileName': None})
    assert evaluate_ast(rule['ast'], windows(1, {'Image': r'C:\Tools\probe.exe'}))[0]
    broad = parsed({'product': 'windows', 'service': 'sysmon'}, {'OriginalFileName': None})
    assert not evaluate_ast(broad['ast'], windows(3, {'Image': r'C:\Tools\probe.exe'}))[0]


def test_security_unobservable_field_cannot_be_invented_by_an_extra_native_key():
    rule = parsed({'product': 'windows', 'category': 'process_creation'}, {'OriginalFileName': 'probe.exe'})
    event = windows(4688, {'NewProcessName': r'C:\Tools\probe.exe', 'OriginalFileName': 'probe.exe'}, security=True)
    assert not evaluate_ast(rule['ast'], event)[0]


def test_version_dependent_security_parent_image_is_usable_when_delivered():
    rule = parsed({'product': 'windows', 'category': 'process_creation'}, {'ParentImage|endswith': r'\probe.exe'})
    event = windows(4688, {'NewProcessName': r'C:\Tools\child.exe',
                          'ParentProcessName': r'C:\Tools\probe.exe'}, security=True)
    assert evaluate_ast(rule['ast'], event)[0]


def test_security_process_subject_identity_remains_an_explicit_actor_field():
    rule = parsed({'product': 'windows', 'service': 'security'},
                  {'EventID': 4688, 'SubjectUserName': 'analyst'})
    event = windows(4688, {'NewProcessName': r'C:\Tools\probe.exe', 'SubjectUserName': 'analyst'}, security=True)
    assert evaluate_ast(rule['ast'], event)[0]


def test_detailed_evaluation_exposes_unobservable_and_missing_comparisons():
    from romulus.content.sigma_parser import evaluate_ast_detail
    rule = parsed({'product': 'windows', 'category': 'process_creation'}, {'OriginalFileName': None})
    assert evaluate_ast_detail(rule['ast'], windows(4688, {}, security=True)) == (
        False, [], ['typed_field_unavailable_for_event_class: process.original_file_name'])
    rule = parsed({'product': 'windows', 'category': 'network_connection'}, {'DestinationPort': 443})
    assert evaluate_ast_detail(rule['ast'], windows(3, {})) == (
        False, [], ['missing_typed_value: destination.port'])


@pytest.mark.parametrize('channel,provider,code,field', [
    (LEGACY_POWERSHELL_CHANNEL, LEGACY_POWERSHELL_PROVIDER, 400, 'ScriptBlockId'),
    (LEGACY_POWERSHELL_CHANNEL, LEGACY_POWERSHELL_PROVIDER, 403, 'ScriptBlockText'),
    (POWERSHELL_CHANNEL, POWERSHELL_PROVIDER, 4104, 'HostApplication'),
    (POWERSHELL_CHANNEL, POWERSHELL_PROVIDER, 4103, 'ScriptBlockId')])
def test_powershell_absence_uses_native_class_instead_of_the_shared_script_family(channel, provider, code, field):
    rule = parsed({'product': 'windows', 'service': 'powershell'}, {field: None})
    raw = LogicalWindowsEvent(channel, provider, code, 'ws01', 1, '2026-01-02T03:04:05Z', {})
    assert not evaluate_ast(rule['ast'], one(windows_hit(raw, 'elastic_agent')))[0]


@pytest.mark.parametrize('code', [2, 11, 15, 23, 26, 29])
def test_file_event_category_matches_only_native_file_creation(code):
    rule = parsed({'product': 'windows', 'category': 'file_event'}, {'TargetFilename': r'C:\Probe\target'})
    event = windows(code, {'TargetFilename': r'C:\Probe\target'})
    assert evaluate_ast(rule['ast'], event)[0] is (code == 11)


@pytest.mark.parametrize('category,codes', [('file_delete', [23, 26]), ('file_change', [2]),
    ('create_stream_hash', [15]), ('file_executable_detected', [29])])
def test_specific_file_categories_use_their_native_actions(category, codes):
    rule = parsed({'product': 'windows', 'category': category}, {'TargetFilename': r'C:\Probe\target'})
    assert rule['mapping']['event_codes'] == [str(code) for code in codes]
    for code in [2, 11, 15, 23, 26, 29]:
        assert evaluate_ast(rule['ast'], windows(code, {'TargetFilename': r'C:\Probe\target'}))[0] is (code in codes)


@pytest.mark.parametrize('code', [17, 18])
def test_pipe_category_evaluates_native_creation_and_connection(code):
    rule = parsed({'product': 'windows', 'category': 'pipe_created'}, {'PipeName': r'\probe'})
    assert evaluate_ast(rule['ast'], windows(code, {'PipeName': r'\probe'}))[0]


@pytest.mark.parametrize('shape', ['winlogbeat_8', 'elastic_agent'])
def test_registry_security_native_hive_and_value_name_suppress_the_sysmon_filter(shape):
    rule = parsed({'product': 'windows', 'category': 'registry_set'},
        {'TargetObject|contains': '\\SOFTWARE\\Example\\'},
        {'filter_target': {'TargetObject|startswith': 'HKLM\\SOFTWARE\\Example\\'}})
    for code, security, data in [(13, False, {'TargetObject': r'HKLM\SOFTWARE\Example\Value'}),
        (4657, True, {'ObjectName': r'\REGISTRY\MACHINE\SOFTWARE\Example', 'ObjectValueName': 'Value'})]:
        assert not evaluate_ast(rule['ast'], windows(code, data, security=security, shape=shape))[0]
    positive = parsed({'product': 'windows', 'category': 'registry_set'},
                      {'TargetObject': r'HKLM\SOFTWARE\Example\Value'})
    assert evaluate_ast(positive['ast'], windows(4657,
        {'ObjectName': r'\REGISTRY\MACHINE\SOFTWARE\Example', 'ObjectValueName': 'Value'},
        security=True, shape=shape))[0]


def test_wfp_image_rules_exclude_device_paths_without_a_drive_mapping():
    rule = parsed({'product': 'windows', 'category': 'network_connection'}, {'DestinationPort': 443},
                  {'filter_image': {'Image|startswith': 'C:\\'}})
    exclusions = rule['mapping']['exclusions']
    assert any(item['event_class'][2] == 5156 and item['reason'] == 'wfp_image_device_path_unmapped'
               for item in exclusions)
    event = windows(5156, {'Application': r'\device\harddiskvolume2\Tools\probe.exe',
                          'DestPort': '443'}, security=True)
    assert not evaluate_ast(rule['ast'], event)[0]


@pytest.mark.parametrize('destination,matched', [('198.51.100.2', True), ('192.0.2.2', False)])
def test_wfp_native_endpoint_negated_filter_remains_runnable(destination, matched):
    rule = parsed({'product': 'windows', 'category': 'network_connection'}, {'DestinationPort': 443},
                  {'filter_ip': {'DestinationIp': '192.0.2.2'}})
    event = windows(5156, {'DestAddress': destination, 'DestPort': '443'}, security=True)
    assert evaluate_ast(rule['ast'], event)[0] is matched


def test_query_results_rules_name_irrecoverable_native_string_exclusion():
    result = parse_rule({'logsource': {'product': 'windows', 'category': 'dns_query'},
        'detection': {'selection': {'QueryName|endswith': '.example.test'},
                      'filter_answer': {'QueryResults|contains': ';::ffff:198.51.100.20;'},
                      'condition': 'selection and not filter_answer'}})
    assert result['mapping']['exclusions'] == [{'event_class': [SYSMON_CHANNEL, SYSMON, 22],
        'reason': 'query_results_native_string_unavailable', 'fields': ['QueryResults']}]
    assert any('query_results_native_string_unavailable' in reason for reason in result['reasons'])
    assert result['ast'] == {}
