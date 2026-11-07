"""Native normalizer records prove Sigma field and absence inventories."""
import pytest

from romulus.content import sigma_mapping
from romulus.content.sigma_parser import evaluate_ast_detail, parse_rule
from romulus.evidence.normalize import normalize_hits
from romulus.evidence.windows_catalog import (
    EVENTLOG,
    POWERSHELL_PROVIDER,
    SECURITY,
    SYSMON,
    SYSMON_CHANNEL,
    lookup_event_class,
)
from tests.fixtures import zeek_logs
from tests.test_auth_tamper_normalize import ADD_USER
from tests.test_evidence import SYSCALL, hit
from tests.test_network_normalizers import arkime, eve, one
from tests.test_zeek_windows_protocols import normalize
from tests.windows_fixtures import LogicalWindowsEvent, all_logical_events, windows_hit


def compiled(logsource, selection, *, negated=False):
    result = parse_rule({'logsource': logsource,
        'detection': {'selection': selection, 'condition': 'not selection' if negated else 'selection'}})
    assert result['reasons'] == []
    return result['ast']


@pytest.mark.parametrize('shape', ['winlogbeat_8', 'elastic_agent'])
@pytest.mark.parametrize('legacy', [False, True])
def test_generic_dns_inventory_includes_endpoint_and_observer_queries(shape, legacy):
    ast = compiled({'category': 'dns'}, {'query|endswith': '.example.test'})
    if legacy:
        del ast['scope']['field_inventory']
    native = LogicalWindowsEvent(SYSMON_CHANNEL, SYSMON, 22, 'ws01', 1,
        '2026-01-02T03:04:05Z', {'QueryName': 'probe.example.test'})
    endpoint = one(windows_hit(native, shape))
    observer = normalize(zeek_logs.WRITERS['elastic'](zeek_logs.DNS, 'dns-query'))
    for event in (endpoint, observer):
        assert evaluate_ast_detail(ast, event) == (True, ['dns.question.name'], [])
        assert evaluate_ast_detail(compiled({'category': 'dns'}, {'query': 'benign.example'}), event) == (
            False, [], [])


def test_generic_firewall_inventory_keeps_sysmon_destination_hostname():
    ast = compiled({'category': 'firewall'}, {'DestinationHostname': 'probe.example.test'})
    native = LogicalWindowsEvent(SYSMON_CHANNEL, SYSMON, 3, 'ws01', 1,
        '2026-01-02T03:04:05Z', {'DestinationHostname': 'probe.example.test'})
    assert evaluate_ast_detail(ast, one(windows_hit(native, 'elastic_agent'))) == (
        True, ['destination.hostname'], [])


def test_legacy_dns_inventory_recognizes_delivered_query_without_rewriting_ast():
    ast = compiled({'category': 'dns'}, {'query': 'probe.example.test'})
    native = LogicalWindowsEvent(SYSMON_CHANNEL, SYSMON, 22, 'ws01', 1,
        '2026-01-02T03:04:05Z', {'QueryName': 'probe.example.test'})
    for row in ast['scope']['field_inventory']:
        if row.get('family') == 'dns_lookup':
            row['fields'] = []
            row['absence_fields'] = []
    from romulus.content.sigma_parser import ast_digest
    digest = ast_digest(ast)
    assert evaluate_ast_detail(ast, one(windows_hit(native, 'elastic_agent'))) == (
        True, ['dns.question.name'], [])
    assert ast_digest(ast) == digest


@pytest.mark.parametrize('missing_inventory', [False, True])
def test_legacy_security_inventory_recognizes_delivered_account_without_rewriting_ast(missing_inventory):
    ast = compiled({'product': 'windows', 'service': 'security'}, {'TargetUserName': 'target'})
    for row in ast['scope']['field_inventory']:
        if row['event_class'] == ['Security', SECURITY, 4688]:
            row['fields'] = []
            row['absence_fields'] = []
    if missing_inventory:
        del ast['scope']['field_inventory']
    native = LogicalWindowsEvent('Security', SECURITY, 4688, 'ws01', 1,
        '2026-01-02T03:04:05Z', {'TargetUserName': 'target'})
    from romulus.content.sigma_parser import ast_digest
    digest = ast_digest(ast)
    assert evaluate_ast_detail(ast, one(windows_hit(native, 'elastic_agent'))) == (
        True, ['account.name'], [])
    assert ast_digest(ast) == digest


@pytest.mark.parametrize('field,typed', [
    ('OriginalFileName', 'process.original_file_name'), ('ParentImage', 'process.parent.executable')])
def test_legacy_security_inventory_cannot_invent_unobservable_absence(field, typed):
    ast = compiled({'product': 'windows', 'category': 'process_creation'}, {field: None})
    for row in ast['scope']['field_inventory']:
        if row['event_class'] == ['Security', SECURITY, 4688]:
            row['fields'] = [typed]
            row['absence_fields'] = [typed]
    native = LogicalWindowsEvent('Security', SECURITY, 4688, 'ws01', 1,
        '2026-01-02T03:04:05Z', {'NewProcessName': r'C:\Tools\probe.exe'})
    assert evaluate_ast_detail(ast, one(windows_hit(native, 'elastic_agent'))) == (
        False, [], ['typed_field_unavailable_for_event_class: '+typed])


@pytest.mark.parametrize('category,record', [
    ('proxy', eve('http', {'event_type': 'http', 'http': {
        'hostname': 'probe.example.test', 'url': '/probe', 'http_method': 'GET',
        'http_user_agent': 'ProbeAgent', 'status': 200}})),
    ('firewall', windows_hit(LogicalWindowsEvent(SYSMON_CHANNEL, SYSMON, 3, 'ws01', 1,
        '2026-01-02T03:04:05Z', {'SourceIp': '192.0.2.1', 'SourcePort': '50100',
        'SourceHostname': 'source.example.test', 'DestinationIp': '192.0.2.2', 'DestinationPort': '443',
        'DestinationHostname': 'destination.example.test', 'Protocol': 'tcp'}), 'elastic_agent'))])
def test_generic_inventory_contains_every_mapped_target_delivered_by_network_fixture(category, record):
    event = one(record)
    mapped = sigma_mapping.map_rule({'category': category}, {})
    fields = sigma_mapping._fields('*', category, '', mapped['families'])
    mapped = sigma_mapping.map_rule({'category': category}, {'selection': {name: 'probe' for name in fields}})
    inventory = next(row for row in mapped['field_inventory'] if row.get('family') == event.family)
    targets = sigma_mapping._targets(mapped['fields']) & event.fields.keys()
    assert targets <= set(inventory['fields']), targets - set(inventory['fields'])


@pytest.mark.parametrize('row', sigma_mapping.LOGSOURCE_TABLE,
                         ids=lambda row: f'{row.product}-{row.key}-{row.value}')
def test_every_logsource_row_has_explicit_class_or_family_field_and_absence_inventory(row):
    source = {row.key: row.value, **({'product': row.product} if row.product != '*' else {})}
    mapped = sigma_mapping.map_rule(source, {})
    assert mapped['reasons'] == []
    if row.product == 'windows':
        assert {tuple(entry['event_class']) for entry in mapped['field_inventory']} == {
            tuple(event_class) for event_class in mapped['windows_event_classes']}
    else:
        assert {entry['family'] for entry in mapped['field_inventory']} == set(row.families)
    for entry in mapped['field_inventory']:
        if 'family' in entry:
            assert entry['family'] in sigma_mapping._FAMILY_FIELDS
        assert 'absence_fields' in entry
        assert set(entry['absence_fields']) <= set(entry['fields'])


def test_missing_family_inventory_is_a_configuration_error(monkeypatch):
    monkeypatch.setattr(sigma_mapping, '_FAMILY_FIELDS',
                        {key: value for key, value in sigma_mapping._FAMILY_FIELDS.items()
                         if key != 'dns_lookup'})
    with pytest.raises(RuntimeError, match='dns_lookup'):
        sigma_mapping._validate_family_inventory()


_AUDIT_HEADER = 'pid=7001 uid=0 auid=1000 ses=12'
_AUDIT_MESSAGE = 'comm="systemd" exe="/usr/lib/systemd/systemd" hostname=? addr=? terminal=? res=success'
_AUDIT_SYSCALL = SYSCALL.replace('1731950250.320:76806', '1893920400.600:5006')
AUDIT_FIXTURES = [
    ('auth', [('type=USER_LOGIN msg=audit(1893920400.120:5001): '
               f'{_AUDIT_HEADER} acct="alice" exe="/usr/sbin/sshd" addr=203.0.113.8 res=success')],
     'pid', 7001),
    ('account_change', [ADD_USER], 'exe', '/usr/sbin/useradd'),
    ('service_change', [(f"type=SERVICE_STOP msg=audit(1893920400.120:5001): {_AUDIT_HEADER} "
                        f"msg='unit=auditd {_AUDIT_MESSAGE}'")], 'exe', '/usr/lib/systemd/systemd'),
    ('system_state', [(f"type=SYSTEM_BOOT msg=audit(1893920400.120:5001): {_AUDIT_HEADER} "
                     f"msg='{_AUDIT_MESSAGE}'")], 'exe', '/usr/lib/systemd/systemd'),
    ('audit_config', [('type=CONFIG_CHANGE msg=audit(1893920400.600:5006): auid=1000 ses=12 '
                      'op=remove_rule key="exec" list=4 res=1'), _AUDIT_SYSCALL], 'exe', '/usr/bin/dash'),
    ('net_socket', [_AUDIT_SYSCALL.replace('syscall=59', 'syscall=42').replace('SYSCALL=execve', 'SYSCALL=connect'),
                    'type=SOCKADDR msg=audit(1893920400.600:5006): saddr=020001BBC000020A0000000000000000'],
     'exe', '/usr/bin/dash'),
]


@pytest.mark.parametrize('family,records,field,value', AUDIT_FIXTURES, ids=[row[0] for row in AUDIT_FIXTURES])
def test_audit_family_inventory_preserves_delivered_mapped_process_fields(family, records, field, value):
    events, skips, errors = normalize_hits([hit(f'audit-{index}', 'linux.audit', raw)
                                          for index, raw in enumerate(records)])
    assert errors == [] and skips == {} and len(events) == 1
    event = events[0]
    assert event.family == family
    source = {'product': 'linux', 'service': 'auditd'}
    mapping = sigma_mapping.map_rule(source, {'selection': {
        name: 'probe' for name in sigma_mapping._LINUX}})
    inventory = next(row for row in mapping['field_inventory'] if row['family'] == family)
    delivered = sigma_mapping._targets(mapping['fields']) & event.fields.keys()
    assert delivered <= set(inventory['fields']), delivered - set(inventory['fields'])
    target = sigma_mapping._LINUX[field]
    assert event.get(target) == value
    assert evaluate_ast_detail(compiled(source, {field: value}), event) == (True, [target], [])
    benign = value+1 if isinstance(value, int) else 'benign-executable'
    assert evaluate_ast_detail(compiled(source, {field: benign}), event) == (False, [], [])


WINDOWS_NATIVE_FIXTURES = [
    ('Security', SECURITY, 4688, {'NewProcessName': r'C:\Tools\probe.exe',
        'SubjectUserName': 'actor', 'SubjectDomainName': 'example',
        'TargetUserName': 'target', 'TargetDomainName': 'example'}),
    *[('Security', SECURITY, code, {'TargetUserName': 'target', 'TargetDomainName': 'example'})
      for code in (4634, 4647, 4778, 4779)],
    *[('Security', SECURITY, code, {'SubjectUserName': 'actor', 'SubjectDomainName': 'example',
                                   'IpAddress': '192.0.2.10', 'IpPort': '50100'})
      for code in (5140, 5145)],
    *[('Security', SECURITY, code, {'SubjectUserName': 'actor', 'SubjectDomainName': 'example',
                                   'ProcessName': r'C:\Tools\probe.exe', 'ProcessId': '42'})
      for code in (4656, 4663, 4670)],
    ('System', 'Service Control Manager', 7036, {'param1': 'ProbeService', 'param2': 'running'}),
    *[(SYSMON_CHANNEL, SYSMON, code, {'ImageLoaded': r'C:\Tools\probe.dll',
        **({'OriginalFileName': 'probe.dll'} if code == 7 else {}), 'Hashes': 'MD5='+'ab'*16+',SHA1='+'cd'*20+
        ',SHA256='+'ef'*32+',IMPHASH='+'12'*16}) for code in (6, 7)],
]


@pytest.mark.parametrize('shape', ['winlogbeat_8', 'elastic_agent'])
@pytest.mark.parametrize('channel,provider,code,data', WINDOWS_NATIVE_FIXTURES,
                         ids=[f'{row[1]}-{row[2]}' for row in WINDOWS_NATIVE_FIXTURES])
def test_windows_inventory_contains_every_mapped_target_delivered_by_native_fixture(
        shape, channel, provider, code, data):
    source = {'product': 'windows', 'service': {
        'Security': 'security', 'System': 'system', SYSMON_CHANNEL: 'sysmon'}[channel]}
    native = LogicalWindowsEvent(channel, provider, code, 'ws01', 1, '2026-01-02T03:04:05Z', data)
    event = one(windows_hit(native, shape))
    event_class = lookup_event_class(channel, provider, code)
    fields = sigma_mapping._fields('windows', '', source['service'],
                                  sigma_mapping.map_rule(source, {})['families'])
    targets = sigma_mapping._targets(fields) & event.fields.keys()
    inventory = sigma_mapping._windows_fields(event_class)
    assert targets <= inventory, targets - inventory
    for name, target in fields.items():
        alternatives = target if isinstance(target, list) else [] if isinstance(target, dict) else [target]
        for typed in alternatives:
            if typed in targets:
                assert evaluate_ast_detail(compiled(source, {name: event.get(typed)}), event) == (
                    True, [typed], [])
                value = event.get(typed)
                benign = value+1 if isinstance(value, int) else 'benign-native-value'
                assert evaluate_ast_detail(compiled(source, {name: benign}), event) == (False, [], [])
    if 'Hashes' in data:
        for algorithm, digest in (('MD5', 'ab'*16), ('SHA1', 'cd'*20), ('SHA256', 'ef'*32), ('IMPHASH', '12'*16)):
            assert evaluate_ast_detail(compiled(source, {'Hashes': algorithm+'='+digest}), event) == (
                True, ['file.hash.'+algorithm.lower()], [])
            assert evaluate_ast_detail(compiled(source, {'Hashes': algorithm+'='+'0'*len(digest)}), event) == (
                False, [], [])


@pytest.mark.parametrize('code,data,selector,typed,value', [
    (4703, {'ProcessName': r'C:\Tools\probe.exe', 'ProcessId': '42'},
     'Image', 'process.executable', r'C:\Tools\probe.exe'),
    (4661, {'ProcessName': r'C:\Tools\probe.exe', 'ProcessId': '42'},
     'Image', 'process.executable', r'C:\Tools\probe.exe'),
    (4719, {'SubjectUserName': 'actor'}, 'SubjectUserName', 'user.name', 'actor'),
    (4799, {'TargetUserName': 'Administrators'}, 'TargetUserName', 'account.name', 'administrators'),
    (4778, {'ClientAddress': '192.0.2.10'}, 'IpAddress', 'source.ip', '192.0.2.10')])
@pytest.mark.parametrize('shape', ['winlogbeat_8', 'elastic_agent'])
def test_security_service_inventory_preserves_native_mapped_targets(code, data, selector, typed, value, shape):
    native = LogicalWindowsEvent('Security', SECURITY, code, 'ws01', 1, '2026-01-02T03:04:05Z', data)
    event = one(windows_hit(native, shape))
    assert event.get(typed) == value
    source = {'product': 'windows', 'service': 'security'}
    assert evaluate_ast_detail(compiled(source, {'EventID': code, selector: value}), event) == (
        True, sorted(['event.code', typed]), [])
    assert evaluate_ast_detail(compiled(source, {'EventID': code, selector: 'benign-native-value'}), event) == (
        False, [], [])


# The shared logon fixture supplies fields from several different native schemas.
# Only those absent from that particular native class are exempt from this check.
_NATIVE_SHARED_HELPER_EXTRAS = {
    **{(SECURITY, code): {'auth.service_name'} for code in (4624, 4625)},
    (SECURITY, 4648): {'auth.logon_type', 'auth.service_name', 'source.hostname'},
    (SECURITY, 4672): {'account.domain', 'account.name', 'auth.logon_type', 'auth.service_name',
                       'source.hostname', 'source.ip', 'source.port'},
    (SECURITY, 4634): {'auth.service_name', 'source.hostname', 'source.ip', 'source.port'},
    (SECURITY, 4647): {'auth.logon_type', 'auth.service_name', 'source.hostname', 'source.ip', 'source.port'},
    **{(SECURITY, code): {'auth.logon_type', 'source.hostname'} for code in (4768, 4769, 4770, 4771)},
    (SECURITY, 4776): {'auth.logon_type', 'auth.service_name', 'source.ip', 'source.port'},
    **{(SECURITY, code): {'auth.logon_type', 'auth.service_name', 'source.port'} for code in (4778, 4779)},
    (SECURITY, 4964): {'auth.logon_type', 'auth.service_name', 'source.hostname', 'source.ip', 'source.port'},
    (SECURITY, 4688): {'process.original_file_name'},
    # File fixture helpers share Contents and hashes, but only stream creation
    # carries Contents, and file creation/time changes carry no hashes.
    **{(SYSMON, code): {'file.hash.md5', 'file.hash.sha1', 'file.hash.sha256', 'file.hash.imphash',
                        'file.stream.content'} for code in (2, 11)},
    **{(SYSMON, code): {'file.stream.content'} for code in (23, 26, 29)},
    # Driver-load fixtures reuse owning-process data from image-load fixtures.
    (SYSMON, 6): {'process.executable', 'process.pid', 'process.guid', 'process.user',
                  'process.original_file_name', 'image.original_file_name'},
    # Registry add/delete/rename fixtures reuse the Details of a value-set event.
    **{(SYSMON, code): {'registry.value'} for code in (12, 14)},
    # Only log-cleared 1102 carries a subject; the provider's other fixtures reuse it.
    **{(EVENTLOG, code): {'user.name', 'user.domain'} for code in (1100, 1104, 1108)},
    # A start-type change does not record the configured service account.
    ('Service Control Manager', 7040): {'service.account'},
    # Module-logging fixtures reuse the script-block ID/path of script-block logging.
    (POWERSHELL_PROVIDER, 4103): {'script.block_id', 'script.path'},
    # NETLOGON param1 names a machine account, never a service.
    **{('NETLOGON', code): {'service.name'} for code in (5805, 5723)},
}


@pytest.mark.parametrize('shape', ['winlogbeat_8', 'elastic_agent'])
def test_all_supported_native_catalogue_fixtures_declare_every_delivered_mapped_target(shape):
    sources = []
    supported = set()
    for row in sigma_mapping.LOGSOURCE_TABLE:
        if row.product != 'windows':
            continue
        source = {'product': 'windows', row.key: row.value}
        mapping = sigma_mapping.map_rule(source, {})
        classes = {tuple(item) for item in mapping['windows_event_classes']}
        fields = sigma_mapping._fields('windows', mapping['category'], source.get('service', ''),
                                      mapping['families'])
        sources.append((source, classes, sigma_mapping._targets(fields)))
        supported.update(classes)
    natives = all_logical_events()
    assert supported <= {(native.channel, native.provider, native.event_id) for native in natives}
    gaps = []
    for native in natives:
        key = (native.channel, native.provider, native.event_id)
        applicable = [(source, targets) for source, classes, targets in sources if key in classes]
        if not applicable:
            continue
        event = one(windows_hit(native, shape))
        declared = sigma_mapping._windows_fields(lookup_event_class(*key))
        extras = _NATIVE_SHARED_HELPER_EXTRAS.get((native.provider, native.event_id), set())
        assert extras.isdisjoint(declared), (key, extras & declared)
        for source, targets in applicable:
            missing = (targets & event.fields.keys()) - declared - extras
            if missing:
                gaps.append(f'{native.provider}/{native.event_id} {source}: {sorted(missing)}')
    assert not gaps, '\n'.join(gaps)


@pytest.mark.parametrize('protocol', ['smb', 'tls'])
@pytest.mark.parametrize('selection,negated', [
    ({'c-useragent': None}, False), ({'c-useragent|exists': False}, False),
    ({'c-useragent|exists': True}, True)])
@pytest.mark.parametrize('legacy', ['current', 'missing_absence', 'overbroad_absence'])
def test_session_http_absence_never_matches_other_protocols(protocol, selection, negated, legacy):
    ast = compiled({'category': 'proxy'}, selection, negated=negated)
    if legacy != 'current':
        for row in ast['scope']['field_inventory']:
            if legacy == 'missing_absence':
                row.pop('absence_fields', None)
            else:
                row['absence_fields'] = row['fields']
    event = one(arkime(protocol=['tcp', protocol]))
    assert evaluate_ast_detail(ast, event) == (
        False, [], ['typed_field_unavailable_for_event_class: user_agent.original'])


@pytest.mark.parametrize('protocol', ['smb', 'tls'])
@pytest.mark.parametrize('absence', ['null', 'missing', 'not_present'])
def test_legacy_proxy_without_inventory_cannot_publish_http_absence_from_session(protocol, absence):
    from romulus.content.sigma_parser import ast_digest
    from romulus.detect.sigma import SigmaRule
    from romulus.hunt.publish import publish_match
    from tests.test_sigma_playbook import row
    from tests.test_sweep import _repo
    detection = {'selection': {'SourceIp|exists': True}, 'condition': 'selection'}
    if absence == 'not_present':
        detection.update(filter_presence={'c-useragent|exists': True},
                         condition='selection and not filter_presence')
    else:
        detection['selection']['c-useragent' if absence == 'null' else 'c-useragent|exists'] = (
            None if absence == 'null' else False)
    result = parse_rule({'logsource': {'category': 'proxy'}, 'detection': detection})
    assert result['reasons'] == []
    ast = result['ast']
    del ast['scope']['field_inventory']
    assert 'windows_event_classes' in ast['scope'] and 'scope' in ast['scope']
    digest = ast_digest(ast)
    record = arkime(protocol=['tcp', protocol])
    event = one(record)
    owner = SigmaRule(dict(row(), ast=ast, mapping=result['mapping'], digest=digest, lane='high',
                           activation_reason='Mission-approved predicate'))
    repo = _repo()
    try:
        published = [publish_match(repo, 'h1', owner, match, None,
            {record['_index']+'/'+record['_id']: record['_source']}) for match in owner.consume([event])]
        assert all(item['lane'] == 'high' for item in published)
        assert published == []
        assert evaluate_ast_detail(ast, event) == (
            False, [], ['typed_field_unavailable_for_event_class: user_agent.original'])
        assert ast_digest(ast) == digest
    finally:
        owner.close_spill()
        repo.engine.dispose()


def test_session_delivered_http_value_remains_searchable():
    ast = compiled({'category': 'proxy'}, {'c-useragent': 'ProbeAgent'})
    event = one(arkime(protocol=['tcp', 'http'], http={'useragent': ['ProbeAgent']}))
    assert event.get('user_agent.original') == ['ProbeAgent']
    assert evaluate_ast_detail(ast, event) == (True, ['user_agent.original'], [])


@pytest.mark.parametrize('selection,negated', [
    ({'c-useragent': None}, False), ({'c-useragent|exists': False}, False),
    ({'c-useragent|exists': True}, True)])
@pytest.mark.parametrize('legacy', [False, True])
def test_http_transaction_absence_is_supported_on_its_typed_class_fields(selection, negated, legacy):
    ast = compiled({'category': 'proxy'}, selection, negated=negated)
    if legacy:
        del ast['scope']['field_inventory']
    event = one(eve('http', {'event_type': 'http', 'http': {'http_method': 'GET', 'url': '/probe'}}))
    assert evaluate_ast_detail(ast, event) == (True, [], [])


def test_http_transaction_absence_never_invents_a_path_representation():
    ast = compiled({'category': 'proxy'}, {'cs-uri-stem': None})
    event = one(eve('http', {'event_type': 'http', 'http': {'http_method': 'GET', 'url': '/probe'}}))
    assert evaluate_ast_detail(ast, event) == (
        False, [], ['typed_field_unavailable_for_event_class: url.path'])


@pytest.mark.parametrize('selection,negated', [
    ({'c-useragent': None}, False), ({'c-useragent|exists': False}, False),
    ({'c-useragent|exists': True}, True)])
def test_access_log_http_field_absence_stays_unknown(selection, negated):
    ast = compiled({'category': 'proxy'}, selection, negated=negated)
    event = one({'_id': 'access', '_index': 'web', '_source': {
        '@timestamp': '2026-01-02T03:04:05Z', 'event': {'dataset': 'apache.access'},
        'http': {'request': {'method': 'GET'}}, 'url': {'original': '/probe'}}})
    assert event.family == 'http_access'
    assert evaluate_ast_detail(ast, event) == (
        False, [], ['typed_field_unavailable_for_event_class: user_agent.original'])


@pytest.mark.parametrize('protocol', ['smb', 'tls'])
def test_session_absence_contract_is_limited_to_endpoint_tuple(protocol):
    ast = compiled({'category': 'proxy'}, {
        'SourceIp': None, 'SourcePort': None, 'DestinationIp': None, 'DestinationPort': None, 'Protocol': None,
        'c-useragent': None, 'cs-host': None, 'cs-method': None, 'sc-status': None, 'c-uri': None})
    session_inventory = next(row for row in ast['scope']['field_inventory'] if row.get('family') == 'net_session')
    assert set(session_inventory['absence_fields']) == {
        'source.ip', 'source.port', 'destination.ip', 'destination.port', 'network.transport'}
    endpoint = compiled({'category': 'proxy'}, {'SourcePort|exists': False})
    record = arkime(protocol=['tcp', protocol])
    record['_source']['source'].pop('port')
    assert evaluate_ast_detail(endpoint, one(record)) == (True, [], [])


@pytest.mark.parametrize('shape', ['winlogbeat_8', 'elastic_agent'])
@pytest.mark.parametrize('code', [5142, 5143, 5144])
def test_share_change_actor_fields_are_available_to_security_rules(shape, code):
    native = LogicalWindowsEvent('Security', SECURITY, code, 'ws01', 1,
        '2026-01-02T03:04:05Z', {'SubjectUserName': 'share-admin', 'SubjectDomainName': 'EXAMPLE',
                               'ShareName': r'\\*\Inventory', 'ShareLocalPath': r'C:\Shares\Inventory'})
    event = one(windows_hit(native, shape))
    ast = compiled({'product': 'windows', 'service': 'security'},
                   {'SubjectUserName': 'share-admin', 'SubjectDomainName': 'EXAMPLE'})
    matched, fields, reasons = evaluate_ast_detail(ast, event)
    assert matched and set(fields) == {'user.name', 'user.domain'} and reasons == []
