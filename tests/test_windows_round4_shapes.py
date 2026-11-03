"""Synthetic native envelopes for saved declarations and real shipper shapes."""
import base64
from dataclasses import replace

import pytest
from starlette.datastructures import FormData

from romulus.detect.windows_memory_events import WritableUnsignedDllLoad
from romulus.detect.windows_proxy import (
    CompilerProxyExecution,
    MshtaExecution,
    PowerShellEncodedOrCradle,
    Regsvr32Execution,
    Rundll32Execution,
    ScriptHostRemoteOrWritable,
)
from romulus.detect.windows_registration_events import ScheduledTaskRegistration, ServiceRegistration
from romulus.evidence.windows_catalog import SYSMON, SYSMON_CHANNEL, TASK_CHANNEL, TASK_PROVIDER
from romulus.site import (
    COLLECTION_PATH,
    load_site_facts,
    save_site_facts,
    validate_site_content,
)
from romulus.web import site_form
from tests.test_windows_c_identity_review import REPLICATION, native
from tests.test_windows_script_rules import CASES
from tests.windows_fixtures import all_logical_events, windows_hit
from tests.windows_process_support import run


def process(image, command, **data):
    return native(1, {'Image': 'C:\\Windows\\System32\\' + image, 'CommandLine': command, **data},
                  channel=SYSMON_CHANNEL, provider=SYSMON)


def test_old_saved_empty_sync_list_remains_undeclared_until_checkbox_save(tmp_path):
    path = tmp_path / COLLECTION_PATH
    path.parent.mkdir(parents=True)
    path.write_text('schema: romulus-site-collection@1\ndomain_controllers: [dc01.example.test]\n'
                    'directory_sync_accounts: []\n', encoding='utf-8')
    facts = load_site_facts(tmp_path)
    assert 'directory_sync_accounts' not in facts.content
    assert site_form.view(facts.content)['directory_sync_accounts_declared'] is False
    from romulus.detect.windows_directory_events import DirectoryReplicationAccess
    rule = DirectoryReplicationAccess()
    rule.site_facts = facts
    hit = rule.consume([native(4662, REPLICATION)])[0]
    assert hit.proposed_lane == 'lead' and 'not configured' in ' '.join(hit.notes)
    content = site_form.parse_form(FormData([('group_count', '0'), ('domain_controllers', 'dc01.example.test'),
                                            ('directory_sync_accounts_declared', '1')]))
    assert validate_site_content(content).content['directory_sync_accounts_declared'] is True
    save_site_facts(tmp_path, content, facts.digest)
    saved = load_site_facts(tmp_path)
    assert saved.content['directory_sync_accounts'] == []
    assert saved.content['directory_sync_accounts_declared'] is True
    assert site_form.view(saved.content)['directory_sync_accounts_declared'] is True


def test_legacy_pipeline_text_is_partial_and_bindings_are_separate():
    event = native(800, {'param1': "Write-Output 'example pipeline'", 'param2': 'HostApplication=powershell.exe\nUserId=EXAMPLE\\analyst',
                         'param3': 'CommandInvocation(Write-Output): "Write-Output"'},
                   channel='Windows PowerShell', provider='PowerShell')
    assert event.get('script.text') == "Write-Output 'example pipeline'"
    assert event.get('script.module_payload').startswith('CommandInvocation')
    assert event.get('script.host_application') == 'powershell.exe'
    assert event.get('script.context')['UserId'] == 'EXAMPLE\\analyst'
    assert event.get('script.complete') is False and event.get('script.view') == 'single'


@pytest.mark.parametrize('code', [23, 26, 29])
@pytest.mark.parametrize('hash_fields', [{'Hash': 'SHA256=ABC123,MD5=DEF456'},
                                        {'Hashes.SHA256': 'ABC123', 'Hashes.MD5': 'DEF456'}])
def test_native_pe_evidence_and_file_hashes_are_typed(code, hash_fields):
    event = native(code, {'TargetFilename': r'C:\Users\Public\sample.dat', 'IsExecutable': 'true',
                          **hash_fields}, channel=SYSMON_CHANNEL, provider=SYSMON)
    assert event.get('file.is_executable') is True
    assert event.get('file.hashes') == {'sha256': 'abc123', 'md5': 'def456'}
    assert event.fields['file.hashes'].origin.count('#parsed:sysmon-hashes') == 1


@pytest.mark.parametrize('prefix', ['C:', 'D:', r'\Device\HarddiskVolume3', r'\\?\D:',
                                     r'\??\D:', r'\\?\Volume{11111111-2222-3333-4444-555555555555}'])
@pytest.mark.parametrize('directory', [r'Windows\System32\spool\drivers\color', 'ProgramData', 'PerfLogs'])
def test_positive_writable_windows_directory_never_lowers_attention_on_other_volumes(prefix, directory):
    event = native(7, {'Image': r'C:\Windows\System32\host.exe',
        'ImageLoaded': prefix + '\\' + directory + r'\component.dll',
        'Signed': 'false', 'SignatureStatus': 'Unavailable'}, channel=SYSMON_CHANNEL, provider=SYSMON)
    [hit] = WritableUnsignedDllLoad().judge(event)
    assert hit.lane == 'high'


@pytest.mark.parametrize('kind,codes,rights', [('Process', '%%4481 %%4484 %%4486', ['create_thread', 'vm_read', 'dup_handle']),
                                            ('Key', '%%4432 %%4433 %%4435', ['query_value', 'set_value', 'enumerate_sub_keys'])])
def test_access_messages_use_object_type_table(kind, codes, rights):
    event = native(4656, {'ObjectType': kind, 'AccessList': codes})
    assert event.get('object.accesses') == rights
    assert not any('unknown Windows message' in text for text in event.caveats)


@pytest.mark.parametrize('image,command,rule', [
    ('cscript.exe', 'cscript.exe //e:jscript report.js', ScriptHostRemoteOrWritable),
    ('wscript.exe', 'wscript.exe .\\report.vbs', ScriptHostRemoteOrWritable),
    ('rundll32.exe', 'rundll32.exe .\\report.dll,Entry', Rundll32Execution),
    ('regsvr32.exe', 'regsvr32.exe /s report.dll', Regsvr32Execution),
    ('mshta.exe', 'mshta.exe report.hta', MshtaExecution),
    ('msxsl.exe', 'msxsl.exe report.xml style.xsl', CompilerProxyExecution),
])
def test_relative_proxy_operand_is_placed_with_native_current_directory(image, command, rule):
    event = process(image, command, CurrentDirectory='C:\\Users\\analyst\\Desktop\\')
    if rule is Regsvr32Execution:
        assert not run(rule(), [event])  # Bare libraries use DLL search order, not the CWD.
        return
    [hit] = rule().judge(event)
    assert 'placed using the recorded working directory' in hit.text
    assert 'Desktop' in hit.text
    assert any(p.field == 'process.current_directory' for p in hit.predicate)
    assert set(hit.attack) <= set(rule.attack)


def test_script_host_remote_url_claim_names_url():
    [hit] = ScriptHostRemoteOrWritable().judge(process('cscript.exe', 'cscript.exe https://example.test/report.js'))
    assert 'remote URL' in hit.text and 'user-writable' not in hit.text


@pytest.mark.parametrize('parent,lane', [(r'C:\Windows\System32\cmd.exe', 'lead'),
                                       (r'C:\Program Files\Java\bin\java.exe', 'lead'),
                                       (r'C:\Program Files\Office\WINWORD.EXE', 'high'),
                                       (r'C:\Windows\System32\inetsrv\w3wp.exe', 'high')])
def test_encoded_only_process_lane_uses_parent_evidence(parent, lane):
    encoded = base64.b64encode('Get-Date'.encode('utf-16le')).decode()
    events = [process('powershell.exe', 'powershell.exe -enc ' + encoded, ParentImage=parent) for _ in range(3)]
    matches = run(PowerShellEncodedOrCradle(), events)
    assert all(match.proposed_lane == lane for match in matches)
    assert any(match.group_key for match in matches)
    if lane == 'high':
        assert all('recorded parent image' in match.claim for match in matches)


@pytest.mark.parametrize('source', [text for name, text in CASES if name in {
    'download', 'offensive_function', 'amsi_bypass'}])
def test_encoded_process_high_requires_observed_strong_script_shape(source):
    encoded = base64.b64encode(source.encode('utf-16le')).decode()
    matches = run(PowerShellEncodedOrCradle(), [process('powershell.exe', 'powershell.exe -enc ' + encoded) for _ in range(3)])
    assert all(match.proposed_lane == 'high' for match in matches)
    assert any(match.group_key for match in matches)


def test_undecodable_encoded_process_is_still_a_reported_lead():
    matches = run(PowerShellEncodedOrCradle(), [process('powershell.exe', 'powershell.exe -enc !invalid') for _ in range(3)])
    assert all(match.proposed_lane == 'lead' and 'could not be decoded' in match.claim for match in matches)
    assert any(match.group_key for match in matches)


def test_bare_service_image_is_lead_with_no_directory_claim():
    [hit] = ServiceRegistration().judge(native(7045, {'ServiceName': 'example', 'ImagePath': 'calc.exe',
                                                     'ServiceType': 'user mode service'}, channel='System',
                                             provider='Service Control Manager'))
    assert hit.lane == 'lead' and 'no directory recorded' in hit.text and 'outside standard' not in hit.text


def test_relative_driver_service_uses_systemroot_scope():
    [hit] = ServiceRegistration().judge(native(7045, {'ServiceName': 'example',
                    'ImagePath': r'System32\drivers\example.sys', 'ServiceType': 'kernel mode driver'},
                    channel='System', provider='Service Control Manager'))
    assert hit.lane == 'lead' and 'SystemRoot' in hit.text


def test_com_handler_registration_folds_fleet_by_clsid():
    rule = ScheduledTaskRegistration()
    events = []
    for ordinal in range(30):
        events.append(native(200, {'TaskName': '\\Example',
            'ActionName': '{47E30D54-DAC1-473A-AFF7-2355BF78881F}'}, host=f'ws{ordinal:02}',
            record=ordinal+800000, offset=ordinal, channel=TASK_CHANNEL, provider=TASK_PROVIDER))
    matches = run(rule, events)
    assert len({match.group_key for match in matches}) == 1
    assert matches[-1].group_key
    assert 'ws29' in {event.host for event in matches[-1].events}
    assert len(matches[-1].events) == 21  # First record of the first 20 hosts, plus the latest boundary.
    assert '21 of the 30 records are cited' in matches[-1].claim
    assert len(dict(matches[-1].fleet_hosts)) == 30


def test_winlogbeat8_fixture_has_native_envelope_and_old_sysmon_variant():
    event = next(e for e in all_logical_events() if e.provider == SYSMON and e.event_id == 10)
    event = replace(event, data={**event.data, 'StartModule': '', 'OriginalFileName': 'example.exe',
                                 'Hashes': 'SHA256=ABCDEF', 'TargetObject': r'HKCU\Software\Example\(Default)'})
    hit = windows_hit(event, 'winlogbeat_8', old_sysmon=True)
    winlog = hit['_source']['winlog']
    assert winlog['event_id'] == '10' and hit['_source']['event']['code'] == '10'
    assert 'time_created' not in winlog
    assert winlog['user']['identifier'] == 'S-1-5-18'
    data = winlog['event_data']
    assert 'SourceProcessGUID' in data and 'StartModule' not in data and 'OriginalFileName' not in data
    assert data['Hash'] == 'SHA256=ABCDEF' and data['TargetObject'].endswith('{Default}')
