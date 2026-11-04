"""Synthetic native envelopes for source-shape, action and code-publication regressions."""
import pytest

from romulus.detect.windows_endpoint_events import RemoteManagementPipe
from romulus.detect.windows_file_events import (
    ExecutableAlternateStream,
    ExecutableCreationTimeChange,
    LureApplicationFileWrite,
    StartupFileWrite,
    WebRootFileWrite,
    WritableExecutableDeletion,
)
from romulus.detect.windows_memory_events import (
    LsassProcessAccess,
    ProcessImageTampering,
    RemoteThreadCreation,
    WritableUnsignedDllLoad,
)
from romulus.detect.windows_registration_events import ScheduledTaskRegistration, ServiceRegistration
from romulus.detect.windows_registry_events import RegistryDefender, RegistryServiceCommand, RegistryUserCom
from romulus.evidence.windows import normalize_windows
from romulus.evidence.windows_catalog import SECURITY, TASK_CHANNEL, TASK_PROVIDER
from tests.test_windows_b_round3 import _IDS, fold
from tests.test_windows_b_round3 import native as _native
from tests.windows_fixtures import LogicalWindowsEvent, windows_hit


def native(code, data, host='ws01'):
    if code in {4656, 4663, 7045, 200}:
        channel, provider = ('System', 'Service Control Manager') if code == 7045 else (
            (TASK_CHANNEL, TASK_PROVIDER) if code == 200 else ('Security', SECURITY))
        return normalize_windows(windows_hit(LogicalWindowsEvent(channel, provider, code, host,
            next(_IDS), '2026-01-02T03:00:00Z', data), 'winlogbeat_8'))
    return _native(code, data, host)


@pytest.mark.parametrize('source', [r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
                                   r'C:\Windows\System32\inetsrv\w3wp.exe'])
@pytest.mark.parametrize('module', [None, '', '-', 'unknown'])
def test_r3_b1_recorded_address_without_module_is_high_with_source_target_and_reason(source, module):
    data = {'SourceImage': source, 'TargetImage': r'C:\Windows\System32\notepad.exe', 'StartAddress': '0x005A0000'}
    if module is not None:
        data['StartModule'] = module
    hit = RemoteThreadCreation().judge(native(8, data))[0]
    assert hit.lane == 'high'
    assert 'no start module was recorded for start address 0x005A0000' in hit.text
    assert 'outside any loaded image' in hit.text and 'notepad.exe' in hit.text
    assert source.casefold() in hit.text.casefold()
    assert any(item.field == 'thread.start_address' for item in hit.predicate)


def test_r3_b1_missing_both_address_and_module_and_known_ctrlroutine_are_leads():
    data = {'SourceImage': r'C:\Windows\System32\csrss.exe', 'TargetImage': r'C:\Windows\System32\cmd.exe'}
    assert RemoteThreadCreation().judge(native(8, data))[0].lane == 'lead'
    hit = RemoteThreadCreation().judge(native(8, {**data, 'StartModule': r'C:\Windows\System32\kernelbase.dll',
        'StartFunction': 'CtrlRoutine', 'StartAddress': '0x7FF00123'}))[0]
    assert hit.lane == 'lead' and 'CtrlRoutine' in hit.text and 'kernelbase.dll' in hit.text


@pytest.mark.parametrize('root', [r'HKLM\Software\Microsoft', r'HKLM\Software\Policies\Microsoft'])
@pytest.mark.parametrize('tail,value', [(r'Exclusions\Paths\C:\Users\Public', 0),
    (r'Exclusions\Processes\unfamiliar.exe', 0), (r'Real-Time Protection\DisableRealtimeMonitoring', 1),
    ('DisableAntiSpyware', 1)])
def test_r3_b2_sensitive_defender_values_are_high_on_both_roots(root, tail, value):
    event = native(13, {'TargetObject': root + r'\Windows Defender' + '\\' + tail,
                        'Details': f'DWORD (0x{value:08x})'})
    assert RegistryDefender().judge(event)[0].lane == 'high'


@pytest.mark.parametrize('rule,directory,first,last,count', [
    (LureApplicationFileWrite, r'C:\Users\{user}\Downloads', 'BrowserSetup.exe', 'Invoice_2027.exe', 30),
    (StartupFileWrite, r'C:\Users\{user}\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup', 'Meeting.lnk', 'update.lnk', 25),
    (WebRootFileWrite, r'C:\inetpub\wwwroot', 'status.aspx', 'administration.aspx', 2),
])
def test_r3_b3_code_keeps_basename_and_first_finding_on_each_host(rule, directory, first, last, count):
    writer = r'C:\Program Files\Google\Chrome\Application\chrome.exe'
    events = [native(11, {'Image': writer, 'TargetFilename': directory.format(user=f'user{i}') + '\\' + first},
                     host=f'ws{i}') for i in range(count)]
    attack = native(11, {'Image': writer, 'TargetFilename': directory.format(user='victim') + '\\' + last}, host='latehost')
    matches, _ = fold(rule(), [*events, attack])
    assert len([match for match in matches if not match.group_key]) == count + 1
    own = next(match for match in matches if match.events[0].id == attack.id)
    assert 'latehost' in own.claim and last.casefold() in own.claim.casefold()
    assert last.casefold() in rule().judge(attack)[0].content.casefold()


@pytest.mark.parametrize('code', [23, 26])
def test_r3_i1_pe_evidence_prevents_extension_based_folding(code):
    writer = r'C:\Program Files\Internet Explorer\IEInstal.exe'
    events = [native(code, {'Image': writer, 'TargetFilename': fr'C:\Users\user{i}\AppData\Local\Temp\cache.dat',
        'IsExecutable': 'false'}, host=f'ws{i}') for i in range(25)]
    attack = native(code, {'Image': writer, 'TargetFilename': r'C:\Users\victim\AppData\Local\Temp\consent.exe.dat',
        'IsExecutable': 'true', 'Hashes': 'SHA256=' + 'a'*64}, host='latehost')
    matches, _ = fold(WritableExecutableDeletion(), [*events, attack])
    own = next(match for match in matches if not match.group_key and match.events[0].id == attack.id)
    assert 'latehost' in own.claim and 'consent.exe.dat' in own.claim
    assert {'file.is_executable', 'file.hashes'} <= {item.field for item in own.predicate}
    assert attack.get('file.is_executable') is True


def test_r3_i2_replaced_images_fold_by_image_class_and_type_with_first_immediate():
    events = [native(25, {'Image': fr'C:\Users\user{i}\AppData\Local\Programs\Editor\26.1.{i}\Code.exe',
        'Type': 'Image is replaced'}, host=f'ws{i}') for i in range(30)]
    first = ProcessImageTampering().consume([events[0]])
    assert len(first) == 1 and first[0].proposed_lane == 'high'
    matches, _ = fold(ProcessImageTampering(), events)
    assert len(matches) == 1 and '30 host(s)' in matches[0].claim
    assert matches[0].proposed_lane == 'high' and 'code.exe' in matches[0].claim.casefold()


@pytest.mark.parametrize('pipe', ['svcctl', 'atsvc'])
def test_r3_i3_execution_pipe_keeps_each_target_host_first_finding(pipe):
    data = {'ShareName': r'\\*\IPC$', 'RelativeTargetName': pipe, 'AccessMask': '0x12019f',
        'SubjectUserName': 'deployment', 'SubjectDomainName': 'EXAMPLE', 'IpAddress': '192.0.2.8'}
    events = [native(5145, data, host=f'ws{i}') for i in range(25)]
    attack = native(5145, {**data, 'SubjectUserName': 'unexpected', 'IpAddress': '198.51.100.9'}, host='latehost')
    matches, _ = fold(RemoteManagementPipe(), [*events, attack])
    assert len(matches) == 26
    own = next(match for match in matches if match.events[0].id == attack.id)
    assert 'latehost' in own.claim and not own.group_key


@pytest.mark.parametrize('root', [r'C:', r'%SystemDrive%'])
def test_r3_system_volume_only_lowering_scope(root):
    data = {'SourceImage': root + r'\Program Files\Vendor\agent.exe',
        'TargetImage': r'C:\Windows\System32\lsass.exe', 'GrantedAccess': '0x1010'}
    assert LsassProcessAccess().judge(native(10, data))[0].lane == 'lead'
    assert LsassProcessAccess().judge(native(10, {**data, 'SourceImage': r'D:\Program Files\Vendor\agent.exe'}))[0].lane == 'high'


def test_r3_unknown_signature_is_counted_not_assessed_and_never_a_lead():
    event = native(7, {'Image': r'C:\Windows\System32\host.exe', 'ImageLoaded': r'C:\Windows\System32\module.dll'})
    rule = WritableUnsignedDllLoad()
    assert not rule.consume([event])
    assert rule.missing_required == 1 and rule.evaluated == 0
    assert any('not assessed: no signature fields in this record' in note for note in rule.coverage_notes())


@pytest.mark.parametrize('marker', ['(Default)', '{Default}'])
def test_a1_both_native_default_value_spellings_are_com_server_values(marker):
    path = r'HKCU\Software\Classes\CLSID\{42aedc87-2188-41fd-b9a3-0c966feabec1}\InprocServer32' + '\\' + marker
    hit = RegistryUserCom().judge(native(13, {'TargetObject': path, 'Details': r'C:\Users\Public\component.dll'}))[0]
    assert hit.lane == 'high'


@pytest.mark.parametrize('code', [4656, 4663])
@pytest.mark.parametrize('source,lane', [(r'C:\Windows\System32\diagnostic.exe', 'lead'), (r'C:\Users\Public\inspect.exe', 'high')])
def test_a5_security_lsass_process_object_uses_same_positive_rights_and_path_lanes(code, source, lane):
    event = native(code, {'ObjectType': 'Process', 'ObjectName': r'\Device\HarddiskVolume1\Windows\System32\lsass.exe',
        'ProcessName': source, 'ProcessId': '0x124', 'AccessMask': '0x10', 'AccessList': '%%4484'})
    hit = LsassProcessAccess().judge(event)[0]
    assert hit.lane == lane and 'lsass.exe' in hit.text and 'PROCESS_VM_READ' in hit.text
    assert {'object.name', 'object.type', 'object.access_mask', 'process.executable'} <= {item.field for item in hit.predicate}
    assert 'dump occurred' not in hit.text


@pytest.mark.parametrize('root', [r'C:\Windows\assembly\NativeImages_v4.0.30319_64', r'C:\Windows\WinSxS'])
def test_a8_unsigned_native_and_component_images_fold_per_host_without_dropping(root):
    events = [native(7, {'Image': r'C:\Windows\System32\host.exe',
        'ImageLoaded': root + fr'\Assembly{i}\{i:032x}\Component{i}.ni.dll',
        'Signed': 'false', 'SignatureStatus': 'Unavailable'}) for i in range(100)]
    matches, _ = fold(WritableUnsignedDllLoad(), events)
    assert 1 <= len(matches) <= 2
    assert all(match.proposed_lane in {'lead', 'high'} for match in matches)
    assert any('100 Windows event record(s)' in match.claim for match in matches)


def test_a_claims_name_service_registry_key_and_do_not_double_path_backslashes():
    event = native(13, {'TargetObject': r'HKLM\System\CurrentControlSet\Services\ExampleService\ImagePath',
                       'Details': r'C:\Tools\worker.exe'})
    hit = RegistryServiceCommand().judge(event)[0]
    assert 'exampleservice' in hit.text.casefold() and r'C:\Tools\worker.exe' in hit.text
    assert r'C:\\Tools' not in hit.text


def test_a_claims_old_stream_record_names_recorded_path_and_missing_stream():
    event = native(15, {'Image': r'C:\Windows\explorer.exe', 'TargetFilename': r'C:\Users\Public\Downloads', 'Hash': 'Unknown'})
    text = ExecutableAlternateStream().judge(event)[0].text
    assert r'C:\Users\Public\Downloads' in text and 'stream name not recorded' in text


@pytest.mark.parametrize('clsid', ['{0358b920-0ac7-461f-98f4-58e32cd89148}',
    '{c947d50f-378e-4ff6-8835-fcb50305244d}', '{ecd4fc4d-521c-11d0-b792-00a0c90312e1}'])
def test_r3_expanded_sourced_builtin_com_identities_raise_per_user_shadow(clsid):
    path = 'HKCU\\Software\\Classes\\CLSID\\' + clsid + r'\InprocServer32\{Default}'
    assert RegistryUserCom().judge(native(13, {'TargetObject': path, 'Details': r'C:\Users\Public\component.dll'}))[0].lane == 'high'


def test_r3_b3_stream_script_suffix_with_data_type_keeps_own_host_finding():
    events = [native(15, {'Image': r'C:\Windows\explorer.exe',
        'TargetFilename': fr'C:\Users\user{i}\Downloads\report.txt:script.ps1:$DATA', 'Contents': 'unclassified'}, host=f'ws{i}')
        for i in range(2)]
    matches, _ = fold(ExecutableAlternateStream(), events)
    assert len(matches) == 2 and all(not match.group_key for match in matches)


def test_registration_com_handler_fleet_key_is_nonempty_cross_host_and_members_cited():
    events = [native(200, {'TaskName': f'\\Example{i}', 'ActionName': '{47E30D54-DAC1-473A-AFF7-2355BF78881F}'},
                     host=f'ws{i}') for i in range(3)]
    first = ScheduledTaskRegistration().consume([events[0]])
    assert len(first) == 1 and first[0].group_key
    matches, _ = fold(ScheduledTaskRegistration(), events)
    assert len(matches) == 1 and matches[0].group_key
    assert '3 host(s)' in matches[0].claim and '47e30d54' in matches[0].claim
    assert {event.host for event in matches[0].events} == {'ws0', 'ws1', 'ws2'}
    assert 'remains retrievable' not in matches[0].claim


def test_registration_bare_image_needs_separate_risk_for_high_and_relative_driver_has_scope():
    data = {'ServiceName': 'example', 'ImagePath': 'calc.exe', 'ServiceType': 'user mode service'}
    plain = ServiceRegistration().judge(native(7045, data))[0]
    assert plain.lane == 'lead' and 'no directory recorded' in plain.text
    assert 'outside standard' not in plain.text
    assert ServiceRegistration().judge(native(7045, {**data, 'ImagePath': 'calc.exe https://example.test/resource'}))[0].lane == 'high'
    driver = ServiceRegistration().judge(native(7045, {**data, 'ImagePath': r'System32\drivers\example.sys',
                                                      'ServiceType': 'kernel mode driver'}))[0]
    assert driver.lane == 'lead' and 'SystemRoot' in driver.text


@pytest.mark.parametrize('rule,code,extra', [
    (ExecutableCreationTimeChange, 2, {'CreationUtcTime': '2020-01-01 00:00:00.000',
                                     'PreviousCreationUtcTime': '2026-01-02 03:00:00.000'}),
    (WritableExecutableDeletion, 23, {'IsExecutable': 'false'}),
    (ExecutableAlternateStream, 15, {'Contents': '[ZoneTransfer] ZoneId=3'}),
])
def test_r3_b3_code_timestamps_deletions_and_base_stream_files_keep_each_host(rule, code, extra):
    events = [native(code, {'Image': r'C:\Program Files\Google\Chrome\Application\chrome.exe',
        'TargetFilename': fr'C:\Users\user{i}\Downloads\program.exe' + (':Zone.Identifier' if code == 15 else ''),
        **extra}, host=f'ws{i}') for i in range(2)]
    matches, _ = fold(rule(), events)
    assert len(matches) == 2 and all(not match.group_key for match in matches)
    assert {match.events[0].host for match in matches} == {'ws0', 'ws1'}


def test_a5_access_names_without_mask_are_positive_rights_and_nonprocess_objects_do_not_match():
    data = {'ObjectType': 'Process', 'ObjectName': r'C:\Windows\System32\lsass.exe',
            'ProcessName': r'C:\Users\Public\inspect.exe', 'AccessList': '%%4484'}
    hit = LsassProcessAccess().judge(native(4663, data))[0]
    assert hit.lane == 'high' and 'PROCESS_VM_READ' in hit.text
    assert not LsassProcessAccess().judge(native(4663, {**data, 'ObjectType': 'Key'}))
