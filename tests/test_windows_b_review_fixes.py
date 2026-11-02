"""Native event regressions for memory, registry, endpoint and file evidence boundaries."""
import itertools

import pytest

from romulus.detect.windows_endpoint_events import (
    AdminShareTransfer,
    DefenderProtection,
    DefenderThreat,
    RemoteManagementPipe,
    ToolNamedPipe,
)
from romulus.detect.windows_file_events import (
    ExecutableAlternateStream,
    LureApplicationFileWrite,
    StartupFileWrite,
)
from romulus.detect.windows_memory_events import (
    DumpLibraryLoad,
    LsassProcessAccess,
    ProcessImageTampering,
    RemoteThreadCreation,
    UnsignedDriverLoad,
    WritableUnsignedDllLoad,
)
from romulus.detect.windows_registry_events import (
    RegistryDefender,
    RegistryImageExecution,
    RegistryRunKeys,
    RegistryServiceCommand,
    RegistryUserCom,
    RegistryWinlogon,
)
from romulus.evidence.windows import normalize_windows
from romulus.evidence.windows_catalog import (
    DEFENDER_CHANNEL,
    DEFENDER_PROVIDER,
    SECURITY,
    SYSMON,
    SYSMON_CHANNEL,
)
from tests.windows_event_support import event
from tests.windows_fixtures import LogicalWindowsEvent, windows_hit

_IDS = itertools.count(80000)
_GUID = '{11111111-2222-3333-4444-555555555555}'


def native(code, data, *, host='ws01.example.test', provider=SYSMON, channel=SYSMON_CHANNEL):
    fixture = LogicalWindowsEvent(channel, provider, code, host, next(_IDS), '2026-01-02T03:00:00Z', data)
    return normalize_windows(windows_hit(fixture, 'winlogbeat_8'))


def access(source=r'C:\Windows\System32\svchost.exe', mask='0x1410', trace=r'C:\Windows\System32\ntdll.dll+123', **extra):
    return native(10, {'SourceImage': source, 'TargetImage': r'C:\Windows\System32\lsass.exe',
                       'GrantedAccess': mask, 'CallTrace': trace, **extra})


@pytest.mark.parametrize('source', [r'C:\Windows\System32\csrss.exe', r'C:\Windows\System32\wininit.exe',
    r'C:\Windows\System32\wbem\WmiPrvSE.exe', r'C:\Program Files\Elastic\Endpoint\elastic-endpoint.exe',
    r'C:\Windows\Sysmon64.exe', r'C:\Program Files\VMware\VMware Tools\vmtoolsd.exe'])
def test_b_b2_install_path_ordinary_lsass_access_is_lead(source):
    assert LsassProcessAccess().judge(access(source))[0].lane == 'lead'


def test_b_b2_spoofed_security_name_and_unknown_frame_are_high():
    assert LsassProcessAccess().judge(access(r'C:\ProgramData\x\MsMpEng.exe'))[0].lane == 'high'
    assert LsassProcessAccess().judge(access(trace='UNKNOWN(0x123)+0x456'))[0].lane == 'high'


@pytest.mark.parametrize('mask', ['0x14c0', '0x40', '0x80', '0x1440'])
def test_b_i1_handle_and_parent_rights_are_leads(mask):
    hit = LsassProcessAccess().judge(access(r'C:\Users\a\x.exe', mask))[0]
    assert hit.lane == 'lead' and 'PROCESS_VM_READ' not in hit.text


def test_b_i1_seclogon_trace_is_notable():
    ev = access(mask='0x1010', trace=r'C:\Windows\System32\seclogon.dll+12')
    assert LsassProcessAccess().judge(ev)[0].lane == 'high'


def test_b_b3_ordinary_remote_thread_and_install_tamper_are_leads():
    thread = native(8, {'SourceImage': r'C:\Windows\System32\csrss.exe',
        'TargetImage': r'C:\Windows\System32\cmd.exe', 'StartModule': r'C:\Windows\System32\kernel32.dll',
        'StartFunction': 'CtrlRoutine', 'StartAddress': '0x123', 'NewThreadId': '77'})
    assert RemoteThreadCreation().judge(thread)[0].lane == 'lead'
    tamper = native(25, {'Image': r'C:\Program Files\Google\Chrome\chrome.exe', 'Type': 'Image is replaced'})
    assert ProcessImageTampering().judge(tamper)[0].lane == 'high'


@pytest.mark.parametrize('root', [r'HKU\S-1-5-21-1-2-3-1001_Classes', r'HKCU\Software\Classes',
    r'HKCU\Software\Classes\Wow6432Node', r'HKCU\Software\Wow6432Node\Classes'])
def test_b_b4_real_com_views_and_install_payload_lead(root):
    ev = native(13, {'EventType': 'SetValue', 'TargetObject': root + '\\CLSID\\' + _GUID + r'\InprocServer32\(Default)',
                      'Details': r'C:\Program Files\Vendor\server.dll'})
    assert RegistryUserCom().judge(ev)[0].lane == 'lead'


def test_b_b4_unknown_com_class_writable_payload_is_lead():
    ev = native(13, {'TargetObject': r'HKU\S-1-5-21-1-2-3-1001_Classes\CLSID' + '\\' + _GUID + r'\InprocServer32\(Default)',
        'Details': r'C:\ProgramData\x.dll'})
    assert RegistryUserCom().judge(ev)[0].lane == 'lead'


@pytest.mark.parametrize('value', ['unknown.dll', 'unknown.exe /start', r'"C:\Program Files\Vendor\app.exe" /embedding',
                                  r'E:\Vendor\app.dll', r'\\server\share\app.dll'])
def test_b_b4_com_payload_without_writable_evidence_is_lead(value):
    ev = native(13, {'TargetObject': r'HKCU\Software\Classes\CLSID' + '\\' + _GUID + r'\LocalServer32\(Default)',
                     'Details': value})
    assert RegistryUserCom().judge(ev)[0].lane == 'lead'


@pytest.mark.parametrize('path', [r'C:\ProgramData\x\evil.dll', r'\\server\share\evil.dll', r'E:\evil.dll',
    r'C:\PerfLogs\evil.dll', r'C:\Windows\Tasks\evil.dll', r'C:\Windows\Tracing\evil.dll',
    r'C:\Users\a\evil.dat', r'C:\Users\a\evil.tmp'])
def test_b_i3_i4_module_paths_and_suffixes_never_hide_load(path):
    ev = native(7, {'Image': r'C:\Windows\System32\rundll32.exe', 'ImageLoaded': path, 'Signed': 'false'})
    assert WritableUnsignedDllLoad().judge(ev)


@pytest.mark.parametrize('target', ['__123.456', 'x.aspx', 'payload.tmp'])
def test_b_i4_admin_share_suffix_never_gates(target):
    ev = native(5145, {'ShareName': r'\\*\ADMIN$', 'RelativeTargetName': target, 'AccessMask': '0x2'},
                provider=SECURITY, channel='Security')
    assert AdminShareTransfer().judge(ev)


@pytest.mark.parametrize('accesses', ['%%4417', 'WriteData (or AddFile)', None])
def test_b_i6_missing_share_mask_preserves_write_or_unknown_lead(accesses):
    ev = native(5145, {'ShareName': r'\\*\ADMIN$', 'RelativeTargetName': 'payload.exe', 'AccessList': accesses},
                provider=SECURITY, channel='Security')
    assert AdminShareTransfer().judge(ev)[0].lane == 'lead'


def test_b_i5_rename_destination_into_run_is_observed():
    ev = native(14, {'EventType': 'RenameKey', 'TargetObject': r'HKLM\Software\Temp\K',
        'NewName': r'HKLM\Software\Microsoft\Windows\CurrentVersion\Run'})
    assert 'renamed' in RegistryRunKeys().judge(ev)[0].text


def test_b_i5_key_rename_into_ifeo_observes_new_target_without_inventing_debugger_value():
    ev = native(14, {'EventType': 'RenameKey', 'TargetObject': r'HKLM\Software\Temp\app.exe',
        'NewName': r'HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe'})
    hit = RegistryImageExecution().judge(ev)[0]
    assert hit.lane == 'lead' and 'renamed' in hit.text and 'unknown' in hit.text
    assert any(item.field == 'registry.new_path' for item in hit.predicate)


def test_b_i7_expired_signature_wording_and_lane():
    ev = native(6, {'ImageLoaded': r'C:\Windows\System32\drivers\oem.sys', 'Signed': 'true', 'SignatureStatus': 'Expired'})
    hit = UnsignedDriverLoad().judge(ev)[0]
    assert hit.lane == 'lead' and 'expired' in hit.text.casefold() and 'invalid' not in hit.text.casefold()


def test_b_i7_signature_updates_are_not_policy():
    ev = native(13, {'TargetObject': r'HKLM\Software\Microsoft\Windows Defender\Signature Updates\SignaturesLastUpdated',
                     'Details': 'Binary Data'})
    assert not RegistryDefender().judge(ev)


@pytest.mark.parametrize('name', [r'\MSSE-1-server', r'\MSSE-6546-server', r'\PSEXESVC-WS01-1234-stdin',
    r'\PSEXESVC-WS01-1234-stdout', r'\PSEXESVC-WS01-1234-stderr', r'\PAExec-1-WS01'])
def test_b_i2_documented_tool_pipe_forms(name):
    assert ToolNamedPipe().judge(native(17, {'PipeName': name}))[0].lane == 'lead'


def test_b_i4_startup_url_and_unnamed_stream_content_are_observed():
    startup = r'C:\Users\a\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\x.url'
    assert StartupFileWrite().judge(native(11, {'TargetFilename': startup}))
    assert ExecutableAlternateStream().judge(native(15, {'TargetFilename': r'C:\Users\a\d.txt:payload'}))


def test_b_i8_office_recent_shortcut_is_outside_lure_signal():
    ev = native(11, {'Image': r'C:\Program Files\Microsoft Office\WINWORD.EXE',
        'TargetFilename': r'C:\Users\a\AppData\Roaming\Microsoft\Office\Recent\report.docx.LNK'})
    assert not LureApplicationFileWrite().judge(ev)


def test_b_i8_ordinary_dump_module_install_load_is_outside_signal_but_unexpected_loader_remains():
    data = {'Image': r'C:\Program Files\Vendor\app.exe', 'ImageLoaded': r'C:\Windows\System32\dbghelp.dll',
            'Signed': 'true', 'SignatureStatus': 'Valid'}
    assert not DumpLibraryLoad().judge(native(7, data))
    assert DumpLibraryLoad().judge(native(7, {**data, 'Image': r'C:\ProgramData\Vendor\app.exe'}))[0].lane == 'lead'


@pytest.mark.parametrize('pipe', ['samr', 'lsarpc'])
def test_b_i8_read_only_identity_lookup_pipe_requires_another_qualifier(pipe):
    base = {'ShareName': r'\\*\IPC$', 'RelativeTargetName': pipe, 'AccessMask': '0x1'}
    assert not RemoteManagementPipe().judge(native(5145, base, provider=SECURITY, channel='Security'))
    assert RemoteManagementPipe().judge(native(5145, {**base, 'AccessMask': '0x3'}, provider=SECURITY, channel='Security'))


def test_b_minor_low_pua_retains_defender_record_at_lead():
    ev = native(1116, {'Threat Name': 'PUA:Win32/Foo', 'Severity Name': 'Low', 'Category Name': 'Potentially Unwanted Software'},
                provider=DEFENDER_PROVIDER, channel=DEFENDER_CHANNEL)
    assert DefenderThreat().judge(ev)[0].lane == 'lead'


def test_b_minor_truncated_winlogon_still_high_when_additional_image_is_recorded():
    ev = native(13, {'TargetObject': r'HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell',
                     'Details': r'explorer.exe, C:\ProgramData\x.exe ...'})
    hit = RegistryWinlogon().judge(ev)[0]
    assert hit.lane == 'high' and 'truncated' in hit.text


def test_b_minor_missing_access_images_are_explicit_unresolved_leads():
    ev = native(10, {'SourceImage': r'C:\Users\a\x.exe', 'GrantedAccess': '0x1010'})
    hit = LsassProcessAccess().judge(ev)[0]
    assert hit.lane == 'lead' and 'target image' in hit.text and 'unresolved' in hit.text
    ev = native(10, {'TargetImage': r'C:\Windows\System32\lsass.exe', 'GrantedAccess': '0x1010'})
    hit = LsassProcessAccess().judge(ev)[0]
    assert 'unresolved source' in hit.text.casefold()


def test_b_b1_native_lsass_instance_and_aslr_offsets_merge_but_modules_and_masks_separate():
    rule = LsassProcessAccess()
    one = access(SourceProcessId='1', SourceProcessGUID='{00000000-0000-0000-0000-000000000001}',
                 TargetProcessId='2', TargetProcessGUID='{00000000-0000-0000-0000-000000000002}')
    two = access(trace=r'C:\Windows\System32\ntdll.dll+456', SourceProcessId='31',
                 SourceProcessGUID='{00000000-0000-0000-0000-000000000031}', TargetProcessId='32',
                 TargetProcessGUID='{00000000-0000-0000-0000-000000000032}')
    assert rule.judge(one)[0].content == rule.judge(two)[0].content
    for other in [access(mask='0x1010'), access(trace=r'C:\Windows\System32\kernelbase.dll+123')]:
        assert rule.judge(one)[0].content != rule.judge(other)[0].content
    assert {item.field for item in rule.judge(one)[0].predicate} >= {'source.pid', 'target.pid', 'source.guid', 'target.guid'}


def test_b_b1_remote_thread_instance_and_addresses_merge_but_function_separates():
    rule = RemoteThreadCreation()
    base = {'SourceImage': r'C:\Windows\System32\csrss.exe', 'TargetImage': r'C:\Windows\System32\cmd.exe',
            'StartModule': r'C:\Windows\System32\kernel32.dll', 'StartFunction': 'CtrlRoutine'}
    one = native(8, {**base, 'SourceProcessId': '1', 'TargetProcessId': '2', 'NewThreadId': '3', 'StartAddress': '0x123'})
    two = native(8, {**base, 'SourceProcessId': '11', 'TargetProcessId': '22', 'NewThreadId': '33', 'StartAddress': '0x456'})
    assert rule.judge(one)[0].content == rule.judge(two)[0].content
    assert rule.judge(one)[0].content != rule.judge(native(8, {**base, 'StartFunction': 'AnotherFunction'}))[0].content


@pytest.mark.parametrize('name', ['MSSE-1-server', 'MSSE-6546-server', 'PSEXESVC-WS01-12-stdin',
                                  'PSEXESVC-WS02-54-stdin', 'PAExec-1-WS01.exe', 'PAExec-2-WS02.exe'])
def test_b_b1_tool_pipe_content_does_not_keep_embedded_pids_or_random_names(name):
    rule = ToolNamedPipe()
    base = 'MSSE-123-server' if name.startswith('MSSE') else 'PSEXESVC-OTHER-77-stdin' if name.startswith('PSEXESVC') else 'PAExec-9-OTHER.exe'
    assert rule.judge(native(17, {'PipeName': name}))[0].content == rule.judge(native(17, {'PipeName': base}))[0].content


def test_b_minor_exclusion_trailing_slash_and_equals_are_preserved():
    ev = native(13, {'TargetObject': 'HKLM\\Software\\Microsoft\\Windows Defender\\Exclusions\\Paths\\C:\\Temp\\',
                     'Details': 'DWORD (0x00000000)'})
    assert RegistryDefender().judge(ev)[0].lane == 'lead'
    ev = native(5007, {'New Value': r'HKLM\Software\Microsoft\Windows Defender\Exclusions\Paths\C:\a=b = 0x0'},
                provider=DEFENDER_PROVIDER, channel=DEFENDER_CHANNEL)
    assert DefenderProtection().judge(ev)[0].lane == 'high'


@pytest.mark.parametrize('rule,path', [
    (RegistryRunKeys, r'HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Run\x'),
    (RegistryRunKeys, r'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\x'),
    (RegistryServiceCommand, r'HKLM\System\CurrentControlSet\Services\x\Parameters\ServiceDll'),
    (RegistryRunKeys, r'HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\Load'),
    (RegistryRunKeys, r'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders\Startup'),
    (RegistryUserCom, r'HKCU\Software\Classes\CLSID' + '\\' + _GUID + r'\TreatAs\(Default)'),
])
def test_b_minor_persistence_breadth(rule, path):
    assert rule().judge(native(13, {'TargetObject': path, 'Details': r'C:\Users\a\x.dll'}))


@pytest.mark.parametrize('rule,family,code,base,changed', [
    (LsassProcessAccess, 'process_access', 10, {'source.executable': r'C:\Tools\a.exe',
        'target.executable': r'C:\Windows\System32\lsass.exe', 'process.access.mask': 0x10}, {'process.access.mask': 0x18}),
    (RegistryRunKeys, 'registry_change', 13, {'registry.path_key': r'hkey_current_user\software\microsoft\windows\currentversion\run\x',
        'registry.value': 'one.exe'}, {'registry.value': 'two.exe'}),
    (AdminShareTransfer, 'share_access', 5145, {'share.name': r'\\*\ADMIN$', 'share.relative_target': 'one.exe',
        'share.access_mask': 2, 'source.ip': '10.0.0.1'}, {'share.relative_target': 'two.exe'}),
    (StartupFileWrite, 'file_change', 11, {'file.path': r'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\one.exe',
        'process.executable': r'C:\Tools\writer.exe'}, {'process.executable': r'C:\Tools\other.exe'}),
])
def test_b_b1_each_family_merges_new_instances_separates_content_and_publishes_hosts(rule, family, code, base, changed):
    instance = rule()
    first = event(family, code, native='first', **{**base, 'source.pid': 1, 'process.pid': 1, 'share.session_id': '1'})
    second = event(family, code, native='repeat', offset=1, **{**base, 'source.pid': 2, 'process.pid': 2, 'share.session_id': '2'})
    first_hit, second_hit = instance.judge(first)[0], instance.judge(second)[0]
    assert first_hit.content and first_hit.content == second_hit.content
    assert instance._shape(first, first_hit) == instance._shape(second, second_hit)
    other = event(family, code, **{**base, **changed})
    assert instance._shape(first, first_hit) != instance._shape(other, instance.judge(other)[0])
    assert instance.consume([first])
    instance.drain_staged()
    assert all(match.group_key for match in instance.consume([second]))
    assert instance.consume([event(family, code, host='ws02', native='newhost', **base)])
