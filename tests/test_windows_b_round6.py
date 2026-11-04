"""Proxy/path corrections using native records, normalization and consume/finalize."""
import pytest

from romulus.detect.windows_file_events import LureApplicationFileWrite
from romulus.detect.windows_memory_events import LsassProcessAccess
from romulus.detect.windows_proxy import (
    CompilerProxyExecution,
    MshtaExecution,
    MsiexecRemotePackage,
    Regsvr32Execution,
    Rundll32Execution,
    ScriptHostRemoteOrWritable,
)
from tests.test_windows_b_round3 import fold
from tests.test_windows_b_round5 import native, proc
from tests.windows_process_support import run


@pytest.mark.parametrize('rule,image,command', [
    (Rundll32Execution, 'rundll32.exe', 'rundll32.exe example.dll,Start'),
    (Rundll32Execution, 'rundll32.exe', 'rundll32.exe conf3234.dll f8753 d948'),
    (Regsvr32Execution, 'regsvr32.exe', 'regsvr32.exe /s example.dll'),
])
@pytest.mark.parametrize('cwd', ['C:\\Users\\alice\\', 'C:\\Users\\alice\\AppData\\Local\\Temp\\tmp1375\\',
                                 '\\\\server\\share\\work\\', '\\\\?\\UNC\\server\\share\\work\\',
                                 '\\??\\UNC\\server\\share\\work\\'])
def test_bare_non_system_library_is_search_order_lead(rule, image, command, cwd):
    [match] = run(rule(), [proc(image, command, cwd)])
    assert match.proposed_lane == 'lead'
    assert 'not a recognized Windows system library' in match.claim
    assert 'may load from there' in match.claim
    assert cwd in match.claim
    assert any(field.field == 'process.current_directory' for field in match.predicate)


@pytest.mark.parametrize('library', ['kernel32.dll', 'user32.dll', 'ntdll.dll', 'shell32.dll', 'msxml3.dll',
    'msxml6.dll', 'scrrun.dll', 'scrobj.dll', 'vbscript.dll', 'jscript.dll', 'urlmon.dll', 'comsvcs.dll',
    'dfshim.dll', 'davclnt.dll', 'printui.dll', 'desk.cpl', 'url.dll', 'ieframe.dll', 'shdocvw.dll',
    'advpack.dll', 'ieadvpack.dll', 'setupapi.dll', 'syssetup.dll', 'pcwutl.dll', 'zipfldr.dll',
    'shimgvw.dll', 'mshtml.dll', 'ncpa.cpl', 'odbccp32.cpl', 'sysdm.cpl', 'joy.cpl'])
def test_bare_recognized_system_libraries_stay_quiet(library):
    assert not run(Regsvr32Execution(), [proc('regsvr32.exe', f'regsvr32.exe /s {library}', 'C:\\Users\\alice\\')])


def test_system_library_name_at_explicit_writable_location_still_reports():
    [match] = run(Regsvr32Execution(), [proc('regsvr32.exe', r'regsvr32.exe C:\Users\Public\shell32.dll')])
    assert match.proposed_lane == 'lead' and 'user-writable location' in match.claim


@pytest.mark.parametrize('cwd', [None, 'relative', 'C:relative', '\\Users\\alice', 'C:\\Windows\\System32\\'])
def test_bare_library_needs_recorded_absolute_writable_or_unc_cwd(cwd):
    assert not run(Rundll32Execution(), [proc('rundll32.exe', 'rundll32.exe example.dll,Start', cwd)])


@pytest.mark.parametrize('export', ['url.dll,OpenURL', 'url.dll,FileProtocolHandler', 'shell32.dll,ShellExec_RunDLL',
    'advpack.dll,LaunchINFSection', 'zipfldr.dll,RouteTheCall', 'shell32.dll,Control_RunDLL'])
@pytest.mark.parametrize('target', ['https://example.test/a.bin', r'\\server\share\a.bin',
                                   r'\\?\UNC\server\share\a.bin', r'\??\UNC\server\share\a.bin'])
def test_proxy_export_remote_target_is_high_without_claiming_remote_library(export, target):
    [match] = run(Rundll32Execution(), [proc('rundll32.exe', f'rundll32.exe {export} {target}')])
    assert match.proposed_lane == 'high'
    assert 'proxy export' in match.claim and 'remote target' in match.claim
    assert target in match.claim and 'remote DLL' not in match.claim


@pytest.mark.parametrize('target', [r'C:\ProgramData\x\payload.dll', r'C:\PROGRA~3\DATAUS~1.DLL',
                                  'payload.dll', 'unknown.cpl', r'C:\Tools\payload.bin',
                                  r'C:\Windows\SysWOW64\nested\file.bin', r'C:\Windows\System32\nested\desk.cpl'])
def test_control_panel_export_accepts_non_system_targets_of_any_extension(target):
    [match] = run(Rundll32Execution(), [proc('rundll32.exe', f'rundll32.exe shell32.dll,Control_RunDLL {target}')])
    assert match.proposed_lane == 'lead' and target in match.claim


@pytest.mark.parametrize('target', ['desk.cpl', 'appwiz.cpl', r'C:\Windows\System32\desk.cpl',
                                  r'C:\Windows\SysWOW64\desk.cpl'])
def test_control_panel_export_system_targets_stay_quiet(target):
    assert not run(Rundll32Execution(), [proc('rundll32.exe', f'rundll32.exe shell32.dll,Control_RunDLL {target}',
                                            'C:\\Users\\alice\\')])


@pytest.mark.parametrize('prefix', [r'\\?\UNC', r'\??\UNC'])
def test_extended_unc_library_is_remote_high(prefix):
    [match] = run(Rundll32Execution(), [proc('rundll32.exe', f'rundll32.exe {prefix}\\server\\share\\a.dll,Start')])
    assert match.proposed_lane == 'high' and 'remote DLL' in match.claim


@pytest.mark.parametrize('cwd', [r'\\?\UNC\server\share\work', r'\??\UNC\server\share\work'])
def test_relative_library_uses_extended_unc_working_directory(cwd):
    [match] = run(Regsvr32Execution(), [proc('regsvr32.exe', r'regsvr32.exe .\helper.dll', cwd)])
    assert match.proposed_lane == 'lead' and 'UNC path' in match.claim
    assert 'placed using the recorded working directory' in match.claim


@pytest.mark.parametrize('rule,image,command,lane', [
    (CompilerProxyExecution, 'msbuild.exe', r'msbuild.exe \??\UNC\server\share\Users\build.xml', 'lead'),
    (MshtaExecution, 'mshta.exe', r'mshta.exe \??\UNC\server\share\page.hta', 'high'),
    (MsiexecRemotePackage, 'msiexec.exe', r'msiexec.exe /i \??\UNC\server\share\install.msi', 'lead'),
])
def test_extended_unc_paths_preserve_other_proxy_readers(rule, image, command, lane):
    [match] = run(rule(), [proc(image, command)])
    assert match.proposed_lane == lane


@pytest.mark.parametrize('script', ['pubprn.vbs', 'SyncAppvPublishingServer.vbs', 'winrm.vbs', 'manage-bde.wsf',
                                  ])
@pytest.mark.parametrize('protocol,lane', [('https:', 'lead'), ('ftp:', 'lead'), ('script:https:', 'high'),
                                         ('scriptlet:https:', 'high')])
def test_signed_script_proxy_reads_remote_arguments_after_plain_arguments(script, protocol, lane):
    target = protocol + '//example.test/a.sct'
    command = f'cscript.exe //b C:\\Windows\\System32\\{script} localhost ignored {target}'
    [match] = run(ScriptHostRemoteOrWritable(), [proc('cscript.exe', command, 'C:\\Windows\\System32\\')])
    assert match.proposed_lane == lane
    assert script in match.claim and target in match.claim and 'argument 5' in match.claim


def test_remote_script_moniker_is_high_for_an_unlisted_script_too():
    [match] = run(ScriptHostRemoteOrWritable(), [proc('wscript.exe',
        r'wscript.exe C:\Tools\launch.vbs plain script:https://example.test/a.sct')])
    assert match.proposed_lane == 'high' and 'argument 3' in match.claim


def test_later_remote_moniker_takes_priority_over_plain_proxy_url():
    [match] = run(ScriptHostRemoteOrWritable(), [proc('cscript.exe',
        r'cscript.exe C:\Windows\System32\pubprn.vbs https://example.test/a scriptlet:https://example.test/b.sct')])
    assert match.proposed_lane == 'high' and 'argument 3' in match.claim


@pytest.mark.parametrize('command', [r'wscript.exe launch.vbs install',
    r'cscript.exe C:\Windows\System32\slmgr.vbs C:\Users\Public\argument.js',
    r'cscript.exe C:\Windows\System32\pubprn.vbs \\srv "LDAP://CN=Container,DC=example,DC=test"',
    r'wscript.exe C:\Tools\launch.vbs https://example.test/a.js'])
def test_plain_arguments_and_normal_printing_arguments_do_not_create_proxy_findings(command):
    image = command.split()[0]
    assert not run(ScriptHostRemoteOrWritable(), [proc(image, command, 'C:\\Windows\\System32\\')])


@pytest.mark.parametrize('rule,image,operand', [
    (Rundll32Execution, 'rundll32.exe', r'C:\PROGRA~3\DATAUS~1.DLL,Start'),
    (Regsvr32Execution, 'regsvr32.exe', r'C:\PROGRA~1\Vendor\helper.dll'),
    (ScriptHostRemoteOrWritable, 'cscript.exe', r'C:\PROGRA~1\Vendor\launch.vbs'),
])
def test_short_path_operand_is_unresolved_lead(rule, image, operand):
    [match] = run(rule(), [proc(image, f'{image} {operand}')])
    assert match.proposed_lane == 'lead'
    assert 'path recorded in 8.3 short form; its long location is not recorded' in match.claim


def test_short_name_under_literal_system_directory_does_not_raise_by_itself():
    assert not run(Regsvr32Execution(), [proc('regsvr32.exe', r'regsvr32.exe C:\Windows\System32\EXAMPL~1.dll')])


def test_short_name_cannot_lower_memory_access_to_installed_scope():
    event = native(10, {'SourceImage': r'C:\Program Files\VENDOR~1\helper.exe',
                        'TargetImage': r'C:\Windows\System32\lsass.exe', 'GrantedAccess': '0x10'})
    [match], _ = fold(LsassProcessAccess(), [event])
    assert match.proposed_lane == 'high'
    assert 'memory-related rights were recorded' in match.claim
    assert 'source path does not establish' in match.claim


@pytest.mark.parametrize('drive,expected', [('C:', True), ('c:', True), ('D:', False)])
def test_drive_relative_library_uses_only_matching_recorded_cwd(drive, expected):
    matches = run(Rundll32Execution(), [proc('rundll32.exe', f'rundll32.exe {drive}helper.dll,Start',
                                           'C:\\Users\\alice\\')])
    assert bool(matches) is expected
    if matches:
        assert 'placed using the recorded working directory' in matches[0].claim
        assert r'C:\Users\alice\helper.dll'.casefold() in matches[0].claim.casefold()


@pytest.mark.parametrize('writer,cache', [
    ('OUTLOOK.EXE', r'Microsoft\Windows\INetCache\Content.Outlook\ABC'),
    ('WINWORD.EXE', r'Microsoft\Windows\INetCache\Content.MSO\ABC'),
    ('chrome.exe', r'Microsoft\Windows\INetCache\Content.Outlook\ABC'),
    ('OUTLOOK.EXE', r'Microsoft\Windows\INetCache\IE\ABC'),
    ('WINWORD.EXE', r'Google\Chrome\User Data\Default\Cache\Cache_Data'),
])
def test_office_cache_or_nonbrowser_writer_keeps_script_findings_separate(writer, cache):
    events = [native(11, {'Image': f'C:\\Program Files\\Vendor\\{writer}',
        'TargetFilename': fr'C:\Users\u{i}\AppData\Local\{cache}\Invoice.js'}, f'ws{i}') for i in range(3)]
    matches, _ = fold(LureApplicationFileWrite(), events)
    assert len(matches) == 3 and all(not match.group_key for match in matches)
