"""Synthetic native Windows records through normalization, consume and fleet publication."""
import base64
import itertools

import pytest

from romulus.detect.bounded import StateBudget
from romulus.detect.windows_endpoint_events import RemoteManagementPipe
from romulus.detect.windows_file_events import (
    ExecutableAlternateStream,
    LureApplicationFileWrite,
    WritableExecutableDeletion,
)
from romulus.detect.windows_lineage import LureAppSpawnsCodeRunner
from romulus.detect.windows_memory_events import (
    LsassProcessAccess,
    ProcessImageTampering,
    RemoteThreadCreation,
)
from romulus.detect.windows_path_data import BUILTIN_COM_CLASSES
from romulus.detect.windows_proxy import (
    PowerShellEncodedOrCradle,
    Regsvr32Execution,
    Rundll32Execution,
    ScriptHostRemoteOrWritable,
)
from romulus.detect.windows_registry_events import RegistryUserCom, RegistryWinlogon
from romulus.evidence.windows import normalize_windows
from romulus.evidence.windows_catalog import SECURITY, SYSMON, SYSMON_CHANNEL
from tests.test_windows_b_round3 import fold
from tests.windows_fixtures import LogicalWindowsEvent, windows_hit
from tests.windows_process_support import run, security4688, security4689

_IDS = itertools.count(850000)
_CHROME = r'C:\Program Files\Google\Chrome\Application\chrome.exe'
_WORD = r'C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE'
_SYSTEM = 'C:\\Windows\\System32\\'


def native(code, data, host='ws01', *, outcome=None):
    security = code in {4656, 4663, 4688, 5145}
    hit = windows_hit(LogicalWindowsEvent('Security' if security else SYSMON_CHANNEL,
        SECURITY if security else SYSMON, code, host, next(_IDS), '2026-01-02T03:00:00Z', data), 'winlogbeat_8')
    if outcome is not None:
        hit['_source'].setdefault('event', {})['outcome'] = outcome
    return normalize_windows(hit)


def proc(image, command, cwd=None):
    data = {'Image': _SYSTEM + image, 'CommandLine': command, 'ParentImage': r'C:\Windows\explorer.exe'}
    if cwd is not None:
        data['CurrentDirectory'] = cwd
    return native(1, data)


def hashes(i, imp='0' * 32):
    return f'SHA1={i:040x},MD5={i:032x},SHA256={i:064x},IMPHASH={imp}'


@pytest.mark.parametrize('hosts', [1, 30])
def test_r4_b_n1_zone_hashes_without_pe_evidence_fold(hosts):
    events = [native(15, {'Image': _CHROME, 'TargetFilename': fr'C:\Users\u{i}\Downloads\report{i}.pdf:Zone.Identifier',
        'Contents': f'[ZoneTransfer] ZoneId=3 HostUrl=https://example.test/{i}', 'Hash': hashes(i)}, f'ws{i % hosts}')
        for i in range(30 if hosts > 1 else 20)]
    [match], _ = fold(ExecutableAlternateStream(), events)
    assert match.proposed_lane == 'lead' and f'{len(events)} Windows event record(s)' in match.claim
    assert any(item.field == 'file.hashes' for item in match.predicate)


@pytest.mark.parametrize('code', [23, 26])
def test_r4_b_n1_document_temporary_deletions_with_hashes_fold(code):
    events = [native(code, {'Image': _WORD, 'TargetFilename': fr'C:\Users\alice\AppData\Local\Temp\~WRS{i:04x}.tmp',
        'Hashes': hashes(i), 'IsExecutable': 'false'}) for i in range(20)]
    [match], _ = fold(WritableExecutableDeletion(), events)
    assert match.proposed_lane == 'lead' and '20 Windows event record(s)' in match.claim


@pytest.mark.parametrize('evidence', [{'IsExecutable': 'true'}, {'Hash': hashes(1, 'a' * 32)}, {'Contents': 'MZ synthetic'}])
def test_r4_b_n1_positive_pe_evidence_keeps_late_own_finding(evidence):
    events = [native(15, {'Image': _CHROME, 'TargetFilename': fr'C:\Users\u{i}\Downloads\cache.dat:Zone.Identifier',
        'Hash': hashes(i), 'Contents': '[ZoneTransfer]'}, f'ws{i}') for i in range(30)]
    late = native(15, {'Image': _CHROME, 'TargetFilename': r'C:\Users\victim\Downloads\consent.exe.dat:Zone.Identifier',
        **evidence}, 'late31')
    matches, _ = fold(ExecutableAlternateStream(), [*events, late])
    own = next(m for m in matches if not m.group_key and m.events[0].id == late.id)
    assert 'late31' in own.claim and 'consent.exe.dat' in own.claim


_CODE_EXTENSIONS = ['.xll', '.wll', '.chm', '.msc', '.application', '.appref-ms', '.settingcontent-ms', '.ws',
    '.iqy', '.slk', '.library-ms', '.searchconnector-ms', '.diagcab', '.gadget', '.vsto', '.xbap', '.ppkg',
    '.docm', '.dotm', '.xlsm', '.xltm', '.xlam', '.xla', '.pptm', '.potm', '.ppam', '.ppsm', '.sldm',
    '.one', '.onepkg', '.iso', '.img', '.vhd', '.vhdx']


@pytest.mark.parametrize('suffix', _CODE_EXTENSIONS)
def test_r4_b_n2_every_code_capable_extension_keeps_late_host(suffix):
    events = [native(11, {'Image': _WORD, 'TargetFilename': fr'C:\Users\u{i}\Downloads\Budget{i}{suffix}'}, f'ws{i}')
              for i in range(30)]
    late = native(11, {'Image': _WORD, 'TargetFilename': fr'C:\Users\victim\Downloads\Invoice{suffix}'}, 'late31')
    matches, _ = fold(LureApplicationFileWrite(), [*events, late])
    assert len(matches) == 31 and all(not m.group_key for m in matches)
    assert any(m.events[0].id == late.id and 'late31' in m.claim for m in matches)


@pytest.mark.parametrize('suffix', ['.zip', '.7z', '.rar', '.gz', '.tar'])
def test_r4_b_n2_archive_extensions_remain_foldable(suffix):
    events = [native(11, {'Image': _WORD, 'TargetFilename': fr'C:\Users\u{i}\Downloads\Budget{i}{suffix}'}, f'ws{i}')
              for i in range(31)]
    [match], _ = fold(LureApplicationFileWrite(), events)
    assert match.group_key and match.fleet_host_count == 31


@pytest.mark.parametrize('cache', [r'Microsoft\Windows\INetCache\IE\ABCD1234',
    r'Google\Chrome\User Data\Default\Cache\Cache_Data', r'Microsoft\Edge\User Data\Profile 1\Code Cache\js',
    r'Mozilla\Firefox\Profiles\abc.default\cache2\entries'])
@pytest.mark.parametrize('suffix', ['.js', '.ts', '.c', '.txt'])
def test_r4_b_n2_browser_cache_text_and_scripts_fold_but_pe_does_not(cache, suffix):
    events = [native(11, {'Image': _CHROME, 'TargetFilename': fr'C:\Users\u{i}\AppData\Local\{cache}\resource{i}{suffix}',
        'Hashes': hashes(i)}, f'ws{i}') for i in range(31)]
    [match], _ = fold(LureApplicationFileWrite(), events)
    assert match.group_key and match.fleet_host_count == 31
    late = native(11, {'Image': _CHROME, 'TargetFilename': fr'C:\Users\victim\AppData\Local\{cache}\resource{suffix}',
        'IsExecutable': 'true'}, 'late32')
    matches, _ = fold(LureApplicationFileWrite(), [*events, late])
    assert any(not m.group_key and m.events[0].id == late.id for m in matches)


@pytest.mark.parametrize('suffix', ['.xll', '.chm', '.msc', '.docm', '.iso', '.exe'])
def test_r4_b_n2_nontext_cache_artifacts_keep_own_findings(suffix):
    events = [native(11, {'Image': _WORD, 'TargetFilename': fr'C:\Users\u{i}\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\ABCD1234\Invoice{suffix}'},
                     f'ws{i}') for i in range(31)]
    matches, _ = fold(LureApplicationFileWrite(), events)
    assert len(matches) == 31 and all(not m.group_key for m in matches)


@pytest.mark.parametrize('path', [r'C:\Users\INetCache\Downloads\script.js',
    r'C:\Users\alice\Downloads\INetCache\script.js', r'C:\Users\alice\Chrome\User Data\Default\Cache\script.js'])
def test_r4_b_n2_cache_names_outside_profile_grammar_cannot_fold_code(path):
    matches, _ = fold(LureApplicationFileWrite(), [native(11, {'Image': _CHROME, 'TargetFilename': path}, f'ws{i}')
                                                  for i in range(2)])
    assert len(matches) == 2 and all(not match.group_key for match in matches)


@pytest.mark.parametrize('pipe', ['svcctl', 'atsvc'])
@pytest.mark.parametrize('has_ip', [True, False])
def test_r4_b_n3_execution_pipe_distinguishes_same_host_source_or_account(pipe, has_ip):
    base = {'ShareName': r'\\*\IPC$', 'RelativeTargetName': pipe, 'AccessMask': '0x12019f',
            'SubjectUserName': 'deployment', 'SubjectDomainName': 'EXAMPLE'}
    if has_ip:
        base['IpAddress'] = '192.0.2.8'
    events = [native(5145, base) for _ in range(30)]
    late = native(5145, {**base, 'SubjectUserName': 'helpdesk2', **({'IpAddress': '198.51.100.9'} if has_ip else {})})
    matches, _ = fold(RemoteManagementPipe(), [*events, late])
    own = next(m for m in matches if not m.group_key and m.events[0].id == late.id)
    assert ('198.51.100.9' if has_ip else 'helpdesk2') in own.claim


@pytest.mark.parametrize('root', [r'HKLM\SOFTWARE', r'HKU\S-1-5-21-1-2-3-1001\SOFTWARE'])
@pytest.mark.parametrize('prefix', ['D:', r'\Device\HarddiskVolume7',
    r'\\?\Volume{12345678-1234-1234-1234-123456789abc}', r'\\?\D:', r'\??\D:'])
def test_r4_b_n4_winlogon_other_volumes_never_establish_default(root, prefix):
    event = native(13, {'TargetObject': root + r'\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell',
        'Details': prefix + r'\Windows\explorer.exe'})
    [match], _ = fold(RegistryWinlogon(), [event])
    assert match.proposed_lane == 'high'


@pytest.mark.parametrize('path', [r'C:\Windows\explorer.exe', r'\\?\C:\Windows\explorer.exe',
    r'\??\C:\Windows\explorer.exe', r'\SystemRoot\explorer.exe', r'%SystemRoot%\explorer.exe',
    r'%windir%\explorer.exe', r'%SystemDrive%\Windows\explorer.exe'])
def test_r4_b_n4_only_explicit_system_volume_defaults_are_excluded(path):
    event = native(13, {'TargetObject': r'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell', 'Details': path})
    assert not fold(RegistryWinlogon(), [event])[0]


@pytest.mark.parametrize('image,command,rule', [
    ('rundll32.exe', 'rundll32.exe shell32.dll,Control_RunDLL desk.cpl', Rundll32Execution),
    ('rundll32.exe', 'rundll32.exe printui.dll,PrintUIEntry /il', Rundll32Execution),
    ('regsvr32.exe', 'regsvr32.exe /s msxml3.dll', Regsvr32Execution),
    ('wscript.exe', 'wscript.exe "C:\\Program Files\\Vendor\\launch.vbs" install', ScriptHostRemoteOrWritable),
    ('cscript.exe', 'cscript.exe //nologo C:\\Windows\\System32\\slmgr.vbs C:\\Users\\Public\\argument.js', ScriptHostRemoteOrWritable),
])
def test_r4_b_n5_bare_dll_search_and_script_arguments_make_no_false_placement(image, command, rule):
    assert not run(rule(), [proc(image, command, 'C:\\Users\\alice\\')])


@pytest.mark.parametrize('rule,image,operand', [(Rundll32Execution, 'rundll32.exe', '.\\component.dat,Entry'),
    (Regsvr32Execution, 'regsvr32.exe', '/s .\\component.bin'),
    (ScriptHostRemoteOrWritable, 'cscript.exe', '//nologo sub\\report.js')])
@pytest.mark.parametrize('cwd,label', [('C:\\Users\\alice\\', 'user-writable location'),
                                     ('\\\\fileserver\\share\\', 'UNC path')])
def test_r4_b_m7_relative_directory_operands_use_local_or_unc_cwd(rule, image, operand, cwd, label):
    [match] = run(rule(), [proc(image, image + ' ' + operand, cwd)])
    assert label in match.claim and 'placed using the recorded working directory' in match.claim
    assert any(p.field == 'process.current_directory' for p in match.predicate)


_EXPORTS = [('url', name) for name in ('OpenURL', 'OpenURLA', 'FileProtocolHandler')]
_EXPORTS += [(dll, 'OpenURL') for dll in ('ieframe', 'shdocvw')]
_EXPORTS += [(dll, name) for dll in ('advpack', 'ieadvpack') for name in ('RegisterOCX', 'LaunchINFSection', 'LaunchINFSectionEx')]
_EXPORTS += [('setupapi', 'InstallHinfSection'), ('syssetup', 'SetupInfObjectInstallAction'), ('pcwutl', 'LaunchApplication'),
    ('zipfldr', 'RouteTheCall'), ('shell32', 'ShellExec_RunDLL'), ('shell32', 'ShellExec_RunDLLA'),
    ('shimgvw', 'ImageView_Fullscreen'), ('mshtml', 'PrintHTML')]


@pytest.mark.parametrize('library,entry', _EXPORTS)
def test_r4_b_n5_every_sourced_proxy_export_is_a_lead_with_target(library, entry):
    command = f'rundll32.exe {library}.dll,{entry} C:\\Tools\\sample.target'
    [match] = run(Rundll32Execution(), [proc('rundll32.exe', command, 'C:\\Users\\alice\\')])
    assert match.proposed_lane == 'lead'
    assert entry in match.claim and r'C:\Tools\sample.target' in match.claim
    assert 'resolved through the DLL search order' in match.claim and 'user-writable' not in match.claim
    assert any('lolbas-project.github.io/lolbas/Libraries/' in n for n in match.notes)


@pytest.mark.parametrize('target,expected', [(r'C:\Users\Public\settings.cpl', True),
    (r'C:\Windows\System32\desk.cpl', False), ('desk.cpl', False), (r'.\settings.cpl', True)])
def test_r4_b_n5_control_panel_proxy_requires_outside_system_cpl(target, expected):
    matches = run(Rundll32Execution(), [proc('rundll32.exe', 'rundll32.exe shell32.dll,Control_RunDLL ' + target,
                                           'C:\\Users\\alice\\')])
    assert bool(matches) == expected
    if expected:
        assert matches[0].proposed_lane == 'lead'


@pytest.mark.parametrize('module', [None, '-', 'unknown'])
def test_r4_b_m1_no_module_and_no_address_is_lead(module):
    data = {'SourceImage': _SYSTEM + 'csrss.exe', 'TargetImage': _SYSTEM + 'cmd.exe'}
    if module is not None:
        data['StartModule'] = module
    [match], _ = fold(RemoteThreadCreation(), [native(8, data)])
    assert match.proposed_lane == 'lead' and 'start module was not recorded' in match.claim


@pytest.mark.parametrize('extra,reason', [({'StartAddress': '0x1234'}, 'no start module'),
    ({'SourceImage': r'C:\Users\Public\inspect.exe'}, 'system-volume installation'),
    ({'TargetImage': _SYSTEM + 'lsass.exe'}, 'target is lsass.exe')])
def test_r4_b_m1_high_remote_thread_claim_names_the_reason(extra, reason):
    [match], _ = fold(RemoteThreadCreation(), [native(8, {'SourceImage': _SYSTEM + 'csrss.exe',
        'TargetImage': _SYSTEM + 'cmd.exe', **extra})])
    assert match.proposed_lane == 'high' and reason in match.claim and 'high priority because' in match.claim


def test_r4_b_m2_failed_request_missing_process_and_unknown_rights_are_worded_honestly():
    base = {'ObjectType': 'Process', 'ObjectName': _SYSTEM + 'lsass.exe'}
    [failure], _ = fold(LsassProcessAccess(), [native(4656, {**base, 'AccessMask': '0x10'}, outcome='failure')])
    assert 'operation failed' in failure.claim and 'process not recorded' in failure.claim
    assert not any('shows granted access' in text for text in [failure.claim, *failure.notes])
    [unknown], _ = fold(LsassProcessAccess(), [native(4663, base)])
    assert 'memory-related' not in unknown.claim and 'PROCESS_VM_' not in unknown.claim and "by ''" not in unknown.claim


def test_r4_b_m4_accessibility_com_identity_is_sourced_and_shadow_is_high():
    clsid = '{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}'
    name, source = BUILTIN_COM_CLASSES[clsid]
    assert name == 'CAccPropServicesClass' and source.startswith('https://learn.microsoft.com/')
    [match], _ = fold(RegistryUserCom(), [native(13, {'TargetObject': 'HKCU\\Software\\Classes\\CLSID\\' + clsid +
        r'\InprocServer32\{Default}', 'Details': r'C:\Users\Public\component.dll'})])
    assert match.proposed_lane == 'high'


def test_r4_b_m6_fleet_host_list_spills_and_first_per_host_citations_are_bounded(tmp_path):
    rule = ProcessImageTampering()
    rule.spill_dir = tmp_path
    rule.budget = StateBudget(tmp_path, disk_total=16 * 2**20, reserve=0)
    rule.members_store.hot_size = 2
    staged, named, published = {}, {}, {}
    rule.load = lambda ids: [staged[key] for key in ids if key in staged]
    events = [native(25, {'Image': _CHROME, 'Type': 'Image is replaced'}, f'ws{i:04}') for i in range(300)]
    for event in events:
        for match in rule.consume([event]):
            named.update(match.fleet_hosts)
            assert match.fleet_hosts_complete is False
            published[match.group_key] = match
        staged.update({item.id: item for item in rule.drain_staged()})
    [match] = rule.finalize()
    all_hosts = dict(match.fleet_hosts)
    assert match.fleet_hosts_complete is True
    assert named == all_hosts == {event.host: event.id for event in events}
    assert len(published) == 1 and match.fleet_host_count == 300
    assert '280 additional host(s)' in match.claim
    assert {e.id for e in events[:20]} <= {e.id for e in match.events}
    assert len(match.events) <= 22 and rule.members_store.on_disk > 0
    assert len(rule.members_store.hot) <= 2 and not rule.limits
    rule.close_spill()


def test_generic_fleet_names_every_host_and_keeps_own_first_findings(tmp_path):
    rule = LsassProcessAccess()
    rule.spill_dir = tmp_path
    rule.budget = StateBudget(tmp_path, disk_total=16 * 2**20, reserve=0)
    rule.members_store.hot_size = 2
    data = {'SourceImage': _SYSTEM + 'inspect.exe', 'TargetImage': _SYSTEM + 'lsass.exe', 'GrantedAccess': '0x10'}
    events = [native(10, data, f'ws{i:04}') for i in range(30)]
    events.append(native(10, data, 'ws0029'))
    matches, _ = fold(rule, events)
    assert len([m for m in matches if not m.group_key]) == 30
    [fleet] = [m for m in matches if m.group_key]
    assert dict(fleet.fleet_hosts) == {event.host: event.id for event in events[:30]}
    assert fleet.fleet_host_count == 30 and len(fleet.events) <= 22
    assert {event.id for event in events[:20]} <= {event.id for event in fleet.events}
    assert rule.members_store.on_disk > 0 and len(rule.members_store.hot) <= 2
    rule.close_spill()


@pytest.mark.parametrize('row', [None, [1]])
def test_fleet_missing_or_short_member_cannot_silently_finish_a_snapshot(row, monkeypatch):
    rule = ProcessImageTampering()
    matches, _ = fold(rule, [native(25, {'Image': _CHROME, 'Type': 'Image is replaced'}, f'ws{i}')
                             for i in range(2)])
    [match] = matches
    monkeypatch.setattr(rule.members_store, 'peek', lambda key: row)
    with pytest.raises(LookupError, match='Host list for fleet shape .+ at host ws1'):
        list(match.fleet_hosts)
    assert any('fleet_hosts' in str(item) for item in rule.limits)


def test_generic_fleet_withdrawal_snapshot_and_reappearing_host_keep_exact_membership():
    image = r'C:\Program Files\Office\WINWORD.EXE'
    parent = security4688(image=image, command='winword.exe', pid=700, offset=0)
    children = [security4688(image=_SYSTEM + 'cmd.exe', command='cmd.exe /c echo proof',
                            pid=800 + i, ppid=700, offset=5 + i) for i in range(2)]
    ended = security4689(image=image, pid=700, offset=2)
    later_parent = security4688(image=image, command='winword.exe', pid=700, offset=10)
    later_child = security4688(image=_SYSTEM + 'cmd.exe', command='cmd.exe /c echo proof', pid=900, ppid=700, offset=15)
    rule = LureAppSpawnsCodeRunner()
    staged = {event.id: event for event in [parent, *children, ended, later_parent, later_child]}
    rule.load = lambda ids: [staged[key] for key in ids]
    rule.consume([parent, *children])
    rule.drain_staged()
    rule.consume([ended])
    rule.drain_staged()
    [withdrawn] = [m for m in rule.finalize() if m.group_key]
    assert withdrawn.fleet_hosts_complete and withdrawn.fleet_host_count == 0 and not list(withdrawn.fleet_hosts)
    own = rule.consume([later_parent, later_child])
    assert any(not m.group_key and m.proposed_lane == 'high' for m in own)
    rule.drain_staged()
    [current] = [m for m in rule.finalize() if m.group_key]
    assert current.fleet_hosts_complete and current.fleet_host_count == 1
    assert list(current.fleet_hosts) == [(later_child.host, later_child.id)]


@pytest.mark.parametrize('image,lane', [(_SYSTEM + 'inetsrv\\w3wp.exe', 'high'),
    (_SYSTEM + 'cmd.exe', 'lead'), (r'C:\Program Files\Java\bin\java.exe', 'lead')])
@pytest.mark.parametrize('late', [False, True])
def test_encoded_process_uses_recorded_lineage_parent_through_consume(image, lane, late):
    encoded = base64.b64encode('Get-Date'.encode('utf-16le')).decode()
    parent = security4688(image=image, command=image, pid=700, offset=0)
    child = security4688(image=_SYSTEM + 'WindowsPowerShell\\v1.0\\powershell.exe',
        command='powershell.exe -enc ' + encoded, pid=800, ppid=700, offset=5)
    rule = PowerShellEncodedOrCradle()
    matches = run(rule, [[child], [parent]] if late else [[parent], [child]])
    own = [m for m in matches if not m.group_key and any(e.id == child.id for e in m.events)]
    assert own[-1].proposed_lane == lane
    if lane == 'high':
        assert parent.id in {e.id for e in own[-1].events}
        assert 'recorded parent image' in own[-1].claim


def test_encoded_parent_termination_fence_keeps_encoded_only_lead():
    encoded = base64.b64encode('Get-Date'.encode('utf-16le')).decode()
    parent = security4688(image=_SYSTEM + 'inetsrv\\w3wp.exe', command='w3wp.exe', pid=700, offset=0)
    ended = security4689(image=_SYSTEM + 'inetsrv\\w3wp.exe', pid=700, offset=2)
    child = security4688(image=_SYSTEM + 'WindowsPowerShell\\v1.0\\powershell.exe',
        command='powershell.exe -enc ' + encoded, pid=800, ppid=700, offset=5)
    [match] = run(PowerShellEncodedOrCradle(), [parent, ended, child])
    assert match.proposed_lane == 'lead'


def test_encoded_lineage_parent_is_cited_by_the_final_fleet_match():
    encoded = base64.b64encode('Get-Date'.encode('utf-16le')).decode()
    parent = security4688(image=_SYSTEM + 'inetsrv\\w3wp.exe', command='w3wp.exe', pid=700, offset=0)
    children = [security4688(image=_SYSTEM + 'WindowsPowerShell\\v1.0\\powershell.exe',
        command='powershell.exe -enc ' + encoded, pid=800 + i, ppid=700, offset=5 + i) for i in range(3)]
    matches = run(PowerShellEncodedOrCradle(), [[parent], children])
    fleet = next(m for m in matches if m.group_key)
    assert fleet.proposed_lane == 'high' and parent.id in fleet.context_ids
    assert parent.id in {event.id for event in fleet.events}
    assert any(p.field == 'process.parent.executable_key' and ':lineage:' in p.origin for p in fleet.predicate)


@pytest.mark.parametrize('source', ['Get-Date', 'Invoke-WebRequest $url -OutFile $f; & $f'])
def test_encoded_only_or_start_request_stays_lead_through_fleet_fold(source):
    encoded = base64.b64encode(source.encode('utf-16le')).decode()
    events = [proc('powershell.exe', 'powershell.exe -enc ' + encoded) for _ in range(4)]
    matches = run(PowerShellEncodedOrCradle(), events)
    assert matches and all(m.proposed_lane == 'lead' for m in matches)
    assert any(m.group_key for m in matches)
