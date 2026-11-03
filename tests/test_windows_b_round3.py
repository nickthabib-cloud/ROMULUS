"""Production-envelope regressions for Windows behavior lanes and fleet classes."""
import itertools

import pytest

from romulus.detect.bounded import StateBudget
from romulus.detect.windows_endpoint_events import (
    AdminShareTransfer,
    GppPolicyFileAccess,
    RemoteManagementPipe,
)
from romulus.detect.windows_file_events import (
    ExecutableAlternateStream,
    ExecutableCreationTimeChange,
    LureApplicationFileWrite,
    StartupFileWrite,
    WebRootFileWrite,
    WritableExecutableDeletion,
)
from romulus.detect.windows_memory_events import (
    DumpLibraryLoad,
    LsassProcessAccess,
    ProcessImageTampering,
    RemoteThreadCreation,
    UnexpectedClrLoad,
    WritableUnsignedDllLoad,
)
from romulus.detect.windows_registry_events import RegistryDefender, RegistryUserCom
from romulus.evidence.windows import normalize_windows
from romulus.evidence.windows_catalog import SECURITY, SYSMON, SYSMON_CHANNEL
from tests.windows_fixtures import LogicalWindowsEvent, windows_hit

_IDS = itertools.count(300000)
_ONEDRIVE = '{CB3D0F55-BC2C-4C1A-85ED-23ED75B5106B}'
_BUILTIN = '{42aedc87-2188-41fd-b9a3-0c966feabec1}'


def native(code, data, host='ws01', shipper='winlogbeat_8', outcome=None):
    provider, channel = (SECURITY, 'Security') if code == 5145 else (SYSMON, SYSMON_CHANNEL)
    hit = windows_hit(LogicalWindowsEvent(
        channel, provider, code, host, next(_IDS), '2026-01-02T03:00:00Z', data), shipper)
    if outcome is not None:
        hit['_source'].setdefault('event', {})['outcome'] = outcome
    return normalize_windows(hit)


def fold(rule, events):
    """Retain exactly the records the production staging protocol asks to retain."""
    staged = {}
    rule.load = lambda ids: [staged[key] for key in ids if key in staged]
    published = {}
    for event in events:
        matches = rule.consume([event])
        staged.update({item.id: item for item in rule.drain_staged()})
        for match in matches:
            published[match.group_key or match.events[0].id] = match
    for match in rule.finalize():
        published[match.group_key or match.events[0].id] = match
    return list(published.values()), staged


@pytest.mark.parametrize('product,image', [('Windows Defender', 'MsMpEng.exe'),
    ('Windows Defender Advanced Threat Protection', 'MsSense.exe')])
@pytest.mark.parametrize('mask', ['0x1010', '0x1410', '0x1fffff'])
def test_b2_n1_protected_platform_paths_are_leads_and_versions_fold(product, image, mask):
    events = [native(10, {'SourceImage': fr'C:\ProgramData\Microsoft\{product}\Platform\{version}\{image}',
        'TargetImage': r'C:\Windows\System32\lsass.exe', 'GrantedAccess': mask,
        'CallTrace': r'C:\Windows\System32\ntdll.dll+123'})
        for version in ['4.18.24090.11-0', '4.18.25010.7-0']]
    rule = LsassProcessAccess()
    assert all(rule.judge(item)[0].lane == 'lead' for item in events)
    assert rule.judge(events[0])[0].content == rule.judge(events[1])[0].content
    assert '24090' not in rule.judge(events[0])[0].content


@pytest.mark.parametrize('path', [r'C:\ProgramData\x\MsMpEng.exe',
    r'C:\ProgramData\Microsoft\Windows Defender\x.exe',
    r'C:\ProgramData\Microsoft\Windows Defender\Platform\not-a-version\MsMpEng.exe',
    r'C:\Windows\System32\spool\drivers\color\x.exe'])
def test_b2_n1_familiar_names_outside_platform_grammar_do_not_lower_lane(path):
    assert LsassProcessAccess().judge(native(10, {'SourceImage': path,
        'TargetImage': r'C:\Windows\System32\lsass.exe', 'GrantedAccess': '0x1010'}))[0].lane == 'high'


@pytest.mark.parametrize('prefix', [r'\\?\C:', r'\Device\HarddiskVolume3', 'C:'])
def test_b2_n1_platform_volume_spellings_are_path_scope(prefix):
    hit = LsassProcessAccess().judge(native(10, {'SourceImage': prefix +
        r'\PROGRAMDATA\Microsoft\Windows Defender\Platform\4.18.24090.11-0\anything.exe',
        'TargetImage': r'C:\Windows\System32\lsass.exe', 'GrantedAccess': '0x1010'}))[0]
    assert hit.lane == ('high' if prefix.startswith('\\Device') else 'lead')


@pytest.mark.parametrize('tail,value', [(r'Features\TamperProtection', 4), (r'Spynet\SpynetReporting', 0),
    (r'Spynet\SubmitSamplesConsent', 2),
    (r'Windows Defender Exploit Guard\ASR\Rules\d4f940ab-401b-4efc-aadc-ad5f3c50688a', 0)])
def test_b2_n2_nonpolicy_defender_settings_remain_leads(tail, value):
    ev = native(13, {'EventType': 'SetValue', 'TargetObject': r'HKLM\Software\Microsoft\Windows Defender' + '\\' + tail,
                     'Details': f'DWORD (0x{value:08x})'})
    assert RegistryDefender().judge(ev)[0].lane == 'lead'


def test_b2_n2_signature_bookkeeping_excluded_but_policy_and_exclusions_keep_lanes():
    for tail in [r'Signature Updates\AVSignatureVersion', r'Signature Updates\ASSignatureVersion']:
        assert not RegistryDefender().judge(native(13, {'TargetObject': r'HKLM\Software\Microsoft\Windows Defender' + '\\' + tail,
            'Details': '1.2.3.4'}))
    for root in [r'HKLM\Software\Microsoft', r'HKLM\Software\Policies\Microsoft']:
        for tail in [r'Exclusions\Paths\C:\Temp', r'Exclusions\Processes\x.exe',
                     r'Real-Time Protection\DisableRealtimeMonitoring']:
            ev = native(13, {'TargetObject': root + r'\Windows Defender' + '\\' + tail,
                'Details': 'DWORD (0x00000000)' if 'Exclusions' in tail else 'DWORD (0x00000001)'})
            assert RegistryDefender().judge(ev)[0].lane == 'high'
    policy = native(13, {'TargetObject': r'HKLM\Software\Policies\Microsoft\Windows Defender\Spynet\SpynetReporting',
                        'Details': 'DWORD (0x00000000)'})
    assert RegistryDefender().judge(policy)[0].lane == 'lead'


@pytest.mark.parametrize('shipper', ['winlogbeat_7', 'winlogbeat_8', 'elastic_agent'])
@pytest.mark.parametrize('tail', [r'Exclusions\Paths\C:\Users\Public\payloads',
                               r'Exclusions\Processes\payload.exe'])
def test_b2_n2_nonpolicy_and_matching_policy_exclusions_are_high(shipper, tail):
    for root, expected in [(r'HKLM\Software\Microsoft', 'high'),
                           (r'HKLM\Software\Policies\Microsoft', 'high')]:
        ev = native(13, {'EventType': 'SetValue', 'TargetObject': root + r'\Windows Defender' + '\\' + tail,
                         'Details': 'DWORD (0x00000000)'}, shipper=shipper)
        hit = RegistryDefender().judge(ev)[0]
        assert hit.lane == expected
        assert any(item.field == 'registry.path_key' for item in hit.predicate)
        assert any(item.field == 'registry.value' for item in hit.predicate)


@pytest.mark.parametrize('value', [0, 1])
def test_b2_n2_nonpolicy_protection_setting_writes_stay_observations(value):
    event = native(13, {'TargetObject': r'HKLM\Software\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring',
                       'Details': f'DWORD (0x{value:08x})'})
    hit = RegistryDefender().judge(event)[0]
    assert hit.lane == ('high' if value == 1 else 'lead')
    if value == 0:
        assert 'effective protection impact unknown' in hit.text


def test_b2_n1_short_alias_is_not_guessed_to_be_a_protected_platform_root():
    event = native(10, {'SourceImage': r'C:\PROGRA~3\Microsoft\WINDOW~1\Platform\4.18.24090.11-0\MsMpEng.exe',
        'TargetImage': r'C:\Windows\System32\lsass.exe', 'GrantedAccess': '0x1010'})
    assert LsassProcessAccess().judge(event)[0].lane == 'high'


def com(clsid=_ONEDRIVE, value=r'C:\ProgramData\x.dll', root=r'HKCU\Software\Classes', kind='InprocServer32', host='ws01'):
    return native(13, {'TargetObject': root + '\\CLSID\\' + clsid + '\\' + kind + r'\(Default)',
                       'Details': value}, host)


def test_b2_n3_onedrive_three_users_hosts_two_versions_is_one_cited_lead():
    events = [com(value=fr'C:\Users\{user}\AppData\Local\Microsoft\OneDrive\{version}\FileSyncShell64.dll',
        root=fr'HKU\S-1-5-21-1-2-3-{1000+i}_Classes', host=f'ws{i}')
        for i, user in enumerate(['alice', 'bob', 'carol']) for version in ['24.201.1006.0005', '24.211.1020.0001']]
    rule = RegistryUserCom()
    first = rule.consume([events[0]])
    assert len(first) == 1 and first[0].proposed_lane == 'lead' and first[0].group_key
    matches, staged = fold(RegistryUserCom(), events)
    assert len(matches) == 1 and matches[0].proposed_lane == 'lead'
    assert '6 Windows event record(s)' in matches[0].claim and '3 host(s)' in matches[0].claim
    assert {item.host for item in matches[0].events} == {'ws0', 'ws1', 'ws2'}
    assert all(item.id in staged for item in matches[0].events)


@pytest.mark.parametrize('root', [r'HKU\S-1-5-21-1-2-3-1001_Classes', r'HKCU\Software\Classes\Wow6432Node',
                                 r'HKCU\Software\Wow6432Node\Classes'])
@pytest.mark.parametrize('kind,value', [('InprocServer32', r'C:\Users\a\evil.dll'),
    ('TreatAs', '{11111111-2222-3333-4444-555555555555}')])
def test_b2_n3_sourced_builtin_shadow_high_but_unknown_programdata_is_lead(root, kind, value):
    assert RegistryUserCom().judge(com(_BUILTIN, value, root, kind))[0].lane == 'high'
    assert RegistryUserCom().judge(com())[0].lane == 'lead'


@pytest.mark.parametrize('path', [r'C:\Windows\System32\wlbsctrl.dll', r'C:\Windows\System32\spool\drivers\color\x.dll',
    r'C:\Windows\System32\Tasks\x.dll', r'C:\Windows\Tasks\x.dll', r'C:\Windows\Temp\x.dll',
    r'C:\Windows\Tracing\x.dll', r'C:\Program Files\App\x.dll'])
def test_b2_i1_unsigned_install_tree_modules_surface_but_valid_system_load_does_not(path):
    ev = native(7, {'Image': r'C:\Windows\System32\svchost.exe', 'ImageLoaded': path,
        'Signed': 'false', 'SignatureStatus': 'Unavailable'})
    assert WritableUnsignedDllLoad().judge(ev)[0].lane in {'lead', 'high'}
    assert not WritableUnsignedDllLoad().judge(native(7, {'Image': r'C:\Windows\System32\svchost.exe',
        'ImageLoaded': r'C:\Windows\System32\kernel32.dll', 'Signed': 'true', 'SignatureStatus': 'Valid',
        'Signature': 'Microsoft Windows'}))


def test_b2_i2_thousand_chrome_cache_files_fold_and_code_extensions_remain_distinct():
    writer = r'C:\Program Files\Google\Chrome\Application\chrome.exe'
    events = [native(11, {'Image': writer, 'TargetFilename': fr'C:\Users\alice\AppData\Local\Google\Chrome\User Data\Default\Cache\Cache_Data\f_{i:06x}'}) for i in range(1000)]
    matches, _ = fold(LureApplicationFileWrite(), events)
    assert len(matches) == 1 and '1000 Windows event record(s)' in matches[0].claim
    assert matches[0].proposed_lane == 'lead'
    assert len(matches[0].events) <= 10
    assert any('Citation coverage is partial' in note for note in matches[0].notes)
    for suffix in ['.exe', '.dll', '.ps1', '.aspx']:
        ev = native(11, {'Image': writer, 'TargetFilename': r'C:\Users\alice\Downloads\payload' + suffix})
        assert LureApplicationFileWrite().consume([ev])
    contents = {LureApplicationFileWrite().judge(native(11, {'Image': writer,
        'TargetFilename': r'C:\Users\alice\Downloads\payload' + suffix}))[0].content for suffix in ['.exe', '.dll', '.ps1', '.aspx']}
    assert len(contents) == 4
    startup = native(11, {'Image': writer, 'TargetFilename': r'C:\Users\alice\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\x.exe'})
    assert StartupFileWrite().consume([startup])


def test_b2_i2_default_iis_aspx_and_static_webroot_files_have_own_findings():
    writer = r'C:\Windows\System32\inetsrv\w3wp.exe'
    script = native(11, {'Image': writer, 'TargetFilename': r'C:\inetpub\wwwroot\shell.aspx'})
    rule = WebRootFileWrite()
    assert rule.consume([script])[0].proposed_lane == 'lead'
    static = [native(11, {'Image': writer, 'TargetFilename': fr'C:\inetpub\wwwroot\image{i}.png'}) for i in range(30)]
    matches, _ = fold(WebRootFileWrite(), [script, *static])
    assert len(matches) == 31 and all(not match.group_key for match in matches)
    assert rule.judge(script)[0].content != rule.judge(static[0])[0].content
    assert 'execution is not established' in rule.judge(script)[0].text
    for path in [r'C:\backup\inetpub\wwwroot\shell.aspx', r'C:\inetpub\wwwroot_backup\shell.aspx',
                 r'\\host\share\inetpub\wwwroot\shell.aspx']:
        assert not rule.judge(native(11, {'Image': writer, 'TargetFilename': path}))


def test_b2_i2_code_directory_instances_keep_first_host_findings_and_basename_content():
    events = [native(11, {'Image': fr'C:\Users\{user}\AppData\Local\Browser\{version}\chrome.exe',
        'TargetFilename': fr'C:\Users\{user}\AppData\Local\Temp\{{{guid}}}\{version}\{i:032x}\file{i}.exe'}, host=f'ws{i}')
        for i, (user, version, guid) in enumerate([
            ('alice', '23.1.2.3', '11111111-2222-3333-4444-555555555555'),
            ('bob', '24.2.3.4', 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee')])]
    matches, _ = fold(LureApplicationFileWrite(), events)
    assert len(matches) == 2 and all(not match.group_key for match in matches)
    assert {event.host for match in matches for event in match.events} == {'ws0', 'ws1'}
    assert all(field in {item.field for item in matches[0].predicate}
               for field in ['file.path', 'process.executable'])


@pytest.mark.parametrize('rule,code,writer,path,extra', [
    (ExecutableAlternateStream, 15, r'C:\Program Files\Google\Chrome\Application\chrome.exe',
     r'C:\Users\alice\Downloads\report{}.pdf:Zone.Identifier', {'Contents': '[ZoneTransfer] ZoneId=3 HostUrl=https://example.test/{}'}),
    (WritableExecutableDeletion, 23, r'C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE',
     r'C:\Users\alice\AppData\Local\Temp\~WRS{:04x}.tmp', {}),
    (ExecutableCreationTimeChange, 2, r'C:\Program Files\7-Zip\7zFM.exe', r'C:\Users\alice\Documents\x\readme{}.txt',
     {'CreationUtcTime': '2020-01-01 00:00:00.000', 'PreviousCreationUtcTime': '2026-01-02 03:00:00.000'}),
])
def test_b2_i2_benign_stream_delete_and_archive_timestamp_classes_fold(rule, code, writer, path, extra):
    events = [native(code, {'Image': writer, 'TargetFilename': path.format(i),
        'Hashes': f'SHA256={i:064x},IMPHASH=' + '0' * 32,
        **{name: value.format(i) for name, value in extra.items()}}) for i in range(20)]
    matches, _ = fold(rule(), events)
    assert len(matches) == 1 and matches[0].proposed_lane == 'lead'
    assert '20 Windows event record(s)' in matches[0].claim


@pytest.mark.parametrize('pipe', ['samr', 'lsarpc', 'svcctl', 'atsvc', 'drsuapi'])
def test_b2_i3_management_fanout_folds_by_pipe_outcome_account_class_and_counts_ips(pipe):
    events = [native(5145, {'ShareName': r'\\*\IPC$', 'RelativeTargetName': pipe, 'AccessMask': '0x12019F',
        'SubjectUserName': f'WS{i}$', 'SubjectDomainName': 'EXAMPLE', 'IpAddress': f'10.0.{i//254}.{i%254+1}'}) for i in range(200)]
    matches, _ = fold(RemoteManagementPipe(), events)
    assert all(match.proposed_lane == 'lead' for match in matches)
    if pipe in {'svcctl', 'atsvc'}:
        assert len(matches) == 200 and all(not match.group_key for match in matches)
    else:
        assert len(matches) == 1
        assert '200 distinct source IP' in matches[0].claim and 'machine account' in matches[0].claim
    user = native(5145, {'ShareName': r'\\*\IPC$', 'RelativeTargetName': pipe, 'AccessMask': '0x12019F',
        'SubjectUserName': 'administrator', 'IpAddress': '10.0.0.1'})
    assert RemoteManagementPipe().judge(user)[0].content != RemoteManagementPipe().judge(events[0])[0].content


def test_b2_i3_gpp_fanout_folds_sources_and_policy_guids():
    events = [native(5145, {'ShareName': r'\\*\SYSVOL', 'RelativeTargetName':
        fr'corp.example\Policies\{{31B2F340-016D-11D2-945F-{i:012x}}}\Machine\Preferences\Groups\Groups.xml',
        'AccessMask': '0x120089', 'SubjectUserName': f'WS{i}$', 'IpAddress': f'10.0.0.{i+1}'}) for i in range(200)]
    matches, _ = fold(GppPolicyFileAccess(), events)
    assert len(matches) == 1 and '200 distinct source IP' in matches[0].claim


def test_b2_i3_source_cardinality_spills_and_repeated_ips_do_not_inflate_count(tmp_path):
    rule = RemoteManagementPipe()
    rule.spill_dir = tmp_path
    rule.budget = StateBudget(tmp_path, disk_total=16*2**20, reserve=0)
    rule.members_store.hot_size = 2
    events = [native(5145, {'ShareName': r'\\*\IPC$', 'RelativeTargetName': 'samr', 'AccessMask': '0x12019F',
        'SubjectUserName': f'WS{i}$', 'IpAddress': f'10.0.0.{i+1}'}) for i in range(200)]
    events += [native(5145, {'ShareName': r'\\*\IPC$', 'RelativeTargetName': 'samr', 'AccessMask': '0x12019F',
        'SubjectUserName': 'DUPLICATE$', 'IpAddress': '10.0.0.1'}) for _ in range(20)]
    matches, _ = fold(rule, events)
    assert len(matches) == 1 and '200 distinct source IP' in matches[0].claim
    assert '220 Windows event record(s)' in matches[0].claim
    assert rule.members_store.on_disk > 0 and len(rule.members_store.hot) <= 2
    assert not rule.limits
    rule.close_spill()


@pytest.mark.parametrize('rule,share,path', [
    (RemoteManagementPipe, 'IPC$', 'samr'),
    (GppPolicyFileAccess, 'SYSVOL', r'corp.example\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Preferences\Groups\Groups.xml'),
])
def test_b2_i3_failed_and_successful_access_checks_do_not_fold_together(rule, share, path):
    data = {'ShareName': '\\\\*\\' + share, 'RelativeTargetName': path, 'AccessMask': '0x12019F',
            'SubjectUserName': 'WORKSTATION$', 'IpAddress': '10.0.0.1'}
    good, failed = [native(5145, data, outcome=value) for value in ['success', 'failure']]
    assert rule().judge(good)[0].content != rule().judge(failed)[0].content
    assert 'failed' in rule().judge(failed)[0].text
    matches, _ = fold(rule(), [good, failed])
    assert len(matches) == 2


@pytest.mark.parametrize('access,write,no_signal', [
    ('%%4416', False, True), ('%%4417', True, False), ('%%4418', True, False),
    ('%%4419', False, True), ('%%4420', False, False), ('%%4421', False, True),
    ('%%4422', False, False), ('%%4423', False, True), ('%%4424', False, False),
    ('%%1537', False, False), ('%%1538', False, True), ('%%1539', False, False),
    ('%%1540', False, False), ('%%1541', False, True), ('%%1542', False, False),
])
def test_b2_m1_every_normalized_file_access_name_has_honest_transfer_wording(access, write, no_signal):
    hits = AdminShareTransfer().judge(native(5145, {'ShareName': r'\\*\ADMIN$',
        'RelativeTargetName': 'x.exe', 'AccessList': access}))
    if no_signal:
        assert not hits
    else:
        assert ('write/append access' in hits[0].text) is write


def test_b2_n3_treatas_targets_stay_distinct_and_progid_redirects_are_observed():
    values = ['{11111111-2222-3333-4444-555555555555}', '{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}']
    hits = [RegistryUserCom().judge(com(_BUILTIN, value, kind='TreatAs'))[0] for value in values]
    assert hits[0].content != hits[1].content
    assert all(item.lane == 'high' for item in hits)
    for root in [r'HKCU\Software\Classes', r'HKCU\Software\Classes\Wow6432Node',
                 r'HKCU\Software\Wow6432Node\Classes']:
        ev = native(13, {'TargetObject': root + r'\Example.Application\CLSID\(Default)', 'Details': _BUILTIN})
        hit = RegistryUserCom().judge(ev)[0]
        assert hit.lane == 'lead' and 'ProgID redirection' in hit.text


def test_b2_scratchpad_companion_lookalikes_preserve_positive_only_meaning():
    # Exact companion shapes from probe_b.py: an unknown COM class does not
    # establish a shadow even when its LocalServer32 value names a system utility.
    value = r'C:\Windows\System32\rundll32.exe C:\Users\alice\evil.dll,Run'
    assert RegistryUserCom().judge(com(value=value, kind='LocalServer32'))[0].lane == 'lead'
    assert not RemoteManagementPipe().judge(native(5145, {'ShareName': r'\\*\IPC$',
        'RelativeTargetName': 'samr', 'AccessMask': '0x1'}))
    rename = native(14, {'EventType': 'RenameKey', 'TargetObject': r'HKCU\Software\X',
        'NewName': r'HKU\S-1-5-21-1-2-3-1001\Software\Microsoft\Windows\CurrentVersion\Run'})
    from romulus.detect.windows_registry_events import RegistryRunKeys
    assert 'renamed' in RegistryRunKeys().judge(rename)[0].text


def test_b2_shared_install_scope_keeps_dump_library_and_clr_claims_narrow():
    dll = {'ImageLoaded': r'C:\Windows\System32\comsvcs.dll', 'Signed': 'true', 'SignatureStatus': 'Valid'}
    for source in [r'C:\Windows\System32\rundll32.exe',
        r'C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24090.11-0\MsMpEng.exe']:
        assert not DumpLibraryLoad().judge(native(7, {'Image': source, **dll}))
    assert DumpLibraryLoad().judge(native(7, {'Image': r'C:\ProgramData\x\MsMpEng.exe', **dll}))[0].lane == 'lead'
    root = r'\\?\Volume{11111111-2222-3333-4444-555555555555}'
    clr = {'Image': root + r'\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
           'ImageLoaded': root + r'\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll',
           'Signed': 'true', 'SignatureStatus': 'Valid'}
    assert UnexpectedClrLoad().judge(native(7, clr))[0].lane == 'lead'
    assert UnexpectedClrLoad().judge(native(7, {**clr, 'Signed': 'false'}))[0].lane == 'lead'


@pytest.mark.parametrize('shipper', ['winlogbeat_7', 'winlogbeat_8', 'elastic_agent'])
@pytest.mark.parametrize('access', ['%%4417', '%%4416\n\t%%4417', 'WriteData (or AddFile)',
    '%%4418', 'AppendData (or AddSubdirectory)'])
def test_b2_m1_normalized_accesses_claim_write_and_read_only_never_does(shipper, access):
    data = {'ShareName': r'\\*\ADMIN$', 'RelativeTargetName': 'x.exe', 'AccessList': access}
    hit = AdminShareTransfer().judge(native(5145, data, shipper=shipper))[0]
    assert 'write/append access' in hit.text
    assert not AdminShareTransfer().judge(native(5145, {**data, 'AccessList': '%%4416'}, shipper=shipper))


@pytest.mark.parametrize('image', [r'C:\Users\alice\AppData\Local\Programs\Microsoft VS Code\Code.exe',
                                 r'C:\Windows\System32\svchost.exe'])
def test_b2_i4_tampering_type_determines_lane_for_electron_and_system_images(image):
    assert ProcessImageTampering().judge(native(25, {'Image': image, 'Type': 'Image is replaced'}))[0].lane == 'high'
    assert ProcessImageTampering().judge(native(25, {'Image': image, 'Type': 'Image is locked for access'}))[0].lane == 'lead'


def test_b2_m3_missing_module_is_unresolved_but_recorded_dash_is_a_cited_marker():
    data = {'SourceImage': r'C:\Windows\System32\csrss.exe', 'TargetImage': r'C:\Windows\System32\cmd.exe'}
    missing = RemoteThreadCreation().judge(native(8, data))[0]
    marker = RemoteThreadCreation().judge(native(8, {**data, 'StartModule': '-'}))[0]
    assert missing.lane == 'lead' and 'not recorded' in missing.text
    assert marker.lane == 'lead' and 'not recorded' in marker.text
    assert any(item.field == 'thread.start_module' and item.value == '-' for item in marker.predicate)
