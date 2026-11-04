"""Native Windows application records retain precise positive claims and lanes."""
import importlib
import itertools
from datetime import UTC, datetime, timedelta

import pytest

from romulus.evidence.windows import normalize_windows
from romulus.evidence.windows_catalog import SECURITY
from tests.windows_fixtures import LogicalWindowsEvent, windows_hit
from tests.windows_process_support import run

IDS = itertools.count(820000)
START = datetime(2026, 1, 2, tzinfo=UTC)
LSP = 'Microsoft-Windows-Winsock-WS2HELP'


def native(provider, code, data, *, host='ws01', offset=0, channel='Application'):
    hit = windows_hit(LogicalWindowsEvent(channel, provider, code, host, next(IDS),
        (START + timedelta(seconds=offset)).isoformat(), data), 'winlogbeat_8')
    hit['_source']['winlog']['event_id'] = str(code)
    hit['_source']['event'] = {'code': str(code)}
    hit['_source']['winlog'].pop('time_created', None)
    return normalize_windows(hit)


def rule(name):
    return getattr(importlib.import_module('romulus.detect.windows_catalog_events'), name)()


CASES = [
    ('SilentProcessExitLsass', 'Microsoft-Windows-ProcessExitMonitor', 3001,
     {'param1': r'C:\Windows\System32\lsass.exe', 'param2': r'C:\Users\u\monitor.exe', 'param3': '0'},
     'high', 'termination'),
    ('MssqlXpCmdshellEnabled', 'MSSQLSERVER', 15457,
     {'param1': 'xp_cmdshell', 'param2': '0', 'param3': '1'}, 'high', 'from 0 to 1'),
    ('MssqlXpCmdshellDisabled', 'MSSQL$INSTANCE', 15457,
     {'param1': 'xp_cmdshell', 'param2': '1', 'param3': '0'}, 'lead', 'from 1 to 0'),
    ('MssqlXpCmdshellExec', 'MSSQLSERVER', 33205,
     {'param1': 'action_id:EX  \nsucceeded:true\nobject_name:xp_cmdshell\nstatement:EXEC xp_cmdshell test\ndatabase_name:master'},
     'high', 'execute operation'),
    ('MssqlXpCmdshellBlocked', 'MSSQLSERVER', 15281,
     {'param6': 'xp_cmdshell'}, 'lead', 'blocked'),
    ('BootConfigIntegrityDisabled', SECURITY, 4826,
     {'KernelDebug': '%%1842', 'TestSigning': '%%1843'}, 'high', 'kernel debugging'),
    ('NtdsDatabaseCopy', 'ESENT', 325,
     {'param1': 'NTDS', 'param2': '123', 'param5': r'C:\Users\u\copy\ntds.dit'}, 'high', 'created'),
    ('NtdsDatabaseCopy', 'ESENT', 327,
     {'param1': 'NTDS', 'param2': '123', 'param5': r'C:\copy\ntds.dit'}, 'lead', 'detached'),
    ('LspInstalled', LSP, 1, {'LSPName': 'Example proxy', 'Installer': r'C:\Windows\System32\msiexec.exe',
      'Catalog': '64'}, 'lead', 'installed'),
    ('LspInstalled', LSP, 1, {'LSPName': 'Example proxy', 'Installer': r'C:\Users\u\setup.exe',
      'Catalog': '32'}, 'high', 'installed'),
    ('MsiInstallFromUrl', 'MsiInstaller', 1040,
     {'param1': 'https://example.test/package.msi', 'param2': '123'}, 'lead', 'began'),
    ('MsiInstallFromUrl', 'MsiInstaller', 1042,
     {'param1': 'https://example.test/package.msi', 'param2': '123'}, 'lead', 'ended'),
]


def event_for(provider, code, data, **kwargs):
    channel = 'Security' if provider == SECURITY else LSP + '/Operational' if provider == LSP else 'Application'
    return native(provider, code, data, channel=channel, **kwargs)


@pytest.mark.parametrize('name,provider,code,data,lane,text', CASES)
@pytest.mark.parametrize('offset', [0, 600])
def test_native_catalog_positive_claim_lane_and_boundary(name, provider, code, data, lane, text, offset):
    instance = rule(name)
    event = event_for(provider, code, data, offset=offset)
    [match] = run(instance, [event])
    assert match.proposed_lane == lane
    assert text in match.claim
    assert match.events[0].id == event.id
    assert match.ts == event.ts
    assert match.predicate
    instance.release_state()


@pytest.mark.parametrize('name,provider,code,data', [
    ('SilentProcessExitLsass', 'Microsoft-Windows-ProcessExitMonitor', 3001,
     {'param1': r'C:\Windows\notepad.exe', 'param2': r'C:\lsass.exe'}),
    ('MssqlXpCmdshellEnabled', 'MSSQLSERVER', 15457,
     {'param1': 'show advanced options', 'param2': '0', 'param3': '1'}),
    ('MssqlXpCmdshellEnabled', 'MSSQLSERVER', 15457,
     {'param1': 'xp_cmdshell', 'param2': '1', 'param3': '0'}),
    ('MssqlXpCmdshellExec', 'MSSQLSERVER', 33205,
     {'param1': 'action_id:LGIS\nobject_name:xp_cmdshell\nstatement:login'}),
    ('MssqlXpCmdshellExec', 'MSSQLSERVER', 33205,
     {'param1': 'action_id:EX\nobject_name:other\nstatement:xp_cmdshell'}),
    ('MssqlXpCmdshellBlocked', 'MSSQLSERVER', 15281, {'param6': 'other', 'param1': 'xp_cmdshell'}),
    ('BootConfigIntegrityDisabled', SECURITY, 4826,
     {'KernelDebug': '%%1843', 'TestSigning': '%%1843', 'HypervisorDebug': '%%1843'}),
    ('BootConfigIntegrityDisabled', SECURITY, 4826, {'KernelDebug': '%%9999'}),
    ('NtdsDatabaseCopy', 'ESENT', 325, {'param5': r'C:\Windows\edb.log', 'param1': 'ntds.dit'}),
    ('MsiInstallFromUrl', 'MsiInstaller', 1040, {'param1': r'C:\Program Files\Example\package.msi'}),
    ('MsiInstallFromUrl', 'MsiInstaller', 1040, {'param1': '{00000000-0000-0000-0000-000000000000}'}),
    ('MsiInstallFromUrl', 'MsiInstaller', 1042, {'param1': r'C:\Program Files\Example\package.msi'}),
])
def test_native_catalog_hard_negatives(name, provider, code, data):
    instance = rule(name)
    assert run(instance, [event_for(provider, code, data)]) == []
    instance.release_state()


@pytest.mark.parametrize('name,provider,code,data,lane,text', CASES)
def test_missing_native_required_fields_are_named(name, provider, code, data, lane, text):
    instance = rule(name)
    event = event_for(provider, code, {})
    assert instance.consume([event]) == []
    assert instance.missing_required or instance.limits or instance.coverage_notes
    instance.release_state()


def test_boot_claim_never_invents_a_disabled_or_unknown_setting():
    instance = rule('BootConfigIntegrityDisabled')
    [match] = run(instance, [event_for(SECURITY, 4826,
        {'KernelDebug': '%%1842', 'TestSigning': '%%1843', 'HypervisorDebug': '%%9999'})])
    assert 'kernel debugging' in match.claim
    assert 'test signing' not in match.claim and 'hypervisor debugging' not in match.claim
    instance.release_state()


def test_failed_sql_execute_is_an_attempt_not_success():
    instance = rule('MssqlXpCmdshellExec')
    [match] = run(instance, [event_for('MSSQLSERVER', 33205,
        {'param1': 'action_id:EX\nsucceeded:false\nobject_name:xp_cmdshell'})])
    assert match.proposed_lane == 'lead' and 'attempt' in match.claim
    instance.release_state()


@pytest.mark.parametrize('path', [r'\Device\HarddiskVolume1\Windows\System32\lsass.exe',
                                  r'C:\WINDOWS\SYSTEM32\LSASS.EXE'])
def test_silent_exit_device_and_case_spellings_are_high(path):
    instance = rule('SilentProcessExitLsass')
    [match] = run(instance, [event_for('Microsoft-Windows-ProcessExitMonitor', 3001,
                                    {'param1': path, 'param2': r'C:\monitor.exe'})])
    assert match.proposed_lane == 'high'
    instance.release_state()


def test_shadow_ntds_database_attach_is_high_without_inventing_extraction():
    instance = rule('NtdsDatabaseCopy')
    [match] = run(instance, [event_for('ESENT', 326,
        {'param5': r'C:\$SNAP_EXAMPLE_VOLUMEC$\Windows\NTDS\ntds.dit', 'param2': 'not-a-pid'})])
    assert match.proposed_lane == 'high' and 'pid unrecorded' in match.claim
    assert 'extracted' not in match.claim
    instance.release_state()


@pytest.mark.parametrize('package', ['https://', 'https:///package.msi', '(NULL)', '-'])
def test_malformed_package_never_becomes_a_url_installation(package):
    instance = rule('MsiInstallFromUrl')
    assert run(instance, [event_for('MsiInstaller', 1040, {'param1': package, 'param2': 'bad'})]) == []
    instance.release_state()


@pytest.mark.parametrize('name,provider,code,data,lane,text', CASES)
def test_catalog_folding_runs_through_real_sweep(tmp_path, monkeypatch, name, provider, code, data, lane, text):
    from romulus.hunt import sweep as sw
    from romulus.sources.models import Window
    from tests.test_sweep import _complete, _repo

    instance = rule(name)
    monkeypatch.setattr(sw, 'fresh_pack', lambda: [instance])
    sweep = sw.Sweep(_repo(), None, 'h1', Window(start=START, end=START + timedelta(hours=1)), {}, stage_dir=tmp_path)
    channel = 'Security' if provider == SECURITY else LSP + '/Operational' if provider == LSP else 'Application'
    hits = [windows_hit(LogicalWindowsEvent(channel, provider, code, host, next(IDS),
             (START + timedelta(seconds=offset)).isoformat(), data), 'winlogbeat_8')
            for host, offset in [('host-a', 0), ('host-b', 1), ('host-a', 2)]]
    try:
        monkeypatch.setattr(sw, 'execute', lambda client, intent, contract: _complete(intent, hits))
        sweep.run_partition(hits[0]['_index'], None, [],
                            Window(start=START, end=START + timedelta(hours=1)), est=len(hits))
        sweep.finalize()
        rows = sweep.repo.candidates('h1')
        assert rows and all(row['lane'] == lane for row in rows)
        assert any(text in row['claim'] for row in rows)
        ids = {identity for row in rows for identity in row['event_ids']}
        assert ids and sweep.repo.events_by_ids(ids)
        if name == 'LspInstalled' and lane == 'lead':
            [row] = rows
            members, after = sweep.repo.candidate_hosts(row['id'])
            assert {item['host'] for item in members} == {'host-a', 'host-b'} and not after
        else:
            # Code, sensitive configuration and writable paths keep both hosts' first observations.
            host_set = {event['host'] for event in sweep.repo.events_by_ids(ids)}
            assert {'host-a', 'host-b'} <= host_set
    finally:
        sweep.close_stage()


@pytest.mark.parametrize('name,provider,items,common', [
    ('MsiInstallFromUrl', 'MsiInstaller',
     [(1040, {'param1': 'https://example.test/package.msi', 'param2': '100'}),
      (1042, {'param1': 'https://example.test/package.msi', 'param2': '200'})],
     'A Windows Installer transaction lifecycle record for a package at https://example.test/package.msi'),
    ('NtdsDatabaseCopy', 'ESENT',
     [(325, {'param5': r'C:\backup\ntds.dit', 'param2': '100'}),
      (325, {'param5': r'C:\backup\ntds.dit', 'param2': '200'})],
     r'ESENT recorded an ntds.dit database created at C:\backup\ntds.dit'),
])
def test_folded_claim_names_only_shared_lifecycle_facts(tmp_path, monkeypatch, name, provider, items, common):
    from romulus.hunt import sweep as sw
    from romulus.sources.models import Window
    from tests.test_sweep import _complete, _repo

    instance = rule(name)
    monkeypatch.setattr(sw, 'fresh_pack', lambda: [instance])
    window = Window(start=START, end=START + timedelta(hours=1))
    sweep = sw.Sweep(_repo(), None, 'h1', window, {}, stage_dir=tmp_path)
    hits = [windows_hit(LogicalWindowsEvent('Application', provider, code, host, next(IDS),
              (START + timedelta(seconds=index)).isoformat(), data), 'winlogbeat_8')
            for index, (host, (code, data)) in enumerate(zip(('host-a', 'host-a', 'host-b'),
                                                         (items[0], items[1], items[1])))]
    try:
        monkeypatch.setattr(sw, 'execute', lambda client, intent, contract: _complete(intent, hits))
        sweep.run_partition(hits[0]['_index'], None, [], window, est=len(hits))
        sweep.finalize()
        aggregate = [row for row in sweep.repo.candidates('h1') if 'recurred as the same shape' in row['claim']]
        assert aggregate
        for row in aggregate:
            assert row['claim'].startswith(common + ' recurred')
            assert 'pid 100' not in row['claim'] and 'pid 200' not in row['claim']
            assert '3 Windows event record(s)' in row['claim']
    finally:
        sweep.close_stage()
