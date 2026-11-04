"""Native registry and elevation observations through Windows normalization."""
import importlib
import importlib.util
import itertools
from datetime import UTC, datetime, timedelta

import pytest

from romulus.evidence.windows import normalize_windows
from romulus.evidence.windows_catalog import SYSMON, SYSMON_CHANNEL
from tests.windows_fixtures import LogicalWindowsEvent, windows_hit
from tests.windows_process_support import run

START = datetime(2026, 1, 2, tzinfo=UTC)
IDS = itertools.count(930000)
USER = r'EXAMPLE\analyst'


def rule(name):
    module = 'romulus.detect.windows_elevation_events'
    assert importlib.util.find_spec(module), 'W4b registry/elevation implementation is absent'
    return getattr(importlib.import_module(module), name)()


def native(code, data, offset=0, host='ws01', user=USER):
    data = {'User': user, **data}
    hit = windows_hit(LogicalWindowsEvent(SYSMON_CHANNEL, SYSMON, code, host, next(IDS),
        (START + timedelta(seconds=offset)).isoformat(), data), 'winlogbeat_8')
    hit['_source']['winlog']['event_id'] = str(code)
    hit['_source']['winlog'].pop('time_created', None)
    return normalize_windows(hit), hit


UAC = [r'HKCU\Software\Classes\ms-settings\shell\open\command\(Default)',
       r'HKU\S-1-5-21-1-2-3-1001\Software\Classes\mscfile\shell\open\command\DelegateExecute',
       r'HKCU\Software\Microsoft\Windows\CurrentVersion\App Paths\example.exe\(Default)',
       r'HKCU\Environment\windir', r'HKCU\Volatile Environment\SYSTEMROOT']


@pytest.mark.parametrize('path', UAC)
@pytest.mark.parametrize('payload,lane', [(r'C:\Users\analyst\payload.exe', 'high'), ('example.exe', 'lead')])
def test_native_uac_registry_targets(path, payload, lane):
    owner = rule('UacRegistryHijack')
    [match] = run(owner, [native(13, {'TargetObject': path, 'Details': payload})[0]])
    assert match.proposed_lane == lane and 'registry' in match.claim.casefold()
    owner.release_state()


@pytest.mark.parametrize('path', [r'HKLM\Software\Classes\ms-settings\shell\open\command\(Default)',
    r'HKCU\Software\Classes\other\shell\open\command\(Default)',
    r'HKCU\Software\Classes\ms-settings\shell\open\other\(Default)'])
def test_uac_neighbor_targets_stay_quiet(path):
    owner = rule('UacRegistryHijack')
    assert not run(owner, [native(13, {'TargetObject': path, 'Details': r'C:\Users\u\payload.exe'})[0]])
    owner.release_state()


@pytest.mark.parametrize('action', ['CreateKey', 'DeleteKey'])
def test_uac_sensitive_command_key_changes_are_only_leads(action):
    owner = rule('UacRegistryHijack')
    [match] = run(owner, [native(12, {'TargetObject':
        r'HKCU\Software\Classes\ms-settings\shell\open\command', 'EventType': action})[0]])
    assert match.proposed_lane == 'lead'
    owner.release_state()


@pytest.mark.parametrize('name,path', [
    ('UacRegistryHijack', UAC[0]),
    ('RegistryPersistenceExtension', r'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\DirectoryServiceExtPt')])
def test_missing_payload_preserves_sensitive_target_as_unknown_lead(name, path):
    owner = rule(name)
    [match] = run(owner, [native(13, {'TargetObject': path})[0]])
    assert match.proposed_lane == 'lead' and 'unknown' in match.claim.casefold()
    owner.release_state()


@pytest.mark.parametrize('details,lane,found', [('DWORD (0x00000001)', None, False),
    ('not-a-number', 'lead', True), ('0', 'lead', True)])
def test_uac_policy_reenable_and_untyped_data_do_not_invent_disabling(details, lane, found):
    owner = rule('SecurityControlRegistry')
    matches = run(owner, [native(13, {'TargetObject':
        r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA', 'Details': details})[0]])
    assert bool(matches) == found
    if found:
        assert matches[0].proposed_lane == lane
    owner.release_state()


POLICY = [
    (r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA', 'DWORD (0x00000000)', 13, 'high'),
    (r'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging', 'DWORD (0x00000000)', 13, 'high'),
    (r'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment\__PSLockdownPolicy', '-', 12, 'high'),
    (r'HKCU\Software\Microsoft\Office\16.0\Word\Security\AccessVBOM', 'DWORD (0x00000001)', 13, 'lead'),
    (r'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\NullSessionPipes', 'example', 13, 'lead')]


@pytest.mark.parametrize('path,value,code,lane', POLICY)
def test_security_policy_observations(path, value, code, lane):
    owner = rule('SecurityControlRegistry')
    [match] = run(owner, [native(code, {'TargetObject': path, 'Details': value,
                                       'EventType': 'DeleteValue' if code == 12 else 'SetValue'})[0]])
    assert match.proposed_lane == lane
    assert any('not' in note.casefold() and ('policy' in note.casefold() or 'effective' in note.casefold())
               for note in match.notes)
    owner.release_state()


def test_exact_scriptblock_logging_key_deletion_is_high_with_unknown_effect():
    owner = rule('SecurityControlRegistry')
    neighbor = rule('SecurityControlRegistry')
    path = r'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    try:
        [match] = run(owner, [native(12, {'TargetObject': path, 'EventType': 'DeleteKey'})[0]])
        assert match.proposed_lane == 'high' and 'unknown' in match.claim.casefold()
        assert not run(neighbor, [native(12, {
            'TargetObject': path + r'\Unrelated', 'EventType': 'DeleteKey'})[0]])
    finally:
        owner.release_state()
        neighbor.release_state()


def test_app_paths_search_directory_is_a_configuration_lead():
    owner = rule('UacRegistryHijack')
    try:
        [match] = run(owner, [native(13, {'TargetObject':
            r'HKCU\Software\Microsoft\Windows\CurrentVersion\App Paths\example.exe\Path',
            'Details': r'C:\Users\alice\bin'})[0]])
        assert match.proposed_lane == 'lead'
        assert 'search path' in match.claim.casefold()
    finally:
        owner.release_state()


@pytest.mark.parametrize('payload', ['"C:\\Users\\alice\\payload.exe',
                                    'cmd.exe /c "unterminated'])
def test_unclosed_uac_command_is_an_unknown_lead(payload):
    owner = rule('UacRegistryHijack')
    try:
        [match] = run(owner, [native(13, {'TargetObject': UAC[0], 'Details': payload})[0]])
        assert match.proposed_lane == 'lead' and 'unknown' in match.claim.casefold()
    finally:
        owner.release_state()


@pytest.mark.parametrize('payload', ['"C:\\Users\\alice\\payload.exe"',
                                    'cmd.exe /c "paired"', 'cmd.exe /c literal\\"quote'])
def test_valid_uac_command_quoting_retains_supported_payload_high(payload):
    owner = rule('UacRegistryHijack')
    try:
        [match] = run(owner, [native(13, {'TargetObject': UAC[0], 'Details': payload})[0]])
        assert match.proposed_lane == 'high'
    finally:
        owner.release_state()


PERSIST = [
    (r'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\DirectoryServiceExtPt', r'\\server\share\helper.dll', 'high'),
    (r'HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB\{123}\DatabasePath', r'C:\Windows\AppPatch\Custom\example.sdb', 'high'),
    (r'HKLM\SYSTEM\CurrentControlSet\Control\Print\Printers\Printer\CopyFiles\Example\Module', r'C:\Users\u\helper.dll', 'high'),
    (r'HKLM\Software\Microsoft\Windows NT\CurrentVersion\Ports\Example', 'example.dll', 'lead'),
    (r'HKLM\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\Example\cmdLine', r'C:\Users\u\helper.exe', 'high'),
    (r'HKCU\Software\Microsoft\IEAK\GroupPolicy\PendingGPOs\Example\Path1', r'C:\Example\policy', 'lead'),
    (r'HKCU\Software\Example\SymbolicLinkValue', r'\Registry\Machine\Software\Example', 'lead')]


@pytest.mark.parametrize('path,value', [
    (r'HKLM\Software\Microsoft\Windows NT\CurrentVersion\Print\Printers\Example\CopyFiles\Module', r'C:\Windows\System32\spool\drivers\x64\4\example.dll'),
    (r'HKLM\Software\Microsoft\Windows NT\CurrentVersion\Print\Printers\Example\CopyFiles\Component\Module', 'example.dll'),
    (r'HKLM\Software\Microsoft\Windows NT\CurrentVersion\Ports\C:\Example\example.dll', '(Empty)'),
    (r'HKCU\Software\Microsoft\IEAK\GroupPolicy\PendingGPOs\Path1', r'C:\Example\policy.inf')])
def test_native_additional_registry_views_and_value_name_paths(path, value):
    owner = rule('RegistryPersistenceExtension')
    [match] = run(owner, [native(13, {'TargetObject': path, 'Details': value})[0]])
    assert match.proposed_lane == 'lead'
    owner.release_state()


@pytest.mark.parametrize('path,value,lane', PERSIST)
def test_native_persistence_targets(path, value, lane):
    owner = rule('RegistryPersistenceExtension')
    [match] = run(owner, [native(13, {'TargetObject': path, 'Details': value})[0]])
    assert match.proposed_lane == lane
    assert 'does not establish' in ' '.join(match.notes).casefold()
    owner.release_state()


def child(offset=60, host='ws01', user=USER):
    return native(1, {'Image': r'C:\Windows\System32\cmd.exe', 'CommandLine': 'cmd.exe',
        'ParentImage': r'C:\Windows\System32\fodhelper.exe', 'IntegrityLevel': 'High',
        'ProcessId': '400', 'ParentProcessId': '200',
        'ProcessGuid': '{00000000-0000-0000-0000-000000000400}'}, offset, host, user)


@pytest.mark.parametrize('delta,other_user,lane', [(0, False, 'high'), (600, False, 'high'),
                                               (601, False, 'lead'), (60, True, 'lead')])
@pytest.mark.parametrize('late', [False, True])
def test_real_sweep_elevation_correlation(tmp_path, monkeypatch, delta, other_user, lane, late):
    from romulus.hunt import sweep as sw
    from romulus.sources.models import Window
    from tests.test_sweep import _complete, _repo
    owner = rule('AutoElevatedShell')
    monkeypatch.setattr(sw, 'fresh_pack', lambda: [owner])
    sweep = sw.Sweep(_repo(), None, 'h1', Window(start=START, end=START + timedelta(hours=1)), {}, stage_dir=tmp_path)
    write = native(13, {'TargetObject': UAC[0], 'Details': r'C:\Users\u\payload.exe'},
                   user=r'EXAMPLE\other' if other_user else USER)
    started = child(delta)
    batches = [[started], [write]] if late else [[write], [started]]
    try:
        for batch in batches:
            monkeypatch.setattr(sw, 'execute', lambda client, intent, mapping, batch=batch:
                                _complete(intent, [hit for _, hit in batch]))
            sweep.run_partition(batch[0][1]['_index'], None, [], sweep.window, est=len(batch))
        sweep.finalize()
        [row] = sweep.repo.candidates('h1')
        assert row['lane'] == lane
        assert '10 minutes' in row['claim']
        assert row['event_ids']
    finally:
        sweep.close_stage()


def test_elevation_still_publishes_when_actual_storage_budget_cannot_allocate_history(tmp_path, monkeypatch):
    from romulus.detect.bounded import StateBudget
    from romulus.hunt import sweep as sw
    from romulus.sources.models import Window
    from tests.test_sweep import _complete, _repo
    owner = rule('AutoElevatedShell')
    budget = StateBudget(tmp_path, disk_total=1024, reserve=0)
    monkeypatch.setattr(sw, 'fresh_pack', lambda: [owner])
    monkeypatch.setattr(sw, 'state_budget', lambda settings, directory: budget)
    sweep = sw.Sweep(_repo(), None, 'h1', Window(start=START, end=START + timedelta(hours=1)), {}, stage_dir=tmp_path)
    event, hit = child()
    try:
        monkeypatch.setattr(sw, 'execute', lambda client, intent, mapping: _complete(intent, [hit]))
        sweep.run_partition(hit['_index'], None, [], sweep.window, est=1)
        sweep.finalize()
        [row] = sweep.repo.candidates('h1')
        assert row['lane'] == 'lead' and owner.limits
        assert row['ts'].replace(tzinfo=UTC) == event.ts
    finally:
        sweep.close_stage()


def drive_native(owner, batches):
    from tests.windows_process_support import stored
    matches = []
    for batch in batches:
        matches.extend(owner.consume([event for event, _ in batch]))
    matches.extend(owner.finalize())
    return stored(matches)


@pytest.mark.parametrize('offset,host,user', [(70, 'other-host', USER), (-1, 'ws01', USER),
                                          (70, 'ws01', ''), (70, 'ws01', 'unqualified')])
def test_correlation_does_not_borrow_a_host_future_write_or_unknown_user(offset, host, user):
    owner = rule('AutoElevatedShell')
    written = native(13, {'TargetObject': UAC[0], 'Details': r'C:\Users\u\payload.exe'},
                     60, 'ws01', USER)
    started = child(offset, host, user)
    [match] = drive_native(owner, [[written], [started]])
    assert match.proposed_lane == 'lead'
    owner.release_state()


@pytest.mark.parametrize('mismatch,boot,terminated,expected', [
    (False, False, False, 'high'), (True, False, False, 'lead'),
    (False, True, False, 'lead'), (False, False, True, 'lead')])
def test_constrained_parent_guid_context_needs_image_and_lifetime(mismatch, boot, terminated, expected):
    owner = rule('AutoElevatedShell')
    guid = '{00000000-0000-0000-0000-000000000200}'
    parent = native(1, {'Image': r'C:\Windows\System32\fodhelper.exe' if mismatch else r'C:\Windows\System32\mmc.exe',
        'CommandLine': r'mmc.exe C:\Users\analyst\console.msc', 'ProcessGuid': guid,
        'ProcessId': '200', 'IntegrityLevel': 'High'}, 1)
    write = native(13, {'TargetObject': UAC[0], 'Details': r'C:\Users\u\payload.exe'}, 2)
    started = native(1, {'Image': r'C:\Windows\System32\cmd.exe', 'CommandLine': 'cmd.exe',
        'ParentImage': r'C:\Windows\System32\mmc.exe', 'ParentProcessGuid': guid,
        'ProcessGuid': '{00000000-0000-0000-0000-000000000400}', 'IntegrityLevel': 'High'}, 60)
    middle = []
    if boot:
        record = LogicalWindowsEvent('System', 'Microsoft-Windows-Kernel-General', 12, 'ws01', next(IDS),
                                     (START + timedelta(seconds=30)).isoformat(), {})
        hit = windows_hit(record, 'winlogbeat_8')
        middle.append((normalize_windows(hit), hit))
    if terminated:
        middle.append(native(5, {'Image': r'C:\Windows\System32\mmc.exe', 'ProcessGuid': guid}, 30))
    matches = drive_native(owner, [[parent, write], middle, [started]])
    [match] = [match for match in matches if match.playbook_id == owner.id]
    assert match.proposed_lane == expected
    owner.release_state()


def test_native_sid_identity_uses_validated_subject_fields():
    owner = rule('AutoElevatedShell')
    subject = {'SubjectUserSid': 'S-1-5-21-1-2-3-1001', 'SubjectUserName': 'analyst',
               'SubjectDomainName': 'EXAMPLE'}
    write = native(13, {'TargetObject': UAC[0], 'Details': r'C:\Users\u\payload.exe', **subject}, user='')
    started = native(1, {'Image': r'C:\Windows\System32\cmd.exe', 'CommandLine': 'cmd.exe',
        'ParentImage': r'C:\Windows\System32\fodhelper.exe', 'IntegrityLevel': 'High', **subject}, 30, user='')
    [match] = drive_native(owner, [[write], [started]])
    assert match.proposed_lane == 'high'
    owner.release_state()


@pytest.mark.parametrize('parent,command', [
    ('mmc.exe', r'mmc.exe C:\Windows\System32\eventvwr.msc'),
    ('dllhost.exe', 'dllhost.exe /Processid:{00000000-0000-0000-0000-000000000000}'),
    ('dllhost.exe', 'dllhost.exe /Other:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}')])
def test_known_benign_or_wrong_constrained_parent_argv_never_raises_a_high(parent, command):
    owner = rule('AutoElevatedShell')
    guid = '{00000000-0000-0000-0000-000000000200}'
    born = native(1, {'Image': 'C:\\Windows\\System32\\' + parent, 'CommandLine': command,
                      'ProcessGuid': guid, 'IntegrityLevel': 'High'}, 1)
    write = native(13, {'TargetObject': UAC[0], 'Details': r'C:\Users\u\payload.exe'}, 2)
    started = native(1, {'Image': r'C:\Windows\System32\cmd.exe', 'CommandLine': 'cmd.exe',
                        'ParentImage': 'C:\\Windows\\System32\\' + parent,
                        'ParentProcessGuid': guid, 'IntegrityLevel': 'High'}, 30)
    [match] = drive_native(owner, [[born, write], [started]])
    assert match.proposed_lane == 'lead'
    owner.release_state()


def test_real_sqlite_full_history_insert_does_not_lose_the_native_child(tmp_path, monkeypatch):
    from romulus.detect.bounded import StateBudget
    from romulus.hunt import sweep as sw
    from romulus.sources.models import Window
    from tests.test_sweep import _complete, _repo
    owner = rule('AutoElevatedShell')
    budget = StateBudget(tmp_path, disk_total=256 * 1024, reserve=0)
    monkeypatch.setattr(sw, 'fresh_pack', lambda: [owner])
    monkeypatch.setattr(sw, 'state_budget', lambda settings, directory: budget)
    sweep = sw.Sweep(_repo(), None, 'h1', Window(start=START, end=START + timedelta(hours=1)), {}, stage_dir=tmp_path)
    spill = owner.rows.store()
    spill.db.execute('CREATE TABLE allocation_fault(data BLOB)')
    spill.db.execute('CREATE TRIGGER allocate_on_row BEFORE INSERT ON windows_rows BEGIN '
                     'INSERT INTO allocation_fault VALUES(zeroblob(1048576)); END')
    spill.db.commit()
    spill.grew()
    observed = []
    original_failed = spill.failed
    def witness(error, **kwargs):
        observed.append(getattr(error, 'sqlite_errorcode', None))
        return original_failed(error, **kwargs)
    monkeypatch.setattr(spill, 'failed', witness)
    event, hit = child()
    try:
        monkeypatch.setattr(sw, 'execute', lambda client, intent, mapping: _complete(intent, [hit]))
        sweep.run_partition(hit['_index'], None, [], sweep.window, est=1)
        assert spill.db.execute('SELECT count(*) FROM allocation_fault').fetchone()[0] == 0
        assert sum(path.stat().st_size for path in tmp_path.rglob('*') if path.is_file()) <= budget.disk_total
        sweep.finalize()
        [row] = sweep.repo.candidates('h1')
        assert row['lane'] == 'lead' and row['ts'].replace(tzinfo=UTC) == event.ts
        assert 13 in observed  # Actual SQLITE_FULL, not an injected exception.
        assert owner.limits
    finally:
        sweep.close_stage()


def test_late_registry_context_converges_to_the_same_canonical_high():
    write = native(13, {'TargetObject': UAC[0], 'Details': r'C:\Users\u\payload.exe'}, 0)
    started = child(60)
    results = []
    for batches in ([[write], [started]], [[started], [write]]):
        owner = rule('AutoElevatedShell')
        try:
            [match] = drive_native(owner, batches)
            results.append((match.group_key, match.claim, match.proposed_lane,
                            [event.id for event in match.events], sorted(match.context_ids)))
        finally:
            owner.release_state()
    assert results[0] == results[1] and results[0][2] == 'high'


def test_new_elevation_storage_scenario_is_identical_under_effective_hash_seeds(tmp_path):
    import json
    import os
    import subprocess
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    outputs = []
    for seed in ('0', '2', '6'):
        environment = dict(os.environ, PYTHONHASHSEED=seed,
                           PYTHONPATH=os.pathsep.join((str(root / 'src'), str(root))))
        completed = subprocess.run([sys.executable, str(Path(__file__)), 'elevation-seed-proof'],
            cwd=root, env=environment, text=True, capture_output=True, check=True)
        result = json.loads(completed.stdout)
        assert result.pop('effective_seed') == seed
        outputs.append(result)
    assert outputs[0] == outputs[1] == outputs[2]


if __name__ == '__main__':
    import json
    import os
    import sys
    assert sys.argv[1:] == ['elevation-seed-proof']
    owner = rule('AutoElevatedShell')
    written = native(13, {'TargetObject': UAC[0], 'Details': r'C:\Users\u\payload.exe'}, 0)
    started = child(600)
    try:
        [match] = drive_native(owner, [[started], [written]])
        print(json.dumps({'effective_seed': os.environ.get('PYTHONHASHSEED'),
            'group': match.group_key, 'claim': match.claim, 'lane': match.proposed_lane,
            'native_ids': [event.id for event in match.events], 'context': sorted(match.context_ids)}, sort_keys=True))
    finally:
        owner.release_state()
