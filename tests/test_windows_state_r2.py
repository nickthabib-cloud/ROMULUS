"""Native retrieval and compact account/elevation state review proofs."""
from datetime import timedelta

import pytest

from romulus.detect.base import Match, Playbook
from romulus.detect.windows_elevation_events import AutoElevatedShell
from romulus.detect.windows_process_w4 import ParentAccountTransition
from romulus.evidence.windows_catalog import SECURITY
from romulus.hunt import sweep as sw
from romulus.sources.compile import compile_es
from romulus.sources.models import Window
from romulus.sources.profile import contract_from_types
from tests.test_sweep import _complete, _repo
from tests.test_windows_elevation_w4 import UAC, drive_native
from tests.test_windows_elevation_w4 import native as elevation
from tests.test_windows_process_w4 import START, native, process, sweep_run
from tests.throughput_fixture import _matches


class RetrievalReader(Playbook):
    id = 'test.r2-retrieval'
    families = ('auth', 'process_exec', 'script_block', 'remote_access', 'network_filter')
    os_families = ('windows',)

    def consume(self, events):
        return [Match(self.id, 'native record evaluated', 'observation', [event], [], event.ts, 'medium', 'lead', 'medium', event.entities(), group_key=event.id) for event in events]


@pytest.mark.parametrize('mapping', ['text', 'no-provider'])
def test_r2_weak_class_contract_retains_security_sysmon_and_powershell(tmp_path, monkeypatch, mapping):
    types = {'@timestamp': 'date', 'winlog.channel': 'text' if mapping == 'text' else 'keyword', 'winlog.event_id': 'text' if mapping == 'text' else 'long', 'winlog.event_data': 'flattened', 'winlog.computer_name': 'keyword'}
    if mapping == 'text':
        types['winlog.provider_name'] = 'text'
    contract = contract_from_types('win-host', types, role='host', hosts=('host.example.test',))
    records = [native({'LogonType': '10', 'TargetUserName': 'alice'}, code=4624, provider=SECURITY, channel='Security'), native(process(r'C:\Windows\System32\cmd.exe', r'EXAMPLE\alice', 1), n=2), native({'ScriptBlockText': 'Write-Output fixture', 'ScriptBlockId': 's', 'MessageNumber': '1', 'MessageTotal': '1'}, n=3, code=4104, provider='Microsoft-Windows-PowerShell', channel='Microsoft-Windows-PowerShell/Operational')]
    monkeypatch.setattr(sw, 'fresh_pack', lambda: [RetrievalReader()])
    sweep = sw.Sweep(_repo(), None, 'h1', Window(start=START, end=START + timedelta(hours=1)), {contract.target: contract}, stage_dir=tmp_path)
    try:
        groups = sweep._any_of_for(contract.target, contract)
        assert groups == sweep._any_of_for(contract.target, contract)
        reason = 'Windows event-class mapping cannot restrict WFP 5156/5158 or RdpCoreTS 131/132/148; base dataset/channel fallback accepts their volume; no Windows classes withheld.'
        def execute(_client, intent, _contract):
            query = compile_es(intent, contract).body['query']
            selected = [hit for _, hit in records if _matches(query, hit['_source'], '@timestamp')]
            return _complete(intent, selected)
        monkeypatch.setattr(sw, 'execute', execute)
        sweep.run_partition(contract.target, contract, [], sweep.window, est=len(records), any_of=groups)
        sweep.finalize()
        ids = {event_id for row in sweep.repo.candidates('h1') for event_id in row['event_ids']}
        assert {event.id for event, _ in records} <= ids
        assert sweep._windows_inventory_reasons[contract.target].count(reason) == 1
    finally:
        sweep.close_stage()


def test_r2_unrelated_refused_fence_does_not_demote_retained_parent(tmp_path, monkeypatch):
    parent = native(process(r'C:\Users\alice\service.exe', r'EXAMPLE\alice', 1))
    fence = native({'ProcessGuid': '{00000000-0000-0000-0000-000000000099}'}, n=9, code=5)
    child = native(process(r'C:\Windows\System32\cmd.exe', r'NT AUTHORITY\SYSTEM', 2, ParentProcessGuid=parent[0].get('process.guid')), n=2, offset=1)
    owner = ParentAccountTransition()
    original = owner.rows.put
    monkeypatch.setattr(owner.rows, 'put', lambda key, event, value='': False if event.id == fence[0].id else original(key, event, value))
    [finding], _ = sweep_run(tmp_path, monkeypatch, owner, [[fence], [parent], [child]], assert_raw=(parent, child))
    assert finding['lane'] == 'high'
    assert any('fence' in str(value).lower() for value in owner.limits.values())


def test_r2_account_precision_duplicate_remains_unique(tmp_path, monkeypatch):
    parent = native(process(r'C:\Users\alice\service.exe', r'EXAMPLE\alice', 1))
    duplicate = native(process(r'C:\Users\alice\service.exe', r'EXAMPLE\alice', 1), n=9)
    duplicate[1]['_source']['@timestamp'] = duplicate[0].ts.replace(microsecond=123456).isoformat()
    duplicate[1]['_source']['winlog']['time_created'] = duplicate[1]['_source']['@timestamp']
    from romulus.evidence.windows import normalize_windows
    duplicate = (normalize_windows(duplicate[1]), duplicate[1])
    assert duplicate[0].ts.microsecond == 123456
    child = native(process(r'C:\Windows\System32\cmd.exe', r'NT AUTHORITY\SYSTEM', 2, ParentProcessGuid=parent[0].get('process.guid')), n=2, offset=1)
    [finding], _ = sweep_run(tmp_path, monkeypatch, ParentAccountTransition(), [[parent, duplicate], [child]])
    assert finding['lane'] == 'high'


def test_r2_duplicate_mmc_parent_does_not_demote_elevation():
    guid = '{00000000-0000-0000-0000-000000000200}'
    data = {'Image': r'C:\Windows\System32\mmc.exe', 'CommandLine': r'mmc.exe C:\Users\alice\console.msc', 'ProcessGuid': guid, 'IntegrityLevel': 'High'}
    parent, duplicate = elevation(1, data, 1), elevation(1, data, 1)
    write = elevation(13, {'TargetObject': UAC[0], 'Details': r'C:\Users\u\payload.exe'}, 2)
    child = elevation(1, {'Image': r'C:\Windows\System32\cmd.exe', 'CommandLine': 'cmd.exe', 'ParentImage': r'C:\Windows\System32\mmc.exe', 'ParentProcessGuid': guid, 'IntegrityLevel': 'High'}, 30)
    owner = AutoElevatedShell()
    try:
        [match] = drive_native(owner, [[parent, duplicate, write], [child]])
        assert match.proposed_lane == 'high'
    finally:
        owner.release_state()


def test_r2_irrelevant_creations_and_terminations_have_no_full_bodies():
    owner, elevated = ParentAccountTransition(), AutoElevatedShell()
    try:
        events = [native(process(r'C:\Windows\System32\services.exe', r'NT AUTHORITY\SYSTEM', n + 1), n=n + 1)[0] for n in range(20)]
        terms = [native({'ProcessGuid': event.get('process.guid')}, n=100+n, code=5)[0] for n, event in enumerate(events)]
        list(owner.consume(events + terms))
        elevated.consume(events + terms)
        assert owner.rows.store().execute("SELECT count(*) FROM windows_rows WHERE k LIKE 'parent:%' AND event<>''").fetchone()[0] == 0
        assert owner.rows.store().execute("SELECT max(length(event)+length(raw)) FROM windows_rows WHERE k LIKE 'termination:%'").fetchone()[0] < 1800
        assert not elevated.rows.ready or elevated.rows.store().execute('SELECT count(*) FROM windows_rows').fetchone()[0] == 0
    finally:
        owner.release_state()
        elevated.release_state()


def test_r2_late_child_without_source_keeps_high_and_names_unavailable_body(tmp_path, monkeypatch):
    parent = native(process(r'C:\Users\alice\service.exe', r'EXAMPLE\alice', 1))
    child = native(process(r'C:\Windows\System32\cmd.exe', r'NT AUTHORITY\SYSTEM', 2, ParentProcessGuid=parent[0].get('process.guid')), n=2, offset=1)
    [finding], _ = sweep_run(tmp_path, monkeypatch, ParentAccountTransition(), [[child], [parent]])
    assert finding['lane'] == 'high'
    assert 'Citation body not retrieved' in finding['claim']
    assert {child[0].id, parent[0].id} <= set(finding['event_ids'])


def test_r2_compact_fence_keeps_native_identity_origins_and_body_boundary():
    from romulus.hunt.citations import COMPACT_CITATION_NOTE
    from romulus.hunt.publish import SourceCitationFetcher
    parent = native(process(r'C:\Users\alice\service.exe', r'EXAMPLE\alice', 1))
    fence = native({'ProcessGuid': parent[0].get('process.guid')}, n=3, offset=1, code=5)
    child = native(process(r'C:\Windows\System32\cmd.exe', r'NT AUTHORITY\SYSTEM', 2, ParentProcessGuid=parent[0].get('process.guid')), n=2, offset=2)
    owner = ParentAccountTransition()
    try:
        list(owner.consume([parent[0], fence[0]]))
        [match] = list(owner.consume([child[0]]))
        compact = next(event for event in match.events if event.id == fence[0].id)
        assert compact.raw == fence[0].raw and compact.ts == fence[0].ts and compact.host == fence[0].host
        assert compact.fields['process.guid'] == fence[0].fields['process.guid']
        assert COMPACT_CITATION_NOTE in compact.caveats
        SourceCitationFetcher(None).hydrate(match)
        assert 'Citation body not retrieved' in match.claim
        sources = {ref.key: fence[1]['_source'] for ref in fence[0].raw}
        SourceCitationFetcher(None).hydrate(match, sources)
        assert all(match.raw_copies[ref.key] == fence[1]['_source'] for ref in fence[0].raw)
        assert COMPACT_CITATION_NOTE not in next(event for event in match.events if event.id == compact.id).caveats
    finally:
        owner.release_state()


def test_r2_compact_pending_child_keeps_account_entities():
    owner = ParentAccountTransition()
    child = native(process(r'C:\Windows\System32\cmd.exe', r'NT AUTHORITY\SYSTEM', 2, ParentProcessGuid='{00000000-0000-0000-0000-000000000001}'))[0]
    try:
        list(owner.consume([child]))
        [(_key, compact, _raw, _value)] = list(owner.rows.iterate(prefix='pending:'))
        assert compact.entities() == child.entities()
    finally:
        owner.release_state()


def test_r2_specific_refusal_caveat_does_not_lower_lane(tmp_path, monkeypatch):
    parent = native(process(r'C:\Users\alice\service.exe', r'EXAMPLE\alice', 1))
    fence = native({'ProcessGuid': parent[0].get('process.guid')}, n=3, offset=1, code=5)
    child = native(process(r'C:\Windows\System32\cmd.exe', r'NT AUTHORITY\SYSTEM', 2, ParentProcessGuid=parent[0].get('process.guid')), n=2, offset=2)
    owner = ParentAccountTransition()
    original = owner.rows.put
    monkeypatch.setattr(owner.rows, 'put', lambda key, event, value='': False if event.id == fence[0].id else original(key, event, value))
    [finding], _ = sweep_run(tmp_path, monkeypatch, owner, [[parent], [fence], [child]])
    assert finding['lane'] == 'high' and 'this host/GUID was refused' in finding['claim']


def test_r2_refusal_key_memory_is_bounded_and_overflow_named():
    owner = ParentAccountTransition()
    try:
        for n in range(5000):
            owner._refused(str(n))
        assert len(owner.refused_parent_keys) == 4096
        assert owner.refused_parent_overflow and 'process_account_refusal_keys' in owner.limits
    finally:
        owner.release_state()


@pytest.mark.parametrize('kind', ['termination', 'boot'])
@pytest.mark.parametrize('raise_refusal', [False, True])
def test_r2_late_refused_fence_updates_retained_high_caveat(tmp_path, monkeypatch, kind, raise_refusal):
    from romulus.detect.bounded import StateExhausted
    parent = native(process(r'C:\Users\alice\service.exe', r'EXAMPLE\alice', 1))
    child = native(process(r'C:\Windows\System32\cmd.exe', r'NT AUTHORITY\SYSTEM', 2,
                           ParentProcessGuid=parent[0].get('process.guid')), n=2, offset=2)
    fence = (native({'ProcessGuid': parent[0].get('process.guid')}, n=3, offset=1, code=5)
             if kind == 'termination' else native({}, n=3, offset=1, code=12,
                 channel='System', provider='Microsoft-Windows-Kernel-General'))
    owner = ParentAccountTransition()
    original = owner.rows.put
    def put(key, event, value=''):
        if event.id == fence[0].id:
            if raise_refusal:
                raise StateExhausted('native fixture physical refusal')
            return False
        return original(key, event, value)
    monkeypatch.setattr(owner.rows, 'put', put)
    [finding], _ = sweep_run(tmp_path, monkeypatch, owner, [[parent], [child], [fence]])
    assert finding['lane'] == 'high'
    assert 'this host/GUID was refused' in finding['claim']
    assert {parent[0].id, child[0].id} <= set(finding['event_ids'])


@pytest.mark.parametrize('correction', ['refused_conflict', 'stored_conflict', 'stored_fence'])
def test_r2_late_refusal_does_not_restore_a_corrected_lead(tmp_path, monkeypatch, correction):
    parent = native(process(r'C:\Users\alice\service.exe', r'EXAMPLE\alice', 1))
    child = native(process(r'C:\Windows\System32\cmd.exe', r'NT AUTHORITY\SYSTEM', 2,
                           ParentProcessGuid=parent[0].get('process.guid')), n=2, offset=2)
    changed = (native({'ProcessGuid': parent[0].get('process.guid')}, n=4, offset=1, code=5)
               if correction == 'stored_fence' else native(
                   process(r'C:\Users\bob\other.exe', r'EXAMPLE\bob', 1), n=4))
    refused = native({}, n=5, offset=1, code=12, channel='System', provider='Microsoft-Windows-Kernel-General')
    owner = ParentAccountTransition()
    original = owner.rows.put
    blocked = {refused[0].id}
    if correction == 'refused_conflict':
        blocked.add(changed[0].id)
    monkeypatch.setattr(owner.rows, 'put', lambda key, event, value='': False if event.id in blocked else original(key, event, value))
    [finding], _ = sweep_run(tmp_path, monkeypatch, owner, [[parent], [child], [changed], [refused]])
    assert finding['lane'] == 'lead'
    assert 'unresolved' in finding['claim']


@pytest.mark.parametrize('kind', ['termination', 'boot'])
def test_r2_late_unrelated_refusal_never_caveats_the_retained_high(tmp_path, monkeypatch, kind):
    parent = native(process(r'C:\Users\alice\service.exe', r'EXAMPLE\alice', 1))
    child = native(process(r'C:\Windows\System32\cmd.exe', r'NT AUTHORITY\SYSTEM', 2,
                           ParentProcessGuid=parent[0].get('process.guid')), n=2, offset=2)
    refused = (native({'ProcessGuid': '{00000000-0000-0000-0000-000000000099}'}, n=3, offset=1, code=5)
               if kind == 'termination' else native({}, n=3, offset=1, code=12, host='other.example.test',
                   channel='System', provider='Microsoft-Windows-Kernel-General'))
    owner = ParentAccountTransition()
    original = owner.rows.put
    monkeypatch.setattr(owner.rows, 'put', lambda key, event, value='': False if event.id == refused[0].id else original(key, event, value))
    [finding], _ = sweep_run(tmp_path, monkeypatch, owner, [[parent], [child], [refused]])
    assert finding['lane'] == 'high'
    assert 'this host/GUID was refused' not in finding['claim']


def test_r2_untracked_refused_conflict_cannot_restore_high_after_refusal_cap(tmp_path, monkeypatch):
    from romulus.detect.windows_rows import row_key
    parent = native(process(r'C:\Users\alice\service.exe', r'EXAMPLE\alice', 1))
    child = native(process(r'C:\Windows\System32\cmd.exe', r'NT AUTHORITY\SYSTEM', 2,
                           ParentProcessGuid=parent[0].get('process.guid')), n=2, offset=2)
    conflict = native(process(r'C:\Users\bob\other.exe', r'EXAMPLE\bob', 1), n=4)
    owner = ParentAccountTransition()
    # Retain host-scoped uncertainty but fill the same4096-entry emergency budget
    # before the conflicting parent can acquire its own terminal-conflict bit.
    owner._refused('boot:' + row_key(child[0].host))
    for n in range(4095):
        owner._refused('other:' + str(n))
    original = owner.rows.put
    monkeypatch.setattr(owner.rows, 'put', lambda key, event, value='': False if event.id == conflict[0].id else original(key, event, value))
    [finding], _ = sweep_run(tmp_path, monkeypatch, owner, [[parent], [child], [conflict]])
    assert finding['lane'] == 'lead'
    assert len(owner.refused_parent_keys) == 4096
    assert owner.refused_conflict_overflow and 'process_account_refusal_conflicts' in owner.limits
