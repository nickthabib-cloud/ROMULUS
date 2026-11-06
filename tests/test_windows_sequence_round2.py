"""Creator handles, broker reparenting and bounded Windows sequence retention."""
import itertools

import pytest

from romulus.detect.windows_sequence_extensions import (
    ParentProcessSpoofing,
    SamAdminRegistryWithoutAudit,
    SmbHostDiscovery,
)
from tests.windows_event_support import event, run
from tests.windows_process_support import stored


def creation(guid, parent, image, *, offset=0):
    return event('process_exec', 1, native='create-' + guid, offset=offset, **{
        'process.guid': guid, 'process.parent.guid': parent, 'process.executable': image})


def access(source='actor', target='parent', image=r'C:\Tools\actor.exe', target_image=r'C:\Windows\explorer.exe', *, native='access', offset=1):
    return event('process_access', 10, native=native, offset=offset, **{
        'source.guid': source, 'source.pid': 100, 'source.executable': image,
        'target.guid': target, 'target.executable': target_image, 'process.access.mask': 0x1fffff})


@pytest.mark.parametrize('order', list(itertools.permutations(range(3))))
def test_creators_handle_to_its_child_is_not_parent_spoofing_in_any_arrival_order(order):
    records = [creation('parent', 'actor', r'C:\Windows\explorer.exe'), access(),
               creation('child', 'parent', r'C:\Tools\child.exe', offset=2)]
    owner = ParentProcessSpoofing()
    try:
        matches = run(owner, [[records[n]] for n in order])
        if order in {(1, 2, 0), (2, 1, 0)}:
            [match] = matches
            assert match.proposed_lane == 'lead' and 'creator' in match.revision_reason.lower()
        else:
            assert matches == []
        assert owner.rows.store().execute("SELECT COUNT(*) FROM windows_rows WHERE k LIKE '[\"access\",%'").fetchone()[0] == 0
    finally:
        owner.release_state()


@pytest.mark.parametrize('reverse', [False, True])
@pytest.mark.parametrize('name', ['svchost', 'csrss', 'conhost', 'services', 'wininit'])
def test_native_system32_reparenting_brokers_are_caveated_leads(reverse, name):
    records = [creation('parent', 'other', r'C:\Windows\explorer.exe'),
               access(image='C:\\Windows\\System32\\' + name + '.exe'),
               creation('child', 'parent', r'C:\Tools\child.exe', offset=2)]
    owner = ParentProcessSpoofing()
    try:
        [match] = run(owner, [[e] for e in reversed(records)] if reverse else [[e] for e in records])
        assert match.proposed_lane == 'lead'
        assert any('reparent' in text.lower() for text in match.notes)
        assert name + '.exe' in match.claim and 'explorer.exe' in match.claim and 'child.exe' in match.claim
    finally:
        owner.release_state()


@pytest.mark.parametrize('image', [r'C:\Tools\svchost.exe', r'C:\Windows\SysWOW64\csrss.exe',
    r'D:\Windows\System32\svchost.exe',r'\Device\HarddiskVolume7\Windows\System32\svchost.exe',
    r'C:\Users\alice\Windows\System32\conhost.exe', r'\\server\Windows\System32\services.exe'])
def test_broker_basename_masquerades_stay_high(image):
    owner = ParentProcessSpoofing()
    try:
        [match] = run(owner, [access(image=image), creation('child', 'parent', r'C:\Tools\child.exe', offset=2)])
        assert match.proposed_lane == 'high'
    finally:
        owner.release_state()


@pytest.mark.parametrize('source,target', [(r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe', r'C:\Windows\explorer.exe'),
    (r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe', r'C:\Windows\System32\winlogon.exe'),
    (r'C:\Python\python.exe', r'C:\Windows\System32\lsass.exe'), (r'C:\Tools\meterpreter.exe', r'C:\Windows\explorer.exe')])
@pytest.mark.parametrize('reverse', [False, True])
def test_attack_shapes_with_long_lived_target_keep_high(source, target, reverse):
    records = [access(image=source, target_image=target), creation('child', 'parent', r'C:\Tools\child.exe', offset=2)]
    owner = ParentProcessSpoofing()
    try:
        [match] = run(owner, [[e] for e in reversed(records)] if reverse else [[e] for e in records])
        assert match.proposed_lane == 'high'
        assert all(name in match.claim for name in (source, target, r'C:\Tools\child.exe'))
    finally:
        owner.release_state()


def test_fifty_children_fold_once_and_only_pending_children_need_finalization():
    target = creation('parent', 'other', r'C:\Windows\explorer.exe')
    children = [creation(f'child-{n}', 'parent', r'C:\Tools\child.exe', offset=2+n/100) for n in range(50)]
    owner = ParentProcessSpoofing()
    try:
        [match] = run(owner, [[target, access()], children])
        assert match.proposed_lane == 'high' and '50' in match.claim
        assert len(match.events) <= 8
        assert not list(owner.finalize())
        assert owner.rows.store().execute("SELECT COUNT(*) FROM ppid_pending WHERE id LIKE 'create-child-%'").fetchone()[0] == 0
        assert owner.rows.store().execute("SELECT COUNT(*) FROM windows_rows WHERE k LIKE '[\"child\",%' AND LENGTH(event)>0").fetchone()[0] == 0
    finally:
        owner.release_state()


@pytest.mark.parametrize('code,group,member,suppress', [(4720, 'S-1-5-32-544', 'S-1-5-21-1-2-3-1001', False),
    (4732, 'S-1-5-32-555', 'S-1-5-21-1-2-3-1001', False),
    (4732, 'S-1-5-32-544', 'S-1-5-21-1-2-3-1002', False),
    (4732, 'S-1-5-32-544', 'S-1-5-21-1-2-3-1001', True), (4732, 'S-1-5-32-544', None, True)])
@pytest.mark.parametrize('reverse', [False, True])
def test_only_administrators_membership_for_matching_typed_member_suppresses(code, group, member, suppress, reverse):
    write = event('registry_change', 13, native='sam', offset=1, **{
        'registry.path_key': r'HKLM\SAM\SAM\Domains\Builtin\Aliases\00000220\C',
        'registry.action': 'value_set', 'account.member_id': 'S-1-5-21-1-2-3-1001'})
    audit = event('account_change', code, native='audit', **{'account.group_id': group, 'account.member_id': member})
    owner = SamAdminRegistryWithoutAudit()
    try:
        records = [write, audit] if reverse else [audit, write]
        assert bool(run(owner, [[e] for e in records])) is not suppress
    finally:
        owner.release_state()


def test_smb_repeated_destination_retains_coalesced_state_without_losing_old_bursts():
    owner = SmbHostDiscovery()
    records = [event('net_socket', 3, native=f'smb-{n}', offset=n/100, **{
        'source.ip': '10.0.0.1', 'destination.ip': f'10.1.0.{n%24+1}', 'destination.port': 445,
        'network.direction': 'egress', 'network.transport': 'tcp'}) for n in range(2400)]
    last = event('net_socket', 3, native='twenty-fifth', offset=25, **{'source.ip': '10.0.0.1',
        'destination.ip': '10.1.0.25', 'destination.port': 445, 'network.direction': 'egress', 'network.transport': 'tcp'})
    try:
        list(owner.consume(records))
        assert owner.rows.store().execute('SELECT COUNT(*) FROM windows_rows').fetchone()[0] <= 24
        assert owner.rows.account.used < 100_000
        [match] = run(owner, [last])
        assert match.proposed_lane == 'lead'
    finally:
        owner.release_state()


@pytest.mark.parametrize('reverse', [False, True])
def test_smb_later_repeats_never_erase_an_older_qualifying_window(reverse):
    records = [event('net_socket', 3, native=f'{stamp}-{n}', offset=stamp+n, **{
        'source.ip': '10.0.0.1', 'destination.ip': f'10.1.0.{n+1}', 'destination.port': 445,
        'network.direction': 'egress', 'network.transport': 'tcp'})
        for stamp in (0, 10_000) for n in range(25 if stamp == 0 else 24)]
    owner = SmbHostDiscovery()
    try:
        [match] = run(owner, [[e] for e in reversed(records)] if reverse else [[e] for e in records])
        assert match.proposed_lane == 'lead' and match.ts == records[24].ts
        assert owner.rows.store().execute('SELECT COUNT(*) FROM windows_rows').fetchone()[0] == 49
    finally:
        owner.release_state()


def test_late_target_in_same_partition_can_hydrate_children_before_the_stage_is_flushed():
    records = [creation('child', 'parent', r'C:\Tools\child.exe', offset=2), access(),
               creation('parent', 'other', r'C:\Windows\explorer.exe')]
    owner = ParentProcessSpoofing()
    try:
        [match] = list(owner.consume(records))
        assert match.proposed_lane == 'high' and match.events[0].id == 'create-child'
        assert not list(owner.finalize())
    finally:
        owner.release_state()


def test_unknown_target_parent_publishes_immediately_and_is_not_republished_at_finalize():
    records = [access(), creation('child', 'parent', r'C:\Tools\child.exe', offset=2)]
    owner = ParentProcessSpoofing()
    owner.load = lambda ids: [e for e in records if e.id in ids]
    try:
        [match] = list(owner.consume(records))
        assert match.proposed_lane == 'high'
        assert any('target creation record' in note for note in match.notes)
        assert not list(owner.finalize())
    finally:
        owner.release_state()


def test_many_creator_handles_leave_only_fingerprint_creation_rows():
    owner = ParentProcessSpoofing()
    target = creation('parent', 'actor', r'C:\Windows\explorer.exe')
    try:
        assert list(owner.consume([target])) == []
        for n in range(500):
            assert list(owner.consume([access(native=f'access-{n}')])) == []
        rows = owner.rows.store()
        assert rows.execute("SELECT COUNT(*) FROM windows_rows WHERE k LIKE '[\"access\",%' OR k LIKE '[\"pending_access\",%'").fetchone()[0] == 0
        assert rows.execute('SELECT COUNT(*) FROM windows_rows WHERE LENGTH(event)>0').fetchone()[0] == 0
        assert owner.rows.account.used < 10_000
    finally:
        owner.release_state()


@pytest.mark.parametrize('late_high', [False, True])
def test_broker_access_never_hides_a_nonbroker_parent_creation_sequence(late_high):
    target = creation('parent', 'other', r'C:\Windows\explorer.exe')
    broker = access(image=r'C:\Windows\System32\svchost.exe', native='broker', offset=1.5)
    attacker = access(image=r'C:\Tools\attacker.exe', native='attacker', offset=1)
    child = creation('child', 'parent', r'C:\Tools\child.exe', offset=2)
    records = [target, broker, child, attacker] if late_high else [target, attacker, broker, child]
    owner = ParentProcessSpoofing()
    try:
        matches = run(owner, [[e] for e in records])
        assert any(m.proposed_lane == 'high' and 'attacker.exe' in m.claim for m in matches)
    finally:
        owner.release_state()


def test_retained_unknown_target_sequence_can_publish_when_optional_growth_is_refused(monkeypatch):
    records = [access(), creation('child', 'parent', r'C:\Tools\child.exe', offset=2)]
    owner = ParentProcessSpoofing()
    owner.load = lambda ids: [e for e in records if e.id in ids]
    try:
        [match] = list(owner.consume(records))
        monkeypatch.setattr(owner.rows, 'room', lambda: False)
        assert list(owner.finalize()) == []
        assert match.proposed_lane == 'high'
    finally:
        owner.release_state()


@pytest.mark.parametrize('parent,lane', [('actor', 'lead'), ('other', 'high')])
def test_live_target_creation_resolves_retained_children_even_when_new_indexes_are_full(monkeypatch, parent, lane):
    records = [access(), creation('child', 'parent', r'C:\Tools\child.exe', offset=2)]
    target = creation('parent', parent, r'C:\Windows\explorer.exe')
    owner = ParentProcessSpoofing()
    owner.load = lambda ids: [e for e in records if e.id in ids]
    try:
        initial = list(owner.consume(records))
        monkeypatch.setattr(owner.rows, 'room', lambda: False)
        [match] = stored([*initial, *owner.consume([target]), *owner.finalize()])
        assert match.proposed_lane == lane
    finally:
        owner.release_state()
