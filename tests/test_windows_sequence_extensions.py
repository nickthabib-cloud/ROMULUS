"""Native-event keyed sequences must survive arrival order and duplicate copies."""
import importlib

import pytest

from tests.windows_event_support import event, run


def rule(name):
    return getattr(importlib.import_module('romulus.detect.windows_sequence_extensions'), name)()


@pytest.mark.parametrize('reverse', [False, True])
def test_parent_handle_access_then_child_cites_both_across_partitions(reverse):
    access = event('process_access', 10, native='access', **{
        'source.guid': 'creator', 'source.pid': 100, 'source.executable': r'C:\Tools\creator.exe',
        'target.guid': 'parent', 'process.access.mask': 0x80})
    child = event('process_exec', 1, native='child', offset=1, **{
        'process.guid': 'child', 'process.parent.guid': 'parent'})
    batches = [[child], [access]] if reverse else [[access], [child]]
    [match] = run(rule('ParentProcessSpoofing'), batches)
    assert match.proposed_lane == 'high'
    assert {e.id for e in match.events} == {'access', 'child'}


@pytest.mark.parametrize('reverse', [False, True])
def test_parent_sequence_is_published_as_soon_as_both_observations_arrive(reverse):
    access = event('process_access', 10, native='access', **{
        'source.guid': 'creator', 'source.pid': 100, 'source.executable': r'C:\Tools\creator.exe',
        'target.guid': 'parent', 'process.access.mask': 0x80})
    child = event('process_exec', 1, native='child', offset=1, **{
        'process.guid': 'child', 'process.parent.guid': 'parent'})
    first, second = (child, access) if reverse else (access, child)
    instance = rule('ParentProcessSpoofing')
    target = event('process_exec', 1, native='target', **{
        'process.guid': 'parent', 'process.parent.guid': 'other', 'process.executable': r'C:\Windows\explorer.exe'})
    instance.load = lambda ids: [e for e in (child, target) if e.id in ids]
    try:
        assert list(instance.consume([target])) == []
        assert list(instance.consume([first])) == []
        [match] = list(instance.consume([second]))
        assert match.proposed_lane == 'high'
        assert list(instance.finalize()) == []
    finally:
        instance.release_state()


@pytest.mark.parametrize('change', ['wrong_host', 'late', 'no_guid', 'system', 'no_right', 'same_creator'])
def test_parent_spoofing_requires_the_complete_native_sequence(change):
    access = event('process_access', 10, native='access', **{
        'source.guid': 'creator', 'source.pid': 4 if change == 'system' else 100,
        'source.executable': 'System' if change == 'system' else r'C:\Tools\creator.exe',
        'target.guid': 'parent', 'process.access.mask': 0x10 if change == 'no_right' else 0x80})
    child = event('process_exec', 1, native='child', offset=11 if change == 'late' else 1,
        host='other' if change == 'wrong_host' else 'ws01', **{
        'process.guid': 'creator' if change == 'same_creator' else 'child',
        'process.parent.guid': None if change == 'no_guid' else 'parent'})
    assert not run(rule('ParentProcessSpoofing'), [[access], [child]])


@pytest.mark.parametrize('audit_offset', [None, -300, 300, 301])
def test_sam_membership_write_uses_symmetric_audit_context(audit_offset):
    written = event('registry_change', 13, native='written', offset=400, **{
        'registry.path_key': r'HKLM\SAM\SAM\Domains\Builtin\Aliases\00000220\C',
        'registry.action': 'value_set'})
    batches = [[written]]
    if audit_offset is not None:
        batches.append([event('account_change', 4732, native='audit', offset=400 + audit_offset,
                              **{'account.group_id': 'S-1-5-32-544'})])
    matches = run(rule('SamAdminRegistryWithoutAudit'), batches)
    assert bool(matches) is (audit_offset in {None, 301})
    if matches:
        assert matches[0].proposed_lane == 'lead'
        assert any('collection' in n.lower() for n in matches[0].notes)


@pytest.mark.parametrize('reverse', [False, True])
def test_runmru_is_correlated_with_inbound_rdp_in_either_order(reverse):
    rdp = event('auth', 4624, native='rdp', **{'auth.logon_type': 10, 'source.ip': '10.0.0.5'})
    write = event('registry_change', 13, native='mru', offset=30, **{
        'registry.path_key': r'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU\a',
        'registry.action': 'value_set'})
    [match] = run(rule('RdpRunMruWrite'), [[write], [rdp]] if reverse else [[rdp], [write]])
    assert match.proposed_lane == 'lead'
    assert {e.id for e in match.events} == {'rdp', 'mru'}


@pytest.mark.parametrize('distinct,span,duplicate', [(25, 100, False), (24, 100, False),
                                                   (25, 1000, False), (24, 100, True)])
def test_smb_discovery_counts_distinct_internal_hosts_in_the_time_window(distinct, span, duplicate):
    events = [event('net_socket', 3, native=f'conn-{n}', offset=n*span/(distinct-1), **{
        'source.ip': '10.0.0.1', 'destination.ip': f'10.1.0.{n+1}',
        'destination.port': 445, 'network.direction': 'egress', 'network.transport': 'tcp'})
        for n in range(distinct)]
    if duplicate:
        events += events
    matches = run(rule('SmbHostDiscovery'), [[e] for e in reversed(events)])
    assert bool(matches) is (distinct == 25 and span < 600)
    if matches:
        assert matches[0].proposed_lane == 'lead' and matches[0].severity == 'low'


def test_large_below_threshold_smb_window_has_bounded_database_work():
    # Recounting every preceding row is quadratic even when the distinct threshold is never reached.
    instance = rule('SmbHostDiscovery')
    events = [event('net_socket', 3, native=f'conn-{n}', offset=n/100, **{
        'source.ip': '10.0.0.1', 'destination.ip': f'10.1.0.{n%24+1}',
        'destination.port': 445, 'network.direction': 'egress', 'network.transport': 'tcp'})
        for n in range(5000)]
    list(instance.consume(events))
    steps = 0
    def progress():
        nonlocal steps
        steps += 1000
        return int(steps > 5_000_000)
    instance.rows.store().db.set_progress_handler(progress, 1000)
    try:
        assert list(instance.finalize()) == []
    finally:
        instance.rows.store().db.set_progress_handler(None, 0)
        instance.release_state()


@pytest.mark.parametrize('name', ['ParentProcessSpoofing', 'SamAdminRegistryWithoutAudit', 'RdpRunMruWrite', 'SmbHostDiscovery'])
def test_refused_sequence_schema_is_named_partial_instead_of_a_rule_failure(tmp_path, name):
    from romulus.detect.bounded import StateBudget
    instance = rule(name)
    instance.budget = StateBudget(tmp_path, disk_total=1024, reserve=0)
    instance.budget.plan(1)
    from tests.test_windows_sequence_replay import observations
    kind = {'ParentProcessSpoofing': 'parent', 'SamAdminRegistryWithoutAudit': 'sam',
            'RdpRunMruWrite': 'rdp', 'SmbHostDiscovery': 'smb'}[name]
    try:
        list(instance.consume([e for e, _ in observations(kind)[1]]))
        list(instance.finalize())
        assert instance.limit_reasons()
        assert not instance.assures_negative
    finally:
        instance.release_state()


def test_late_accesses_do_not_repeat_completed_parent_sequence_work():
    instance = rule('ParentProcessSpoofing')
    children = [event('process_exec', 1, native=f'child-{n}', offset=1, **{
        'process.guid': f'child-{n}', 'process.parent.guid': 'parent'}) for n in range(300)]
    accesses = [event('process_access', 10, native=f'access-{n}', **{
        'source.guid': 'creator', 'source.pid': 100, 'source.executable': r'C:\Tools\creator.exe',
        'target.guid': 'parent', 'process.access.mask': 0x80}) for n in range(300)]
    target = event('process_exec', 1, native='target', **{
        'process.guid': 'parent', 'process.parent.guid': 'other', 'process.executable': r'C:\Windows\explorer.exe'})
    instance.load = lambda ids: [e for e in children if e.id in ids]
    assert list(instance.consume([target])) == []
    assert list(instance.consume(children)) == []
    steps = 0
    def progress():
        nonlocal steps
        steps += 1000
        return int(steps > 1_000_000)
    instance.rows.store().db.set_progress_handler(progress, 1000)
    try:
        matches = list(instance.consume(accesses))
        assert len(matches) == 300
        assert {m.events[0].id for m in matches} == {e.id for e in children}
    finally:
        instance.rows.store().db.set_progress_handler(None, 0)
        instance.release_state()
