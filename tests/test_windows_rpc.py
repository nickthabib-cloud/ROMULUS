"""RPC ETW records preserve sides, conservative claims, and bounded folds."""
import copy
import importlib
import itertools
from dataclasses import replace
from datetime import timedelta

import pytest

from romulus.evidence.normalize import normalize_hits
from romulus.evidence.rpc_catalog import INTERFACES
from romulus.evidence.windows import normalize_windows, windows_record_signature
from romulus.evidence.windows_catalog import collection_requirements, lookup_event_class
from romulus.site import load_site_facts
from tests.test_windows_process_coverage import START
from tests.windows_fixtures import LogicalWindowsEvent, windows_hit
from tests.windows_process_support import run

RPC = 'Microsoft-Windows-RPC'
EFSR = 'c681d488-d850-11d0-8c52-00c04fd90f7e'
DRSR = 'e3514235-4b06-11d1-ab04-00c04fc2dcd2'
SVCCTL = '367abb81-9844-35f1-ad32-98f038001003'
IDS = itertools.count(900000)


def hit(*, code=5, uuid=EFSR, opnum='0', protocol='2', address=r'\\10.0.2.14', pid=123,
        host='ws01.example.test', offset=0, serial=None):
    data = {'InterfaceUuid': '{' + uuid + '}', 'Protocol': protocol, 'Endpoint': r'\pipe\lsarpc'}
    if opnum is not None:
        data['ProcNum'] = opnum
    if address is not None:
        data['NetworkAddress'] = address
    raw = windows_hit(LogicalWindowsEvent('', RPC, code, host, serial or next(IDS),
        (START + timedelta(seconds=offset)).isoformat(), data), 'winlogbeat_8')
    raw['_source']['winlog'].pop('channel', None)
    raw['_source']['winlog']['event_id'] = str(code)
    raw['_source']['winlog']['process'] = {'pid': pid}
    return raw


def rule(name):
    return getattr(importlib.import_module('romulus.detect.windows_rpc'), name)()


def test_rpc_missing_channel_catalog_and_provider_requirement():
    row = lookup_event_class(None, RPC, '5')
    assert row is not None and row.family == 'rpc_call'
    assert collection_requirements(row) == (('event_provider', {'provider': RPC}, 'event provider ' + RPC),)


def test_other_provider_missing_channel_and_missing_provider_stay_uncatalogued():
    assert lookup_event_class(None, 'Microsoft-Windows-Sysmon', 1) is None
    assert lookup_event_class('Security', None, 4624) is None
    assert lookup_event_class(None, None, 5) is None
    assert lookup_event_class(None, RPC, 9) is None


@pytest.mark.parametrize('uuid', [EFSR, EFSR.upper()])
@pytest.mark.parametrize('braced', [True, False])
def test_rpc_native_uuid_and_shared_class(uuid, braced):
    raw = hit(uuid=uuid)
    if not braced:
        raw['_source']['winlog']['event_data']['InterfaceUuid'] = uuid
    event = normalize_windows(raw)
    assert event.family == 'rpc_call'
    assert event.get('rpc.interface_uuid') == EFSR
    assert event.get('rpc.op_class') == 'coercion'
    assert event.get('rpc.operation') == 'EfsRpcOpenFileRaw'
    assert event.get('rpc.interface_name')
    assert event.get('rpc.opnum') == 0
    assert event.get('process.pid') == 123
    assert event.get('rpc.network_address') == '10.0.2.14'


@pytest.mark.parametrize('protocol,expected', [('1', 'tcp'), ('ncacn_ip_tcp', 'tcp'),
    ('2', 'named_pipe'), ('ncacn_np', 'named_pipe'), ('3', 'local'), ('ncalrpc', 'local')])
def test_rpc_protocol_spellings(protocol, expected):
    assert normalize_windows(hit(protocol=protocol)).get('rpc.protocol') == expected


@pytest.mark.parametrize('address,expected', [(r'\\server.test', 'server.test'), ('server', 'server'),
    ('10.0.2.14', '10.0.2.14'), ('2001:db8::1', '2001:db8::1'), ('[2001:db8::1]', '2001:db8::1'),
    ('NULL', None), ('', None), (None, None)])
def test_network_address_is_recorded_target_or_absent(address, expected):
    assert normalize_windows(hit(address=address)).get('rpc.network_address') == expected


def test_client_and_server_and_distinct_pid_do_not_merge_but_copies_do():
    a = hit(serial=1234)
    b = copy.deepcopy(a)
    b['_id'] += '-server'
    b['_source']['winlog']['event_id'] = '6'
    c = copy.deepcopy(a)
    c['_id'] += '-pid'
    c['_source']['winlog']['process']['pid'] = 456
    duplicate = copy.deepcopy(a)
    duplicate['_id'] += '-copy'
    events, skips, errors = normalize_hits([a, b, c, duplicate])
    assert not errors
    assert len(events) == 3 and len({event.id for event in events}) == 3
    assert len({windows_record_signature(raw) for raw in [a, b, c]}) == 3
    assert any(count == 1 and 'duplicate' in reason for reason, count in skips.items())


@pytest.mark.parametrize('code,address,lane,phrase', [
    (5, r'\\10.0.2.14', 'high', 'client call to'),
    (5, 'NULL', 'lead', 'client call to'),
    (6, 'NULL', 'high', 'server call received on'),
])
def test_coercion_claim_and_lane(code, address, lane, phrase):
    instance = rule('RpcCoercionCall')
    [match] = run(instance, [normalize_windows(hit(code=code, address=address))])
    assert match.proposed_lane == lane and phrase in match.claim
    assert 'over named pipe' in match.claim and 'was observed' in match.claim
    if code == 6:
        assert 'a caller the server-side record does not name' in match.claim
    elif lane == 'high':
        assert '10.0.2.14' in match.claim
    else:
        assert any('target' in text and 'not recorded' in text for text in match.notes)
    instance.release_state()


@pytest.mark.parametrize('opnum', ['not-a-number', None])
def test_invalid_or_missing_opnum_is_untyped_caveated_other(opnum):
    event = normalize_windows(hit(opnum=opnum))
    assert not event.has('rpc.opnum') and event.get('rpc.op_class') == 'other'
    assert any('ProcNum' in text for text in event.caveats)
    instance = rule('RpcCoercionCall')
    assert run(instance, [event]) == []
    instance.release_state()


def test_unknown_protocol_is_untyped_caveated_and_never_matches():
    event = normalize_windows(hit(protocol='surprise'))
    assert not event.has('rpc.protocol') and any('Protocol' in text for text in event.caveats)
    for name in ('RpcCoercionCall', 'RpcReplicationCall', 'RpcRemoteAdminCall'):
        instance = rule(name)
        assert run(instance, [event]) == []
        instance.release_state()


@pytest.mark.parametrize('uuid,opnum', [(EFSR, '999'), ('11111111-1111-1111-1111-111111111111', '0')])
def test_unknown_call_normalizes_other_without_coercion(uuid, opnum):
    event = normalize_windows(hit(uuid=uuid, opnum=opnum))
    assert event.get('rpc.op_class') == 'other'
    instance = rule('RpcCoercionCall')
    assert not run(instance, [event])
    instance.release_state()


@pytest.mark.parametrize('declared,lane', [(('dc01',), 'high'), ((), 'lead'), (('ws01.example.test',), None)])
def test_replication_client_role(declared, lane, tmp_path):
    instance = rule('RpcReplicationCall')
    instance.site_facts = replace(load_site_facts(tmp_path), domain_controllers=declared)
    matches = run(instance, [normalize_windows(hit(uuid=DRSR, opnum='3', protocol='1'))])
    assert len(matches) == (lane is not None)
    if matches:
        assert matches[0].proposed_lane == lane
        if lane == 'lead':
            assert any('domain controllers not declared; replication from a domain controller is routine' in text
                       for text in matches[0].notes)
    instance.release_state()


def test_server_replication_does_not_identify_caller():
    instance = rule('RpcReplicationCall')
    assert not run(instance, [normalize_windows(hit(code=6, uuid=DRSR, opnum='3', protocol='1'))])
    instance.release_state()


@pytest.mark.parametrize('protocol', ['3', 'ncalrpc', 'unknown'])
@pytest.mark.parametrize('name,uuid,opnum', [('RpcCoercionCall', EFSR, '0'),
    ('RpcReplicationCall', DRSR, '3'), ('RpcRemoteAdminCall', SVCCTL, '12')])
def test_all_rules_require_typed_remote_transport(name, uuid, opnum, protocol):
    instance = rule(name)
    assert not run(instance, [normalize_windows(hit(uuid=uuid, opnum=opnum, protocol=protocol))])
    instance.release_state()


@pytest.mark.parametrize('interface,operation', [(interface, operation) for interface in INTERFACES
    for operation in interface.operations])
def test_entire_shared_catalog_admin_lanes_and_ignored_classes(interface, operation):
    high = {'driver_install', 'sid_history', 'credential_access', 'secret_write'}
    lead = {'service_create', 'service_start', 'service_modify', 'service_control', 'service_delete',
            'task_register', 'remote_registry', 'remote_shutdown', 'account_change', 'account_rights_change', 'wmi_dcom'}
    instance = rule('RpcRemoteAdminCall')
    matches = run(instance, [normalize_windows(hit(code=6, uuid=interface.uuid, opnum=str(operation.opnum)))])
    expected = 'high' if operation.op_class in high else 'lead' if operation.op_class in lead else None
    assert len(matches) == (expected is not None)
    if matches:
        assert matches[0].proposed_lane == expected
        assert all(attack in ' '.join(matches[0].notes) for attack in operation.attack)
    instance.release_state()


def test_ten_thousand_service_creations_fold_once_with_bounded_citations():
    instance = rule('RpcRemoteAdminCall')
    batches = [[normalize_windows(hit(uuid=SVCCTL, opnum='12', offset=i, serial=3000000+i))
                for i in range(start, start+100)] for start in range(0, 10000, 100)]
    [match] = run(instance, batches)
    assert match.proposed_lane == 'lead'
    assert '10000 RPC call record(s)' in match.claim
    assert batches[0][0].ts.isoformat() in match.claim and batches[-1][-1].ts.isoformat() in match.claim
    assert len(match.events) <= 16
    assert len(instance.groups) <= 1 and len(instance.members_store) <= 1
    instance.release_state()

def test_same_call_both_sides_produces_two_distinct_observations():
    instance = rule('RpcCoercionCall')
    matches = run(instance, [normalize_windows(hit(code=5, serial=991)),
                             normalize_windows(hit(code=6, serial=991, address='NULL'))])
    assert len(matches) == 2
    assert len({match.group_key for match in matches}) == 2
    instance.release_state()


@pytest.mark.parametrize('interface,operation', [(interface, operation) for interface in INTERFACES
    for operation in interface.operations if operation.op_class in {'coercion', 'replication'}])
def test_catalog_coercion_and_replication_operations_use_catalog_attack(interface, operation, tmp_path):
    name = 'RpcCoercionCall' if operation.op_class == 'coercion' else 'RpcReplicationCall'
    instance = rule(name)
    instance.site_facts = replace(load_site_facts(tmp_path), domain_controllers=('dc01',))
    [match] = run(instance, [normalize_windows(hit(uuid=interface.uuid, opnum=str(operation.opnum)))])
    assert match.proposed_lane == 'high'
    assert all(technique in ' '.join(match.notes) for technique in operation.attack)
    instance.release_state()


def test_new_rules_are_registered_once_without_a_site_detection_gate():
    from romulus.detect.registry import PACK_VERSION, fresh_pack
    from romulus.evidence.windows import WINDOWS_NORMALIZER
    assert PACK_VERSION == 'pack@51' and WINDOWS_NORMALIZER == 'windows-ecs@16'
    ids = [instance.id for instance in fresh_pack()]
    for name in ('win.rpc_coercion_call', 'win.rpc_replication_call', 'win.rpc_remote_admin_call'):
        assert ids.count(name) == 1

def test_fully_qualified_dc_declaration_does_not_suppress_another_domain(tmp_path):
    instance = rule('RpcReplicationCall')
    instance.site_facts = replace(load_site_facts(tmp_path), domain_controllers=('ws01.other.test',))
    [match] = run(instance, [normalize_windows(hit(uuid=DRSR, opnum='3'))])
    assert match.proposed_lane == 'high'
    instance.release_state()

@pytest.mark.parametrize('opnums', [('3', '5'), ('5', '3')])
@pytest.mark.parametrize('declared,lane', [(('dc01',), 'high'), ((), 'lead')])
def test_mixed_replication_fold_unions_every_operation_technique(opnums, declared, lane, tmp_path):
    instance = rule('RpcReplicationCall')
    instance.site_facts = replace(load_site_facts(tmp_path), domain_controllers=declared)
    events = [normalize_windows(hit(uuid=DRSR, opnum=number, offset=i)) for i, number in enumerate(opnums)]
    [match] = run(instance, events)
    assert match.proposed_lane == lane and '2 RPC call record(s)' in match.claim
    assert {event.get('rpc.opnum') for event in match.events} == {3, 5}
    assert 'ATT&CK context (not proof): T1003.006, T1207' in match.notes
    instance.release_state()


def test_uncited_member_contributes_technique_to_bounded_rpc_fold(tmp_path):
    instance = rule('RpcReplicationCall')
    instance.site_facts = replace(load_site_facts(tmp_path), domain_controllers=('dc01',))
    events = [normalize_windows(hit(uuid=DRSR, opnum='5' if i == 12 else '3', offset=i)) for i in range(20)]
    [match] = run(instance, events)
    assert len(match.events) <= 16 and all(event.get('rpc.opnum') == 3 for event in match.events)
    assert '20 RPC call record(s)' in match.claim
    assert 'ATT&CK context (not proof): T1003.006, T1207' in match.notes
    instance.release_state()


def _rpc_fold_with_missing_citations(*, all_missing):
    instance = rule('RpcReplicationCall')
    events = [normalize_windows(hit(uuid=DRSR, opnum='3', offset=i)) for i in range(20)]
    by_id = {event.id: event for event in events}
    instance.load = lambda ids: [by_id[event_id] for event_id in ids if event_id in by_id]
    instance.consume(events)
    instance.drain_staged()
    instance.drain_bounds()
    absent = set(by_id) if all_missing else {events[-1].id}
    instance.load = lambda ids: [by_id[event_id] for event_id in ids if event_id not in absent]
    matches = list(instance.finalize())
    instance.release_state()
    return matches


def test_rpc_unavailable_citations_preserve_honest_fallback_claim():
    [match] = _rpc_fold_with_missing_citations(all_missing=True)
    assert match.citation_unavailable and not match.events
    assert 'One cited call:' not in match.claim
    assert 'no citation could be retained' in ' '.join(match.notes).lower()


def test_rpc_missing_last_bound_retains_interval_caveat():
    [match] = _rpc_fold_with_missing_citations(all_missing=False)
    assert match.events and not match.citation_unavailable
    assert 'record that ends this interval was not kept for citation' in match.claim
    assert 'interval is computed from every record' in match.claim


@pytest.mark.parametrize('declared,host,lane', [
    (('ws01',), 'ws01.example.test', None),
    (('WS01.Example.Test.',), 'ws01.example.test', None),
    (('ws01.example.test',), 'ws01', None),
    (('ws01.other.test',), 'ws01.example.test', 'high'),
    (('10.0.0.5',), 'ws01.example.test', 'high'),
    (('dc01', '10.0.0.5'), 'ws01.example.test', 'high'),
])
def test_declared_controller_matching_by_short_full_and_address(declared, host, lane, tmp_path):
    instance = rule('RpcReplicationCall')
    instance.site_facts = replace(load_site_facts(tmp_path), domain_controllers=declared)
    matches = run(instance, [normalize_windows(hit(uuid=DRSR, opnum='3', protocol='1', host=host))])
    assert [match.proposed_lane for match in matches] == ([lane] if lane else [])
    if any(name[0].isdigit() for name in declared):
        assert any('declared by address' in text for text in matches[0].notes)
    instance.release_state()


def test_rpc_catalog_fits_one_any_of_retrieval_predicate():
    # Retrieval sends every classified interface as one contains predicate, which compiles at most 256 values.
    assert 0 < len(INTERFACES) <= 256


@pytest.mark.parametrize('code', [5, 6])
def test_rpc_claim_is_one_sentence_ending_with_host_and_time(code):
    instance = rule('RpcCoercionCall')
    [match] = run(instance, [normalize_windows(hit(code=code))])
    assert '. on ' not in match.claim and ', was observed' not in match.claim.replace('does not name, was', '')
    assert match.claim.count(' was observed on ws01 at ') == 1 and match.claim.endswith('.')
    instance.release_state()
