"""Primitive Zeek lateral observations in every native delivery shape."""
import importlib
import importlib.util
from datetime import timedelta
from types import SimpleNamespace

import pytest

from romulus.detect.netdef import DIRECTION_ASSUMED_REASON
from romulus.evidence.typed import RawRef, fv
from tests.fixtures import zeek_logs as zl
from tests.test_zeek_windows_protocols import every_shape
from tests.windows_event_support import run


def facts(**changes):
    return SimpleNamespace(internal_networks=changes.get('internal_networks', ()),
        external_networks=changes.get('external_networks', ()),
        management_hosts=changes.get('management_hosts', ()),
        domain_controller_addresses=changes.get('domain_controller_addresses', ()),
        directory_sync_hosts=changes.get('directory_sync_hosts', ()),
        directory_sync_addresses=changes.get('directory_sync_addresses', ()))


def rule(name, site=None):
    assert importlib.util.find_spec('romulus.detect.zeek_lateral') is not None, 'Zeek lateral rule module is missing'
    owner = getattr(importlib.import_module('romulus.detect.zeek_lateral'), name)()
    owner.site_facts = site or facts()
    return owner


def check_shapes(name, row, lane, site=None, attack=None, note=None):
    decisions=[]
    for shape, event in every_shape(row).items():
        hits=rule(name, site).judge(event)
        assert len(hits)==int(lane is not None), (name, shape, hits)
        if not hits:
            continue
        [hit]=hits
        assert hit.lane==lane, (shape, hit)
        if attack is not None:
            assert hit.attack==attack
        if note:
            assert note in hit.notes
        assert 'logged in' not in hit.text.lower() and 'succeeded' not in hit.text.lower()
        decisions.append((hit.text,hit.lane,hit.attack,hit.content,hit.notes))
    assert len(set(decisions))<=1


@pytest.mark.parametrize('endpoint,operation,lane', [('spoolss','RpcAddPrinterDriverEx','high'),
    ('lsarpc','LsarQuerySecret','high'),('lsarpc','LsarSetSecret','high'),
    ('drsuapi','DRSAddSidHistory','high'),('svcctl','CreateServiceW','lead'),
    ('ITaskSchedulerService','SchRpcRegisterTask','lead'),('epmapper','ept_map',None),
    ('svcctl','CreateServiceW_extra',None)])
def test_remote_rpc_uses_the_shared_exact_catalog_in_all_shapes(endpoint,operation,lane):
    check_shapes('RpcRemoteAdminCall',zl.DCE_RPC.with_(endpoint=endpoint,operation=operation),lane)


@pytest.mark.parametrize('entry', [zl.CLIENT, zl.CLIENT+'/32'])
def test_management_service_call_is_retained_as_a_caveated_lead(entry):
    check_shapes('RpcRemoteAdminCall',zl.DCE_RPC,'lead',facts(management_hosts=(entry,)),
                 note='declared management source; authorized administration can produce this call')


def test_management_sensor_name_is_never_the_rpc_client_identity():
    check_shapes('RpcRemoteAdminCall',zl.DCE_RPC,'lead',facts(management_hosts=(zl.SENSOR,)))
    event=next(iter(every_shape(zl.DCE_RPC).values()))
    assert not rule('RpcRemoteAdminCall',facts(management_hosts=(zl.SENSOR,))).judge(event)[0].notes
    # a network record establishes a declared role by address only: a name there could be client-asserted
    event=event.model_copy(update={'fields':{**event.fields,'source.hostname':fv('SCCM.EXAMPLE.TEST.','test')}})
    assert not rule('RpcRemoteAdminCall',facts(management_hosts=('sccm',))).judge(event)[0].notes
    assert rule('RpcRemoteAdminCall',facts(management_hosts=(zl.CLIENT,))).judge(event)[0].notes


@pytest.mark.parametrize('operation,attack', [('DRSGetNCChanges',('T1003.006',)),('DRSReplicaAdd',('T1207',))])
def test_replication_from_non_dc_is_high_and_dc_to_dc_is_quiet(operation,attack):
    row=zl.DCE_RPC.with_(endpoint='drsuapi',operation=operation)
    check_shapes('WireReplicationCall',row,'high',facts(domain_controller_addresses=(zl.DC,)),attack)
    check_shapes('WireReplicationCall',row,None,facts(domain_controller_addresses=(zl.CLIENT,zl.DC)))


def test_replication_without_dc_declaration_is_only_a_caveated_lead():
    check_shapes('WireReplicationCall',zl.DCE_RPC.with_(endpoint='drsuapi',operation='DRSGetNCChanges'),
                 'lead',note='domain controller addresses not declared')


def test_dc_source_to_non_dc_destination_is_not_suppressed():
    check_shapes('WireReplicationCall',zl.DCE_RPC.with_(endpoint='drsuapi',operation='DRSGetNCChanges'),
                 'lead',facts(domain_controller_addresses=(zl.CLIENT,)),
                 note='declared domain-controller source; destination is not a declared domain controller')


def test_sync_source_is_a_lead_even_when_it_is_also_a_declared_dc():
    row=zl.DCE_RPC.with_(endpoint='drsuapi',operation='DRSGetNCChanges')
    check_shapes('WireReplicationCall',row,'lead',facts(domain_controller_addresses=(zl.CLIENT,zl.DC),
        directory_sync_addresses=(zl.CLIENT+'/32',)),
        note='declared directory-sync host; a compromised sync server is a DCSync path')


@pytest.mark.parametrize('name,row,inside', [('RdpRemoteSession',zl.RDP,None),('VncRemoteSession',zl.RFB,'lead')])
def test_remote_sessions_respect_explicit_site_ranges_and_carveouts(name,row,inside):
    check_shapes(name,row,'high',facts(internal_networks=('192.0.2.0/24',)))
    check_shapes(name,row,inside,facts(internal_networks=('10.0.0.0/8',)))
    check_shapes(name,row,'high',facts(internal_networks=('10.0.0.0/8',),external_networks=(zl.CLIENT+'/32',)))
    # undeclared: the default definition decides, with the assumed-direction note
    check_shapes(name,row,inside,note=DIRECTION_ASSUMED_REASON)


@pytest.mark.parametrize('name,row', [('RdpRemoteSession',zl.RDP),('VncRemoteSession',zl.RFB)])
def test_a_source_family_the_site_names_no_range_of_is_never_outside(name,row):
    v6=row.with_(**{'id.orig_h':'fd00:10::5','id.resp_h':'fd00:10::20'})
    check_shapes(name,v6,'lead',facts(internal_networks=('10.0.0.0/8',)),
                 note='internal networks name no IPv6 range; source direction is unresolved')


@pytest.mark.parametrize('name,row', [('RdpRemoteSession',zl.RFB),('VncRemoteSession',zl.RDP)])
def test_remote_protocols_do_not_cross_match(name,row):
    check_shapes(name,row,None,facts(internal_networks=('192.0.2.0/24',)))


@pytest.mark.parametrize('uri,port,lane', [('/wsman',5985,'lead'),('/wsman?x=1',5986,'lead'),
    ('/wsman-extra',5985,None),('/x/wsman',5985,None),('/wsman/',5985,None),
    ('/wsman',80,None),('/%77sman',5985,None)])
def test_winrm_requires_exact_typed_path_and_service_port(uri,port,lane):
    check_shapes('HttpWinrm',zl.HTTP.with_(uri=uri,**{'id.resp_p':port}),lane)


def test_winrm_same_address_does_not_show_remote_access():
    check_shapes('HttpWinrm',zl.HTTP.with_(uri='/wsman',**{'id.resp_p':5985,'id.resp_h':zl.CLIENT}),None)


@pytest.mark.parametrize('hours,request_type,lane', [(10,'TGS',None),(10.001,'TGS','lead'),
    (11,'AS',None),(11,None,None),(1,'TGS',None)])
def test_long_ticket_is_a_strict_tgs_lifetime_observation(hours,request_type,lane):
    check_shapes('TgsLongLifetime',zl.KERBEROS.with_(till=zl.KERBEROS.ts+hours*3600,request_type=request_type),lane)


@pytest.mark.parametrize('name,row', [('RpcRemoteAdminCall',zl.DCE_RPC),
    ('WireReplicationCall',zl.DCE_RPC.with_(endpoint='drsuapi',operation='DRSGetNCChanges')),
    ('RdpRemoteSession',zl.RDP),('VncRemoteSession',zl.RFB),
    ('HttpWinrm',zl.HTTP.with_(uri='/wsman',**{'id.resp_p':5985})),('TgsLongLifetime',zl.KERBEROS)])
def test_non_zeek_producer_cannot_trigger_any_primitive(name,row):
    event=next(iter(every_shape(row).values())).model_copy(update={'normalizer':'windows-ecs@16'})
    owner=rule(name)
    assert owner.judge(event)==[] and owner.consume([event])==[]


def test_group_counts_distinct_raw_references_per_row_and_publishes_high_immediately():
    first=next(iter(every_shape(zl.DCE_RPC.with_(endpoint='spoolss',operation='RpcAddPrinterDriverEx')).values()))
    first=first.model_copy(update={'raw':[RawRef(target='a',native_id='1'),RawRef(target='a',native_id='1'),RawRef(target='b',native_id='1')]})
    second=first.model_copy(update={'id':'second','ts':first.ts+timedelta(seconds=1),
        'raw':[RawRef(target='a',native_id='2'),RawRef(target='b',native_id='2'),RawRef(target='c',native_id='2')]})
    owner=rule('RpcRemoteAdminCall')
    owner.load=lambda ids:[e for e in (first,second) if e.id in ids]
    initial=owner.consume([first]);assert initial and initial[0].proposed_lane=='high'
    assert '2 raw reference(s)' in initial[0].claim
    owner.drain_staged();owner.drain_bounds()
    owner.consume([second]);owner.drain_staged();owner.drain_bounds()
    [final]=owner.finalize()
    assert '5 raw reference(s)' in final.claim and 'network-observed' in final.claim
    assert 'process' not in final.claim.lower() and 'Windows' not in final.claim
    assert final.group_key==initial[0].group_key and final.bounded_revision
    assert final.fleet_host_count==0
    owner.release_state()


def test_multi_sensor_fold_has_one_final_revision_without_target_host_attribution():
    row=zl.DCE_RPC.with_(endpoint='spoolss',operation='RpcAddPrinterDriverEx')
    first=next(iter(every_shape(row).values()))
    second=first.model_copy(update={'id':'second','host':'other-sensor',
        'fields':{**first.fields,'observer.name':fv('other-sensor','test')},
        'raw':[RawRef(target='other',native_id='1')]})
    owner=rule('RpcRemoteAdminCall')
    matches=run(owner,[[first],[second]])
    assert len(matches)==1 and '2 raw reference(s)' in matches[0].claim
    assert 'host(s)' not in matches[0].claim and not matches[0].fleet_host_count
    owner.release_state()


def test_normalized_uuid_opnum_support_and_untrusted_class_label():
    event=next(iter(every_shape(zl.DCE_RPC).values()))
    fields={k:v for k,v in event.fields.items() if k not in {'rpc.endpoint','rpc.operation'}}
    hit=rule('RpcRemoteAdminCall').judge(event.model_copy(update={'fields':fields}))
    assert hit and hit[0].lane=='lead'
    spoof=event.model_copy(update={'fields':{**event.fields,'rpc.operation':fv('not-an-operation','test'),
        'rpc.op_class':fv('driver_install','test')}})
    assert rule('RpcRemoteAdminCall').judge(spoof)==[]

def test_unknown_actor_fields_do_not_demote_a_catalog_driver_call():
    check_shapes('RpcRemoteAdminCall',zl.DCE_RPC.with_(endpoint='spoolss',operation='RpcAddPrinterDriverEx'),
                 'high',facts(management_hosts=(zl.CLIENT,)))


def test_rpc_peer_missing_or_same_cannot_establish_remote_observation():
    for row in (zl.DCE_RPC.with_(**{'id.orig_h':None}),zl.DCE_RPC.with_(**{'id.resp_h':zl.CLIENT})):
        check_shapes('RpcRemoteAdminCall',row,None)
        check_shapes('WireReplicationCall',row.with_(endpoint='drsuapi',operation='DRSGetNCChanges'),None)


def test_declared_sync_hostname_is_a_source_role_not_observer_role():
    event=next(iter(every_shape(zl.DCE_RPC.with_(endpoint='drsuapi',operation='DRSGetNCChanges')).values()))
    owner=rule('WireReplicationCall',facts(domain_controller_addresses=(zl.DC,),directory_sync_hosts=(zl.SENSOR,)))
    assert owner.judge(event)[0].lane=='high'
    # a typed source name never lowers DCSync: only a declared address does, and a name-only declaration is named
    event=event.model_copy(update={'fields':{**event.fields,'source.hostname':fv('SYNC01.example.test','source')}})
    owner.site_facts=facts(domain_controller_addresses=(zl.DC,),directory_sync_hosts=('sync01',))
    [hit]=owner.judge(event)
    assert hit.lane=='high' and any('declared by name only' in note for note in hit.notes)
    owner.site_facts=facts(domain_controller_addresses=(zl.DC,),directory_sync_addresses=(zl.CLIENT,))
    assert owner.judge(event)[0].lane=='lead'


def test_bounded_fold_keeps_exact_count_when_examples_are_limited():
    first=next(iter(every_shape(zl.DCE_RPC.with_(endpoint='spoolss',operation='RpcAddPrinterDriverEx')).values()))
    events=[first.model_copy(update={'id':f'call-{n}','ts':first.ts+timedelta(milliseconds=n),
        'raw':[RawRef(target='wire',native_id=str(n))]}) for n in range(1000)]
    owner=rule('RpcRemoteAdminCall')
    [match]=run(owner,[events[:500],events[500:]])
    assert match.proposed_lane=='high' and '1000 raw reference(s)' in match.claim
    assert len(match.events)<=16 and len(owner.groups)==1 and len(owner.members_store)==1
    assert any('bounded examples' in note for note in match.notes)
    owner.release_state()


def test_unavailable_citations_keep_the_positive_lane_and_network_count():
    first=next(iter(every_shape(zl.DCE_RPC.with_(endpoint='spoolss',operation='RpcAddPrinterDriverEx')).values()))
    second=first.model_copy(update={'id':'second','raw':[RawRef(target='wire',native_id='second')]})
    owner=rule('RpcRemoteAdminCall')
    owner.consume([first,second]);owner.drain_staged();owner.drain_bounds()
    owner.load=lambda ids:[]
    [match]=owner.finalize()
    assert match.proposed_lane=='high' and match.citation_unavailable
    assert '2 raw reference(s)' in match.claim and 'host(s)' not in match.claim
    assert not match.fleet_host_count and any('citation' in note.lower() for note in match.notes)
    owner.release_state()

@pytest.mark.parametrize('name,row,lane', [('RpcRemoteAdminCall',zl.DCE_RPC,'lead'),
    ('WireReplicationCall',zl.DCE_RPC.with_(endpoint='drsuapi',operation='DRSGetNCChanges'),'high'),
    ('RdpRemoteSession',zl.RDP,'high'),('VncRemoteSession',zl.RFB,'high'),
    ('HttpWinrm',zl.HTTP.with_(uri='/wsman',**{'id.resp_p':5985}),'lead'),
    ('TgsLongLifetime',zl.KERBEROS,'lead')])
def test_each_primitive_publishes_first_network_observation_immediately(name,row,lane):
    owner=rule(name,facts(internal_networks=('192.0.2.0/24',),domain_controller_addresses=(zl.DC,)))
    event=next(iter(every_shape(row).values()))
    [match]=owner.consume([event])
    assert match.proposed_lane==lane and '1 raw reference(s)' in match.claim
    assert match.claim_type=='network_observation' and event.host not in match.claim
    assert 'Windows' not in owner.positive_only_reason and not match.fleet_host_count
    owner.release_state()

def test_long_ticket_claim_identifies_requested_validity_without_inventing_a_granted_lifetime():
    event=next(iter(every_shape(zl.KERBEROS).values()))
    owner=rule('TgsLongLifetime')
    [match]=owner.consume([event])
    assert 'requested' in match.claim.lower()
    assert 'requested' in owner.title.lower()
    assert any('does not establish' in note and 'granted lifetime' in note and 'golden ticket' in note
               for note in match.notes)
    assert any('benign clients can request' in note.lower() for note in match.notes)
    assert 'ticket validity beyond' not in match.claim.lower()
    owner.release_state()
