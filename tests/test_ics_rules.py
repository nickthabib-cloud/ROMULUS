"""ICS requests, declaration-based lanes, pairing, and polling negatives."""
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from romulus.evidence.typed import RawRef, TypedEvent, fv
from tests.windows_event_support import run

START = datetime(2026, 1, 1, tzinfo=UTC)


def event(number=1, *, protocol='modbus', op='write', request=True, sender='10.0.0.8',
          receiver='10.0.0.20', offset=0, transaction='7', exception=None, **changes):
    values = {'observer.product': 'zeek', 'observer.name': 'tap', 'zeek.log': 'modbus',
              'zeek.uid': 'conn', 'ics.protocol': protocol, 'ics.function_code': 6,
              'ics.function_name': 'Write Single Register', 'ics.op_class': op,
              'ics.sender': sender, 'ics.receiver': receiver, 'ics.transaction_id': transaction,
              **changes}
    if request is not None:
        values['ics.is_request'] = request
    if exception is not None:
        values['ics.exception'] = exception
    return TypedEvent(id=str(number), family='ics_tx', ts=START+timedelta(seconds=offset),
        host='tap', normalizer='zeek-ecs@3', raw=[RawRef(target='ics', native_id=str(number))],
        fields={key: fv(value, str(number)+':'+key) for key, value in values.items()})


def rule(name, hosts=None):
    from romulus.detect import ics
    owner = getattr(ics, name)()
    owner.site_facts = SimpleNamespace(ics_control_hosts=tuple(hosts or ()),
        content={} if hosts is None else {'ics_control_hosts': list(hosts)})
    return owner


@pytest.mark.parametrize('name,op,program,hosts,lane', [
    ('WriteOrControlCommand','write',None,None,'lead'),
    ('WriteOrControlCommand','control',None,['10.0.0.8'],'context'),
    ('WriteOrControlCommand','write',None,['10.0.0.9'],'high'),
    ('WriteOrControlCommand','write',None,[],'high'),
    ('ModeChangeOrRestart','restart',None,None,'high'),
    ('ModeChangeOrRestart','mode_change',None,['10.0.0.8'],'lead'),
    ('ModeChangeOrRestart','restart',None,['10.0.0.9'],'high'),
    ('ProgramTransfer','program_transfer','download',None,'high'),
    ('ProgramTransfer','program_transfer','download',['10.0.0.8'],'lead'),
    ('ProgramTransfer','program_transfer','upload',None,'lead'),
])
def test_ics_lanes_follow_only_typed_operation_and_address_declaration(name,op,program,hosts,lane):
    extra = {'ics.program_direction': program} if program else {}
    matches=run(rule(name,hosts),[event(op=op,**extra)])
    assert len(matches)==1 and matches[0].proposed_lane==lane
    assert 'request observed' in matches[0].claim
    assert 'process state changed' not in matches[0].claim
    if name=='WriteOrControlCommand' and hosts is None:
        assert 'ICS control hosts are not declared' in matches[0].notes


@pytest.mark.parametrize('protocol',['modbus','dnp3','s7comm','cip','bacnet'])
@pytest.mark.parametrize('is_request',[False,None])
def test_responses_and_unknown_direction_never_become_commands(protocol,is_request):
    assert not run(rule('WriteOrControlCommand'),[event(protocol=protocol,request=is_request)])


def test_packet_sender_is_the_controller_even_when_source_ip_is_the_device():
    owner=rule('WriteOrControlCommand',['10.0.0.8'])
    [match]=run(owner,[event(**{'source.ip':'10.0.0.20','destination.ip':'10.0.0.8'})])
    assert match.proposed_lane=='context'
    assert '10.0.0.8' in match.claim


@pytest.mark.parametrize('response_changes,ack', [
    ({},True),({'ics.transaction_id':'8'},False),({'zeek.uid':'other'},False),
    ({'observer.name':'other'},False),({'ics.exception':True},False),
    ({'ics.exception':None},False),
])
def test_only_same_sensor_uid_transaction_success_can_acknowledge_a_request(response_changes,ack):
    response=event(2,request=False,sender='10.0.0.20',receiver='10.0.0.8',
                   offset=1,exception=False)
    response=response.model_copy(update={'fields':{**response.fields,
        **{key:fv(value,'response:'+key) for key,value in response_changes.items()}}})
    [match]=run(rule('WriteOrControlCommand'),[[event()],[response]])
    assert ('write acknowledged without exception' in match.claim) is ack
    assert '1 request record(s)' in match.claim
    if ack:
        assert {item.id for item in match.events}=={'1','2'}


def test_ack_pairing_is_order_independent_and_expired_reused_id_is_not_success():
    request=event()
    response=event(2,request=False,sender='10.0.0.20',receiver='10.0.0.8',
                   offset=1,exception=False)
    [match]=run(rule('WriteOrControlCommand'),[[response],[request]])
    assert 'write acknowledged without exception' in match.claim
    late=response.model_copy(update={'ts':START+timedelta(hours=1)})
    [match]=run(rule('WriteOrControlCommand'),[request,late])
    assert 'acknowledged without exception' not in match.claim


def test_one_response_cannot_acknowledge_two_reused_transaction_requests():
    first,second=event(1,offset=0),event(2,offset=2)
    response=event(3,request=False,sender='10.0.0.20',receiver='10.0.0.8',offset=3,exception=False)
    [ordered]=run(rule('WriteOrControlCommand',[]),[[first,second,response]])
    [reversed_batches]=run(rule('WriteOrControlCommand',[]),[[response],[first],[second]])
    assert ordered.claim==reversed_batches.claim


@pytest.mark.parametrize('name',['WriteOrControlCommand','ModeChangeOrRestart','ProgramTransfer',
                                'RemoteDiscovery','ExceptionBurst'])
def test_high_rate_polling_reads_are_not_findings(name):
    assert not run(rule(name),[event(n,op='read',offset=n,transaction=str(n)) for n in range(80)])


def test_discovery_requires_five_devices_within_one_sliding_window():
    rows=[event(n,op='discovery',receiver=f'10.0.1.{n}',offset=n*100,transaction=str(n))
          for n in range(1,6)]
    [match]=run(rule('RemoteDiscovery'),rows)
    assert match.proposed_lane=='lead' and '5 distinct receivers' in match.claim
    assert not run(rule('RemoteDiscovery'),rows[:4])
    sparse=[row.model_copy(update={'ts':START+timedelta(seconds=n*601)})
            for n,row in enumerate(rows)]
    assert not run(rule('RemoteDiscovery'),sparse)
    [context]=run(rule('RemoteDiscovery',['10.0.0.8']),rows[:1])
    assert context.proposed_lane=='context'
    duplicate=[event(n,op='discovery',offset=n,transaction=str(n)) for n in range(20)]
    assert not run(rule('RemoteDiscovery'),duplicate)


def test_exception_burst_counts_distinct_requests_and_never_claims_denial():
    rows=[event(n,request=False,sender='10.0.0.20',receiver='10.0.0.8',offset=n,
                exception=True,transaction=str(n)) for n in range(1,21)]
    [match]=run(rule('ExceptionBurst'),rows)
    assert match.proposed_lane=='lead' and '20 exception responses' in match.claim
    assert 'from 10.0.0.20' in match.claim
    assert 'misconfigured poller' in ' '.join(match.notes).lower()
    assert 'denial of service occurred' not in match.claim.lower()
    repeated=[row.model_copy(update={'fields':{**row.fields,
        'ics.transaction_id':fv('1','same transaction')}}) for row in rows]
    [reused] = run(rule('ExceptionBurst'),repeated)
    assert '20 exception responses' in reused.claim


def test_exception_rows_without_transaction_identity_cannot_prove_many_requests():
    owner=rule('ExceptionBurst')
    rows=[event(n,request=False,sender='10.0.0.20',receiver='10.0.0.8',offset=n,
                exception=True,transaction=None) for n in range(30)]
    assert not run(owner,rows)
    assert owner.missing_required==30

@pytest.mark.parametrize('log',['modbus','dnp3_control','s7comm','cip','bacnet'])
def test_real_protocol_requests_reach_the_command_detector_in_each_carried_shape(log):
    from tests.fixtures import zeek_ics as zi
    from tests.test_zeek_ics_normalize import normalize
    for shape in zi.SHAPES_BY_LOG[log]:
        normalized=normalize(zi.ROWS[log],shape)
        matches=run(rule('WriteOrControlCommand'),[normalized])
        assert len(matches)==1 and matches[0].proposed_lane=='lead', (log,shape)
        assert 'request observed' in matches[0].claim
        if shape=='security_onion' and log=='modbus':
            assert 'transaction summary' in ' '.join(matches[0].notes)
            assert 'acknowledged without exception' not in matches[0].claim


def test_dnp3_transaction_summary_can_prove_a_request_without_inventing_packet_direction():
    from tests.fixtures import zeek_ics as zi
    from tests.test_zeek_ics_normalize import normalize
    for shape in zi.SHAPES_BY_LOG['dnp3']:
        normalized=normalize(zi.ROWS['dnp3'],shape)
        assert normalized.get('ics.is_request') is None
        [match]=run(rule('WriteOrControlCommand'),[normalized])
        assert 'request observed' in match.claim
        assert 'acknowledged without exception' not in match.claim
        assert 'transaction summary' in ' '.join(match.notes)


def test_ics_addresses_are_eligible_for_standalone_high_indicator_matches():
    from romulus.detect.indicators import Indicator, IndicatorMatch, IndicatorSet
    from tests.fixtures import zeek_ics as zi
    from tests.test_zeek_ics_normalize import normalize
    row=normalize(zi.ROWS['modbus'],'plain')
    indicator=Indicator('ics-ip','ip',(row.get('source.ip'),),'listed address','high','high')
    [match]=run(IndicatorMatch(IndicatorSet([indicator])),[row])
    assert match.proposed_lane=='high'


@pytest.mark.parametrize('subfunction',['Restart Communications Option','Force Listen Only Mode'])
@pytest.mark.parametrize('shape',['malcolm','plain'])
def test_native_modbus_diagnostic_request_summary_reaches_the_high_lane(subfunction,shape):
    from tests.fixtures import zeek_ics as zi
    from tests.test_zeek_ics_normalize import normalize
    row=zi.ROWS['modbus_detailed'].with_(func='DIAGNOSTICS',request_subfunction_code=subfunction)
    event=normalize(row,shape)
    assert event.get('ics.is_request') is None
    [match]=run(rule('ModeChangeOrRestart'),[event])
    assert match.proposed_lane=='high' and 'request observed' in match.claim
    assert 'acknowledged without exception' not in match.claim


@pytest.mark.parametrize('shape',['malcolm','plain'])
def test_native_bacnet_device_control_request_reaches_the_high_lane(shape):
    from tests.fixtures import zeek_ics as zi
    from tests.test_zeek_ics_normalize import normalize
    event=normalize(zi.ROWS['bacnet_device_control'].with_(device_state='Cold Start'),shape)
    [match]=run(rule('ModeChangeOrRestart'),[event])
    assert match.proposed_lane=='high'
