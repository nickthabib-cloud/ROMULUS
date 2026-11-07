"""Polling selection is bounded, keeps writes/unknowns/exceptions, and falls back visibly."""
from romulus.hunt.ics_filters import selection
from romulus.sources.compile import build_query
from romulus.sources.models import SearchIntent
from romulus.sources.profile import OPS_BY_TYPE, FieldContract, FieldSpec
from tests.test_ics_native_exclusion import intent


def contract(types,**extra):
    return FieldContract(target='ics',role='network',**extra,fields={
        path:FieldSpec(native=path,type=kind,ops=sorted(OPS_BY_TYPE[kind]),aggregatable=True)
        for path,kind in types.items()})


def accepts(query,row):
    if 'bool' in query:
        body=query['bool']
        return (all(accepts(item,row) for item in body.get('filter',[]))
            and not any(accepts(item,row) for item in body.get('must_not',[]))
            and (not body.get('should') or sum(accepts(item,row) for item in body['should'])>=body.get('minimum_should_match',1)))
    if 'range' in query:
        return True  # source window is fixed for this synthetic polling batch
    if 'exists' in query:
        return query['exists']['field'] in row
    if 'term' in query:
        field,value=next(iter(query['term'].items()))
        return row.get(field)==value
    field,values=next(iter(query['terms'].items()))
    return row.get(field) in values


def query(plan,owner):
    base=intent([3])
    return build_query(SearchIntent(kind='raw',target='ics',window=base.window,any_of=plan.groups),owner)


def test_large_polling_batch_excludes_every_read_and_retains_every_write_and_exception():
    owner=contract({'func':'keyword','exception':'keyword'},zeek_sensor='tap',zeek_log='modbus')
    plan=selection(owner,{})
    assert plan.selected and 'excluded at retrieval' in ' '.join(plan.reasons)
    compiled=query(plan,owner)
    rows=({'func':'READ_HOLDING_REGISTERS'} for _ in range(100_000))
    assert sum(accepts(compiled,row) for row in rows)==0
    rows=[{'func':'WRITE_SINGLE_REGISTER'} for _ in range(40)]
    rows += [{'func':'READ_INPUT_REGISTERS','exception':'ILLEGAL_DATA_ADDRESS'},
             {'func':'FUTURE_VENDOR_COMMAND'},{}]
    assert sum(accepts(compiled,row) for row in rows)==43
    assert len(plan.groups)<=3


def test_unmapped_or_analyzed_function_field_retrieves_unfiltered_with_reason():
    for fields in ({'exception':'keyword'},{'func':'text','exception':'keyword'}):
        plan=selection(contract(fields,zeek_sensor='tap',zeek_log='modbus'),{})
        assert not plan.selected and not plan.groups
        assert 'unfiltered' in ' '.join(plan.reasons)


def test_missing_contract_keeps_retrieval_unfiltered_with_reason():
    plan = selection(None, {})
    assert not plan.selected and not plan.groups
    assert 'no field contract' in ' '.join(plan.reasons)


def test_mixed_malcolm_selection_does_not_exclude_another_producer_or_hide_missing_functions():
    owner=contract({'event.provider':'keyword','event.dataset':'keyword',
                    'zeek.modbus.func':'keyword','zeek.modbus.exception':'keyword'})
    plan=selection(owner,{'datasets':{'zeek:modbus':100},
        'inventory':[{'provider':'zeek','dataset':'modbus'},{'provider':'suricata','dataset':'flow'}]})
    assert plan.selected
    compiled=query(plan,owner)
    assert not accepts(compiled,{'event.provider':'zeek','event.dataset':'modbus',
                                'zeek.modbus.func':'READ_HOLDING_REGISTERS'})
    assert accepts(compiled,{'event.provider':'suricata','event.dataset':'modbus',
                             'zeek.modbus.func':'READ_HOLDING_REGISTERS'})
    assert accepts(compiled,{'event.provider':'zeek','event.dataset':'modbus'})
    assert accepts(compiled,{'event.provider':'zeek','event.dataset':'conn'})


def test_sweep_connects_ics_selection_and_retains_existing_filters():
    from romulus.hunt.sweep import Sweep
    from romulus.sources.models import Predicate
    owner=contract({'func':'keyword','exception':'keyword'},zeek_sensor='tap',zeek_log='modbus')
    sweep=Sweep.__new__(Sweep)
    sweep._profiles={'ics':{}}
    groups=sweep._select_ics('ics',owner,[[Predicate(field='func',op='exists')]])
    assert groups and all(group[0].op=='exists' for group in groups)
    assert sweep._ics_selection['ics'].selected


def test_unfilterable_second_shipper_shape_cannot_disappear_from_a_mixed_target():
    owner=contract({'event.provider':'keyword','event.dataset':'keyword','event.module':'text',
        'data_stream.dataset':'text','zeek.modbus.func':'keyword','zeek.modbus.exception':'keyword',
        'modbus.function':'keyword','modbus.exception':'keyword'})
    plan=selection(owner,{'datasets':{'zeek:modbus':20,'zeek.modbus':20},
        'inventory':[{'provider':'zeek','dataset':'modbus'},{'provider':'','dataset':'zeek.modbus'}]})
    assert not plan.selected and not plan.groups
    assert 'unfiltered' in ' '.join(plan.reasons)


def test_address_ioc_search_keeps_reads_even_when_ics_polling_can_be_filtered():
    from romulus.detect.indicators import Indicator, IndicatorMatch, IndicatorSet
    from romulus.hunt.sweep import Sweep
    owner=contract({'func':'keyword','exception':'keyword'},zeek_sensor='tap',zeek_log='modbus')
    sweep=Sweep.__new__(Sweep)
    sweep._profiles={'ics':{}}
    sweep.pack=[IndicatorMatch(IndicatorSet([Indicator('ics-ip','ip',('10.0.0.8',),'address','high','high')]))]
    assert sweep._select_ics('ics',owner,[])==[]
    assert not sweep._ics_selection['ics'].selected
    assert 'indicator' in ' '.join(sweep._ics_selection['ics'].reasons).lower()


def test_unknown_producer_native_inventory_cannot_be_covered_by_only_a_malcolm_marker():
    owner=contract({'event.provider':'keyword','event.dataset':'keyword',
                    'zeek.modbus.func':'keyword','zeek.modbus.exception':'keyword'})
    plan=selection(owner,{'datasets':{'zeek:modbus':20},'inventory':[
        {'provider':'zeek','dataset':'modbus'},{'provider':'','dataset':'modbus'}]})
    assert not plan.selected and not plan.groups
