"""Inventory lag cannot hide new ICS logs, and one read-unfilterable log stays local."""
from romulus.hunt.ics_filters import selection
from tests.test_ics_retrieval import accepts, contract, query


def test_inventory_lag_and_missing_provider_retain_uninventoried_ics_records():
    owner = contract({'event.provider': 'keyword', 'event.dataset': 'keyword',
                      'zeek.modbus.func': 'keyword', 'zeek.modbus.exception': 'keyword'})
    plan = selection(owner, {'datasets': {'zeek:modbus': 100},
                            'inventory': [{'provider': 'zeek', 'dataset': 'modbus'}]})
    assert plan.selected
    compiled = query(plan, owner)
    for dataset in ('s7comm', 'bacnet_property', 'bacnet_device_control'):
        assert accepts(compiled, {'event.provider': 'zeek', 'event.dataset': dataset})
    assert accepts(compiled, {'event.dataset': 'modbus', 'zeek.modbus.func': 'READ_COILS'})
    assert not accepts(compiled, {'event.provider': 'zeek', 'event.dataset': 'modbus',
                                  'zeek.modbus.func': 'READ_COILS'})


def test_unfilterable_dnp3_objects_does_not_unfilter_other_logs():
    owner = contract({'event.provider': 'keyword', 'event.dataset': 'keyword',
                      'zeek.modbus.func': 'keyword', 'zeek.modbus.exception': 'keyword',
                      'zeek.dnp3_objects.function_code': 'keyword'})
    plan = selection(owner, {'datasets': {'zeek:modbus': 100, 'zeek:dnp3_objects': 50},
        'inventory': [{'provider': 'zeek', 'dataset': name} for name in ('modbus', 'dnp3_objects')]})
    assert plan.selected
    compiled = query(plan, owner)
    assert accepts(compiled, {'event.provider': 'zeek', 'event.dataset': 'dnp3_objects'})
    assert not accepts(compiled, {'event.provider': 'zeek', 'event.dataset': 'modbus',
                                  'zeek.modbus.func': 'READ_COILS'})
    assert any('dnp3_objects' in note and 'unfiltered' in note for note in plan.reasons)


def test_only_unfilterable_logs_do_not_claim_polling_exclusion():
    owner = contract({'event.provider': 'keyword', 'event.dataset': 'keyword'})
    plan = selection(owner, {'datasets': {'zeek:dnp3_objects': 50}})
    assert not plan.selected
    assert not plan.groups
    assert any('dnp3_objects' in note and 'unfiltered' in note for note in plan.reasons)
