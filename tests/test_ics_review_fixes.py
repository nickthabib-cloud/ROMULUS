"""Native ICS omissions remain visible, and unfiltered polling does not consume command state."""
from datetime import timedelta

import pytest

from romulus.evidence.typed import fv
from tests.test_ics_rules import event, rule
from tests.windows_event_support import run


def count_rows(owner):
    return owner.rows.store().execute('SELECT COUNT(*) FROM windows_rows').fetchone()[0] if owner.rows.ready else 0


@pytest.mark.parametrize('name', ['WriteOrControlCommand', 'ModeChangeOrRestart', 'ProgramTransfer'])
@pytest.mark.parametrize('volume', [1000, 100_000])
def test_polling_responses_allocate_no_command_rows(name, volume):
    owner = rule(name)
    for start in range(0, volume, 500):
        owner.consume([event(n, op='read', request=False, offset=n, transaction=str(n), exception=False)
                       for n in range(start, min(start + 500, volume))])
    assert count_rows(owner) == 0
    assert owner.drain_staged() == []


@pytest.mark.parametrize('sender,receiver', [(None, '10.0.0.20'), ('10.0.0.8', None),
                                          ('10.0.0.8', '10.0.0.8')])
def test_unusable_request_endpoints_are_named_as_missing(sender, receiver):
    owner = rule('WriteOrControlCommand')
    assert run(owner, [event(sender=sender, receiver=receiver)]) == []
    assert owner.missing_required == 1
    assert any('1 ICS requests had no typed endpoints' in note for note in owner.coverage_notes())


@pytest.mark.parametrize('subfunction', [None, ''])
def test_modbus_diagnostics_without_a_subfunction_are_not_a_clean_mode_change_evaluation(subfunction):
    owner = rule('ModeChangeOrRestart')
    extra = {} if subfunction is None else {'ics.subfunction': subfunction}
    request = event(op='diagnostic', **{'ics.function_code': 8, 'ics.function_name': 'DIAGNOSTICS'}, **extra)
    assert run(owner, [request]) == []
    assert owner.missing_required == 1
    assert any('1 Modbus diagnostics requests (function 8) had no typed subfunction' in note
               for note in owner.coverage_notes())


def test_typed_modbus_diagnostics_stay_judged_and_other_rules_ignore_them():
    owner = rule('ModeChangeOrRestart')
    typed = event(op='diagnostic', **{'ics.function_code': 8, 'ics.subfunction': 0})
    assert run(owner, [typed]) == [] and owner.missing_required == 0
    restart = event(op='restart', **{'ics.function_code': 8, 'ics.subfunction': 1})
    assert [hit.proposed_lane for hit in run(rule('ModeChangeOrRestart'), [restart])] == ['high']
    writes = rule('WriteOrControlCommand')
    assert run(writes, [event(op='diagnostic', **{'ics.function_code': 8})]) == [] and writes.missing_required == 0


def test_unknown_write_capable_protocol_functions_are_not_a_clean_evaluation():
    owner = rule('WriteOrControlCommand')
    assert run(owner, [event(op='other', protocol='s7comm')]) == []
    assert owner.missing_required == 1
    assert any('1 requests used functions outside the catalogue and were not judged' in note
               for note in owner.coverage_notes())


def test_reused_transaction_ids_count_separate_exception_records():
    owner = rule('ExceptionBurst')
    rows = [event(n, request=False, sender='10.0.0.20', receiver='10.0.0.8', offset=n * 10,
                  exception=True, transaction='7') for n in range(20)]
    [match] = run(owner, rows)
    assert '20 exception responses' in match.claim
    assert match.proposed_lane == 'lead'


def test_other_sensors_copy_exceptions_without_inflating_the_burst():
    owner = rule('ExceptionBurst')
    rows = [event(n, request=False, sender='10.0.0.20', receiver='10.0.0.8', offset=n * 10,
                  exception=True, transaction='7') for n in range(10)]
    copies = [row.model_copy(update={'id': 'copy-' + row.id, 'ts': row.ts + timedelta(seconds=2),
        'fields': {**row.fields, 'observer.name': fv('tap-2', 'second sensor')}}) for row in rows]
    assert run(owner, [rows, copies]) == []


@pytest.mark.parametrize('field', ['ics.unit', 'ics.address', 'ics.quantity',
                                  'ics.status', 'ics.status_code', 'ics.error_class', 'ics.iin'])
def test_distinguishable_exception_records_are_not_cross_sensor_copies(field):
    first, second = ('ILLEGAL_DATA_ADDRESS', 'SLAVE_DEVICE_FAILURE') if field == 'ics.status' else (1, 2)
    rows = [event(n, request=False, sender='10.0.0.20', receiver='10.0.0.8', offset=n * 10,
                  exception=True, transaction='7', **{field: first}) for n in range(10)]
    different = [row.model_copy(update={'id': 'other-' + row.id, 'ts': row.ts + timedelta(seconds=1),
        'fields': {**row.fields, 'observer.name': fv('tap-2', 'second sensor'), field: fv(second, 'different value')}})
        for row in rows]
    [match] = run(rule('ExceptionBurst'), [rows, different])
    assert '20 exception responses' in match.claim


def test_missing_exception_observer_is_partial_instead_of_crashing_or_a_clean_negative():
    owner = rule('ExceptionBurst')
    row = event(request=False, exception=True, **{'observer.name': None}).model_copy(update={'host': None})
    assert run(owner, [row]) == []
    assert owner.missing_required == 1
    assert any('1 ICS exception records had no observer identity' in note for note in owner.coverage_notes())


def test_acknowledgement_survives_unfiltered_polling_responses():
    owner = rule('WriteOrControlCommand')
    rows = [event('read-' + str(n), op='read', request=False, offset=n,
                  transaction='r' + str(n), exception=False) for n in range(1000)]
    request = event('write', offset=10)
    response = event('ack', request=False, sender='10.0.0.20', receiver='10.0.0.8',
                     offset=11, exception=False)
    [match] = run(owner, [rows, [response], [request]])
    assert '1 write acknowledged without exception' in match.claim
    assert count_rows(owner) == 2


@pytest.mark.parametrize('volume', [1000, 100_000])
def test_repeated_discovery_queries_coalesce_without_keeping_every_record(volume):
    owner = rule('RemoteDiscovery')
    for start in range(0, volume, 500):
        owner.consume([event(n, op='discovery', offset=n / 100, transaction=str(n))
                       for n in range(start, min(start + 500, volume))])
    store = owner.rows.store()
    tables = {row[0] for row in store.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    retained = count_rows(owner)
    if 'ics_discovery' in tables:
        retained += store.execute('SELECT COUNT(*) FROM ics_discovery').fetchone()[0]
    assert retained == 1
    assert store.execute('SELECT SUM(records) FROM ics_discovery').fetchone()[0] == volume


def test_coalesced_discovery_history_keeps_the_middle_qualifying_window():
    rows = [event('history-' + str(n), op='discovery', offset=n * 300, transaction=str(n))
            for n in range(10)]
    rows += [event('fanout-' + str(n), op='discovery', receiver=f'10.0.1.{n}', offset=1300 + n)
             for n in range(1, 5)]
    [match] = run(rule('RemoteDiscovery'), [rows[-4:], rows[:-4]])
    assert '5 distinct receivers' in match.claim


def test_discovery_does_not_bridge_a_real_gap_between_retained_intervals():
    rows = [event('early', op='discovery', offset=0), event('late', op='discovery', offset=2002)]
    rows += [event('fanout-' + str(n), op='discovery', receiver=f'10.0.1.{n}', offset=650 + n)
             for n in range(1, 5)]
    assert run(rule('RemoteDiscovery'), rows) == []


@pytest.mark.parametrize('sender,receiver', [(None, '10.0.0.20'), ('10.0.0.8', None),
                                          ('10.0.0.8', '10.0.0.8')])
def test_discovery_endpoint_omissions_are_named_as_missing(sender, receiver):
    owner = rule('RemoteDiscovery')
    assert run(owner, [event(op='discovery', sender=sender, receiver=receiver)]) == []
    assert owner.missing_required == 1
    assert any('1 ICS requests had no typed endpoints' in note for note in owner.coverage_notes())


def test_modbus_discovery_summaries_use_logical_roles_without_inventing_packet_direction():
    rows = [event(n, op='discovery', request=None, sender=None, receiver=None, offset=n,
                  **{'ics.request_observed': True, 'conn.orig_h': '10.0.0.8',
                     'conn.resp_h': f'10.0.1.{n}'}) for n in range(1, 6)]
    [match] = run(rule('RemoteDiscovery'), rows)
    assert '5 distinct receivers' in match.claim
    assert any('logical connection' in note for note in match.notes)
    assert all(not row.has('ics.sender') and not row.has('ics.receiver') for row in match.events)
    [context] = run(rule('RemoteDiscovery', ['10.0.0.8']), rows[:1])
    assert context.proposed_lane == 'context'
