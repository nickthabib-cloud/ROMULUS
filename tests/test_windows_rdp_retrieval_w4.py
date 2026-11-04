"""RdpCoreTS channel chatter remains inventory-only unless a rule reads it."""
from datetime import timedelta

import pytest

from romulus.detect.base import Playbook
from romulus.evidence.windows_catalog import EVENT_CLASSES
from romulus.hunt.sweep import Sweep
from romulus.sources.compile import compile_es
from romulus.sources.models import SearchIntent, Window
from tests.test_windows_catalog_state_w4 import CHANNEL, RDP
from tests.test_windows_process_coverage import START, _contract
from tests.throughput_fixture import _matches


class Reader(Playbook):
    id = 'win.rdp_bluekeep_channel'
    families = ('remote_access',)
    os_families = ('windows',)
    windows_event_classes = tuple((CHANNEL, RDP, code) for code in (131, 132, 148, 168))


def setup(extra=()):
    contract = _contract()
    window = Window(start=START, end=START + timedelta(hours=1))
    sweep = Sweep(None, None, 'test', window, {contract.target: contract})
    sweep.pack = [Reader(), *extra]
    sweep._windows_read_tokens[contract.target] = {event.token for event in EVENT_CLASSES if event.family == 'remote_access'}
    return sweep, contract, window


def fetched(sweep, contract, window, code, name=None):
    groups = sweep._any_of_for(contract.target, contract)
    assert groups
    body = compile_es(SearchIntent(kind='raw', target=contract.target, window=window, any_of=groups), contract).body
    source = {'@timestamp': (START + timedelta(minutes=1)).isoformat(), 'winlog': {
        'channel': CHANNEL, 'provider_name': RDP, 'event_id': code,
        'event_data': {} if name is None else {'ChannelName': name}}}
    return _matches(body['query'], source, '@timestamp')


@pytest.mark.parametrize('code', [132, 148])
@pytest.mark.parametrize('name', ['ms_t120', 'MS_T120', 'mS_t120', 'Ms_T120'])
def test_native_internal_channel_ascii_cases_survive_flattened_query(code, name):
    sweep, contract, window = setup()
    assert fetched(sweep, contract, window, code, name)
    assert not fetched(sweep, contract, window, code, 'rdpdr')


@pytest.mark.parametrize('code', [68, 72, 104, 129, 140])
def test_unread_core_channel_classes_stay_inventory_only(code):
    sweep, contract, window = setup()
    assert not fetched(sweep, contract, window, code)


@pytest.mark.parametrize('code', [131, 168, 132, 148])
def test_connection_spine_and_missing_channel_name_remain_accountable(code):
    sweep, contract, window = setup()
    assert fetched(sweep, contract, window, code)


def test_missing_channel_mapping_withholds_channel_chatter_and_names_partial():
    sweep, contract, window = setup()
    contract.fields.pop('remote.channel_name', None)
    assert not fetched(sweep, contract, window, 148, 'rdpdr')
    assert any('RdpCoreTS' in reason for reason in sweep._windows_inventory_reasons[contract.target])


@pytest.mark.parametrize('missing', ['event.provider', 'event.code', 'inventory'])
def test_missing_class_mapping_never_fetches_the_whole_rdp_channel(missing):
    sweep, contract, window = setup()
    if missing == 'inventory':
        sweep._windows_read_tokens.clear()
    else:
        contract.fields.pop(missing)
    assert not fetched(sweep, contract, window, 148, 'rdpdr')
    assert sweep._windows_inventory_reasons[contract.target]


def test_another_explicit_reader_preserves_its_required_class():
    class Other(Playbook):
        id = 'test.other'
        families = ('remote_access',)
        os_families = ('windows',)
        windows_event_classes = ((CHANNEL, RDP, 72), (CHANNEL, RDP, 148))
    sweep, contract, window = setup([Other()])
    assert fetched(sweep, contract, window, 72)
    assert fetched(sweep, contract, window, 148, 'rdpdr')
