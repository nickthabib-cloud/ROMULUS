"""The high-volume WFP stream is retrieved only for a typed tunnel shape."""
from datetime import timedelta

import pytest

from romulus.detect.base import Playbook
from romulus.evidence.windows_catalog import SECURITY, WindowsEventClass
from romulus.hunt import sweep as module
from romulus.hunt.sweep import Sweep
from romulus.sources.compile import compile_es
from romulus.sources.models import SearchIntent, Window
from tests.test_windows_process_coverage import START, _contract
from tests.throughput_fixture import _matches


class TunnelReader(Playbook):
    id = 'win.rdp_loopback_tunnel'
    families = ('network_filter',)
    os_families = ('windows',)


def setup(monkeypatch):
    classes = [WindowsEventClass('Security', SECURITY, code, 'network_filter', 'WFP',
               f'https://learn.microsoft.com/windows/security/threat-protection/auditing/event-{code}')
               for code in (5156, 5158)]
    monkeypatch.setattr(module, 'EVENT_CLASSES', classes)
    contract = _contract()
    window = Window(start=START, end=START + timedelta(hours=1))
    sweep = Sweep(None, None, 'test', window, {contract.target: contract})
    sweep.pack = [TunnelReader()]
    sweep._windows_read_tokens[contract.target] = {item.token for item in classes}
    return sweep, contract, window


@pytest.mark.parametrize('side,address', [('Source', '127.0.0.2'), ('Dest', '127.12.1.5'),
                                        ('Source', '::1'), ('Dest', '0:0:0:0:0:0:0:1')])
def test_wfp_tunnel_query_keeps_each_loopback_orientation(monkeypatch, side, address):
    sweep, contract, window = setup(monkeypatch)
    groups = sweep._any_of_for(contract.target, contract)
    assert groups and all(any(p.field.startswith('wfp.') for p in group) for group in groups)
    body = compile_es(SearchIntent(kind='raw', target=contract.target, window=window, any_of=groups), contract).body
    # The fixture matcher executes the actual compiled filter on a native Winlogbeat record.
    data = {'SourceAddress': '10.0.0.8', 'DestAddress': '10.0.0.9', 'SourcePort': '49152', 'DestPort': '445'}
    data[side + 'Address'] = address
    data[side + 'Port'] = '3389'
    source = {'@timestamp': (START + timedelta(minutes=1)).isoformat(),
              'winlog': {'channel': 'Security', 'provider_name': SECURITY, 'event_id': 5156, 'event_data': data}}
    assert _matches(body['query'], source, '@timestamp')
    data[side + 'Port'] = '445'
    assert not _matches(body['query'], source, '@timestamp')


def test_wfp_bind_records_are_inventory_only(monkeypatch):
    sweep, contract, _ = setup(monkeypatch)
    groups = sweep._any_of_for(contract.target, contract)
    assert not any(p.field == 'event.code' and p.value == 5158 for group in groups for p in group)


def test_missing_wfp_mapping_is_named_without_fetching_whole_stream(monkeypatch):
    sweep, contract, _ = setup(monkeypatch)
    for field in list(contract.fields):
        if field.startswith('wfp.'):
            del contract.fields[field]
    groups = sweep._any_of_for(contract.target, contract)
    assert not any(p.field == 'event.code' and p.value in (5156, 5158) for group in groups for p in group)
    assert any('WFP' in reason for reason in sweep._windows_inventory_reasons[contract.target])


@pytest.mark.parametrize('missing', ['event.code', 'event.provider', 'inventory'])
def test_wfp_unavailable_class_filter_preserves_security_fallback(monkeypatch, missing):
    sweep, contract, window = setup(monkeypatch)
    if missing == 'inventory':
        sweep._windows_read_tokens.clear()
    else:
        contract.fields.pop(missing)
    groups = sweep._any_of_for(contract.target, contract)
    assert groups
    body = compile_es(SearchIntent(kind='raw', target=contract.target, window=window, any_of=groups), contract).body
    source = {'@timestamp': (START + timedelta(minutes=1)).isoformat(),
              'winlog': {'channel': 'Security', 'provider_name': SECURITY, 'event_id': 5156,
                         'event_data': {'DestPort': '445', 'DestAddress': '10.0.0.9'}}}
    assert _matches(body['query'], source, '@timestamp') == (missing != 'inventory')
    assert sweep._windows_inventory_reasons[contract.target]
