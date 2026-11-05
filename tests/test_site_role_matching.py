"""Exact declared names and networks never borrow a Zeek sensor's identity."""
import importlib

import pytest

from tests.windows_event_support import event


@pytest.mark.parametrize('value,entries,want', [
    ('10.0.0.2', ('10.0.0.0/24',), True),
    ('10.1.0.2', ('10.0.0.0/24',), False),
    ('::ffff:10.0.0.2', ('10.0.0.2',), True),
    ('2001:db8::2', ('2001:db8::/64',), True),
    ('not-an-address', ('10.0.0.2',), False),
    ('10.0.0.2', ('sccm.example.test',), False),
])
def test_address_roles_use_network_membership(value, entries, want):
    roles = importlib.import_module('romulus.detect.site_roles')
    assert roles.address_member(value, entries) is want


@pytest.mark.parametrize('value,entries,want', [
    ('DC01.EXAMPLE.TEST.', ('dc01.example.test',), True),
    ('dc01', ('dc01.example.test',), True),
    ('dc01.other.test', ('dc01.example.test',), False),
    ('10.0.0.2', ('10.0.0.2',), False),
    ('sccm.example.test', ('sccm*',), False),
])
def test_host_roles_use_exact_names_and_conservative_short_name_matching(value, entries, want):
    roles = importlib.import_module('romulus.detect.site_roles')
    assert roles.host_member(value, entries) is want


def test_declared_source_cannot_use_the_observer_or_rpc_server_address():
    roles = importlib.import_module('romulus.detect.site_roles')
    observed = event('rpc_tx', 1, host='sync01', **{
        'source.ip': '10.0.0.9', 'destination.ip': '10.0.0.2', 'rpc.network_address': '10.0.0.2'})
    assert not roles.declared_source(observed, ('sync01',), ('10.0.0.2',))
    assert roles.declared_source(observed, (), ('10.0.0.9',))
