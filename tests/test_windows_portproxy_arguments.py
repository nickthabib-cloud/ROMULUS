"""Documented named, positional and service-name operands in native proxy requests."""
import pytest

from romulus.detect.windows_tunnels_w4 import PortproxyConfiguration
from tests.test_windows_b_round5 import proc
from tests.windows_process_support import run


@pytest.mark.parametrize('arguments', [
    '3389 192.0.2.10 3389 0.0.0.0',
    'https 192.0.2.10 https 0.0.0.0 tcp',
    'listenport=https connectaddress=server.example.test connectport=https',
    'listenport=3389 192.0.2.10 3389',
    '3389 connectaddress=192.0.2.10 connectport=3389',
    'listenp=3389 connecta=192.0.2.10 connectp=3389',
])
def test_documented_portproxy_operands_publish_native_request(arguments):
    rule = PortproxyConfiguration()
    try:
        [match] = run(rule, [proc('netsh.exe', 'netsh.exe interface portproxy add v4tov4 ' + arguments)])
        assert match.proposed_lane == 'high' and 'request' in match.claim
        assert 'successful command parsing' in ' '.join(match.notes)
    finally:
        rule.release_state()


@pytest.mark.parametrize('arguments', [
    '0 192.0.2.10 3389',
    '3389 192.0.2.10 70000',
    '-invalid 192.0.2.10 https',
    '3389 192.0.2.10 https 0.0.0.0 udp',
    '3389 192.0.2.10',
    'listenport=3389 connectaddress=192.0.2.10 connectport=3389 unexpected=value',
    'l=3389 connectaddress=192.0.2.10 connectport=3389',
    'listenport=3389 listenport=443 connectaddress=192.0.2.10 connectport=3389',
])
def test_malformed_or_ambiguous_proxy_operands_stay_quiet(arguments):
    rule = PortproxyConfiguration()
    try:
        assert not run(rule, [proc('netsh.exe', 'netsh.exe interface portproxy add v4tov4 ' + arguments)])
    finally:
        rule.release_state()
