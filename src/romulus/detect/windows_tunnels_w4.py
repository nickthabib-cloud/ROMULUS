"""Native loopback service records and explicit port-forwarding configuration requests."""
from __future__ import annotations

import ipaddress
import json
import re

from romulus.detect.windows_behavior import BehaviorFleetRule
from romulus.detect.windows_cmdline import split_argv
from romulus.detect.windows_ecar import class_discriminator, ecar_record
from romulus.detect.windows_events import WindowsEventRule, basename, components, integer, signal
from romulus.detect.windows_memory_events import _installed_path
from romulus.evidence.windows_catalog import SECURITY, SYSMON, SYSMON_CHANNEL

_NETSH = 'https://learn.microsoft.com/windows-server/networking/technologies/netsh/netsh-interface-portproxy'
_RDP = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager'
_RDP_CHANNEL = _RDP + '/Operational'
_PORTS = frozenset({3389, 445, 5985})
_WEB = frozenset({'w3wp.exe', 'httpd.exe', 'php-cgi.exe', 'tomcat.exe', 'tomcat8.exe', 'tomcat9.exe', 'tomcat10.exe'})


def _loopback(value):
    try:
        return ipaddress.ip_address(str(value)).is_loopback
    except ValueError:
        return False


def _command(event):
    return split_argv(str(event.get('process.command_line') or ''))


def _request_port(value):
    number = integer(value)
    if number is not None:
        return 1 <= number <= 65535
    # The documented command also accepts service names. Do not resolve them
    # against this analyst machine or imply the target accepted the request.
    return isinstance(value, str) and re.fullmatch(r'[a-z][a-z0-9-]*', value) is not None


def _portproxy_parameters(tokens):
    names = ('listenport', 'connectaddress', 'connectport', 'listenaddress', 'protocol')
    values = {}
    for token in tokens:
        if '=' in token:
            prefix, value = token.split('=', 1)
            candidates = [name for name in names if prefix and name.startswith(prefix)]
            if len(candidates) != 1:
                return None
            name = candidates[0]
        else:
            name = next((name for name in names if name not in values), None)
            value = token
        if name is None or name in values or not value:
            return None
        values[name] = value
    values.setdefault('connectport', values.get('listenport'))
    if not values.get('connectaddress') or not all(_request_port(values.get(name))
                                                 for name in ('listenport', 'connectport')):
        return None
    if values.get('protocol', 'tcp') != 'tcp':
        return None
    return values


def _forward_endpoint(value, version):
    address, separator, port = str(value or '').rpartition('/')
    if not separator or not 1 <= (integer(port) or 0) <= 65535:
        return False
    try:
        return ipaddress.ip_address(address).version == version
    except ValueError:
        # Retain DNS/NetBIOS names without resolving them on the analyst host.
        labels = address.rstrip('.').split('.')
        return (len(address) <= 253 and not re.fullmatch(r'[0-9.]+', address)
                and all(re.fullmatch(r'(?i)[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?', label)
                        for label in labels))


class LoopbackRemoteService(BehaviorFleetRule):
    id = 'win.loopback_remote_service'
    title = 'RDP authentication or logon names a loopback source'
    families = ('auth', 'remote_access')
    windows_event_classes = (('Security', SECURITY, 4624), (_RDP_CHANNEL, _RDP, 1149))
    attack = ('T1572', 'T1090.001')
    benign = ('Local gateways, legitimate forwarding and local clients can produce loopback logons.',)
    next_checks = ('Review forwarding configuration and the resulting session activity.',)
    research = ('https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4624',)

    def judge(self, event):
        code = event.get('event.code')
        if code == 4624:
            if integer(event.get('auth.logon_type')) != 10:
                return []
            action = 'a RemoteInteractive logon'
        elif code == 1149 and event.get('remote.action') == 'rdp_authentication':
            action = 'RDP authentication'
        else:
            return []
        address = event.get('source.ip')
        if not address:
            self.missing_required += 1
            return []
        if not _loopback(address):
            return []
        return [signal(event, 'loopback_rdp_logon', f'Windows recorded {action} naming loopback source {address}',
                       self.attack, ('source.ip', 'auth.logon_type', 'remote.action', 'remote.user', 'auth.target_account'),
                       content=json.dumps([code, address, event.get('auth.target_account'), event.get('remote.user')], sort_keys=True),
                       notes=('A loopback source is observed; it does not prove a remote tunnel, authorization or malicious access.',))]


class LoopbackServiceConnection(WindowsEventRule):
    ecar_compatible = True
    id = 'win.loopback_service_connection'
    title = 'A nonstandard process connected to a loopback remote-management service'
    families = ('net_socket',)
    windows_event_classes = ((SYSMON_CHANNEL, SYSMON, 3),)
    required_fields = ('process.executable',)
    attack = ('T1572', 'T1090.001')
    benign = ('Authorized local forwarding or management software can make these connections.',)
    next_checks = ('Inspect the process lineage and any forwarding configuration.',)
    research = ('https://learn.microsoft.com/sysinternals/downloads/sysmon',)

    def judge(self, event):
        if not class_discriminator(event, 3, 'net_socket'):
            return []
        image = event.get('process.executable_key') or event.get('process.executable')
        if not image:
            self.missing_required += 1
            return []
        for endpoint in ('source', 'destination'):
            port = integer(event.get(endpoint + '.port'))
            if port not in _PORTS or not _loopback(event.get(endpoint + '.ip')):
                continue
            name = basename(image)
            expected = {3389: {'mstsc.exe', 'svchost.exe'},
                        445: {'system', 'system.exe'}, 5985: {'svchost.exe'}}
            if _installed_path(image) and name in expected[port]:
                continue
            if port == 445 and name == 'system' and str(image).casefold() == 'system':
                continue
            high = name in _WEB
            return [signal(event, 'loopback_management_connection',
                           f"Recorded process '{self.describe(image)}' made a loopback connection on service port {port}",
                           self.attack, ('process.executable', endpoint + '.ip', endpoint + '.port', 'network.transport'),
                           lane='high' if high else 'lead',
                           content=json.dumps([image, endpoint, port, event.get(endpoint + '.ip')]),
                           notes=('The connection does not establish a tunnel or successful remote administration.',))]
        return []


class PortproxyConfiguration(WindowsEventRule):
    ecar_compatible = True
    id = 'win.portproxy_configuration'
    version = "2"
    title = 'Windows port-proxy configuration was requested or written'
    families = ('process_exec', 'registry_change')
    windows_event_classes = ((SYSMON_CHANNEL, SYSMON, 1), ('Security', SECURITY, 4688), (SYSMON_CHANNEL, SYSMON, 13))
    attack = ('T1572', 'T1090.001')
    benign = ('Authorized administrators configure local forwarding and compatibility proxies.',)
    next_checks = ('Review the listener/target ownership and whether forwarding took effect.',)
    research = (_NETSH,)

    def judge(self, event):
        if event.family == 'registry_change':
            if not class_discriminator(event, 13, 'registry_change'):
                return []
            path = event.get('registry.path') or event.get('registry.path_key')
            if ecar_record(event) and event.has('registry.value_name'):
                path = str(path or '').rstrip('\\') + '\\' + str(event.get('registry.value_name'))
            stem, separator, listener = str(path or '').rpartition('\\')
            parts = components(stem)
            if not separator or len(parts) != 7 or parts[0] not in {'hklm', 'hkey_local_machine'} or parts[1] != 'system':
                return []
            if not (parts[2] == 'currentcontrolset' or re.fullmatch(r'controlset[0-9]{3}', parts[2])):
                return []
            if parts[3:5] != ('services', 'portproxy') or parts[5] not in {'v4tov4', 'v4tov6', 'v6tov4', 'v6tov6'} or parts[6] != 'tcp':
                return []
            mode = parts[5]
            high = _forward_endpoint(listener, int(mode[1])) and _forward_endpoint(event.get('registry.value'), int(mode[5]))
            return [signal(event, 'portproxy_registry', f'A Windows port-proxy forwarding value was written at {self.describe(path)}',
                           self.attack, ('registry.path', 'registry.path_key', 'registry.value',
                                         *(('registry.value_name',) if ecar_record(event) else ())), lane='high' if high else 'lead',
                           content=json.dumps([path, event.get('registry.value')]),
                           notes=('The registry write is observed; active forwarding or successful access is not established.',))]
        image = event.get('process.executable_key') or event.get('process.executable')
        if basename(image) != 'netsh.exe':
            return []
        argv = _command(event)
        tokens = [token.casefold() for token in argv[1:]]
        if tokens[:1] == ['-c']:
            tokens = tokens[1:]
        if len(tokens) < 5 or not tokens[0] or not 'interface'.startswith(tokens[0]) or not tokens[1] or not 'portproxy'.startswith(tokens[1]):
            return []
        if not tokens[2] or not any(action.startswith(tokens[2]) for action in ('add', 'set')):
            return []
        # The short v-prefix records an attempted address-family request; it does
        # not establish that netsh accepted an ambiguous abbreviation.
        if not tokens[3] or not any(mode.startswith(tokens[3]) for mode in ('v4tov4', 'v4tov6', 'v6tov4', 'v6tov6')):
            return []
        if _portproxy_parameters(tokens[4:]) is None:
            self.missing_required += 1
            return []
        return [signal(event, 'portproxy_argv', 'A recorded netsh command requested a port-proxy forwarding configuration',
                       self.attack, ('process.executable', 'process.command_line'), lane='high',
                       content=json.dumps(argv[1:], ensure_ascii=True),
                       notes=('A configuration request is observed; successful command parsing, forwarding and remote access are not established.',))]


RULES = (LoopbackRemoteService, LoopbackServiceConnection, PortproxyConfiguration)
