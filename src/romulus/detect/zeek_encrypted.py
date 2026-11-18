"""Remote administration, RPC, Kerberos and directory traffic judged from what Zeek records whether or not it can
read the payload.

SMB 3 encryption, sealed DCE-RPC, WinRM over HTTPS or Kerberos-wrapped HTTP, LDAP with sign-and-seal or TLS, SSH and
RDP over TLS all hide the operations the protocol rules (``net.rpc_*``, ``net.smb_*``, ``net.http_winrm``) read. The
connection itself stays visible in Zeek's conn log, and Kerberos ticket exchanges keep their service names in clear.
These rules read only those typed facts:

- ``net.remote_shell_fanout`` and ``net.smb_rpc_fanout``: one internal source opening connections to a remote-access
  or SMB/RPC port on many internal hosts within minutes. Every counted connection is one Zeek shows the source opening
  (its history begins with the originator's SYN) and both sides carrying payload, so refused attempts, SYN-only probes
  and silent hosts (the sweeps ``net.horizontal_sweep`` counts) are never members.
- ``net.epm_dynamic_rpc``: a connection to the RPC endpoint mapper (135/tcp) and, within thirty seconds after it, a
  connection from the same source to the same host on a high port: the client asks the mapper where an interface
  listens and then binds to it, the shape of DCOM, WMI, remote task scheduling and other MS-RPC over TCP. Declared
  domain controllers are never destinations, so this shape toward a controller is not judged here.
- ``net.kerberos_service_ticket_fanout``: TGS exchanges for many distinct services from one source and client,
  whatever the ticket's encryption type (``net.kerberos_rc4_service_fanout`` counts the RC4 ones).
- ``net.ldap_bulk_response``: one directory-service connection on which the server sent a bulk volume of data to a
  client that is not a declared domain controller.

All are positive-only: a connection shows that two hosts exchanged data, never what was done, and the absence of a
record says nothing. Missing typed fields are counted as unevaluated records, never as a negative.
"""
from __future__ import annotations

import json
from datetime import timedelta
from ipaddress import ip_address
from typing import ClassVar

from romulus.detect.bounded import HOT_COUNT, KeyedStore
from romulus.detect.netdef import DIRECTION_ASSUMED_REASON, assume_direction, current
from romulus.detect.network_producers import ZEEK_ONLY, rule_reads
from romulus.detect.site_roles import address_member
from romulus.detect.windows_events import signal
from romulus.detect.zeek_lateral import ZeekBehaviorRule, _site_networks
from romulus.detect.zeek_rate_state import ZeekWindowRule
from romulus.hunt.citations import COMPACT_CITATION_NOTE, compact_event, expand_event

_CONN_DOC = 'https://docs.zeek.org/en/master/scripts/base/protocols/conn/main.zeek.html'
_KRB_DOC = 'https://docs.zeek.org/en/master/scripts/base/protocols/krb/main.zeek.html'
_RPC_PORTS_DOC = ('https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/'
                  'default-dynamic-port-range-tcpip-chang')
_EPM_DOC = 'https://pubs.opengroup.org/onlinepubs/9629399/apdxo.htm'
_DCOM_DOC = 'https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/'
_SERVICE_PORTS_DOC = ('https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/'
                      'service-overview-and-network-port-requirements')

_CONN_FIELDS = ('observer.name', 'observer.product', 'zeek.log', 'zeek.uid', 'source.ip', 'source.port',
                'destination.ip', 'destination.port', 'network.transport', 'network.protocols', 'conn.history',
                'conn.state', 'tcp.opened_by_orig', 'flow.bytes_toserver', 'flow.bytes_toclient', 'session.duration_s',
                'conn.interim')
_CONN_REQUIRED = ('source.ip', 'destination.ip', 'destination.port', 'network.transport')

REMOTE_SHELL_PORTS = {22: 'SSH', 3389: 'RDP', 5985: 'WinRM', 5986: 'WinRM over TLS'}
SMB_RPC_PORTS = {445: 'SMB', 139: 'SMB over NetBIOS', 135: 'RPC endpoint mapper'}
DIRECTORY_PORTS = {389: 'LDAP', 636: 'LDAPS', 3268: 'global catalog', 3269: 'global catalog over TLS'}
EPM_PORT = 135
# The dynamic leg: any registered or dynamic port (Windows uses 49152-65535 by default and 1025-5000 before Vista,
# and administrators can restrict RPC to another range), excluding the fixed ports of other Windows services. A Zeek
# service name on the leg must be one MS-RPC can carry.
DYNAMIC_FLOOR = 1024
NOT_DYNAMIC = frozenset({*REMOTE_SHELL_PORTS, *SMB_RPC_PORTS, *DIRECTORY_PORTS, 88, 464, 1433, 1434, 3306, 5432,
                         5722, 8080, 8443, 9389})
RPC_SERVICES = frozenset({'dce_rpc', 'gssapi', 'ntlm', 'krb', 'krb_tcp'})
# A client looks up an interface in the endpoint mapper and binds to the returned port at once: the lookup and the
# bind are one call path in the RPC runtime (and DCOM activation returns its binding the same way), so the second
# connection follows within milliseconds to a few seconds. Thirty seconds leaves room for slow links and retries
# without pairing unrelated connections minutes apart.
EPM_FOLLOW = timedelta(seconds=30)
# A member's logon, Group Policy processing and name lookups return kilobytes to tens of kilobytes per LDAP
# connection. A search result entry with a tool's attribute set is roughly 1-4 KB, so five million bytes on one
# connection is thousands of directory objects returned to one client: a bulk read of users, groups or computers,
# far above routine member traffic. A domain with fewer objects than that cannot produce it, and a reader that splits
# its reads across many connections stays under it on each.
LDAP_BULK_BYTES = 5_000_000


def _networks(rule):
    site = getattr(rule, 'site_facts', None)
    internal = tuple(getattr(site, 'internal_networks', ()) or ())
    return _site_networks(internal, tuple(getattr(site, 'external_networks', ()) or ())) if internal else current()


def _address(value):
    try:
        address = ip_address(value)
    except (ValueError, TypeError):
        return None
    return getattr(address, 'ipv4_mapped', None) or address


def _count(value):
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _conn_record(event):
    """A Zeek conn record (the only net_flow log Zeek writes)."""
    return event.family == 'net_flow' and rule_reads(event, ZEEK_ONLY) and event.get('zeek.log') == 'conn'


def _exchange(event):
    """(answered, decided): whether Zeek shows the source opening this TCP connection and both sides sending payload.
    `decided` is False when the history or a payload counter is not recorded, so the record cannot be judged."""
    sent, received = _count(event.get('flow.bytes_toserver')), _count(event.get('flow.bytes_toclient'))
    if event.get('conn.history') in (None, '') or sent is None or received is None:
        return False, False
    return event.get('tcp.opened_by_orig') is True and sent > 0 and received > 0, True


def _site(rule):
    return getattr(rule, 'site_facts', None)


def _notes_for_source(rule, source, networks):
    notes = []
    if address_member(source, getattr(_site(rule), 'management_hosts', ())):
        notes.append('declared management source; authorized administration can produce these connections')
    if not networks.configured:
        notes.append(DIRECTION_ASSUMED_REASON)
    return notes


def _undecided(rule, name, text):
    rule.evaluated -= 1
    rule.missing_required += 1
    rule.note_coverage(name, text)


class _ConnFanout(ZeekWindowRule):
    """One internal source, many distinct internal destinations on a set of ports, each an answered connection."""
    families = ('net_flow',)
    required_fields = _CONN_REQUIRED
    citation_fields = _CONN_FIELDS
    uses_site_facts = True
    direction_dependent = True
    severity = 'high'
    state_slice = 'routine'
    distinct, thin_members = True, True
    ports: ClassVar[dict[int, str]] = {}
    span_words = ''
    research: ClassVar[tuple[str, ...]] = (_CONN_DOC,)
    adds = ''

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if getattr(cls, 'id', None):
            services = ', '.join(f'{name} ({port}/tcp)' for port, name in sorted(cls.ports.items()))
            cls.card = {
                'behavior': cls.title,
                'telemetry': ('Zeek conn records as net_flow: source.ip, destination.ip, destination.port, '
                              'network.transport, conn.history (tcp.opened_by_orig), flow.bytes_toserver and '
                              'flow.bytes_toclient (payload bytes), in every Zeek shipper shape. Suricata flow '
                              'records are not read: their byte counters are frame bytes and they carry no history'),
                'fidelity': ('Aggregate observation of answered connections: Zeek shows the source opening each one '
                             'and both sides sending payload. The payload is not read; a connection is not a logon, '
                             'a command or a successful authentication'),
                'benign_and_cost': '; '.join(cls.benign) + '. One finding per source, revised in place',
                'query_cost': ('One conn sweep; selected connections are held in the disk-backed window state, '
                               'repeats of one source and destination thinned losslessly to about one per window'),
                'next_pivot': '; '.join(cls.next_checks),
                'adds': cls.adds,
                'research_basis': '; '.join(cls.research),
                'retrieval': ('The sweep retrieves every conn record of the network targets in each partition, a '
                              'superset of what this evaluator reads; rows without history or payload counters are '
                              'counted as unevaluated'),
                'lanes': (f'Lead: {services} to many hosts is also the work of administrators, management servers and '
                          'credentialed scanners; severity high because lateral movement is high impact if adverse'),
                'window': f'{cls.threshold} distinct internal destinations within {cls.span_words}',
            }

    def _peers(self, event):
        """(source, destination) of an opened TCP connection to a counted port, else None; reads typed fields only."""
        if not _conn_record(event) or event.get('network.transport') != 'tcp':
            return None
        if _count(event.get('destination.port')) not in self.ports:
            return None
        source, destination = _address(event.get('source.ip')), _address(event.get('destination.ip'))
        return None if source is None or destination is None or source == destination else (source, destination)

    def skipped(self, source, destination):
        return False

    def live_select(self, event):
        # Coverage counting happens only for records read live, never for a restored witness.
        peers = self._peers(event)
        if peers is not None:
            answered, decided = _exchange(event)
            if not decided:
                _undecided(self, 'conn_exchange', 'Connections to the counted ports without a recorded Zeek history '
                                                  'or payload byte counts were not judged.')
                return None
            if answered:
                assume_direction(self)
        return self.select(event)

    def select(self, event):
        peers = self._peers(event)
        if peers is None:
            return None
        answered, decided = _exchange(event)
        if not (answered and decided):
            return None
        source, destination = peers
        networks = _networks(self)
        if not (networks.is_internal(source) and networks.is_internal(destination)) or self.skipped(source,
                                                                                                     destination):
            return None
        return (str(source),), str(destination), 'attempt'

    def describe(self, event, total_refs, distinct_members, role):
        source = event.get('source.ip')
        services = ', '.join(sorted(set(self.ports.values())))
        notes = [
            'A counted connection is one Zeek shows the source opening, with payload from both sides; refused '
            'attempts and SYN-only probes are not counted.',
            'The payload was not read: these are connections, not logons, commands or successful authentication.',
            'Repeat connections of one source and destination are thinned without changing any window\'s distinct '
            'hosts; the raw-reference count is a lower bound.',
            *_notes_for_source(self, source, _networks(self)),
        ]
        if not getattr(_site(self), 'domain_controller_addresses', ()):
            notes.append('domain controller addresses are not declared: connections a member makes to its controllers '
                         'are counted like any other host')
        return 'lead', (f'Source {source} opened answered {services} connections to at least {distinct_members} '
                        f'distinct internal hosts within {self.span_words} (at least {total_refs} raw references).'), \
            tuple(notes)


class RemoteShellFanout(_ConnFanout):
    id = 'net.remote_shell_fanout'
    title = 'One internal source opened answered SSH, RDP or WinRM connections to several internal hosts'
    ports = REMOTE_SHELL_PORTS
    # An administrator working by hand opens one or two interactive sessions at a time. Four distinct hosts within ten
    # minutes is a script, a tool or a jump host driving them, at any fleet size.
    seconds, threshold, span_words = 600, 4, 'ten minutes'
    attack = ('T1021.001', 'T1021.004', 'T1021.006')
    benign = ('Configuration management (Ansible, Salt over SSH), jump hosts and administrators working through a '
              'list of servers', 'Credentialed vulnerability scanners logging in to each host')
    next_checks = ('Which accounts logged on to the destinations at these times (host logon records)',
                   'Processes started on the destinations by the remote-access service',
                   'Whether the source is a declared management or jump host')
    research = (_CONN_DOC, 'ATT&CK Enterprise 20.0 T1021.001, T1021.004, T1021.006 (Network Traffic: Network '
                'Connection Creation)', _SERVICE_PORTS_DOC)
    adds = ('net.internal_rdp needs Zeek\'s RDP analyzer and reports each session; net.http_winrm needs readable '
            'HTTP. This counts answered connections on the ports themselves, so SSH, WinRM over TLS and RDP the '
            'analyzer did not parse are counted too')


class SmbRpcFanout(_ConnFanout):
    id = 'net.smb_rpc_fanout'
    title = 'One internal source opened answered SMB or RPC endpoint-mapper connections to many internal hosts'
    ports = SMB_RPC_PORTS
    # A client opens SMB and RPC connections to the few servers it uses (domain controllers, file and print servers).
    # Ten distinct hosts within fifteen minutes is host-by-host remote execution or collection, at any fleet size;
    # the same rate the decoded enumeration fan-out uses.
    seconds, threshold, span_words = 900, 10, 'fifteen minutes'
    attack = ('T1021.002', 'T1021.003', 'T1047')
    benign = ('Software distribution, inventory, backup and monitoring servers that reach every host over SMB or RPC',
              'Credentialed vulnerability scanners')
    next_checks = ('Services, scheduled tasks or WMI activity created on the destinations at these times',
                   'Files written to administrative shares on the destinations',
                   'Whether the source is a declared management server')
    research = (_CONN_DOC, 'ATT&CK Enterprise 20.0 T1021.002, T1021.003, T1047 (Network Traffic: Network Connection '
                'Creation)', _SERVICE_PORTS_DOC)
    adds = ('net.rpc_host_enumeration_fanout and the other net.rpc_* rules need decoded RPC operations; '
            'net.horizontal_sweep needs twenty destinations on one port and counts silent ones. This counts only '
            'answered connections, across SMB and the endpoint mapper together, so encrypted SMB 3 and sealed RPC '
            'are counted')

    def skipped(self, source, destination):
        # declared controllers replicate and call each other over SMB and RPC all day
        controllers = getattr(_site(self), 'domain_controller_addresses', ())
        return bool(controllers) and address_member(str(source), controllers) and address_member(str(destination),
                                                                                                 controllers)


class KerberosServiceTicketFanout(ZeekWindowRule):
    id = 'net.kerberos_service_ticket_fanout'
    title = 'TGS exchanges from one source and client for many distinct services'
    families = ('kerberos_tx',)
    required_fields = ('source.ip', 'kerberos.request_type')
    citation_fields = ('observer.name', 'observer.product', 'zeek.log', 'zeek.uid', 'source.ip', 'destination.ip',
                       'kerberos.request_type', 'kerberos.client', 'kerberos.client_name', 'kerberos.service',
                       'kerberos.cipher', 'auth.encryption_type', 'kerberos.success', 'auth.status')
    uses_site_facts = True
    severity = 'high'
    state_slice = 'routine'
    thin_members = True
    # One principal's logon asks for a handful of service tickets (directory, SYSVOL, its file and print servers);
    # Kerberoasting asks for every account with a service name at once. Ten distinct services within five minutes
    # per source and client is the same breadth the Windows ticket-record rule uses, independent of domain size.
    seconds, threshold, distinct = 300, 10, True
    attack = ('T1558.003',)
    benign = ('Multi-user hosts (terminal servers, Citrix) and NAT gateways where many principals share one address',
              'Monitoring and management servers authenticating to many hosts by Kerberos')
    next_checks = ('The services named: user accounts with service names are the Kerberoasting targets',
                   'The ticket encryption types issued (RC4 tickets are crackable offline far faster)',
                   'Logons by the requested service accounts after this window')
    research = (_KRB_DOC, 'ATT&CK Enterprise 20.0 T1558.003',
                'https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/')

    def live_select(self, event):
        if (rule_reads(event, self.producers) and str(event.get('kerberos.request_type')).strip().upper() == 'TGS'
                and _address(event.get('source.ip')) is not None and _service(event.get('kerberos.service')) is None):
            _undecided(self, 'kerberos_service', 'TGS records without a recorded service name were not judged.')
            return None
        return self.select(event)

    def select(self, event):
        if not rule_reads(event, self.producers) or str(event.get('kerberos.request_type')).strip().upper() != 'TGS':
            return None
        source = _address(event.get('source.ip'))
        service = _service(event.get('kerberos.service'))
        if source is None or service is None:
            return None
        if service.split('/', 1)[0] in {'krbtgt', 'kadmin'}:
            return None
        client = _name(event.get('kerberos.client'))
        return (str(source), client), service, 'attempt'

    def describe(self, event, total_refs, distinct_members, role):
        client = _name(event.get('kerberos.client'))
        who = f' for client {client}' if client else ' (client not recorded)'
        notes = [
            'Ticket-granting (krbtgt) referrals and password-change (kadmin) exchanges are not counted.',
            'The exchanges are observed; the claim counts requests and does not state that every ticket was issued.',
            'The ten-in-five-minutes breadth is a review heuristic, not proof of offline cracking.',
            'Repeat exchanges for one service are thinned without changing any window\'s distinct services; the '
            'raw-reference count is a lower bound.',
        ]
        if address_member(event.get('source.ip'), getattr(_site(self), 'management_hosts', ())):
            notes.append('declared management source; authorized administration can request many service tickets')
        return 'lead', (f'Source {event.get("source.ip")}{who} had TGS exchanges for at least {distinct_members} '
                        f'distinct services within five minutes (at least {total_refs} raw references).'), tuple(notes)


KerberosServiceTicketFanout.card = {
    'behavior': KerberosServiceTicketFanout.title,
    'telemetry': ('Zeek kerberos records as kerberos_tx: source.ip, kerberos.request_type, kerberos.client, '
                  'kerberos.service; in every Zeek shipper shape'),
    'fidelity': ('Aggregate of observed TGS exchanges, keyed by source address and client principal; service names '
                 'are compared case-folded without their realm. Any ticket encryption type'),
    'benign_and_cost': '; '.join(KerberosServiceTicketFanout.benign) + '. One finding per source and client',
    'query_cost': ('One kerberos sweep; TGS rows held in the disk-backed window state, repeats of one service '
                   'thinned losslessly to about one per window'),
    'next_pivot': '; '.join(KerberosServiceTicketFanout.next_checks),
    'adds': ('net.kerberos_rc4_service_fanout counts RC4 tickets only; tools that ask for AES tickets, or accounts '
             'that only have AES keys, are counted here'),
    'research_basis': '; '.join(KerberosServiceTicketFanout.research),
    'retrieval': ('The sweep retrieves every kerberos record of the network targets; TGS rows without a service '
                  'name are counted as unevaluated'),
    'lanes': ('Lead: multi-user hosts and Kerberos-authenticating management servers produce the same breadth; '
              'severity high because cracked service-account credentials are high impact'),
    'window': '10 distinct services within five minutes per source and client',
}


def _name(value):
    return value.strip().casefold() if isinstance(value, str) and value.strip() not in {'', '-', '?'} else ''


def _service(value):
    """A service principal name, case-folded without its realm; None when none is recorded."""
    name = _name(value)
    if not name:
        return None
    return name.rsplit('@', 1)[0] or None


class EpmDynamicRpc(ZeekBehaviorRule):
    """A connection to the endpoint mapper and, within thirty seconds after it, a connection from the same source to
    the same host on a high port. Each mapper connection is held per (sensor, source, destination); the high-port
    connection is judged against it, so only the 135 legs are retained, never every high-port connection."""
    id = 'net.epm_dynamic_rpc'
    title = 'An RPC endpoint-mapper connection followed by a high-port connection to the same host'
    version = '1'
    severity = 'high'
    state_slice = 'routine'
    families = ('net_flow',)
    required_fields = _CONN_REQUIRED
    uses_site_facts = True
    direction_dependent = True
    attack = ('T1021.003', 'T1047', 'T1053.005', 'T1569.002')
    benign = ('Domain members calling domain controllers (Netlogon, LSA, SAM); declare the controllers so these are '
              'not reported', 'Certificate enrollment, DFS replication, backup and management consoles calling '
              'their servers', 'A WMI or DCOM management server or scanner polling every client: one finding for '
              'that source, listing its destinations')
    next_checks = ('Processes started on the destination at this time (WMI provider host, DCOM-activated '
                   'applications, the task scheduler, the service control manager)',
                   'Logons to the destination from the source (network logon type 3)',
                   'Other sources reaching the same destination this way')
    research = (_CONN_DOC, _EPM_DOC, _DCOM_DOC, _RPC_PORTS_DOC,
                'ATT&CK Enterprise 20.0 T1021.003, T1047 (Network Traffic: Network Connection Creation)')

    DESTINATIONS_NAMED = 10

    def __init__(self):
        super().__init__()
        self.legs = KeyedStore(self, 'epm_legs', HOT_COUNT)
        # exact distinct destinations per source finding: (shape, destination) presence, and per shape
        # [count, the first DESTINATIONS_NAMED destinations, whether a refused write made the count a lower bound]
        self.destination_pairs = KeyedStore(self, 'epm_destination_pairs', HOT_COUNT)
        self.destinations = KeyedStore(self, 'epm_destinations', HOT_COUNT)
        # set once any source's count could not be retained: a later count for that source restarts below its truth
        # while its pair records stand, so every count this rule states is then a lower bound
        self.destination_state_lost = False

    def _owned_stores(self):
        return [*super()._owned_stores(), self.legs, self.destination_pairs, self.destinations]

    def _note_group(self, shape, hit, event, *, new_host, link_host=True):
        group = super()._note_group(shape, hit, event, new_host=new_host, link_host=link_host)
        destination = str(_address(event.get('destination.ip')) or event.get('destination.ip'))
        if self.destination_pairs.get((shape, destination)) is None:
            state = self.destinations.get(shape) or [0, [], False]
            if self.destination_pairs.put((shape, destination), 1):
                state[0] += 1
                if len(state[1]) < self.DESTINATIONS_NAMED:
                    state[1].append(destination)
            else:
                state[2] = True
                self.note_limit('epm_destinations', 'A distinct-destination record could not be retained; the '
                                                    'destination count of its source is a lower bound.')
            if not self.destinations.put(shape, state):
                self.destination_state_lost = True
                self.note_limit('epm_destinations', "A source's destination count could not be retained; its "
                                                    'finding states the count it last held.')
        return group

    def _network_claim(self, match, group):
        match = super()._network_claim(match, group)
        shape = (match.group_key or '').rsplit('|', 1)[-1]
        state = self.destinations.peek(shape)
        if state is None:
            return match
        count, named, capped = state
        capped = capped or self.destination_state_lost
        listed = ', '.join(named) + (f', and {count - len(named)} more' if count > len(named) else '')
        prefix = f'{group.common}: '
        rest = match.claim[len(prefix):] if match.claim.startswith(prefix) else match.claim
        match.claim = (f'{prefix}{"at least " if capped else ""}{count} distinct destination'
                       f'{"s" if count != 1 else ""} ({listed}); {rest} The cited records are examples.')
        return match

    def consume(self, events):
        return super().consume([event for event in events if _conn_record(event)])

    def _offer_group_example(self, group, event, hit, *, new_host):
        # the mapper connection is part of the claim: its record is held and staged with the high-port one
        offered = group.examples.offer(event)
        for item in hit.context:
            if group.examples.offer(item):
                self._pending.append(item)
                self._fresh.append(group.examples)
        return offered

    def judge(self, event):
        if event.get('network.transport') != 'tcp':
            return []
        port = _count(event.get('destination.port'))
        if port is None or (port != EPM_PORT and (port < DYNAMIC_FLOOR or port in NOT_DYNAMIC)):
            return []
        source, destination = _address(event.get('source.ip')), _address(event.get('destination.ip'))
        if source is None or destination is None or source == destination:
            return []
        answered, decided = _exchange(event)
        if not decided:
            _undecided(self, 'conn_exchange', 'Connections to the endpoint mapper or a high port without a recorded '
                                              'Zeek history or payload byte counts were not judged.')
            return []
        if not answered:
            return []
        networks = _networks(self)
        assume_direction(self)
        if not (networks.is_internal(source) and networks.is_internal(destination)):
            return []
        controllers = getattr(_site(self), 'domain_controller_addresses', ())
        if controllers and address_member(str(destination), controllers):
            return []
        key = (event.host or '', str(source), str(destination))
        if port == EPM_PORT:
            held = self.legs.get(key)
            if held is None or held[0] <= event.ts.timestamp():
                # only the facts the pairing cites, and a bounded sample of native references
                leg = event.model_copy(update={
                    'fields': {name: fact for name, fact in event.fields.items() if name in _CONN_FIELDS},
                    'raw': event.raw[:3], 'caveats': list(dict.fromkeys([*event.caveats, COMPACT_CITATION_NOTE]))})
                if not self.legs.put(key, (event.ts.timestamp(), compact_event(leg))):
                    self.refuse('epm_legs', 'An endpoint-mapper connection could not be held for pairing; later '
                                            'high-port connections from its source to its host were not paired.')
            return []
        protocols = event.get('network.protocols')
        if isinstance(protocols, list) and protocols and not set(protocols) <= RPC_SERVICES:
            return []
        held = self.legs.get(key)
        if held is None:
            return []
        start, payload = held
        delay = event.ts.timestamp() - start
        if not 0 <= delay <= EPM_FOLLOW.total_seconds():
            return []
        mapper = expand_event(payload)
        notes = list(_notes_for_source(self, str(source), networks))
        if not controllers:
            notes.append('domain controller addresses are not declared: if the destination is one, this is the shape '
                         'of every domain member\'s Netlogon, LSA and SAM calls')
        notes += ['The payload was not read: the interface and operation called are not known, and a connection is '
                  'not proof of execution.',
                  'The endpoint-mapper connection is the most recent one from this source to this host before the '
                  'high-port connection.']
        text = (f'Endpoint-mapper connection from {source} to {destination} at {mapper.ts.isoformat()} followed '
                f'{delay:.3f} s later by an answered connection to port {port}')
        common = (f'Endpoint-mapper connections from {source} followed within {int(EPM_FOLLOW.total_seconds())} s '
                  'by an answered high-port connection to the same host')
        fields = (*_CONN_REQUIRED, 'conn.history', 'tcp.opened_by_orig', 'flow.bytes_toserver', 'flow.bytes_toclient',
                  'network.protocols', 'zeek.uid')
        hit = signal(event, self.id, text, self.attack, fields, lane='lead', severity='high', notes=tuple(notes),
                     common=common, content=json.dumps([str(source), 'epm-dynamic']))
        hit.context = [mapper]
        return [hit]


EpmDynamicRpc.card.update(
    behavior=EpmDynamicRpc.title,
    telemetry=('Zeek conn records as net_flow: source.ip, destination.ip, destination.port, network.transport, '
               'conn.history (tcp.opened_by_orig), payload bytes and network.protocols, in every Zeek shipper shape'),
    fidelity=('Sequence of two answered connections (the source opened each, both sides sent payload) between the '
              'same pair, the high-port one starting 0-30 s after the mapper one. The payload is not read: the RPC '
              'interface, the operation and any execution are not established'),
    benign_and_cost='; '.join(EpmDynamicRpc.benign) + '. One finding per source, listing its destinations',
    adds=('net.rpc_remote_admin_call and net.rpc_coercion_call need Zeek\'s DCE-RPC analyzer to name the operation; '
          'this shape is visible when the calls are sealed or the analyzer did not run'),
    research_basis='; '.join(EpmDynamicRpc.research),
    retrieval=('The sweep retrieves every conn record of the network targets; rows without history or payload counters '
               'are counted as unevaluated'),
    lanes=('Lead: DCOM, WMI and remote task scheduling look the same as management consoles and certificate '
           'enrollment on the wire; declared domain controllers are not destinations; severity high because remote '
           'execution is high impact'),
    window=('the high-port connection starts 0-30 s after the endpoint-mapper connection. Records are paired in '
            'time order within a batch and across batches read in time order; a high-port connection read in an '
            'earlier batch than its mapper connection is not paired'),
    blind_spot=('declared domain controllers are never destinations: DCOM or WMI toward a controller is left to the '
                'decoded RPC rules and host telemetry'),
)


class LdapBulkResponse(ZeekBehaviorRule):
    id = 'net.ldap_bulk_response'
    title = 'A directory-service connection returned a bulk volume of data to one client'
    version = '1'
    state_slice = 'routine'
    families = ('net_flow',)
    required_fields = _CONN_REQUIRED
    uses_site_facts = True
    # a bulk-read signal: trust enumeration (T1482) is a few small queries and is not distinguished on the wire
    attack = ('T1087.002', 'T1069.002', 'T1018')
    benign = ('Identity synchronization, provisioning and HR connectors, mail and collaboration servers, and '
              'inventory tools that read the directory in bulk',
              'Administrators exporting the directory')
    next_checks = ('The process on the client that held the connection (directory collectors and snapshot tools)',
                   'Kerberos service-ticket and LDAP query records from the same client',
                   'Whether the client is a declared directory-sync or management host')
    research = (_CONN_DOC, 'ATT&CK Enterprise 20.0 T1087.002, T1069.002, T1018',
                'https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/',
                _SERVICE_PORTS_DOC)

    def consume(self, events):
        return super().consume([event for event in events if _conn_record(event)])

    def judge(self, event):
        if event.get('network.transport') != 'tcp':
            return []
        port = _count(event.get('destination.port'))
        if port not in DIRECTORY_PORTS:
            return []
        source, destination = _address(event.get('source.ip')), _address(event.get('destination.ip'))
        if source is None or destination is None or source == destination:
            return []
        received = _count(event.get('flow.bytes_toclient'))
        if received is None or event.get('conn.history') in (None, ''):
            _undecided(self, 'conn_exchange', 'Directory-service connections without a recorded Zeek history or '
                                              'server payload byte count were not judged.')
            return []
        if event.get('tcp.opened_by_orig') is not True or received < LDAP_BULK_BYTES:
            return []
        site = _site(self)
        controllers = getattr(site, 'domain_controller_addresses', ())
        if controllers and address_member(str(source), controllers):
            return []
        # judged wherever the client is: a bulk read from outside the site is no less a lead
        notes = []
        if address_member(str(source), getattr(site, 'management_hosts', ())):
            notes.append('declared management source; authorized administration can read the directory in bulk')
        if address_member(str(source), getattr(site, 'directory_sync_addresses', ())):
            notes.append('declared directory-sync host; synchronization reads the directory in bulk')
        if not controllers:
            notes.append('domain controller addresses are not declared: a controller reading another controller\'s '
                         'global catalog is not told apart')
        if event.get('conn.interim') is True:
            notes.append('Counted from an interim record of a connection still open: the bytes are those so far.')
        notes.append('The payload was not read: the volume shows a bulk response, not which objects or attributes '
                     'were read.')
        text = (f'{DIRECTORY_PORTS[port]} connection from {source} to {destination}:{port} on which the server sent '
                f'{received} payload bytes')
        common = (f'Directory-service connections from {source} on which the server sent at least '
                  f'{LDAP_BULK_BYTES} payload bytes; the cited records name each server')
        fields = (*_CONN_REQUIRED, 'conn.history', 'tcp.opened_by_orig', 'flow.bytes_toclient', 'flow.bytes_toserver',
                  'zeek.uid', 'session.duration_s')
        return [signal(event, self.id, text, self.attack, fields, lane='lead', severity='medium', notes=tuple(notes),
                       common=common, content=json.dumps([str(source), 'ldap-bulk']))]


LdapBulkResponse.card.update(
    behavior=LdapBulkResponse.title,
    telemetry=('Zeek conn records as net_flow: source.ip, destination.ip, destination.port 389/636/3268/3269, '
               'conn.history (tcp.opened_by_orig) and flow.bytes_toclient (server payload bytes)'),
    fidelity=('One connection the client opened on which the directory server sent at least five million payload '
              'bytes. Works for LDAP, LDAP with sign-and-seal, LDAPS and the global catalog alike; the objects read '
              'are not established'),
    benign_and_cost='; '.join(LdapBulkResponse.benign) + '. One finding per client, listing its servers',
    adds=('Zeek\'s ldap logs name searches only when LDAP is unsealed; this volume shape holds for sealed LDAP and '
          'LDAPS. First-time directory access per client needs a history baseline and is not judged here. A reader '
          'that splits its reads across many smaller connections, or a domain with too few objects, stays under the '
          'per-connection volume'),
    research_basis='; '.join(LdapBulkResponse.research),
    retrieval=('The sweep retrieves every conn record of the network targets; directory connections without history '
               'or server byte counts are counted as unevaluated'),
    lanes=('Lead: directory synchronization and inventory read in bulk too; declared domain controllers are not '
           'clients; severity medium because discovery alone changes nothing'),
    window='per connection: at least 5,000,000 server payload bytes',
)


RULES = (RemoteShellFanout, SmbRpcFanout, KerberosServiceTicketFanout, EpmDynamicRpc, LdapBulkResponse)
