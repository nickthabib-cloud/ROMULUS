"""Peer-keyed network rates with exact disk-backed raw-reference windows."""
from ipaddress import ip_address

from romulus.detect.network_producers import ZEEK_AND_SURICATA, sensor_words
from romulus.detect.zeek_lateral import _call, _peers
from romulus.detect.zeek_rate_state import ZeekWindowRule

_RPC = 'https://docs.zeek.org/en/master/scripts/base/protocols/dce-rpc/main.zeek.html'
_KRB = 'https://docs.zeek.org/en/master/scripts/base/protocols/krb/main.zeek.html'
_NTLM = 'https://docs.zeek.org/en/master/scripts/base/protocols/ntlm/main.zeek.html'
_FIELDS = ('observer.name', 'observer.product', 'zeek.log', 'zeek.uid', 'source.ip', 'destination.ip',
           'rpc.endpoint', 'rpc.operation', 'rpc.interface_uuid', 'rpc.opnum', 'rpc.op_class',
           'kerberos.request_type', 'kerberos.service', 'kerberos.client', 'kerberos.client_name',
           'kerberos.error_source', 'auth.status', 'auth.encryption_type',
           'ntlm.username', 'ntlm.domain', 'ntlm.success')


def _source(event):
    try:
        address = ip_address(event.get('source.ip'))
    except (ValueError, TypeError):
        return None
    return str(getattr(address, 'ipv4_mapped', None) or address)


def _name(value):
    return value.strip().casefold() if isinstance(value, str) and value.strip() not in {'', '-', '?'} else ''


class _Rate(ZeekWindowRule):
    version = '6'
    # Each rate reads facts Zeek and Suricata type alike (the per-rule matrix is in docs/detection/network-protocols.md);
    # a fact one sensor does not record leaves that sensor's rows unselected, never counted.
    producers = ZEEK_AND_SURICATA
    citation_fields = _FIELDS
    required_fields = ('source.ip',)
    benign = ('Authorized administration, scanners and ordinary authentication can produce rate leads.',)
    next_checks = ('Review the cited requests, source role and independent authentication or endpoint evidence.',)
    research = (_RPC,)

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if getattr(cls, 'id', None):
            cls.card = {
                'behavior': cls.title, 'telemetry': ', '.join(cls.families),
                'fidelity': 'Typed positive network observations; raw-reference counts do not certify unique actions.',
                'benign_and_cost': '; '.join(cls.benign),
                'query_cost': 'One family sweep and indexed disk-backed window state.',
                'next_pivot': '; '.join(cls.next_checks),
                'research_basis': '; '.join(cls.research),
                'retrieval': (f'Declared typed {sensor_words(cls.producers)} families; missing fields and state '
                              'refusals remain unresolved.'),
                'lanes': 'The concrete observation defines its evidence-supported lane.',
            }


class ZerologonRate(_Rate):
    id, title = 'net.netlogon_authentication_burst', 'Repeated Netlogon secure-channel authentication calls'
    families = ('rpc_tx',)
    required_fields = ('source.ip', 'destination.ip')
    # Normal machine secure-channel setup uses a handful of calls; the bypass succeeds with
    # probability 1/256 per independent attempt. Fifty in a minute is a conspicuous review signal.
    seconds, threshold = 60, 50
    attack = ('T1210',)
    research = (_RPC, 'https://github.com/bvcyber/CVE-2020-1472')

    def select(self, event):
        peers = _peers(event)
        call = _call(event)
        if (not peers or call.op_class != 'secure_channel'
                or call.operation is None or not call.operation.name.startswith('NetrServerAuthenticate')):
            return None
        return peers, call.operation.name, 'attempt'

    def describe(self, event, total_refs, distinct_members, role):
        return 'high', (f'At least {total_refs} raw references to Netlogon authenticate calls from '
                        f'{event.get("source.ip")} to {event.get("destination.ip")} were observed within 60 seconds.'), (
            'A legitimate machine normally needs only a handful of setup calls; Zerologon needs about 256 attempts on average.',
            'Authentication calls are observed; authentication success, exploitation and distinct packet counts are not established.',
        )


class Rc4TgsFanout(_Rate):
    id, title = 'net.kerberos_rc4_service_fanout', 'TGS exchanges with RC4 ticket encryption for many services'
    families = ('kerberos_tx',)
    seconds, threshold, distinct = 300, 10, True
    attack, research = ('T1558.003',), (_KRB,)

    def select(self, event):
        source, service = _source(event), _name(event.get('kerberos.service'))
        if (not source or not service or event.get('auth.encryption_type') != 23
                or _name(event.get('kerberos.request_type')) != 'tgs'):
            return None
        return (source,), service, 'attempt'

    def describe(self, event, total_refs, distinct_members, role):
        return 'lead', (f'Source {event.get("source.ip")} had TGS exchanges with RC4 ticket encryption for at least '
                        f'{distinct_members} distinct services in five minutes ({total_refs} raw references).'), (
            'Distinct services reduce repeated legacy-service noise; a legacy RC4 domain can still explain this lead.',
            'The sensor cipher describes the issued ticket encryption, not a requested cipher preference.',
            'The breadth threshold is a review heuristic, not proof of ticket cracking.',
        )


class KerberosPrincipalEnumeration(_Rate):
    id, title = 'net.kerberos_principal_enumeration', 'KDC unknown-principal errors for many distinct principals'
    families = ('kerberos_tx',)
    seconds, threshold, distinct = 600, 20, True
    attack, research = ('T1087.002',), (_KRB,)

    def select(self, event):
        source = _source(event)
        name, principal = _name(event.get('kerberos.client_name')), _name(event.get('kerberos.client'))
        if (not source or not name or not principal or event.get('auth.status') != 6
                or event.get('kerberos.error_source') != 'kdc'):
            return None
        return (source,), principal, 'attempt'

    def describe(self, event, total_refs, distinct_members, role):
        return 'lead', (f'The KDC returned unknown-client-principal errors for at least {distinct_members} distinct '
                        f'principals from {event.get("source.ip")} in ten minutes ({total_refs} raw references).'), (
            'Inventory, scanners and stale account lists can also produce unknown-principal discovery patterns.',
        )


def _account(event):
    name = _name(event.get('ntlm.username'))
    domain = _name(event.get('ntlm.domain'))
    return domain + '\\' + name if name and domain else name


_ATTEMPT_NOTES = (
    'Rows with an unrecorded success field count as attempts, not proven failures.',
    'The ten-minute threshold is a review heuristic; authorized scanners and stale credentials can explain it.',
)


class NtlmPasswordSpray(_Rate):
    id, title = 'net.ntlm_password_spray', 'One source attempted NTLM authentication for many users'
    families = ('ntlm_tx',)
    seconds, threshold, distinct = 600, 10, True
    attack, research = ('T1110.003',), (_NTLM,)
    success_fields = ('source.ip', 'ntlm.username', 'ntlm.domain', 'ntlm.success')
    success_history_noise = True

    def select(self, event):
        source, account = _source(event), _account(event)
        if not source:
            return None
        if event.get('ntlm.success') is True:
            return (source,), account, 'success'
        return ((source,), account, 'attempt') if account else None

    def describe(self, event, total_refs, distinct_members, role):
        later = role == 'success'
        notes = _ATTEMPT_NOTES
        if later:
            notes += ('A later success is temporally associated; the records do not prove which credential or intent caused it.',)
        elif role == 'shared_success':
            notes += ((f'This source already logged a success for {_account(event)} before the qualifying episode; '
                       'shared-source or NAT authentication history keeps this observation a lead.'),)
        return ('high' if later else 'lead',
                f'Source {event.get("source.ip")} has NTLM attempts for at least {distinct_members} distinct users '
                f'in ten minutes ({total_refs} raw references)'
                + (f' followed by a later recorded authentication success for {_account(event)}.' if later else '.'),
                notes)


class NtlmPasswordGuessing(NtlmPasswordSpray):
    id, title = 'net.ntlm_password_guessing', 'Repeated NTLM authentication attempts for one user'
    threshold, distinct = 20, False
    attack = ('T1110.001',)

    def select(self, event):
        source, account = _source(event), _account(event)
        if not source or not account or event.get('ntlm.success') is True:
            return None
        return (source, account), account, 'attempt'

    def describe(self, event, total_refs, distinct_members, role):
        return 'lead', (f'Source {event.get("source.ip")} has at least {total_refs} NTLM attempt raw references '
                        f'for {_account(event)} in ten minutes.'), _ATTEMPT_NOTES


# Calls that list a remote host's sessions, shares, open connections, logged-on users or local group members: what a
# host-by-host collector (session and local-admin collection, share finders, `net view`) sends to every computer it
# visits. Single-object reads a client makes while mapping a share (NetrShareGetInfo) or reading server facts are left
# out.
HOST_ENUMERATION = frozenset({'NetrShareEnum', 'NetrShareEnumSticky', 'NetrSessionEnum', 'NetrConnectionEnum',
                              'NetrFileEnum', 'NetrWkstaUserEnum', 'SamrEnumerateAliasesInDomain',
                              'SamrGetMembersInAlias', 'SamrEnumerateUsersInDomain'})
# SAM operations that list the directory in bulk. Name and SID translation, logon-time membership reads and password
# policy reads are what every member makes routinely and are left out.
DIRECTORY_LISTING = frozenset({'SamrEnumerateDomainsInSamServer', 'SamrEnumerateUsersInDomain',
                               'SamrQueryDisplayInformation', 'SamrQueryDisplayInformation2',
                               'SamrQueryDisplayInformation3', 'SamrEnumerateGroupsInDomain', 'SamrGetMembersInGroup',
                               'SamrEnumerateAliasesInDomain', 'SamrGetMembersInAlias'})


def _operation(event, names):
    peers, call = _peers(event), _call(event)
    if not peers or call.op_class != 'enumeration' or call.operation is None or call.operation.name not in names:
        return None
    return peers, call.operation.name


class RpcHostEnumerationFanout(_Rate):
    id = 'net.rpc_host_enumeration_fanout'
    title = 'One source called session, share or local-group enumeration on many hosts'
    families = ('rpc_tx',)
    required_fields = ('source.ip', 'destination.ip')
    # A client lists sessions or shares only on the few servers it uses; ten distinct hosts in fifteen minutes is the
    # host-by-host sweep of a collector, at any fleet size.
    seconds, threshold, distinct = 900, 10, True
    span_words = 'fifteen minutes'
    attack = ('T1049', 'T1033', 'T1135', 'T1069.001')
    benign = ('Inventory, monitoring and vulnerability-scanning servers enumerate hosts on a schedule.',)

    def select(self, event):
        found = _operation(event, HOST_ENUMERATION)
        return None if found is None else ((found[0][0],), found[0][1], 'attempt')

    def describe(self, event, total_refs, distinct_members, role):
        return 'lead', (f'Source {event.get("source.ip")} called session, share, connection, user or local-group '
                        f'enumeration on at least {distinct_members} distinct hosts in {self.span_words} '
                        f'({total_refs} raw references).'), (
            ('A host-by-host sweep is the collection pattern of session and local-administrator mapping and share '
             'discovery; inventory and scanning servers can explain it.'),
            'The calls are observed; what each host returned is not.',
        )


class RpcHostEnumerationSlowFanout(RpcHostEnumerationFanout):
    """The same host-by-host enumeration throttled below the fifteen-minute rate (a collector's jitter or throttle
    settings). Twenty-five distinct hosts in a day from one source is still a sweep; inventory and scanning servers
    explain it as they explain the fast form."""
    id = 'net.rpc_host_enumeration_slow_fanout'
    title = 'One source called session, share or local-group enumeration on many hosts over a day'
    seconds, threshold, distinct = 86400, 25, True
    span_words = 'one day'


class RpcDirectoryListing(_Rate):
    id = 'net.rpc_directory_listing'
    title = 'One source made bulk user, group or member listing calls over SAM RPC'
    families = ('rpc_tx',)
    required_fields = ('source.ip', 'destination.ip')
    # One administrative command lists one kind of object; three distinct bulk listing calls from one source within ten
    # minutes is a collector walking the directory. Keyed on the source, so a collector visiting thousands of hosts is
    # one finding, not one per host.
    seconds, threshold, distinct = 600, 3, True
    attack = ('T1087.002', 'T1069.002', 'T1069.001')
    benign = ('Identity-management and auditing tools read the directory in bulk on a schedule.',)

    def select(self, event):
        found = _operation(event, DIRECTORY_LISTING)
        return None if found is None else ((found[0][0],), found[1], 'attempt')

    def describe(self, event, total_refs, distinct_members, role):
        return 'lead', (f'Source {event.get("source.ip")} made at least {distinct_members} distinct bulk SAM listing '
                        f'calls (users, groups, aliases or members) in ten minutes, including to '
                        f'{event.get("destination.ip")} ({total_refs} raw references).'), (
            'Name and SID translation and logon-time membership reads are not counted.',
            'The calls are observed; what the server returned is not.',
        )


RULES = (ZerologonRate, Rc4TgsFanout, KerberosPrincipalEnumeration, NtlmPasswordSpray, NtlmPasswordGuessing,
         RpcHostEnumerationFanout, RpcHostEnumerationSlowFanout, RpcDirectoryListing)
