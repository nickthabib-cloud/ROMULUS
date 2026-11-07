"""Peer-keyed network rates with exact disk-backed raw-reference windows."""
from ipaddress import ip_address

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
    version = '5'
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
                'retrieval': 'Declared typed Zeek families; missing fields and state refusals remain unresolved.',
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
            'Zeek cipher describes the issued ticket encryption, not a requested cipher preference.',
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


RULES = (ZerologonRate, Rc4TgsFanout, KerberosPrincipalEnumeration, NtlmPasswordSpray, NtlmPasswordGuessing)
