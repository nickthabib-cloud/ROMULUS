"""Network-observed Zeek RPC and remote-access primitives with bounded immediate folds."""
import json
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from ipaddress import ip_address
from urllib.parse import urlsplit

from romulus.detect.base import Match
from romulus.detect.netdef import DIRECTION_ASSUMED_REASON, SiteNetworks, current
from romulus.detect.site_roles import address_member
from romulus.detect.windows_events import WindowsEventRule, signal
from romulus.detect.windows_rpc import RpcRemoteAdminCall as WindowsRpcRemoteAdminCall
from romulus.evidence.rpc_catalog import lookup_call, lookup_zeek

_RPC_DOC = 'https://docs.zeek.org/en/master/scripts/base/protocols/dce-rpc/main.zeek.html'
_REMOTE_DOC = 'https://docs.zeek.org/en/master/scripts/base/protocols/rdp/main.zeek.html'
_WINRM_DOC = 'https://learn.microsoft.com/windows/win32/winrm/installation-and-configuration-for-windows-remote-management'
_TICKET_DOC = 'https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/jj852188(v=ws.11)'
_RPC_FIELDS = ('source.ip', 'source.hostname', 'destination.ip', 'rpc.endpoint', 'rpc.operation',
               'rpc.interface_uuid', 'rpc.opnum', 'rpc.op_class')
# Compare the requested till with AD's default 600-minute service-ticket age. Zeek reads till
# from the TGS request, not the granted ticket; benign clients can ask beyond the KDC's policy.
TICKET_LIFETIME = timedelta(hours=10)


def _zeek(event):
    return event.normalizer.startswith('zeek-ecs@') and event.get('observer.product') == 'zeek'


def _peers(event):
    try:
        source, destination = ip_address(event.get('source.ip')), ip_address(event.get('destination.ip'))
    except (ValueError, TypeError):
        return None
    source = getattr(source, 'ipv4_mapped', None) or source
    destination = getattr(destination, 'ipv4_mapped', None) or destination
    return (str(source), str(destination)) if source != destination else None


def _call(event):
    if event.has('rpc.endpoint') and event.has('rpc.operation'):
        return lookup_zeek(event.get('rpc.endpoint'), event.get('rpc.operation'))
    return lookup_call(event.get('rpc.interface_uuid'), event.get('rpc.opnum'))


@lru_cache(maxsize=64)
def _site_networks(internal, external):
    return SiteNetworks.from_lists(internal, external)


class ZeekBehaviorRule(WindowsEventRule):
    """Reuse disk-backed folds and bounded citations; members are network observations, not processes."""
    os_families = ('linux', 'windows')
    windows_event_classes = ()
    uses_parent = False
    reads_command_line = False
    claim_type = 'network_observation'
    positive_only_reason = ('Zeek network observations report typed positive evidence; absence and successful '
                            'action are not established.')
    benign = ('Authorized administration and configured domain policies can produce these observations.',)
    next_checks = ('Review the cited network records and independent endpoint or authentication outcomes.',)
    research = (_RPC_DOC,)

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if getattr(cls, 'id', None):
            cls.card.update(fidelity='Typed network observations from a Zeek sensor; no successful action is inferred.',
                query_cost='Declared Zeek families, with bounded disk-backed grouping and citation examples.',
                telemetry=', '.join(cls.families),
                lanes='Evidence determines the lane; counts are per-row distinct raw references.')

    def consume(self, events):
        return super().consume([event for event in events if _zeek(event)])

    @staticmethod
    def raw_weight(event):
        return len({ref.key for ref in event.raw})

    def _note_group(self, shape, hit, event, *, new_host, link_host=True):
        group = super()._note_group(shape, hit, event, new_host=new_host, link_host=link_host)
        if group is not None:
            group.records += self.raw_weight(event) - 1
            group.attack = tuple(sorted(set(group.attack) | set(hit.attack)))
            group.zeek_notes = tuple(sorted(set(getattr(group, 'zeek_notes', ())) | set(hit.notes)))
            self.groups.put(shape, group)
        return group

    def record_match(self, event, hit):
        shape = self._shape(event, hit)
        context = [item for item in hit.context if item.id != event.id]
        return Match(self.id,
            f'{hit.text}; {self.raw_weight(event)} raw reference(s), network-observed at {event.ts.isoformat()}.',
            self.claim_type, [event, *context], list(hit.predicate), event.ts, hit.severity, hit.lane,
            hit.confidence, event.entities(), [*hit.notes, 'ATT&CK context (not proof): ' + ', '.join(hit.attack)],
            group_key=f'{self.id}|fleet|{shape}', bounded_revision=True,
            raw_copies=dict(hit.raw_copies), context_ids={item.id for item in context},
            revision_reason='The network observation revises the bounded group evidence.')

    def _fold(self, event, hit, out):
        start = len(out)
        shape, role = super()._fold(event, hit, out)
        group = self.groups.get(shape) if shape is not None else None
        if group is not None and role == 'own' and group.records > self.raw_weight(event):
            match = self._fleet_match(shape, group, final=False)
            if match is not None:
                out[start:] = [match]
                group.emitted_records = group.records
                self.groups.put(shape, group)
        return shape, role

    def _network_claim(self, match, group):
        first = datetime.fromtimestamp(group.ends.first[0], UTC).isoformat() if group.ends.first else '?'
        last = datetime.fromtimestamp(group.ends.last[0], UTC).isoformat() if group.ends.last else '?'
        match.claim = (f'{group.common}: {group.records} raw reference(s), network-observed '
                       f'from {first} through {last}. Counts do not establish successful action.')
        match.notes = [*getattr(group, 'zeek_notes', ()),
                       'ATT&CK context (not proof): ' + ', '.join(group.attack)]
        if match.citation_unavailable:
            match.notes.append('Supporting citations could not be retained; the positive group tally remains available.')
        elif sum(self.raw_weight(event) for event in match.events) < group.records:
            match.notes.append('Citations are bounded examples; the raw-reference total includes uncited members.')
        # Grouping internally tracks observers; do not present sensors as the traffic's endpoint hosts.
        match.fleet_hosts, match.fleet_host_count, match.fleet_hosts_complete = (), 0, False
        match.bounded_revision = True
        match.revision_reason = 'The bounded network fold replaces the earlier raw-reference count and citation sample.'
        return match

    def _fleet_match(self, shape, group, *, final):
        match = super()._fleet_match(shape, group, final=final)
        return self._network_claim(match, group) if match is not None else None

    def uncited_finding(self, key, state, match):
        match = super().uncited_finding(key, state, match)
        return self._network_claim(match, state)


class RpcRemoteAdminCall(ZeekBehaviorRule):
    id = 'net.rpc_remote_admin_call'
    title = 'A classified remote administration RPC call was observed'
    families = ('rpc_tx',)
    required_fields = ('source.ip', 'destination.ip')
    _HIGH, _LEAD = WindowsRpcRemoteAdminCall._HIGH, WindowsRpcRemoteAdminCall._LEAD
    attack = WindowsRpcRemoteAdminCall.attack

    def judge(self, event):
        if not _zeek(event) or event.family != 'rpc_tx' or not (peers := _peers(event)):
            return []
        call = _call(event)
        if call.interface is None or call.op_class not in self._HIGH | self._LEAD:
            return []
        lane = 'high' if call.op_class in self._HIGH else 'lead'
        management = getattr(getattr(self, 'site_facts', None), 'management_hosts', ())
        notes = ()
        if call.op_class.startswith('service_') and address_member(event.get('source.ip'), management):
            notes = ('declared management source; authorized administration can produce this call',)
        text = f'RPC {call.op_class} call observed from {peers[0]} to {peers[1]} on interface {call.interface.uuid}'
        return [signal(event, self.id, text, call.attack, _RPC_FIELDS, lane=lane,
            severity='high' if lane == 'high' else 'medium', notes=notes,
            common=text, content=json.dumps([*peers, call.interface.uuid, call.op_class]))]


class WireReplicationCall(ZeekBehaviorRule):
    id = 'net.rpc_replication_call'
    title = 'A directory replication RPC call was observed'
    families = ('rpc_tx',)
    required_fields = ('source.ip', 'destination.ip')
    attack = ('T1003.006', 'T1207')

    def judge(self, event):
        if not _zeek(event) or event.family != 'rpc_tx' or not (peers := _peers(event)):
            return []
        call = _call(event)
        if call.op_class != 'replication' or call.interface is None:
            return []
        site = getattr(self, 'site_facts', None)
        controllers = getattr(site, 'domain_controller_addresses', ())
        source_dc, server_dc = (address_member(peer, controllers) for peer in peers)
        if address_member(event.get('source.ip'), getattr(site, 'directory_sync_addresses', ())):
            lane, notes = 'lead', ('declared directory-sync host; a compromised sync server is a DCSync path',)
        elif not controllers:
            lane, notes = 'lead', ('domain controller addresses not declared',)
        elif source_dc and server_dc:
            return []
        elif source_dc:
            lane, notes = 'lead', ('declared domain-controller source; destination is not a declared domain controller',)
        else:
            lane, notes = 'high', ()
            if getattr(site, 'directory_sync_hosts', ()) and not getattr(site, 'directory_sync_addresses', ()):
                notes = (('directory-sync hosts are declared by name only, which a network record cannot match: '
                          'if this source is one, declare its address'),)
        text = f'Directory replication RPC call observed from {peers[0]} to {peers[1]} on interface {call.interface.uuid}'
        return [signal(event, self.id, text, call.attack, _RPC_FIELDS, lane=lane,
            severity='high' if lane == 'high' else 'medium', notes=notes, common=text,
            content=json.dumps([*peers, call.interface.uuid, call.op_class]))]


class _RemoteSession(ZeekBehaviorRule):
    families = ('remote_session',)
    required_fields = ('source.ip', 'destination.ip', 'remote.protocol')
    research = (_REMOTE_DOC,)
    protocol = ''
    inside_lane = None

    def judge(self, event):
        if (not _zeek(event) or event.family != 'remote_session'
                or event.get('remote.protocol') != self.protocol or not (peers := _peers(event))):
            return []
        site = getattr(self, 'site_facts', None)
        internal = getattr(site, 'internal_networks', ())
        networks = _site_networks(tuple(internal), tuple(getattr(site, 'external_networks', ()))) if internal else current()
        source = ip_address(peers[0])
        if not any(network.version == source.version for network in networks.internal):
            # e.g. IPv4-only ranges on a dual-stack site: an IPv6 source cannot be placed inside or outside
            lane, notes = 'lead', (
                f'internal networks name no IPv{source.version} range; source direction is unresolved',)
        elif networks.is_internal(source):
            lane, notes = self.inside_lane, ()
        else:
            lane, notes = 'high', ()
        if lane is None:
            return []
        if not networks.configured:
            notes = (*notes, DIRECTION_ASSUMED_REASON)
        text = f'{self.protocol.upper()} session negotiation observed from {peers[0]} to {peers[1]}'
        return [signal(event, self.id, text, self.attack,
            ('source.ip', 'destination.ip', 'destination.port', 'remote.protocol'), lane=lane,
            severity='high' if lane == 'high' else 'medium', notes=notes, common=text,
            content=json.dumps([*peers, self.protocol]))]


class RdpRemoteSession(_RemoteSession):
    id, title = 'net.external_rdp', 'RDP session negotiation from outside the declared site'
    protocol = 'rdp'
    attack = ('T1133', 'T1021.001')


class VncRemoteSession(_RemoteSession):
    id, title = 'net.vnc_session', 'VNC session negotiation was observed'
    protocol, inside_lane = 'vnc', 'lead'
    attack = ('T1021.005',)
    research = ('https://docs.zeek.org/en/master/scripts/base/protocols/rfb/main.zeek.html',)


class HttpWinrm(ZeekBehaviorRule):
    id, title = 'net.http_winrm', 'An HTTP request targeted the WinRM service path'
    families = ('http_tx',)
    required_fields = ('source.ip', 'destination.ip', 'destination.port', 'url.original')
    attack = ('T1021.006',)
    research = (_WINRM_DOC,)

    def judge(self, event):
        if (not _zeek(event) or event.family != 'http_tx' or event.get('destination.port') not in {5985, 5986}
                or not (peers := _peers(event))):
            return []
        try:
            path = urlsplit(event.get('url.original') or '').path
        except (ValueError, TypeError):
            return []
        if path != '/wsman':
            return []
        text = f'HTTP /wsman request observed from {peers[0]} to {peers[1]}:{event.get("destination.port")}'
        return [signal(event, self.id, text, self.attack,
            ('source.ip', 'destination.ip', 'destination.port', 'url.original'), common=text,
            content=json.dumps([*peers, event.get('destination.port')]))]


class TgsLongLifetime(ZeekBehaviorRule):
    id, title = 'net.kerberos_long_ticket_lifetime', 'TGS requested validity extends beyond ten hours'
    families = ('kerberos_tx',)
    required_fields = ('kerberos.request_type', 'kerberos.till')
    attack = ('T1558.001',)
    research = (_TICKET_DOC,
                'https://raw.githubusercontent.com/zeek/zeek/master/scripts/base/protocols/krb/main.zeek')

    def judge(self, event):
        if (not _zeek(event) or event.family != 'kerberos_tx'
                or str(event.get('kerberos.request_type') or '').strip().upper() != 'TGS'):
            return []
        try:
            till = datetime.fromisoformat(event.get('kerberos.till'))
            if till - event.ts <= TICKET_LIFETIME:
                return []
        except (ValueError, TypeError, OverflowError):
            return []
        text = 'A TGS request with requested validity beyond ten hours was observed'
        return [signal(event, self.id, text, self.attack,
            ('source.ip', 'destination.ip', 'kerberos.request_type', 'kerberos.till', 'kerberos.client', 'kerberos.service'),
            notes=('Ten hours is the default AD service-ticket age used as a comparison for the requested validity.',
                   'The request field does not establish the granted lifetime or a golden ticket; benign clients can request beyond domain policy.',),
            common=text, content=json.dumps([event.get('source.ip'),event.get('destination.ip'),event.get('kerberos.client')]))]


# TgsLongLifetime is not registered: Windows clients request till 2037-09-13 (no expiry) on ordinary TGS requests,
# so the requested validity marks nearly every ticket; it needs the granted lifetime, which Zeek does not log.
RULES = (RpcRemoteAdminCall, WireReplicationCall, RdpRemoteSession, VncRemoteSession, HttpWinrm)
