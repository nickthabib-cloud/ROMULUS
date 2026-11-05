"""RPC ETW call observations; the records do not establish an operation's outcome."""
import ipaddress
from datetime import UTC, datetime

from romulus.detect.base import pf
from romulus.detect.citing import bound_note, cited_phrase
from romulus.detect.site_roles import address_member, host_member
from romulus.detect.windows_events import WindowsEventRule, signal
from romulus.evidence.rpc_catalog import INTERFACES, lookup_call
from romulus.evidence.windows_catalog import RPC_PROVIDER

_FIELDS = ('rpc.side', 'rpc.interface_uuid', 'rpc.interface_name', 'rpc.operation', 'rpc.opnum',
           'rpc.op_class', 'rpc.protocol', 'rpc.endpoint', 'rpc.network_address', 'process.pid', 'host.full_name')


class _RpcCall(WindowsEventRule):
    families = ('rpc_call',)
    windows_event_classes = (('', RPC_PROVIDER, 5), ('', RPC_PROVIDER, 6))
    required_fields = ('rpc.side', 'rpc.interface_uuid', 'rpc.op_class', 'rpc.protocol')
    research = ('https://learn.microsoft.com/windows/win32/rpc/rpc-start-page',)
    benign = ('Legitimate administration, backup and replication use RPC.',)
    next_checks = ('Review the cited call, the logging host role, and independent outcome evidence.',)

    def judge(self, event):
        if event.get('rpc.protocol') not in {'tcp', 'named_pipe'}:
            return []
        call = lookup_call(event.get('rpc.interface_uuid'), event.get('rpc.opnum'))
        lane, notes = self.decision(event, call.op_class)
        if lane is None or call.interface is None or call.operation is None:
            return []
        side = event.get('rpc.side')
        if side not in {'client', 'server'}:
            return []
        action = 'client call to' if side == 'client' else 'server call received on'
        transport = 'TCP' if event.get('rpc.protocol') == 'tcp' else 'named pipe'
        text = (f'An RPC {action} the {event.get("rpc.interface_name")} interface '
                f'({call.operation.name}, opnum {call.operation.opnum}) over {transport}')
        if side == 'client' and event.get('rpc.network_address'):
            text += f' to {event.get("rpc.network_address")}'
        if side == 'server':
            text += ', from a caller the server-side record does not name,'
        text += ' was observed'
        content = repr((event.host, side, call.interface.uuid, call.op_class, event.get('rpc.network_address')))
        return [signal(event, self.id, text, call.attack, _FIELDS, lane=lane,
                       severity='high' if lane == 'high' else 'medium', content=content, notes=notes)]

    def _note_group(self, shape, hit, event, *, new_host, link_host=True):
        group = super()._note_group(shape, hit, event, new_host=new_host, link_host=link_host)
        if group is not None:
            # Catalog techniques form a finite union independent of citation sampling.
            attack = tuple(sorted(set(group.attack) | set(hit.attack)))
            if attack != group.attack:
                group.attack = attack
                self.groups.put(shape, group)
        return group

    def record_match(self, event, hit):
        match = super().record_match(event, hit)
        if not self.one_shot:
            match.group_key = f'{self.id}|fleet|{self._shape(event, hit)}'
            match.bounded_revision = True
        return match

    def _fleet_match(self, shape, group, *, final):
        match = super()._fleet_match(shape, group, final=final)
        if match is None:
            return None
        match.revision_reason = 'The bounded RPC fold replaces the earlier count and citation sample.'
        match.bounded_revision = True
        if match.citation_unavailable:
            return match
        missing_bounds = set(group.ends.ids()) - {event.id for event in match.events}
        first = datetime.fromtimestamp(group.ends.first[0], UTC).isoformat() if group.ends.first else '?'
        last = datetime.fromtimestamp(group.ends.last[0], UTC).isoformat() if group.ends.last else '?'
        match.claim = (f'{group.records} RPC call record(s) on {", ".join(group.sample_hosts)}, '
                       f'first {first}, last {last}, folded by host, side, interface, operation class and address. '
                       f'One cited call: {group.common}.'
                       + cited_phrase(len(match.events), group.records, not missing_bounds)
                       + bound_note(missing_bounds, group.ends))
        if match.events:
            _, notes = self.decision(match.events[0], match.events[0].get('rpc.op_class'))
            match.notes.extend(notes)
        return match


class RpcCoercionCall(_RpcCall):
    """Observe remote coercion-class calls. Enumeration is deferred to aggregate discovery;
    secure-channel rate analysis needs a peer (Zeek), server replication is routine and
    cannot name a caller, and PrinterBug notification requires the target role.
    """
    id = 'win.rpc_coercion_call'
    title = 'A remote coercion-class RPC call was observed'
    attack = ('T1187',)

    def decision(self, event, op_class):
        if op_class != 'coercion':
            return None, ()
        if event.get('rpc.side') == 'client' and not event.get('rpc.network_address'):
            return 'lead', ('The client target network address was not recorded, or could not be read.',)
        return 'high', ()


class RpcReplicationCall(_RpcCall):
    """Observe client replication outside declared DCs. Server replication is routine and
    cannot name a caller; secure-channel rate analysis needs a peer (Zeek), enumeration
    needs aggregate discovery, and PrinterBug notification requires the target role.
    """
    id = 'win.rpc_replication_call'
    version = '2'
    title = 'A directory replication RPC client call was observed'
    attack = ('T1003.006', 'T1207')

    def judge(self, event):
        hits = super().judge(event)
        if hits and self._directory_sync_source(event):
            for hit in hits:
                # A sync-role lead must not fold into an undeclared-DC lead and
                # lose its role caveat when the bounded fold picks another witness.
                hit.content += '|declared-directory-sync'
                if address_member(event.get('source.ip'),
                                  getattr(getattr(self, 'site_facts', None), 'directory_sync_addresses', ())):
                    hit.predicate.append(pf(event, 'source.ip'))
        return hits

    def _directory_sync_source(self, event):
        site = getattr(self, 'site_facts', None)
        return (host_member(event.get('host.full_name') or event.host, getattr(site, 'directory_sync_hosts', ()))
                or address_member(event.get('source.ip'), getattr(site, 'directory_sync_addresses', ())))

    def decision(self, event, op_class):
        if op_class != 'replication' or event.get('rpc.side') != 'client':
            return None, ()
        site = getattr(self, 'site_facts', None)
        # On client ETW records the logging host is the source. NetworkAddress
        # names the target server and cannot establish a directory-sync client.
        if self._directory_sync_source(event):
            return 'lead', ('declared directory-sync host; a compromised sync server is a DCSync path',)
        controllers = getattr(site, 'domain_controllers', ())
        if not controllers:
            return 'lead', ('domain controllers not declared; replication from a domain controller is routine',)
        if _is_controller(event, controllers):
            return None, ()
        if any(_is_address(name) for name in controllers):
            # An address cannot be matched to the logging host's name. The call stays high: a replication client
            # outside the named controllers is never demoted on an unmatchable declaration.
            return 'high', (('Some domain controllers are declared by address, which cannot be matched to the '
                             'logging host name: if this host is one of them, the call is routine. Declare '
                             'controllers by host name.'),)
        return 'high', ()


def _is_address(name) -> bool:
    try:
        ipaddress.ip_address(str(name).strip())
    except ValueError:
        return False
    return True


def _is_controller(event, controllers) -> bool:
    """Whether the logging host is a declared controller. A record or declaration with only a short name matches
    by first label; when both are full names they must be equal, so a same-named host in another domain is not one."""
    full = str(event.get('host.full_name') or event.host).strip().rstrip('.').casefold()
    short = full.split('.', 1)[0]
    for name in controllers:
        declared = str(name).strip().rstrip('.').casefold()
        if declared == full:
            return True
        if ('.' not in declared or '.' not in full) and declared.split('.', 1)[0] == short:
            return True
    return False


class RpcRemoteAdminCall(_RpcCall):
    """Observe classified remote administration calls. Enumeration needs aggregate discovery;
    secure-channel rate analysis needs a peer (Zeek), server replication is routine and
    cannot name a caller, and PrinterBug notification requires the target role.
    """
    id = 'win.rpc_remote_admin_call'
    title = 'A remote administration RPC call was observed'
    _HIGH = frozenset({'driver_install', 'sid_history', 'credential_access', 'secret_write'})
    _LEAD = frozenset({'service_create', 'service_start', 'service_modify', 'service_control', 'service_delete',
                      'task_register', 'remote_registry', 'remote_shutdown', 'account_change',
                      'account_rights_change', 'wmi_dcom'})
    attack = tuple(sorted({technique for interface in INTERFACES for operation in interface.operations
                           if operation.op_class in {'driver_install', 'sid_history', 'credential_access',
                               'secret_write', 'service_create', 'service_start', 'service_modify', 'service_control',
                               'service_delete', 'task_register', 'remote_registry', 'remote_shutdown',
                               'account_change', 'account_rights_change', 'wmi_dcom'} for technique in operation.attack}))

    def decision(self, event, op_class):
        return ('high' if op_class in self._HIGH else 'lead' if op_class in self._LEAD else None), ()


RULES = (RpcCoercionCall, RpcReplicationCall, RpcRemoteAdminCall)
