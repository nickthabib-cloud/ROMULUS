"""Selective native Windows queries for high-volume event classes."""
from romulus.evidence.rpc_catalog import INTERFACES
from romulus.evidence.windows_catalog import RPC_PROVIDER
from romulus.sources.models import Predicate

RDP_CORE_PROVIDER = 'Microsoft-Windows-RemoteDesktopServices-RdpCoreTS'
RDP_CORE_CHANNEL = RDP_CORE_PROVIDER + '/Operational'
_SCOPED_RDP_READERS = frozenset({'win.rdp_bluekeep_channel', 'win.rdp_headless_client'})


def is_rdp_core(event):
    return event.provider.casefold() == RDP_CORE_PROVIDER.casefold() and event.channel.casefold() == RDP_CORE_CHANNEL.casefold()


def _declares(rule, event):
    return any((str(channel).casefold(), str(provider).casefold(), code) == event.key
               for channel, provider, code in rule.windows_event_classes)


def _generic_rdp_reader(rule):
    return not rule.windows_event_classes and 'remote_access' in (*rule.families, *rule.context_families)


def rdp_class_requested(event, rules):
    """Explicit event-class declarations narrow this high-volume provider's family scope."""
    return any(_declares(rule, event) or _generic_rdp_reader(rule) for rule in rules)


def rdp_channel_groups(contract, base, event, rules):
    """Return bounded native channel-name terms, preserving independent readers' needs."""
    if event.event_id not in (132, 148) or any(
            rule.id not in _SCOPED_RDP_READERS and (_declares(rule, event) or _generic_rdp_reader(rule))
            for rule in rules):
        return [base]
    field = 'remote.channel_name'
    if not contract.supports(field, 'in') or not contract.supports(field, 'missing'):
        return None
    # Three ASCII letters make eight exact spellings. Terms work on flattened
    # leaves; unsupported case-insensitive wildcard matching is not required.
    names = sorted(a + b + '_' + c + '120' for a in ('m', 'M') for b in ('s', 'S') for c in ('t', 'T'))
    return [[*base, Predicate(field=field, op='in', value=names)],
            [*base, Predicate(field=field, op='missing')]]


def wfp_tunnel_groups(contract, base):
    """Retrieve a superset of native loopback RDP connections in either orientation.

    WFP ports are canonical decimal native fields. Prefix queries work on flattened
    leaves; IPv6 prefixes deliberately include extra addresses judged locally.
    https://www.elastic.co/guide/en/elasticsearch/reference/8.19/flattened.html#supported-operations
    https://learn.microsoft.com/windows/security/threat-protection/auditing/event-5156
    """
    groups = []
    for side in ("source", "destination"):
        address, port = f"wfp.{side}_address", f"wfp.{side}_port"
        if not contract.supports(port, "eq"):
            return None
        port_type = contract.fields[port].type
        value = "3389" if port_type in {"keyword", "constant_keyword", "wildcard", "flattened"} else 3389
        if contract.supports(address, "prefix"):
            alternatives = [("prefix", item) for item in ("127.", "::", "0")]
        elif contract.supports(address, "cidr"):
            alternatives = [("cidr", item) for item in ("127.0.0.0/8", "::1/128")]
        else:
            return None
        for operation, network in alternatives:
            groups.append([*base, Predicate(field=port, op="eq", value=value),
                           Predicate(field=address, op=operation, value=network)])
    return groups


def rpc_call_groups(contract):
    """RPC retrieval is a superset of the tolerant native normalization.

    Case-insensitive contains accepts every canonical UUID's mixed case, braces and
    whitespace spellings, and every protocol-sequence spelling. Each is one any-of
    predicate, so a group stays a few clauses whatever the catalog's size: a cross
    product of per-protocol and per-interface groups would pass the clause limits of
    some engines and fail the whole Windows query. Extra substring hits
    are checked by typed fields locally. Missing native leaves also cover XML-only
    payloads and alternative native key case. Text mappings cannot safely filter
    values: use the available provider/code predicates, or no restriction if neither
    is expressible, while preserving every other Windows channel's fallback.
    """
    base = []
    if contract.supports('event.provider', 'eq'):
        base.append(Predicate(field='event.provider', op='eq', value=RPC_PROVIDER))
    code = contract.spec('event.code')
    if code and code.type in {'long', 'integer', 'short'} and contract.supports('event.code', 'in'):
        bases = [[*base, Predicate(field='event.code', op='in', value=[5, 6])]]
    elif contract.supports('event.code', 'contains'):
        # int() accepts zero padding, whitespace and a leading sign as well.
        bases = [[*base, Predicate(field='event.code', op='contains', value=str(n))] for n in (5, 6)]
    else:
        bases = [base]
    code_scoped = code is not None and (code.type in {'long', 'integer', 'short'}
                                        or contract.supports('event.code', 'contains'))
    strict = (contract.supports('event.provider', 'eq') and code_scoped
              and all(contract.supports(field, op) for field in ('rpc.interface_uuid', 'rpc.protocol')
                      for op in ('contains', 'missing')))
    if not strict:
        return bases, False
    transport = Predicate(field='rpc.protocol', op='contains', value=['1', '2', 'ncacn_ip_tcp', 'ncacn_np'])
    interfaces = Predicate(field='rpc.interface_uuid', op='contains', value=[i.uuid for i in INTERFACES])
    out = []
    for group in bases:
        out.append([*group, transport, interfaces])
        out.append([*group, transport, Predicate(field='rpc.interface_uuid', op='missing')])
        out.append([*group, Predicate(field='rpc.protocol', op='missing')])
    return out, True


def nxlog_windows_group(contract):
    """The predicates that select NXLog's flat Windows records (top-level Channel and EventID, no winlog object), or
    None when the target cannot search both fields: that shape is then not assessed there."""
    if not all(contract.supports(name, "exists") for name in ("Channel", "EventID")):
        return None
    group = [Predicate(field="Channel", op="exists"), Predicate(field="EventID", op="exists")]
    if contract.supports("winlog.channel", "missing"):
        group.append(Predicate(field="winlog.channel", op="missing"))
    return group
