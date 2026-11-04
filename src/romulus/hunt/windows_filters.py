"""Selective native Windows queries for high-volume event classes."""
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
