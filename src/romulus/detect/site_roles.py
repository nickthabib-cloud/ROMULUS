"""Exact site role lookups; a network observer is never the traffic's source host."""
from functools import lru_cache
from ipaddress import ip_address, ip_network

ROLE_LOOKUP_CACHE = 4096  # Eviction recomputes a lookup; it never forgets detection evidence.


@lru_cache(maxsize=ROLE_LOOKUP_CACHE)
def _address_member(value, entries):
    try:
        address = ip_address(value)
    except ValueError:
        return False
    candidates = (address, address.ipv4_mapped) if getattr(address, 'ipv4_mapped', None) else (address,)
    for entry in entries:
        try:
            network = ip_network(entry, strict=True)
        except ValueError:
            continue
        if any(candidate.version == network.version and candidate in network for candidate in candidates):
            return True
    return False


def address_member(value, entries):
    return isinstance(value, str) and _address_member(value.strip(), tuple(entries))


def _hostname(value):
    if not isinstance(value, str):
        return ''
    name = value.strip().rstrip('.').casefold()
    if not name or any(char in name for char in '*?/:\\'):
        return ''
    try:
        ip_address(name)
    except ValueError:
        return name
    return ''


@lru_cache(maxsize=ROLE_LOOKUP_CACHE)
def _host_member(name, entries):
    for item in entries:
        declared = _hostname(item)
        if declared and (declared == name or ('.' not in declared or '.' not in name)
                         and declared.split('.', 1)[0] == name.split('.', 1)[0]):
            return True
    return False


def host_member(value, entries):
    name = _hostname(value)
    return bool(name) and _host_member(name, tuple(entries))


def declared_source(event, hosts=(), addresses=()):
    """Use only source-role typed facts; destination and observer names cannot establish the source."""
    return (address_member(event.get('source.ip'), addresses)
            or host_member(event.get('source.hostname'), hosts))
