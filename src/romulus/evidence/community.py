"""Shared Community ID v1 construction for host and network telemetry."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import struct

# Community ID v1 (corelight/community-id-spec): transports whose identifiers contain two ports.
COMMUNITY_ID_PROTOCOLS = {"tcp": 6, "udp": 17, "sctp": 132}


def community_id(src, sport, dst, dport, transport) -> str | None:
    """Return the seed-zero Community ID v1 for a valid IP 5-tuple, else ``None``."""
    number = COMMUNITY_ID_PROTOCOLS.get(str(transport or "").lower())
    if (number is None or not isinstance(sport, int) or not isinstance(dport, int)
            or isinstance(sport, bool) or isinstance(dport, bool)
            or not (0 <= sport <= 65535 and 0 <= dport <= 65535)):
        return None
    try:
        a, b = ipaddress.ip_address(str(src)).packed, ipaddress.ip_address(str(dst)).packed
    except ValueError:
        return None
    if len(a) != len(b):
        return None
    if (a, sport) > (b, dport):
        a, b, sport, dport = b, a, dport, sport
    data = struct.pack("!H", 0) + a + b + struct.pack("!BBHH", number, 0, sport, dport)
    return "1:" + base64.b64encode(hashlib.sha1(data).digest()).decode()
