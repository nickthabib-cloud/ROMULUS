"""Producer contracts for network protocol records.

This gate proves family semantics, not the presence of a rule's required fields:
consumers must still test those fields and report missing coverage. The field and
producer matrix is documented in docs/detection/network-protocols.md.

Arkime sessions retain unordered protocol value lists. They are deliberately not
transactions, even when a session contains a single listed value; this gate never
admits them to a rate. Sensor labels are presentation, not producer identity.
"""
from __future__ import annotations

from romulus.evidence.typed import TypedEvent

PROTOCOL_FAMILIES: dict[str, frozenset[str]] = {
    "zeek-ecs": frozenset({
        "net_flow", "dns_query", "http_tx", "tls_session", "ssh_session", "file_transfer",
        "net_alert", "x509_certificate", "smb_tx", "rpc_tx", "kerberos_tx", "ntlm_tx",
        "remote_session", "ldap_tx", "address_assignment", "app_tx", "asset_observed",
        "sensor_health", "ics_tx",
    }),
    "suricata-eve": frozenset({
        "net_alert", "net_flow", "dns_query", "http_tx", "file_transfer", "tls_session", "ssh_session",
        "smb_tx", "rpc_tx", "kerberos_tx", "ntlm_tx", "remote_session", "ldap_tx", "app_tx",
        "address_assignment",
    }),
}


def protocol_record(event: TypedEvent, family: str) -> bool:
    """Whether the exact family carries this producer's documented typed contract."""
    if event.family != family:
        return False
    producer, separator, version = event.normalizer.partition("@")
    return bool(separator and version.isascii() and version.isdecimal() and bool(version.lstrip("0"))
                and family in PROTOCOL_FAMILIES.get(producer, ()))
