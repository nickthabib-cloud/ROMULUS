"""Typed event families and the claim kinds their fields can support."""
from __future__ import annotations

# This is the typed-event vocabulary recorded by the store and catalog. Keep it
# explicit so a new family cannot silently become eligible for every claim.
REGISTERED_EVENT_FAMILIES = frozenset({
    "account_change", "address_assignment", "app_tx", "application_compatibility", "asset_observed",
    "audit_config", "auth", "boot_configuration", "database_audit", "dcom_access", "defender_event",
    "directory_access", "directory_change", "dns_lookup", "dns_query", "ese_database", "file_access",
    "file_change", "file_transfer", "http_access", "http_body", "http_tx", "ics_tx", "image_load",
    "kernel_module", "kerberos_tx", "ldap_tx", "mail_message", "msi_install", "net_alert", "net_flow", "net_session",
    "net_socket", "network_filter", "ntlm_tx", "object_access", "pipe_event", "privilege_adjustment",
    "privilege_use", "process_access", "process_exec", "process_observed", "process_tampering",
    "process_termination", "registry_change", "remote_access", "remote_session", "remote_thread", "rpc_call",
    "rpc_tx", "scheduled_task", "script_block", "security_enumeration", "sensor_health", "service_change",
    "share_access", "share_change", "silent_process_exit", "smb_tx", "ssh_session", "system_state",
    "tcp_stream", "tls_session", "vpn_session", "web_error", "winsock_catalog", "wmi_subscription", "x509_certificate",
})

_EXECUTION = frozenset({
    "boot_configuration", "image_load", "kernel_module", "process_access", "process_exec",
    "process_observed", "process_tampering", "process_termination", "remote_thread",
    "scheduled_task", "script_block", "service_change", "silent_process_exit",
})
_NETWORK = frozenset({
    "address_assignment", "app_tx", "asset_observed", "dns_lookup", "dns_query", "file_transfer",
    "http_access", "http_body", "http_tx", "ics_tx", "net_alert", "net_flow", "net_session",
    "net_socket", "network_filter", "remote_access", "remote_session", "rpc_call", "rpc_tx",
    "sensor_health", "smb_tx", "ssh_session", "tcp_stream", "tls_session", "web_error",
    "winsock_catalog", "x509_certificate",
})
_AUTH = frozenset({"auth", "dcom_access", "kerberos_tx", "ldap_tx", "ntlm_tx", "privilege_use"})
_FILE = frozenset({"ese_database", "file_access", "file_change", "file_transfer", "msi_install"})
_ACCOUNT = frozenset({
    "account_change", "directory_access", "directory_change", "privilege_adjustment", "share_access",
    "share_change",
})

CLAIM_KIND_FAMILIES = {
    family: frozenset({"mention"})
    | ({"execution"} if family in _EXECUTION else set())
    | ({"network"} if family in _NETWORK else set())
    | ({"auth"} if family in _AUTH else set())
    | ({"file"} if family in _FILE else set())
    | ({"account_change"} if family in _ACCOUNT else set())
    for family in REGISTERED_EVENT_FAMILIES
}

CLAIM_KINDS = frozenset({"execution", "network", "auth", "file", "account_change", "mention"})


def supports_claim_kind(family: str, claim_kind: str) -> bool:
    return claim_kind in CLAIM_KIND_FAMILIES.get(family, ())
