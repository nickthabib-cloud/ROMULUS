"""Source-free deterministic expansion tier definitions."""
from __future__ import annotations

TIER_PLAN: tuple[tuple[str, tuple[str, ...], str], ...] = (
    ("T1", ("login_session", "process_lineage", "network_flow"), "anchor ±5 min"),
    ("T2", ("host_after_anchor", "flow_host_side"), "anchor ±5 min"),
    ("T3", ("login_session", "process_lineage", "network_flow", "host_after_anchor",
            "flow_host_side"), "anchor ±30 min"),
    ("T4", ("source_ip", "account"), "anchor ±5 min"),
    ("T5", ("login_session", "process_lineage", "network_flow", "host_after_anchor",
            "flow_host_side", "source_ip", "account"), "anchor ±2 h"),
)

# Windows-only additions are kept outside the portable plan: Linux manifests, budgets and expansion output remain
# byte-identical, while anchors carrying Windows evidence receive the extra typed reaches at the same tier windows.
WINDOWS_TIER_ADDITIONS: tuple[tuple[str, tuple[str, ...], str], ...] = (
    ("T1", ("process_activity", "process_session", "kerberos_logon"), "anchor ±5 min"),
    ("T2", ("remote_logon_source", "service_process"), "anchor ±5 min"),
    ("T3", (
        "process_activity", "process_session", "kerberos_logon", "remote_logon_source", "service_process",
    ), "anchor ±30 min"),
    ("T4", (), "anchor ±5 min"),
    ("T5", (
        "process_activity", "process_session", "kerberos_logon", "remote_logon_source", "service_process",
    ), "anchor ±2 h"),
)
