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
