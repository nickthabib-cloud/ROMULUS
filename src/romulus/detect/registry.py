"""The active playbook pack and per-source applicability."""
from __future__ import annotations

from romulus.baseline.playbook import BASELINE_PLAYBOOKS
from romulus.detect.auth import AUTH_PLAYBOOKS
from romulus.detect.base import Playbook
from romulus.detect.context import CONTEXT_PLAYBOOKS
from romulus.detect.correlation import CORRELATION_PLAYBOOKS
from romulus.detect.dns import DNS_PLAYBOOKS
from romulus.detect.flows import FLOW_PLAYBOOKS
from romulus.detect.hijack import HIJACK_PLAYBOOKS
from romulus.detect.host import HOST_PLAYBOOKS, share_lineage
from romulus.detect.indicators import INDICATOR_PLAYBOOKS
from romulus.detect.kernel_files import KERNEL_FILE_PLAYBOOKS
from romulus.detect.lineage import LINEAGE_PLAYBOOKS
from romulus.detect.network import NETWORK_PLAYBOOKS
from romulus.detect.packets import PACKET_PLAYBOOKS
from romulus.detect.sessions import SESSION_PLAYBOOKS
from romulus.detect.tamper import TAMPER_PLAYBOOKS
from romulus.detect.tls import TLS_PLAYBOOKS
from romulus.detect.windows_account_events import WINDOWS_ACCOUNT_PLAYBOOKS
from romulus.detect.windows_auth_events import WINDOWS_AUTH_EVENT_PLAYBOOKS
from romulus.detect.windows_catalog_events import CATALOG_EVENT_RULES
from romulus.detect.windows_catalog_state import RULES as WINDOWS_CATALOG_STATE_RULES
from romulus.detect.windows_common import WindowsProcessRule, share_windows_lineage
from romulus.detect.windows_correlations import WINDOWS_CORRELATION_PLAYBOOKS
from romulus.detect.windows_credentials import WINDOWS_CREDENTIAL_PLAYBOOKS
from romulus.detect.windows_defense import WINDOWS_DEFENSE_PLAYBOOKS
from romulus.detect.windows_directory_events import WINDOWS_DIRECTORY_PLAYBOOKS
from romulus.detect.windows_driver_hashes import RULES as WINDOWS_DRIVER_HASH_RULES
from romulus.detect.windows_elevation_events import ELEVATION_EVENT_RULES
from romulus.detect.windows_endpoint_events import WINDOWS_ENDPOINT_PLAYBOOKS
from romulus.detect.windows_events import WindowsEventRule
from romulus.detect.windows_file_events import WINDOWS_FILE_PLAYBOOKS
from romulus.detect.windows_housekeeping import RULES as WINDOWS_HOUSEKEEPING_RULES
from romulus.detect.windows_image_file_rules import RULES as WINDOWS_IMAGE_FILE_RULES
from romulus.detect.windows_injection_w4 import RULES as WINDOWS_INJECTION_RULES
from romulus.detect.windows_lineage import WINDOWS_LINEAGE_PLAYBOOKS
from romulus.detect.windows_linked import WINDOWS_LINKED_PLAYBOOKS
from romulus.detect.windows_lolbin_w4 import RULES as WINDOWS_LOLBIN_RULES
from romulus.detect.windows_memory_events import WINDOWS_MEMORY_PLAYBOOKS
from romulus.detect.windows_process_w4 import RULES as WINDOWS_PROCESS_W4_RULES
from romulus.detect.windows_proxy import WINDOWS_PROXY_PLAYBOOKS
from romulus.detect.windows_registration_events import WINDOWS_REGISTRATION_PLAYBOOKS
from romulus.detect.windows_registry_events import WINDOWS_REGISTRY_PLAYBOOKS
from romulus.detect.windows_remote import WINDOWS_REMOTE_PLAYBOOKS
from romulus.detect.windows_rpc import RULES as WINDOWS_RPC_RULES
from romulus.detect.windows_scripts import WINDOWS_SCRIPT_PLAYBOOKS
from romulus.detect.windows_sequence_extensions import RULES as WINDOWS_SEQUENCE_RULES
from romulus.detect.windows_tunnels_w4 import RULES as WINDOWS_TUNNEL_RULES
from romulus.detect.zeek_alerts import ZEEK_ALERT_PLAYBOOKS
from romulus.detect.zeek_lateral import RULES as ZEEK_LATERAL_PLAYBOOKS
from romulus.detect.zeek_rates import RULES as ZEEK_RATE_PLAYBOOKS
from romulus.detect.zeek_smb import RULES as ZEEK_SMB_PLAYBOOKS

PACK_VERSION = "pack@51"
WINDOWS_PROCESS_PLAYBOOKS = (WINDOWS_LINEAGE_PLAYBOOKS + WINDOWS_PROXY_PLAYBOOKS + WINDOWS_CREDENTIAL_PLAYBOOKS
                             + WINDOWS_DEFENSE_PLAYBOOKS + WINDOWS_REMOTE_PLAYBOOKS)
WINDOWS_HOST_PLAYBOOKS = list(WINDOWS_MEMORY_PLAYBOOKS + WINDOWS_REGISTRY_PLAYBOOKS
                            + WINDOWS_ENDPOINT_PLAYBOOKS + WINDOWS_FILE_PLAYBOOKS
                            + CATALOG_EVENT_RULES + tuple(rule for rule in WINDOWS_CATALOG_STATE_RULES
                                                         if issubclass(rule, WindowsEventRule)))
WINDOWS_DOMAIN_PLAYBOOKS = list(WINDOWS_AUTH_EVENT_PLAYBOOKS + WINDOWS_ACCOUNT_PLAYBOOKS
                              + WINDOWS_REGISTRATION_PLAYBOOKS + WINDOWS_DIRECTORY_PLAYBOOKS
                              + WINDOWS_CORRELATION_PLAYBOOKS
                              + tuple(rule for rule in WINDOWS_CATALOG_STATE_RULES
                                      if not issubclass(rule, WindowsEventRule)))
_WINDOWS_ADDITIONS = (tuple(WINDOWS_PROCESS_W4_RULES) + tuple(ELEVATION_EVENT_RULES)
                      + tuple(WINDOWS_INJECTION_RULES) + tuple(WINDOWS_LOLBIN_RULES)
                      + tuple(WINDOWS_TUNNEL_RULES) + tuple(WINDOWS_RPC_RULES)
                      + WINDOWS_DRIVER_HASH_RULES + WINDOWS_HOUSEKEEPING_RULES
                      + WINDOWS_IMAGE_FILE_RULES + WINDOWS_SEQUENCE_RULES)
WINDOWS_PROCESS_PLAYBOOKS += [rule for rule in _WINDOWS_ADDITIONS if issubclass(rule, WindowsProcessRule)]
WINDOWS_HOST_PLAYBOOKS += [rule for rule in _WINDOWS_ADDITIONS
                         if issubclass(rule, WindowsEventRule) and not issubclass(rule, WindowsProcessRule)]
WINDOWS_DOMAIN_PLAYBOOKS += [rule for rule in _WINDOWS_ADDITIONS
                           if not issubclass(rule, (WindowsEventRule, WindowsProcessRule))]

ALL_PLAYBOOKS = (HOST_PLAYBOOKS + HIJACK_PLAYBOOKS + KERNEL_FILE_PLAYBOOKS + LINEAGE_PLAYBOOKS + AUTH_PLAYBOOKS
                 + TAMPER_PLAYBOOKS + NETWORK_PLAYBOOKS + DNS_PLAYBOOKS + SESSION_PLAYBOOKS + TLS_PLAYBOOKS + FLOW_PLAYBOOKS
                 + CORRELATION_PLAYBOOKS + INDICATOR_PLAYBOOKS + CONTEXT_PLAYBOOKS + PACKET_PLAYBOOKS
                 + WINDOWS_PROCESS_PLAYBOOKS + WINDOWS_HOST_PLAYBOOKS + WINDOWS_DOMAIN_PLAYBOOKS
                 + list(WINDOWS_LINKED_PLAYBOOKS) + list(WINDOWS_SCRIPT_PLAYBOOKS) + ZEEK_ALERT_PLAYBOOKS
                 + list(ZEEK_LATERAL_PLAYBOOKS) + list(ZEEK_SMB_PLAYBOOKS) + list(ZEEK_RATE_PLAYBOOKS)
                 + BASELINE_PLAYBOOKS)
_ANCHOR_CLASSES = {playbook.id: playbook.anchor_class for playbook in ALL_PLAYBOOKS}


_KINDS = {playbook.id: playbook.kind for playbook in ALL_PLAYBOOKS}


def rule_kind(rule_id: str) -> str:
    """The expansion scheduling category of a rule; baseline and context findings never become anchors."""
    kind = _KINDS.get(rule_id, "direct")
    return "context" if kind == "baseline" else kind


def anchor_class_for_rule(rule_id: str, *, metadata=None) -> str:
    """Resolve only registered rule identities; rule-name substrings carry no semantics."""
    if metadata is not None and rule_id in metadata:
        return metadata[rule_id].anchor_class
    return _ANCHOR_CLASSES.get(rule_id, Playbook.anchor_class)


def fresh_pack():
    """New evaluator instances for one hunt (they carry aggregate state)."""
    # context rules run only in expansion, packet rules only in the packet stage; baseline playbooks consume
    # window cells in the sweep and are judged by the later baseline stage.
    pack = [cls() for cls in ALL_PLAYBOOKS if cls.kind not in ("context", "packet")]
    share_lineage(pack)           # one Linux exec lineage for every rule that keeps one
    share_windows_lineage(pack)   # one Windows process-history store for every parent-resolving Windows rule
    return pack


def fresh_direct_pack():
    """Fresh evaluators safe for a bounded pivot subset."""
    pack = [cls() for cls in ALL_PLAYBOOKS if cls.kind == "direct"
            or (cls.kind == "aggregate" and getattr(cls, "direct_eligible", False))]
    for rule in pack:
        if isinstance(rule, WindowsEventRule):
            rule.one_shot = True
            rule.kind = "direct"
    return pack


def fresh_context_pack():
    """Fresh context-only evaluators; never called by the sweep."""
    return [cls() for cls in ALL_PLAYBOOKS if cls.kind == "context" and not getattr(cls, "per_link_evidence", False)]


def bind_windows_site(pack, site_facts):
    """Forward the caller's already-frozen site snapshot; rules never reload configuration."""
    for rule in pack:
        if isinstance(rule, WindowsEventRule) or getattr(rule, 'uses_site_facts', False):
            rule.site_facts = site_facts
    return pack


def pack_manifest() -> list[dict]:
    return [{"id": c.id, "version": c.version, "title": c.title, "kind": c.kind, "families": list(c.families),
             "required_fields": list(c.required_fields), "severity": c.severity, "lane": c.lane,
             "attack": list(c.attack), "assures_negative": c.assures_negative,
             "anchor_class": c.anchor_class} for c in ALL_PLAYBOOKS]
