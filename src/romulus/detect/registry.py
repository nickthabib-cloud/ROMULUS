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

PACK_VERSION = "pack@24"
ALL_PLAYBOOKS = (HOST_PLAYBOOKS + HIJACK_PLAYBOOKS + KERNEL_FILE_PLAYBOOKS + LINEAGE_PLAYBOOKS + AUTH_PLAYBOOKS
                 + TAMPER_PLAYBOOKS + NETWORK_PLAYBOOKS + DNS_PLAYBOOKS + SESSION_PLAYBOOKS + TLS_PLAYBOOKS + FLOW_PLAYBOOKS
                 + CORRELATION_PLAYBOOKS + INDICATOR_PLAYBOOKS + CONTEXT_PLAYBOOKS + PACKET_PLAYBOOKS
                 + BASELINE_PLAYBOOKS)
_ANCHOR_CLASSES = {playbook.id: playbook.anchor_class for playbook in ALL_PLAYBOOKS}


_KINDS = {playbook.id: playbook.kind for playbook in ALL_PLAYBOOKS}


def rule_kind(rule_id: str) -> str:
    """The expansion scheduling category of a rule; baseline and context findings never become anchors."""
    kind = _KINDS.get(rule_id, "direct")
    return "context" if kind == "baseline" else kind


def anchor_class_for_rule(rule_id: str) -> str:
    """Resolve only registered rule identities; rule-name substrings carry no semantics."""
    return _ANCHOR_CLASSES.get(rule_id, Playbook.anchor_class)


def fresh_pack():
    """New evaluator instances for one hunt (they carry aggregate state)."""
    # context rules run only in expansion, packet rules only in the packet stage; baseline playbooks consume
    # window cells in the sweep and are judged by the later baseline stage.
    pack = [cls() for cls in ALL_PLAYBOOKS if cls.kind not in ("context", "packet")]
    share_lineage(pack)           # one exec lineage for every rule that keeps one
    return pack


def fresh_direct_pack():
    """Fresh evaluators safe for a bounded pivot subset."""
    return [cls() for cls in ALL_PLAYBOOKS if cls.kind == "direct"]


def fresh_context_pack():
    """Fresh context-only evaluators; never called by the sweep."""
    return [cls() for cls in ALL_PLAYBOOKS if cls.kind == "context"]


def pack_manifest() -> list[dict]:
    return [{"id": c.id, "version": c.version, "title": c.title, "kind": c.kind, "families": list(c.families),
             "required_fields": list(c.required_fields), "severity": c.severity, "lane": c.lane,
             "attack": list(c.attack), "assures_negative": c.assures_negative,
             "anchor_class": c.anchor_class} for c in ALL_PLAYBOOKS]
