"""The active playbook pack and per-source applicability."""
from __future__ import annotations

from romulus.detect.correlation import CORRELATION_PLAYBOOKS
from romulus.detect.host import HOST_PLAYBOOKS
from romulus.detect.network import NETWORK_PLAYBOOKS

PACK_VERSION = "m2-pack@1"
ALL_PLAYBOOKS = HOST_PLAYBOOKS + NETWORK_PLAYBOOKS + CORRELATION_PLAYBOOKS


def fresh_pack():
    """New evaluator instances for one hunt (they carry aggregate state)."""
    return [cls() for cls in ALL_PLAYBOOKS]


def fresh_direct_pack():
    """Fresh evaluators safe for a bounded pivot subset."""
    return [cls() for cls in ALL_PLAYBOOKS if cls.kind == "direct"]


def pack_manifest() -> list[dict]:
    return [{"id": c.id, "version": c.version, "title": c.title, "kind": c.kind, "families": list(c.families),
             "required_fields": list(c.required_fields), "severity": c.severity, "lane": c.lane,
             "attack": list(c.attack), "assures_negative": c.assures_negative} for c in ALL_PLAYBOOKS]
