"""Build the immutable hunt manifest (scope, sources, versions, budgets, config digest)."""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime

from romulus import __version__
from romulus.baseline.playbook import BASELINE_PLAYBOOKS
from romulus.config import Settings
from romulus.decide.policy import POLICY_VERSION
from romulus.detect.netdef import SiteNetworks
from romulus.detect.registry import PACK_VERSION, pack_manifest
from romulus.evidence.normalize import NORMALIZER_VERSION
from romulus.hunt.packets import PACKET_NORMALIZER
from romulus.site import SiteFacts
from romulus.sources.models import Window
from romulus.store.db import digest


def new_hunt_id() -> str:
    return datetime.now(UTC).strftime("h%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]


def baseline_site(s: Settings, targets: list[str]) -> str:
    """Configured site identity, or a deterministic identity for this exact target set."""
    if s.site.strip():
        return s.site.strip()
    material = json.dumps(sorted(set(targets)), separators=(",", ":"), ensure_ascii=False)
    return "targets-sha256:" + hashlib.sha256(material.encode()).hexdigest()


def build_manifest(s: Settings, window: Window, original_input: dict, style: str, targets: list[str],
                   profiles: dict[str, dict], hypothesis: str = "", budgets: dict | None = None,
                   ai_agent: dict | None = None, site_facts: SiteFacts | None = None,
                   baseline_store_cut_digest: str | None = None) -> dict:
    safe_cfg = {k: v for k, v in s.redacted().items() if k not in ("secret_key",)}
    manifest = {
        "schema": "hunt-manifest@1",
        "romulus_version": __version__,
        "style": style,
        "hypothesis": hypothesis,
        "window": {"start": window.start.isoformat(), "end": window.end.isoformat(), "semantics": "[start, end) UTC"},
        "original_input": original_input,
        "targets": targets,
        "source_profiles": {t: {
            "id": p["id"], "backend_version": p["backend_version"], "doc_count": p["doc_count"],
            "datasets": p["datasets"], "role": p["role"], "os_family": p["os_family"],
        } for t, p in profiles.items()},
        "pack": {"version": PACK_VERSION, "playbooks": pack_manifest()},
        "normalizer": NORMALIZER_VERSION,
        "packet_normalizer": PACKET_NORMALIZER,
        "policy": POLICY_VERSION,
        "model": {"triage": s.ollama_model_triage, "synthesis": s.synthesis_model, "num_ctx": s.ollama_num_ctx,
                  "think": s.ollama_think},
        "agent_mode": s.agent_mode,
        # which addresses are the site's: the sweep's direction-dependent rules read this definition
        "internal_networks": SiteNetworks.from_settings(s).record(),
        "baseline": {
            "plan_version": "baseline-plan@1",
            "site": baseline_site(s, targets),
            "history_days": 7,
            "min_live_hours": 48,
            "specs": [
                {"id": playbook.spec.id, "version": playbook.spec.version,
                 "key_version": playbook.spec.key_version}
                for playbook in sorted(BASELINE_PLAYBOOKS, key=lambda item: item.spec.id)
            ],
            "decay": {"first_seen": "none", "rare_half_life_days": 14, "rate": "none"},
            "thresholds": {"rare": None},
            "budget": {"queries": 200, "records": 5_000_000, "seconds": 1800},
            "store_cut_digest": baseline_store_cut_digest or digest([]),
            "internal_networks": SiteNetworks.from_settings(s).record(),
        },
        "budgets": budgets or {"agent_steps_total": 60, "agent_steps_per_case": 8, "max_cases": 12,
                               "wall_clock_minutes": 120},
        # the AI agent's provider and model as configured when the hunt was created (no key, no URL path)
        "ai_agent": ai_agent or {"requested": False, "state": "not_configured", "reason": "not evaluated"},
        "config_digest": digest(safe_cfg),
    }
    site = site_facts.manifest_entry() if site_facts is not None else None
    if site is not None:
        manifest["site"] = site
    return manifest
