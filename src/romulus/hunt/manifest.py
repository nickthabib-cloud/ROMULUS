"""Build the immutable hunt manifest (scope, sources, versions, budgets, config digest)."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime

from romulus import __version__
from romulus.config import Settings
from romulus.decide.policy import POLICY_VERSION
from romulus.detect.registry import PACK_VERSION, pack_manifest
from romulus.evidence.normalize import NORMALIZER_VERSION
from romulus.sources.models import Window
from romulus.store.db import digest


def new_hunt_id() -> str:
    return datetime.now(UTC).strftime("h%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]


def build_manifest(s: Settings, window: Window, original_input: dict, style: str, targets: list[str],
                   profiles: dict[str, dict], hypothesis: str = "", budgets: dict | None = None) -> dict:
    safe_cfg = {k: v for k, v in s.redacted().items() if k not in ("secret_key",)}
    return {
        "schema": "hunt-manifest@1",
        "romulus_version": __version__,
        "style": style,
        "hypothesis": hypothesis,
        "window": {"start": window.start.isoformat(), "end": window.end.isoformat(), "semantics": "[start, end) UTC"},
        "original_input": original_input,
        "targets": targets,
        "source_profiles": {t: {"id": p["id"], "backend_version": p["backend_version"], "doc_count": p["doc_count"],
                                "datasets": p["datasets"]} for t, p in profiles.items()},
        "pack": {"version": PACK_VERSION, "playbooks": pack_manifest()},
        "normalizer": NORMALIZER_VERSION,
        "policy": POLICY_VERSION,
        "model": {"triage": s.ollama_model_triage, "synthesis": s.synthesis_model, "num_ctx": s.ollama_num_ctx,
                  "think": s.ollama_think},
        "agent_mode": s.agent_mode,
        "budgets": budgets or {"agent_steps_total": 60, "agent_steps_per_case": 8, "max_cases": 12,
                               "wall_clock_minutes": 120},
        "config_digest": digest(safe_cfg),
    }
