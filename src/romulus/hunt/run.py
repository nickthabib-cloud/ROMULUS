"""Create and run a hunt end to end: inventory -> sweep -> agent investigation -> result."""
from __future__ import annotations

import logging
from datetime import datetime

from romulus.config import Settings
from romulus.hunt.manifest import build_manifest, new_hunt_id
from romulus.hunt.sweep import Sweep
from romulus.sources.es import ElasticClient
from romulus.sources.models import Window
from romulus.sources.profile import build_profile
from romulus.store.db import digest, make_engine, migrate
from romulus.store.repo import Repo

log = logging.getLogger("romulus.hunt")


def open_repo(s: Settings) -> Repo:
    e = make_engine(s.db_path)
    migrate(e)
    return Repo(e)


def create_hunt(s: Settings, start: datetime, end: datetime, created_by: str, style: str = "broad",
                hypothesis: str = "", original_input: dict | None = None) -> str:
    repo = open_repo(s)
    window = Window(start=start, end=end)
    client = ElasticClient(s)
    profiles, targets = {}, []
    for pat in s.es_index_patterns:
        for target in client.resolve(pat):
            prof, _contract = build_profile(client, target)
            profiles[target] = prof.model_dump(mode="json")
            targets.append(target)
    manifest = build_manifest(s, window, original_input or {"start": start.isoformat(), "end": end.isoformat()},
                              style, targets, profiles, hypothesis)
    hid = new_hunt_id()
    repo.create_hunt(hid, manifest, digest(manifest), created_by)
    for p in profiles.values():
        repo.save_profile(hid, p)
    return hid


def run_hunt(s: Settings, hunt_id: str, agent: bool = True, on_candidate=None) -> dict:
    repo = open_repo(s)
    h = repo.get_hunt(hunt_id)
    if h is None:
        raise KeyError(hunt_id)
    m = h["manifest"]
    window = Window(start=datetime.fromisoformat(m["window"]["start"]), end=datetime.fromisoformat(m["window"]["end"]))
    client = ElasticClient(s)
    contracts = {}
    for target in m["targets"]:
        prof, contract = build_profile(client, target)
        if prof.id != m["source_profiles"][target]["id"]:
            # mapping or content changed since the manifest was fixed: proceed, but say so
            repo.audit("system", "source_profile_changed", hunt_id, {"target": target, "now": prof.id,
                                                                   "manifest": m["source_profiles"][target]["id"]})
        contracts[target] = contract
    repo.set_hunt_state(hunt_id, "running")
    sweep = Sweep(repo, client, hunt_id, window, contracts, on_candidate)
    try:
        for target in m["targets"]:
            sweep.run_target(target)
        sweep.finalize()
    except Exception as e:  # noqa: BLE001 - recorded, hunt marked failed, re-raised
        repo.set_hunt_state(hunt_id, "failed", stop_reason=f"sweep error: {e}")
        raise
    agent_summary = None
    if agent:
        from romulus.agent.controller import Investigator
        agent_summary = Investigator(s, repo, client, hunt_id, contracts, window).run()
    counts = repo.lane_counts(hunt_id)
    partial = bool(sweep.partial_reasons) or (agent_summary or {}).get("partial", False)
    reportable = counts.get("urgent", 0) + counts.get("high", 0)
    result = ("reportable_findings" if reportable else "leads_only" if counts.get("lead") else
              "no_qualifying_observation_in_assessed_scope")
    reason = "; ".join(sweep.partial_reasons[:10]) or "frontier complete"
    if agent_summary and agent_summary.get("stop_reason"):
        reason += f"; agent: {agent_summary['stop_reason']}"
    repo.set_hunt_state(hunt_id, "partial" if partial else "completed_within_scope", detection_result=result,
                        stop_reason=reason)
    return {"hunt_id": hunt_id, "stats": sweep.stats, "lanes": counts, "detection_result": result,
            "partial_reasons": sweep.partial_reasons, "agent": agent_summary}
