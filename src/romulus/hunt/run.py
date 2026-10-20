"""Create and run a hunt end to end: inventory -> sweep -> agent investigation -> result."""
from __future__ import annotations

import logging
from datetime import datetime

from romulus.agent.controller import Investigator
from romulus.config import Settings
from romulus.hunt.expansion import ExpansionEngine
from romulus.hunt.links import LinkFetcher
from romulus.hunt.manifest import build_manifest, new_hunt_id
from romulus.hunt.pivot import PivotExecutor
from romulus.hunt.stage import clear_stale_stages
from romulus.hunt.sweep import Sweep
from romulus.sources.es import ElasticClient
from romulus.sources.models import Window
from romulus.sources.profile import build_profile
from romulus.store.db import digest, make_engine, migrate, utcnow
from romulus.store.repo import Repo

log = logging.getLogger("romulus.hunt")
HUNT_LEASE_SECONDS = 600


def _lease_seconds(settings: Settings) -> int:
    return max(HUNT_LEASE_SECONDS, settings.ollama_timeout_seconds + 120)


def open_repo(s: Settings) -> Repo:
    e = make_engine(s.db_path)
    migrate(e)
    return Repo(e)


def create_hunt(s: Settings, start: datetime, end: datetime, created_by: str, style: str = "broad",
                hypothesis: str = "", original_input: dict | None = None, expand: bool = True) -> str:
    repo = open_repo(s)
    window = Window(start=start, end=end)
    client = ElasticClient(s)
    profiles, targets = {}, []
    if not s.es_index_patterns:
        raise ValueError("no ES_INDEX_PATTERNS configured: nothing to hunt")
    for pat in s.es_index_patterns:
        resolved = client.resolve(pat)
        if not resolved:
            # a configured source that is absent must never become an empty "completed" hunt
            raise ValueError(f"source pattern {pat!r} resolves to no index or data stream; fix the "
                             f"configuration or remove the pattern before hunting")
        for target in resolved:
            prof, _contract = build_profile(client, target)
            profiles[target] = prof.model_dump(mode="json")
            targets.append(target)
    manifest = build_manifest(s, window, original_input or {"start": start.isoformat(), "end": end.isoformat()},
                              style, targets, profiles, hypothesis)
    manifest["expansion"] = {"enabled": expand, "max_depth": 3, "max_source_queries": 180}
    hid = new_hunt_id()
    repo.create_hunt(hid, manifest, digest(manifest), created_by)
    for p in profiles.values():
        repo.save_profile(hid, p)
    return hid


def _contracts(s: Settings, repo: Repo, hunt: dict, client: ElasticClient,
               owner_token: str | None = None) -> dict:
    hunt_id = hunt["id"]
    manifest = hunt["manifest"]
    contracts = {}
    for target in manifest["targets"]:
        profile, contract = build_profile(client, target)
        recorded = manifest.get("source_profiles", {}).get(target)
        if recorded and profile.id != recorded["id"]:
            repo.audit("system", "source_profile_changed", hunt_id, {
                "target": target, "now": profile.id, "manifest": recorded["id"],
            }, owner_token=owner_token)
        contracts[target] = contract
    return contracts


def _detection_result(repo: Repo, hunt_id: str) -> tuple[dict[str, int], str]:
    counts = repo.lane_counts(hunt_id)
    reportable = counts.get("urgent", 0) + counts.get("high", 0)
    result = ("reportable_findings" if reportable else "leads_only" if counts.get("lead") else
              "no_qualifying_observation_in_assessed_scope")
    return counts, result


def _finish(repo: Repo, hunt_id: str, agent_summary: dict, sweep_summary: dict,
            *, stats: dict | None = None, partial_reasons: list[str] | None = None,
            expansion_summary: dict | None = None, owner_token: str | None = None) -> dict:
    partial_reasons = partial_reasons or list(sweep_summary.get("partial_reasons") or [])
    sweep_complete = bool(sweep_summary.get("complete"))
    missing_summary = not sweep_summary
    agent_status = agent_summary.get("status")
    partial = (missing_summary or not sweep_complete or agent_status == "unavailable"
               or (expansion_summary or {}).get("status") == "partial")
    counts, result = _detection_result(repo, hunt_id)
    reasons = partial_reasons[:10]
    if missing_summary:
        reasons.append("sweep summary missing; coverage remains conservatively partial")
    elif sweep_complete:
        reasons.append("frontier complete")
    else:
        reasons.append("sweep coverage partial")
    if agent_summary.get("stop_reason"):
        reasons.append(f"agent: {agent_summary['stop_reason']}")
    if expansion_summary and expansion_summary.get("stop_reason"):
        reasons.append(f"expansion: {expansion_summary['stop_reason']}")
    repo.audit(
        "system", "hunt.agent_summary", hunt_id, agent_summary, owner_token=owner_token,
    )
    state = "failed" if agent_status == "failed" else ("partial" if partial else "completed_within_scope")
    repo.set_hunt_state(
        hunt_id, state, owner_token=owner_token,
        detection_result=result, stop_reason="; ".join(reasons),
    )
    return {
        "hunt_id": hunt_id,
        "execution_state": state,
        "stats": stats or sweep_summary.get("stats") or {},
        "lanes": counts,
        "detection_result": result,
        "partial_reasons": partial_reasons,
        "agent": agent_summary,
        "expansion": expansion_summary or {},
    }


def _run_expansion(s: Settings, repo: Repo, client: ElasticClient, hunt: dict, contracts: dict,
                   window: Window, owner_token: str) -> dict:
    manifest = hunt["manifest"]
    config = manifest.get("expansion") or {}
    if config.get("enabled", True) is False:
        summary = {"status": "disabled", "stop_reason": "disabled by --no-expand", "unexpanded": []}
        repo.audit("system", "hunt.expansion_summary", hunt["id"], summary, owner_token=owner_token)
        return summary

    def heartbeat():
        repo.heartbeat_hunt(hunt["id"], _lease_seconds(s), owner_token=owner_token)

    executor = PivotExecutor(
        repo, client, hunt["id"], contracts, heartbeat=heartbeat, owner_token=owner_token,
    )
    budget_seconds = float((manifest.get("budgets") or {}).get("wall_clock_minutes", 120)) * 60
    started_at = hunt.get("started_at")
    if started_at is not None:
        if started_at.tzinfo is None:
            started_at = started_at.replace(tzinfo=utcnow().tzinfo)
        budget_seconds = max(0.0, budget_seconds - (utcnow() - started_at).total_seconds())
    return ExpansionEngine(
        repo, hunt["id"], window, LinkFetcher(executor, window.start, window.end),
        max_depth=int(config.get("max_depth", 3)),
        max_source_queries=int(config.get("max_source_queries", 180)),
        wall_clock_seconds=budget_seconds, owner_token=owner_token, heartbeat=heartbeat,
    ).run()


def _run_investigator(s: Settings, repo: Repo, client: ElasticClient, hunt_id: str,
                      contracts: dict, window: Window, owner_token: str,
                      agent_mode: str) -> dict:
    def heartbeat():
        repo.heartbeat_hunt(hunt_id, _lease_seconds(s), owner_token=owner_token)

    executor = PivotExecutor(
        repo, client, hunt_id, contracts, heartbeat=heartbeat, owner_token=owner_token,
    )

    return Investigator(
        s, repo, executor, hunt_id, window, heartbeat=heartbeat, owner_token=owner_token,
        agent_mode=agent_mode,
    ).run()


def run_hunt(s: Settings, hunt_id: str, agent: bool | None = None, on_candidate=None,
             agent_mode: str | None = None, expand: bool | None = None) -> dict:
    repo = open_repo(s)
    hunt = repo.get_hunt(hunt_id)
    if hunt is None:
        raise KeyError(hunt_id)
    initial_manifest = hunt["manifest"]
    if expand is not None and bool((initial_manifest.get("expansion") or {}).get("enabled", True)) != expand:
        raise ValueError("expansion mode is immutable after hunt creation")
    claimed = repo.claim_hunt(hunt_id, _lease_seconds(s))
    owner_token = claimed["lease_owner"]
    h = repo.get_hunt(hunt_id)
    m = h["manifest"]
    mode = "off" if agent is False else (agent_mode or m.get("agent_mode") or s.agent_mode)
    window = Window(start=datetime.fromisoformat(m["window"]["start"]), end=datetime.fromisoformat(m["window"]["end"]))
    client = ElasticClient(s)
    try:
        contracts = _contracts(s, repo, h, client, owner_token)
    except Exception as exc:
        repo.audit("system", "hunt.sweep_summary", hunt_id, {
            "finished": False, "complete": False, "partial_reasons": [], "stats": {},
            "error": f"source preflight error: {exc}",
        }, owner_token=owner_token)
        repo.set_hunt_state(
            hunt_id, "failed", owner_token=owner_token,
            stop_reason=f"source preflight error: {exc}",
        )
        raise
    def heartbeat():
        repo.heartbeat_hunt(hunt_id, _lease_seconds(s), owner_token=owner_token)

    stage_dir = s.home / "stage"
    clear_stale_stages(stage_dir)
    sweep = Sweep(
        repo, client, hunt_id, window, contracts, on_candidate, heartbeat=heartbeat, stage_dir=stage_dir,
    )
    try:
        for target in m["targets"]:
            sweep.run_target(target)
        sweep.finalize()
    except Exception as e:
        sweep.close_stage()
        repo.audit("system", "hunt.sweep_summary", hunt_id, {
            "finished": False, "complete": False, "partial_reasons": sweep.partial_reasons,
            "stats": sweep.stats, "error": str(e),
        }, owner_token=owner_token)
        repo.set_hunt_state(
            hunt_id, "failed", owner_token=owner_token, stop_reason=f"sweep error: {e}",
        )
        raise
    sweep_summary = {
        "finished": True,
        "complete": not sweep.partial_reasons,
        "partial_reasons": sweep.partial_reasons,
        "stats": sweep.stats,
    }
    repo.audit(
        "system", "hunt.sweep_summary", hunt_id, sweep_summary, owner_token=owner_token,
    )
    expansion_summary = _run_expansion(s, repo, client, repo.get_hunt(hunt_id), contracts, window, owner_token)
    agent_summary = {
        "status": "disabled", "mode": "off", "partial": False,
        "stop_reason": "investigator disabled (agent mode off)",
        "unworked_count": len(repo.candidates(hunt_id, ["urgent", "high", "lead"])),
    }
    if mode != "off":
        try:
            agent_summary = _run_investigator(
                s, repo, client, hunt_id, contracts, window, owner_token, mode,
            )
        except Exception as exc:
            log.exception("investigator failed")
            agent_summary = {
                "status": "failed", "mode": mode, "partial": True,
                "stop_reason": f"investigator error: {exc}",
                "unworked_count": len(repo.candidates(hunt_id, ["urgent", "high", "lead"])),
            }
    return _finish(
        repo, hunt_id, agent_summary, sweep_summary,
        stats=sweep.stats, partial_reasons=sweep.partial_reasons,
        expansion_summary=expansion_summary, owner_token=owner_token,
    )


def resume_hunt(s: Settings, hunt_id: str, agent_mode: str | None = None) -> dict:
    """Resume only persisted investigator work; the deterministic sweep is never re-run."""
    repo = open_repo(s)
    hunt = repo.get_hunt(hunt_id)
    if hunt is None:
        raise KeyError(hunt_id)
    sweep_audit = repo.latest_audit(hunt_id, "hunt.sweep_summary")
    sweep_summary = dict(sweep_audit["detail"]) if sweep_audit else {}
    if hunt["execution_state"] == "running" and not sweep_summary.get("finished"):
        raise RuntimeError("running hunt cannot resume because the sweep did not finish")
    if sweep_summary and not sweep_summary.get("finished"):
        raise RuntimeError("hunt cannot resume agent work because the sweep did not finish")
    if hunt["execution_state"] == "failed" and not sweep_summary.get("finished"):
        raise RuntimeError("failed hunt cannot resume because the sweep did not finish")
    claimed = repo.claim_hunt(hunt_id, _lease_seconds(s), resume=True)
    owner_token = claimed["lease_owner"]
    hunt = repo.get_hunt(hunt_id)
    manifest = hunt["manifest"]
    mode = agent_mode or manifest.get("agent_mode") or s.agent_mode
    window = Window(
        start=datetime.fromisoformat(manifest["window"]["start"]),
        end=datetime.fromisoformat(manifest["window"]["end"]),
    )
    client = ElasticClient(s)
    try:
        contracts = _contracts(s, repo, hunt, client, owner_token)
    except Exception as exc:
        stop_reason = f"source preflight error: {exc}"
        repo.audit("system", "hunt.agent_summary", hunt_id, {
            "status": "failed", "partial": True, "stop_reason": stop_reason,
            "unworked_count": len(repo.candidates(hunt_id, ["urgent", "high", "lead"])),
        }, owner_token=owner_token)
        repo.set_hunt_state(
            hunt_id, "failed", owner_token=owner_token, stop_reason=stop_reason,
        )
        raise
    expansion_summary = _run_expansion(s, repo, client, hunt, contracts, window, owner_token)
    agent_summary = {
        "status": "disabled", "mode": "off", "partial": False,
        "stop_reason": "investigator disabled (agent mode off)",
        "unworked_count": len(repo.candidates(hunt_id, ["urgent", "high", "lead"])),
    }
    if mode != "off":
        try:
            agent_summary = _run_investigator(
                s, repo, client, hunt_id, contracts, window, owner_token, mode,
            )
        except Exception as exc:
            log.exception("resumed investigator failed")
            agent_summary = {
                "status": "failed", "mode": mode, "partial": True,
                "stop_reason": f"investigator error: {exc}",
                "unworked_count": len(repo.candidates(hunt_id, ["urgent", "high", "lead"])),
            }
    return _finish(
        repo, hunt_id, agent_summary, sweep_summary,
        expansion_summary=expansion_summary, owner_token=owner_token,
    )
