"""Create and run a hunt end to end: inventory -> sweep -> agent investigation -> result."""
from __future__ import annotations

import logging
from datetime import datetime

from romulus.agent.controller import Investigator
from romulus.agent.provider import agent_readiness
from romulus.config import Settings
from romulus.evidence.normalize import NORMALIZER_VERSION
from romulus.hunt.expansion import ExpansionEngine
from romulus.hunt.links import LinkFetcher, is_agent_reach
from romulus.hunt.manifest import build_manifest, new_hunt_id
from romulus.hunt.packets import PACKET_NORMALIZER, run_packet_stage
from romulus.hunt.pivot import PivotExecutor
from romulus.hunt.stage import clear_stale_stages
from romulus.hunt.sweep import Sweep
from romulus.site import ensure_site_unchanged, load_site_facts
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


def ai_agent_entry(s: Settings, requested: bool | None = None) -> dict:
    """The manifest's record of the AI agent: whether this hunt asked for it, and its provider readiness."""
    wanted = (s.agent_default == "on") if requested is None else requested
    try:
        readiness = agent_readiness(s)
    except Exception as exc:      # the agent's configuration must never stop a deterministic hunt
        log.exception("agent readiness failed")
        return {"requested": wanted, "state": "blocked", "reason": f"readiness check failed: {exc}"[:300]}
    return {"requested": wanted, **readiness.provenance(s)}


def create_hunt(s: Settings, start: datetime, end: datetime, created_by: str, style: str = "broad",
                hypothesis: str = "", original_input: dict | None = None, expand: bool = True,
                ai_agent: bool | None = None) -> str:
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
    site_facts = load_site_facts(s.home)
    manifest = build_manifest(s, window, original_input or {"start": start.isoformat(), "end": end.isoformat()},
                              style, targets, profiles, hypothesis, ai_agent=ai_agent_entry(s, ai_agent),
                              site_facts=site_facts)
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
        if hunt.get("_resume_scope_check") and recorded and (
            recorded.get("role") not in (None, profile.role)
            or recorded.get("os_family") not in (None, contract.os_family)
        ):
            raise RuntimeError(
                f"source role/OS changed for {target}: manifest "
                f"{recorded.get('role')}/{recorded.get('os_family')}, now "
                f"{profile.role}/{contract.os_family}; start a new hunt instead of resuming"
            )
        if recorded and profile.id != recorded["id"]:
            repo.audit("system", "source_profile_changed", hunt_id, {
                "target": target, "now": profile.id, "manifest": recorded["id"],
            }, owner_token=owner_token)
        contracts[target] = contract
    return contracts


def _ai_agent_phase(s: Settings, repo: Repo, hunt_id: str, manifest: dict, owner_token: str | None,
                    requested: bool | None = None) -> dict:
    """Record what the AI agent phase did. It never changes detection results, lanes, coverage or the hunt's
    execution state: with the agent absent, refused or failing, the deterministic findings stand as they are."""
    entry = manifest.get("ai_agent") or {}
    wanted = entry.get("requested", False) if requested is None else requested
    try:
        readiness = agent_readiness(s)
    except Exception as exc:      # never leave a finished deterministic hunt unfinished
        log.exception("agent readiness failed")
        summary = {"status": "blocked", "reason": f"agent readiness check failed: {exc}"[:300], "model_calls": 0}
        repo.audit("system", "hunt.ai_agent_summary", hunt_id, summary, owner_token=owner_token)
        return summary
    base = {"provider": readiness.provider, "model": readiness.model,
            "endpoint_host": readiness.decision.host if readiness.decision else None,
            "egress": readiness.decision.egress if readiness.decision else None, "model_calls": 0}
    if not wanted:
        summary = {**base, "status": "disabled", "reason": "the AI agent was not requested for this hunt"}
    elif readiness.state == "not_configured":
        summary = {**base, "status": "not_configured", "reason": readiness.message()}
    elif readiness.state == "blocked":
        summary = {**base, "status": "blocked", "reason": readiness.message()}
    else:
        summary = {**base, "status": "not_run",
                   "reason": "the AI agent phase is not available in this build; the provider is ready"}
    repo.audit("system", "hunt.ai_agent_summary", hunt_id, summary, owner_token=owner_token)
    return summary


def _detection_result(repo: Repo, hunt_id: str) -> tuple[dict[str, int], str]:
    counts = repo.lane_counts(hunt_id)
    reportable = counts.get("urgent", 0) + counts.get("high", 0)
    result = ("reportable_findings" if reportable else "leads_only" if counts.get("lead") else
              "no_qualifying_observation_in_assessed_scope")
    return counts, result


def _finish(repo: Repo, hunt_id: str, agent_summary: dict, sweep_summary: dict,
            *, stats: dict | None = None, partial_reasons: list[str] | None = None,
            expansion_summary: dict | None = None, packet_summary: dict | None = None,
            ai_agent_summary: dict | None = None, owner_token: str | None = None) -> dict:
    partial_reasons = list(partial_reasons or sweep_summary.get("partial_reasons") or [])
    sweep_complete = bool(sweep_summary.get("complete"))
    missing_summary = not sweep_summary
    agent_status = agent_summary.get("status")
    packet_status = (packet_summary or {}).get("status")
    packets_incomplete = packet_status in ("partial", "failed")
    if packets_incomplete:
        partial_reasons.append(f"packet_stage:{packet_status}")
    partial = (missing_summary or not sweep_complete or agent_status == "unavailable" or packets_incomplete
               or (expansion_summary or {}).get("status") in {"partial", "failed"})
    counts, result = _detection_result(repo, hunt_id)
    reasons = partial_reasons[:10]
    if missing_summary:
        reasons.append("sweep summary missing; coverage remains conservatively partial")
    elif sweep_complete:
        reasons.append("frontier complete")
    else:
        reasons.append("sweep coverage partial")
    if packets_incomplete:
        detail = (packet_summary.get("partial_reasons") or [packet_summary.get("error") or ""])[0]
        reasons.append(f"packet stage {packet_status}: {detail}"[:200])
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
        "ai_agent": ai_agent_summary or {},
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

    max_source_queries = int(config.get("max_source_queries", 180))
    executor = PivotExecutor(
        repo, client, hunt["id"], contracts, heartbeat=heartbeat, owner_token=owner_token,
        source_query_budget=max_source_queries,
        dataset_inventory={
            target: set(profile.get("datasets", {}))
            for target, profile in manifest.get("source_profiles", {}).items()
        },
        site_facts=ensure_site_unchanged(s.home, manifest.get("site")),
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
        max_source_queries=max_source_queries,
        wall_clock_seconds=budget_seconds, owner_token=owner_token, heartbeat=heartbeat,
    ).run()


def _run_expansion_safely(
    s: Settings, repo: Repo, client: ElasticClient, hunt: dict, contracts: dict,
    window: Window, owner_token: str,
) -> dict:
    try:
        return _run_expansion(s, repo, client, hunt, contracts, window, owner_token)
    except Exception as exc:
        log.exception("expansion failed")
        linked = {
            link["anchor_id"] for link in repo.expansion_links(hunt["id"])
            if not is_agent_reach(link["link_type"], link["strength"])
        }
        for anchor in repo.expansion_anchors(hunt["id"]):
            if anchor["status"] == "pending":
                # an anchor some of whose links ran was partly expanded, not unexpanded
                repo.update_expansion_anchor(
                    anchor["id"], "expanded_partial" if anchor["id"] in linked else "unexpanded",
                    ["expansion error"], owner_token=owner_token,
                )
        summary = {
            "status": "failed", "stop_reason": f"expansion error: {exc}",
            "error": str(exc),
            "unexpanded": [
                anchor["id"] for anchor in repo.expansion_anchors(hunt["id"])
                if anchor["status"] == "unexpanded"
            ],
        }
        repo.audit(
            "system", "hunt.expansion_summary", hunt["id"], summary, owner_token=owner_token,
        )
        return summary


def _packet_stage(s: Settings, repo: Repo, client: ElasticClient, hunt_id: str, window: Window,
                  contracts: dict, heartbeat, owner_token: str | None) -> dict:
    """Run the packet stage and record its summary. `finished` marks a stage that ran to its end (complete or
    partial); a resume re-runs a stage that has no finished summary."""
    try:
        summary = run_packet_stage(s, repo, client, hunt_id, window, contracts, heartbeat,
                                   owner_token=owner_token)
    except Exception as exc:          # packet evidence enriches; it must never sink the hunt
        log.exception("packet stage failed")
        summary = {"status": "failed", "finished": False, "error": str(exc)[:300]}
    repo.audit("system", "hunt.packet_summary", hunt_id, summary, owner_token=owner_token)
    return summary


def _run_investigator(s: Settings, repo: Repo, client: ElasticClient, hunt_id: str,
                      contracts: dict, window: Window, owner_token: str,
                      agent_mode: str) -> dict:
    def heartbeat():
        repo.heartbeat_hunt(hunt_id, _lease_seconds(s), owner_token=owner_token)

    hunt = repo.get_hunt(hunt_id)
    executor = PivotExecutor(
        repo, client, hunt_id, contracts, heartbeat=heartbeat, owner_token=owner_token,
        dataset_inventory={
            target: set(profile.get("datasets", {}))
            for target, profile in hunt["manifest"].get("source_profiles", {}).items()
        },
        site_facts=ensure_site_unchanged(s.home, hunt["manifest"].get("site")),
    )

    return Investigator(
        s, repo, executor, hunt_id, window, heartbeat=heartbeat, owner_token=owner_token,
        agent_mode=agent_mode,
    ).run()


def run_hunt(s: Settings, hunt_id: str, agent: bool | None = None, on_candidate=None,
             agent_mode: str | None = None, expand: bool | None = None, ai_agent: bool | None = None) -> dict:
    repo = open_repo(s)
    hunt = repo.get_hunt(hunt_id)
    if hunt is None:
        raise KeyError(hunt_id)
    initial_manifest = hunt["manifest"]
    site_facts = ensure_site_unchanged(s.home, initial_manifest.get("site"))
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
        site_facts=site_facts,
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
    # packet findings first, so they can anchor expansion like any sweep finding
    packet_summary = _packet_stage(s, repo, client, hunt_id, window, contracts, heartbeat, owner_token)
    expansion_summary = _run_expansion_safely(
        s, repo, client, repo.get_hunt(hunt_id), contracts, window, owner_token,
    )
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
    ai_agent_summary = _ai_agent_phase(s, repo, hunt_id, m, owner_token, ai_agent)
    return _finish(
        repo, hunt_id, agent_summary, sweep_summary,
        stats=sweep.stats, partial_reasons=sweep.partial_reasons,
        expansion_summary=expansion_summary, packet_summary=packet_summary,
        ai_agent_summary=ai_agent_summary, owner_token=owner_token,
    )


def resume_hunt(s: Settings, hunt_id: str, agent_mode: str | None = None, ai_agent: bool | None = None) -> dict:
    """Resume only persisted investigator work; the deterministic sweep is never re-run."""
    repo = open_repo(s)
    hunt = repo.get_hunt(hunt_id)
    if hunt is None:
        raise KeyError(hunt_id)
    recorded_manifest = hunt.get("manifest") or {}
    ensure_site_unchanged(s.home, recorded_manifest.get("site"))
    recorded = recorded_manifest.get("normalizer")
    packets_recorded = recorded_manifest.get("packet_normalizer")
    if packets_recorded and packets_recorded != PACKET_NORMALIZER:
        raise RuntimeError(f"hunt {hunt_id} rebuilt packets with {packets_recorded}; this build is {PACKET_NORMALIZER}. "
                           "Start a new hunt over the same window instead of resuming.")
    if recorded and recorded != NORMALIZER_VERSION:
        # Its sweep evidence has the old event ids; new fetches would get new ones, so a record could be both
        # the anchor and its own "linked" activity. Start a new hunt instead.
        raise RuntimeError(f"hunt {hunt_id} was normalized with {recorded}; this build is {NORMALIZER_VERSION}. "
                           "Start a new hunt over the same window instead of resuming.")
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
        contracts = _contracts(s, repo, {**hunt, "_resume_scope_check": True}, client, owner_token)
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
    packet_audit = repo.latest_audit(hunt_id, "hunt.packet_summary")
    packet_summary = dict(packet_audit["detail"]) if packet_audit else {}
    if not packet_summary.get("finished"):

        def heartbeat():
            repo.heartbeat_hunt(hunt_id, _lease_seconds(s), owner_token=owner_token)

        packet_summary = _packet_stage(s, repo, client, hunt_id, window, contracts, heartbeat, owner_token)
    expansion_summary = _run_expansion_safely(
        s, repo, client, hunt, contracts, window, owner_token,
    )
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
    ai_agent_summary = _ai_agent_phase(s, repo, hunt_id, manifest, owner_token, ai_agent)
    return _finish(
        repo, hunt_id, agent_summary, sweep_summary,
        expansion_summary=expansion_summary, packet_summary=packet_summary,
        ai_agent_summary=ai_agent_summary, owner_token=owner_token,
    )
