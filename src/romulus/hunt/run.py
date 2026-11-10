"""Create and run a hunt end to end: inventory -> sweep -> agent investigation -> result."""
from __future__ import annotations

import logging
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta
from threading import Event, Thread
from time import monotonic

from sqlalchemy.exc import OperationalError

from romulus.agent.investigate import recover_agent_finalization, run_agent_phase, skip_agent_phase
from romulus.agent.provider import agent_readiness, build_provider
from romulus.config import Settings
from romulus.detect import netdef
from romulus.evidence.normalize import NORMALIZER_VERSION
from romulus.hunt.baseline_stage import run_baseline_stage
from romulus.hunt.baseline_writer import DEFAULT_RETAIN_BYTES, run_hunt_segment_writer
from romulus.hunt.expansion import PER_ANCHOR_SOURCE_QUERIES, ExpansionEngine
from romulus.hunt.links import LinkFetcher, is_agent_reach
from romulus.hunt.manifest import build_manifest, inventory_usable, new_hunt_id
from romulus.hunt.packets import PACKET_NORMALIZER, run_packet_stage
from romulus.hunt.pivot import PivotExecutor
from romulus.hunt.site_networks import (
    check_host_addresses,
    contradiction_reason,
    install_for_hunt,
    narrow_direction_negatives,
)
from romulus.hunt.stage import clear_stale_stages
from romulus.hunt.sweep import Sweep
from romulus.site import ensure_site_unchanged, load_site_facts
from romulus.sources.es import ElasticClient
from romulus.sources.models import Window
from romulus.sources.profile import build_profile
from romulus.store.db import digest, make_engine, migrate, utcnow
from romulus.store.repo import Repo, is_lease_lost

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
    site_facts = load_site_facts(s.home)
    if not s.es_index_patterns:
        raise ValueError("no ES_INDEX_PATTERNS configured: nothing to hunt")
    for pat in s.es_index_patterns:
        resolved = client.resolve(pat)
        if not resolved:
            # a configured source that is absent must never become an empty "completed" hunt
            raise ValueError(f"source pattern {pat!r} resolves to no index or data stream; fix the "
                             f"configuration or remove the pattern before hunting")
        for target in resolved:
            options = {"site_facts": site_facts} if target in (site_facts.content.get("zeek") or {}).get("plain_sources", {}) else {}
            prof, _contract = build_profile(client, target, **options)
            profiles[target] = prof.model_dump(mode="json")
            targets.append(target)
    manifest = build_manifest(s, window, original_input or {"start": start.isoformat(), "end": end.isoformat()},
                              style, targets, profiles, hypothesis, ai_agent=ai_agent_entry(s, ai_agent),
                              site_facts=site_facts)
    baseline = manifest["baseline"]
    baseline["store_cut_digest"] = repo.baseline_store_cut_digest(
        site=baseline["site"], targets=targets, specs=baseline["specs"],
        start=window.start - timedelta(days=int(baseline["history_days"])), end=window.start,
    )
    manifest["expansion"] = {
        "enabled": expand, "max_depth": 3, "per_anchor_source_queries": PER_ANCHOR_SOURCE_QUERIES,
        "max_source_queries": s.expansion_max_source_queries, "wall_clock_minutes": s.expansion_wall_clock_minutes,
    }
    from romulus.content.indicator_lists import IndicatorLists
    manifest['indicator_lists'] = IndicatorLists(repo).pin()
    from romulus.content.sigma_store import SigmaRules
    manifest['sigma_rules'] = SigmaRules(repo).pin()
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
    site_facts = ensure_site_unchanged(s.home, manifest.get("site"))
    for target in manifest["targets"]:
        options = {"site_facts": site_facts} if target in (site_facts.content.get("zeek") or {}).get("plain_sources", {}) else {}
        profile, contract = build_profile(client, target, **options)
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


@contextmanager
def _agent_heartbeat(repo: Repo, hunt_id: str, owner_token: str, lease_seconds: int):
    """Renew ownership while a source or model call blocks, without holding a database lock."""
    stopped = Event()
    failures = []
    # The caller claimed or renewed the lease just before entering; ownership is certain until this deadline.
    owned_until = [monotonic() + lease_seconds]

    def heartbeat():
        if failures:
            raise RuntimeError(f"hunt {hunt_id} agent lease ownership lost") from failures[0]
        started = monotonic()
        try:
            repo.heartbeat_agent_lease(hunt_id, lease_seconds, owner_token=owner_token)
        except OperationalError as exc:
            # A busy or locked database is transient: the lease is still ours while a third of it remains,
            # so the next renewal retries. Only a fence failure, or running out of margin, is ownership lost.
            if monotonic() < owned_until[0] - lease_seconds / 3:
                log.warning("hunt %s agent lease renewal deferred: %s", hunt_id, exc)
                return
            failures.append(exc)
            raise
        except Exception as exc:
            failures.append(exc)
            raise
        owned_until[0] = started + lease_seconds

    def renew():
        while not stopped.wait(max(0.01, lease_seconds / 3)):
            try:
                heartbeat()
            except Exception:  # noqa: BLE001 - propagate the renewal failure through the guarded callback.
                return

    worker = Thread(target=renew, name=f"agent-heartbeat-{hunt_id}", daemon=True)
    worker.start()
    try:
        yield heartbeat
    finally:
        stopped.set()
        worker.join()


def _ai_agent_phase(s: Settings, repo: Repo, hunt_id: str, manifest: dict, owner_token: str | None,
                    client: ElasticClient, contracts: dict, requested: bool | None = None,
                    *, resuming: bool = False, previous_run: dict | None = None) -> dict:
    """Keep all agent failures inside its own lease and preserve the completed detection state."""
    try:
        existing = previous_run if previous_run is not None else (repo.agent_run(hunt_id) or {})
        if owner_token is None:
            owner_token = repo.claim_agent_lease(hunt_id, _lease_seconds(s))["lease_owner"]
        with _agent_heartbeat(repo, hunt_id, owner_token, _lease_seconds(s)) as heartbeat:
            heartbeat()
            wanted = (manifest.get("ai_agent") or {}).get("requested", False) if requested is None else requested
            if not wanted:
                return skip_agent_phase(s, repo, hunt_id, "not_requested", owner_token=owner_token).as_dict()
            readiness = None
            try:
                readiness = agent_readiness(s)
                reason = None if readiness.ready else f"provider_not_ready: {readiness.message()}"
            except Exception as exc:  # noqa: BLE001 - provider configuration cannot undo detection completion.
                reason = f"readiness check failed: {type(exc).__name__}: {exc}"[:500]
            if reason:
                if resuming and existing:
                    if (repo.agent_run(hunt_id) or {}).get("state") != existing.get("state"):
                        repo.save_agent_run({"hunt_id": hunt_id, **{key: existing.get(key) for key in (
                            "state", "reason", "prompt_digests", "provider", "started_at", "ended_at")}},
                            owner_token=owner_token)
                    repo.release_agent_lease(hunt_id, owner_token=owner_token)
                    return {"status": existing["state"], "reason": reason, "unworked": []}
                return skip_agent_phase(s, repo, hunt_id, reason,
                                        provider=readiness.provenance(s) if readiness else {},
                                        owner_token=owner_token).as_dict()
            provider = build_provider(s, readiness=readiness)
            from romulus.hunt.agent_tools import build_agent_toolbox
            toolbox_factory = lambda session_id: build_agent_toolbox(
                s, repo, hunt_id, client=client, contracts=contracts, session_id=session_id,
                owner_token=owner_token, heartbeat=heartbeat,
            )
            return run_agent_phase(s, repo, hunt_id, provider=provider, toolbox_factory=toolbox_factory,
                                   owner_token=owner_token, heartbeat=heartbeat).as_dict()
    except Exception as exc:
        if is_lease_lost(exc):
            return {"status": "partial", "reason": "lease_lost", "unworked": []}
        log.exception("AI agent phase failed")
        reason = f"agent_error: {type(exc).__name__}: {exc}"[:500]
        summary = {"status": "failed", "reason": reason, "unworked": []}
        if owner_token is None:
            return summary
        try:
            repo.finalize_agent_run(hunt_id, {"state": "failed", "reason": reason,
                                              "ended_at": utcnow()}, owner_token=owner_token, summary=summary)
        except Exception:
            # An unavailable store cannot record its own failure; an expired owner cannot write at all.
            log.exception("could not persist the agent failure")
        return summary


def _site_network_check(client: ElasticClient, contracts: dict, window: Window, heartbeat) -> dict:
    """Host addresses in the hunt window outside the installed internal-network definition: a warning for the
    sweep summary. A failed check is recorded and never stops the hunt."""
    try:
        result = check_host_addresses(client, contracts, netdef.current(), window, heartbeat=heartbeat)
    except Exception as exc:          # a warning check must never sink the hunt
        log.exception("internal-network check failed")
        return {"definition": netdef.current().summary(), "error": f"{exc}"[:300], "warning": None}
    if result["warning"]:
        log.warning(result["warning"])
    return result


def _detection_result(repo: Repo, hunt_id: str) -> tuple[dict[str, int], str]:
    counts = repo.lane_counts(hunt_id)
    reportable = counts.get("urgent", 0) + counts.get("high", 0)
    result = ("reportable_findings" if reportable else "leads_only" if counts.get("lead") else
              "no_qualifying_observation_in_assessed_scope")
    return counts, result


def _finish(repo: Repo, hunt_id: str, agent_summary: dict, sweep_summary: dict,
            *, stats: dict | None = None, partial_reasons: list[str] | None = None,
            expansion_summary: dict | None = None, packet_summary: dict | None = None,
            baseline_summary: dict | None = None, ai_agent_summary: dict | None = None,
            owner_token: str | None = None, retain_budget_bytes: int | None = None,
            pending_agent_owner_token: str | None = None,
            pending_agent_lease_seconds: int | None = None) -> dict:
    partial_reasons = list(partial_reasons or sweep_summary.get("partial_reasons") or [])
    sweep_complete = bool(sweep_summary.get("complete"))
    missing_summary = not sweep_summary
    packet_status = (packet_summary or {}).get("status")
    packets_incomplete = packet_status in ("partial", "failed")
    baseline_status = (baseline_summary or {}).get("status")
    baseline_failed = bool(
        (baseline_summary or {}).get("stage_failed") or baseline_status == "failed"
    )
    if baseline_failed:
        partial_reasons.append(f"baseline_stage:{baseline_status}")
    if packets_incomplete:
        partial_reasons.append(f"packet_stage:{packet_status}")
    partial = (missing_summary or not sweep_complete or packets_incomplete or baseline_failed
               or (expansion_summary or {}).get("status") in {"partial", "failed"})
    try:
        # The writer decides per hour from each hour's own window cells, so a hunt left partial by another stage still
        # writes the hours whose baseline inputs were complete; whether it is partial decides only how long its window
        # material is kept (for a resume).
        segment_summary = run_hunt_segment_writer(
            repo, hunt_id, hunt_partial=partial,
            baseline_finished=bool((baseline_summary or {}).get("finished")),
            retain_budget_bytes=(DEFAULT_RETAIN_BYTES if retain_budget_bytes is None else retain_budget_bytes),
        )
    except Exception as exc:
        log.exception("hunt-derived baseline segment writer failed")
        segment_summary = {
            "status": "failed", "written": 0, "stale": 0, "max_write_seconds": 0.0,
            "specs": {}, "reason": f"hunt-derived segment writer failed: {exc}"[:300],
        }
        # The writer only stores this hunt's counts for later hunts' baselines. Its failure costs future history,
        # stated in the baseline summary, and changes nothing this hunt evaluated.
    baseline_summary = {**(baseline_summary or {}), "segment_writer": segment_summary}
    repo.audit(
        "system", "hunt.baseline_summary", hunt_id, baseline_summary, owner_token=owner_token,
    )
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
    if baseline_failed:
        reasons.append(f"baseline stage {baseline_status}: source, staging, or execution failure")
    if expansion_summary and expansion_summary.get("stop_reason"):
        reasons.append(f"expansion: {expansion_summary['stop_reason']}")
    # Retain the legacy report projection alongside the richer AI-specific summary.
    repo.audit("system", "hunt.agent_summary", hunt_id, agent_summary, owner_token=owner_token)
    state = "partial" if partial else "completed_within_scope"
    repo.set_hunt_state(
        hunt_id, state, owner_token=owner_token,
        detection_result=result, stop_reason="; ".join(reasons),
        pending_agent_owner_token=pending_agent_owner_token,
        pending_agent_lease_seconds=pending_agent_lease_seconds,
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
        "baseline": baseline_summary or {},
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
    # A hunt recorded before per-anchor shares keeps its fixed total.
    per_anchor = config.get("per_anchor_source_queries")
    executor = PivotExecutor(
        repo, client, hunt["id"], contracts, heartbeat=heartbeat, owner_token=owner_token,
        source_query_budget=max_source_queries,
        dataset_inventory={
            target: set(profile.get("datasets", {}))
            for target, profile in manifest.get("source_profiles", {}).items()
            if inventory_usable(profile)
        },
        site_facts=ensure_site_unchanged(s.home, manifest.get("site")),
    )
    if "wall_clock_minutes" in config:
        # Expansion's own time limit, so a long sweep never leaves it none. A resumed expansion has what earlier runs
        # of it did not spend fetching.
        fetched_ms = sum(int(link["duration_ms"] or 0) for link in repo.expansion_links(hunt["id"])
                         if not is_agent_reach(link["link_type"], link["strength"]))
        budget_seconds = max(0.0, float(config["wall_clock_minutes"]) * 60 - fetched_ms / 1000)
    else:
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
        per_anchor_source_queries=int(per_anchor) if per_anchor is not None else None,
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


def _baseline_stage(repo: Repo, client: ElasticClient, hunt: dict, window: Window,
                    contracts: dict, heartbeat, owner_token: str | None,
                    carry_budget_bytes: int | None = None) -> dict:
    """Run or resume the baseline stage; a crash is an explicit partial result, not a hunt stopper."""
    hunt_id = hunt["id"]
    try:
        summary = run_baseline_stage(
            repo, hunt_id, window, client=client, contracts=contracts,
            heartbeat=heartbeat, owner_token=owner_token,
            **({} if carry_budget_bytes is None else {"carry_budget_bytes": carry_budget_bytes}),
        )
    except Exception as exc:
        log.exception("baseline stage failed")
        summary = {"status": "failed", "finished": False, "stage_failed": True, "error": str(exc)[:300],
                   "snapshot_digest": (repo.baseline_snapshot(hunt_id) or {}).get("digest")}
        for item in (hunt["manifest"].get("baseline") or {}).get("specs") or []:
            repo.set_rule_cell(
                hunt_id, item["id"], item["version"], "*", "window", "evaluated_partial", 0, 0,
                {"reasons": [f"baseline stage failed: {exc}"[:300]]}, owner_token=owner_token,
            )
    repo.audit("system", "hunt.baseline_summary", hunt_id, summary, owner_token=owner_token)
    return summary


def run_hunt(s: Settings, hunt_id: str, on_candidate=None, expand: bool | None = None,
             claimed_owner: str | None = None) -> dict:
    repo = open_repo(s)
    hunt = repo.get_hunt(hunt_id)
    if hunt is None:
        raise KeyError(hunt_id)
    initial_manifest = hunt["manifest"]
    site_facts = ensure_site_unchanged(s.home, initial_manifest.get("site"))
    if expand is not None and bool((initial_manifest.get("expansion") or {}).get("enabled", True)) != expand:
        raise ValueError("expansion mode is immutable after hunt creation")
    # the hunt's internal-network definition, installed once before the sweep
    install_for_hunt(s, hunt_id, initial_manifest)
    if claimed_owner is None:
        claimed = repo.claim_hunt(hunt_id, _lease_seconds(s))
    else:
        if hunt["execution_state"] != "running" or hunt["lease_owner"] != claimed_owner:
            raise RuntimeError("hunt start ownership changed before execution")
        repo.heartbeat_hunt(hunt_id, _lease_seconds(s), owner_token=claimed_owner)
        claimed = hunt
    owner_token = claimed["lease_owner"]
    h = repo.get_hunt(hunt_id)
    m = h["manifest"]
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

    stage_dir = s.stage_path
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
    site_check = _site_network_check(client, contracts, window, heartbeat)
    contradiction = contradiction_reason(site_check)
    if contradiction:
        # the hunt's own hosts contradict the definition (or it could not be checked): no direction-dependent
        # rule may keep a complete negative, and the hunt says why it is partial
        narrow_direction_negatives(repo, hunt_id, contradiction, owner_token=owner_token)
        sweep.partial_reasons.append(contradiction)
    sweep_summary = {
        "finished": True,
        "complete": not sweep.partial_reasons,
        "partial_reasons": sweep.partial_reasons,
        "stats": sweep.stats,
        "internal_networks": site_check,
    }
    repo.audit(
        "system", "hunt.sweep_summary", hunt_id, sweep_summary, owner_token=owner_token,
    )
    # packet findings first, so they can anchor expansion like any sweep finding
    packet_summary = _packet_stage(s, repo, client, hunt_id, window, contracts, heartbeat, owner_token)
    baseline_summary = _baseline_stage(
        repo, client, repo.get_hunt(hunt_id), window, contracts, heartbeat, owner_token,
        int(s.baseline_carry_disk_gb * 1e9),
    )
    expansion_summary = _run_expansion_safely(
        s, repo, client, repo.get_hunt(hunt_id), contracts, window, owner_token,
    )
    agent_owner = uuid.uuid4().hex
    result = _finish(
        repo, hunt_id, {"status": "disabled", "mode": "off"}, sweep_summary,
        stats=sweep.stats, partial_reasons=sweep.partial_reasons,
        expansion_summary=expansion_summary, packet_summary=packet_summary,
        baseline_summary=baseline_summary,
        owner_token=owner_token, pending_agent_owner_token=agent_owner,
        pending_agent_lease_seconds=_lease_seconds(s),
        retain_budget_bytes=int(s.baseline_retain_disk_gb * 1e9),
    )
    return _with_agent_result(result, repo, _ai_agent_phase(s, repo, hunt_id, m, agent_owner, client, contracts))


def _with_agent_result(result: dict, repo: Repo, summary: dict) -> dict:
    """Return the result refreshed by the agent's atomic finalization without changing detection completion."""
    combined = {**result, "ai_agent": summary,
                "agent": {"status": summary.get("status", "unknown"), "stop_reason": summary.get("reason")}}
    try:
        stored = repo.get_hunt(result["hunt_id"])
        combined.update(lanes=repo.lane_counts(result["hunt_id"]), detection_result=stored["detection_result"])
    except Exception:
        log.exception("could not read the refreshed agent result")
    return combined


def resume_hunt(s: Settings, hunt_id: str) -> dict:
    """Resume persisted agent work without repeating a completed deterministic hunt."""
    repo = open_repo(s)
    hunt = repo.get_hunt(hunt_id)
    if hunt is None:
        raise KeyError(hunt_id)
    sweep_audit = repo.latest_audit(hunt_id, "hunt.sweep_summary")
    sweep_summary = dict(sweep_audit["detail"]) if sweep_audit else {}
    if hunt["execution_state"] == "running" and not sweep_summary.get("finished", sweep_summary.get("complete")):
        # The worker stopped without reaching any end transition (killed, out of memory, host reboot). Once its
        # lease has expired, end the hunt as failed so its whole-window cells stop claiming a complete answer;
        # a live lease refuses the claim and nothing changes. Ending it needs no source, site or normalizer, so
        # this comes before the checks that a resumed sweep would need.
        stale = repo.claim_hunt(hunt_id, _lease_seconds(s), resume=True)
        repo.audit("system", "hunt.sweep_summary", hunt_id, {
            "finished": False, "complete": False, "partial_reasons": [], "stats": sweep_summary.get("stats") or {},
            "error": "the hunt's worker stopped before its sweep finished",
        }, owner_token=stale["lease_owner"])
        repo.set_hunt_state(hunt_id, "failed", owner_token=stale["lease_owner"],
                            stop_reason="the hunt's worker stopped before its sweep finished")
        raise RuntimeError("running hunt cannot resume because the sweep did not finish; it is now marked failed")
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
    # expansion and the investigator read the definition the sweep used; a changed one is refused here
    install_for_hunt(s, hunt_id, recorded_manifest)
    if sweep_summary and not sweep_summary.get("finished"):
        raise RuntimeError("hunt cannot resume agent work because the sweep did not finish")
    if hunt["execution_state"] == "failed" and not sweep_summary.get("finished"):
        raise RuntimeError("failed hunt cannot resume because the sweep did not finish")
    agent_run = repo.agent_run(hunt_id) or {}
    agent_reason = str(agent_run.get("reason") or "")
    resumable_agent = (
        agent_run.get("state") in {"pending", "running"}
        or (agent_run.get("state") == "partial" and
            any(reason in agent_reason for reason in ("provider_unavailable", "interrupted")))
    )
    agent_only = hunt["execution_state"] == "completed_within_scope" and resumable_agent
    if hunt["execution_state"] == "completed_within_scope" and not agent_only:
        raise ValueError(f"hunt {hunt_id} has no resumable agent phase")
    claimed = (repo.claim_agent_lease(hunt_id, _lease_seconds(s)) if agent_only else
               repo.claim_hunt(hunt_id, _lease_seconds(s), resume=True))
    owner_token = claimed["lease_owner"]
    hunt = repo.get_hunt(hunt_id)
    manifest = hunt["manifest"]
    if agent_only:
        base_result = {"hunt_id": hunt_id, "execution_state": hunt["execution_state"],
                       "stats": sweep_summary.get("stats") or {}, "lanes": repo.lane_counts(hunt_id),
                       "detection_result": hunt.get("detection_result"), "baseline": {}, "expansion": {}}
        try:
            with _agent_heartbeat(repo, hunt_id, owner_token, _lease_seconds(s)):
                recovered = recover_agent_finalization(repo, hunt_id, owner_token=owner_token)
            if recovered is not None:
                return _with_agent_result(base_result, repo, recovered.as_dict())
        except Exception as exc:  # noqa: BLE001 - recovery errors stay inside the independent agent phase.
            reason = "lease_lost" if is_lease_lost(exc) else f"agent_error: {type(exc).__name__}"
            summary = {"status": "partial" if is_lease_lost(exc) else "failed", "reason": reason}
            if not is_lease_lost(exc):
                try:
                    repo.finalize_agent_run(hunt_id, {"state": "failed", "reason": reason},
                                            owner_token=owner_token, summary=summary)
                except Exception:
                    log.exception("could not record local agent recovery failure")
            return {**base_result, "agent": summary, "ai_agent": summary}
    window = Window(
        start=datetime.fromisoformat(manifest["window"]["start"]),
        end=datetime.fromisoformat(manifest["window"]["end"]),
    )
    client = ElasticClient(s)
    try:
        if agent_only:
            with _agent_heartbeat(repo, hunt_id, owner_token, _lease_seconds(s)):
                contracts = _contracts(s, repo, {**hunt, "_resume_scope_check": True}, client, owner_token)
        else:
            contracts = _contracts(s, repo, {**hunt, "_resume_scope_check": True}, client, owner_token)
    except Exception as exc:
        if agent_only:
            reason = "lease_lost" if is_lease_lost(exc) else f"provider_not_ready: source preflight failed: {exc}"[:500]
            ai_agent_summary = {"status": agent_run.get("state", "partial"), "reason": reason}
            try:
                repo.release_agent_lease(hunt_id, owner_token=owner_token)
            except Exception:
                log.exception("could not release the unavailable agent's lease")
            return {"hunt_id": hunt_id, "execution_state": hunt["execution_state"],
                    "stats": sweep_summary.get("stats") or {}, "lanes": repo.lane_counts(hunt_id),
                    "detection_result": hunt.get("detection_result"), "agent": ai_agent_summary,
                    "ai_agent": ai_agent_summary, "baseline": {}, "expansion": {}}
        stop_reason = f"source preflight error: {exc}"
        repo.set_hunt_state(
            hunt_id, "failed", owner_token=owner_token, stop_reason=stop_reason,
        )
        raise
    if agent_only:
        ai_agent_summary = _ai_agent_phase(s, repo, hunt_id, manifest, owner_token, client, contracts, resuming=True)
        return _with_agent_result({"hunt_id": hunt_id, "execution_state": hunt["execution_state"],
                "stats": sweep_summary.get("stats") or {}, "lanes": repo.lane_counts(hunt_id),
                "detection_result": hunt.get("detection_result"), "agent": ai_agent_summary,
                "ai_agent": ai_agent_summary, "baseline": {}, "expansion": {}}, repo, ai_agent_summary)
    packet_audit = repo.latest_audit(hunt_id, "hunt.packet_summary")
    packet_summary = dict(packet_audit["detail"]) if packet_audit else {}
    if not packet_summary.get("finished"):

        def heartbeat():
            repo.heartbeat_hunt(hunt_id, _lease_seconds(s), owner_token=owner_token)

        packet_summary = _packet_stage(s, repo, client, hunt_id, window, contracts, heartbeat, owner_token)
    baseline_audit = repo.latest_audit(hunt_id, "hunt.baseline_summary")
    baseline_summary = dict(baseline_audit["detail"]) if baseline_audit else {}
    if not baseline_summary.get("finished"):

        def heartbeat():
            repo.heartbeat_hunt(hunt_id, _lease_seconds(s), owner_token=owner_token)

        baseline_summary = _baseline_stage(
            repo, client, hunt, window, contracts, heartbeat, owner_token,
            int(s.baseline_carry_disk_gb * 1e9),
        )
    expansion_summary = _run_expansion_safely(
        s, repo, client, hunt, contracts, window, owner_token,
    )
    agent_owner = uuid.uuid4().hex
    result = _finish(
        repo, hunt_id, {"status": "disabled", "mode": "off"}, sweep_summary,
        expansion_summary=expansion_summary, packet_summary=packet_summary,
        baseline_summary=baseline_summary,
        owner_token=owner_token, pending_agent_owner_token=agent_owner,
        pending_agent_lease_seconds=_lease_seconds(s),
        retain_budget_bytes=int(s.baseline_retain_disk_gb * 1e9),
    )
    return _with_agent_result(result, repo, _ai_agent_phase(
        s, repo, hunt_id, manifest, agent_owner, client, contracts, resuming=True, previous_run=agent_run))
