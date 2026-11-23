"""Create and run a hunt end to end: inventory -> sweep -> agent investigation -> result."""
from __future__ import annotations

import logging
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta
from threading import Event, Thread
from time import monotonic

from sqlalchemy.exc import OperationalError

from romulus.agent import hunt_budget
from romulus.agent.investigate import (
    STOPPED_REASON,
    continuation_plan,
    recover_agent_finalization,
    run_agent_phase,
    skip_agent_phase,
    stop_agent_phase,
)
from romulus.agent.provider import AgentReadiness, BudgetLimits, agent_readiness, build_provider
from romulus.config import Settings
from romulus.detect import netdef
from romulus.evidence.normalize import NORMALIZER_VERSION
from romulus.hunt.baseline_stage import run_baseline_stage
from romulus.hunt.baseline_writer import DEFAULT_RETAIN_BYTES, run_hunt_segment_writer
from romulus.hunt.controls import HuntStopped, StopWatch
from romulus.hunt.expansion import PER_ANCHOR_SOURCE_QUERIES, ExpansionEngine
from romulus.hunt.links import LinkFetcher, is_agent_reach
from romulus.hunt.manifest import build_manifest, inventory_usable, new_hunt_id, normalizer_versions
from romulus.hunt.net_join_pass import finished as join_finished
from romulus.hunt.net_join_pass import mark_not_run as mark_join_not_run
from romulus.hunt.net_join_pass import prune_rows as prune_join_rows
from romulus.hunt.net_join_pass import run_join_pass
from romulus.hunt.packets import PACKET_NORMALIZER, run_packet_stage
from romulus.hunt.pivot import PivotExecutor
from romulus.hunt.rank import PASS_BEFORE_EXPANSION, PASS_FINAL, run_rank_pass
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
from romulus.sources.network_coverage import check_network_addresses, unknown_coverage
from romulus.sources.packets import arkime_expression_fields
from romulus.sources.profile import build_profile
from romulus.store.db import digest, make_engine, migrate, utcnow
from romulus.store.repo import AGENT_MODEL_FORCED, Repo, is_lease_lost

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


def network_coverage_entry(client, contracts: dict, definition: netdef.SiteNetworks, window: Window) -> dict:
    """The manifest's record of how the observed network addresses sit against the internal networks."""
    try:
        return check_network_addresses(client, contracts, definition, window)
    except Exception as exc:      # a configuration diagnostic must never stop a hunt: it is recorded as unknown
        log.exception("network-address coverage check failed")
        return unknown_coverage(window, f"the network-address coverage check failed ({type(exc).__name__})")


def create_hunt(s: Settings, start: datetime, end: datetime, created_by: str, style: str = "broad",
                hypothesis: str = "", original_input: dict | None = None, expand: bool = True,
                ai_agent: bool | None = None, agent_budget: dict | None = None) -> str:
    """Create a hunt. `agent_budget` is the agent budget chosen for it (romulus.agent.hunt_budget.choose, checked
    against the requester's role); without one the hunt gets the standard budget. It is pinned in the manifest."""
    repo = open_repo(s)
    if agent_budget is None:
        agent_budget = hunt_budget.choose(s, hunt_budget.DEFAULT_PROFILE, role="analyst", chosen_by=created_by)
    window = Window(start=start, end=end)
    client = ElasticClient(s)
    profiles, targets, contracts = {}, [], {}
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
            contracts[target] = _contract
            targets.append(target)
    manifest = build_manifest(s, window, original_input or {"start": start.isoformat(), "end": end.isoformat()},
                              style, targets, profiles, hypothesis, ai_agent=ai_agent_entry(s, ai_agent),
                              site_facts=site_facts)
    # the agent budget is pinned here: every agent stage and every resume reads it (plus any extension), never the
    # live settings; the provider's prices recorded beside it stay as readiness found them
    recorded = manifest["ai_agent"].get("budgets") or BudgetLimits.from_settings(s).as_dict()
    manifest["ai_agent"]["budgets"] = {**recorded, **hunt_budget.pinned_block(agent_budget)}
    manifest["internal_networks"]["coverage"] = network_coverage_entry(
        client, contracts, netdef.SiteNetworks.from_record(manifest["internal_networks"]), window)
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
    from romulus.content.mention_patterns import load_mention_patterns, pattern_pin
    # the mention pattern set the hunt is created with: its sweep names every file that differs when it runs
    manifest['mention_patterns'] = pattern_pin(load_mention_patterns(settings=s))
    hid = new_hunt_id()
    repo.create_hunt(hid, manifest, digest(manifest), created_by)
    arkime = arkime_profile_fields(s, [target for target in targets
                                       if getattr(contracts[target], "time_field", None) == "firstPacket"])
    for target, p in profiles.items():
        repo.save_profile(hid, {**p, **arkime[target]} if target in arkime else p)
    repo.audit(agent_budget["chosen_by"], "hunt.agent_budget_chosen", hid, {
        "profile": agent_budget["profile"], "overrides": agent_budget["overrides"], "limits": agent_budget["limits"],
        "role": agent_budget["role"], "above_ceiling": agent_budget["above_ceiling"],
        "agent_requested": bool(manifest["ai_agent"].get("requested"))})
    return hid


def arkime_profile_fields(s: Settings, arkime_targets: list[str], transport=None) -> dict[str, dict]:
    """What each Arkime session target's stored profile adds: the viewer's expression fields (read once, from the
    configured viewer, never at the model's request), or a note saying why they are unknown. Nothing when the hunt has
    no Arkime target. The viewer is the one the packet stage reads for the same targets; a viewer that cannot be read
    never stops a hunt."""
    if not arkime_targets:
        return {}
    try:
        fields, problem = arkime_expression_fields(s, transport=transport)
    except Exception as exc:      # a diagnostic read must never stop a hunt: recorded as unknown
        log.exception("Arkime field list read failed")
        fields, problem = [], f"Arkime expression fields unavailable: the read failed ({type(exc).__name__})"
    extra: dict = {"arkime_fields": fields}
    if problem:
        extra["arkime_fields_note"] = problem
    return {target: extra for target in arkime_targets}


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


# How long the agent's budget gate trusts its last read of the hunt's budget extensions.
EXTENSION_CHECK_SECONDS = 15.0


def _limits_refresh(s: Settings, repo: Repo, hunt_id: str, manifest: dict):
    """The agent gate's view of extensions added while it runs: the hunt's model-call limits, read again at most every
    EXTENSION_CHECK_SECONDS (one indexed query)."""
    state = {"at": None}

    def refresh(limits: BudgetLimits) -> BudgetLimits | None:
        now = monotonic()
        if state["at"] is not None and now - state["at"] < EXTENSION_CHECK_SECONDS:
            return None
        state["at"] = now
        return hunt_budget.apply_main(limits, hunt_budget.resolve(repo, hunt_id, manifest, s)["limits"])
    return refresh


def _ai_agent_phase(s: Settings, repo: Repo, hunt_id: str, manifest: dict, owner_token: str | None,
                    client: ElasticClient, contracts: dict, requested: bool | None = None,
                    *, resuming: bool = False, previous_run: dict | None = None, readiness_snapshot=None) -> dict:
    """Keep all agent failures inside its own lease and preserve the completed detection state. The phase runs on the
    hunt's pinned agent budget plus its extensions (`hunt_budget.hunt_settings`), and honours an analyst's stop
    request for the agent or the whole hunt."""
    live_settings = s
    try:
        existing = previous_run if previous_run is not None else (repo.agent_run(hunt_id) or {})
        if owner_token is None:
            owner_token = repo.claim_agent_lease(hunt_id, _lease_seconds(s))["lease_owner"]
        s = hunt_budget.hunt_settings(live_settings, repo, hunt_id, manifest)
        watch = StopWatch(repo, hunt_id, ("hunt", "agent"))
        with _agent_heartbeat(repo, hunt_id, owner_token, _lease_seconds(s)) as heartbeat:
            heartbeat()
            wanted = (manifest.get("ai_agent") or {}).get("requested", False) if requested is None else requested
            if not wanted:
                return skip_agent_phase(s, repo, hunt_id, "not_requested", owner_token=owner_token).as_dict()
            stopped = watch()
            if stopped:
                # stopped before it started: nothing was asked of the model; a resume runs it
                result = stop_agent_phase(s, repo, hunt_id, stopped, owner_token=owner_token).as_dict()
                watch.honor("agent")
                return result
            readiness = None
            try:
                readiness = readiness_snapshot if readiness_snapshot is not None else agent_readiness(s)
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
            # each session reads the hunt's limits again, so an extension added while the phase runs reaches the
            # sessions that start after it
            toolbox_factory = lambda session_id: build_agent_toolbox(
                hunt_budget.hunt_settings(live_settings, repo, hunt_id, manifest), repo, hunt_id, client=client,
                contracts=contracts, session_id=session_id, owner_token=owner_token, heartbeat=heartbeat,
            )
            refresh = _limits_refresh(live_settings, repo, hunt_id, manifest)
            triage = None
            if s.agent_triage == "on":
                from romulus.hunt.triage import run_cited_triage_in_phase, run_triage_in_phase

                def triage(phase_heartbeat, cited=None):
                    # the triage pass under this phase's lease, before the assessment reads its verdicts; with
                    # `cited`, its extension to the groups the assessment's narrative cites without a verdict
                    if cited is not None:
                        return run_cited_triage_in_phase(s, repo, hunt_id, cited, owner_token=owner_token,
                                                         heartbeat=phase_heartbeat, readiness=readiness,
                                                         build=build_provider, stop=watch)
                    return run_triage_in_phase(s, repo, hunt_id, owner_token=owner_token, heartbeat=phase_heartbeat,
                                               readiness=readiness, build=build_provider, stop=watch)
            result = run_agent_phase(s, repo, hunt_id, provider=provider, toolbox_factory=toolbox_factory,
                                     owner_token=owner_token, heartbeat=heartbeat, triage=triage, stop=watch,
                                     refresh=refresh).as_dict()
            if STOPPED_REASON in str(result.get("reason") or ""):
                watch.honor("agent")
            return result
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
    """The hunt's headline result: the store's one rule (the final ranking when complete, else the lanes), which the
    agent phase's finalization applies again."""
    return repo.lane_counts(hunt_id), repo.detection_result(hunt_id)[1]


def _finish(repo: Repo, hunt_id: str, agent_summary: dict, sweep_summary: dict,
            *, stats: dict | None = None, partial_reasons: list[str] | None = None,
            expansion_summary: dict | None = None, packet_summary: dict | None = None,
            baseline_summary: dict | None = None, ai_agent_summary: dict | None = None,
            owner_token: str | None = None, retain_budget_bytes: int | None = None,
            pending_agent_owner_token: str | None = None,
            pending_agent_lease_seconds: int | None = None, stopped: dict | None = None) -> dict:
    """End the deterministic run. `stopped` ({"detail", "stage", "not_run"}) is an analyst's stop the run honoured
    after its sweep: the hunt is partial, and its stop reason names the stages that did not run."""
    partial_reasons = list(partial_reasons or sweep_summary.get("partial_reasons") or [])
    if stopped:
        partial_reasons.insert(0, stopped_text(stopped))
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
               or (expansion_summary or {}).get("status") in {"partial", "failed"} or bool(stopped))
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
        **({"stopped": stopped} if stopped else {}),
    }


def stopped_text(stopped: dict) -> str:
    """How a stop after the sweep reads in the hunt's stop reason and report."""
    not_run = list(stopped.get("not_run", [])) or ["nothing further"]
    return (f"stopped by analyst ({stopped['detail']}) at the {stopped['stage']}: not run: {', '.join(not_run)}; "
            "these results are partial, and resuming the hunt runs what did not run")


def _stopped_in_sweep(repo: Repo, hunt_id: str, sweep, targets: list[str], started: list[str], stop: HuntStopped,
                      watch: StopWatch, owner_token: str) -> dict:
    """End a hunt an analyst stopped during its sweep: keep every finding it stored, finalize nothing (an aggregate
    over part of the window could report what the rest would contradict), and leave it partial and resumable. Its
    sweep summary says the sweep did not finish and why; ending the hunt narrows every whole-window answer. The
    mention pool of the partitions read is kept too, its coverage partial for the stop."""
    try:
        sweep.publish_mentions(stopped=f"stopped by analyst ({stop.detail})")
    except Exception as exc:  # noqa: BLE001 - the stop must end the hunt even when the pool cannot be stored
        sweep.stats["mentions"] = {"status": "not_scanned", "reasons": [f"the mention pool was not stored: {exc}"]}
    sweep.close_stage()
    current = started[-1] if started else None
    not_started = [target for target in targets if target not in started]
    reason = (f"stopped by analyst ({stop.detail}) during the sweep" + (f" of {current}" if current else "")
              + ": partitions not yet read stay planned and were not evaluated"
              + (f"; sources not started: {', '.join(not_started)}" if not_started else "")
              + "; no whole-window answer is complete, and the stages after the sweep (packet, baseline, expansion "
                "and any AI agent) did not run. Resuming the hunt runs the sweep again")
    summary = {"finished": False, "complete": False, "partial_reasons": [*sweep.partial_reasons, reason],
               "stats": sweep.stats, "stopped": {"detail": stop.detail, "stage": "sweep", "target": current,
                                                 "not_started": not_started}}
    repo.audit("system", "hunt.sweep_summary", hunt_id, summary, owner_token=owner_token)
    counts, result = _detection_result(repo, hunt_id)
    repo.set_hunt_state(hunt_id, "partial", owner_token=owner_token, detection_result=result, stop_reason=reason)
    watch.honor("sweep")
    repo.honor_open_stops(hunt_id, "sweep")       # an agent stop too: the agent does not run
    return {"hunt_id": hunt_id, "execution_state": "partial", "stats": sweep.stats, "lanes": counts,
            "detection_result": result, "partial_reasons": summary["partial_reasons"], "stopped": summary["stopped"],
            "agent": {"status": "not_run", "stop_reason": reason},
            "ai_agent": {"status": "not_run", "reason": STOPPED_REASON}, "baseline": {}, "expansion": {}}


def _stages_after_sweep(s: Settings, repo: Repo, client: ElasticClient, hunt_id: str, window: Window,
                        contracts: dict, owner_token: str, watch: StopWatch, *, packet_summary: dict | None = None,
                        baseline_summary: dict | None = None) -> tuple[dict | None, dict | None, dict, dict | None]:
    """The packet and baseline stages (each unless its summary says it finished), the ranking passes and expansion,
    stopping before the next stage, or before the next expansion link, when an analyst asks the hunt to stop. Returns
    (packet, baseline, expansion summaries, the stop or None); a stage the stop kept from running records no summary,
    so a resume runs it."""

    def heartbeat():
        repo.heartbeat_hunt(hunt_id, _lease_seconds(s), owner_token=owner_token)

    stop: dict | None = None
    not_run: list[str] = []

    def stopping(stage: str) -> bool:
        nonlocal stop
        if stop is None:
            detail = watch()
            if detail:
                stop = {"detail": detail, "stage": stage}
        if stop is not None:
            not_run.append(stage)
        return stop is not None

    # packet findings first, so they can anchor expansion like any sweep finding
    if not (packet_summary or {}).get("finished") and not stopping("packet stage"):
        packet_summary = _packet_stage(s, repo, client, hunt_id, window, contracts, heartbeat, owner_token)
    if not (baseline_summary or {}).get("finished") and not stopping("baseline stage"):
        baseline_summary = _baseline_stage(
            repo, client, repo.get_hunt(hunt_id), window, contracts, heartbeat, owner_token,
            int(s.baseline_carry_disk_gb * 1e9),
        )
    # the network-to-host join over the findings the packet and baseline stages published, from the sweep's kept rows
    if not join_finished(repo, hunt_id) and not stopping(JOIN_STAGE):
        _join_pass(s, repo, client, hunt_id, heartbeat, owner_token)
    # A resumed hunt ranks again over what is stored; each pass replaces its previous rows, so this is idempotent.
    run_rank_pass(repo, hunt_id, PASS_BEFORE_EXPANSION, owner_token=owner_token, heartbeat=heartbeat)
    if stopping("expansion"):
        expansion_summary = {"status": "not_run", "stop_reason": "not run: stopped by analyst"}
    else:
        expansion_summary = _run_expansion_safely(s, repo, client, repo.get_hunt(hunt_id), contracts, window,
                                                  owner_token, stop_check=watch)
        if expansion_summary.get("stopped") and stop is None:
            stop = {"detail": expansion_summary["stopped"], "stage": "expansion"}
    run_rank_pass(repo, hunt_id, PASS_FINAL, owner_token=owner_token, heartbeat=heartbeat)
    if stop is not None:
        if ((repo.get_hunt(hunt_id) or {}).get("manifest") or {}).get("ai_agent", {}).get("requested"):
            not_run.append("AI agent")
        stop["not_run"] = not_run
        mark_unrun_stages(repo, hunt_id, "not run: stopped by analyst", not_run=not_run, owner_token=owner_token)
    return packet_summary, baseline_summary, expansion_summary, stop


JOIN_STAGE = "network-host join"


def _join_pass(s: Settings, repo: Repo, client: ElasticClient, hunt_id: str, heartbeat, owner_token: str) -> dict:
    """The join's pass after the packet and baseline stages. A failure leaves its summary unfinished (a resume runs
    it again) and the join's window cell partial, naming the error; the hunt goes on."""
    try:
        return run_join_pass(repo, client, hunt_id, s.stage_path, owner_token=owner_token, heartbeat=heartbeat)
    except Exception as exc:
        log.exception("network-host join pass failed")
        summary = {"finished": False, "complete": False, "error": str(exc)[:300]}
        mark_join_not_run(repo, hunt_id, f"failed: {exc}"[:300], owner_token=owner_token)
        repo.audit("system", "hunt.join_summary", hunt_id, summary, owner_token=owner_token)
        return summary


def mark_unrun_stages(repo: Repo, hunt_id: str, reason: str, *, not_run: list[str] | None = None,
                      owner_token: str | None = None) -> list[str]:
    """Make every rule a stopped run's skipped stage owns read partial, never "no data in scope" or complete, until a
    resume runs the stage (its own cells then replace these). `not_run` names the stages; without it, every stage
    after the sweep whose summary does not say it finished (a force stop's case). Returns the stages marked.

    The baseline stage owns each baseline spec's whole-window cell; the packet stage owns its rules' cells on each
    Arkime session target (and on every other target, where they do not apply), and the indicator rule's URL and
    SHA256 cells there."""
    hunt = repo.get_hunt(hunt_id) or {}
    manifest = hunt.get("manifest") or {}
    if not_run is None:
        not_run = [stage for stage, action in (("packet stage", "hunt.packet_summary"),
                                               ("baseline stage", "hunt.baseline_summary"))
                   if not ((repo.latest_audit(hunt_id, action) or {}).get("detail") or {}).get("finished")]
        if not join_finished(repo, hunt_id):
            not_run.append(JOIN_STAGE)
    marked = []
    if "baseline stage" in not_run:
        for item in (manifest.get("baseline") or {}).get("specs") or []:
            repo.set_rule_cell(hunt_id, item["id"], item["version"], "*", "window", "evaluated_partial", 0, 0,
                               {"reasons": [f"baseline stage {reason}"]}, owner_token=owner_token)
        marked.append("baseline stage")
    if "packet stage" in not_run and manifest.get("window"):
        from romulus.hunt.packets import mark_not_run
        from romulus.sources.profile import schema_of
        window = Window(start=datetime.fromisoformat(manifest["window"]["start"]),
                        end=datetime.fromisoformat(manifest["window"]["end"]))
        profiles = repo.source_profiles(hunt_id)
        targets = list(manifest.get("targets") or [])
        packet_targets = [target for target in targets
                          if schema_of((profiles.get(target) or {}).get("field_types") or {}) == "arkime_sessions"]
        mark_not_run(repo, hunt_id, window, targets, packet_targets, f"packet stage {reason}",
                     owner_token=owner_token)
        marked.append("packet stage")
    if JOIN_STAGE in not_run:
        mark_join_not_run(repo, hunt_id, reason, owner_token=owner_token)
        marked.append(JOIN_STAGE)
    return marked


def _run_expansion(s: Settings, repo: Repo, client: ElasticClient, hunt: dict, contracts: dict,
                   window: Window, owner_token: str, stop_check=None) -> dict:
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
        wall_clock_seconds=budget_seconds, owner_token=owner_token, heartbeat=heartbeat, stop_check=stop_check,
    ).run()


def _run_expansion_safely(
    s: Settings, repo: Repo, client: ElasticClient, hunt: dict, contracts: dict,
    window: Window, owner_token: str, stop_check=None,
) -> dict:
    try:
        return _run_expansion(s, repo, client, hunt, contracts, window, owner_token,
                              **({"stop_check": stop_check} if stop_check is not None else {}))
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
             claimed_owner: str | None = None, resweep: bool = False) -> dict:
    """Run a claimed hunt end to end. `resweep`: a resume runs again the sweep of a hunt stopped during it, and its
    sources must still have the role and OS family the hunt recorded."""
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
        contracts = _contracts(s, repo, {**h, "_resume_scope_check": True} if resweep else h, client, owner_token)
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
    prune_join_rows(stage_dir, repo)
    sweep = Sweep(
        repo, client, hunt_id, window, contracts, on_candidate, heartbeat=heartbeat, stage_dir=stage_dir,
        site_facts=site_facts,
    )
    # an analyst's request to stop the hunt, read before each source and each partition the sweep reads
    watch = StopWatch(repo, hunt_id, ("hunt",))
    sweep.stop_check = watch
    started: list[str] = []
    try:
        try:
            for target in m["targets"]:
                stopped = watch()
                if stopped:
                    raise HuntStopped(stopped)
                started.append(target)
                sweep.run_target(target)
                # the records outside the sweep's selection, for the mention scan only
                residue = getattr(sweep, "mention_residue", None)
                if residue is not None:
                    residue(target)
        except HuntStopped as stop:
            return _stopped_in_sweep(repo, hunt_id, sweep, m["targets"], started, stop, watch, owner_token)
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
    packet_summary, baseline_summary, expansion_summary, stop = _stages_after_sweep(
        s, repo, client, hunt_id, window, contracts, owner_token, watch)
    if stop is not None:
        result = _finish(
            repo, hunt_id, {"status": "disabled", "mode": "off"}, sweep_summary,
            stats=sweep.stats, partial_reasons=sweep.partial_reasons,
            expansion_summary=expansion_summary, packet_summary=packet_summary,
            baseline_summary=baseline_summary, owner_token=owner_token,
            retain_budget_bytes=int(s.baseline_retain_disk_gb * 1e9), stopped=stop,
        )
        watch.honor(stop["stage"])
        repo.honor_open_stops(hunt_id, stop["stage"])     # an agent stop too: the agent does not run
        return {**result, "ai_agent": {"status": "not_run", "reason": STOPPED_REASON},
                "agent": {"status": "not_run", "stop_reason": STOPPED_REASON}}
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
    out = _with_agent_result(result, repo, _ai_agent_phase(s, repo, hunt_id, m, agent_owner, client, contracts),
                             settings=s, manifest=m)
    _close_unapplied_stops(repo, hunt_id)
    return out


def _close_unapplied_stops(repo: Repo, hunt_id: str) -> None:
    """A stop requested after the run's last safe point did not stop anything: say so, never leave it pending."""
    try:
        repo.mark_stops_unapplied(hunt_id)
    except Exception:  # noqa: BLE001 - the run is finished; the request then stays shown as requested
        log.exception("could not close hunt %s's unapplied stop requests", hunt_id)


def _triage_after_agent(s: Settings, repo: Repo, hunt_id: str, manifest: dict, agent_summary: dict) -> dict | None:
    """The AI triage pass the agent phase ran before its assessment, else one run now that the phase has ended and
    released its lease (the phase reused its assessment, or ended before it), when the hunt asked for the agent,
    triage is on and the provider is ready. A hunt with no surfaced finding makes no call. Never raises: triage only
    orders a separate view, and its failure is recorded without touching the hunt or the agent's result."""
    if isinstance(agent_summary.get("ai_triage"), dict):
        # run once per phase: a second pass would replace the verdicts the stored narrative was checked against
        return agent_summary["ai_triage"]
    try:
        if s.agent_triage != "on" or not (manifest.get("ai_agent") or {}).get("requested", False):
            return None
        if agent_summary.get("status") in (None, "skipped") or agent_summary.get("reason") == "lease_lost":
            return None
        if STOPPED_REASON in str(agent_summary.get("reason") or ""):
            return None                      # an analyst stopped the agent: no further model call
        s = hunt_budget.hunt_settings(s, repo, hunt_id, manifest)
        readiness = agent_readiness(s)
        if not readiness.ready:
            return None
        if not repo.reportable_count(hunt_id):
            return {"status": "skipped", "reason": "no surfaced findings"}
        from romulus.hunt.triage import run_triage
        return run_triage(s, repo, hunt_id, readiness=readiness, build=build_provider)
    except Exception as exc:  # triage must never change a finished hunt's result
        log.exception("AI triage after the agent phase failed")
        return {"status": "failed", "reason": f"triage_error: {type(exc).__name__}: {exc}"[:300]}


def _with_agent_result(result: dict, repo: Repo, summary: dict, *, settings: Settings | None = None,
                       manifest: dict | None = None) -> dict:
    """Return the result refreshed by the agent's atomic finalization without changing detection completion. With
    `settings`, the AI triage pass runs first (after the agent phase) and its summary is added."""
    triage = (_triage_after_agent(settings, repo, result["hunt_id"], manifest or {}, summary)
              if settings is not None else None)
    combined = {**result, "ai_agent": summary,
                "agent": {"status": summary.get("status", "unknown"), "stop_reason": summary.get("reason")}}
    if triage is not None:
        combined["ai_triage"] = triage
    try:
        stored = repo.get_hunt(result["hunt_id"])
        combined.update(lanes=repo.lane_counts(result["hunt_id"]), detection_result=stored["detection_result"])
    except Exception:
        log.exception("could not read the refreshed agent result")
    return combined


class AgentModelMismatch(ValueError):
    """A resume would run the hunt's agent with another model than the one it recorded."""


def recorded_agent_model(repo: Repo, hunt: dict) -> str:
    """The model the hunt's agent ran with, else the one its manifest recorded when the hunt was created ("" when
    neither names one)."""
    run = repo.agent_run(hunt["id"]) or {}
    return str((run.get("provider") or {}).get("model")
               or ((hunt.get("manifest") or {}).get("ai_agent") or {}).get("model") or "")


def _check_agent_model(s: Settings, repo: Repo, hunt: dict, force_model: bool) -> dict | None:
    """A resumed agent keeps the model the hunt recorded: its signed reasoning and its results belong to that model.
    Another model is refused unless the caller forces it; a forced switch is returned as {"from", "to"}, for the
    resume to record once it holds the hunt's lease."""
    if not ((hunt.get("manifest") or {}).get("ai_agent") or {}).get("requested"):
        return None
    recorded = recorded_agent_model(repo, hunt)
    if recorded and s.agent_model != recorded and not force_model:
        raise AgentModelMismatch(
            f"hunt {hunt['id']}'s agent used model {recorded}, but this resume would use "
            f"{s.agent_model or 'no model'}. Resume with --agent-model {recorded}, or add --force-model to "
            "continue with the other model.")
    if recorded and s.agent_model != recorded:
        log.warning("hunt %s: the agent continues with model %s instead of the recorded %s (forced)",
                    hunt["id"], s.agent_model, recorded)
        return {"from": recorded, "to": s.agent_model}
    return None


def _agent_extended(repo: Repo, hunt_id: str, agent_run: dict) -> bool:
    """Whether an analyst added budget to the hunt's agent after its run last ended."""
    added = repo.latest_budget_extension_at(hunt_id)
    if added is None:
        return False
    ended = agent_run.get("ended_at")
    if ended is not None and ended.tzinfo is None:
        ended = ended.replace(tzinfo=added.tzinfo)
    return ended is None or added > ended


def resume_hunt(s: Settings, hunt_id: str, *, force_model: bool = False, continue_agent: bool = False,
                actor: str = "system", on_claimed=None) -> dict:
    """Resume persisted agent work without repeating a completed deterministic hunt. The agent keeps the model the
    hunt recorded unless `force_model`. `on_claimed()` runs once this resume holds the hunt's (or its agent's) lease
    (the command line records its worker process then, so a refused resume never replaces a live worker's record).

    A hunt an analyst stopped resumes too, and the resume clears the stop request (`actor` is recorded): one stopped
    during its sweep runs the sweep again (its writes are idempotent, and its aggregates must read every partition),
    one stopped later runs the stages it did not run. An agent run that ended partial because it was stopped, was
    interrupted, or reached a limit that budget was added to after it ended, continues from its persisted
    hypotheses, sessions and spend. `continue_agent` continues only the agent (never a deterministic stage), also
    on a partial hunt."""
    repo = open_repo(s)
    hunt = repo.get_hunt(hunt_id)
    if hunt is None:
        raise KeyError(hunt_id)
    stale_summary = {}
    if hunt["execution_state"] == "running":
        stale_audit = repo.latest_audit(hunt_id, "hunt.sweep_summary")
        stale_summary = dict(stale_audit["detail"]) if stale_audit else {}
    if hunt["execution_state"] == "running" and not stale_summary.get("finished", stale_summary.get("complete")):
        # The worker stopped without reaching any end transition (killed, out of memory, host reboot). Once its
        # lease has expired, end the hunt as failed so its whole-window cells stop claiming a complete answer;
        # a live lease refuses the claim and nothing changes. Ending it needs no source, site or normalizer, so
        # this comes before the checks that a resumed sweep would need.
        stale = repo.claim_hunt(hunt_id, _lease_seconds(s), resume=True)
        repo.audit("system", "hunt.sweep_summary", hunt_id, {
            "finished": False, "complete": False, "partial_reasons": [], "stats": stale_summary.get("stats") or {},
            "error": "the hunt's worker stopped before its sweep finished",
        }, owner_token=stale["lease_owner"])
        repo.set_hunt_state(hunt_id, "failed", owner_token=stale["lease_owner"],
                            stop_reason="the hunt's worker stopped before its sweep finished")
        raise RuntimeError("running hunt cannot resume because the sweep did not finish; it is now marked failed")
    forced = _check_agent_model(s, repo, hunt, force_model)
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
    if "normalizers" in recorded_manifest:
        recorded_versions = recorded_manifest["normalizers"]
        if not isinstance(recorded_versions, dict):
            raise RuntimeError(f"hunt {hunt_id} has an invalid normalizer version map. "
                               "Start a new hunt over the same window instead of resuming.")
        current_versions = normalizer_versions()
        for producer, version in recorded_versions.items():
            current = current_versions.get(producer)
            if current is None or version != current:
                raise RuntimeError(f"hunt {hunt_id} was normalized with {producer}={version}; "
                                   f"this build is {current or 'missing that producer'}. "
                                   "Start a new hunt over the same window instead of resuming.")
    # Suricata and Arkime used the shared producer before their independent epochs.
    # An older shared manifest without both explicit epochs cannot safely mix its
    # staged identities with new fetches, even when the shared epoch is unchanged.
    versions = recorded_manifest.get("normalizers") or {}
    if recorded or "lab-ecs" in versions:
        missing = {"suricata-eve", "arkime"} - versions.keys()
        if missing:
            raise RuntimeError(f"hunt {hunt_id} has legacy shared network normalization without "
                               f"{', '.join(sorted(missing))} producer versions. "
                               "Start a new hunt over the same window instead of resuming.")
    # expansion and the investigator read the definition the sweep used; a changed one is refused here
    install_for_hunt(s, hunt_id, recorded_manifest)
    sweep_audit = repo.latest_audit(hunt_id, "hunt.sweep_summary")
    sweep_summary = dict(sweep_audit["detail"]) if sweep_audit else {}
    if sweep_summary.get("stopped") and not sweep_summary.get("finished"):
        # stopped during the sweep (by request, or by a force stop): the sweep runs again from the start
        if continue_agent:
            raise ValueError(f"hunt {hunt_id} was stopped during its sweep and its agent never ran: resume the "
                             "whole hunt")
        if hunt["execution_state"] != "partial":
            raise RuntimeError(f"hunt {hunt_id} is {hunt['execution_state']}; only a partial hunt resumes its sweep")
        before = (repo.latest_stop(hunt_id) or {}).get("id")
        owner = repo.claim_hunt(hunt_id, _lease_seconds(s), resume=True)["lease_owner"]
        if on_claimed is not None:
            on_claimed()
        repo.clear_stops(hunt_id, actor, up_to_id=before)
        if forced is not None:
            repo.audit("system", AGENT_MODEL_FORCED, hunt_id, forced, owner_token=owner)
        return run_hunt(s, hunt_id, claimed_owner=owner, resweep=True)
    if sweep_summary and not sweep_summary.get("finished"):
        raise RuntimeError("hunt cannot resume agent work because the sweep did not finish")
    if hunt["execution_state"] == "failed" and not sweep_summary.get("finished"):
        raise RuntimeError("failed hunt cannot resume because the sweep did not finish")
    agent_run = repo.agent_run(hunt_id) or {}
    agent_reason = str(agent_run.get("reason") or "")
    resumable_agent = (
        agent_run.get("state") in {"pending", "running"}
        or (agent_run.get("state") == "partial" and
            (any(reason in agent_reason for reason in ("provider_unavailable", "interrupted", STOPPED_REASON))
             or _agent_extended(repo, hunt_id, agent_run)))
    )
    agent_only = resumable_agent and (hunt["execution_state"] == "completed_within_scope"
                                      or (continue_agent and hunt["execution_state"] == "partial"))
    if continue_agent and not agent_only:
        raise ValueError(f"hunt {hunt_id} has no agent run to continue: it continues after it stopped, was "
                         "interrupted, or reached a limit that budget was added to afterwards")
    if hunt["execution_state"] == "completed_within_scope" and not agent_only:
        raise ValueError(f"hunt {hunt_id} has no resumable agent phase")
    before = (repo.latest_stop(hunt_id) or {}).get("id")
    claimed = (repo.claim_agent_lease(hunt_id, _lease_seconds(s)) if agent_only else
               repo.claim_hunt(hunt_id, _lease_seconds(s), resume=True))
    owner_token = claimed["lease_owner"]
    if on_claimed is not None:
        on_claimed()
    # the analyst asked the hunt to run again: a stop requested before this resume claimed it no longer applies (one
    # requested after the claim is for this run)
    repo.clear_stops(hunt_id, actor, up_to_id=before)
    if forced is not None:
        # recorded only now, under the lease: a refused resume switched nothing
        repo.audit("system", AGENT_MODEL_FORCED, hunt_id, forced, owner_token=owner_token)
    hunt = repo.get_hunt(hunt_id)
    manifest = hunt["manifest"]
    if agent_only:
        # who continued the agent, why, and where it starts (a continuation never orients again once orient is done)
        why = ("stop_cleared" if STOPPED_REASON in agent_reason else
               "extension" if _agent_extended(repo, hunt_id, agent_run) else
               "provider_unavailable" if "provider_unavailable" in agent_reason else
               "interrupted")
        plan = continuation_plan(hunt_budget.hunt_settings(s, repo, hunt_id, manifest), repo, hunt_id)
        repo.audit(actor, "hunt.agent_resume", hunt_id, {
            "reason": why, "starting_phase": plan["starting_phase"], "previous_state": agent_run.get("state"),
            "previous_reason": agent_reason[:500] or None})
        base_result = {"hunt_id": hunt_id, "execution_state": hunt["execution_state"],
                       "stats": sweep_summary.get("stats") or {}, "lanes": repo.lane_counts(hunt_id),
                       "detection_result": hunt.get("detection_result"), "baseline": {}, "expansion": {}}
        try:
            with _agent_heartbeat(repo, hunt_id, owner_token, _lease_seconds(s)):
                recovered = recover_agent_finalization(repo, hunt_id, owner_token=owner_token)
            if recovered is not None:
                return _with_agent_result(base_result, repo, recovered.as_dict(), settings=s, manifest=manifest)
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
    # A pending template handoff is local work. Keep existing partial investigation recovery on its
    # original path, and resolve readiness once so a changing configuration cannot open a source path.
    if agent_only and agent_run.get("state") == "pending":
        wanted = (manifest.get("ai_agent") or {}).get("requested", False)
        try:
            readiness = agent_readiness(s) if wanted else None
        except Exception as exc:  # noqa: BLE001 - configuration failure still leaves only local template work.
            readiness = AgentReadiness("blocked", f"readiness_error:{type(exc).__name__}",
                                       s.agent_provider, s.agent_model)
        if not wanted or not readiness.ready:
            summary = _ai_agent_phase(s, repo, hunt_id, manifest, owner_token, None, {},
                                      readiness_snapshot=readiness)
            return _with_agent_result(base_result, repo, summary, settings=s, manifest=manifest)
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
        out = _with_agent_result({"hunt_id": hunt_id, "execution_state": hunt["execution_state"],
                "stats": sweep_summary.get("stats") or {}, "lanes": repo.lane_counts(hunt_id),
                "detection_result": hunt.get("detection_result"), "agent": ai_agent_summary,
                "ai_agent": ai_agent_summary, "baseline": {}, "expansion": {}}, repo, ai_agent_summary,
                settings=s, manifest=manifest)
        _close_unapplied_stops(repo, hunt_id)
        return out
    packet_audit = repo.latest_audit(hunt_id, "hunt.packet_summary")
    packet_summary = dict(packet_audit["detail"]) if packet_audit else {}
    baseline_audit = repo.latest_audit(hunt_id, "hunt.baseline_summary")
    baseline_summary = dict(baseline_audit["detail"]) if baseline_audit else {}
    watch = StopWatch(repo, hunt_id, ("hunt",))
    packet_summary, baseline_summary, expansion_summary, stop = _stages_after_sweep(
        s, repo, client, hunt_id, window, contracts, owner_token, watch,
        packet_summary=packet_summary, baseline_summary=baseline_summary)
    if stop is not None:
        result = _finish(
            repo, hunt_id, {"status": "disabled", "mode": "off"}, sweep_summary,
            expansion_summary=expansion_summary, packet_summary=packet_summary,
            baseline_summary=baseline_summary, owner_token=owner_token,
            retain_budget_bytes=int(s.baseline_retain_disk_gb * 1e9), stopped=stop,
        )
        watch.honor(stop["stage"])
        repo.honor_open_stops(hunt_id, stop["stage"])     # an agent stop too: the agent does not run
        return {**result, "ai_agent": {"status": "not_run", "reason": STOPPED_REASON},
                "agent": {"status": "not_run", "stop_reason": STOPPED_REASON}}
    agent_owner = uuid.uuid4().hex
    result = _finish(
        repo, hunt_id, {"status": "disabled", "mode": "off"}, sweep_summary,
        expansion_summary=expansion_summary, packet_summary=packet_summary,
        baseline_summary=baseline_summary,
        owner_token=owner_token, pending_agent_owner_token=agent_owner,
        pending_agent_lease_seconds=_lease_seconds(s),
        retain_budget_bytes=int(s.baseline_retain_disk_gb * 1e9),
    )
    out = _with_agent_result(result, repo, _ai_agent_phase(
        s, repo, hunt_id, manifest, agent_owner, client, contracts, resuming=True, previous_run=agent_run),
        settings=s, manifest=manifest)
    _close_unapplied_stops(repo, hunt_id)
    return out
