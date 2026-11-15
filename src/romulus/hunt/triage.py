"""Run the AI triage pass on a finished hunt under the agent lease, and export the triage order.

The pass runs after the agent phase when the agent is enabled (`after_agent_phase`), or on demand
(`romulus triage <hunt>`). It claims the hunt's agent lease, so it never overlaps detection, the agent, deletion or
maintenance, and releases it without touching the agent's state. A hunt stored before the agent phase existed gets no
agent record from it. Every failure stays inside the pass: it is recorded, and the report keeps its deterministic
order.
"""
from __future__ import annotations

import json
import logging
from collections.abc import Callable
from pathlib import Path

from romulus.agent.triage import LABEL, latest_summary, run_triage_pass
from romulus.agent.triage_order import OrderWorkspace, group_key
from romulus.config import Settings
from romulus.store.db import utcnow
from romulus.store.repo import TRIAGE_SUMMARY, Repo, is_lease_lost

log = logging.getLogger("romulus.triage")
EXPORT_SCHEMA = "ai-triage-order@1"


def run_triage(s: Settings, repo: Repo, hunt_id: str, *, provider=None, readiness=None, force: bool = False,
               build: Callable | None = None) -> dict:
    """Claim the agent lease, run one triage pass and release the lease. Never raises for a provider, budget or
    validation problem: the summary says what happened. `build(settings, readiness=...)` constructs the provider
    when none is given."""
    from romulus.hunt.run import _agent_heartbeat, _lease_seconds
    if provider is None:
        from romulus.agent.provider import agent_readiness, build_provider
        readiness = readiness if readiness is not None else agent_readiness(s)
        if not readiness.ready:
            return {"status": "skipped", "reason": f"provider_not_ready: {readiness.message()}"}
    try:
        owner, created = repo.claim_triage_lease(hunt_id, _lease_seconds(s))
    except (RuntimeError, ValueError) as exc:
        return {"status": "skipped", "reason": str(exc)[:300]}
    summary: dict
    try:
        with _agent_heartbeat(repo, hunt_id, owner, _lease_seconds(s)) as heartbeat:
            if provider is None:
                provider = (build or build_provider)(s, readiness=readiness)
            summary = run_triage_pass(s, repo, hunt_id, provider, owner_token=owner, heartbeat=heartbeat, force=force)
    except Exception as exc:
        if is_lease_lost(exc):
            return {"status": "partial", "reason": "lease_lost"}
        log.exception("AI triage pass failed")
        summary = {"label": LABEL, "status": "failed", "reason": f"triage_error: {type(exc).__name__}: {exc}"[:500],
                   "at": str(utcnow())}
        try:
            repo.audit("system", TRIAGE_SUMMARY + "_failed", hunt_id, summary, owner_token=owner)
        except Exception:
            log.exception("could not record the triage failure")
    try:
        repo.release_triage_lease(hunt_id, owner_token=owner, created=created)
    except Exception as exc:
        if not is_lease_lost(exc):
            log.exception("could not release the triage lease")
    return summary


def write_export(repo: Repo, hunt_id: str, path: Path) -> dict:
    """Write the latest triage pass's order as JSON: every surfaced finding id, in triage order, rebuilt from the
    stored findings and the pass's promoted groups (with no pass, or nothing promoted, it is the deterministic order).
    The file is streamed, so memory stays bounded whatever the hunt's size. Returns the export's header."""
    summary = latest_summary(repo, hunt_id) or {}
    promoted: dict[int, list[str]] = {}
    after = 0
    while page := repo.triage_groups(hunt_id, statuses=("promoted",), after_position=after):
        for row in page:
            promoted.setdefault(int(row["section"]), []).append(group_key(
                int(row["section"]), row["provenance"], row["rule_id"], row["entity_kind"], row["entity"] or ""))
        after = page[-1]["position"]
    with OrderWorkspace(repo, hunt_id) as ws:
        ws.build()
        header = {"schema": EXPORT_SCHEMA, "label": LABEL, "hunt_id": hunt_id, "pass": summary.get("pass"),
                  "status": summary.get("status") or "not_run", "reason": summary.get("reason"),
                  "prompt_digest": summary.get("prompt_digest"), "model": summary.get("model"),
                  "provider": summary.get("provider"), "mode": "ranked" if ws.ranked else "lanes",
                  "findings": ws.findings, "deterministic_order_digest": ws.order_digest,
                  # the store changed after the pass: its promotions apply to the findings that still match
                  "stale": bool(summary) and summary.get("order_digest") != ws.order_digest,
                  "groups": summary.get("groups"),
                  "promoted_groups": sum(len(keys) for keys in promoted.values())}
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        count = 0
        with path.open("w", encoding="utf-8", newline="\n") as out:
            out.write(json.dumps(header, sort_keys=True)[:-1] + ', "order": [')
            for finding_id in ws.triage_order(promoted):
                out.write(("" if count == 0 else ", ") + json.dumps(finding_id))
                count += 1
            out.write("]}\n")
        if count != ws.findings:
            raise RuntimeError(f"triage export wrote {count} of {ws.findings} findings")
    return {**header, "written": count, "path": str(path)}
