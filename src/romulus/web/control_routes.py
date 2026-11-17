"""Analyst controls on a hunt: the agent budget chosen at the start, extending it, and stopping the hunt or its agent.

Every POST checks the CSRF token and reads the account's role from the database (a demoted or disabled account loses
the control at once, not when its session expires). A lead may control any hunt; an analyst the hunts they started.
Only a lead may force a stop, or go above the site's agent budget ceiling. romulus/hunt/controls.py has the rules.
"""
from __future__ import annotations

import math
import os
import subprocess
from datetime import datetime, timedelta
from urllib.parse import urlencode

from fastapi import Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select

from romulus.agent import hunt_budget
from romulus.hunt.controls import (
    GRANT_MAX_AGE_SECONDS,
    ControlRefused,
    continuation_command,
    describe,
    extend_budget,
    force_stop,
    may_control,
    request_stop,
)
from romulus.store import schema as t
from romulus.store.db import utcnow
from romulus.store.repo import TRIAGE_PURPOSE
from romulus.web.auth import csrf_ok

CONTROL_MESSAGES = {
    "stop_requested": "Stop requested: the hunt stops at its next safe point and keeps everything it found.",
    "agent_stop_requested": "Stop requested for the AI agent: it stops before its next model call; the deterministic "
                            "hunt is not affected.",
    "force_stopped": "The hunt's worker process was ended. The hunt is partial and can be resumed.",
    "extended": "Agent budget extended.",
    "extended_continuing": "Agent budget extended; the agent continues from where it stopped.",
    "extended_running": "Agent budget extended; the running agent uses it from its next model call.",
}
# The budget form's fields: field name -> agent limit (minutes become seconds)
START_FIELDS = {"max_calls": "max_calls", "max_tokens": "max_tokens", "minutes": "max_wall_seconds",
                "max_cost_usd": "max_cost_usd", "max_source_queries": "max_source_queries",
                "max_initial_hypotheses": "max_initial_hypotheses", "max_hypotheses": "max_hypotheses",
                "max_sessions_per_hypothesis": "max_sessions_per_hypothesis",
                "max_tool_calls_per_session": "max_tool_calls_per_session"}
EXTEND_FIELDS = {"calls": "max_calls", "tokens": "max_tokens", "minutes": "max_wall_seconds",
                 "source_queries": "max_source_queries", "cost_usd": "max_cost_usd"}
EXTENSIONS_SHOWN = 20


def account_role(repo, user: dict) -> str:
    """The account's role as the database has it now; 403 for a disabled or removed account."""
    with repo.engine.connect() as c:
        row = c.execute(select(t.user.c.role, t.user.c.disabled).where(t.user.c.username == user.get("u"))).first()
    if row is None or row.disabled:
        raise HTTPException(403, "an active account is required")
    return row.role


def _number(name: str, value: str, limit: str) -> float | int | None:
    value = (value or "").strip()
    if not value:
        return None
    try:
        number = float(value)
    except ValueError:
        raise HTTPException(400, f"{name} must be a number") from None
    if not math.isfinite(number) or number < 0:
        raise HTTPException(400, f"{name} must be a non-negative number")
    if limit == "max_wall_seconds":
        return int(number * 60)
    return number if limit == "max_cost_usd" else int(number)


def budget_from_form(form, fields: dict) -> dict:
    out = {}
    for name, limit in fields.items():
        value = _number(name, str(form.get(name, "") or ""), limit)
        if value is not None:
            out[limit] = value
    return out


def new_hunt_context(s, repo, user: dict) -> dict:
    """What the start form shows about agent budgets: each profile's limits and the site ceiling."""
    return {"profiles": {name: hunt_budget.profile_limits(s, name) for name in hunt_budget.PROFILES},
            "ceiling": hunt_budget.ceiling(s), "labels": hunt_budget.LABELS,
            "default_profile": hunt_budget.DEFAULT_PROFILE, "is_lead": user.get("r") == "lead"}


def start_grant(s, repo, user: dict, form) -> tuple[str, dict]:
    """Check the start form's agent budget against the account's role and store it as a grant for the hunt process;
    returns the grant id and the checked choice. 400 when refused."""
    profile = str(form.get("effort", "") or hunt_budget.DEFAULT_PROFILE)
    if profile not in hunt_budget.PROFILES:
        raise HTTPException(400, "bad budget profile")
    role = account_role(repo, user)
    actor = f"web:{user['u']}"
    try:
        choice = hunt_budget.choose(s, profile, budget_from_form(form, START_FIELDS), role=role, chosen_by=actor)
    except hunt_budget.BudgetRefused as exc:
        raise HTTPException(400, str(exc)) from None
    grant = repo.create_budget_grant(created_by=actor, role=role,
                                     choice={"profile": choice["profile"], "overrides": choice["overrides"]},
                                     max_age_seconds=GRANT_MAX_AGE_SECONDS)
    return grant, choice


def controls_view(repo, s, hunt: dict, user: dict) -> dict:
    """The run page's budget and controls panel: the limits pinned for the agent, the extensions, the spend against
    each limit, the latest stop request, and which controls this account may use now."""
    hunt_id = hunt["id"]
    manifest = hunt["manifest"] or {}
    resolved = hunt_budget.resolve(repo, hunt_id, manifest, s)
    usage = repo.agent_usage(hunt_id, exclude_purposes=(TRIAGE_PURPOSE,))
    rows = hunt_budget.view(resolved, usage, repo.agent_source_queries(hunt_id),
                            repo.agent_elapsed_ms(hunt_id, exclude_purposes=(TRIAGE_PURPOSE,)) / 1000)
    extensions = resolved["extensions"]
    live = repo.run_liveness(hunt_id)
    stop = repo.latest_stop(hunt_id)
    owner = may_control(repo, hunt, f"web:{user.get('u')}", user.get("r", ""))
    agent_requested = bool((manifest.get("ai_agent") or {}).get("requested"))
    open_stop = stop if stop and stop["state"] in ("requested", "honored") else None
    force_at = (open_stop["requested_at"] + timedelta(seconds=s.hunt_stop_grace_seconds)) if open_stop else None
    running = live["hunt"] or live["agent"]
    return {
        "source": resolved["source"], "profile": resolved["profile"], "from_settings": resolved["from_settings"],
        "rows": rows, "extensions": list(reversed(extensions))[:EXTENSIONS_SHOWN],
        "extensions_more": max(0, len(extensions) - EXTENSIONS_SHOWN), "extensions_total": len(extensions),
        "agent_requested": agent_requested, "live": live, "running": running, "stop": stop,
        "stop_text": describe(stop) if stop else "", "can_control": owner,
        "can_stop_hunt": owner and running and not (open_stop and open_stop["scope"] == "hunt"),
        "can_stop_agent": owner and agent_requested and (live["agent"] or live["hunt"]) and not open_stop,
        "can_force": (user.get("r") == "lead" and open_stop is not None and running
                      and not (open_stop["scope"] == "agent" and live["hunt"])),
        "force_at": force_at, "force_ready": bool(force_at and utcnow() >= force_at),
        "can_extend": owner and agent_requested, "is_lead": user.get("r") == "lead",
        "ceiling": hunt_budget.ceiling(s), "profiles": hunt_budget.PROFILES,
        "grace_seconds": s.hunt_stop_grace_seconds,
    }


def stop_banner(repo, hunt_id: str) -> dict | None:
    """The stopped-by banner every hunt tab shows while a stop request is open, or after one ended the run."""
    stop = repo.latest_stop(hunt_id)
    if stop is None or stop["state"] not in ("requested", "honored", "forced"):
        return None
    what = "the AI agent" if stop["scope"] == "agent" else "the hunt"
    if stop["state"] == "requested":
        text = (f"Stop of {what} requested by {stop['requested_by']} at {stop['requested_at']:%Y-%m-%d %H:%M:%S} "
                "UTC: it stops at its next safe point.")
    elif stop["state"] == "honored":
        where = ", ".join((stop.get("detail") or {}).get("honored_in") or []) or "its next safe point"
        text = (f"{what[0].upper()}{what[1:]} was stopped by {stop['requested_by']} (requested "
                f"{stop['requested_at']:%Y-%m-%d %H:%M:%S} UTC; stopped at: {where}). What it found is kept; what it "
                "did not run is named as not run, and its results are partial. Resuming the hunt continues it.")
    else:
        text = (f"The hunt's worker process was force-stopped by {(stop.get('detail') or {}).get('forced_by')} after "
                f"a stop requested by {stop['requested_by']} at {stop['requested_at']:%Y-%m-%d %H:%M:%S} UTC was not "
                "honoured in time. The hunt is partial (interrupted); resuming the hunt continues it.")
    return {"state": stop["state"], "text": text}


def register_control_routes(app, repo, s, env_file, need):
    # synchronous handlers: FastAPI runs them in its thread pool, so a force stop's wait never blocks the server
    def checked(request: Request, hunt_id: str, csrf: str) -> tuple[dict, str]:
        u = need(request)
        if not csrf_ok(u, csrf):
            raise HTTPException(403, "bad CSRF token")
        if repo.get_hunt(hunt_id) is None:
            raise HTTPException(404)
        return u, account_role(repo, u)

    def back(hunt_id: str, code: str):
        return RedirectResponse(f"/hunts/{hunt_id}/run?" + urlencode({"control": code}) + "#controls",
                                status_code=303)

    @app.post("/hunts/{hunt_id}/stop")
    def stop_hunt(request: Request, hunt_id: str, csrf: str = Form(""), scope: str = Form("hunt")):
        u, role = checked(request, hunt_id, csrf)
        if scope not in ("hunt", "agent"):
            raise HTTPException(400, "bad stop scope")
        try:
            request_stop(repo, hunt_id, scope=scope, actor=f"web:{u['u']}", role=role)
        except ControlRefused as exc:
            raise HTTPException(409 if "not running" in str(exc) or "no AI agent" in str(exc) else 403,
                                str(exc)) from None
        return back(hunt_id, "agent_stop_requested" if scope == "agent" else "stop_requested")

    @app.post("/hunts/{hunt_id}/force-stop")
    def force_stop_hunt(request: Request, hunt_id: str, csrf: str = Form(""), confirm: str = Form("")):
        u, role = checked(request, hunt_id, csrf)
        if role != "lead":
            raise HTTPException(403, "only a lead may force a hunt to stop")
        if confirm != hunt_id:
            raise HTTPException(400, "force stop not confirmed")
        try:
            force_stop(s, repo, hunt_id, actor=f"web:{u['u']}", role=role)
        except ControlRefused as exc:
            raise HTTPException(409, str(exc)) from None
        return back(hunt_id, "force_stopped")

    @app.post("/hunts/{hunt_id}/extend")
    def extend(request: Request, hunt_id: str, csrf: str = Form(""), effort: str = Form(""),
               calls: str = Form(""), tokens: str = Form(""), minutes: str = Form(""),
               source_queries: str = Form(""), cost_usd: str = Form("")):
        u, role = checked(request, hunt_id, csrf)
        profile = effort or None
        if profile is not None and profile not in hunt_budget.PROFILES:
            raise HTTPException(400, "bad budget profile")
        amounts = budget_from_form({"calls": calls, "tokens": tokens, "minutes": minutes,
                                    "source_queries": source_queries, "cost_usd": cost_usd}, EXTEND_FIELDS)
        if profile is not None and amounts:
            raise HTTPException(400, "give amounts or a profile, not both")
        actor = f"web:{u['u']}"
        try:
            done = extend_budget(s, repo, hunt_id, actor=actor, role=role, profile=profile,
                                 amounts=amounts or None)
        except ControlRefused as exc:
            raise HTTPException(403 if "only a lead" in str(exc) else 400, str(exc)) from None
        if done["running"]:
            return back(hunt_id, "extended_running")
        if not _continuable(repo, hunt_id):
            return back(hunt_id, "extended")
        # continue the agent from its persisted state in its own process, as a hunt start does
        s.logs_dir.mkdir(parents=True, exist_ok=True)
        env = {**os.environ, "USER": actor}
        with open(s.logs_dir / f"hunt-extend-{datetime.now():%Y%m%d-%H%M%S}.log", "ab") as log:
            subprocess.Popen(continuation_command(env_file, hunt_id), stdout=log, stderr=subprocess.STDOUT,
                             env=env, start_new_session=True)
        repo.audit(actor, "web.agent_continue", hunt_id=hunt_id)
        return back(hunt_id, "extended_continuing")


def _continuable(repo, hunt_id: str) -> bool:
    """Whether the hunt's agent can continue now: its run ended partial and the hunt's detection is finished."""
    hunt = repo.get_hunt(hunt_id) or {}
    run = repo.agent_run(hunt_id) or {}
    return hunt.get("execution_state") in ("completed_within_scope", "partial") and run.get("state") == "partial"
