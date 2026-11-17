"""Per-hunt AI agent budgets: the presets an analyst picks from, the site ceiling, the budget pinned in the hunt
manifest, and the extensions added to it later.

A hunt's agent limits are chosen when the hunt is created and written into its manifest (`ai_agent.budgets`, schema
`BUDGET_SCHEMA`). Every agent stage, every resume and every continuation reads that pinned budget plus the hunt's
recorded extensions, never the live settings: a changed .env changes new hunts only. A hunt created before budgets
were pinned keeps what its manifest recorded (model calls, tokens, wall clock, cost, tool calls per session and source
queries when its agent was configured) and reads every other limit from the current settings, and says so.

The limits are hunt totals, and spending persists: a limit raised by an extension continues from what the agent
already used. New limit = pinned + every extension.
"""
from __future__ import annotations

import math
from dataclasses import replace

from romulus.config import Settings

BUDGET_SCHEMA = "agent-budget@1"
PROFILES = ("quick", "standard", "deep")
DEFAULT_PROFILE = "standard"

# limit -> the setting that is its standard value
LIMITS: dict[str, str] = {
    "max_calls": "agent_max_calls",
    "max_tokens": "agent_max_tokens",
    "max_wall_seconds": "agent_max_wall_seconds",
    "max_cost_usd": "agent_max_cost_usd",
    "max_source_queries": "agent_max_source_queries",
    "max_initial_hypotheses": "agent_max_initial_hypotheses",
    "max_hypotheses": "agent_max_hypotheses",
    "max_sessions_per_hypothesis": "agent_max_sessions_per_hypothesis",
    "max_tool_calls_per_session": "agent_max_tool_calls_per_session",
}
# the limits an extension may add to by amount (an extension to a profile may raise every limit)
EXTENDABLE = ("max_calls", "max_tokens", "max_wall_seconds", "max_source_queries", "max_cost_usd")
# The triage pass has its own budget. Its work is set by how many findings the hunt surfaced, not by how deeply the
# agent investigates, so every profile pins the standard triage limits.
TRIAGE_LIMITS: dict[str, str] = {
    "triage_max_calls": "agent_triage_max_calls",
    "triage_max_input_tokens": "agent_triage_max_input_tokens",
    "triage_max_output_tokens": "agent_triage_max_output_tokens",
    "triage_max_wall_seconds": "agent_triage_max_wall_seconds",
}
# smallest accepted value of each limit (the settings' own lower bounds; a cost of 0 means no cost budget)
MINIMUM: dict[str, float] = {
    "max_calls": 1, "max_tokens": 1000, "max_wall_seconds": 60, "max_cost_usd": 0.0, "max_source_queries": 1,
    "max_initial_hypotheses": 1, "max_hypotheses": 1, "max_sessions_per_hypothesis": 1,
    "max_tool_calls_per_session": 1,
}
# A cost budget has no setting maximum; this one only rejects a mistyped amount.
COST_MAXIMUM = 1_000_000.0
# At most this many extensions per hunt: each is an analyst's action, and the limits are their sum.
MAX_EXTENSIONS = 100

# Multipliers of the standard (.env) limits.
#
# quick: a first look at the strongest findings. A quarter of the calls, tokens, source queries, cost and hypotheses,
#   half the rounds per hypothesis and half the wall clock: orient plus a few leads in minutes, at about a quarter of
#   the standard cost. Tool calls per session stay standard, so each lead it follows is followed properly.
# standard: the site's .env values.
# deep: a mission hunt the team will wait hours for. The agent's work grows with hypotheses x rounds per hypothesis x
#   tool calls per round; deep doubles the hypotheses it may open and the rounds each gets, and gives each round half
#   again as many tool calls. Calls, tokens, source queries and cost grow four-fold, so the hunt totals, not the
#   per-hypothesis limits, decide where the extra effort goes (the agent works the strongest leads first). The wall
#   clock grows six-fold (one standard hour becomes six) so that over a long mission hunt the calls and tokens, not
#   the clock, are what the agent spends.
MULTIPLIERS: dict[str, dict[str, float]] = {
    "quick": {"max_calls": 0.25, "max_tokens": 0.25, "max_wall_seconds": 0.5, "max_cost_usd": 0.25,
              "max_source_queries": 0.25, "max_initial_hypotheses": 0.5, "max_hypotheses": 0.25,
              "max_sessions_per_hypothesis": 0.5, "max_tool_calls_per_session": 1.0},
    "standard": dict.fromkeys(LIMITS, 1.0),
    "deep": {"max_calls": 4.0, "max_tokens": 4.0, "max_wall_seconds": 6.0, "max_cost_usd": 4.0,
             "max_source_queries": 4.0, "max_initial_hypotheses": 2.0, "max_hypotheses": 2.0,
             "max_sessions_per_hypothesis": 2.0, "max_tool_calls_per_session": 1.5},
}
LABELS = {
    "max_calls": "model calls", "max_tokens": "budget tokens", "max_wall_seconds": "wall clock (s)",
    "max_cost_usd": "cost (USD)", "max_source_queries": "source queries",
    "max_initial_hypotheses": "initial hypotheses", "max_hypotheses": "hypotheses",
    "max_sessions_per_hypothesis": "sessions per hypothesis", "max_tool_calls_per_session": "tool calls per session",
}


class BudgetRefused(ValueError):
    """A budget choice or extension outside what the requester may set."""


def hard_maximum(key: str) -> float:
    """The limit's own maximum: the bound its setting accepts (no role may go above it)."""
    if key == "max_cost_usd":
        return COST_MAXIMUM
    for item in Settings.model_fields[LIMITS[key]].metadata:
        bound = getattr(item, "le", None)
        if bound is not None:
            return bound
    raise KeyError(key)


def _value(key: str, value: float) -> float | int:
    return round(float(value), 6) if key == "max_cost_usd" else int(value)


def standard_limits(s: Settings) -> dict:
    return {key: _value(key, getattr(s, field)) for key, field in LIMITS.items()}


def ceiling(s: Settings) -> dict:
    """The most an analyst may set each limit to: the standard limit times the site multiplier, within the limit's
    maximum. A cost of 0 (no cost budget) has no ceiling of its own."""
    out = {}
    for key, value in standard_limits(s).items():
        scaled = value * s.agent_budget_ceiling_multiplier
        out[key] = _value(key, min(hard_maximum(key), scaled if key == "max_cost_usd" else math.floor(scaled)))
    return out


def profile_limits(s: Settings, profile: str) -> dict:
    if profile not in MULTIPLIERS:
        raise BudgetRefused(f"unknown budget profile {profile!r}: choose {', '.join(PROFILES)}")
    out = {}
    for key, value in standard_limits(s).items():
        factor = MULTIPLIERS[profile][key]
        if key == "max_cost_usd":
            scaled = round(value * factor, 6)
        elif factor >= 1:
            scaled = math.ceil(value * factor)
        else:
            scaled = max(int(MINIMUM[key]), round(value * factor))
        out[key] = _value(key, min(hard_maximum(key), scaled))
    return out


def check_limits(s: Settings, limits: dict, role: str) -> list[str]:
    """Refuse a value outside its bounds, or above the site ceiling for anyone but a lead. Returns the limits that
    are above the ceiling (allowed: the requester is a lead)."""
    top = ceiling(s)
    above = []
    for key, value in limits.items():
        if key not in LIMITS:
            raise BudgetRefused(f"unknown agent limit {key!r}")
        if value < MINIMUM[key]:
            raise BudgetRefused(f"{LABELS[key]} must be at least {MINIMUM[key]}")
        if value > hard_maximum(key):
            raise BudgetRefused(f"{LABELS[key]} {value} is above its maximum {hard_maximum(key)}")
        # a hunt with no cost budget has none to exceed; a cost budget where the site sets none has no ceiling
        if key == "max_cost_usd" and not top[key]:
            continue
        if value > top[key]:
            if role != "lead":
                raise BudgetRefused(f"{LABELS[key]} {value} is above the site ceiling {top[key]} "
                                    f"(AGENT_BUDGET_CEILING_MULTIPLIER); only a lead may go above it")
            above.append(key)
    return above


def choose(s: Settings, profile: str = DEFAULT_PROFILE, overrides: dict | None = None, *, role: str,
           chosen_by: str) -> dict:
    """The budget block a new hunt pins: the profile's limits with explicit overrides, checked against the ceiling
    for `role`. Raises BudgetRefused."""
    overrides = {key: _value(key, value) for key, value in (overrides or {}).items() if value is not None}
    unknown = set(overrides) - set(LIMITS)
    if unknown:
        raise BudgetRefused(f"unknown agent limit {sorted(unknown)[0]!r}")
    limits = {**profile_limits(s, profile), **overrides}
    above = check_limits(s, limits, role)
    return {"schema": BUDGET_SCHEMA, "profile": profile, "overrides": overrides, "limits": limits,
            "ceiling": ceiling(s), "above_ceiling": sorted(above), "chosen_by": chosen_by, "role": role,
            "triage": {key: getattr(s, field) for key, field in TRIAGE_LIMITS.items()}}


def pinned_block(choice: dict) -> dict:
    """What the manifest's `ai_agent.budgets` carries for a chosen budget, beside its provider limits and prices."""
    return {**choice["limits"], "schema": BUDGET_SCHEMA, "profile": choice["profile"],
            "overrides": choice["overrides"], "ceiling": choice["ceiling"],
            "above_ceiling": choice["above_ceiling"], "chosen_by": choice["chosen_by"], "role": choice["role"],
            "triage": choice["triage"]}


def is_pinned(manifest: dict) -> bool:
    return (((manifest or {}).get("ai_agent") or {}).get("budgets") or {}).get("schema") == BUDGET_SCHEMA


def _extensions(repo, hunt_id: str) -> list[dict]:
    reader = getattr(repo, "agent_budget_extensions", None)
    return list(reader(hunt_id)) if reader is not None else []


def resolve(repo, hunt_id: str, manifest: dict, settings: Settings) -> dict:
    """The hunt's agent limits: what its manifest pinned (or, for a hunt created before budgets were pinned, what it
    recorded and the current settings for the rest), plus every extension.

    Returns {"source", "profile", "base", "added", "limits", "extensions", "from_settings", "triage"}: `source` is
    "pinned" or "settings"; `from_settings` names the limits read from the current settings."""
    budgets = ((manifest or {}).get("ai_agent") or {}).get("budgets") or {}
    pinned = budgets.get("schema") == BUDGET_SCHEMA
    extensions = _extensions(repo, hunt_id)
    if getattr(settings, "_budget_hunt", "") == hunt_id:
        # already resolved for this hunt (hunt_settings): its values are the hunt's limits, extensions included
        limits = standard_limits(settings)
        return {"source": "pinned" if pinned else "settings", "profile": budgets.get("profile"),
                "base": None, "added": None, "limits": limits, "extensions": extensions,
                "from_settings": [] if pinned else _legacy_missing(budgets),
                "triage": {key: getattr(settings, field) for key, field in TRIAGE_LIMITS.items()}}
    current = standard_limits(settings)
    base, from_settings = {}, []
    for key in LIMITS:
        recorded = budgets.get(key)
        if key == "max_cost_usd" and key in budgets:
            recorded = recorded or 0.0           # an older record stores "no cost budget" as null
        if recorded is None:
            base[key] = current[key]
            from_settings.append(key)
        else:
            base[key] = _value(key, recorded)
    added = dict.fromkeys(LIMITS, 0)
    for row in extensions:
        for key, amount in (row.get("amounts") or {}).items():
            if key in added:
                added[key] = _value(key, added[key] + amount)
    limits = {key: _value(key, min(hard_maximum(key), base[key] + added[key])) for key in LIMITS}
    triage = budgets.get("triage") if pinned and isinstance(budgets.get("triage"), dict) else {}
    return {"source": "pinned" if pinned else "settings", "profile": budgets.get("profile") if pinned else None,
            "base": base, "added": added, "limits": limits, "extensions": extensions,
            "from_settings": [] if pinned else from_settings,
            "triage": {key: triage.get(key, getattr(settings, field)) for key, field in TRIAGE_LIMITS.items()}}


def _legacy_missing(budgets: dict) -> list[str]:
    return [key for key in LIMITS if budgets.get(key) is None and not (key == "max_cost_usd" and key in budgets)]


def hunt_settings(settings: Settings, repo, hunt_id: str, manifest: dict | None = None) -> Settings:
    """`settings` with the hunt's agent limits (pinned plus extensions) in place of the live ones, for one run of its
    agent or triage pass. Nothing is written back."""
    if getattr(settings, "_budget_hunt", "") == hunt_id:
        return settings
    if manifest is None:
        manifest = (repo.get_hunt(hunt_id) or {}).get("manifest") or {}
    resolved = resolve(repo, hunt_id, manifest, settings)
    update = {LIMITS[key]: value for key, value in resolved["limits"].items()}
    update.update({TRIAGE_LIMITS[key]: value for key, value in resolved["triage"].items()})
    copy = settings.model_copy(update=update)
    copy._budget_hunt = hunt_id
    return copy


def apply_main(limits, resolved_limits: dict):
    """BudgetLimits with the hunt-total model limits replaced by the resolved ones (prices are kept)."""
    return replace(limits, max_calls=int(resolved_limits["max_calls"]), max_tokens=int(resolved_limits["max_tokens"]),
                   max_wall_seconds=int(resolved_limits["max_wall_seconds"]),
                   max_cost_usd=float(resolved_limits["max_cost_usd"] or 0.0))


def extended_record(budgets: dict, repo, hunt_id: str) -> dict:
    """A manifest's recorded `ai_agent.budgets` with the hunt's extensions added to each limit it records (for a
    page or report that shows the limits in force)."""
    out = dict(budgets or {})
    for row in _extensions(repo, hunt_id):
        for key, amount in (row.get("amounts") or {}).items():
            if key in LIMITS and out.get(key) is not None:
                out[key] = _value(key, min(hard_maximum(key), out[key] + amount))
    return out


def with_extensions(limits, repo, hunt_id: str):
    """BudgetLimits recorded in a manifest, with the hunt's extensions added to its model-call limits."""
    added = dict.fromkeys(("max_calls", "max_tokens", "max_wall_seconds", "max_cost_usd"), 0)
    for row in _extensions(repo, hunt_id):
        for key, amount in (row.get("amounts") or {}).items():
            if key in added:
                added[key] += amount
    return apply_main(limits, {key: min(hard_maximum(key), getattr(limits, key) + added[key]) for key in added})


def extension(s: Settings, current: dict, *, role: str, profile: str | None = None,
              amounts: dict | None = None) -> dict:
    """The amounts one extension adds: explicit amounts (only EXTENDABLE limits), or what raises each limit to
    `profile`'s. The new totals are checked against the ceiling for `role`. Raises BudgetRefused."""
    if (profile is None) == (not amounts):
        raise BudgetRefused("give either amounts to add or a budget profile to raise the limits to")
    if profile is not None:
        target = profile_limits(s, profile)
        added = {key: _value(key, max(0, target[key] - current[key])) for key in LIMITS}
        added = {key: value for key, value in added.items() if value}
        if not added:
            raise BudgetRefused(f"every limit is already at or above the {profile} budget")
    else:
        added = {}
        for key, value in amounts.items():
            if value is None:
                continue
            if key not in EXTENDABLE:
                raise BudgetRefused(f"{key!r} cannot be extended by amount")
            if value < 0:
                raise BudgetRefused(f"{LABELS[key]} to add must not be negative")
            if value:
                added[key] = _value(key, value)
        if not added:
            raise BudgetRefused("nothing to add: every amount is 0")
        if "max_cost_usd" in added and not current.get("max_cost_usd"):
            raise BudgetRefused("this hunt's agent has no cost budget to extend")
    totals = {key: _value(key, current[key] + added.get(key, 0)) for key in LIMITS}
    above = check_limits(s, {key: totals[key] for key in added}, role)
    return {"amounts": added, "profile": profile, "totals": totals, "above_ceiling": sorted(above)}


def view(resolved: dict, usage: dict, source_queries: int, wall_seconds: float) -> list[dict]:
    """Rows for a page or report: each limit, what the manifest pinned, what extensions added, and what is spent."""
    spent = {"max_calls": usage.get("calls", 0), "max_tokens": usage.get("budget_tokens", usage.get("tokens", 0)),
             "max_wall_seconds": round(wall_seconds, 1), "max_cost_usd": usage.get("cost_usd"),
             "max_source_queries": source_queries}
    rows = []
    for key in LIMITS:
        base = (resolved.get("base") or {}).get(key)
        rows.append({"key": key, "label": LABELS[key], "pinned": base,
                     "added": (resolved.get("added") or {}).get(key, 0), "limit": resolved["limits"][key],
                     "spent": spent.get(key), "from_settings": key in resolved.get("from_settings", [])})
    return rows
