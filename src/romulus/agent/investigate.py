"""Persisted, bounded hypothesis investigation over the A2 read and pivot tools."""
from __future__ import annotations

import json
import logging
import math
import threading
import uuid
from collections import deque
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, replace
from time import monotonic

from romulus.agent import hunt_budget
from romulus.agent.admission import (
    CUTTABLE_TEXT,
    AgentAdmission,
    text_limit,
    truncated_text,
    typed_alias_arguments,
)
from romulus.agent.assessment import SECRET_GUARD_SUMMARY, assess_output, run_assessment, template_assessment
from romulus.agent.dossier import build_dossier
from romulus.agent.grounding import triage_context
from romulus.agent.provider import (
    AgentBudget,
    BudgetExhausted,
    BudgetLimits,
    ChatRequest,
    ProviderUnavailable,
    SecretGuardTripped,
    charge_of,
    charge_parts,
    parts_of,
    record_call,
    record_failure,
    record_secret_guard,
)
from romulus.agent.provider.base import PROVIDER_STATE, ToolCall, estimate_tokens, redact_value
from romulus.agent.provider.budget import AgentStopped
from romulus.agent.refusals import bounded, reason, tool_result_reasons
from romulus.agent.toolbox import Toolbox
from romulus.agent.triage import latest_summary
from romulus.config import Settings, redact_text
from romulus.hunt.rank import place_late_findings
from romulus.report.incidents import build_incident_graph
from romulus.store.db import digest, utcnow
from romulus.store.repo import TRIAGE_PURPOSE, Repo, is_lease_lost

log = logging.getLogger("romulus.agent")


@dataclass
class AgentPhaseResult:
    state: str
    reason: str | None
    prompt_digests: dict
    provider: dict
    sessions: list[dict] = field(default_factory=list)
    limits_hit: list[str] = field(default_factory=list)
    unworked: list[str] = field(default_factory=list)
    usage: dict = field(default_factory=dict)
    # refused tool calls and assessment answers, as counts by tool and reason (field paths and error types only)
    refusals: dict = field(default_factory=dict)
    # sessions the secret guard ended, by setting name (never a value)
    secret_guard: dict = field(default_factory=dict)
    # the AI triage pass run before the assessment (its summary), when the phase ran one
    triage: dict | None = None

    def as_dict(self) -> dict:
        out = {"status": self.state, "reason": self.reason, "prompt_digests": self.prompt_digests,
               "provider": self.provider, "sessions": self.sessions, "limits_hit": self.limits_hit,
               "unworked": self.unworked, "usage": self.usage, "refusals": self.refusals}
        if self.secret_guard:
            out["secret_guard"] = self.secret_guard
        if self.triage is not None:
            out["ai_triage"] = self.triage
        return out


# The anthropic adapter's prompt-cache entries live five minutes from their last use. A prefix the previous call of a
# session read from or wrote to the cache is counted at the read weight only while that call started less than
# CACHE_TRUST_SECONDS ago: the minute of margin covers the time between the cache's use and the next call's start.
CACHE_TTL_SECONDS = 300.0
CACHE_TRUST_SECONDS = CACHE_TTL_SECONDS - 60.0
# A request's cache breakpoint looks back at most 20 content positions for the previous entry (a run of tool_use
# blocks, or of tool_result blocks, is one position). A request that appended more than this many since the previous
# call is reserved as written to the cache; the margin covers the wire format's own blocks.
CACHE_LOOKBACK_POSITIONS = 16
# A session's finish_session calls that may be refused before it ends capped: an over-long summary needs two.
FINISH_ATTEMPTS = 3
# The end reason of a session the secret guard ended (its state is `secret_guard`).
SECRET_GUARD_REASON = "secret_guard"
# The reason an analyst's stop request ended a session or the phase (a stopped session's state is `interrupted`).
# A run stopped this way is resumable: `hunt resume` continues it from its persisted work.
STOPPED_REASON = "stopped_by_analyst"


@dataclass
class _CachedPrefix:
    """What the previous call of an append-only session left in the configured model's prompt cache."""
    tokens: int             # prompt tokens that call read from or wrote to the cache
    since: float            # when that call started, on the budget's clock


@dataclass
class _Reservation:
    prompt_est: int
    max_output: int
    tokens: int
    cost: float
    purpose: str
    retry_budget: str | None = None
    cached: int = 0                         # prompt tokens reserved at the cache-read weight
    overrun: tuple[int, int] | None = None  # (charged, reserved) budget tokens when the charge exceeded the reservation


class _BudgetGate:
    """Reserve worst-case concurrent calls so parallel sessions cannot race past hunt caps.

    A call reserves its own worst case while it runs, and the assessment keeps its hold. The worst case is
    `BudgetLimits.worst_tokens_cached`: the prefix the session's previous call left in the configured model's prompt
    cache at the read weight while that entry is still alive (`CACHE_TRUST_SECONDS`), the rest of the prompt at the
    dearest weight, the full output and thinking allowance, and, only when the refusal fallback is on, one whole
    attempt by the fallback model (no shared cache: its prompt at the dearest weight). Without a live cached prefix it
    is `worst_tokens`. A charge that comes out above its reservation is recorded on the reservation (`overrun`). A call that fits beside what is already spent but not beside the live
    reservations of calls still in flight waits for them to settle (they almost always settle far below their worst
    case) instead of stopping its session; it stops only when it cannot fit even with nothing else in flight. Waiters
    are served in arrival order. The stop's detail states what was spent, reserved and held, and the limit."""

    # how often a waiting call re-checks the wall-clock budget while calls in flight hold their reservations
    WAIT_SECONDS = 5.0

    def __init__(self, budget: AgentBudget, settings: Settings, assess_output: int | None = None, *,
                 stop: Callable[[], str | None] | None = None,
                 refresh: Callable[[BudgetLimits], BudgetLimits | None] | None = None):
        self.budget = budget
        self.settings = settings
        # the assess call's own output limit (romulus.agent.assessment.assess_output), which its hold reserves
        self.assess_output = assess_output
        # `stop()`: what an analyst's open stop request says (None while there is none); `refresh(limits)`: the hunt's
        # limits now, raised by budget extensions added while the phase runs (None: unchanged). Both are cheap.
        self.stop = stop
        self.refresh = refresh
        self.lock = threading.Lock()
        self.changed = threading.Condition(self.lock)
        self.queue: deque[object] = deque()
        self.calls = 0
        self.tokens = 0
        self.cost = 0.0

    def stopped(self) -> str | None:
        """The open stop request's description, or None. A failing check never stops the agent by itself."""
        if self.stop is None:
            return None
        try:
            return self.stop()
        except Exception:  # noqa: BLE001 - a store hiccup is retried at the next safe point
            log.exception("could not read the hunt's stop request")
            return None

    def _refresh_limits(self) -> None:
        if self.refresh is None:
            return
        try:
            limits = self.refresh(self.budget.limits)
        except Exception:  # noqa: BLE001 - the limits in force stay until the next read
            log.exception("could not read the hunt's agent budget extensions")
            return
        if limits is not None and limits != self.budget.limits:
            with self.changed:
                self.budget.limits = limits
                self.changed.notify_all()

    def _reserve_for_assess(self, prompt: int, output: int) -> tuple[int, int, float, float]:
        limits = self.budget.limits
        output = self.assess_output or output
        fraction = self.settings.agent_assess_reserve_fraction
        calls = max(1, math.ceil(limits.max_calls * fraction))
        tokens = max(math.ceil(limits.max_tokens * fraction),
                     limits.worst_tokens(min(max(prompt, 4096), 16_000), output))
        cost = max(limits.max_cost_usd * fraction,
                   limits.worst_cost(min(max(prompt, 4096), 16_000), output)) if limits.max_cost_usd else 0.0
        wall = max(limits.max_wall_seconds * fraction, min(limits.max_wall_seconds, 60.0))
        return calls, tokens, cost, wall

    def _over(self, prompt: int, output: int, purpose: str, tokens: int, cost: float, *,
              live: bool, cached: int = 0) -> BudgetExhausted | None:
        """Why this call cannot start now (None when it can): against what is spent, the assessment's hold and, with
        `live`, the reservations of calls in flight. Called with the lock held."""
        limits, spent = self.budget.limits, self.budget
        try:
            spent.check(prompt, output, worst_tokens=tokens)
        except BudgetExhausted as exc:
            return exc
        basis = (f" ({cached} prompt tokens still in the prompt cache counted at the read weight)" if cached
                 else "")
        held_calls, held_tokens, held_cost, held_wall = (
            self._reserve_for_assess(prompt, output) if purpose != "assess" else (0, 0, 0.0, 0.0))
        in_flight = (self.calls, self.tokens, self.cost) if live else (0, 0, 0.0)
        if spent.calls + in_flight[0] + 1 + held_calls > limits.max_calls:
            return BudgetExhausted("calls", (
                f"{spent.calls} of {limits.max_calls} calls used, {in_flight[0]} in flight, {held_calls} held for "
                "the assessment"))
        if spent.budget_tokens + in_flight[1] + tokens + held_tokens > limits.max_tokens:
            return BudgetExhausted("tokens", (
                f"{spent.budget_tokens} of {limits.max_tokens} budget tokens (weighted by price) spent, {tokens} "
                f"reserved for this call's worst case{basis}, {in_flight[1]} reserved by calls in flight, "
                f"{held_tokens} held for the assessment"))
        if limits.max_cost_usd and spent.cost_usd + in_flight[2] + cost + held_cost > limits.max_cost_usd:
            return BudgetExhausted("cost", (
                f"about ${spent.cost_usd:.4f} of ${limits.max_cost_usd:.2f} spent, ${cost:.4f} reserved for this "
                f"call's worst case, ${in_flight[2]:.4f} reserved by calls in flight, ${held_cost:.4f} held for the "
                "assessment"))
        if held_wall and spent.wall_seconds() + held_wall >= limits.max_wall_seconds:
            return BudgetExhausted("wall-clock", (
                f"{spent.wall_seconds():.0f} s of {limits.max_wall_seconds} s used, {held_wall:.0f} s held for the "
                "assessment"))
        return None

    def cached_tokens(self, prefix: _CachedPrefix | None) -> int:
        """The prompt tokens of `prefix` still in the cache now: none once the entry may have expired."""
        if prefix is None or self.budget.clock() - prefix.since >= CACHE_TRUST_SECONDS:
            return 0
        return prefix.tokens

    def reserve(self, prompt: int, output: int, purpose: str, *,
                prefix: _CachedPrefix | None = None) -> _Reservation:
        stopped = self.stopped()
        if stopped:
            raise AgentStopped(stopped)
        self._refresh_limits()
        limits = self.budget.limits
        cost = limits.worst_cost(prompt, output)
        ticket = object()
        with self.changed:
            self.queue.append(ticket)
            try:
                while True:
                    if self.queue[0] is ticket:
                        limits = self.budget.limits
                        # decided when the call may start: a wait can outlast the cache entry
                        cached = self.cached_tokens(prefix)
                        tokens = limits.worst_tokens_cached(prompt, cached, output)
                        # never past a limit with nothing else in flight: a stop, since spending only grows
                        alone = self._over(prompt, output, purpose, tokens, cost, live=False, cached=cached)
                        if alone is not None:
                            raise alone
                        if self._over(prompt, output, purpose, tokens, cost, live=True, cached=cached) is None:
                            self.calls += 1
                            self.tokens += tokens
                            self.cost += cost
                            return _Reservation(prompt, output, tokens, cost, purpose, cached=cached)
                    # it fits once the calls in flight settle, or it is not this call's turn yet
                    self.changed.wait(self.WAIT_SECONDS)
                    stopped = self.stopped()
                    if stopped:
                        raise AgentStopped(stopped)
            finally:
                self.queue.remove(ticket)
                self.changed.notify_all()

    def settle(self, reservation: _Reservation, result=None, error: BaseException | None = None) -> None:
        with self.changed:
            self.calls -= 1
            self.tokens -= reservation.tokens
            self.cost -= reservation.cost
            try:
                charged = None
                if error is not None:
                    charged = self.budget.charge_failure(error)
                elif result is not None:
                    charged = self.budget.charge(result)
                if charged is not None and charged["budget_tokens"] > reservation.tokens:
                    reservation.overrun = (int(charged["budget_tokens"]), reservation.tokens)
            finally:
                self.changed.notify_all()

    def attempt_guard(self, reservation: _Reservation, billed: dict) -> bool:
        parts = parts_of(billed.get("billed"))
        if not billed.get("retry_available"):
            return True
        limits = self.budget.limits
        used = charge_parts(parts)
        extra_tokens = limits.worst_tokens(reservation.prompt_est, reservation.max_output)
        extra_cost = limits.worst_cost(reservation.prompt_est, reservation.max_output)
        with self.lock:
            tokens = (self.budget.budget_tokens + max(0, self.tokens - reservation.tokens)
                      + limits.budget_tokens(used) + extra_tokens)
            cost = self.budget.cost_usd + max(0.0, self.cost - reservation.cost) + limits.charge_cost(used) + extra_cost
            if tokens > limits.max_tokens:
                reservation.retry_budget = "tokens"
            elif limits.max_cost_usd and cost > limits.max_cost_usd:
                reservation.retry_budget = "cost"
            elif self.budget.wall_seconds() >= limits.max_wall_seconds:
                reservation.retry_budget = "wall-clock"
            return reservation.retry_budget is None


def _prompt(name: str) -> str:
    from importlib.resources import files
    return files("romulus.agent").joinpath("prompts", name).read_text(encoding="utf-8")


def _prompt_set() -> dict[str, str]:
    names = ("system.md", "orient.md", "investigate.md", "assess.md")
    return {name: _prompt(name) for name in names}


def _agent_usage(repo: Repo, hunt_id: str) -> dict:
    """The agent's own calls: the triage pass spends from its own budget and reports its usage in its summary."""
    return repo.agent_usage(hunt_id, exclude_purposes=(TRIAGE_PURPOSE,))


def _triage_record(summary: dict) -> dict:
    """What the phase's stored summary keeps of its triage pass (the pass's full summary is stored on its own)."""
    record = {key: summary[key] for key in ("status", "reason", "pass", "reused", "model") if key in summary}
    if isinstance(summary.get("cited"), dict):
        record["cited"] = {key: summary["cited"][key] for key in (
            "status", "reason", "groups", "triaged", "untriaged_cited_skipped", "paragraphs_strength_changed",
            "regrounded_revision") if key in summary["cited"]}
    return record


def _store_template(repo: Repo, hunt_id: str, reason: str, *, owner_token=None) -> dict:
    existing = repo.agent_assessments(hunt_id)
    if existing:
        latest = existing[-1]
        if latest.get("source") in {"template", "agent"}:
            return latest
    template = template_assessment(repo, hunt_id, reason)
    revision = len(existing) + 1
    row = {"id": "aa-" + uuid.uuid4().hex[:20], "hunt_id": hunt_id, "revision": revision,
           "source": "template", "model": {}, "body": template["body"], "checker": {}, "created_at": utcnow()}
    repo.save_agent_assessment(row, owner_token=owner_token)
    return row


def _place_late_ranks(repo: Repo, hunt_id: str, *, owner_token=None) -> None:
    """Place the findings this run stored after the final ranking pass into it. It runs before the run is final, so a
    crash in between is repeated by recovery. Ranking only orders findings: its failure never fails the agent run."""
    try:
        place_late_findings(repo, hunt_id, owner_token=owner_token)
    except Exception as exc:  # ordering cannot undo the agent's stored work
        if is_lease_lost(exc):
            raise
        log.exception("could not rank the findings stored after the final ranking pass")


def _finalize(repo: Repo, hunt_id: str, result: AgentPhaseResult, *, started_at=None,
              owner_token=None) -> AgentPhaseResult:
    _place_late_ranks(repo, hunt_id, owner_token=owner_token)
    result.refusals = repo.agent_refusal_counts(hunt_id)
    result.secret_guard = repo.agent_secret_guard_counts(hunt_id)
    stored = result.as_dict()
    if result.triage is not None:
        stored["ai_triage"] = _triage_record(result.triage)
    repo.finalize_agent_run(hunt_id, {
        "state": result.state, "reason": result.reason, "prompt_digests": result.prompt_digests,
        "provider": result.provider, "started_at": started_at, "ended_at": utcnow(),
    }, owner_token=owner_token, summary=stored)
    return result


def skip_agent_phase(settings: Settings, repo: Repo, hunt_id: str, reason: str, *, provider: dict | None = None,
                     prompt_digests: dict | None = None, owner_token=None) -> AgentPhaseResult:
    """Record an off or unavailable phase without touching deterministic hunt state."""
    _store_template(repo, hunt_id, reason, owner_token=owner_token)
    result = AgentPhaseResult("skipped", reason[:500], prompt_digests or {}, provider or {},
                              usage=_agent_usage(repo, hunt_id))
    return _finalize(repo, hunt_id, result, owner_token=owner_token)


def stop_agent_phase(settings: Settings, repo: Repo, hunt_id: str, detail: str, *, provider: dict | None = None,
                     owner_token=None) -> AgentPhaseResult:
    """Record an agent phase an analyst stopped before it made any call: `partial` (resumable), with STOPPED_REASON
    and who stopped it. The latest stored assessment stands; without one, the template says why there is none."""
    existing = repo.agent_run(hunt_id) or {}
    _store_template(repo, hunt_id, STOPPED_REASON, owner_token=owner_token)
    result = AgentPhaseResult("partial", f"{STOPPED_REASON}: {detail}"[:500], existing.get("prompt_digests") or {},
                              existing.get("provider") or provider or {}, usage=_agent_usage(repo, hunt_id),
                              unworked=_unworked(repo, hunt_id))
    return _finalize(repo, hunt_id, result, started_at=existing.get("started_at"), owner_token=owner_token)


def fail_agent_phase(repo: Repo, hunt_id: str, reason: str, *, owner_token=None) -> dict:
    existing = repo.agent_run(hunt_id) or {}
    try:
        _store_template(repo, hunt_id, reason, owner_token=owner_token)
    except Exception as exc:  # noqa: BLE001 - fallback persistence must never fail the detection run.
        if is_lease_lost(exc):
            return AgentPhaseResult("partial", "lease_lost", {}, {}).as_dict()
        reason = f"{reason}; template_error:{type(exc).__name__}"[:500]
    result = AgentPhaseResult("failed", reason[:500], existing.get("prompt_digests") or {},
                              existing.get("provider") or {}, usage=_agent_usage(repo, hunt_id))
    try:
        return _finalize(repo, hunt_id, result, started_at=existing.get("started_at") or utcnow(),
                         owner_token=owner_token).as_dict()
    except Exception as exc:  # noqa: BLE001 - fallback persistence must never fail the detection run.
        if is_lease_lost(exc):
            return AgentPhaseResult("partial", "lease_lost", {}, {}).as_dict()
        # An unavailable store cannot persist its own failure. Never bypass ownership to report it.
        return result.as_dict()


def _id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:20]}"


def _candidate_views(repo: Repo, hunt_id: str) -> list[dict]:
    return [{"id": row["id"], "lane": row["lane"], "rule_id": row["rule_id"],
             "observed_at": str(row["ts"]) if row["ts"] is not None else None,
             "entities": row.get("entities") or [], "event_ids": row.get("event_ids") or [],
             "citations": [], "source_link_id": row.get("source_link_id")}
            for row in repo.candidates(hunt_id, ["urgent", "high", "lead"])]


def _controller_open_hypotheses(settings, repo, hunt_id: str, session_id: str, admission: AgentAdmission) -> None:
    if repo.agent_hypotheses(hunt_id):
        return
    candidates = repo.candidates(hunt_id, ["urgent", "high", "lead"])
    if not candidates:
        return
    graph = build_incident_graph(repo, hunt_id, _candidate_views(repo, hunt_id))
    by_id = {row["id"]: row for row in candidates}
    lane_priority = {"urgent": 3, "high": 2, "lead": 1}
    ordered = sorted(graph["incidents"], key=lambda incident: (
        -max((lane_priority.get(by_id[item]["lane"], 0) for item in incident["finding_ids"] if item in by_id),
             default=0), incident["id"]))
    existing_support = {row["target_id"] for hypothesis in repo.agent_hypotheses(hunt_id)
                        for row in repo.agent_hypothesis_cites(hypothesis_id=hypothesis["id"])
                        if row["role"] == "support" and row["target_kind"] == "finding"}
    for incident in ordered:
        if len(repo.agent_hypotheses(hunt_id)) >= min(settings.agent_max_initial_hypotheses,
                                                      settings.agent_max_hypotheses):
            break
        top = min((by_id[item] for item in incident["finding_ids"] if item in by_id),
                  key=lambda row: (-lane_priority.get(row["lane"], 0), -float(row["priority"]), row["id"]))
        if top["id"] in existing_support:
            continue
        incident_alias = admission.aliases.alias_for("I", incident["id"])
        statement = f"Investigate incident {incident_alias}: {top['claim']}"
        if len(statement) < 10:
            statement = f"Investigate incident {incident_alias} and review its cited finding."
        try:
            admission.create_controller_hypothesis(statement, finding_id=top["id"], alias=incident_alias)
        except ValueError:
            break
        existing_support.add(top["id"])


def _hypothesis_context(repo: Repo, hunt_id: str, hypothesis: dict, summaries: list[dict],
                        *, owner_token=None) -> dict:
    from romulus.agent.aliases import AliasBook
    aliases = AliasBook(repo, hunt_id, owner_token=owner_token)
    cites = repo.agent_hypothesis_cites(hypothesis_id=hypothesis["id"])
    mapped_cites = []
    kind_map = {"finding": "F", "evidence": "E", "link": "L", "agent_link": "A"}
    for cite in cites:
        mapped_cites.append({"role": cite["role"], "alias": aliases.alias_for(kind_map[cite["target_kind"]], cite["target_id"])})
    entities = [aliases.alias_for("N", item) for item in hypothesis.get("entity_ids") or []]
    body = {"alias": aliases.alias_for("H", hypothesis["id"]), "statement": hypothesis["statement"],
            "techniques": hypothesis["techniques"], "entities": entities, "status": hypothesis["status"],
            "confidence": hypothesis["confidence"], "questions": hypothesis["questions"], "cites": mapped_cites,
            "previous_sessions": summaries}
    return body


def _summaries(repo: Repo, hunt_id: str, hypothesis_id: str) -> list[dict]:
    sessions = [row for row in repo.agent_sessions(hunt_id, hypothesis_id=hypothesis_id, purpose="investigate")
                if row["state"] != "running"]
    rows = [{"state": row["state"], "summary": row.get("summary", ""), "started_at": str(row["started_at"])}
            for row in sessions]
    joined = json.dumps(rows, ensure_ascii=False, sort_keys=True)
    omitted = 0
    while len(joined) > 6000 and rows:
        rows.pop(0)
        omitted += 1
        joined = json.dumps(rows, ensure_ascii=False, sort_keys=True)
    return ([{"omitted_earlier_summaries": omitted, "message": f"{omitted} earlier summaries omitted."}] if omitted else []) + rows


def _touched_entities(repo: Repo, hunt_id: str) -> set[str]:
    touched = set()
    resolved: dict[str, str | None] = {}
    for call in repo.agent_tool_calls(hunt_id):
        if call.get("status") == "refused":
            continue
        for alias in typed_alias_arguments(call["name"], call.get("arguments")):
            if not alias.startswith("N"):
                continue
            if alias not in resolved:
                row = repo.agent_alias(hunt_id, alias)
                resolved[alias] = row["target_id"] if row and row["kind"] == "N" else None
            if resolved[alias] is not None:
                touched.add(resolved[alias])
    return touched


def _priority(repo: Repo, hunt_id: str, hypothesis: dict, touched: set[str]) -> tuple:
    supports = [row for row in repo.agent_hypothesis_cites(hypothesis_id=hypothesis["id"])
                if row["role"] == "support" and row["target_kind"] == "finding"]
    finding_ids = [row["target_id"] for row in supports]
    candidates = {row["id"]: row for row in repo.candidates_by_ids(finding_ids, hunt_id=hunt_id)}
    lane = max(({"urgent": 3, "high": 2, "lead": 1}.get(row["lane"], 0) for row in candidates.values()), default=0)
    untouched = sum(item not in touched for item in hypothesis.get("entity_ids") or [])
    return (-lane, -len(hypothesis.get("questions") or []), -untouched,
            str(hypothesis["created_at"]), hypothesis["id"])


def _session_tools(toolbox: Toolbox) -> list:
    return toolbox.provider_tools()


# A session's reads (every tool that only looks at hunt state or telemetry): AGENT_MAX_TOOL_CALLS_PER_SESSION covers
# its pivots, plus one read for each unit of input it is handed that it can only see by reading it: each dossier index
# page after the first an orient session is shown (one list_findings call each), each finding an investigate session's
# hypothesis cites (one get_finding call each). The extra never exceeds TOOL_CALL_EXTRA_FACTOR times the base, so one
# session stays bounded however large the hunt; the hunt's model-call, token and wall-clock budgets bound the sessions
# together.
TOOL_CALL_EXTRA_FACTOR = 3
# The tools that record the session's work. They never count against the reads, so a session that has read all it may
# can still record what it found and finish. What they store is bounded per hunt by the agent's own caps (hypotheses,
# findings, links, notes, rule requests: AGENT_MAX_*), enforced at admission; this allowance bounds only how many a
# session may attempt, refused ones included, at the largest number of reads a session can ever have.
WRITE_TOOLS = frozenset({"open_hypothesis", "update_hypothesis", "propose_finding", "propose_link", "add_note",
                         "request_rule"})


def _tool_call_allowance(settings: Settings, *, reads: int) -> int:
    base = settings.agent_max_tool_calls_per_session
    return base + min(max(0, reads), TOOL_CALL_EXTRA_FACTOR * base)


def _write_allowance(settings: Settings) -> int:
    return settings.agent_max_tool_calls_per_session * (1 + TOOL_CALL_EXTRA_FACTOR)


def _cited_findings(repo: Repo, hypothesis_id: str) -> int:
    return len({row["target_id"] for row in repo.agent_hypothesis_cites(hypothesis_id=hypothesis_id)
                if row["target_kind"] == "finding"})


def _overlong_field(name: str, arguments, reasons) -> str | None:
    """The free-text field a write or finish_session call was refused for alone, by its length (None otherwise)."""
    field = CUTTABLE_TEXT.get(name, (None, None))[0]
    if field is None or reasons != [reason(field, "string_too_long")]:
        return None
    return field if isinstance(arguments, dict) and isinstance(arguments.get(field), str) else None


def _overlong_retry(toolbox: Toolbox, name: str, field: str, arguments: dict, attempt: int) -> tuple[dict, list[str]]:
    """The first over-length text in a field is refused with the limit and its length (numbers only, never its text).
    The next is accepted cut to the limit at a sentence end, with a marker saying so, and recorded under the reason
    `<field>: truncated_by_product`: the session's work is never lost to text that will not fit."""
    limit = text_limit(CUTTABLE_TEXT[name][1], field)
    length = len(arguments[field])
    too_long = reason(field, "string_too_long")
    if attempt == 1:
        message = (f"{field} has {length} characters; {name} accepts at most {limit}. Call {name} again with a "
                   f"{field} of at most {limit} characters; another over-length {field} is cut to fit and marked as "
                   "truncated.")
        refused = {"status": "refused", "coverage": {"status": "complete", "gaps": []},
                   "counts": {"returned": 0, "total": 0}, "more": False, "errors": [message],
                   "data": {"error": {"code": f"{field}_too_long", "message": message, "length": length,
                                      "limit": limit, "reasons": [too_long]}}}
        return refused, [too_long]
    accepted = toolbox.execute(name, {**arguments, field: truncated_text(arguments[field], limit, field)})
    return accepted, [reason(field, "truncated_by_product")]


def _cache_basis(result, request: ChatRequest, prompt_est: int, started_at: float) -> dict | None:
    """What a completed call left in the configured model's prompt cache, for the session's next reservation: the
    prompt tokens its served attempt read from or wrote to the cache, its reported prompt and output, and the request
    they belong to. None when the call is no basis for that: usage estimated, no cache use reported, a reply a
    fallback model served (the configured model's cache holds none of it) or one that did not complete."""
    if result.status not in ("ok", "invalid_json", "invalid_tool_call", "truncated_output"):
        return None
    if (result.details or {}).get("fallback"):
        return None
    charge = charge_of(result)
    served = charge.parts[-1] if charge.parts else charge
    cached = served.cache_read + served.cache_write
    if charge.estimated or cached <= 0:
        return None
    return {"messages": len(request.messages), "digest": digest(request.messages), "prompt": served.prompt,
            "completion": served.completion, "prompt_est": prompt_est, "cached": cached, "since": started_at}


def _cache_positions(messages: list[dict]) -> int:
    """The content positions `messages` add to a request, as the cache lookback counts them: every block, a run of
    tool calls or of tool results counting once. Counted generously (each message's text is one position)."""
    positions, last = 0, None
    for message in messages:
        role = message.get("role")
        if role == "assistant":
            state = message.get(PROVIDER_STATE) or {}
            kinds = [block.get("type") for block in state.get("content") or [] if isinstance(block, dict)] or (
                ["text"] + (["tool_use"] if message.get("tool_calls") else []))
        else:
            kinds = ["tool_result" if role == "tool" else "text"]
        for kind in kinds:
            if not (kind == last and kind in ("tool_use", "tool_result")):
                positions += 1
            last = kind
    return positions


def _without_secrets(call: ToolCall, settings: Settings) -> ToolCall:
    """The tool call with every configured secret's text removed from its name and arguments (unchanged when none
    holds any)."""
    name = redact_text(call.name, settings)
    arguments = redact_value(call.arguments, settings) if call.arguments is not None else None
    raw = redact_text(call.raw_arguments, settings)
    if name == call.name and arguments == call.arguments and raw == call.raw_arguments:
        return call
    return replace(call, name=name, arguments=arguments, raw_arguments=raw)


# How a tool call to a name that is not a registered tool is stored, counted and summarised: the model made the name
# up, and a made-up name is model text that is never kept.
UNKNOWN_TOOL = "?"


def _stored_name(name: str, toolbox: Toolbox) -> str:
    return name if name in toolbox.registry else UNKNOWN_TOOL


def _deterministic_tool_summary(calls: list[tuple[str, str]], changes: list[dict]) -> str:
    recent = calls[-10:]
    steps = "; ".join(f"{name}: {status}" for name, status in recent) or "no tool calls"
    changed = f"; {len(changes)} hypothesis change(s) recorded" if changes else ""
    return f"Session stopped after {steps}{changed}."[:2000]


def _run_session(settings: Settings, repo: Repo, hunt_id: str, provider, budget_gate: _BudgetGate,
                 toolbox_factory: Callable[[str], Toolbox], prompts: dict[str, str],
                 *, purpose: str, hypothesis: dict | None = None, owner_token=None,
                 heartbeat: Callable[[], None] | None = None) -> dict:
    session_id = _id("as")
    now = utcnow()
    hypothesis_id = hypothesis["id"] if hypothesis else None
    heartbeat = heartbeat or (lambda: None)
    session_saved = False
    admission = None
    tool_history: list[tuple[str, str]] = []
    hypothesis_changes: list[dict] = []
    tool_count = 0
    no_tool_misses = 0
    finish_retried = False
    context_wrap_sent = False
    call_seq = 0
    provider_unavailable = False
    call_limit = settings.agent_max_tool_calls_per_session
    write_limit = _write_allowance(settings)
    read_count = write_count = 0
    reads_closed = writes_closed = False
    overlong: dict[str, int] = {}
    finish_refusals = 0
    # what the previous call left in the prompt cache, and the request it was made with (see `_BudgetGate`)
    cache_basis: dict | None = None
    cache_trusted = True
    overruns = 0

    def finish(state: str, final_summary: str, reason: str | None = None) -> dict:
        # a summary can quote the model (its finish_session text, a refusal, an error): stored without any secret
        final_summary = redact_text(final_summary, settings)
        outcome = {"id": session_id, "hypothesis_id": hypothesis_id, "purpose": purpose, "state": state,
                   "summary": final_summary[:2000], "reason": reason,
                   "provider_unavailable": provider_unavailable, "tool_call_limit": call_limit,
                   "write_call_limit": write_limit, "reservation_overruns": overruns,
                   "limits_hit": sorted(admission.limits_hit) if admission is not None else []}
        if session_saved:
            try:
                repo.update_agent_session(session_id, hunt_id, {
                    "state": state, "summary": final_summary[:2000], "tool_calls": tool_count, "ended_at": utcnow(),
                }, owner_token=owner_token)
            except Exception as exc:
                if is_lease_lost(exc):
                    raise
                outcome.update(state="failed", reason="controller_error",
                               summary=f"Controller error: {type(exc).__name__}: {exc}"[:2000])
        return outcome

    try:
        heartbeat()
        repo.save_agent_session({"id": session_id, "hunt_id": hunt_id, "hypothesis_id": hypothesis_id,
                                 "purpose": purpose, "state": "running", "tool_calls": 0, "summary": "",
                                 "started_at": now, "ended_at": None}, owner_token=owner_token)
        session_saved = True
        if hypothesis_id:
            repo.increment_agent_hypothesis_sessions(hypothesis_id, hunt_id, owner_token=owner_token)
        toolbox = toolbox_factory(session_id)
        admission = AgentAdmission(settings, repo, hunt_id, session_id, hypothesis_id=hypothesis_id,
                                   owner_token=owner_token, purpose=purpose)
        admission.register(toolbox)
        tools = _session_tools(toolbox)
        followable = None
        if getattr(toolbox.executor, "followable_links", None) is not None:
            # remembered across the dossier rebuilds below: each unfinished expansion anchor is planned once per
            # session (they are at most the dossier's materialization cap of reportable findings)
            known: dict[str, tuple[str, ...] | None] = {}

            def followable(finding_id: str) -> tuple[str, ...]:
                if finding_id not in known:
                    known[finding_id] = toolbox.followable_kinds(finding_id)
                return known[finding_id] or ()
        system_text = prompts["system.md"]
        if purpose == "orient":
            orientation = prompts["orient.md"]
            shell = ChatRequest(messages=[{"role": "system", "content": system_text + "\n\n" + orientation},
                                          {"role": "user", "content": ""}], tools=tools, tool_choice="auto")
            context_limit = provider.context_tokens() or settings.agent_context_tokens
            room = (max(1, int(context_limit * 0.85) - estimate_tokens(shell.prompt_text()) -
                        provider.output_limit(shell) - 512) if context_limit else 24_000)
            # Pagination estimates canonical data; measure the actual request envelope too.
            for _ in range(4):
                dossier = build_dossier(repo, hunt_id, token_budget=room, owner_token=owner_token,
                                        followable=followable)
                page = dossier.page(1)
                user = {"message": "Dossier index page 1 of " + str(len(dossier.pages)) +
                        "; call list_findings for the rest.", "page": page}
                messages = [{"role": "system", "content": system_text + "\n\n" + orientation},
                            {"role": "user", "content": json.dumps(user, sort_keys=True, ensure_ascii=False,
                                                                  default=str, separators=(",", ":"))}]
                request = ChatRequest(messages=messages, tools=tools, tool_choice="auto")
                excess = (estimate_tokens(request.prompt_text()) + provider.output_limit(request)
                          - int(context_limit * 0.85)) if context_limit else 0
                if excess <= 0:
                    break
                room = max(1, room - excess - 128)
            if excess > 0:
                return finish("context_full", "Orient input exceeds the available context budget.", "context_full")
            admission.issue_aliases(page, source="dossier")
            call_limit = _tool_call_allowance(settings, reads=len(dossier.pages) - 1)
        else:
            call_limit = _tool_call_allowance(settings, reads=_cited_findings(repo, hypothesis_id))
            context = _hypothesis_context(repo, hunt_id, hypothesis, _summaries(repo, hunt_id, hypothesis_id),
                                          owner_token=owner_token)
            dossier = build_dossier(repo, hunt_id, token_budget=1000, owner_token=owner_token)
            admission.issue_aliases(context, source="hypothesis")
            messages = [{"role": "system", "content": system_text + "\n\n" + prompts["investigate.md"]},
                        {"role": "user", "content": json.dumps({"dossier_header": {
                            "header": dossier.payload.get("header"), "scope": dossier.payload.get("scope")},
                            "hypothesis": context}, sort_keys=True, ensure_ascii=False, default=str)}]
        while True:
            request = ChatRequest(messages=messages, tools=tools, tool_choice="auto")
            prompt_est = estimate_tokens(request.prompt_text())
            ctx = provider.context_tokens()
            max_out = provider.output_limit(request)
            over_context = bool(ctx and prompt_est > ctx * 0.85)
            if over_context and context_wrap_sent:
                return finish("context_full", _deterministic_tool_summary(tool_history, hypothesis_changes),
                              "estimated prompt reached 85% of context")
            if over_context:
                messages.append({"role": "user", "content": "Context is nearly full. Call finish_session now "
                                "with a concise summary; no further investigation is needed in this session."})
                context_wrap_sent = True
                request = ChatRequest(messages=messages, tools=tools, tool_choice="auto")
                prompt_est = estimate_tokens(request.prompt_text())
                max_out = provider.output_limit(request)
            # an append-only session: the previous request is this one's prefix, and that call's cached prompt tokens
            # are still in the cache (while its entry lives); the prompt is bounded by that call's reported prompt,
            # its output (the reply goes back), and the estimated growth since
            prefix, prompt_bound = None, prompt_est
            if (cache_basis is not None and cache_trusted and len(messages) >= cache_basis["messages"]
                    and digest(messages[:cache_basis["messages"]]) == cache_basis["digest"]
                    and _cache_positions(messages[cache_basis["messages"]:]) <= CACHE_LOOKBACK_POSITIONS):
                prompt_bound = max(prompt_est, cache_basis["prompt"] + cache_basis["completion"]
                                   + max(0, prompt_est - cache_basis["prompt_est"]))
                prefix = _CachedPrefix(cache_basis["cached"], cache_basis["since"])
            # before the reservation: nothing between reserving and the call may raise without settling it
            heartbeat()
            try:
                reservation = budget_gate.reserve(prompt_bound, max_out, purpose, prefix=prefix)
            except AgentStopped as exc:
                log.info("agent session %s stopped: %s", session_id, exc.detail)
                return finish("interrupted", f"Stopped by analyst ({exc.detail}). "
                              + _deterministic_tool_summary(tool_history, hypothesis_changes), STOPPED_REASON)
            except BudgetExhausted as exc:
                log.info("agent session %s stopped: %s", session_id, exc)
                stopped = f"Budget stop: {exc}. " + _deterministic_tool_summary(tool_history, hypothesis_changes)
                return finish("budget", stopped, f"budget:{exc.budget}")
            request.attempt_guard = lambda info, reservation=reservation: budget_gate.attempt_guard(reservation, info)
            started = monotonic()
            started_at = budget_gate.budget.clock()
            try:
                result = provider.chat(request)
            except ProviderUnavailable as exc:
                exc.duration_ms = max(int(getattr(exc, "duration_ms", 0) or 0),
                                      int((monotonic() - started) * 1000))
                budget_gate.settle(reservation, error=exc)
                record_failure(repo, provider, hunt_id=hunt_id, purpose=purpose, request=request, error=exc,
                               limits=budget_gate.budget.limits, session_id=session_id, owner_token=owner_token)
                provider_unavailable = True
                return finish("failed", _deterministic_tool_summary(tool_history, hypothesis_changes),
                              f"budget:{reservation.retry_budget}" if reservation.retry_budget else
                              "provider_unavailable")
            except SecretGuardTripped as exc:
                # An earlier reply of this session holds a configured secret's text. It is signed provider state
                # that can be neither redacted nor sent, and the session is append-only, so it ends here: nothing
                # more is sent in it, and what it already wrote is kept. Names and parts only, never the text.
                budget_gate.settle(reservation)
                record_secret_guard(repo, hunt_id=hunt_id, purpose=purpose, session_id=session_id, error=exc,
                                    owner_token=owner_token)
                names = ", ".join(sorted({setting for setting, _ in exc.trips}))
                log.warning("agent session %s ended by the secret guard (%s)", session_id, names)
                return finish("secret_guard", (
                    f"Secret guard: an earlier reply in this session held the text of a configured secret ({names}), "
                    "so the session ended before anything more was sent; its recorded work is kept. "
                    + _deterministic_tool_summary(tool_history, hypothesis_changes)), SECRET_GUARD_REASON)
            except BaseException as exc:
                # settled on every exit: a reservation left behind would hold a sibling's call waiting
                budget_gate.settle(reservation)
                if is_lease_lost(exc) or not isinstance(exc, Exception):
                    raise
                return finish("failed", f"Provider call failed: {type(exc).__name__}: {exc}"[:2000],
                              "provider_error")
            budget_gate.settle(reservation, result=result)
            heartbeat()
            model_call_id = record_call(repo, provider, hunt_id=hunt_id, purpose=purpose, request=request,
                                        result=result, limits=budget_gate.budget.limits, session_id=session_id,
                                        owner_token=owner_token, settings=settings)
            if reservation.overrun is not None:
                # the charge came out above the reservation (the cache did not hold what it was counted for): this
                # session reserves every later prompt as written to the cache, and stops if the limit was crossed
                overruns += 1
                cache_trusted = False
                charged, reserved = reservation.overrun
                spent, limits = budget_gate.budget.budget_tokens, budget_gate.budget.limits
                log.warning("agent session %s: a call was charged %d budget tokens against %d reserved",
                            session_id, charged, reserved)
                if spent > limits.max_tokens:
                    return finish("budget", (
                        f"Budget stop: tokens budget exceeded: a call was charged {charged} budget tokens against "
                        f"{reserved} reserved, and {spent} of {limits.max_tokens} budget tokens are spent. "
                        + _deterministic_tool_summary(tool_history, hypothesis_changes)), "budget:tokens")
            cache_basis = _cache_basis(result, request, prompt_est, started_at) if cache_trusted else None
            if result.status in {"too_large", "truncated_input"}:
                return finish("context_full", result.error or "Provider reported an oversized or truncated input.",
                              "context_full")
            if result.status == "refused":
                return finish("refused", result.error or "Provider refused this session.", "refused")
            messages.append(result.assistant_message())
            if not result.tool_calls:
                if context_wrap_sent:
                    return finish("context_full", _deterministic_tool_summary(tool_history, hypothesis_changes),
                                  "context wrap-up did not finish the session")
                if reads_closed or writes_closed:
                    return finish("capped", _deterministic_tool_summary(tool_history, hypothesis_changes),
                                  "tool-call wrap-up did not finish the session")
                no_tool_misses += 1
                if no_tool_misses == 1:
                    messages.append({"role": "user", "content": "Reply with a tool call; call finish_session to end."})
                    continue
                return finish("failed", _deterministic_tool_summary(tool_history, hypothesis_changes),
                              "no_tool_call_twice")
            no_tool_misses = 0
            # the calls as they are run and stored: any configured secret's text the model wrote is removed first
            # (its turn, kept unchanged for replay, then ends the session at the secret guard)
            calls = [_without_secrets(call, settings) for call in result.tool_calls]
            if context_wrap_sent:
                finish_call = next((call for call in calls if call.name == "finish_session"), None)
                if finish_call is None:
                    for call in calls:
                        call_seq += 1
                        raw = call.raw_arguments[:8192]
                        arguments = call.arguments if call.arguments is not None else raw
                        refused = {"status": "refused", "errors": ["context is nearly full; only finish_session is allowed"]}
                        repo.save_agent_tool_call({"id": _id("atc"), "hunt_id": hunt_id, "session_id": session_id,
                                                   "seq": call_seq, "name": _stored_name(call.name, toolbox),
                                                   "arguments": arguments,
                                                   "arguments_truncated": len(call.raw_arguments.encode()) > 8192,
                                                   "status": "refused", "result_digest": digest(refused),
                                                   "refusal_reasons": [reason("$", "tool_call_limit")],
                                                   "model_call_id": model_call_id, "created_at": utcnow()},
                                                  owner_token=owner_token)
                    return finish("context_full", _deterministic_tool_summary(tool_history, hypothesis_changes),
                                  "context wrap-up did not finish the session")
                allowed_calls = [finish_call]
            else:
                allowed_calls = calls
            executed = finish_tried = False
            for call in allowed_calls:
                call_seq += 1
                kind = ("finish" if call.name == "finish_session" else "write" if call.name in WRITE_TOOLS
                        else "read")
                if kind == "read" and read_count >= call_limit:
                    tool_result = {"status": "refused", "errors": [
                        "read limit reached; only the write tools and finish_session are allowed"]}
                    reasons = [reason("$", "tool_call_limit")]
                elif kind == "write" and write_count >= write_limit:
                    tool_result = {"status": "refused", "errors": ["write limit reached; call finish_session"]}
                    reasons = [reason("$", "write_call_limit")]
                else:
                    tool_count += 1
                    read_count += kind == "read"
                    write_count += kind == "write"
                    executed = executed or kind != "finish"
                    if call.error:
                        # the provider refused the arguments before any tool ran
                        tool_result = {"status": "refused", "errors": [call.error]}
                        reasons = bounded(call.problems) or [reason("$", "invalid_arguments")]
                    else:
                        heartbeat()
                        stopped = budget_gate.stopped()
                        if stopped and kind == "read":
                            # a read may start source queries: none starts after a stop (a write only records)
                            return finish("interrupted", f"Stopped by analyst ({stopped}). "
                                          + _deterministic_tool_summary(tool_history, hypothesis_changes),
                                          STOPPED_REASON)
                        tool_result = toolbox.execute(call.name, call.arguments)
                        reasons = tool_result_reasons(tool_result)
                        field = _overlong_field(call.name, call.arguments, reasons)
                        if field is not None:
                            key = f"{call.name}.{field}"
                            overlong[key] = overlong.get(key, 0) + 1
                            # after the context wrap-up there is no further turn to correct it in
                            tool_result, reasons = _overlong_retry(
                                toolbox, call.name, field, call.arguments, 2 if context_wrap_sent else overlong[key])
                finish_tried = finish_tried or kind == "finish"
                if kind == "finish" and tool_result.get("status") != "complete":
                    finish_refusals += 1
                raw_args = call.raw_arguments.encode("utf-8")
                if call.arguments is not None:
                    stored_args = call.arguments
                    truncated = False
                else:
                    stored_args = raw_args[:8192].decode("utf-8", errors="replace")
                    truncated = len(raw_args) > 8192
                status = tool_result.get("status", "failed")
                admission.issue_aliases(tool_result, tool_name=call.name)
                repo.save_agent_tool_call({"id": _id("atc"), "hunt_id": hunt_id, "session_id": session_id,
                                           "seq": call_seq, "name": _stored_name(call.name, toolbox),
                                           "arguments": stored_args,
                                           "arguments_truncated": truncated, "status": status,
                                           "result_digest": digest(tool_result), "refusal_reasons": reasons,
                                           "model_call_id": model_call_id, "created_at": utcnow()},
                                          owner_token=owner_token)
                repo.update_agent_session(session_id, hunt_id, {"tool_calls": tool_count}, owner_token=owner_token)
                tool_history.append((_stored_name(call.name, toolbox), status))
                if call.name == "update_hypothesis" and status == "complete":
                    hypothesis_changes.append(tool_result.get("data") or {})
                messages.append({"role": "tool", "tool_call_id": call.id,
                                 "content": json.dumps(tool_result, sort_keys=True, ensure_ascii=False, default=str)})
                if call.name == "finish_session" and status == "complete":
                    summary = str((tool_result.get("data") or {}).get("summary") or "Session finished.")
                    end_state = "context_full" if context_wrap_sent else "finished"
                    return finish(end_state, summary, "context_full" if context_wrap_sent else None)
            if context_wrap_sent:
                continue
            if finish_refusals >= FINISH_ATTEMPTS:
                return finish("capped", _deterministic_tool_summary(tool_history, hypothesis_changes),
                              f"finish_session refused {finish_refusals} times")
            closing = []
            if not reads_closed and read_count >= call_limit:
                reads_closed = True
                closing.append("read")
            if not writes_closed and write_count >= write_limit:
                writes_closed = True
                closing.append("write")
            if closing:
                # a spent kind closes; the session may still use the other and must then finish
                writes = ", ".join(sorted(name for name in WRITE_TOOLS if name in toolbox.registry))
                left = ("finish_session" if writes_closed or not writes
                        else f"{writes} and finish_session")
                messages.append({"role": "user", "content": (
                    f"Tool-call limit reached for {' and '.join(closing)} tools in this session. "
                    + ("Only " + left + " remain. Record what you found, then call finish_session with a summary."
                       if reads_closed else "Call finish_session with a summary when the remaining reads are done."))})
                continue
            if (reads_closed or writes_closed) and finish_tried:
                if not finish_retried:
                    # finish_session was refused (its result says why): one corrected call is allowed
                    messages.append({"role": "user", "content": "finish_session was refused; its result says why. "
                                     "Call finish_session once more with a corrected summary."})
                    finish_retried = True
                    continue
                return finish("capped", _deterministic_tool_summary(tool_history, hypothesis_changes),
                              "wrap_up_not_finished")
            if (reads_closed or writes_closed) and not executed:
                return finish("capped", _deterministic_tool_summary(tool_history, hypothesis_changes),
                              "tool-call limit reached and the reply used no remaining tool")
    except Exception as exc:
        if is_lease_lost(exc):
            raise
        return finish("failed", f"Controller error: {type(exc).__name__}: {exc}"[:2000], "controller_error")


def _unworked(repo: Repo, hunt_id: str) -> list[str]:
    return [row["id"] for row in repo.agent_hypotheses(hunt_id)
            if row["status"] == "open" and int(row.get("sessions_run") or 0) == 0]


def _has_open_questions(hypothesis: dict) -> bool:
    return bool(hypothesis.get("questions"))


def _next_hypotheses(settings: Settings, repo: Repo, hunt_id: str) -> list[dict]:
    rows = [row for row in repo.agent_hypotheses(hunt_id) if row["status"] == "open" and
            int(row.get("sessions_run") or 0) < settings.agent_max_sessions_per_hypothesis]
    if not rows:
        return []
    minimum = min(int(row.get("sessions_run") or 0) for row in rows)
    round_rows = [row for row in rows if int(row.get("sessions_run") or 0) == minimum]
    touched = _touched_entities(repo, hunt_id)
    return sorted(round_rows, key=lambda row: _priority(repo, hunt_id, row, touched))


def _investigation_done(repo: Repo, hunt_id: str) -> bool:
    open_rows = [row for row in repo.agent_hypotheses(hunt_id) if row["status"] == "open"]
    return not open_rows or all(int(row.get("sessions_run") or 0) >= 1 and not _has_open_questions(row)
                                for row in open_rows)


def _recover_running_sessions(repo: Repo, hunt_id: str, *, owner_token=None) -> None:
    for session in repo.agent_sessions(hunt_id):
        if session["state"] == "running":
            repo.interrupt_running_agent_session(session["id"], hunt_id, owner_token=owner_token)


def _budget(settings: Settings, manifest: dict, repo: Repo, hunt_id: str, clock) -> AgentBudget:
    config = ((manifest.get("ai_agent") or {}).get("budgets") or {})
    required = {"max_calls", "max_tokens", "max_wall_seconds"}
    limits = (BudgetLimits.from_dict(config, str((manifest.get("ai_agent") or {}).get("model") or ""))
              if required <= config.keys() else BudgetLimits.from_settings(settings))
    # the hunt's limits: what its manifest pinned plus every budget extension (prices stay as recorded)
    limits = hunt_budget.apply_main(limits, hunt_budget.resolve(repo, hunt_id, manifest, settings)["limits"])
    # the triage pass spends from its own budget, never the agent's
    return AgentBudget.from_usage(limits, repo.agent_usage(hunt_id, exclude_purposes=(TRIAGE_PURPOSE,)),
                                  wall_seconds_before=repo.agent_elapsed_ms(
                                      hunt_id, exclude_purposes=(TRIAGE_PURPOSE,)) / 1000.0, clock=clock)


def recover_agent_finalization(repo: Repo, hunt_id: str, *, owner_token=None) -> AgentPhaseResult | None:
    """Finalize persisted finished work without a provider, prompts, or source preflight."""
    existing = repo.agent_run(hunt_id)
    sessions = repo.agent_sessions(hunt_id)
    assessments = repo.agent_assessments(hunt_id)
    if (existing and existing.get("state") == "running" and sessions and assessments
            and not any(row["state"] == "running" for row in sessions)
            and sessions[-1]["purpose"] == "assess"
            and str(assessments[-1]["created_at"]) >= str(sessions[-1]["started_at"])
            and all(str(row.get("ended_at") or row["started_at"]) <= str(assessments[-1]["created_at"])
                    for row in sessions if row["purpose"] != "assess")):
        # Session rows cannot prove that no admission cap was reached before the crash.
        summary = str(sessions[-1].get("summary") or "")
        reason = summary if summary.startswith("budget:") else "recovered_finished_sessions"
        session_views = [{key: row.get(key) for key in
                          ("id", "hypothesis_id", "purpose", "state", "summary", "tool_calls")} for row in sessions]
        recovered = AgentPhaseResult("partial", reason,
                                     existing.get("prompt_digests") or {},
                                     existing.get("provider") or {}, session_views,
                                     usage=_agent_usage(repo, hunt_id))
        return _finalize(repo, hunt_id, recovered, started_at=existing.get("started_at"),
                         owner_token=owner_token)
    return None


def run_agent_phase(settings: Settings, repo: Repo, hunt_id: str, *, provider,
                    toolbox_factory: Callable[[str], Toolbox], owner_token: str | None = None,
                    clock: Callable[[], float] = monotonic,
                    heartbeat: Callable[[], None] | None = None,
                    triage: Callable[[Callable[[], None]], dict] | None = None,
                    stop: Callable[[], str | None] | None = None,
                    refresh: Callable[[BudgetLimits], BudgetLimits | None] | None = None) -> AgentPhaseResult:
    """Run bounded agent work; losing ownership never triggers another fenced write. `triage(heartbeat)` runs the AI
    triage pass under this phase's lease and returns its summary; given, it runs after the investigation and before
    the assessment, whose input then carries its verdicts. `stop()` describes an analyst's open stop request (None
    while there is none): the phase checks it before every model call, before every read tool call and between rounds,
    and once it is set starts no further model call; it keeps what it stored, records the template assessment and ends
    `partial` with STOPPED_REASON. `refresh(limits)` returns the hunt's limits raised by extensions added meanwhile."""
    try:
        return _run_agent_phase(settings, repo, hunt_id, provider=provider, toolbox_factory=toolbox_factory,
                                owner_token=owner_token, clock=clock, heartbeat=heartbeat, triage=triage,
                                stop=stop, refresh=refresh)
    except Exception as exc:
        if not is_lease_lost(exc):
            raise
        return AgentPhaseResult("partial", "lease_lost", {}, {})


def _triage_before_assess(repo: Repo, hunt_id: str, triage, budget: AgentBudget,
                          heartbeat: Callable[[], None]) -> dict:
    """Run the triage pass (its own budget and model) and keep its wall time out of the agent's budget. It reads only
    deterministic findings, so it never depends on the assessment. Any failure but a lost lease is its summary."""
    started = budget.clock()
    try:
        if not repo.reportable_count(hunt_id):
            return {"status": "skipped", "reason": "no surfaced findings"}
        return triage(heartbeat)
    except Exception as exc:
        if is_lease_lost(exc):
            raise
        log.exception("AI triage before the assessment failed")
        return {"status": "failed", "reason": f"triage_error: {type(exc).__name__}: {exc}"[:300]}
    finally:
        budget.exclude_wall(budget.clock() - started)


def _triage_cited(settings: Settings, repo: Repo, hunt_id: str, triage, assessment: dict, context,
                  budget: AgentBudget, heartbeat: Callable[[], None], *, owner_token=None) -> dict:
    """After the assessment: triage the groups of the Reported findings its narrative cites that the pass left without
    a verdict (`triage(heartbeat, cited=...)`, on the pass's model and budget, its wall time kept out of the agent's),
    then ground the stored narrative again with the new verdicts and store it as the next revision. The model's text
    is unchanged. With no new verdict (a failure, a timeout, a spent budget, nothing to triage) the stored grounding
    stands as it is: a missing verdict is never benign. Returns what was done, with the reason."""
    from romulus.agent.assessment import cited_triage_groups, reground_narrative, save_assessment_revision
    started = budget.clock()
    out: dict = {}
    published = False
    try:
        groups, skipped = cited_triage_groups(repo, hunt_id, assessment["ungrounded"], context,
                                              settings.agent_triage_cited_max_groups)
        out = {"groups": len(groups), "untriaged_cited_skipped": skipped}
        if not groups:
            return {**out, "status": "skipped",
                    "reason": "no cited group lacks a verdict" if not skipped else "AGENT_TRIAGE_CITED_MAX_GROUPS is 0"}
        heartbeat()
        result = triage(heartbeat, cited=groups)
        out.update({key: result[key] for key in ("status", "reason", "triaged", "by_assessment") if key in result})
        if not result.get("triaged"):
            return out
        published = True
        regrounded = triage_context(latest_summary(repo, hunt_id))
        narrative, checker, changed = reground_narrative(
            repo, hunt_id, assessment["ungrounded"], assessment["body"]["narrative"], assessment["checker"],
            regrounded)
        checker = {**checker, "regrounded_after_cited_triage": 1, "paragraphs_strength_changed": changed,
                   **({"untriaged_cited_skipped": skipped} if skipped else {})}
        revision = save_assessment_revision(repo, {
            "id": _id("aa"), "hunt_id": hunt_id, "source": "agent", "model": assessment["model"],
            "body": {**assessment["body"], "narrative": narrative}, "checker": checker, "created_at": utcnow()},
            owner_token=owner_token)
        return {**out, "regrounded_revision": revision, "paragraphs_strength_changed": changed}
    except Exception as exc:
        if is_lease_lost(exc):
            raise
        # once verdicts are published, a failure leaves the stored grounding behind the pass: said apart
        stage = "reground_error" if published else "triage_error"
        log.exception("AI triage of the narrative's cited groups failed (%s)", stage)
        return {**out, "status": "failed", "reason": f"{stage}: {type(exc).__name__}: {exc}"[:300]}
    finally:
        budget.exclude_wall(budget.clock() - started)


def _run_agent_phase(settings: Settings, repo: Repo, hunt_id: str, *, provider,
                    toolbox_factory: Callable[[str], Toolbox], owner_token: str | None = None,
                    clock: Callable[[], float] = monotonic,
                    heartbeat: Callable[[], None] | None = None,
                    triage: Callable[[Callable[[], None]], dict] | None = None,
                    stop: Callable[[], str | None] | None = None,
                    refresh: Callable[[BudgetLimits], BudgetLimits | None] | None = None) -> AgentPhaseResult:
    """Run persisted sessions before atomically finalizing their deterministic result projection. The phases run in
    order: orient, investigate, the AI triage pass (when given), assess."""
    heartbeat = heartbeat or (lambda: None)
    heartbeat()
    hunt = repo.get_hunt(hunt_id)
    if hunt is None:
        raise KeyError(hunt_id)
    recovered = recover_agent_finalization(repo, hunt_id, owner_token=owner_token)
    if recovered is not None:
        return recovered
    prompts = _prompt_set()
    prompt_digests = {name: digest(text) for name, text in prompts.items()}
    provider_data = provider.describe()
    existing = repo.agent_run(hunt_id)
    if existing and existing.get("state") == "completed" and repo.agent_assessments(hunt_id):
        return AgentPhaseResult("completed", existing.get("reason"), existing.get("prompt_digests") or {},
                                existing.get("provider") or provider_data, usage=_agent_usage(repo, hunt_id))
    _recover_running_sessions(repo, hunt_id, owner_token=owner_token)
    budget = _budget(settings, hunt["manifest"], repo, hunt_id, clock)
    gate = _BudgetGate(budget, settings, assess_output=assess_output(settings, provider).limit)
    gate.stop, gate.refresh = stop, refresh
    start = existing.get("started_at") if existing and existing.get("started_at") else utcnow()
    repo.save_agent_run({"hunt_id": hunt_id, "state": "running", "reason": None,
                         "prompt_digests": prompt_digests,
                         "provider": {**provider_data, "models_reported": _agent_usage(repo, hunt_id).get("models_reported", [])},
                         "started_at": start, "ended_at": None}, owner_token=owner_token)
    all_sessions = []
    limits_hit: set[str] = set()
    reasons: list[str] = []
    assessment_stale = False
    assessment_fault = False
    orient = {}
    reportable_count = repo.candidate_count_lanes(hunt_id, ("urgent", "high", "lead"))
    orient_finished = any(row["purpose"] == "orient" and row["state"] == "finished"
                          for row in repo.agent_sessions(hunt_id))
    stopped = gate.stopped()
    if stopped:
        reasons.append(STOPPED_REASON)
    if reportable_count and not orient_finished and not stopped:
        assessment_stale = True
        orient = _run_session(settings, repo, hunt_id, provider, gate, toolbox_factory, prompts,
                              purpose="orient", owner_token=owner_token, heartbeat=heartbeat)
        all_sessions.append(orient)
        limits_hit.update(orient.get("limits_hit") or [])
        if orient.get("reason"):
            reasons.append(orient["reason"])
        orient_rows = repo.agent_sessions(hunt_id, purpose="orient")
        latest_orient = orient_rows[-1] if orient_rows else None
        if latest_orient and not str(orient.get("reason") or "").startswith("controller_error"):
            admission = AgentAdmission(settings, repo, hunt_id, latest_orient["id"], owner_token=owner_token,
                                       purpose="orient")
            _controller_open_hypotheses(settings, repo, hunt_id, latest_orient["id"], admission)
            limits_hit.update(admission.limits_hit)

    consecutive_outages = 1 if reportable_count and not orient_finished and orient.get("provider_unavailable") else 0
    stop_scheduling = str(orient.get("reason") or "").startswith("controller_error") or bool(stopped)
    while not stop_scheduling:
        stopped = gate.stopped()
        if stopped:
            break
        batch = _next_hypotheses(settings, repo, hunt_id)
        if not batch:
            break
        room = batch[:settings.agent_concurrency]
        assessment_stale = True
        before = {row["id"]: int(row.get("sessions_run") or 0) for row in room}
        # Breadth-first round selection in _next_hypotheses means every selected hypothesis is distinct.
        completed = []
        with ThreadPoolExecutor(max_workers=len(room), thread_name_prefix="romulus-agent") as pool:
            futures = {pool.submit(_run_session, settings, repo, hunt_id, provider, gate, toolbox_factory, prompts,
                                   purpose="investigate", hypothesis=hypothesis, owner_token=owner_token,
                                   heartbeat=heartbeat): hypothesis
                       for hypothesis in room}
            for future in as_completed(futures):
                try:
                    outcome = future.result()
                except Exception as exc:
                    if is_lease_lost(exc):
                        raise
                    outcome = {"state": "failed", "reason": f"controller_error: {type(exc).__name__}: {exc}"}
                completed.append(outcome)
                all_sessions.append(outcome)
                limits_hit.update(outcome.get("limits_hit") or [])
                if outcome.get("provider_unavailable"):
                    consecutive_outages += 1
                    if consecutive_outages >= 2:
                        stop_scheduling = True
                else:
                    consecutive_outages = 0
                if outcome.get("reason"):
                    reasons.append(outcome["reason"])
        if stop_scheduling:
            reasons.append("provider_unavailable")
        if any(str(row.get("reason") or "").startswith("controller_error") for row in completed):
            break
        after = {row["id"]: int(row.get("sessions_run") or 0) for row in repo.agent_hypotheses(hunt_id)}
        if not any(after.get(key, count) > count for key, count in before.items()):
            reasons.append("no_progress")
            break
        if any(str(row.get("reason") or "").startswith("budget:") for row in completed):
            reasons.extend(row["reason"] for row in completed if str(row.get("reason") or "").startswith("budget:"))
            break
        if _investigation_done(repo, hunt_id):
            break

    stopped = stopped or gate.stopped() or next(
        (STOPPED_REASON for session in all_sessions if session.get("reason") == STOPPED_REASON), None)
    if stopped and STOPPED_REASON not in reasons:
        reasons.append(STOPPED_REASON)
    existing_assessments = repo.agent_assessments(hunt_id)
    triage_summary = None
    if stopped:
        # an analyst stopped the agent: no further model call (no triage pass, no assessment). The latest stored
        # assessment stands; without one, the template says why there is none.
        try:
            _store_template(repo, hunt_id, STOPPED_REASON, owner_token=owner_token)
        except Exception as exc:
            if is_lease_lost(exc):
                raise
            assessment_fault = True
            reasons.append(f"template_error:{type(exc).__name__}")
        assessment = {"stopped": True}
    elif existing_assessments and existing_assessments[-1].get("source") == "agent" and not assessment_stale:
        assessment = {"revision": existing_assessments[-1]["revision"], "body": existing_assessments[-1]["body"]}
    else:
        # the triage pass runs only when an assessment is about to: its verdicts are part of the assess input
        if triage is not None:
            # the investigation stored all it will: place its late findings into the final ranking first, so the
            # pass reads the order the report will show and stays current (the assessment adds no findings)
            _place_late_ranks(repo, hunt_id, owner_token=owner_token)
            triage_summary = _triage_before_assess(repo, hunt_id, triage, budget, heartbeat)
        context = triage_context(triage_summary, enabled=triage is not None or settings.agent_triage == "on")
        stopped = gate.stopped()
        if stopped:
            # stopped during the triage pass: no assessment call; the latest stored assessment stands
            reasons.append(STOPPED_REASON)
            try:
                _store_template(repo, hunt_id, STOPPED_REASON, owner_token=owner_token)
            except Exception as exc:
                if is_lease_lost(exc):
                    raise
                assessment_fault = True
                reasons.append(f"template_error:{type(exc).__name__}")
            assessment = {"stopped": True}
        else:
            try:
                assessment = run_assessment(settings, repo, hunt_id, provider, budget, owner_token=owner_token,
                                            clock=clock, heartbeat=heartbeat, triage=context)
            except Exception as exc:
                if is_lease_lost(exc):
                    raise
                assessment_fault = True
                assessment = None
                reasons.append(f"assessment_error:{type(exc).__name__}")
        if (assessment is not None and not assessment.get("stopped") and triage is not None and context.usable
                and not gate.stopped()):
            triage_summary = {**triage_summary, "cited": _triage_cited(
                settings, repo, hunt_id, triage, assessment, context, budget, heartbeat, owner_token=owner_token)}
    if assessment is None:
        assessment_sessions = repo.agent_sessions(hunt_id, purpose="assess")
        assessment_reason = ((assessment_sessions[-1].get("summary") or "") if assessment_sessions else "")
        if assessment_reason.startswith("budget:") or assessment_reason == "provider_unavailable":
            reasons.append(assessment_reason)
        elif assessment_reason.startswith("context_full"):
            reasons.append("context_full")
        # the assessment's own retry tripped the secret guard (an investigate session's trip is not the reason)
        assess_guarded = assessment_reason.startswith(SECRET_GUARD_SUMMARY)
        reason = next((item for item in reasons if item.startswith("budget:")), None)
        if reason is None:
            reason = ("provider_unavailable" if "provider_unavailable" in reasons else
                      "context_full" if "context_full" in reasons else
                      SECRET_GUARD_REASON if assess_guarded else "assessment_not_produced")
        try:
            _store_template(repo, hunt_id, reason, owner_token=owner_token)
        except Exception as exc:
            if is_lease_lost(exc):
                raise
            assessment_fault = True
            reasons.append(f"template_error:{type(exc).__name__}")
        reasons.append(reason)
    limits_hit.update(item for session in all_sessions for item in session.get("limits_hit", []))
    # each hunt-total or session-share source-query cap a pivot reached (persisted, so a resume keeps it): the
    # investigation was budget-limited. Per-call caps are routine and counted on the run page only.
    caps = getattr(repo, "agent_source_query_caps", None)
    if caps is not None:
        limits_hit.update(f"cap:source_queries:{kind}" for kind in caps(hunt_id, limiting_only=True))
    state ="failed" if assessment_fault else "partial" if limits_hit or reasons or assessment is None else "completed"
    if consecutive_outages >= 2 and not assessment_fault:
        state = "partial"
    reason = "; ".join(dict.fromkeys([*sorted(limits_hit), *reasons])) or None
    usage = _agent_usage(repo, hunt_id)
    provider_data = {**provider_data, "models_reported": usage.get("models_reported", [])}
    heartbeat()
    result = AgentPhaseResult(state, reason, prompt_digests, provider_data, all_sessions,
                              sorted(limits_hit), _unworked(repo, hunt_id), usage, triage=triage_summary)
    return _finalize(repo, hunt_id, result, started_at=start, owner_token=owner_token)
