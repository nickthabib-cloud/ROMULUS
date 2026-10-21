"""Per-hunt agent budgets: calls, tokens, wall-clock time and an optional estimated cost.

Every budget is checked before each call against the worst case that call could use (its prompt estimate
plus the full output allowance), so a call never starts that could take the hunt past a limit. Spending
is rebuilt from the stored call rows, so a resumed hunt continues from what it has already used.
"""
from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass

from romulus.agent.provider.base import ChatResult, estimate_tokens
from romulus.config import Settings


@dataclass(frozen=True)
class BudgetLimits:
    max_calls: int
    max_tokens: int
    max_wall_seconds: int
    max_cost_usd: float              # 0: no cost budget
    price_input_per_mtok: float
    price_output_per_mtok: float

    @classmethod
    def from_settings(cls, s: Settings) -> BudgetLimits:
        return cls(s.agent_max_calls, s.agent_max_tokens, s.agent_max_wall_seconds, s.agent_max_cost_usd,
                   s.agent_price_input_per_mtok, s.agent_price_output_per_mtok)

    def as_dict(self) -> dict:
        return {"max_calls": self.max_calls, "max_tokens": self.max_tokens,
                "max_wall_seconds": self.max_wall_seconds,
                "max_cost_usd": self.max_cost_usd or None,
                "price_input_per_mtok": self.price_input_per_mtok or None,
                "price_output_per_mtok": self.price_output_per_mtok or None}

    def cost(self, prompt_tokens: int, completion_tokens: int) -> float:
        return (prompt_tokens * self.price_input_per_mtok + completion_tokens * self.price_output_per_mtok) / 1e6

    @property
    def priced(self) -> bool:
        return bool(self.price_input_per_mtok or self.price_output_per_mtok)


class BudgetExhausted(RuntimeError):
    def __init__(self, budget: str, detail: str):
        super().__init__(f"{budget} budget reached: {detail}")
        self.budget = budget
        self.detail = detail


def charged_tokens(result: ChatResult) -> tuple[int, int, bool]:
    """(prompt, completion, estimated): reported usage when the server gives it, else a text estimate."""
    if result.usage.reported:
        return int(result.usage.prompt_tokens or 0), int(result.usage.completion_tokens or 0), False
    completion = estimate_tokens(result.content + "".join(c.raw_arguments for c in result.tool_calls))
    return result.prompt_tokens_est, completion, True


class AgentBudget:
    def __init__(self, limits: BudgetLimits, *, calls: int = 0, tokens: int = 0, cost_usd: float = 0.0,
                 wall_seconds_before: float = 0.0, clock: Callable[[], float] = time.monotonic):
        self.limits = limits
        self.calls = calls
        self.tokens = tokens
        self.cost_usd = cost_usd
        self.estimated = False
        self.wall_seconds_before = wall_seconds_before
        self.clock = clock
        self.started = clock()

    @classmethod
    def from_usage(cls, limits: BudgetLimits, usage: dict, **kwargs) -> AgentBudget:
        """Continue from `Repo.agent_usage` totals."""
        budget = cls(limits, calls=int(usage.get("calls", 0)), tokens=int(usage.get("tokens", 0)),
                     cost_usd=float(usage.get("cost_usd", 0.0)), **kwargs)
        budget.estimated = bool(usage.get("estimated"))
        return budget

    def wall_seconds(self) -> float:
        return self.wall_seconds_before + (self.clock() - self.started)

    def check(self, prompt_tokens_est: int, max_output_tokens: int) -> None:
        lim = self.limits
        if self.calls + 1 > lim.max_calls:
            raise BudgetExhausted("calls", f"{self.calls} of {lim.max_calls} calls used")
        worst = prompt_tokens_est + max_output_tokens
        if self.tokens + worst > lim.max_tokens:
            raise BudgetExhausted("tokens", f"{self.tokens} of {lim.max_tokens} tokens used; the next call "
                                            f"could use up to {worst}")
        elapsed = self.wall_seconds()
        if elapsed >= lim.max_wall_seconds:
            raise BudgetExhausted("wall-clock", f"{elapsed:.0f} s of {lim.max_wall_seconds} s used")
        if lim.max_cost_usd:
            next_cost = lim.cost(prompt_tokens_est, max_output_tokens)
            if self.cost_usd + next_cost > lim.max_cost_usd:
                raise BudgetExhausted("cost", f"about ${self.cost_usd:.4f} of ${lim.max_cost_usd:.2f} used; the "
                                              f"next call could cost up to ${next_cost:.4f}")

    def charge(self, result: ChatResult) -> dict:
        """Record one completed call; returns what it was charged."""
        prompt, completion, estimated = charged_tokens(result)
        cost = self.limits.cost(prompt, completion)
        self.calls += 1
        self.tokens += prompt + completion
        self.cost_usd += cost
        self.estimated = self.estimated or estimated
        return {"prompt_tokens": prompt, "completion_tokens": completion, "cost_usd": cost, "estimated": estimated}

    def snapshot(self) -> dict:
        return {"calls": self.calls, "tokens": self.tokens,
                "cost_usd": round(self.cost_usd, 6) if self.limits.priced else None,
                "wall_seconds": round(self.wall_seconds(), 1), "usage_estimated": self.estimated,
                "limits": self.limits.as_dict()}
