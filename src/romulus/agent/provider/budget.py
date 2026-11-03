"""Per-hunt agent budgets: calls, tokens, wall-clock time and an optional estimated cost.

Every budget is checked before each call against the worst case that call could use (its prompt estimate
plus the full output allowance), so a call never starts that could take the hunt past a limit. Spending
is rebuilt from the stored call rows, so a resumed hunt continues from what it has already used.

Prompt tokens a provider reads from or writes to its prompt cache are priced at their own rates. An unset cache
read price is the input price (cache reads never cost more than uncached input). An unset cache write price is
the input price, or for the anthropic provider 1.25 times it, the documented price of the five-minute cache
writes that adapter makes. The worst case of the next call prices its whole prompt at the dearest of the three.
"""
from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass

from romulus.agent.provider.base import ChatResult, estimate_tokens
from romulus.config import Settings

# the anthropic adapter's cache writes use the default five-minute lifetime, priced at 1.25x the input price
ANTHROPIC_CACHE_WRITE_MULTIPLIER = 1.25


@dataclass(frozen=True)
class BudgetLimits:
    max_calls: int
    max_tokens: int
    max_wall_seconds: int
    max_cost_usd: float              # 0: no cost budget
    price_input_per_mtok: float
    price_output_per_mtok: float
    price_cache_read_per_mtok: float = 0.0    # 0: the input price
    price_cache_write_per_mtok: float = 0.0   # 0: the input price

    @classmethod
    def from_settings(cls, s: Settings) -> BudgetLimits:
        write = s.agent_price_cache_write_per_mtok
        if not write and s.agent_provider == "anthropic":
            write = s.agent_price_input_per_mtok * ANTHROPIC_CACHE_WRITE_MULTIPLIER
        return cls(s.agent_max_calls, s.agent_max_tokens, s.agent_max_wall_seconds, s.agent_max_cost_usd,
                   s.agent_price_input_per_mtok, s.agent_price_output_per_mtok,
                   s.agent_price_cache_read_per_mtok, write)

    def as_dict(self) -> dict:
        out = {"max_calls": self.max_calls, "max_tokens": self.max_tokens,
               "max_wall_seconds": self.max_wall_seconds,
               "max_cost_usd": self.max_cost_usd or None,
               "price_input_per_mtok": self.price_input_per_mtok or None,
               "price_output_per_mtok": self.price_output_per_mtok or None}
        # cache prices only where they apply, so the record of an unpriced or uncached agent keeps its shape
        if self.price_cache_read_per_mtok:
            out["price_cache_read_per_mtok"] = self.price_cache_read_per_mtok
        if self.price_cache_write_per_mtok:
            out["price_cache_write_per_mtok"] = self.price_cache_write_per_mtok
        return out

    @property
    def cache_read_price(self) -> float:
        return self.price_cache_read_per_mtok or self.price_input_per_mtok

    @property
    def cache_write_price(self) -> float:
        return self.price_cache_write_per_mtok or self.price_input_per_mtok

    def cost(self, prompt_tokens: int, completion_tokens: int, cache_read_tokens: int = 0,
             cache_write_tokens: int = 0) -> float:
        """`prompt_tokens` counts every prompt token; the cache read and write tokens are the parts of it that
        are priced at the cache rates."""
        uncached = max(prompt_tokens - cache_read_tokens - cache_write_tokens, 0)
        return (uncached * self.price_input_per_mtok + cache_read_tokens * self.cache_read_price
                + cache_write_tokens * self.cache_write_price
                + completion_tokens * self.price_output_per_mtok) / 1e6

    def worst_cost(self, prompt_tokens: int, completion_tokens: int) -> float:
        """The most a call with this prompt and output allowance can cost, however its prompt is cached."""
        prompt_price = max(self.price_input_per_mtok, self.cache_read_price, self.cache_write_price)
        return (prompt_tokens * prompt_price + completion_tokens * self.price_output_per_mtok) / 1e6

    @property
    def priced(self) -> bool:
        return bool(self.price_input_per_mtok or self.price_output_per_mtok)


class BudgetExhausted(RuntimeError):
    def __init__(self, budget: str, detail: str):
        super().__init__(f"{budget} budget reached: {detail}")
        self.budget = budget
        self.detail = detail


@dataclass(frozen=True)
class Charge:
    """What one call is charged: every prompt token (cached or not), the cached parts, and the output."""
    prompt: int
    completion: int
    cache_read: int = 0
    cache_write: int = 0
    estimated: bool = False


def charge_of(result: ChatResult) -> Charge:
    """Reported usage when the server gives it (including every attempt the provider billed for one call, when it
    reports them), else a text estimate."""
    billed = (result.details or {}).get("billed")
    if isinstance(billed, dict):
        return Charge(int(billed.get("prompt", 0)), int(billed.get("completion", 0)),
                      int(billed.get("cache_read", 0)), int(billed.get("cache_write", 0)))
    usage = result.usage
    if usage.reported:
        return Charge(int(usage.prompt_tokens or 0), int(usage.completion_tokens or 0),
                      int(usage.cache_read_tokens or 0), int(usage.cache_write_tokens or 0))
    completion = estimate_tokens(result.content + "".join(c.raw_arguments for c in result.tool_calls))
    return Charge(result.prompt_tokens_est, completion, estimated=True)


def charged_tokens(result: ChatResult) -> tuple[int, int, bool]:
    """(prompt, completion, estimated): reported usage when the server gives it, else a text estimate."""
    charge = charge_of(result)
    return charge.prompt, charge.completion, charge.estimated


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
        """`max_output_tokens` is the provider's `output_limit(request)`: for adapters whose models think, it
        includes the thinking allowance."""
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
            next_cost = lim.worst_cost(prompt_tokens_est, max_output_tokens)
            if self.cost_usd + next_cost > lim.max_cost_usd:
                raise BudgetExhausted("cost", f"about ${self.cost_usd:.4f} of ${lim.max_cost_usd:.2f} used; the "
                                              f"next call could cost up to ${next_cost:.4f}")

    def charge(self, result: ChatResult) -> dict:
        """Record one completed call; returns what it was charged."""
        charge = charge_of(result)
        cost = self.limits.cost(charge.prompt, charge.completion, charge.cache_read, charge.cache_write)
        self.calls += 1
        self.tokens += charge.prompt + charge.completion
        self.cost_usd += cost
        self.estimated = self.estimated or charge.estimated
        return {"prompt_tokens": charge.prompt, "completion_tokens": charge.completion,
                "cache_read_tokens": charge.cache_read, "cache_write_tokens": charge.cache_write,
                "cost_usd": cost, "estimated": charge.estimated}

    def snapshot(self) -> dict:
        return {"calls": self.calls, "tokens": self.tokens,
                "cost_usd": round(self.cost_usd, 6) if self.limits.priced else None,
                "wall_seconds": round(self.wall_seconds(), 1), "usage_estimated": self.estimated,
                "limits": self.limits.as_dict()}
