"""Per-hunt agent budgets: calls, tokens, wall-clock time and an optional estimated cost.

Every budget is checked before each call against the worst case that call could use (its prompt estimate
plus the full output allowance), so a call never starts that could take the hunt past a limit. Spending
is rebuilt from the stored call rows, so a resumed hunt continues from what it has already used.

Prompt tokens a provider reads from or writes to its prompt cache are priced at their own rates. An unset cache
read price is the input price (cache reads never cost more than uncached input). An unset cache write price is
the input price, or for the anthropic provider 1.25 times it, the documented price of the five-minute cache
writes that adapter makes. The worst case of the next call prices its whole prompt at the dearest of the three.

With the anthropic refusal fallback on, another model may answer a call the configured model declined, at its
own prices, after the declined attempt was billed too. Each billed attempt is priced by the model that served it
(an attempt whose model is unknown at the dearer of the two price lists), and the worst case of the next call
reserves one full attempt at each model's prices.
"""
from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field

from romulus.agent.provider.base import ChatResult, estimate_tokens
from romulus.config import Settings

# the anthropic adapter's cache writes use the default five-minute lifetime, priced at 1.25x the input price
ANTHROPIC_CACHE_WRITE_MULTIPLIER = 1.25


@dataclass(frozen=True)
class Prices:
    """USD per million tokens."""
    input: float
    output: float
    cache_read: float
    cache_write: float

    def cost(self, prompt: int, completion: int, cache_read: int = 0, cache_write: int = 0) -> float:
        uncached = max(prompt - cache_read - cache_write, 0)
        return (uncached * self.input + cache_read * self.cache_read + cache_write * self.cache_write
                + completion * self.output) / 1e6

    def worst(self, prompt: int, completion: int) -> float:
        return (prompt * max(self.input, self.cache_read, self.cache_write) + completion * self.output) / 1e6


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
    model: str = ""                  # the configured model; the prices above are its prices
    refusal_fallback: bool = False   # another model may answer a declined call, at the fallback prices
    price_fallback_input_per_mtok: float = 0.0
    price_fallback_output_per_mtok: float = 0.0
    price_fallback_cache_read_per_mtok: float = 0.0    # 0: the fallback input price
    price_fallback_cache_write_per_mtok: float = 0.0   # 0: the fallback input price

    @classmethod
    def from_settings(cls, s: Settings) -> BudgetLimits:
        anthropic = s.agent_provider == "anthropic"
        write = s.agent_price_cache_write_per_mtok
        if not write and anthropic:
            write = s.agent_price_input_per_mtok * ANTHROPIC_CACHE_WRITE_MULTIPLIER
        fallback = anthropic and s.agent_refusal_fallback == "default"
        return cls(s.agent_max_calls, s.agent_max_tokens, s.agent_max_wall_seconds, s.agent_max_cost_usd,
                   s.agent_price_input_per_mtok, s.agent_price_output_per_mtok,
                   s.agent_price_cache_read_per_mtok, write, s.agent_model.strip(), fallback,
                   s.agent_price_fallback_input_per_mtok if fallback else 0.0,
                   s.agent_price_fallback_output_per_mtok if fallback else 0.0,
                   s.agent_price_fallback_cache_read_per_mtok if fallback else 0.0,
                   s.agent_price_fallback_input_per_mtok * ANTHROPIC_CACHE_WRITE_MULTIPLIER if fallback else 0.0)

    def as_dict(self) -> dict:
        out = {"max_calls": self.max_calls, "max_tokens": self.max_tokens,
               "max_wall_seconds": self.max_wall_seconds,
               "max_cost_usd": self.max_cost_usd or None,
               "price_input_per_mtok": self.price_input_per_mtok or None,
               "price_output_per_mtok": self.price_output_per_mtok or None}
        # the rest only where they apply, so the record of an unpriced or single-model agent keeps its shape
        optional = {"price_cache_read_per_mtok": self.price_cache_read_per_mtok,
                    "price_cache_write_per_mtok": self.price_cache_write_per_mtok,
                    "refusal_fallback": self.refusal_fallback,
                    "price_fallback_input_per_mtok": self.price_fallback_input_per_mtok,
                    "price_fallback_output_per_mtok": self.price_fallback_output_per_mtok,
                    "price_fallback_cache_read_per_mtok": self.price_fallback_cache_read_per_mtok,
                    "price_fallback_cache_write_per_mtok": self.price_fallback_cache_write_per_mtok}
        out.update({k: v for k, v in optional.items() if v})
        return out

    @classmethod
    def from_dict(cls, budgets: dict, model: str = "") -> BudgetLimits:
        """The limits a hunt manifest recorded (`as_dict`), for the configured `model`."""
        def price(key: str) -> float:
            return float(budgets.get(key) or 0.0)
        return cls(int(budgets["max_calls"]), int(budgets["max_tokens"]), int(budgets["max_wall_seconds"]),
                   price("max_cost_usd"), price("price_input_per_mtok"), price("price_output_per_mtok"),
                   price("price_cache_read_per_mtok"), price("price_cache_write_per_mtok"), model,
                   bool(budgets.get("refusal_fallback")), price("price_fallback_input_per_mtok"),
                   price("price_fallback_output_per_mtok"), price("price_fallback_cache_read_per_mtok"),
                   price("price_fallback_cache_write_per_mtok"))

    @property
    def cache_read_price(self) -> float:
        return self.price_cache_read_per_mtok or self.price_input_per_mtok

    @property
    def cache_write_price(self) -> float:
        return self.price_cache_write_per_mtok or self.price_input_per_mtok

    @property
    def main_prices(self) -> Prices:
        return Prices(self.price_input_per_mtok, self.price_output_per_mtok, self.cache_read_price,
                      self.cache_write_price)

    @property
    def fallback_prices(self) -> Prices:
        fb_in = self.price_fallback_input_per_mtok
        return Prices(fb_in, self.price_fallback_output_per_mtok, self.price_fallback_cache_read_per_mtok or fb_in,
                      self.price_fallback_cache_write_per_mtok or fb_in)

    def prices_for(self, model: str | None) -> Prices:
        """The prices of the model that served an attempt: the configured model's, the fallback model's for any
        other, and for an attempt whose model is unknown the dearer of the two, item by item."""
        main = self.main_prices
        if not self.refusal_fallback or (model and model == self.model):
            return main
        other = self.fallback_prices
        if model:
            return other
        return Prices(*(max(a, b) for a, b in zip((main.input, main.output, main.cache_read, main.cache_write),
                                                 (other.input, other.output, other.cache_read, other.cache_write),
                                                 strict=True)))

    def cost(self, prompt_tokens: int, completion_tokens: int, cache_read_tokens: int = 0,
             cache_write_tokens: int = 0) -> float:
        """A call served by the configured model. `prompt_tokens` counts every prompt token; the cache read and
        write tokens are the parts of it that are priced at the cache rates."""
        return self.main_prices.cost(prompt_tokens, completion_tokens, cache_read_tokens, cache_write_tokens)

    def charge_cost(self, charge: Charge) -> float:
        """What a call's charge costs, each billed attempt at the prices of the model that served it."""
        if not charge.parts:
            return self.cost(charge.prompt, charge.completion, charge.cache_read, charge.cache_write)
        return sum(self.prices_for(p.model).cost(p.prompt, p.completion, p.cache_read, p.cache_write)
                   for p in charge.parts)

    def worst_cost(self, prompt_tokens: int, completion_tokens: int) -> float:
        """The most a call with this prompt and output allowance can cost, however its prompt is cached: with the
        refusal fallback on, a declined full attempt plus a full answer by the fallback model."""
        worst = self.main_prices.worst(prompt_tokens, completion_tokens)
        if self.refusal_fallback:
            worst += self.fallback_prices.worst(prompt_tokens, completion_tokens)
        return worst

    def worst_tokens(self, prompt_tokens: int, completion_tokens: int) -> int:
        return (prompt_tokens + completion_tokens) * (2 if self.refusal_fallback else 1)

    @property
    def priced(self) -> bool:
        return bool(self.price_input_per_mtok or self.price_output_per_mtok)


class BudgetExhausted(RuntimeError):
    def __init__(self, budget: str, detail: str):
        super().__init__(f"{budget} budget reached: {detail}")
        self.budget = budget
        self.detail = detail


@dataclass(frozen=True)
class Part:
    """One billed attempt of a call and the model that served it (empty when unknown)."""
    model: str
    prompt: int
    completion: int
    cache_read: int = 0
    cache_write: int = 0
    worst_case: bool = False     # the attempt failed mid-reply: its output is charged at the full allowance


@dataclass(frozen=True)
class Charge:
    """What one call is charged: every prompt token (cached or not), the cached parts, and the output; `parts`
    lists the billed attempts when the provider reports them."""
    prompt: int
    completion: int
    cache_read: int = 0
    cache_write: int = 0
    estimated: bool = False
    parts: tuple[Part, ...] = field(default=())

    @property
    def worst_case(self) -> bool:
        return any(p.worst_case for p in self.parts)


def parts_of(billed) -> tuple[Part, ...]:
    """Billed attempts as an adapter reports them in `details["billed"]` (or on ProviderUnavailable.billed)."""
    if not isinstance(billed, list):
        return ()
    return tuple(Part(str(p.get("model") or ""), int(p.get("prompt", 0)), int(p.get("completion", 0)),
                      int(p.get("cache_read", 0)), int(p.get("cache_write", 0)), bool(p.get("worst_case")))
                 for p in billed if isinstance(p, dict))


def charge_parts(parts: tuple[Part, ...]) -> Charge:
    return Charge(sum(p.prompt for p in parts), sum(p.completion for p in parts), sum(p.cache_read for p in parts),
                  sum(p.cache_write for p in parts), parts=parts)


def charge_of(result: ChatResult) -> Charge:
    """Every attempt the provider billed for the call when it reports them, else reported usage, else a text
    estimate."""
    parts = parts_of((result.details or {}).get("billed"))
    if parts:
        return charge_parts(parts)
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
        worst = lim.worst_tokens(prompt_tokens_est, max_output_tokens)
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

    def _add(self, charge: Charge) -> dict:
        cost = self.limits.charge_cost(charge)
        self.calls += 1
        self.tokens += charge.prompt + charge.completion
        self.cost_usd += cost
        self.estimated = self.estimated or charge.estimated
        return {"prompt_tokens": charge.prompt, "completion_tokens": charge.completion,
                "cache_read_tokens": charge.cache_read, "cache_write_tokens": charge.cache_write,
                "cost_usd": cost, "estimated": charge.estimated, "worst_case": charge.worst_case}

    def charge(self, result: ChatResult) -> dict:
        """Record one completed call; returns what it was charged."""
        return self._add(charge_of(result))

    def charge_failure(self, exc: BaseException) -> dict:
        """Record a call that raised ProviderUnavailable after attempts the provider billed (`exc.billed`)."""
        return self._add(charge_parts(parts_of(getattr(exc, "billed", None))))

    def snapshot(self) -> dict:
        return {"calls": self.calls, "tokens": self.tokens,
                "cost_usd": round(self.cost_usd, 6) if self.limits.priced else None,
                "wall_seconds": round(self.wall_seconds(), 1), "usage_estimated": self.estimated,
                "limits": self.limits.as_dict()}
