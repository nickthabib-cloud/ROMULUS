"""Which anthropic models the server-side refusal fallback serves.

The models endpoint reports no capability for it, so this documented table is the source. A model listed here has no
server-side fallback: with `fallbacks: "default"` a request it declines stays declined, and a list of fallback models
is refused (HTTP 400), so the adapter sends no `fallbacks` for it and its budget reserves no fallback attempt. Any
other model is taken to have one: an unknown model then reserves a fallback attempt it may not need, never the
reverse.
"""
from __future__ import annotations

# the documented models without a server-side refusal fallback (dated snapshots of them included)
NO_SERVER_FALLBACK = frozenset({"claude-haiku-5-5"})


def server_fallback(model: str) -> bool:
    """Whether the API can answer a request `model` declined with its refusal-fallback model."""
    name = model.strip()
    return not any(name == known or name.startswith(known + "-") for known in NO_SERVER_FALLBACK)


def refusal_fallback_on(s) -> bool:
    """Whether calls on these settings ask for, and may be billed for, a refusal-fallback answer: the anthropic
    provider, AGENT_REFUSAL_FALLBACK=default, and a model the fallback serves."""
    return (s.agent_provider == "anthropic" and s.agent_refusal_fallback == "default"
            and server_fallback(s.agent_model))
