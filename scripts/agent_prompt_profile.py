"""Show how the AI agent's prompts grew, call by call, from a hunt store's recorded model calls.

For each agent session of a hunt it prints every model call in order: the estimated prompt tokens, the prompt tokens
the provider reported, how many of those were read from or written to its prompt cache, the budget tokens charged,
and the tools the reply called. A prompt that grows by roughly one tool result per call is a session re-reading its
earlier results. Reads the store only; prints numbers and tool names, never prompt or telemetry text.

    python scripts/agent_prompt_profile.py <store.sqlite> <hunt-id> [--session <id>]
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from collections.abc import Sequence

from romulus.store.db import make_engine
from romulus.store.repo import Repo


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("store", help="the hunt store's SQLite file")
    parser.add_argument("hunt", help="the hunt id")
    parser.add_argument("--session", help="only this agent session")
    return parser


def profile(repo: Repo, hunt_id: str, session: str | None = None) -> list[dict]:
    """Per session, its calls in order with their prompt sizes, cache use, budget tokens and the tools called."""
    sessions: dict[str, list[dict]] = defaultdict(list)
    for row in repo.model_calls(hunt_id, session_id=session):
        if row.get("session_id") is None:
            continue
        options = row.get("options") or {}
        parsed = row.get("parsed") or {}
        sessions[row["session_id"]].append({
            "purpose": row.get("purpose"), "prompt_est": row.get("prompt_tokens_est"),
            "prompt": row.get("prompt_eval_count"), "completion": row.get("eval_count"),
            "cache_read": options.get("cache_read_tokens", 0), "cache_write": options.get("cache_write_tokens", 0),
            "budget_tokens": options.get("budget_tokens"), "status": row.get("status"),
            "tools": [call.get("name") for call in parsed.get("tool_calls") or []],
        })
    return [{"session": key, "calls": calls} for key, calls in sessions.items()]


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    engine = make_engine(args.store)
    try:
        for item in profile(Repo(engine), args.hunt, args.session):
            calls = item["calls"]
            print(f"session {item['session']} ({calls[0]['purpose']}, {len(calls)} calls)")
            print(f"{'#':>3} {'prompt_est':>10} {'prompt':>9} {'cache_rd':>9} {'cache_wr':>9} {'budget':>9}  tools")
            for n, call in enumerate(calls, 1):
                print(f"{n:>3} {call['prompt_est'] or 0:>10} {call['prompt'] or 0:>9} {call['cache_read']:>9} "
                      f"{call['cache_write']:>9} {call['budget_tokens'] or 0:>9}  {','.join(call['tools'])}")
            total = sum(call["budget_tokens"] or 0 for call in calls)
            peak = max((call["prompt"] or call["prompt_est"] or 0) for call in calls)
            print(f"    budget tokens {total}, largest prompt {peak}\n")
    finally:
        engine.dispose()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
