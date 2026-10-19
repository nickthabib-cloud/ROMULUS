# Architecture decision records

Write one only for decisions that are hard to reverse. Keep each to a page: **Context**, **Decision**, **Rejected alternatives**, **Consequences**, **Revisit if**. Number sequentially; never edit an accepted ADR's decision. Supersede it with a new one instead.

| ADR | Title | Status |
|---|---|---|
| [001](ADR-001-no-langgraph.md) | Explicit controller and single SQLite authority; no LangGraph | Accepted 2026-10-18 |
| [002](ADR-002-runtime-and-stack.md) | Modular monolith on the VM; FastAPI/HTMX; SQLite; Ollama on Windows host | Accepted 2026-10-18 |
| [003](ADR-003-agent-pivot-executor-boundary.md) | Execute agent pivots in the hunt layer | Accepted 2026-10-18 |
| [004](ADR-004-negatives-only-from-kernel-records.md) | Negatives only from evidence that can prove them; argv/text rules positive-only | Accepted 2026-10-19 |
| [005](ADR-005-small-model-investigator.md) | Keep qwen3:8b; menu-driven investigator | Accepted 2026-10-19; decisions 2–5 superseded by ADR-006 |
| [006](ADR-006-deterministic-expansion-optional-model.md) | Deterministic expansion finds; an optional model explains leads and writes the narrative | Accepted 2026-10-19 |
