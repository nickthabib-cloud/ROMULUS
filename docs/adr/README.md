# Architecture decision records

Write one only for decisions that are hard to reverse. Keep each to a page: **Context**, **Decision**, **Rejected alternatives**, **Consequences**, **Revisit if**. Number sequentially; never edit an accepted ADR's decision. Supersede it with a new one instead.

| ADR | Title | Status |
|---|---|---|
| [001](ADR-001-no-langgraph.md) | Explicit controller and single SQLite authority; no LangGraph | Accepted 2026-10-18 |
| [002](ADR-002-runtime-and-stack.md) | Modular monolith on the VM; FastAPI/HTMX; SQLite; Ollama on Windows host | Accepted 2026-10-18 |
| [003](ADR-003-agent-pivot-executor-boundary.md) | Execute agent pivots in the hunt layer | Accepted 2026-10-18 |
