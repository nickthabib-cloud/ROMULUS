# ADR-001: Explicit controller and single SQLite authority; no LangGraph

**Status:** Accepted, 2026-10-18

## Context

v1 used LangGraph with a SQLite checkpointer next to its own application SQLite store (v1 ADR-0004). The two state authorities could disagree. Graph state carried bounded evidence subsets, so correlation silently ran on a subset of the data. Orchestration, detection, state, and reporting all lived in one large mutable workflow module. The v2 agent loop runs on a small local model and needs strict, auditable control: one decision per call, typed validation, and a deterministic fallback.

## Decision

The agent loop is an explicit controller in `romulus.agent`. Each turn it does: pick case → build brief from DB → one schema-validated model call → validate → execute typed tool → persist. All state (cases, model calls, proposals, tasks, evidence) lives in the one SQLite database. There is no framework checkpoint store.

## Rejected alternatives

- **LangGraph with SqliteSaver.** It adds a second persistence model, opaque state reducers, and dependency churn. The parts it would provide (looping, branching, checkpointing) are a few hundred lines here, and those are lines we must understand and test anyway.
- **Free-running tool-calling agent (ReAct over a long transcript).** Small local models degrade over long transcripts, and context truncation is silent in Ollama.

## Consequences

The controller code is ours to test, including crash/resume at every transition. Human-in-the-loop steps (analyst-requested pivots) are rows in the case queue.

## Revisit if

A measured requirement appears that the explicit controller can't express cleanly (e.g., complex multi-agent branching with human approvals mid-graph).
