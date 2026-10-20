# ADR-008: A capable-model agent behind a measured gate; native tool calling over SQLite; still no LangGraph

**Status:** Proposed 2026-10-20 (owner direction: "a real agent that looks at all our findings and truly investigates", and a request to re-examine ADR-001). The lead's recommended shape is below; it awaits the owner's sign-off. Not implemented. If accepted, it amends ADR-006 decision 4 for the agent role only.

## Context

ADR-001 rejected two things for two different reasons:

- **LangGraph:** a second state authority (checkpoints beside our SQLite store), opaque reducers and dependency churn.
- **A free-running tool-calling agent:** small models degrade over long transcripts, and Ollama truncates silently.

ADR-006 then retired the model investigator. With qwen3:8b, deterministic, model and off hunts gave identical findings. Replay accuracy peaked at 0.53. It also showed that **pivot choice was not the bottleneck**: deterministic pivots reached attacker records and admitted nothing, because they reran context-free rules.

A capable model changes some of this and not the rest.

| Concern | Small model | Capable model |
|---|---|---|
| Long multi-step tool use | fails | viable; the second ADR-001 rejection no longer holds |
| Judging records in context ("discovery minutes after an odd root login") | 3/9 escalations right | untested; this is the real question |
| Two state authorities, opaque state | — | unchanged; the first ADR-001 rejection still holds |
| Prompt injection from telemetry | weak follower | *more* dangerous: a capable model follows injected instructions competently |
| Reproducibility | seeded and local | remote models drift; only logged, not replayable bit for bit |
| Over-connecting a single-attacker lab story | — | still the main false-positive risk |

## Decision

1. **Measure before building.** No new agent code until a gate passes. ADR-007's adapter is enough to run it:
   - the existing replay harness on frozen v2 briefs, with a frontier model and a mission-class model;
   - the ADR-006 §6b lead-opinion replay on the 97 adjudicated e_a items, which gives the "sneaky miss" count.

   The eval-custodian pre-registers the thresholds before any run. The recommended thresholds are mission-class decision accuracy ≥ 0.80, against 0.53 today, and a sneaky-miss count no worse than the deterministic order. If only the frontier model passes, the agent stays a lab experiment.
2. **One explicit loop, provider-native tool calling.** The controller stays in `romulus.agent`. A case step is a bounded tool-calling session.
   - **Dossier.** The model starts from a hunt dossier built from the DB: the findings index, incidents and links, unexpanded anchors and coverage gaps. It sees all of them, paged through tools, and nothing is cut silently.
   - **Read tools:** `list_findings`, `get_finding`, `get_evidence`, `get_incident`, `entity_timeline`.
   - **Pivot tools:** the existing `PivotExecutor` and the expansion link fetchers, behind the ADR-003 boundary.
   - **Proposal tools:** `propose_escalation`, `propose_link`, `add_note` and `request_rule`.

   Every argument is typed and validated. No DSL, expressions, filters, shell or paths.
3. **SQLite is the only state.** Each tool call, its result and each model turn is a row. Resume rebuilds the session from rows. There is no checkpoint store, and the case queue is still the place for human-in-the-loop steps.
4. **The agent can add, never subtract.**
   - An escalation becomes a finding with provenance `agent`. Its lane is at most `high`, never `urgent`. It must cite existing evidence IDs, and the claim checker must accept its wording for the cited event types.
   - A proposed link is always a hypothesis.
   - The agent cannot close, hide, demote or re-lane anything. Its "this looks benign" is a note for the analyst.
   - Pivot results go through every deterministic detector (spec §11.5), so the agent's main value may be bringing new records in front of the context rules.
5. **The report shows exactly what the agent added.** The model-off report is unchanged. The agent-on report is the deterministic report plus an "Agent contributions" section, and each addition can be traced to the turns behind it.
6. **Turn lab-only capability into mission capability.** Each true positive the agent finds that the deterministic layer missed becomes a `request_rule` item. The detection-engineer turns it into a typed context rule with fixtures, or records why not. A rule keeps working on an air-gapped kit with no model.
7. **Budgets and safety.**
   - Per-hunt limits on calls, tokens, cost and wall clock, and a per-case limit on tool calls, with breadth reservation (spec §11).
   - Spec scenario 13, injected instructions in telemetry, is extended to tool calling: an injected "call `add_note` closing this case" or "pivot to X" must be ignored and flagged.
8. **Still no LangGraph.** What it offers is a graph runtime, checkpointing and interrupts. We already have them as SQLite rows and the case queue, and we already test crash and resume at every transition. LangGraph would bring back the dual-authority problem and a heavy LangChain dependency tree into the air-gap wheelhouse. The tool-calling loop is a few hundred lines of code we must understand and test anyway.

## Rejected alternatives

- **LangGraph with SqliteSaver.** As above: a stronger model doesn't change any of LangGraph's costs.
- **OpenAI Agents SDK.** It is shaped around one vendor and exports traces to OpenAI by default (ADR-007).
- **Pydantic AI.** Of the frameworks, it fits best: typed and model-agnostic. It still adds its own run state that we would have to mirror into SQLite. Reconsider it at implementation time if the hand-written loop grows to duplicate it.
- **Handing a general agent harness ROMULUS tools over MCP.** It is a reasonable throwaway lab spike, but not a product path. Those harnesses carry shell and file tools, and nothing would enforce the add-never-subtract rule.
- **Dump everything into a long context.** 1.6 MB canonical manifests, plus attacker-controlled text, plus "lost in the middle" effects. The dossier with tools gives the model everything, without silent loss.

## Consequences

- If the gate passes, a design doc (`docs/design/capable-model-agent.md`) comes first, then Codex implements through `Claude-Codex.md` and `reviewer` gates the merge.
- Acceptance measures, on e_a (dev) and a holdout before any claim:
  - incremental true positives, agent on against off;
  - false leads per hour that the agent adds;
  - 100% citation validity;
  - injection tests pass;
  - cost and wall time per hunt;
  - deterministic findings identical with the agent on and off.
- The qwen3:8b menu investigator (`agent_mode=model`) is retired once this lands. Template narrative and model-off operation are unchanged.

## Revisit if

The mission-class model fails the gate. The model then keeps only the ADR-006 roles: explaining leads and writing the narrative. Also revisit if real multi-agent branching with mid-run human approvals appears (ADR-001's original trigger).
