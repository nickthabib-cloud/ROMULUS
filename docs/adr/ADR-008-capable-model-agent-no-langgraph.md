# ADR-008: A hypothesis-driven investigating agent; native tool calling over SQLite; no LangGraph

**Status:** Accepted 2026-10-20 (owner direction). Amends ADR-006 decision 4, so the model may now investigate, add findings and write the report's assessment. ADR-006 decisions 1–3 and 5 stand. Not implemented. Design: `docs/design/investigating-agent.md`.

## Context

The owner wants an AI agent that works like a senior analyst. It reads every indicator ROMULUS produced, develops hypotheses, follows further leads, finds more indicators, and paints the bigger picture. The report then presents its overall hypothesis of what happened. Teams will run a powerful model (ADR-007), and the agent is not expected to be always right.

What ADR-005 and ADR-006 learned still applies:

- qwen3:8b's judgment was poor. That is why ADR-006 limited the model to explaining.
- Pivots alone admit nothing when they rerun context-free rules. The agent's value is judgment in context, not pivot choice.
- Telemetry is attacker-controlled, and a capable model follows injected instructions competently.

ADR-001 rejected LangGraph because of a second state authority, opaque reducers and dependency churn. It rejected free-running tool loops because small models fail on them. A capable model removes the second reason. It does not touch the first.

## Decision

1. **Build the agent.** It runs in the hunt worker after the sweep and deterministic expansion, starting from their findings and incidents. The New hunt page and the CLI have a "Run the AI agent" choice. It is on by default when an agent provider is configured and reachable, and off otherwise. Model-off hunts work exactly as today.
2. **One explicit controller with native tool calling.** The controller in `romulus.agent` runs bounded tool-calling sessions through the ADR-007 port.
   - **Orient:** read the hunt dossier (every finding, incident, unexpanded anchor and coverage gap, paged through tools, with nothing cut silently) and open hypotheses.
   - **Investigate:** one session per hypothesis, by priority with breadth reservation. Pivot, read evidence, update the hypothesis, spawn new ones.
   - **Assess:** write the overall assessment.
3. **Hypotheses are first-class records.** Each one has:
   - a statement;
   - ATT&CK techniques, validated against the vendored STIX;
   - entities;
   - supporting and contradicting citations;
   - open questions;
   - a status: `open`, `supported`, `weakened`, `refuted` or `abandoned`;
   - the model's confidence;
   - a history.

   They are shown in the live view, the UI and the report as the agent's hypotheses, never as observed fact.
4. **Typed tools only.**
   - **Read:** findings, evidence, incidents, entity profiles.
   - **Pivot:** the existing `PivotExecutor` tools and the expansion link fetchers, behind the ADR-003 boundary.
   - **Hypothesis:** open and update.
   - **Output:** propose finding, propose link, note, request rule.
   - **Finish.**

   No DSL, expressions, filters, shell or paths. Every argument is validated, and every tool result reports whether it is complete or partial, with the exact uncovered ranges.
5. **The agent adds and never subtracts.**
   - Records it pulls in go through every deterministic detector and context rule, and those findings keep deterministic provenance at any lane.
   - An agent-proposed finding has provenance `agent` and a lane of at most `high`. It must cite raw evidence returned in this hunt, and the claim checker must accept its wording for the cited event types.
   - Agent links are always hypotheses: dashed and labelled in the timeline.
   - The agent cannot close, hide, demote or re-lane anything, or change scope or coverage. "Looks benign" is a note.
6. **The report leads with the AI assessment.** It is the agent's overall hypothesis: what most likely happened (entry, actions, objective), key steps in time order, confidence, alternative explanations, gaps, and what would confirm or refute it.
   - Every sentence is cited and typed `observed`, `inferred` or `hypothesis`.
   - A deterministic checker removes uncited or unresolvable sentences and downgrades claims that their citations don't support. The removals are counted.
   - The assessment is stored in the report manifest, so every renderer agrees, and labelled "AI-generated hypothesis from the cited evidence; not confirmed by an analyst".
   - Without an agent, the template narrative (ADR-006) is used.
7. **SQLite is the only state.** Every model turn, tool call, result digest and hypothesis change is a row. Each session starts from the DB (the dossier, the hypothesis card and its prior digests), never from a hunt-long transcript. Resume continues from the rows.
8. **Agent wins become rules.** Each agent true positive that the deterministic layer missed gets a `request_rule` item for the detection-engineer. A rule keeps working on a kit with a weaker model or none.
9. **Measured continuously.** The eval-custodian scores agent on against off, per model:
   - incremental true positives;
   - added false leads per hour;
   - hypothesis and assessment accuracy at class level;
   - 100% citation validity;
   - cost and time.

   Results steer the prompts and tools. They do not decide whether the agent exists.

## Rejected alternatives

- **LangGraph with SqliteSaver.** Its graph runtime, checkpoints and interrupts duplicate our SQLite rows and case queue. It brings back the dual-authority problem and adds the LangChain dependency tree to the air-gap wheelhouse. A stronger model changes none of that.
- **OpenAI Agents SDK.** It is built around one vendor and exports traces to OpenAI by default.
- **Pydantic AI.** It is typed and model-agnostic, and the closest fit. It still keeps its own run state, which we would have to mirror into SQLite. The hand-written loop is a few hundred lines.
- **A general agent harness over MCP.** Those harnesses bring shell and file tools, and nothing would enforce add-never-subtract.
- **One long transcript with everything in context.** It would mean multi-megabyte manifests, attacker text and "lost in the middle" effects. A dossier plus tools gives the model everything with nothing lost.

## Consequences

- The qwen3:8b menu investigator (ADR-005 v2, `agent_mode=model|deterministic`) is retired when this lands. The expansion engine stays the deterministic floor.
- ADR-006 §6b lead explanations fold into the agent's notes, and its per-incident model narrative is replaced by the AI assessment. The template narrative stays.
- Spec scenario 13 is extended to tool calls: injected "close this", "pivot to X" or "mark benign" must be ignored and flagged.
- Codex implements the engine through `Claude-Codex.md`. The lead owns the provider port, UI and renderers. `reviewer` gates each slice.

## Revisit if

Measurements show agent findings or assessments adding more false leads than true positives on the dev set and a holdout, or a need for multi-agent branching with mid-run human approvals (ADR-001's original trigger).
