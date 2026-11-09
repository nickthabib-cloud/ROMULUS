# AI investigating agent

ROMULUS can run a bounded AI investigation after its deterministic hunt stages finish. The agent reads the persisted hunt dossier, proposes investigation hypotheses, uses typed read and pivot tools, and writes separately labelled notes, links, rule requests, and findings. It cannot remove or change deterministic findings, lanes, coverage, incidents, or rule outcomes.

## Run flow

The hunt manifest records whether the agent was requested and which provider configuration was used. Provider readiness is checked without blocking the deterministic hunt. An unrequested, unavailable, or failed agent phase is recorded as skipped or partial and receives a deterministic template assessment.

Detection completion is recorded before agent work begins. The agent holds a separate renewable lease, including during blocking model calls. Its work cannot change detection execution state, and a live agent lease prevents deletion and maintenance. After agent work, one transaction refreshes the result from deterministic findings, records the agent's terminal state, and releases its lease. A crashed worker's persisted work can be resumed after lease expiry.

An orient session receives the system instructions and the first dossier page. It can open a bounded set of hypotheses. When there are reportable findings but no hypotheses were opened, the controller creates low-confidence hypotheses from the top finding in each incident.

The scheduler investigates open hypotheses in breadth-first rounds, with bounded concurrency and a per-hypothesis session limit. Each session starts a fresh conversation with the hypothesis card and a bounded set of earlier session summaries. Hypothesis updates and cites are persisted as events. The session stores its state, tool-call count, summary, and model calls so the phase can be resumed without rerunning a completed deterministic hunt.

After investigation, a schema-constrained assessment summarizes cited observations, inferences, hypotheses, gaps, alternatives, and next checks. A deterministic checker removes uncited or unknown-alias sentences, downgrades observations supported only by AI or inferred links, blocks absence claims outside gaps and next checks, and stores real identifiers in the report body. A template based on the deterministic incident narrative and coverage gaps is used when no valid model assessment exists. A previous AI assessment is retained if a later attempt fails, and is labelled stale when investigation has changed since it was written.

## Admission and limits

All model actions use typed arguments. Aliases are hunt-scoped, typed, and accepted only after they have appeared in trusted structured fields of the current session's prompt or a tool result. The claim checker restricts the claim kinds that each typed event family can support. Agent findings can be high or lead, and mention-only claims are lead. A duplicate proposal becomes a note only when the existing reportable finding has at least the admitted lane's strength. Duplicate checks stream matching candidates in bounded batches. Every output tool has a per-hunt cap; cap hits are recorded in the agent run.

Telemetry appears only in JSON data fields returned by tools. The system prompt treats it as untrusted input, and the provider port redacts outgoing text. The model cannot submit DSL, raw source queries, shell commands, paths, or SQL.

Budgets bound calls, tokens, wall time, and optionally cost. The controller preserves an assessment reserve during investigation, records billed provider failures, and checks remaining budget before retry attempts. An agent limit or provider failure affects the agent phase only.

## Reports

The manifest exposes agent provenance, usage, hypotheses, output counts, notes, rule requests, limits, and unworked hypotheses. Agent findings carry `provenance: "agent"`; agent links are displayed as hypotheses and do not join incidents. The Markdown report starts with the assessment and labels it as AI-generated and unconfirmed. The cross-hunt canonical projection keeps agent-only content in its `ai` section so it cannot alter deterministic comparisons.

Detection results and lane totals count deterministic findings, including genuine rule matches discovered by agent pivots. Agent-proposed findings are counted separately and labelled unconfirmed.

The CLI offers `hunt start --agent` and `hunt start --no-agent`, plus `agent reassess` to create another assessment revision and report revision.
