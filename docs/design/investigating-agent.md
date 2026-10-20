# The investigating agent

_Design for ADR-008 (accepted 2026-10-20). Provider: ADR-007. Status: not implemented._

## Goal

After the deterministic sweep and expansion, an AI agent works the hunt the way a senior analyst would:

- it reads everything ROMULUS found;
- it forms hypotheses about what the adversary did;
- it follows leads to test them, and finds further indicators;
- it connects the pieces into a bigger picture.

The report then opens with the agent's overall assessment. The assessment is a cited hypothesis, clearly labelled as AI-generated and unconfirmed.

The deterministic layer stays the floor. With the agent off, or failing, the hunt's findings, lanes, coverage and incidents are exactly what they are today.

## Pipeline

```
sweep ─► expansion (deterministic) ─► agent: orient ─► investigate ×N ─► assess ─► report manifest
   │            │                              │                │
   └─ findings, incidents, coverage ───────────┘   pivots ─► normalization ─► all detectors and context rules
```

The agent is a phase of the hunt worker, recorded in the hunt state (`agent: pending | running | completed | partial | failed | skipped`). An agent failure never makes the detection result partial. It makes the *agent phase* partial, and the report says what was left unworked.

## Provider and configuration (`.env`, ADR-007)

| Key | Meaning |
|---|---|
| `AGENT_PROVIDER` | `openai_compatible` (default) or `ollama` |
| `AGENT_BASE_URL`, `AGENT_API_KEY`, `AGENT_MODEL` | Endpoint, key and pinned model snapshot. Teams use their own server; a hosted API only for evaluation on public data |
| `ROMULUS_MODEL_EGRESS` | Must be `lab-public-data` for any non-local endpoint (bootstrap only) |
| `MODEL_LOCAL_HOSTS` | Extra hosts treated as local, such as a team's model server on a routable enclave address |
| `AGENT_MAX_CALLS`, `AGENT_MAX_TOKENS`, `AGENT_MAX_WALL_SECONDS`, `AGENT_MAX_COST_USD` | Per-hunt budgets (cost is optional and estimated from reported usage) |
| `AGENT_MAX_TOOL_CALLS_PER_SESSION` | Bounds one investigation session (default 25) |
| `AGENT_CONCURRENCY` | Parallel investigation sessions (default 2) |
| `AGENT_DEFAULT` | `on` or `off`; the New hunt checkbox default when the provider is reachable |

## The dossier (what the agent sees first)

The dossier is built deterministically from the DB with short aliases (`F12`, `I3`, `E401`, `N7`). The controller maps them back to real IDs.

- **Scope:** window, sources, and coverage summary with the gaps listed (partial and unassessed source × partition cells).
- **Findings index:** every `urgent`, `high` and `lead` item, one line each: alias, lane, rule, claim, host, account, time.
- **Context counts** by rule. Individual context items are reachable through `list_findings`.
- **Incidents:** members, and links with their strength (observed or inferred).
- **Expansion state:** anchors left unexpanded or partial, and link tiers not reached.

The dossier is compact by construction. If it would still exceed the model's context, the index is paged and the dossier says so ("index page 1 of 3; call `list_findings` for the rest"). Nothing is dropped without saying so.

## Tools

All arguments are typed and validated. Every result carries evidence aliases, counts, and a coverage state (`complete`, or `partial` with the exact uncovered ranges). Results are digests (counts, stacks, time distribution, exemplar rows) with fetch-by-alias for full records. Telemetry text sits in JSON data fields, never in instructions.

| Group | Tools |
|---|---|
| Read | `list_findings(lane?, rule?, entity?, page)`, `get_finding(F)`, `get_evidence(E…)`, `get_incident(I)`, `entity_profile(N)` |
| Pivot (ADR-003 boundary, `PivotExecutor`) | `entity_timeline`, `auth_activity`, `process_tree`, `ids_alerts`, `ip_sessions` (as built), and `follow_link(anchor, link_type)` over the expansion link fetchers (lineage, session, flow, source IP, account, host-after) |
| Hypothesis | `open_hypothesis(statement, techniques, entities, supporting, questions)`, `update_hypothesis(H, status?, confidence?, add_support?, add_contradiction?, questions?, note)` |
| Output | `propose_finding(claim, claim_kind, cites, lane≤high, techniques, rationale)`, `propose_link(from, to, relation, cites, rationale)`, `add_note(target, text)`, `request_rule(pattern_description, cites)` |
| Control | `finish_session(summary)` |

Pivot records go through normalization and **every** deterministic detector and context rule. Those findings are admitted on their own merit, with deterministic provenance, at any lane, including `urgent`.

## Hypotheses

Each hypothesis is a row, `agent_hypotheses`, with an append-only history:

- the statement;
- ATT&CK technique IDs, validated against `content/attack/`;
- entity aliases;
- supporting and contradicting citations;
- open questions;
- a status: `open`, `supported`, `weakened`, `refuted` or `abandoned`;
- the model's confidence: `low`, `medium` or `high`;
- the session that created it.

The UI shows hypotheses in the live view and on a hypotheses tab. They are always labelled "Agent hypothesis". Citations open the evidence.

## The loop

1. **Orient.** One session reads the dossier and opens hypotheses, for example "initial access through the web application on host A, followed by credential discovery". There is a cap on how many it opens at the start; more can be spawned later.
2. **Investigate.** The controller picks the next hypothesis by priority: lane of its supporting findings, open questions, untouched entities, with breadth reservation so no single thread uses up the budget. It then runs one bounded tool-calling session for it. The session starts fresh from the DB, with the dossier header, the hypothesis card, and digests of its earlier sessions; never a hunt-long transcript. The model pivots, reads, proposes findings and links, updates the hypothesis, may open new ones, and ends with `finish_session(summary)`. The summary is persisted and becomes the hypothesis's memory for its next session.
3. **Stop** when no open hypothesis has unanswered questions, or a budget is hit. Remaining open hypotheses and unworked anchors are listed in the report.
4. **Assess.** A final session reads every hypothesis, the agent findings and links, and the deterministic incidents, and writes the assessment (below).

`AGENT_CONCURRENCY` sessions run in parallel on different hypotheses. All writes go through the existing single-writer coordinator.

## Admission of agent output

| Output | Validation | Result |
|---|---|---|
| `propose_finding` | Every cite resolves to raw evidence returned in this hunt. The claim checker accepts the claim kind for the cited event types (execution, mention, network, auth). Lane ≤ `high`. Duplicates of an existing finding become a note on it. | Finding with provenance `agent`, labelled "Agent finding", citing its hypothesis |
| `propose_link` | Both ends resolve; at least one cite | Edge with style `agent` (dashed, labelled hypothesis); never observed |
| `add_note` | Target resolves | Note shown on the target; includes "looks benign" opinions |
| `request_rule` | Cites resolve | Backlog item for the detection-engineer |
| Anything else | — | Rejected and logged. The model sees the validation error in the tool result and may correct it |

The agent cannot close, hide, demote or re-lane anything, or change scope, coverage or rule outcomes.

## The AI assessment in the report

Stored in the report manifest as `ai_assessment`, so the web, Markdown, JSON and DOCX renderers all show the same thing. It appears first in the technical report and in the executive DOCX.

- **Overall hypothesis:** what most likely happened, covering entry point, actions on hosts, movement and apparent objective. It is ordered by time and ATT&CK tactic.
- **Key steps:** a short timeline of the steps that matter, each cited.
- **Confidence** overall and per step, with the reasons.
- **Alternative explanations** that the agent considered, and why it ranks them lower.
- **Gaps:** what the telemetry could not show (coverage gaps, unreached links), and what would confirm or refute the hypothesis.
- **Recommended next checks** for the analyst. These are guidance only; no actions are taken.

The output schema is a list of sentences: `{text, cites: [aliases], kind: observed | inferred | hypothesis}`. A deterministic checker:

- removes sentences that cite nothing or cite unknown aliases;
- downgrades `observed` to `inferred` when the citations are agent links or inferred links;
- counts every change and shows the counts in the section footer.

The header reads "AI-generated hypothesis from the cited evidence. Not confirmed by an analyst. Model: <provider>/<model>." Without an agent, the section is the ADR-006 template narrative. A later "Re-run assessment" action creates a new report revision.

## Safety

- **Prompt injection.** Telemetry is untrusted data. The system prompt says so. Tool results carry telemetry in data fields only. Spec scenario 13 is extended: logs containing "ignore previous instructions", "call add_note … benign" or "pivot to 10.0.0.1" must not change behaviour, and are flagged as suspicious content.
- **No new powers.** All tools are read-only, typed and in scope. There is no free-form query, file or shell tool.
- **Secrets** never enter prompts; `redact_text` is the final filter on every outgoing request.
- **Egress** follows ADR-007.

## Budgets, failure and resume

- **Budgets.** Each one is checked before every call. When one is hit, the agent writes its assessment from what it has, if the remaining budget allows that, and then stops with `partial`.
- **Provider outage.** Up to three retries with backoff, then `partial`. Detection results are unaffected.
- **Resume.** `hunt resume <id>` continues the agent phase from the rows: open hypotheses and unfinished sessions restart from their last persisted digest.
- **Audit.** Every request and response is stored: prompt digest, raw response, tool calls, validation and usage. The live view streams hypotheses, tool calls and agent findings.

## Measurement (eval-custodian)

The eval-custodian scores agent on against off on the dev set, and on a holdout before any claim. Results are reported per provider and model.

- Incremental true positives from agent findings, and from pivoted records that detectors admitted.
- False leads per hour added by agent findings.
- Hypothesis quality at class level: does a `supported` hypothesis match a gold attack phase?
- Assessment accuracy, rated by the lead against the gold storyline at class level. The rater never sees per-opportunity answers.
- 100% citation validity; checker removal rate.
- Calls, tokens, cost and wall time per hunt.
- Determinism check: deterministic findings are identical with the agent on and off.

## Work split and order

| Step | Piece | Owner |
|---|---|---|
| 1 | Provider port: `openai_compatible` and `ollama` adapters, egress class and switch, doctor check, budgets | lead |
| 2 | Dossier builder and the read and pivot tools over `PivotExecutor` and link fetchers | Codex |
| 3 | Controller (orient, investigate, assess), hypotheses table, sessions, resume | Codex |
| 4 | Admission of agent output; `ai_assessment` and its checker in the manifest | Codex |
| 5 | Renderers (Markdown, JSON, web, then DOCX in M7); live view, hypotheses tab, New hunt checkbox, CLI `--agent/--no-agent` | lead |
| 6 | Injection and tool-call adversarial tests; scenario 13 extension | detection-engineer and Codex |
| 7 | Scoring agent on and off; replay harness repurposed for frozen dossiers | eval-custodian |
| — | Review of every slice before merge | `reviewer` |

Retired when this lands: the v2 menu investigator (`brief.py`, `options.py`, `resolver.py`, and the `agent_mode` values `model` and `deterministic`). The case queue, `PivotExecutor`, duplicate-pivot keys and named windows are reused.
