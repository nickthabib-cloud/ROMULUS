# Investigator v2: menu-driven decisions for a small model

## Principle

The model chooses; the controller composes. Every value the controller already knows (IDs, entities, tools, windows, claims, lanes) is offered, never typed by the model. The model's job is judgment: which next move, on what evidence, and why.

## One step

1. **Generate options** for the case (deterministic, below).
2. **Build the brief**: case summary, evidence cards, the option menu.
3. **Build the schema** for this call, with enums from steps 1–2.
4. **Call the model** (unchanged Ollama client and truncation checks).
5. **Resolve**: map the option and aliases back to typed values and build the `AgentDecision`.
6. **Validate** with the existing `validate_decision` (defence in depth; should never fail).
7. **Execute**, exactly as today.

## Option generation

Options are produced by a pure function of durable case state, so they are testable and replayable.

| Kind | Generated from | Never offered when |
|---|---|---|
| Pivot | Each tool × each eligible known entity × each named window, plus per-rule pivot templates from the seed candidates' `next_checks` | Already executed for this case (same tool, entity, window); observer host; tool/entity kind mismatch; process ID not in case evidence; window outside the hunt |
| Spawn | Entities discovered by this case's pivots | Already a case, or an observer, or `max_cases` reached |
| Escalate | Each seed candidate of the case, with claim and lane prefilled | Never hidden; the model may only confirm the candidate as it is |
| Park as lead | Always one option | Never hidden |
| Close | Always one option | Only allowed when no cited evidence is flagged as untrusted instructions (existing rule) |

**Named windows** replace typed timestamps: anchor ±5 min, ±30 min, ±2 h, and the seed-cluster span, each clipped to the hunt window. The anchor is the case's latest cited event.

**Ranking and cap.** Options are ordered by a deterministic prior and capped at about 12, so the menu fits the context and a small model is not overwhelmed. The prior: rule templates first, then the tightest window, then entity kinds by usefulness (host, account, IP), with conclusions always present. The cap is recorded in each step, so a hidden option is never mistaken for an impossible one.

## Brief

- **Evidence cards** `E1…E16`: family, time, host, outcome, and up to four typed fields. Values are truncated as today and delimited as untrusted telemetry.
- **Entities** `N1…` and **candidates** `C1…` (claim, lane, cited cards).
- **Prior steps**: option chosen, outcome, result digest (counts and new entities only).
- **Menu**: `O1…On`, each a one-line plain description, e.g. `O3 — auth_activity for account root, anchor ±30 min`.

Aliases are per call and stored with the step, so a replay resolves them exactly.

## Output schema (per call)

```json
{
  "option": "O1 | … | On",                 // enum
  "evidence": ["E1", …],                    // enum items, 1–4
  "rationale": "string, ≤ 300 chars",
  "benign_alternative": "string, ≤ 200 chars, optional"
}
```

Constrained decoding makes unknown options or evidence aliases unrepresentable. The controller adds the hypothesis and expected outcomes for pivots from the template; the model's rationale is stored as its reasoning.

## Failure handling

- A schema or validation failure after constrained decoding is a defect, not normal behaviour. It is logged as such, retried once, then the case is fallback-parked as today.
- **Deterministic fallback (approved).** Agent mode `deterministic` works cases with no model calls by taking the top-ranked pivot option until no pivot options or budget remain, then parks with an explicit reason; it never escalates or closes. In mode `model`, a step that fails twice takes the top-ranked pivot option (recorded as a deterministic fallback) instead of parking, and parks only when no pivot option remains. Mode `off` (`--no-agent`) stays sweep-only. An Ollama outage still leaves the hunt partial and resumable (acceptance scenario 16). Pivot discoveries always go through deterministic admission.

## Context

The brief is built from cards and a menu, not raw summaries, so it should fit within 8192 without the current shrink cascade. The replay baseline at 8192 vs. 16384 (custodian, in progress) decides whether to raise `OLLAMA_NUM_CTX`.

## Measurement

The investigator replay evaluation (eval-custodian) scores the current design and v2 against the same expected decisions, written as intent (action class, acceptable tools/entities/evidence, must-nots), so it applies to both interfaces. Then an e_a agent-on hunt is rescored with the ablation.

Acceptance targets (owner-approved 2026-10-19):

- valid on first attempt ≥ 98%;
- zero unknown-ID, unknown-entity and duplicate-pivot rejections;
- decision accuracy on the replay set reported with intervals and better than the current design;
- the agent-on ablation shows at least one opportunity reached or concluded that model-off does not, or the gap is reported as the next thing to fix.

## Work split

| Piece | Owner |
|---|---|
| Option generator, aliasing, per-call schema, resolver (in `romulus.agent`) | Codex via `Claude-Codex.md` |
| Replay harness adapted to v2 briefs (`romulus.replay`) | Complete |
| Expected decisions, scoring, ablation | eval-custodian |
| Review of the agent changes | `reviewer` |

## Owner decisions (2026-10-19)

Menu-driven design approved; deterministic fallback approved as specified above; acceptance targets approved.
