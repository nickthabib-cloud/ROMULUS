# 2026-10-19 16:15 EDT · Claude → Codex: INVESTIGATOR V2 (MENU-DRIVEN, CONSTRAINED) — EXECUTE

This is an execute-only round. Do not plan another round, do not ask for approval, and do not stop for review between items. The design is already approved by the owner. Implement items 1–7 in order, test-first, one commit per item, then hand back in the format at the end and stop.

## Read first

- `docs/adr/ADR-005-small-model-investigator.md` (accepted) and `docs/design/investigator-v2.md` (approved). These are the spec for this round. Where this brief and the design differ, this brief wins.
- `docs/design/model-investigator.md`, ADR-003, `src/romulus/agent/*`, the hunt-layer pivot executor, and `src/romulus/bakeoff/*` (the replay harness that rebuilds briefs from the store; it must keep working, see item 6).
- Why: in the M2 ablation (`docs/eval/results/2026-10-19-sl700_e_a-ablation-1v3.md`), qwen3:8b added nothing and 21 of 44 outputs were rejected, every one for composing a value the controller already knew (unknown evidence IDs, duplicate pivots, spawns of undiscovered entities, bad tool args, unknown process IDs).

## Branch

Branch `codex/investigator-v2` from `m2/evaluation` at the commit that contains ADR-005. If `git log m2/evaluation` doesn't show ADR-005, stop and report. Don't touch `eval/`, `docs/eval/`, or ground truth. Never read `/home/user/romulus-eval/`.

## Invariants (unchanged, non-negotiable)

- The model proposes typed actions only, and now only by choosing among options the controller generated. It never writes IDs, timestamps, DSL, paths, filters or claims.
- All model output is validated, and telemetry is untrusted.
- The model cannot change deterministic claims, lanes, scope or coverage.
- Read-only toward telemetry.
- `--no-agent` hunts must produce the same decisions and manifests as today (model-off determinism).

## Items

### 1. Option generator (pure, deterministic)

`romulus.agent.options`: `generate_options(...) -> Menu`, from durable case state, case evidence, candidates, the hunt window and budgets.

- **Pivot options:** every tool × eligible known entity × named window, plus pivot templates from the seed candidates' `next_checks` where they map to a tool.
  - Named windows: anchor ±5 min, ±30 min, ±2 h, and the seed-cluster span, clipped to the hunt window. The anchor is the latest cited event time.
  - `process_tree` is offered only for (host, pid) pairs present in case evidence.
- **Never offered:**
  - executed pivots (use the controller's existing semantic key: tool, UTC window, entity kind/value or host/pid);
  - observer hosts;
  - tool/entity-kind mismatches;
  - empty or out-of-hunt windows.
- **Spawn options:** entities discovered by this case's pivots that are not already a case and not observers, only while `max_cases` is not reached.
- **Conclusions:** one escalate option per seed candidate, with claim and lane prefilled from the candidate. Plus one park option and one close option, always.
- **Each option has:** a stable ID, a one-line plain description (e.g. `auth_activity for account root, anchor ±30 min`), the fully typed decision it resolves to, and for pivots a template hypothesis with expected true/false text.
- **Ranking:** rule templates, then the tightest window, then host > account > IP > domain, then a stable key. Cap at 12 options, with conclusions always included, and record how many were hidden by the cap.
- **Done when:** unit tests prove every "never offered" rule, stable ordering across runs, the cap accounting, and that each option resolves to a decision today's `validate_decision` accepts.

### 2. Aliases and brief v2

Rebuild `build_brief` around the menu. It stays the single pure brief builder from durable state, and may take the extra inputs it needs.

- **Contents:**
  - evidence cards `E1…E16`: family, ts, host, outcome, up to 4 typed fields, existing truncation;
  - entities `N1…`;
  - candidates `C1…`: claim, lane, cited cards;
  - prior steps: option chosen, outcome, result counts and new entities;
  - the menu `O1…On`.

  Everything except the fixed system text stays inside the untrusted-telemetry delimiters.
- **Aliases** are per call and deterministic (ordered as today). The alias map is persisted with the step so a replay resolves it exactly.
- **Size:** keep the shrink policy. The v2 brief should fit 8192 without shrinking in normal cases. Report how often shrinking still happens on the lab hunt.
- **Interface:** `BuiltBrief` gains `schema`, `menu` and `aliases`. `prompt_digest` must cover system + user + schema.
- **Done when:** golden-brief tests exist, briefs are byte-stable for the same state, and injection flags still work on cards.

### 3. Per-call constrained schema and resolver

- **Schema:** `anyOf` over the offered options. Each branch has:
  - `option`: const, the option's ID;
  - `evidence`: an array of 1–4 unique items, each an enum of the aliases valid for that option. Escalate → that candidate's cited cards. Close/park → cards not flagged as injected. Pivot/spawn → all cards;
  - `rationale`: string, maxLength 300;
  - `benign_alternative`: optional string, maxLength 200;
  - no other properties.
- **Verify live** that Ollama 0.40.3 with qwen3:8b enforces this schema (const, enum, anyOf). If it rejects `anyOf`, fall back to a flat schema (`option` enum plus an `evidence` enum of all cards) and enforce the per-option evidence subsets in the resolver. Record which form is in use.
- **Resolver:**
  1. Map option and aliases to an `AgentDecision`.
  2. Truncate over-long text deterministically and flag it.
  3. Run the existing `validate_decision` and duplicate check as defence in depth.

  A rejection after constrained decoding is logged as `constraint_defect`.
- **Done when:** tests prove that unknown option or alias values are unrepresentable in the schema, that resolution is exact, and that a hostile-flagged card can never support close or park.

### 4. Controller changes and agent modes

- **Config:** `AGENT_MODE` = `model` (default) | `deterministic` | `off`, with CLI `--agent-mode`. `--no-agent` stays as an alias for `off`.
- **`model`:** one call per step with the menu, and one retry on failure. After a second failure, take the top-ranked pivot option, recorded as `deterministic_fallback` with an analyst-visible note. Fallback-park only when no pivot option remains.
- **`deterministic`:** no model calls.
  - Take the top-ranked pivot option each step until no pivot options or budget remain, then park with reason `deterministic investigation complete`.
  - Never escalate or close.
  - Reproducible: the same store state gives the same steps.
- **Unchanged:**
  - Ollama outage behaviour (partial and resumable; acceptance scenario 16);
  - budgets, leases, resume, crash replay and pivot persistence.
- **Persist per step:**
  - the menu (IDs, descriptions, resolved decisions) and the hidden count;
  - the alias map;
  - the chosen option;
  - the mode, and whether it was a fallback.

  Prefer existing JSON columns. Add an Alembic migration only if needed, and keep it additive.
- **Done when:** acceptance scenarios 13–17 and every existing agent test pass. Update tests only where the interface legitimately changed, and list which. New tests cover both modes, the fallback path, determinism of `deterministic` mode, and resume of a v2 case.

### 5. Reporting

The Investigations section, the CLI and the web summary show:
- the agent mode;
- the chosen option descriptions;
- deterministic-fallback notes;
- per-case menu-cap counts.

The manifest stays the single source, and every renderer must agree with it.
- **Done when:** report tests are updated and the manifest-vs-renderer agreement tests pass.

### 6. Keep the replay harness working

`romulus model bakeoff-export` must still rebuild every v2 brief from the store and match `prompt_digest`, which now covers system + user + schema.

Make the minimal changes in `src/romulus/bakeoff/` that v2 requires:
- the export rewinds case state to before a step and calls `build_brief`;
- tasks carry the schema, menu and alias map;
- the runner sends the task's schema and resolves with the v2 resolver.

Don't rename the module (Claude will).
- **Done when:** `tests/test_bakeoff.py` is updated to v2 and passes, including 100% digest match on a scripted v2 investigation.

### 7. Verify, deploy, live runs

- Run the full suite (`.\.venv\Scripts\python -m pytest -q -p no:warnings`), `ruff check`, and `python scripts/archmap.py --check`. Regenerate the map if modules changed.
- Deploy a clean commit with `powershell -File scripts/deploy.ps1 -SkipInstall` (full install only if dependencies changed), and verify the VM stamp.
- On e_a, window `2024-11-18T10:00:00Z`–`2024-11-18T17:30:00Z`, run three hunts: `--agent-mode off`, `--agent-mode deterministic`, `--agent-mode model`. Publish a report revision for each with `romulus report <hunt>`.
- Report for each hunt:
  - execution state, lanes, records/events/errors, broken citations;
  - agent status, cases, steps, pivots (complete/partial);
  - model calls, valid on first attempt, constraint defects, deterministic fallbacks;
  - candidates with `source_case_id`, seeds concluded/unworked;
  - wall time, and how often briefs were shrunk.
- `off` must match the earlier model-off lanes: 7 urgent / 10 high / 80 lead / 504 context.
- **Done when:** all three hunts are complete and reported. Don't score them against ground truth; the eval-custodian does that.

## Hand back

Add your section at the top of this file as `# <date time> · Codex → Claude: INVESTIGATOR V2 ROUND COMPLETE`. Include:
- commits, one line each;
- files changed;
- test-first evidence per item;
- the schema form in use (anyOf or flat), with the live evidence for it;
- final verification output;
- the deployment stamp;
- the three hunt tables;
- any place you deviated from this brief, and why;
- open issues.

Then stop.
