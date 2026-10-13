# Adaptive Stopping and Progress Ledger Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace validation-era stopping behavior with a persisted, deterministic progress ledger and progress-aware routing while retaining finite configurable safety backstops.

**Architecture:** A new pure `progress.py` module derives stable investigation snapshots, classifies material changes, maintains bounded stagnation state, and returns deterministic routing decisions. `HuntEngine` records progress after evidence analysis and reasoning, then uses one shared router for post-analysis and post-reasoning decisions. Reports and compact retention preserve only aggregate progress and the final stop basis.

**Tech Stack:** Python 3.11+, `unittest`, existing LangGraph workflow, SQLite persistence, dataclass-backed environment settings.

**Spec:** `docs/superpowers/specs/2026-10-13-adaptive-evidence-grounded-hunting-design.md`

## Global Constraints

- An undirected hunt makes no model call and creates no hypothesis before a deterministic telemetry candidate exists.
- Every stop decision is derived from persisted state; model `continue_investigation` output is advisory only.
- Production defaults are `MAX_RUNTIME_SECONDS=3600`, `MAX_DEPTH=40`, `MAX_TOOL_CALLS=500`, and `MAX_STAGNANT_CYCLES=3`.
- Accepted finite ranges are 10–86,400 seconds, 1–200 reasoning rounds, 1–5,000 external calls, and 1–10 stagnant cycles.
- `MIN_REASONING_ROUNDS` remains loadable for one compatibility cycle but does not force model turns.
- Critical/high deterministic work retains precedence over model reasoning and low-value breadth.
- A hard safety ceiling or exhausted productive frontier cannot produce a clean conclusion while required coverage remains incomplete.
- No external-corpus address, account, hostname, domain, product, vulnerability, command, filename, shell path, timestamp, or attack sequence may enter runtime code, prompts, catalogs, or committed fixtures.
- Compact retention keeps aggregate progress and the final stop basis, not detailed progress history or baselines.
- No new runtime dependency and no active or mutating telemetry action.

## Review Focus

- Resumed legacy state with no progress fields must initialize without treating all prior work as a new productive cycle; `test_initialize_progress_baselines_legacy_state_without_incrementing_stagnation` owns this case.
- Repeated zero-result searches count as progress only when the exact terminal outcome resolves a previously open task or follow-up; `test_compare_progress_distinguishes_resolving_zero_from_repeated_terminal_state` owns this case.
- A model can register distinct but useless searches; registration may expose a frontier once, but a partial, capped, or otherwise nonresolving no-change cycle must still advance stagnation; `test_nonresolving_low_value_search_without_state_change_advances_stagnation` owns this case.
- Reaching the reasoning ceiling on the same cycle that establishes valid coverage closure must not downgrade the already-closed hunt; `test_valid_closure_wins_after_final_allowed_reasoning_turn` owns this case.
- A partial or source-failed hunt stopped for stagnation must report `no_productive_frontier` without claiming closure; `test_stagnation_report_remains_partial_when_coverage_is_open` owns this case.

---

### Task 1: Pure progress and stop-decision contract

**Files:**
- Create: `romulus/investigation/progress.py`
- Create: `tests/test_progress.py`

**Interfaces:**
- Produces: `initialize_progress(state: MutableMapping[str, Any]) -> None`.
- Produces: `snapshot_progress(state: Mapping[str, Any]) -> dict[str, Any]`.
- Produces: `compare_progress(previous: Mapping[str, Any], current: Mapping[str, Any]) -> dict[str, Any]`.
- Produces: `record_progress(state: MutableMapping[str, Any], stage: str, *, history_limit: int = 100) -> dict[str, Any]`.
- Produces: `summarize_progress(state: Mapping[str, Any]) -> dict[str, Any]`.
- Produces: `decide_next_action(*, hard_limit_reason: str | None, reasoning_limit_reason: str | None, coverage_closed: bool, queued_priority_tier: int | None, grounded: bool, can_reason: bool, just_reasoned: bool, stagnant_cycles: int, max_stagnant_cycles: int) -> dict[str, Any]` returning `action` (`pivot`, `reason`, or `report`) and optional `termination_reason`.
- Consumes: `romulus.investigation.scheduler.outcome_resolves(outcome)` for exact terminal resolution.

- [ ] **Step 1: Write failing snapshot and comparison tests**

Add `ProgressSnapshotTests` covering:

```python
def test_snapshot_marks_stable_investigation_transitions():
    # Assert stable IDs/state for evidence, candidates and follow-ups,
    # execution fingerprints, resolving outcomes, hypothesis assessments,
    # graph nodes/edges/paths, and open coverage gaps.

def test_compare_progress_ignores_prose_duplicates_and_raw_count_churn():
    # Change summary/reasoning prose, ordering, duplicate IDs, and raw counters.
    # Assert material_progress is False and changed_ids is empty.

def test_compare_progress_distinguishes_resolving_zero_from_repeated_terminal_state():
    # A newly resolving exact zero closes an open task once; replaying that
    # already-recorded outcome produces no additional progress.
```

- [ ] **Step 2: Run the focused tests and verify RED**

Run: `python -m unittest -v tests.test_progress.ProgressSnapshotTests`

Expected: FAIL because `romulus.investigation.progress` does not exist.

- [ ] **Step 3: Implement snapshot and comparison primitives**

`snapshot_progress` records sorted stable identities rather than raw prose or timestamps. Coverage-gap identities come from open hypothesis IDs, candidate IDs, unfinished follow-up IDs, and unresolved task IDs. `compare_progress` returns bounded changed-ID lists and per-signal counts; newly closed gaps and newly resolving outcomes are material, while duplicate/reordered state is not.

- [ ] **Step 4: Run the snapshot tests and verify GREEN**

Run: `python -m unittest -v tests.test_progress.ProgressSnapshotTests`

Expected: all `ProgressSnapshotTests` pass.

- [ ] **Step 5: Write failing persistence, stagnation, and decision tests**

Add `ProgressLedgerTests` and `StopDecisionTests` covering:

```python
def test_initialize_progress_baselines_legacy_state_without_incrementing_stagnation():
    # Missing fields become a baseline, empty bounded history, and zero streak.

def test_record_progress_resets_after_material_change_and_bounds_history():
    # Unchanged cycles increment; a real change resets to zero; retain <=100.

def test_nonresolving_low_value_search_without_state_change_advances_stagnation():
    # Registration can add frontier state, but its partial/capped or otherwise
    # nonresolving terminal cycle increments the streak instead of resetting it.

def test_stop_decision_preserves_limit_closure_and_high_value_precedence():
    # Hard limit reports; valid closure reports coverage_closure_reached;
    # otherwise queued tier 1/2 work pivots before stagnation or reasoning.

def test_stop_decision_stops_stagnant_breadth_and_never_reads_model_advice():
    # Three stagnant cycles with only tier 3+ or no work reports
    # no_productive_frontier; the API has no continue_investigation input.
```

- [ ] **Step 6: Run the new tests and verify RED**

Run: `python -m unittest -v tests.test_progress.ProgressLedgerTests tests.test_progress.StopDecisionTests`

Expected: FAIL because ledger and stop-decision functions are missing.

- [ ] **Step 7: Implement the bounded ledger and deterministic decision table**

First observation establishes a baseline without claiming progress or incrementing stagnation. Later entries contain stage, material flag, signal counts, bounded changed IDs, and current streak; they do not copy evidence or model prose. The decision order is: hard tool/runtime limit; established closure; tier 1/2 work; exhausted stagnation; post-reasoning queued work; eligible grounded reasoning ahead of tier 3+ breadth; remaining queued work; an open frontier blocked by the reasoning ceiling; otherwise `no_productive_frontier`. This lets already-established closure remain valid after the final allowed reasoning turn while still reporting `depth_budget` when unresolved work needs another reasoning turn.

- [ ] **Step 8: Run the complete progress tests**

Run: `python -m unittest -v tests.test_progress`

Expected: all progress tests pass.

- [ ] **Step 9: Commit Task 1**

```bash
git add romulus/investigation/progress.py tests/test_progress.py
git commit -m "feat: add deterministic hunt progress ledger"
```

---

### Task 2: Production safety settings and backward-compatible state

**Files:**
- Modify: `romulus/config.py`
- Modify: `.env.example`
- Modify: `romulus/investigation/workflow.py`
- Modify: `tests/test_core.py`
- Modify: `tests/test_candidate_loop.py`

**Interfaces:**
- Consumes: Task 1 `initialize_progress(state)`.
- Produces: `Settings.max_stagnant_cycles: int`.
- Produces: new-hunt and resumed-hunt state fields `progress_baseline`, `progress_history`, and `stagnant_cycles`.
- Preserves: `Settings.min_reasoning_rounds` for environment compatibility and reporting during the deprecation cycle.

- [ ] **Step 1: Write failing configuration tests**

In `tests/test_core.py`, replace the loose budget assertion with exact production defaults and add environment-bound tests:

```python
def test_default_configuration_uses_production_safety_backstops():
    assert (cfg.max_runtime_seconds, cfg.max_depth, cfg.max_tool_calls,
            cfg.max_stagnant_cycles) == (3600, 40, 500, 3)

def test_safety_backstops_clamp_to_documented_finite_ranges():
    # Patch extreme environment values and assert 86400, 200, 5000, and 10.
```

Also assert `.env.example` carries the same four defaults.

- [ ] **Step 2: Run configuration tests and verify RED**

Run: `python -m unittest -v tests.test_core.CoreTests.test_default_configuration_uses_production_safety_backstops tests.test_core.CoreTests.test_safety_backstops_clamp_to_documented_finite_ranges`

Expected: FAIL on the old 600/10/160 defaults and missing `max_stagnant_cycles`.

- [ ] **Step 3: Implement settings and example-environment changes**

Add the dataclass field and parse the four values with the exact defaults/ranges from the spec. Keep `MIN_REASONING_ROUNDS` loadable but add a comment identifying it as compatibility-only routing metadata.

- [ ] **Step 4: Run configuration tests and verify GREEN**

Run: `python -m unittest -v tests.test_core.CoreTests.test_default_configuration_uses_production_safety_backstops tests.test_core.CoreTests.test_safety_backstops_clamp_to_documented_finite_ranges`

Expected: both tests pass.

- [ ] **Step 5: Write failing state-schema and initialization tests**

In `tests/test_candidate_loop.py`, assert `HuntState.__annotations__` contains the three progress fields. Add a focused engine-state test proving a new hunt and a supplied legacy/resume mapping call `initialize_progress` without erasing an existing baseline, history, or streak.

- [ ] **Step 6: Run state tests and verify RED**

Run: `python -m unittest -v tests.test_candidate_loop.CandidateLoopTests.test_hunt_state_contains_candidate_loop_fields tests.test_candidate_loop.CandidateLoopTests.test_hunt_initialization_preserves_or_baselines_progress_state`

Expected: FAIL because the workflow schema and run initialization do not include progress state.

- [ ] **Step 7: Add progress state to workflow initialization**

Annotate the three JSON-serializable fields on `HuntState`. Call `initialize_progress` after scheduler initialization for both new and resumed state. Legacy state establishes its current snapshot as a baseline and does not gain a false productive cycle.

- [ ] **Step 8: Run Task 2 tests**

Run: `python -m unittest -v tests.test_core tests.test_candidate_loop tests.test_progress`

Expected: all named modules pass, allowing only existing dependency-gated skips.

- [ ] **Step 9: Commit Task 2**

```bash
git add .env.example romulus/config.py romulus/investigation/workflow.py tests/test_core.py tests/test_candidate_loop.py
git commit -m "feat: raise configurable hunt safety backstops"
```

---

### Task 3: Shared progress-aware investigation routing

**Files:**
- Modify: `romulus/investigation/workflow.py`
- Modify: `tests/test_scheduler_execution.py`
- Modify: `tests/test_candidate_loop.py`
- Modify: `tests/test_core.py`

**Interfaces:**
- Consumes: Task 1 `record_progress`, `decide_next_action`, and `summarize_progress`.
- Consumes: Task 2 `Settings.max_stagnant_cycles` and persisted progress fields.
- Produces: `HuntEngine._route_investigation(state: HuntState, *, just_reasoned: bool) -> str` as the sole post-analysis/post-reasoning routing authority.
- Produces: termination reasons `coverage_closure_reached`, `no_productive_frontier`, `tool_call_budget`, `runtime_budget`, and `depth_budget` with their existing meanings preserved where applicable.

- [ ] **Step 1: Write failing routing-order tests**

Extend `tests/test_scheduler_execution.py` with:

```python
def test_shared_router_drains_critical_and_high_work_before_stagnation():
    # Tier 1/2 queued task returns pivot even at the stagnation threshold.

def test_shared_router_reasons_once_ahead_of_low_value_breadth():
    # Grounded, below ceilings, tier 3+ queued work returns reason before pivot.

def test_shared_router_stops_low_value_breadth_after_stagnation_threshold():
    # Tier 3+ queued work plus streak==max returns report and
    # no_productive_frontier.

def test_shared_router_does_not_force_minimum_reasoning_rounds():
    # No queued work after a reasoning turn reports immediately even when
    # min_reasoning_rounds is larger than depth.

def test_valid_closure_wins_after_final_allowed_reasoning_turn():
    # Already-established closure reports coverage_closure_reached rather
    # than being downgraded solely because depth now equals its ceiling.
```

- [ ] **Step 2: Run routing tests and verify RED**

Run: `python -m unittest -v tests.test_scheduler_execution.SchedulerExecutionTests.test_shared_router_drains_critical_and_high_work_before_stagnation tests.test_scheduler_execution.SchedulerExecutionTests.test_shared_router_reasons_once_ahead_of_low_value_breadth tests.test_scheduler_execution.SchedulerExecutionTests.test_shared_router_stops_low_value_breadth_after_stagnation_threshold tests.test_scheduler_execution.SchedulerExecutionTests.test_shared_router_does_not_force_minimum_reasoning_rounds tests.test_scheduler_execution.SchedulerExecutionTests.test_valid_closure_wins_after_final_allowed_reasoning_turn`

Expected: FAIL because `_route_investigation` does not exist and the old routers still force minimum rounds.

- [ ] **Step 3: Implement the shared router**

`_after_analyze` registers investigation work and delegates with `just_reasoned=False`; `_after_reason` delegates with `just_reasoned=True`. The router selects the next queued task, derives closure and grounded state, distinguishes hard tool/runtime limits from a `depth_budget` reasoning limit, calls `decide_next_action`, writes only the returned termination reason, saves the state, and returns the action. Delete the duplicated routing branches and remove `min_reasoning_rounds` from routing decisions.

- [ ] **Step 4: Run routing tests and verify GREEN**

Run the five tests from Step 2.

Expected: all five pass.

- [ ] **Step 5: Write failing cycle-recording and model-advice tests**

Add focused tests proving:

```python
def test_analysis_and_reasoning_record_progress_before_routing():
    # `_analyze` and `_reason` each update the persisted baseline/history.

def test_model_continue_true_cannot_override_exhausted_frontier():
    # Structured model output with no accepted work cannot keep the loop alive.

def test_nonresolving_search_without_material_change_advances_stagnation():
    # Pivot -> analyze with a partial/capped result and duplicate/no new state
    # increments the streak.

def test_material_evidence_or_closed_gap_resets_stagnation():
    # New admitted evidence or newly resolved task resets the streak.

def test_undirected_hunt_without_candidate_still_never_reasons():
    # Preserve the evidence-first invariant under the new shared router.
```

- [ ] **Step 6: Run the new cycle tests and verify RED**

Run the individual test names added in Step 5 from `tests.test_scheduler_execution` and `tests.test_candidate_loop`.

Expected: FAIL because progress is not yet recorded at the cycle boundaries and old model termination state still influences routing.

- [ ] **Step 7: Record progress at deterministic cycle boundaries**

Call `record_progress` after `_analyze` has rebuilt candidates, graph, and coverage, and after `_reason` has applied admitted assessments/search registrations. Do not use model prose or `continue_investigation` as a progress signal. Keep the baseline and history persisted through `_save`. A task registration is visible as frontier state once; its completed no-change outcome is a later non-progress cycle.

- [ ] **Step 8: Normalize stop reasons and partial semantics**

When the shared router stops for `no_productive_frontier`, leave open scheduler work visible so report finalization records it as unexecuted. Safety ceiling and open-frontier stops remain partial. Valid closure remains eligible for completed status. Replace old normal-exhaustion expectations such as `lead_queue_exhausted`, `no_useful_leads`, and `coverage_frontier_exhausted` only where the new decision table now governs them; keep legacy values readable in persisted reports.

- [ ] **Step 9: Run workflow-focused regressions**

Run: `python -m unittest -v tests.test_progress tests.test_candidate_loop tests.test_scheduler_execution tests.test_core`

Expected: all named modules pass, allowing only existing dependency-gated skips.

- [ ] **Step 10: Commit Task 3**

```bash
git add romulus/investigation/workflow.py tests/test_scheduler_execution.py tests/test_candidate_loop.py tests/test_core.py
git commit -m "feat: route hunts by measured investigation progress"
```

---

### Task 4: Honest reporting, compact retention, documentation, and proof

**Files:**
- Modify: `romulus/reporting/report.py`
- Modify: `romulus/retention.py`
- Modify: `tests/test_customer_report.py`
- Modify: `tests/test_retention.py`
- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Modify: `VALIDATION.md`

**Interfaces:**
- Consumes: Task 1 `summarize_progress(state)` and Task 3 final termination reason.
- Produces: `coverage.progress_summary`, `coverage.max_stagnant_cycles`, and `coverage.stagnant_cycles` in the completed technical state.
- Produces: compact coverage retaining those aggregate fields while omitting `progress_baseline` and `progress_history`.

- [ ] **Step 1: Write failing report tests**

Add to `tests/test_customer_report.py` and `tests/test_scheduler_execution.py`:

```python
def test_technical_report_explains_progress_stop_and_emergency_backstops():
    # Text report includes final stop basis, productive/stagnant cycle totals,
    # current/max stagnation, and used/maximum runtime/calls/rounds.

def test_stagnation_report_remains_partial_when_coverage_is_open():
    # no_productive_frontier + open ledger cannot set closure_ready or completed.

def test_customer_report_uses_plain_language_without_progress_internals():
    # Customer DOCX states investigation ended without another productive
    # evidence pivot and retains the no-clean-environment limitation; it omits
    # baseline hashes, changed-ID lists, and raw progress history.
```

- [ ] **Step 2: Run report tests and verify RED**

Run the individual test names from Step 1.

Expected: FAIL because progress summaries and new stop-language are absent.

- [ ] **Step 3: Add final progress summary and audience-appropriate reporting**

Before report generation, write the bounded summary and configured backstop values into coverage. The technical text appendix may expose aggregate counters and stop basis. The customer report receives only a plain-language limitation and never internal progress history or changed IDs.

- [ ] **Step 4: Run report tests and verify GREEN**

Run the individual test names from Step 1.

Expected: all report tests pass.

- [ ] **Step 5: Write failing compact-retention tests**

Extend the retention fixture with a baseline, multiple progress-history entries, current/max stagnation, and an aggregate progress summary. Assert compact state removes baseline/history but preserves the aggregate summary and final stop basis.

- [ ] **Step 6: Run retention test and verify RED**

Run: `python -m unittest -v tests.test_retention.RetentionTests.test_compact_retention_is_hunt_scoped_report_gated_and_idempotent`

Expected: FAIL because compact coverage does not yet preserve progress aggregates.

- [ ] **Step 7: Implement compact progress retention**

Add only `progress_summary`, `max_stagnant_cycles`, and `stagnant_cycles` to `_compact_coverage`. Do not add detailed history, baselines, model prose, task queries, or rejected proposals to compact state.

- [ ] **Step 8: Run retention and report modules**

Run: `python -m unittest -v tests.test_retention tests.test_customer_report tests.test_scheduler_execution`

Expected: all named modules pass, allowing only existing dependency-gated skips.

- [ ] **Step 9: Update operator documentation**

Update README and `.env` documentation to describe progress-aware stopping, the four production backstops, the compatibility-only status of `MIN_REASONING_ROUNDS`, partial semantics, and explicit small settings for test/validation runs. Add a concise CHANGELOG entry. Do not mention holdout details beyond the generic blind-evaluation boundary already recorded in the design.

- [ ] **Step 10: Run repository-wide local verification**

Run: `python main.py test`

Expected: the complete local suite passes; only documented dependency-gated skips are allowed.

Run: `python -m compileall -q romulus tests`

Expected: exit 0 with no output.

Run: `git diff --check`

Expected: exit 0 with no output.

- [ ] **Step 11: Commit Task 4 runtime/docs changes**

```bash
git add romulus/reporting/report.py romulus/retention.py tests/test_customer_report.py tests/test_retention.py README.md CHANGELOG.md
git commit -m "docs: explain progress-aware hunt completion"
```

- [ ] **Step 12: Deploy the exact candidate commit to the authorized development VM**

Create a secret-free archive of the committed tree, record its SHA-256, copy it over the previously authorized SSH path, verify the same SHA-256 remotely, and extract it into an isolated disposable validation directory. Preserve the VM's operational `.env`, telemetry, hunt state, reports, and external oracle files.

- [ ] **Step 13: Run dependency-complete VM proof**

In the isolated VM directory run:

```bash
python main.py test
python -m compileall -q romulus tests
python main.py doctor
python main.py demo
```

Expected: all dependency-complete tests pass with no skips; compilation is clean; every configured diagnostic is green; the disposable offline hunt reports its progress stop basis, reopens both reports, and applies compact retention without preserving detailed progress history.

- [ ] **Step 14: Record measured proof and clean only disposable artifacts**

Append the exact commit, archive digest, test count, diagnostics, offline hunt ID/outcome, progress-stop evidence, retention evidence, and any limitations to `VALIDATION.md`. Remove only the exact local/remote archive, isolated validation directory, temporary logs, and disposable hunt artifacts. Do not launch a live holdout hunt in this milestone.

- [ ] **Step 15: Commit the validation record**

```bash
git add VALIDATION.md
git commit -m "docs: record adaptive stopping validation"
```

## Completion Gate

- Every production change has a test observed RED before GREEN.
- All Task 1–4 focused tests pass.
- The complete local suite, compilation, and diff check pass.
- A fresh whole-branch review reports no unresolved Critical or Important findings after the single allowed fix pass.
- The exact candidate commit passes the dependency-complete VM suite, compilation, diagnostics, and disposable offline proof.
- Detailed progress history is absent from compact state while aggregate stop evidence remains.
- Runtime code, prompts, catalogs, and fixtures contain no holdout-specific detail.
- The feature branch and existing pull request are updated only after these gates pass.
