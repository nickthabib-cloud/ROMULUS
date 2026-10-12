# Unified Search Scheduler Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Route every ROMULUS evidence search through one persistent, evidence-first scheduler with exact deduplication, source fairness, authoritative outcomes, and defensible closure.

**Architecture:** Add a pure scheduler module that owns task identity, ownership merging, ordering, state transitions, and resume recovery. The workflow compiles safe source tasks, executes scheduler selections through existing read-only adapters, and gives the exact outcome back to scheduler, candidate, hypothesis, coverage, and reporting logic. Existing source validation and evidence normalization remain the execution boundary.

**Tech Stack:** Python 3.12, standard-library `hashlib`/`json`, LangGraph state, SQLite persistence, `unittest`.

**Spec:** `docs/superpowers/specs/2026-10-12-unified-search-scheduler-design.md`

## Global Constraints

- An undirected hunt must not call the model before deterministic telemetry creates a candidate.
- Every post-discovery hypothesis or model proposal must cite visible evidence or candidate IDs; unknown or search-artifact-only references are rejected.
- Elasticsearch allowlists, Arkime credentials and expression validation, TShark PCAP allowlists, mission time bounds, read-only behavior, and result caps remain unchanged.
- Exact execution equivalence includes source, sorted source targets/class, normalized query/selectors, and effective time range. Similar prose alone never causes deduplication.
- `partial`, `failed`, `skipped`, `budget_limited`, and `interrupted` work cannot satisfy closure. A confirmed uncapped zero-result search may resolve its task.
- No new runtime dependency, provider, configuration setting, or telemetry source is introduced.
- Customer-report and compact-retention behavior remain compatible; compact state keeps a small scheduler coverage summary, not the full queue/history.
- `SL700_variant_a_b`, AttackMate commands, storyline, labels, indicators, entities, and timestamps are holdout evaluation data only. They must not enter `romulus/`, prompts, catalogs, runtime configuration, fixtures, or scheduler tests.

## Review Focus

- Semantically identical dictionaries with different insertion order must deduplicate, while different source targets or time windows must not.
- A single merged task outcome must update every owner exactly once; a failed/partial outcome must leave all dependent follow-ups unresolved.
- A very small remaining call budget must expose an unserved host/network family as a gap rather than violating fairness or claiming closure.
- Conflicting or incomplete legacy `completed_leads`/result state must migrate without false resolution or an automatic repeat of an outcome-less completed lead.
- A crash after a read-only remote call but before terminal outcome persistence must permit at most one audited retry and disclose possible duplicate execution.

---

### Task 1: Add task identity and duplicate-owner merging

**Files:**
- Create: `romulus/investigation/scheduler.py`
- Create: `tests/test_scheduler.py`

**Interfaces:**
- Consumes: JSON-serializable scheduler proposal dictionaries defined by the spec.
- Produces: `initialize_scheduler(state: MutableMapping[str, Any]) -> None`, `execution_fingerprint(proposal: Mapping[str, Any]) -> str`, and `register_search_task(state: MutableMapping[str, Any], proposal: Mapping[str, Any]) -> tuple[str, bool]`.
- State shape: `search_tasks: dict[str, dict]`, `search_queue: list[str]`, `search_outcomes: list[dict]`, and `scheduler_history: list[dict]`.

- [ ] **Step 1: Write failing fingerprint and merge tests**

Add `SchedulerRegistrationTests` with:

```python
def test_exact_execution_duplicate_merges_all_owners(self):
    # Register catalog and candidate proposals with reordered query keys but
    # identical source, targets, class, window, and query.
    # Assert one ST-* task, one queue entry, created flags True then False,
    # and merged candidate/follow-up/hypothesis/origin lists.

def test_different_target_selector_or_window_is_not_a_duplicate(self):
    # Change one execution field at a time and assert distinct task IDs.

def test_model_origin_cannot_raise_deterministic_priority(self):
    # Register origin=model_proposal with an extreme supplied tier/score.
    # Assert the stored tier is the scheduler's bounded model tier.
```

- [ ] **Step 2: Run the new tests and verify RED**

Run: `python -m unittest tests.test_scheduler.SchedulerRegistrationTests -v`  
Expected: FAIL because `romulus.investigation.scheduler` does not exist.

- [ ] **Step 3: Implement canonical identity and registration**

In `scheduler.py`:

- Validate required source, family, phase, origin, source targets, query specification, and time range.
- Canonicalize mappings/lists into stable JSON and derive `ST-` plus the first 16 uppercase SHA-256 characters.
- Exclude prose intent, owner IDs, origin, priority, and creation sequence from the execution fingerprint.
- Merge owner/origin/anchor lists without duplicates and keep the strongest code-derived priority.
- Append bounded registration/merge summaries to `scheduler_history`; do not store secrets or query responses.

- [ ] **Step 4: Run focused tests and verify GREEN**

Run: `python -m unittest tests.test_scheduler.SchedulerRegistrationTests -v`  
Expected: PASS, 3 tests.

- [ ] **Step 5: Commit**

```text
git add romulus/investigation/scheduler.py tests/test_scheduler.py
git commit -m "feat: add unified search task registration"
```

---

### Task 2: Add deterministic ordering, outcomes, and recovery

**Files:**
- Modify: `romulus/investigation/scheduler.py`
- Modify: `tests/test_scheduler.py`

**Interfaces:**
- Consumes: Task state produced by Task 1.
- Produces: `select_search_tasks(state: MutableMapping[str, Any], *, phase: str, limit: int = 3) -> list[dict]`, `begin_search_task(state, task_id: str, *, now: str | None = None) -> dict`, `record_search_outcome(state, task_id: str, outcome: Mapping[str, Any], *, now: str | None = None) -> dict`, `outcome_resolves(outcome: Mapping[str, Any]) -> bool`, `recover_interrupted_tasks(state) -> list[str]`, and `migrate_legacy_search_state(state) -> None`.

- [ ] **Step 1: Write failing ordering and fairness tests**

Add tests asserting:

- Discovery selection chooses one healthy queued host task and one healthy queued network task before a second task from either family.
- Investigation selection orders trusted/critical, high/operator, evidence-anchored model, coverage, then medium/low work.
- Within a tier, the less-attempted source family wins, followed by deterministic score and creation sequence.
- JSON round-trip preserves selection order.
- A two-call budget with three host and one network task selects one from each family; a one-call budget records the unserved family in scheduler history.

- [ ] **Step 2: Run ordering tests and verify RED**

Run: `python -m unittest tests.test_scheduler.SchedulerOrderingTests -v`  
Expected: FAIL because selection functions are missing.

- [ ] **Step 3: Implement ordering without a new configuration surface**

Use fixed priority ranks from the spec. Derive source-attempt counts from `search_outcomes`; use `created_sequence` as the final stable tie-breaker. Selection returns task copies and does not mark them running until `begin_search_task` is called.

- [ ] **Step 4: Run ordering tests and verify GREEN**

Run: `python -m unittest tests.test_scheduler.SchedulerOrderingTests -v`  
Expected: PASS.

- [ ] **Step 5: Write failing outcome, retry, and legacy migration tests**

Add tests proving:

- `completed` with confirmed zero matches resolves; capped/timeout/partial/failure/skipped/budget outcomes do not.
- One outcome updates the task once and duplicate recording is idempotent.
- A terminal task is never selected again.
- A persisted `running` task becomes `interrupted`, is requeued once, and a second interruption becomes non-runnable with a possible-duplicate disclosure.
- A legacy completed lead with a matching result becomes terminal; one without a result becomes non-resolving `skipped` with reason `legacy_attempt_unknown` and is not rerun.

- [ ] **Step 6: Run outcome tests and verify RED**

Run: `python -m unittest tests.test_scheduler.SchedulerOutcomeTests -v`  
Expected: FAIL because outcome/recovery functions are missing.

- [ ] **Step 7: Implement outcomes, recovery, and legacy normalization**

Keep `search_outcomes` append-only and bounded to concise attempt summaries. `record_search_outcome` updates only its named task. `recover_interrupted_tasks` never promises exactly-once execution. `migrate_legacy_search_state` preserves legacy fields for inspection but makes scheduler outcomes authoritative.

- [ ] **Step 8: Run the scheduler module and full suite**

Run: `python -m unittest tests.test_scheduler -v`  
Expected: PASS.  
Run: `python -m unittest discover -s tests`  
Expected: Existing suite remains green.

- [ ] **Step 9: Commit**

```text
git add romulus/investigation/scheduler.py tests/test_scheduler.py
git commit -m "feat: schedule searches by evidence value and fairness"
```

---

### Task 3: Create one source-execution outcome boundary

**Files:**
- Modify: `romulus/investigation/workflow.py`
- Create: `tests/test_scheduler_execution.py`

**Interfaces:**
- Consumes: A selected scheduler task from Tasks 1–2 and existing safe source adapters.
- Produces: `HuntEngine._execute_search_task(self, state: HuntState, task: dict) -> dict`, returning the exact normalized outcome accepted by `record_search_outcome`.

- [ ] **Step 1: Write failing source-execution tests**

With existing adapter fakes, add tests for one Elasticsearch task, one Arkime task, and one TShark-per-capture task. Assert each:

- Calls only its allowlisted adapter with the task's effective scope and cap.
- Adds normalized evidence through the existing evidence functions.
- Returns its own `task_id`, status, returned/matched totals, cap/timeout flags, artifact ID, and time range.
- Does not read or mutate an unrelated pivot result.
- Produces `partial` for capped or incomplete responses and a bounded failure outcome for adapter errors.

- [ ] **Step 2: Run execution tests and verify RED**

Run: `python -m unittest tests.test_scheduler_execution -v`  
Expected: FAIL because `_execute_search_task` is missing.

- [ ] **Step 3: Extract the common execution boundary**

Move source dispatch and outcome construction behind `_execute_search_task`. Reuse existing Elasticsearch DSL/native validation, Arkime expression/paging, TShark display-filter validation, mission/anchor time enforcement, caps, `_call`, and evidence-recording helpers. Do not remove old callers until Task 4 routes discovery through this boundary.

- [ ] **Step 4: Run execution and query-safety regressions**

Run: `python -m unittest tests.test_scheduler_execution tests.test_core -v`  
Expected: PASS.

- [ ] **Step 5: Commit**

```text
git add romulus/investigation/workflow.py tests/test_scheduler_execution.py
git commit -m "refactor: unify guarded search execution outcomes"
```

---

### Task 4: Route deterministic discovery through the scheduler

**Files:**
- Modify: `romulus/investigation/workflow.py`
- Modify: `tests/test_scheduler_execution.py`
- Modify: `tests/test_core.py`
- Modify: `tests/test_candidate_loop.py`

**Interfaces:**
- Consumes: Registration/selection/outcome APIs from Tasks 1–3.
- Produces: New `HuntState` fields `search_tasks`, `search_queue`, `search_outcomes`, and `scheduler_history`; graph node `discover`; `HuntEngine._register_discovery_tasks(state) -> list[str]`; and `HuntEngine._drain_scheduled_tasks(state, *, phase: str, limit: int | None = None) -> HuntState`.

- [ ] **Step 1: Write failing workflow discovery tests**

Add tests proving:

- Host behavior/indicator/survey work and Arkime/TShark discovery appear in `search_tasks` before any evidence search executes.
- The first available host and network tasks execute before a second task from one family.
- Two origins that compile to the same exact query/window/targets generate one adapter call and retain both owners.
- Every deterministic evidence query has one scheduler outcome and one execution fingerprint.
- An undirected candidate-free discovery makes zero Ollama calls.
- Budget exhaustion leaves queued tasks represented as explicit gaps and the hunt partial.

- [ ] **Step 2: Run workflow discovery tests and verify RED**

Run: `python -m unittest tests.test_scheduler_execution.SchedulerDiscoveryWorkflowTests -v`  
Expected: FAIL because discovery still executes inside source-specific collection loops.

- [ ] **Step 3: Separate registration from execution**

Keep index discovery, mapping retrieval, and source availability checks in `_collect_host`/`_collect_network`, but replace their evidence-search calls with normalized task registration. Use one TShark task per configured capture so targets and outcomes stay exact. Add `discover` after both collection/inventory nodes and drain discovery in scheduler order, saving state after each task.

Initialize new scheduler state for new hunts. Remove `dynamic_initial_queue` and `dynamic_plan_created` from new state and `HuntState`; tolerate them only during legacy migration.

- [ ] **Step 4: Run discovery and evidence-first regressions**

Run: `python -m unittest tests.test_scheduler_execution tests.test_candidate_loop tests.test_core -v`  
Expected: PASS.

- [ ] **Step 5: Commit**

```text
git add romulus/investigation/workflow.py tests/test_scheduler_execution.py tests/test_core.py tests/test_candidate_loop.py
git commit -m "feat: schedule deterministic discovery across sources"
```

---

### Task 5: Route candidates, model proposals, and coverage through the same queue

**Files:**
- Modify: `romulus/investigation/workflow.py`
- Modify: `romulus/intelligence/analytics.py`
- Modify: `tests/test_candidate_loop.py`
- Modify: `tests/test_scheduler_execution.py`

**Interfaces:**
- Consumes: Scheduler/task execution from Tasks 1–4 and persisted `CandidateLead`/hypothesis state.
- Produces: `HuntEngine._register_directed_initial_tasks(state) -> list[str]`, `HuntEngine._register_investigation_tasks(state) -> list[str]`; model-search registration through `register_search_task`; coverage ledger signature `build_coverage_ledger(hypotheses, search_tasks, search_outcomes, host_available, network_available, candidates=None) -> dict`.

- [ ] **Step 1: Write failing candidate and model ownership tests**

Add tests proving:

- Required follow-ups for critical/high candidates outrank evidence-anchored model and coverage tasks.
- A model proposal referencing an invisible candidate/evidence ID is rejected before registration.
- Model-provided priority cannot move its task above required candidate work.
- Two candidate follow-ups sharing one exact task both receive that task's exact outcome.
- A model task following an older static pivot records its own result, not the last `pivot_results` row.
- An undirected candidate-free reasoning pass neither calls the model nor creates investigation tasks.

- [ ] **Step 2: Run candidate/model scheduler tests and verify RED**

Run: `python -m unittest tests.test_candidate_loop tests.test_scheduler_execution -v`  
Expected: FAIL on missing unified investigation registration/outcome behavior.

- [ ] **Step 3: Replace iterative queue selection**

After both source inventories have registered deterministic discovery work, `_register_directed_initial_tasks` may ask for and register validated initial model searches only when mission mode is directed. Convert candidate-generated lead records, iterative model searches, and coverage-frontier leads into scheduler tasks with merged owner references. `_reason` may assess evidence and register validated proposals but cannot select around scheduler priority. Change `_pivot` into one select/begin/execute/record cycle and feed the returned outcome directly to each owning follow-up.

Stop using `_coverage_fallback`, `lead_queue`, `reasoning_complete`, and `search_fingerprints` as scheduling authorities. Keep legacy fields readable until Task 6 migration tests pass.

- [ ] **Step 4: Write failing closure tests against authoritative outcomes**

Update coverage tests so a high-priority hypothesis/candidate closes only when every owned required task has a resolving outcome and a cited assessment/finding or explicit telemetry gap. Assert zero-result resolution, partial/failure non-resolution, merged ownership, and budget-limited partial status.

- [ ] **Step 5: Run closure tests and verify RED**

Run: `python -m unittest tests.test_candidate_loop.CandidateStateTests.test_hypothesis_closure_requires_every_planned_analytic_and_an_assessment -v`  
Expected: FAIL until `build_coverage_ledger` uses scheduler outcomes.

- [ ] **Step 6: Make scheduler outcomes authoritative for coverage**

Implement the new `build_coverage_ledger` signature. Project legacy `completed_leads` only for backward-compatible reporting; never use it to decide resolution. Preserve actionable-candidate closure rules and explicit telemetry-gap behavior.

- [ ] **Step 7: Run focused and complete suites**

Run: `python -m unittest tests.test_scheduler tests.test_scheduler_execution tests.test_candidate_loop tests.test_core tests.test_behavior_catalog -v`  
Expected: PASS.  
Run: `python -m unittest discover -s tests`  
Expected: Complete suite PASS, with only known dependency-gated local skips.

- [ ] **Step 8: Commit**

```text
git add romulus/investigation/workflow.py romulus/intelligence/analytics.py tests/test_candidate_loop.py tests/test_scheduler_execution.py
git commit -m "feat: unify candidate and coverage scheduling"
```

---

### Task 6: Finish resume compatibility, reporting, retention summary, and validation

**Files:**
- Modify: `romulus/investigation/workflow.py`
- Modify: `romulus/reporting/report.py`
- Modify: `romulus/retention.py`
- Modify: `tests/test_scheduler.py`
- Modify: `tests/test_customer_report.py`
- Modify: `tests/test_retention.py`
- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Modify: `VALIDATION.md`
- Modify: `docs/superpowers/plans/2026-10-12-unified-search-scheduler.md`

**Interfaces:**
- Consumes: Unified tasks/outcomes from Tasks 1–5 and legacy investigation state.
- Produces: Resume-time migration invocation, technical scheduler appendix, compact scheduler summary, and durable validation evidence.

- [x] **Step 1: Write failing resume, report, and compact-state tests**

Add tests proving:

- `run(..., _resume=True)` invokes legacy migration before graph execution and preserves deterministic queued order.
- Terminal tasks are not repeated; an interrupted task is retried no more than once.
- The technical report lists scheduled origin/intent/owners, exact terminal status, returned/matched counts, scope, cap/error, and unresolved gaps without dumping credentials or raw response bodies.
- The customer report does not expose scheduler internals.
- Compact retention drops full task/outcome/history bulk but keeps counts by origin/source/status, duplicate merges avoided, unresolved task count, and source-fairness gaps.

- [x] **Step 2: Run compatibility/report tests and verify RED**

Run: `python -m unittest tests.test_scheduler tests.test_customer_report tests.test_retention -v`  
Expected: FAIL on missing workflow migration/report/compact summary.

- [x] **Step 3: Integrate migration and bounded reporting**

Call `initialize_scheduler`, `migrate_legacy_search_state`, and `recover_interrupted_tasks` before resuming the graph. Render bounded task/outcome summaries only in the technical report. Extend compact coverage with scheduler aggregate counts and gaps; do not retain complete queries, queues, or attempts after finalization.

- [x] **Step 4: Run focused and complete local proof**

Run: `python -m unittest tests.test_scheduler tests.test_scheduler_execution tests.test_candidate_loop tests.test_customer_report tests.test_retention -v`  
Expected: PASS.  
Run: `python -m unittest discover -s tests`  
Expected: Complete suite PASS.  
Run: `python -m compileall -q romulus tests`  
Expected: Exit 0.  
Run: `git diff --check`  
Expected: No output.

- [ ] **Step 5: Run an offline end-to-end proof**

Run a disposable offline hunt under an isolated temporary root and prove:

- All synthetic searches have scheduler tasks/outcomes.
- No duplicate execution fingerprint ran twice.
- Candidate follow-ups cite their own outcomes.
- The cited path and reports remain valid.
- Completed compact retention removes scheduler working bulk and preserves its summary.

- [x] **Step 6: Perform whole-branch review and one fix pass**

Review against the spec and the five Review Focus conditions. Required focus: priority inversion, exact-execution collisions, false closure, resume retry loops, secret leakage, source starvation, and retention growth. Fix Critical/Important findings test-first; record deferred Minor findings in the execution ledger.

- [x] **Step 7: Commit implementation documentation**

Update README architecture/operations, CHANGELOG behavior, VALIDATION measured local proof, and this plan's execution status/decision log.

```text
git add romulus tests README.md CHANGELOG.md VALIDATION.md docs/superpowers/plans/2026-10-12-unified-search-scheduler.md
git commit -m "docs: record unified scheduler behavior"
```

- [ ] **Step 8: Deploy and run dependency-complete VM proof**

Deploy the exact committed code without copying credentials or local runtime data. On the VM run the complete suite, `compileall`, and `doctor`; then run one disposable offline proof and one bounded isolated read-only live hunt only if source health is green. Verify host/network discovery fairness, unique executed fingerprints, correct owner outcomes, and no model call before a valid basis.

- [ ] **Step 9: Evaluate against the external AttackMate holdout after the hunt**

Use the external files `C:/Users/nthca/Desktop/attack_log.json` and `C:/Users/nthca/Desktop/attackmate.json`. Do not expose either file to the ROMULUS process or copy it to the repository or VM.

After reports are closed, read external `attack_log.json` as 53 `actions` records using only `action_uid`, category/description/outcome, `action_info`, `mitre_att&ck`, and start/end times. Use `attackmate.json` JSONL only to clarify human-readable action intent when the structured record is ambiguous. Record, without copying commands or sensitive values into the repository:

- Ground-truth techniques and ordered phases that were observable in configured telemetry.
- Supported ROMULUS matches with cited evidence and compatible entity/time context.
- Incorrect or unsupported reported claims.
- Observable ground-truth steps ROMULUS missed.
- Steps not testable because telemetry was absent or inaccessible.
- For each miss: coverage, budget/scheduling, query execution, candidate promotion, assessment, or reporting cause when determinable.

Do not tune prompts, catalog entries, fixtures, selectors, or priority rules using this same holdout. Run:

`rg -n "SL700|AttackMate|attack_a_b" romulus tests`  
Expected: no matches.

- [ ] **Step 10: Clean up and checkpoint**

Remove only exact disposable validation roots, scripts, and transfer archives after read-only path verification. Do not remove operational VM data, logs, reports, `.env`, telemetry, or external ground-truth files. Update the plan and `VALIDATION.md`, sync those records to the VM, verify hashes, run the final local suite, and pause for operator greenlight.

---

## Completion Contract

- Every new behavior was observed RED before implementation and GREEN afterward.
- All local tests pass; dependency-backed VM tests pass without skips.
- The offline and bounded live validations demonstrate one queue, unique executed fingerprints, source fairness, and exact owner outcomes.
- AttackMate comparison occurs only after the generic hunt and never changes runtime behavior during this milestone.
- Disposable artifacts are removed while operational and external ground-truth data remain untouched.
- The execution ledger and this plan contain every ruling, proof, and remaining limitation needed to resume after context compaction.

## Execution status and decisions

- Tasks 1–5 are complete in commits `60b552c`, `aa472ab`, `893347c`, `19317b6`, and `ac5cb8a` respectively.
- Task 6 steps 1–4 and 6–7 are complete in `e8fb95f`. Focused scheduler/candidate/report/retention proof passed. Subsequent RED/GREEN review added mapping-consistent Elasticsearch family handling, removed nonexecuting labels from identity, canonicalized UTC bounds, persisted one absolute mission window, compiled pending legacy work, kept incomplete legacy results nonresolving, terminalized unrun tasks, propagated late-owner outcomes, and removed pre-telemetry/queued-work model priority inversions. The complete local result is 127 tests with six dependency-gated skips; compilation and diff checks passed. The reviewer found no remaining Critical scheduler defect.
- The first Step 8 no-skip VM run exposed one real LangGraph boundary defect: the untyped `source_health` key was discarded, allowing incomplete task outcomes to close as unavailable-source gaps. The failing integration assertion now proves health persistence and nonclosure, and the corrected VM suite passes all 127 tests with no skips. Exact-commit redeployment, offline/live proof, doctor, and holdout evaluation remain open.
- The subsequent exact-commit `doctor` exposed a planner/adapter TShark allowlist mismatch for valid `tcp.port` and `udp.port` fields. A focused subset-contract test failed RED and passed GREEN after synchronizing the execution allowlist; exact-commit redeployment and the remaining Step 8 gates are still open.
- Exact commit `ae382ec` passed a fully green doctor and isolated offline report/compaction proof. The first holdout-blind live hunt then revealed that generic network candidate follow-ups fanned across Arkime plus every PCAP and that any queued breadth task prevented grounded model reasoning. Two RED/GREEN regressions now enforce Arkime-first generic follow-up and graph-level ordering of high candidate work before model reasoning before lower-value breadth, with the final call reserved for queued source work. Local proof is 129 tests with six dependency skips; redeployment and a replacement live run remain open.
- The obsolete direct model, host-pivot, network-pivot, coverage-fallback, and legacy follow-up paths were removed only after caller searches and focused behavior-preservation tests. Legacy persisted fields remain migration inputs, but new hunts do not create the old scheduling authorities.
- The dependency-light local runtime cannot execute the honest LangGraph/Word offline gate. Step 5 is deferred to the dependency-complete VM rather than being simulated or claimed.
- Implementation documentation is committed through `e8fb95f`; the source-health regression fix is pending its own commit. Exact-commit redeployment, VM offline/live proof, post-hunt holdout comparison, cleanup, and final checkpoint remain open.
