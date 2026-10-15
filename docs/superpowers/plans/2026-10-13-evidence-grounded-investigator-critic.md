# Evidence-Grounded Investigator/Critic Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let ROMULUS create and test a small number of competing, falsifiable explanations after a deterministic telemetry lead exists, with a separate critic and deterministic admission gate preventing unsupported reasoning from changing hunt state.

**Architecture:** A pure case-file builder exposes a bounded, structured view of already-admitted evidence, candidates, hypotheses, search outcomes, graph fragments, coverage gaps, and recent novelty. The existing reasoning graph node makes an investigator call and then a critic call, but only a pure admission module may convert critic-approved items into hypotheses, assessments, searches, or findings. Existing scheduler, query, citation, entity, finding, and path validators remain authoritative.

**Tech Stack:** Python 3.11+, `unittest`, existing Ollama structured JSON API, LangGraph, SQLite, python-docx.

**Spec:** `docs/superpowers/specs/2026-10-13-adaptive-evidence-grounded-hunting-design.md`

## Global Constraints

- An undirected hunt makes no model call and creates no hypothesis before a deterministic telemetry candidate exists.
- Every model hypothesis, assessment, search, and finding cites visible candidate or evidence identifiers; unsupported output is rejected and recorded, never repaired.
- The model and critic have no direct tool access, cannot assign scheduler priority, and cannot add evidence, graph facts, leads, or findings directly.
- New hypothesis ATT&CK mappings must be supported by the cited candidate or be `unmapped`.
- Every admitted hypothesis states supporting observations, a falsifying observation, a benign alternative, and at least one critic-approved discriminating search.
- Queries remain bounded, read-only, evidence/operator scoped, and pass the existing source-native validators and unified scheduler.
- Existing deterministic finding and attack-path admission remains mandatory; proximity never becomes causation.
- Model/critic failure records a reasoning gap and falls back to deterministic candidate investigation without admitting partial model output.
- Compact retention keeps aggregate reasoning counts and availability errors but removes case files, proposal/critic payloads, and detailed reasoning history.
- Fixtures must use unrelated synthetic identities and behaviors. Russell Mitchell storyline identities, timestamps, tools, commands, products, and sequence details must not enter runtime code, prompts, catalogs, or committed fixtures.

## Review Focus

- A candidate whose cited evidence exceeds case-file bounds must never expose a candidate without its owned anchor records; Task 1 tests candidate/evidence co-selection.
- One remaining external-call slot must not start an investigator pass that cannot receive its required critic review; Task 4 tests atomic two-call capacity.
- Critic references to unknown proposal/search IDs must reject those items rather than defaulting to approval; Task 3 tests fail-closed reference handling.
- A valid new hypothesis whose compiled search is duplicate or invalid must remain rejected because it lacks a fresh discriminating search; Tasks 3 and 4 test post-validation admission.
- Resumed legacy hunts without reasoning-summary fields must initialize cleanly without inventing prior investigator/critic counts; Task 5 tests backward-compatible aggregation and compact retention.

---

### Task 1: Build a bounded deterministic reasoning case file

**Files:**
- Create: `romulus/investigation/casefile.py`
- Create: `tests/test_casefile.py`

**Interfaces:**
- Produces: `build_case_file(state: Mapping[str, Any], *, evidence_limit: int = 24, candidate_limit: int = 12, hypothesis_limit: int = 16, timeline_limit: int = 24, outcome_limit: int = 30) -> dict[str, Any]`.
- Produces: `visible_case_ids(case_file: Mapping[str, Any]) -> dict[str, set[str]]` with `candidate_ids`, `evidence_ids`, `hypothesis_ids`, `follow_up_ids`, `task_ids`, and `proposal_ids` keys.
- The case file contains `version`, `mission`, `candidates`, `hypotheses`, `evidence`, `timeline`, `path_fragments`, `completed_searches`, `unresolved_follow_ups`, `source_status`, `coverage_gaps`, and `novelty`; it never includes raw query bodies, credentials, or uncited full state.

- [x] **Step 1: Write failing case-file tests**

Add `CaseFileTests` covering:

- `test_case_file_binds_visible_candidates_to_their_owned_evidence`
- `test_case_file_prioritizes_candidate_anchors_when_evidence_is_over_limit`
- `test_case_file_exposes_exact_outcomes_gaps_paths_and_recent_novelty_without_query_bodies`
- `test_case_file_bounds_every_collection_and_normalizes_legacy_shapes`

- [x] **Step 2: Run the case-file tests and verify RED**

Run: `python -m unittest -v tests.test_casefile`

Expected: import failure because `romulus.investigation.casefile` does not exist.

- [x] **Step 3: Implement the minimal pure case-file builder**

Select visible candidates by deterministic priority, admit their owned evidence before representative remainder, build the compact timeline from factual graph/evidence state, summarize exact scheduler outcomes without query bodies, and copy only bounded JSON-safe values. `visible_case_ids` derives sets exclusively from the built case file.

- [x] **Step 4: Run focused and full tests**

Run: `python -m unittest -v tests.test_casefile`

Expected: all case-file tests pass.

Run: `python -m unittest discover tests`

Expected: full suite passes with only dependency-gated local skips.

- [x] **Step 5: Commit**

```bash
git add romulus/investigation/casefile.py tests/test_casefile.py
git commit -m "feat: build bounded reasoning case files"
```

### Task 2: Define separate investigator and critic model contracts

**Files:**
- Modify: `romulus/agent/ollama.py`
- Modify: `tests/test_core.py`

**Interfaces:**
- Consumes: Task 1 case-file shape.
- Produces: `Ollama.investigate_case(case_file: dict[str, Any], source_fields: dict[str, list[str]], max_searches: int = 3, max_hypotheses: int = 3) -> dict[str, Any]`.
- Produces: `Ollama.criticize_case(case_file: dict[str, Any], investigator_output: dict[str, Any]) -> dict[str, Any]`.
- Produces: `_investigator_schema(sources: list[str], hypothesis_ids: list[str], max_searches: int, max_hypotheses: int) -> dict` and `_critic_schema(investigator_output: Mapping[str, Any]) -> dict`.
- Every investigator assessment, hypothesis, search, and finding has a unique bounded `proposal_id`. Assessments/findings reference an existing `hypothesis_id`; searches use `hypothesis_ref`, which is either an existing hypothesis ID or a new-hypothesis `proposal_id`. A new-hypothesis item contains `candidate_id`, owned `evidence_ids`, `title`, `technique_id`, `explanation`, nonempty `expected_host` or `expected_network`, nonempty `falsifying_observations`, nonempty `benign_explanations`, and `analytic_goal`. The critic output contains only `reviews`; each review contains a known `proposal_id`, `accept` or `reject`, issue codes selected from `citation_mismatch`, `unsupported_causality`, `ignored_benign_alternative`, `duplicate_work`, `missing_discriminating_search`, `avoidable_search_cost`, and `malformed`, plus a short rationale. It has no fields for new evidence, hypotheses, searches, findings, ATT&CK mappings, or priority.

- [x] **Step 1: Write failing structured-contract tests**

Add tests proving:

- `test_investigator_schema_allows_three_grounded_competing_hypotheses_with_falsifiers`
- `test_investigator_prompt_receives_only_the_case_file_and_marks_telemetry_untrusted`
- `test_critic_schema_can_only_review_known_proposal_ids`
- `test_critic_prompt_cannot_author_evidence_searches_findings_or_priorities`
- `test_reasoning_preflight_validates_both_structured_contracts`

- [x] **Step 2: Run the focused tests and verify RED**

Run: `python -m unittest -v tests.test_core.CoreTests.test_investigator_schema_allows_three_grounded_competing_hypotheses_with_falsifiers tests.test_core.CoreTests.test_investigator_prompt_receives_only_the_case_file_and_marks_telemetry_untrusted tests.test_core.CoreTests.test_critic_schema_can_only_review_known_proposal_ids tests.test_core.CoreTests.test_critic_prompt_cannot_author_evidence_searches_findings_or_priorities tests.test_core.CoreTests.test_reasoning_preflight_validates_both_structured_contracts`

Expected: failures because the investigator/critic APIs and schemas do not exist.

- [x] **Step 3: Implement the two structured model calls**

Keep model temperature low and response sizes bounded. The investigator must distinguish observation from interpretation, identify expected and falsifying observations, preserve benign explanations, and propose backward/forward discriminating searches. The critic receives the same case file plus only the structured investigator output and reviews citation mismatch, unsupported causality, ignored benign alternatives, duplicate work, missing discrimination, and avoidable search cost.

- [x] **Step 4: Run focused and full tests**

Run the five focused tests from Step 2, then `python -m unittest discover tests`.

Expected: all pass with only dependency-gated local skips.

- [x] **Step 5: Commit**

```bash
git add romulus/agent/ollama.py tests/test_core.py
git commit -m "feat: separate investigator and critic contracts"
```

### Task 3: Add a pure fail-closed reasoning admission gate

**Files:**
- Create: `romulus/investigation/reasoning.py`
- Create: `tests/test_reasoning_admission.py`

**Interfaces:**
- Consumes: Task 1 case file and Task 2 investigator/critic payloads.
- Produces: `admit_reasoning(case_file: Mapping[str, Any], investigator_output: Mapping[str, Any], critic_output: Mapping[str, Any], existing_hypotheses: Sequence[Mapping[str, Any]]) -> dict[str, Any]`.
- Returns `new_hypotheses`, `assessments`, `searches`, `findings`, `rejections`, and `summary`. Each admitted search replaces `hypothesis_ref` with an existing or newly assigned deterministic `hypothesis_id`. Each new hypothesis has basis `model_grounded_competing`, candidate/evidence basis IDs, deterministic anchor entities/time range derived from the cited case-file records, expected host/network observations, falsifying observations, benign explanations, analytic goal, and a stable `H-AI-...` ID hashed from candidate ID, technique, sorted evidence IDs, and normalized expected/falsifying observations—not title, rationale, or critic prose.
- This module does not mutate state, call sources/model, compile queries, or assign scheduler priority.

- [x] **Step 1: Write failing admission tests**

Add tests proving:

- `test_admits_critic_approved_competing_hypothesis_owned_by_visible_candidate`
- `test_rejects_unknown_unowned_or_cross_candidate_citations`
- `test_rejects_unsupported_attack_mapping_and_missing_falsifier_or_benign_alternative`
- `test_rejects_unknown_critic_references_and_unreviewed_items`
- `test_requires_at_least_one_approved_discriminating_search_for_a_new_hypothesis`
- `test_deduplicates_stable_hypotheses_without_using_model_prose_as_fact`

- [x] **Step 2: Run the admission tests and verify RED**

Run: `python -m unittest -v tests.test_reasoning_admission`

Expected: import failure because `romulus.investigation.reasoning` does not exist.

- [x] **Step 3: Implement deterministic normalization and admission**

Validate critic references first, then candidate/evidence ownership, entity/time anchor presence, mapping, required alternatives/falsifiers, approved searches, and duplicate fingerprints. Treat every unknown or malformed reference as a rejection record. Generate stable hypothesis IDs from validated structural fields, not free-form rationales.

- [x] **Step 4: Run focused and full tests**

Run: `python -m unittest -v tests.test_reasoning_admission`

Run: `python -m unittest discover tests`

Expected: all pass with only dependency-gated local skips.

- [x] **Step 5: Commit**

```bash
git add romulus/investigation/reasoning.py tests/test_reasoning_admission.py
git commit -m "feat: gate grounded reasoning admission"
```

### Task 4: Integrate the atomic investigator/critic cycle with the scheduler

**Files:**
- Modify: `romulus/investigation/workflow.py`
- Modify: `tests/test_candidate_loop.py`
- Modify: `tests/test_scheduler_execution.py`

**Interfaces:**
- Consumes: Task 1 `build_case_file`/`visible_case_ids`, Task 2 model methods, Task 3 `admit_reasoning`.
- Produces: `_run_grounded_reasoning(state: HuntState, source_fields: dict[str, list[str]]) -> dict[str, Any] | None`, called only by `_reason` after a deterministic lead/operator-directed telemetry exists and at least two external-call slots remain.
- Produces: `coverage.reasoning_summary` aggregate counters for investigator/critic calls, unavailable passes, proposed/admitted/rejected hypotheses, assessments, searches, and findings.
- Full investigator and critic payloads remain only in working `reasoning_history`; accepted searches still flow through `_register_model_searches`, and accepted findings still flow through `_publish_model_findings`.

- [x] **Step 1: Write failing workflow tests**

Add tests proving:

- `test_undirected_candidate_free_reasoning_makes_no_investigator_or_critic_call`
- `test_grounded_reasoning_runs_investigator_then_critic_and_admits_only_approved_items`
- `test_critic_rejection_changes_no_hypothesis_search_finding_or_graph_fact`
- `test_critic_failure_discards_investigator_output_and_continues_deterministic_candidate_work`
- `test_one_remaining_external_call_does_not_start_an_unreviewable_investigator_pass`
- `test_new_hypothesis_is_rejected_if_its_search_fails_existing_validation_or_deduplication`
- `test_model_priority_fields_cannot_change_scheduler_order`

- [x] **Step 2: Run the workflow tests and verify RED**

Run: `python -m unittest -v tests.test_candidate_loop.MissionModeTests.test_undirected_candidate_free_reasoning_makes_no_investigator_or_critic_call tests.test_scheduler_execution.SchedulerInvestigationWorkflowTests.test_grounded_reasoning_runs_investigator_then_critic_and_admits_only_approved_items tests.test_scheduler_execution.SchedulerInvestigationWorkflowTests.test_critic_rejection_changes_no_hypothesis_search_finding_or_graph_fact tests.test_scheduler_execution.SchedulerInvestigationWorkflowTests.test_critic_failure_discards_investigator_output_and_continues_deterministic_candidate_work tests.test_scheduler_execution.SchedulerInvestigationWorkflowTests.test_one_remaining_external_call_does_not_start_an_unreviewable_investigator_pass tests.test_scheduler_execution.SchedulerInvestigationWorkflowTests.test_new_hypothesis_is_rejected_if_its_search_fails_existing_validation_or_deduplication tests.test_scheduler_execution.SchedulerInvestigationWorkflowTests.test_model_priority_fields_cannot_change_scheduler_order`

Expected: failures because the workflow still performs a one-pass analyst call and does not admit grounded competing hypotheses.

- [x] **Step 3: Implement the two-call workflow and final validation sequence**

Reserve two model-call slots before starting. Build one case file, call investigator, call critic, run `admit_reasoning`, tentatively normalize new hypotheses, and send searches through existing validation/compilation/deduplication. Commit a new hypothesis to state only when at least one of its approved searches becomes a real scheduler task. Apply only approved assessments/findings after their existing citation/entity/mapping checks. Record rejected items and availability gaps without inventing replacements.

- [x] **Step 4: Run focused and full tests**

Run the exact command from Step 2, then `python -m unittest discover tests`.

Expected: all pass with only dependency-gated local skips.

- [x] **Step 5: Commit**

```bash
git add romulus/investigation/workflow.py tests/test_candidate_loop.py tests/test_scheduler_execution.py
git commit -m "feat: run grounded investigator critic cycle"
```

### Task 5: Report and retain reasoning coverage without model bulk

**Files:**
- Modify: `romulus/reporting/report.py`
- Modify: `romulus/retention.py`
- Modify: `tests/test_customer_report.py`
- Modify: `tests/test_retention.py`

**Interfaces:**
- Consumes: Task 4 `coverage.reasoning_summary` and working `reasoning_history` review records.
- Produces: a technical TXT `INVESTIGATOR AND CRITIC COVERAGE` section containing aggregate calls, admissions, rejections by reason, and availability gaps without raw prompts/query bodies.
- Preserves: customer DOCX wording at findings/coverage level only; no proposal IDs, critic payloads, prompts, or internal role terminology.
- Preserves under compact retention: `coverage.reasoning_summary`; removes full case files, proposal/critic payloads, and reasoning history.

- [x] **Step 1: Write failing report/retention tests**

Add tests proving:

- `test_technical_report_records_reasoning_admission_and_critic_gap_aggregates`
- `test_customer_report_omits_case_file_proposal_and_critic_internals`
- `test_compact_retention_keeps_reasoning_summary_and_removes_reasoning_payloads`
- `test_legacy_state_without_reasoning_summary_compacts_to_zero_free_absence`

- [x] **Step 2: Run the focused tests and verify RED**

Run: `python -m unittest -v tests.test_customer_report.CustomerWordReportTests.test_technical_report_records_reasoning_admission_and_critic_gap_aggregates tests.test_customer_report.CustomerWordReportTests.test_customer_report_omits_case_file_proposal_and_critic_internals tests.test_retention.RetentionTests.test_compact_retention_keeps_reasoning_summary_and_removes_reasoning_payloads tests.test_retention.RetentionTests.test_legacy_state_without_reasoning_summary_compacts_to_zero_free_absence`

Expected: failures because reasoning aggregates are neither reported nor retained.

- [x] **Step 3: Implement audience-separated reporting and compact aggregation**

Add the technical aggregate section and compact coverage key. Keep raw investigator/critic payloads only in working state and rely on the existing report-verification gate before removal. Legacy hunts may omit the summary; reporting and retention must not invent past calls.

- [x] **Step 4: Run focused and full tests**

Run the exact command from Step 2, then `python -m unittest discover tests`.

Expected: all pass with only dependency-gated local skips.

- [x] **Step 5: Commit**

```bash
git add romulus/reporting/report.py romulus/retention.py tests/test_customer_report.py tests/test_retention.py
git commit -m "feat: report grounded reasoning coverage"
```

### Task 6: Validate Milestone 8 locally and on the development VM

**Files:**
- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Modify: `VALIDATION.md`

**Interfaces:**
- Consumes: Tasks 1–5 complete implementation and the authorized SSH validation path.
- Produces: exact local/VM/offline proof and a clean reviewed branch. The Russell Mitchell live hunt remains Milestone 9 and is not used to alter this milestone's code, prompts, catalogs, or fixtures.

- [x] **Step 1: Run complete local verification**

Run:

```bash
python -m unittest discover tests
python -m compileall -q romulus tests
git diff --check
```

Expected: complete local suite passes with only documented dependency-gated skips; compilation and diff check succeed.

- [x] **Step 2: Update operator documentation**

Document the case file, investigator/critic separation, deterministic admission, two-call capacity rule, reasoning aggregates, model-unavailable behavior, and compact-retention boundary. State explicitly that this milestone used no holdout-derived runtime knowledge.

- [x] **Step 3: Commit the runtime/documentation candidate**

```bash
git add README.md CHANGELOG.md
git commit -m "docs: explain grounded investigator critic reasoning"
```

- [x] **Step 4: Perform exact dependency-complete VM proof**

Archive the exact candidate commit, record and match SHA-256 locally/on the VM, extract into a disposable `/tmp` directory, then run the full dependency-complete suite, `compileall`, and read-only `doctor`. Run one isolated synthetic offline hunt with compact retention; reopen DOCX/TXT reports and verify reasoning aggregate/working-state cleanup. Do not alter operational state or run the Russell holdout during this milestone.

- [x] **Step 5: Record proof and clean exact disposable artifacts**

Append commit, digest, test counts, diagnostics, offline hunt ID/outcome, investigator/critic evidence, retention evidence, and limitations to `VALIDATION.md`. Resolve and verify every cleanup target before removing only the exact local/remote archive, extracted validation root, logs, and disposable runtime.

- [x] **Step 6: Commit validation record**

```bash
git add VALIDATION.md
git commit -m "docs: record grounded reasoning validation"
```

- [x] **Step 7: Whole-branch review and final verification**

Request one fresh-context whole-branch review focused on pre-lead model calls, citation/entity/mapping admission, critic authority leakage, orphan investigator output, scheduler priority injection, model failure, report truth, retention, and holdout leakage. One Critical/Important fix pass is allowed, each fix RED→GREEN, followed by the full suite. Record Minor findings as deferred. Finish with a clean status and exact local/remote head match before opening a stacked PR.

After Milestone 8 is accepted, proceed to the separately recorded Milestone 9 blind read-only hunt now authorized by the operator; only then compare finalized results to the external oracle.
