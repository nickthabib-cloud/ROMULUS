# Attack-Path Graph and Safe Retention — Milestone 3

> **For Codex:** Execute this plan in order with `superpowers:test-driven-development`; stop at the verification checkpoint before deployment if any proof fails.

**Goal:** Reconstruct evidence-cited temporal/entity paths without model-created facts, show those paths in both reports, and automatically remove completed-hunt working bulk only after the reports are verified.

**Architecture:** A deterministic graph builder converts normalized evidence into immutable evidence nodes, typed entity nodes, and activity nodes. Observed edges come directly from one record; cross-event edges require an explicit shared entity or an existing conservative host/network correlation and remain labeled as inferred with caveats. Findings reference graph paths assembled only from their cited evidence. A hunt-scoped finalizer verifies both reports, creates a compact manifest, retains cited evidence, and idempotently removes only that hunt's disposable state, log lines, and checkpoints.

**Tech stack:** Python 3.12, SQLite, LangGraph checkpoints, python-docx, unittest.

**Non-goals:** This milestone does not unify the remaining baseline/model/pivot scheduling paths, broaden telemetry collection, or let model output create graph facts. Scheduler consolidation remains a separate milestone so graph correctness and destructive retention behavior can be reviewed independently.

## Execution status — 2026-10-12

- Tasks 1–4 are implemented in commits `f2008b1`, `b2fe2d7`, and `56c4da8`.
- The final local suite passes 86 tests with five dependency-backed checks skipped locally; compilation and whitespace checks pass.
- Three independent review passes are complete. Their report-parsing, JSONL-concurrency, transition-integrity, legacy-state, nested-ECS, documentation, and CLI-observability findings are fixed and covered by regression tests. The final review found no remaining deployment blockers.
- The default policy is `compact`; partial hunts remain resumable, full retention is explicit, and irreversible transitions are rejected before report or state mutation.
- Commit `a08b3ed` is deployed on the development VM. All 86 dependency-complete tests pass there, compilation succeeds, and `doctor` is green for the model, ATT&CK catalog, Elasticsearch, Arkime, TShark, PCAP allowlist, and writable runtime paths.
- Disposable offline hunt `HUNT-D83D7125ED` completed as `evidence_supported_lead`; its reports reopened, its one supported three-step path retained exactly three cited evidence records, and compact retention removed its checkpoint and hunt-scoped JSONL rows.
- Corrected bounded live hunt `HUNT-A4473617E3` collected 150 deterministic context records and 19 candidates before its only model stage. It produced one cited finding and supported path, remained partial/resumable at the intentional depth cap, and did not run hypothesis-generation or initial-search-planning model stages.
- All validation data was isolated under `/tmp` and has been removed. Operational hunts, reports, telemetry, credentials, configuration, and runtime directories were not modified or deleted. Milestone 3 is ready for operator review before scheduler consolidation.

### Decision log

- Report files must be reopened with the real Word parser and match one hunt/report generation before deletion is authorized.
- Finding paths may contain only finding-cited evidence; cross-event links remain explicitly inferred and non-causal.
- Shared JSONL mutation is serialized across processes so one hunt's cleanup cannot erase another hunt's event.
- Legacy compact states without a `finalized` field remain terminal and cannot be resumed.
- A full-retained hunt may later be compacted only after regenerating a compact-policy report; compact data cannot be relabeled full.
- Reports describe compact cleanup as policy intent because cleanup happens only after the reports have been written and verified.
- The first bounded live validation was stopped after a broad phrase (`host and network telemetry`) exposed an optional-separator classifier bug that incorrectly treated `host and` as a concrete host selector. Positive targeting grammar now accepts explicit, quoted, directive, anchored, or structured entity targets while rejecting ordinary scope prose; the exact live objective is a no-model-before-telemetry regression case, and the corrected VM rerun satisfied it.

---

## Task 1: Build the deterministic investigation graph

**Files:**
- Create: `romulus/intelligence/investigation_graph.py`
- Modify: `romulus/investigation/workflow.py`
- Create: `tests/test_investigation_graph.py`

1. Add failing tests proving entity normalization, typed activity extraction, evidence-to-activity provenance, temporal ordering, cross-domain correlation links, deterministic IDs, and explicit inference caveats.
2. Run `python -m unittest tests.test_investigation_graph -v` and confirm the new tests fail because the graph module does not exist.
3. Implement the smallest pure graph builder that satisfies the tests. It must not accept model output and must never turn temporal proximity alone into a causal claim.
4. Add the graph to `HuntState` and rebuild it during `_analyze` after correlation.
5. Re-run the focused tests and the candidate-loop regression tests.

## Task 2: Attach cited paths to findings and reports

**Files:**
- Modify: `romulus/intelligence/investigation_graph.py`
- Modify: `romulus/investigation/workflow.py`
- Modify: `romulus/reporting/report.py`
- Modify: `tests/test_investigation_graph.py`
- Modify: `tests/test_customer_report.py`

1. Add failing tests proving a finding path contains only that finding's cited evidence, orders supported activities by time, keeps disconnected evidence in separate segments, and does not invent a missing step.
2. Add report assertions for a concise customer-facing supported path and a technical edge/caveat appendix.
3. Implement path derivation and attach stable `attack_path_ids` to findings after every analysis pass.
4. Render path steps with timestamps, entities, citations, confidence, and gaps in TXT; render only concise supported steps and caveats in DOCX.
5. Run both focused test modules and inspect a generated Word document programmatically.

## Task 3: Implement hunt-scoped compact finalization

**Files:**
- Modify: `romulus/config.py`
- Modify: `romulus/store.py`
- Create: `romulus/retention.py`
- Create: `tests/test_retention.py`

1. Add failing tests proving report verification is mandatory, completed compact retention keeps cited evidence and structured findings, uncited evidence is removed, another hunt is untouched, JSONL removal is hunt-scoped, checkpoints are removed, and a second run is idempotent.
2. Add a failing test proving partial hunts are not automatically compacted.
3. Implement `compact` and `full` policy parsing, report validation, compact-manifest construction, transactional evidence/state updates, atomic JSONL filtering, and complete checkpoint removal.
4. On cleanup failure, preserve reports and conclusion while recording `retention.status=incomplete` and an error class.
5. Run the focused retention tests.

## Task 4: Integrate automatic and explicit finalization

**Files:**
- Modify: `romulus/investigation/workflow.py`
- Modify: `romulus/cli.py`
- Modify: `tests/test_core.py`
- Modify: `tests/test_retention.py`

1. Add failing workflow tests proving a newly completed hunt auto-compacts only after both reports exist, `full` retains current behavior, and report failure prevents compaction.
2. Add CLI coverage for `--retention compact|full`, `compact --id`, and explicit `finalize --id` for a reported partial hunt.
3. Integrate finalization after the LangGraph connection closes and the terminal state is saved. Never compact workflow-error or unreported hunts.
4. Return and inspect the compact persisted state without changing the hunt outcome.
5. Run the focused workflow and retention tests.

## Task 5: Verify, review, document, and deploy

**Files:**
- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Modify: `VALIDATION.md`

1. Run the complete local suite and `compileall`.
2. Generate an offline completed hunt and prove: reports reopen, the path cites real evidence, uncited working bulk is absent, cited evidence remains, and the hunt has no checkpoint or per-hunt JSONL lines.
3. Review the diff for overclaiming, hunt-ID isolation, deletion scope, secret handling, and backward compatibility.
4. Commit the milestone, deploy to the authorized VM, run the full dependency-backed suite, and run a disposable offline validation.
5. Run one bounded read-only live validation only if source health is green; record measured limitations and remove only the disposable validation hunt artifacts.
6. Pause for operator review before the next scheduler/refactor milestone.
