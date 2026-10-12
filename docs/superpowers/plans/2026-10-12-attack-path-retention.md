# Attack-Path Graph and Safe Retention — Milestone 3

> **For Codex:** Execute this plan in order with `superpowers:test-driven-development`; stop at the verification checkpoint before deployment if any proof fails.

**Goal:** Reconstruct evidence-cited temporal/entity paths without model-created facts, show those paths in both reports, and automatically remove completed-hunt working bulk only after the reports are verified.

**Architecture:** A deterministic graph builder converts normalized evidence into immutable evidence nodes, typed entity nodes, and activity nodes. Observed edges come directly from one record; cross-event edges require an explicit shared entity or an existing conservative host/network correlation and remain labeled as inferred with caveats. Findings reference graph paths assembled only from their cited evidence. A hunt-scoped finalizer verifies both reports, creates a compact manifest, retains cited evidence, and idempotently removes only that hunt's disposable state, log lines, and checkpoints.

**Tech stack:** Python 3.12, SQLite, LangGraph checkpoints, python-docx, unittest.

**Non-goals:** This milestone does not unify the remaining baseline/model/pivot scheduling paths, broaden telemetry collection, or let model output create graph facts. Scheduler consolidation remains a separate milestone so graph correctness and destructive retention behavior can be reviewed independently.

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
