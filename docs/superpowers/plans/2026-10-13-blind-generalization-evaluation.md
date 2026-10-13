# Blind Generalization Evaluation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run and score one blind, read-only ROMULUS hunt against the operator-authorized holdout without exposing oracle details to the runtime or retaining disposable hunt bulk.

**Architecture:** Freeze the reviewed Milestone 8 head into an exact hashed archive, deploy it to an isolated VM checkout, and run one broad hunt in a unique runtime root using the operator-supplied time boundary and production safety backstops. Finalize and compact the hunt before any oracle comparison, preserve only the report/evaluation artifacts, classify misses by responsible layer, and delete the exact disposable runtime and transfer files.

**Tech Stack:** Python CLI, LangGraph, SQLite, Elasticsearch, Arkime, TShark, Ollama, DOCX/TXT reports, Git/GitHub.

**Spec:** `docs/superpowers/specs/2026-10-13-adaptive-evidence-grounded-hunting-design.md`

## Global Constraints

- The hunt objective stays broad and contains no holdout identity, indicator, account, domain, product, vulnerability, command, filename, shell path, technique label, or attack sequence.
- The operator-authorized time boundary may be supplied at execution time; it is not copied into runtime code, prompts, catalogs, tests, fixtures, or this committed plan.
- The oracle remains outside ROMULUS inputs and is read only after the hunt is finalized and compacted.
- All source access is read-only. No service configuration, telemetry, operational hunt state, or existing report is changed.
- Production safety backstops are 3,600 seconds, 40 reasoning rounds, 500 external calls, and three stagnant cycles.
- A source/model failure or safety backstop produces an honest partial result, never a clean conclusion.
- Compact retention keeps reports, cited evidence, supported paths/gaps, and aggregates while removing detailed reasoning, queries, task history, logs, and checkpoints.
- Findings are scored only from their cited retained evidence; absent or unsupported attack stages count as misses.
- Any post-oracle code change must be a generic primitive developed with an unrelated synthetic variant and benign control. The holdout then becomes a regression corpus, not fresh generalization evidence.

## Review Focus

- Confirm the broad mission makes no model call or hypothesis before deterministic telemetry produces a candidate.
- Confirm explicit source failures, caps, or incomplete coverage prevent false closure.
- Confirm each reported finding, technique, entity, and path edge is supported by its retained citations.
- Confirm finalization occurs before oracle comparison and removes detailed model/search/checkpoint state.
- Confirm no oracle-specific detail enters a committed runtime, prompt, catalog, test, fixture, or reusable selector.

---

### Task 1: Freeze and preflight the evaluation candidate

**Files:**
- Create: `data/.superpowers/sdd/2026-10-13-blind-generalization-evaluation/progress.md` (ignored ledger)
- Modify: `docs/superpowers/plans/2026-10-13-blind-generalization-evaluation.md`

**Interfaces:**
- Consumes: reviewed Milestone 8 head and its completed local/VM/offline proof.
- Produces: exact commit/archive digest, isolated VM checkout, unique runtime/report paths, and green read-only diagnostics.

- [x] **Step 1: Record the exact clean candidate and archive digest**

Verify the branch starts at the reviewed Milestone 8 head, contains only this evaluation plan as an intentional change, and archive the committed candidate without credentials or runtime data.

- [x] **Step 2: Deploy to an isolated VM checkout**

Copy the archive to a unique `/tmp` path, match SHA-256, and extract without copying `.env`, local data, reports, logs, or oracle files.

- [x] **Step 3: Run configured read-only diagnostics**

Load the existing deployment configuration without displaying it and run `doctor` from the isolated checkout. Stop before the hunt if any required source, model contract, capture, or writable isolated directory is unavailable.

Expected: all configured dependencies, model schemas, sources, captures, and isolated runtime directories are green.

### Task 2: Run and finalize the blind hunt

**Files:**
- Create: ignored isolated runtime and captured console log under the unique VM `/tmp` root.

**Interfaces:**
- Consumes: Task 1 exact checkout and green diagnostics.
- Produces: one terminal or explicitly finalized hunt with reports and compact retained state, still unseen by the oracle comparison.

- [x] **Step 1: Start one broad undirected hunt**

Pass only the generic broad-hunt objective and the operator-authorized time boundary. Override `ROMULUS_HOME`, `DATA_DIR`, `LOGS_DIR`, and `REPORTS_DIR` to the unique runtime root. Use the production backstops from Global Constraints and compact retention.

Expected: the first model call, if any, occurs only after a deterministic telemetry-backed candidate exists.

- [x] **Step 2: Monitor bounded progress without steering**

Capture the hunt ID, source/task outcomes, candidate creation, first model-call basis, reasoning admissions/rejections, stop reason, and resource usage. Do not add attack hints or alter runtime behavior during the run.

- [x] **Step 3: Resolve terminal state before oracle access**

If completed, verify automatic compact retention. If partial and a productive resumable frontier remains, resume the same hunt within the existing production backstops. If partial cannot productively continue, explicitly finalize it as partial with compact retention and record why.

Expected: matching DOCX/TXT reports exist and the hunt is finalized before Task 4.

### Task 3: Verify reports, retention, and exact cleanup

**Files:**
- Preserve: ignored local copies of the DOCX/TXT reports and a minimal compact-state inspection summary.
- Modify: `VALIDATION.md`

**Interfaces:**
- Consumes: Task 2 finalized compact state.
- Produces: verified evidence/report metrics and no disposable remote working artifacts.

- [x] **Step 1: Reopen and inspect both reports**

Confirm hunt identity, outcome, stop basis, source limitations, findings, path/gaps, scheduler/sampling/progress/reasoning aggregates, and absence of raw prompts or query bodies.

- [x] **Step 2: Inspect compact state**

Count retained findings/evidence and verify detailed reasoning, case files, model payloads, queries, task/outcome history, hunt-scoped JSONL rows, and checkpoints are absent.

- [x] **Step 3: Preserve reports and remove exact disposable artifacts**

Copy the compact result into an ignored local evaluation directory, then resolve and delete only the unique remote archive, checkout, runtime, and capture log plus the local transfer archive. Preserve the report pair for the operator.

### Task 4: Score only after finalization

**Files:**
- Modify: `VALIDATION.md`
- Modify: `docs/superpowers/plans/2026-10-13-blind-generalization-evaluation.md`

**Interfaces:**
- Consumes: Task 3 finalized findings, retained citations, report, and the external operator-supplied oracle.
- Produces: honest stage/entity/path/technique scoring and layer-classified misses without runtime tuning.

- [x] **Step 1: Compare finalized output to the external oracle**

Score attack-stage recall and precision, entity/relationship recall, temporal ordering, unsupported findings, incorrect techniques, explicit gaps, source coverage, and resource/stop metrics.

- [x] **Step 2: Classify each material miss**

Assign misses to retrieval, normalization, candidate generation, hypothesis reasoning, correlation/path construction, admission, or reporting using retained evidence and exact outcomes. Do not infer unseen evidence.

- [x] **Step 3: Record the evaluation boundary and result**

Update `VALIDATION.md` with exact commit/digest/hunt ID, observed metrics, unsupported claims, limitations, classified misses, cleanup, and the fact that the oracle was first consulted after finalization.

- [ ] **Step 4: Commit and publish the evaluation record**

Run `git diff --check`, confirm no oracle-specific runtime/test/catalog changes and no tracked report/database/log files, commit the plan and validation record, push `codex/blind-generalization-evaluation`, and open a stacked PR against `codex/evidence-grounded-reasoning`.

Expected: the evaluation is reproducible and honest; any required general improvement is deferred to a separate TDD implementation milestone.
