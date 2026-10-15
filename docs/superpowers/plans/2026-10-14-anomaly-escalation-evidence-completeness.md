# Anomaly Escalation and Evidence Completeness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make deterministic anomaly escalation operate on complete persisted evidence and elevate general suspicious deviations without scenario knowledge.

**Architecture:** Normalize source records at ingestion, analyze the complete SQLite evidence set, promote candidate-related records into bounded reasoning context, and extend aggregate network signals. Keep scheduler ordering, adapters, prompt bounds, and finding-admission controls intact.

**Tech Stack:** Python 3.11, `unittest`, SQLite, Elasticsearch DSL, existing ROMULUS scheduler and analytics catalog.

**Spec:** `docs/superpowers/specs/2026-10-14-anomaly-escalation-evidence-completeness-design.md`

## Global Constraints

- Do not encode scenario IPs, filenames, timestamps, or attack steps.
- Keep Elasticsearch, Arkime, and TShark access read-only and validated.
- Deterministic analytics use complete persisted evidence; model and checkpoint context remain bounded.
- Preserve original evidence and provenance while adding derived normalization fields.
- Candidate escalation does not require attack-path construction.
- Preserve pre-existing uncommitted import artifacts.

## Review Focus

- A large evidence store must not cause checkpoint growth proportional to all persisted records.
- Invalid or non-audit hexadecimal-looking text must not be decoded as commands.
- Entity promotion must use structured exact entities rather than substring matches.
- New cardinality signals must keep bounded cited evidence and deterministic ordering.
- Noise penalties must not suppress a corroborated low-noise candidate below a lone high-noise match.

---

### Task 1: Normalize Linux audit execution records and compile safer seeds

**Files:**
- Create: `romulus/intelligence/normalization.py`
- Modify: `romulus/investigation/workflow.py`
- Modify: `romulus/intelligence/behavior_catalog.py`
- Modify: `romulus/intelligence/behavior_catalog.json`
- Test: `tests/test_evidence_analysis.py`
- Test: `tests/test_behavior_catalog.py`

**Interfaces:**
- Produces: `normalize_elasticsearch_event(hit: dict) -> dict` and analyzer-compatible hexadecimal prefix clauses from `_predicate_query`.
- Consumes: Existing `_add_es_hit`, semantic role bindings, and catalog predicate evaluation.

- [x] **Step 1: Write failing audit normalization and seed-shape tests**

Assert that a hex-encoded `EXECVE` argument becomes `process.command_line`, invalid hex remains untouched, and `BH-LNX-003` compiles as downloader AND shell with a `6375726c` prefix alternative.

- [x] **Step 2: Run focused tests and verify RED**

Run: `python -m unittest tests.test_evidence_analysis tests.test_behavior_catalog -v`

- [x] **Step 3: Implement normalization and composite seed compilation**

Add derived fields before `_bounded` persistence. Add hex prefixes only for raw audit text aliases and alphanumeric command tokens of at least three characters.

- [x] **Step 4: Run focused tests and verify GREEN**

Run: `python -m unittest tests.test_evidence_analysis tests.test_behavior_catalog -v`

### Task 2: Analyze complete persisted evidence and promote candidate context

**Files:**
- Modify: `romulus/investigation/workflow.py`
- Test: `tests/test_evidence_analysis.py`

**Interfaces:**
- Produces: `HuntEngine._analysis_evidence(state) -> tuple[list[dict], list[dict]]` and `HuntEngine._promote_candidate_context(state, evidence, candidates, limit=200) -> int`.
- Consumes: `Store.list_evidence`, `build_candidate_queue`, and existing bounded hunt context.

- [x] **Step 1: Write failing completeness and promotion tests**

Create late network anomalies after a tiny context cap. Assert that analysis detects them from SQLite and promotes exact candidate and entity-related records into `state["network"]`.

- [x] **Step 2: Run focused tests and verify RED**

Run: `python -m unittest tests.test_evidence_analysis -v`

- [x] **Step 3: Implement complete deterministic analysis and bounded promotion**

Use complete evidence for summaries, candidate matching, and hypothesis evidence selection. Continue to build correlations and graphs only from bounded context after promotion.

- [x] **Step 4: Run focused tests and verify GREEN**

Run: `python -m unittest tests.test_evidence_analysis -v`

### Task 3: Add general network-deviation signals and explainable noise penalties

**Files:**
- Modify: `romulus/intelligence/analytics.py`
- Modify: `romulus/intelligence/behavior_catalog.py`
- Modify: `romulus/intelligence/behavior_catalog.json`
- Test: `tests/test_evidence_analysis.py`
- Test: `tests/test_behavior_catalog.py`

**Interfaces:**
- Produces: aggregate signals `dns_query_fanout`, `http_path_fanout`, `web_scanner_user_agent`, and `scan_then_reverse_connection`.
- Consumes: normalized structured network roles and existing aggregate candidate machinery.

- [x] **Step 1: Write failing signal and ordering tests**

Assert thresholds, bounded citations, shared-entity corroboration, and expected-noise deductions of 0, 6, and 12.

- [x] **Step 2: Run focused tests and verify RED**

Run: `python -m unittest tests.test_evidence_analysis tests.test_behavior_catalog -v`

- [x] **Step 3: Implement signals, catalog entries, and score reasons**

Use distinct structured values and chronological peer-direction records. Keep every signal list bounded by the summary limit.

- [x] **Step 4: Run focused tests and verify GREEN**

Run: `python -m unittest tests.test_evidence_analysis tests.test_behavior_catalog -v`

### Task 4: Document, review, and verify the complete change

**Files:**
- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Modify: `VALIDATION.md`
- Modify: this plan

**Interfaces:**
- Consumes: Tasks 1-3.
- Produces: durable architecture and validation records.

- [x] **Step 1: Update architecture and validation documentation**

Record the persisted-evidence boundary, promotion behavior, generic anomaly signals, and measured test results.

- [x] **Step 2: Run complete verification**

Run: `python -m unittest discover -s tests`

Run: `python -m compileall -q romulus tests`

Run: `git diff --check`

- [x] **Step 3: Request a fresh whole-change code review**

Review for missed evidence, unsafe query broadening, false correlation, unbounded state growth, and scenario leakage. Fix Critical or Important findings test-first.

- [x] **Step 4: Record completion evidence**

Update the plan checkboxes and `VALIDATION.md` with commands and outcomes.
