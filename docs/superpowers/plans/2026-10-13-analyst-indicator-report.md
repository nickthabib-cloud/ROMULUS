# Analyst Indicator Report Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce a concise, evidence-constrained Word report of strong indicators, supporting context, likely noise, narrative, and follow-ups while preserving the exhaustive TXT report.

**Architecture:** Build a canonical reporting case from admitted report items and their owned evidence, ask the local model for selector-based organization and explanation, then fail-closed admit the response before rendering. The DOCX consumes only the admitted briefing or a deterministic fallback; TXT retains the existing technical detail. Final artifacts remain under `Settings.reports_dir`, which defaults to `/home/user/ROMULUS/reports`.

**Tech Stack:** Python 3.11+, unittest, python-docx, requests/Ollama structured JSON, existing ROMULUS reporting and retention modules.

**Spec:** `docs/superpowers/specs/2026-10-13-analyst-indicator-report-design.md`

## Global Constraints

- Do not hardcode any Russell Mitchell scenario answer, address, domain, tool, artifact, or sequence.
- Treat all telemetry as untrusted input and exclude ground-truth labels, rules, and scenario-revealing provenance from model input.
- Render an observable only when deterministic code resolves it from cited canonical evidence.
- Keep the TXT report exhaustive and make the DOCX concise and actionable.
- Model failure must produce a useful deterministic DOCX rather than fail report generation.
- Final DOCX, TXT, and optional anomaly report paths must be descendants of the configured `reports/` directory.
- Do not run a new hunt; generate the acceptance example from the completed hunt.

## Review Focus

- Telemetry contains prompt-like text: synthesis must treat it as data and selectors must still validate.
- One activity appears through several sensors: the DOCX must consolidate it without losing citations.
- A tool-like string appears in a failed HTTP path probe: it must not become a successful download or execution claim.
- The model cites a real evidence ID but invents an artifact value: admission must reject the unsupported value.
- Finalization reaches the discovery runtime budget or Ollama fails: deterministic briefing and reports-directory output must still succeed.

---

### Task 1: Canonical Reporting Case and Fail-Closed Admission

**Files:**
- Create: `romulus/reporting/indicator_review.py`
- Create: `tests/test_indicator_review.py`
- Modify: `romulus/investigation/workflow.py`

**Interfaces:**
- Produces: `build_indicator_case(state: dict, report_items: list[dict]) -> dict`
- Produces: `admit_indicator_review(case: dict, proposal: dict) -> dict`
- Produces: `deterministic_indicator_review(case: dict, reason: str) -> dict`
- Produces persisted `state["indicator_review"]` containing selectors, bounded explanations, status, and rejection reason.

- [ ] **Step 1: Write failing case-builder tests**

Assert that the case contains report-item and evidence selectors, exact normalized observables, admitted relationships, and coverage; assert that `ait.ground_truth`, ground-truth rules, revealing provenance paths, and unowned evidence are absent.

- [ ] **Step 2: Run the case-builder tests and verify RED**

Run: `python -m unittest tests.test_indicator_review.IndicatorCaseTests -v`

Expected: FAIL because `romulus.reporting.indicator_review` does not exist.

- [ ] **Step 3: Implement `build_indicator_case` and generic observable extraction**

Extract bounded domains, IP addresses, ports, URLs, commands, filenames, processes, accounts, protocols, status codes, and timestamps from owned canonical evidence. Preserve source evidence IDs and sensor roles; do not add attack-specific vocabulary.

- [ ] **Step 4: Run the case-builder tests and verify GREEN**

Run: `python -m unittest tests.test_indicator_review.IndicatorCaseTests -v`

- [ ] **Step 5: Write failing admission tests**

Prove valid selectors are admitted, duplicate sensor views consolidate, unsupported IDs and artifact values fail closed, stale persisted selectors fail re-admission, and a 404 directory-enumeration record cannot support a successful download claim.

- [ ] **Step 6: Implement admission and deterministic fallback**

Admission derives artifacts, assets, times, classifications, confidence bounds, and citations from the case. Model text may explain supported facts but cannot override canonical classifications or claim outcomes not present in evidence.

- [ ] **Step 7: Run indicator-review tests and commit**

Run: `python -m unittest tests.test_indicator_review -v`

Commit: `feat: add evidence-constrained indicator review`

### Task 2: Structured LLM Synthesis and Finalization

**Files:**
- Modify: `romulus/agent/ollama.py`
- Modify: `romulus/investigation/workflow.py`
- Test: `tests/test_indicator_review.py`
- Test: `tests/test_activity_narrative.py`

**Interfaces:**
- Produces: `Ollama.synthesize_indicator_review(case_file: dict) -> dict`
- Produces: `Workflow._indicator_review(state: dict) -> dict`

- [ ] **Step 1: Write failing structured-synthesis tests**

Assert that the prompt contains the bounded case, explicitly treats telemetry as untrusted, excludes ground-truth data, and requires selector-based strong indicators, supporting context, likely noise, narrative, and follow-ups.

- [ ] **Step 2: Run focused tests and verify RED**

Run: `python -m unittest tests.test_indicator_review.IndicatorModelTests -v`

- [ ] **Step 3: Implement the schema and `synthesize_indicator_review`**

Use one low-temperature structured call. Allow the model to select and explain strong indicators from reportable evidence without hardcoded behavior families or scenario-specific fields.

- [ ] **Step 4: Write failing finalization tests**

Prove finalization calls synthesis once even when the discovery runtime budget has ended, persists only admitted output, records model failure, and uses deterministic fallback without preventing report generation.

- [ ] **Step 5: Implement `_indicator_review` as a separately bounded finalization responsibility**

Do not schedule searches or extend the hunt. Record synthesis telemetry separately from the discovery frontier and retain the existing overall safety timeout for a stalled model request.

- [ ] **Step 6: Run focused workflow tests and commit**

Run: `python -m unittest tests.test_indicator_review tests.test_activity_narrative -v`

Commit: `feat: synthesize analyst indicator briefing`

### Task 3: Concise DOCX and Reports-Directory Contract

**Files:**
- Modify: `romulus/reporting/report.py`
- Modify: `romulus/retention.py`
- Modify: `tests/test_customer_report.py`
- Modify: `tests/test_retention.py`
- Modify: `.env.example`
- Modify: `README.md`

**Interfaces:**
- Consumes: admitted `state["indicator_review"]` and `deterministic_indicator_review` fallback.
- Produces: DOCX sections `Strong Indicators`, `Supporting Context`, `Likely Noise or Misclassified Activity`, `Possible Activity Narrative`, and `Recommended Follow-ups`.
- Preserves: current exhaustive TXT sections and anomaly TXT behavior.

- [ ] **Step 1: Write failing DOCX-content tests**

Reopen the generated DOCX and assert that exact canonical artifacts, citations, limitations, and follow-ups appear; assert that the repetitive full suspicious-candidate dump does not. Confirm the TXT still contains the full technical candidate and evidence sections.

- [ ] **Step 2: Write failing output-location and retention tests**

Assert every manifest path resolves beneath the supplied `reports_dir`, the default environment path is `/home/user/ROMULUS/reports`, the anomaly report remains under `reports/anomalous/`, and cleanup preserves all manifested reports.

- [ ] **Step 3: Run focused tests and verify RED**

Run: `python -m unittest tests.test_customer_report tests.test_retention -v`

- [ ] **Step 4: Replace the DOCX finding dump with the admitted briefing renderer**

Use compact artifact tables and short evidence-grounded paragraphs. Keep detailed lifecycle, scoring, raw evidence, and search diagnostics in TXT.

- [ ] **Step 5: Enforce and document the reports-directory contract**

Reject final manifest paths outside the configured report root, preserve the existing default, and document where operators find finalized reports.

- [ ] **Step 6: Run focused tests and commit**

Run: `python -m unittest tests.test_customer_report tests.test_retention -v`

Commit: `feat: render concise analyst indicator reports`

### Task 4: Existing-Hunt Example, Visual QA, and Full Verification

**Files:**
- Modify: `docs/VALIDATION.md`
- Modify: `docs/superpowers/plans/2026-10-13-analyst-indicator-report.md`
- Output: configured `reports/HUNT-11692D82D3-<generation-stamp>.docx`
- Output: matching `reports/HUNT-11692D82D3-<generation-stamp>.txt` when the existing finalized state is re-rendered.

**Interfaces:**
- Consumes: the saved completed hunt state; performs report synthesis and rendering only.
- Produces: an analyst-readable example report without executing discovery searches or another hunt.

- [ ] **Step 1: Re-render the completed hunt into the configured reports directory**

Use the retained finalized state from `HUNT-11692D82D3`. Verify no hunt or telemetry-search command runs.

- [ ] **Step 2: Inspect the example structurally**

Reopen the DOCX and verify indicator artifacts, supporting context, likely noise, narrative, follow-ups, citations, and absence of ground-truth labels.

- [ ] **Step 3: Render and inspect every DOCX page**

Use the bundled document renderer. Confirm headings, artifact tables, page breaks, wrapping, fonts, and footers are readable with no clipping or overflow.

- [ ] **Step 4: Run focused and full verification**

Run focused reporting, workflow, classification, narrative, and retention suites; then run the complete test suite, `compileall`, and `git diff --check`. Record any environment-only failures explicitly.

- [ ] **Step 5: Update validation evidence and commit**

Document the exact code commit, test totals, example report path, model/admission result, artifact hits, false-positive handling, and known limitations.

Commit: `docs: validate analyst indicator report`

