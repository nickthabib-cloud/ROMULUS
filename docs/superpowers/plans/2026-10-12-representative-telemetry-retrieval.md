# Representative Telemetry Retrieval Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make capped Elasticsearch, Arkime, and TShark searches retain deterministic evidence across the effective telemetry interval instead of only its earliest records.

**Architecture:** A shared sampling module creates bounded time strata, cap allocations, and ordered rank windows. Each source adapter applies that code-controlled policy using its native capabilities, while the scheduler preserves bounded sampling metadata and continues treating every capped result as partial.

**Tech Stack:** Python 3.11+, unittest, official Elasticsearch client, requests/Arkime API, TShark subprocess wrapper, existing LangGraph workflow and SQLite store.

**Spec:** `docs/superpowers/specs/2026-10-12-representative-telemetry-retrieval-design.md`

## Global Constraints

- No external-corpus address, account, hostname, filename, command, tool name, timestamp, or attack sequence may enter runtime code, prompts, catalogs, or committed test fixtures.
- Sampling is deterministic, read-only, bounded by the existing result cap, and selected by code rather than the model.
- Uncapped searches preserve current exhaustive behavior.
- Capped, failed, timed-out, unknown-total, or missing-stratum work remains partial and cannot satisfy closure.
- Compact retention preserves aggregate sampling coverage only; query bodies, request history, and uncited raw evidence remain disposable.
- Do not add a new runtime dependency.

## Review Focus

- A cap smaller than the configured stratum count must never exceed the cap or create zero-length requests.
- Empty time strata and duplicate records must not consume retained capacity or create false completeness.
- Timezone-equivalent, reversed, and sub-second mission bounds must produce stable non-overlapping strata or fail before source access.
- Missing Elasticsearch timestamps, Arkime totals beyond the allowed offset, and TShark rows without parseable time must fall back conservatively and remain partial.
- Resume and compact retention must preserve the sampling policy/summary without restoring deleted task/query bulk.

---

### Task 1: Shared deterministic sampling contract

**Files:**
- Create: `romulus/investigation/sampling.py`
- Modify: `romulus/config.py`
- Create: `tests/test_sampling.py`

**Interfaces:**
- Produces: `time_strata(start: datetime, end: datetime, count: int) -> list[dict]`, `allocate_cap(cap: int, count: int) -> list[int]`, `rank_windows(total: int, cap: int, count: int) -> list[dict]`, and `sampling_policy(settings) -> dict`.
- Produces: `Settings.time_sampling_strata: int`, loaded from `TIME_SAMPLING_STRATA`, default 8, constrained to 2–24.

- [ ] Write synthetic failing tests for stable non-overlapping UTC strata, exact cap allocation, small caps, evenly distributed rank windows, invalid bounds, and configuration limits.
- [ ] Run `python -m unittest tests.test_sampling -v`; expect missing-module/attribute failures.
- [ ] Implement the minimal shared module and configuration field.
- [ ] Run `python -m unittest tests.test_sampling tests.test_core -v`; expect PASS.
- [ ] Commit with `feat: add deterministic sampling contract`.

### Task 2: Representative Elasticsearch retrieval

**Files:**
- Modify: `romulus/tools/elasticsearch_client.py`
- Modify: `romulus/investigation/workflow.py`
- Create: `tests/test_representative_sampling.py`
- Modify: `tests/test_scheduler_execution.py`

**Interfaces:**
- Consumes: Task 1 time strata, cap allocation, and policy metadata.
- Produces: `ElasticsearchAdapter.search_many(..., timestamp_field: str | None = None, time_range: dict | None = None, sampling: dict | None = None) -> dict` with bounded `sampling` metadata.
- Produces: scheduler outcomes containing the adapter sampling summary and evidence from multiple nonempty strata.

- [ ] Write failing fake-client tests where capped earliest-first results omit synthetic middle/late records; assert representative retention, stable IDs, exact cap, deduplication, partial status, and uncapped compatibility.
- [ ] Run the focused sampling and scheduler-execution tests; expect the new assertions to fail.
- [ ] Implement PIT-scoped bound discovery, safe internal range intersection, per-stratum bounded retrieval, fallback disclosure, and workflow argument/provenance plumbing.
- [ ] Run `python -m unittest tests.test_representative_sampling tests.test_scheduler_execution -v`; expect PASS.
- [ ] Commit with `feat: sample capped elasticsearch windows`.

### Task 3: Representative Arkime retrieval

**Files:**
- Modify: `romulus/tools/arkime_client.py`
- Modify: `romulus/investigation/workflow.py`
- Modify: `tests/test_representative_sampling.py`
- Modify: `tests/test_core.py`
- Modify: `tests/test_scheduler_execution.py`

**Interfaces:**
- Consumes: Task 1 rank windows and sampling policy.
- Produces: `ArkimeAdapter.search_sessions_sampled(...) -> dict` returning deduplicated sessions, matched total, request count, cap state, and rank-window sampling metadata.

- [ ] Write failing tests proving early/middle/late rank retrieval, stable request offsets, duplicate suppression, offset-limit fallback, exact cap, and unchanged uncapped results.
- [ ] Run the focused tests; expect missing-method and earliest-only failures.
- [ ] Implement one bounded adapter operation and route scheduled Arkime tasks through it without increasing scheduler task count.
- [ ] Run `python -m unittest tests.test_representative_sampling tests.test_core tests.test_scheduler_execution -v`; expect PASS.
- [ ] Commit with `feat: sample capped arkime sessions`.

### Task 4: Representative TShark retention

**Files:**
- Modify: `romulus/tools/tshark_client.py`
- Modify: `romulus/investigation/workflow.py`
- Modify: `tests/test_representative_sampling.py`
- Modify: `tests/test_core.py`
- Modify: `tests/test_scheduler_execution.py`

**Interfaces:**
- Consumes: Task 1 time strata, cap allocation, and sampling policy.
- Produces: `TSharkAdapter.inspect(..., sample_start: datetime | None = None, sample_end: datetime | None = None, sampling: dict | None = None) -> dict` with deterministic per-stratum or whole-stream reservoir metadata.

- [ ] Write failing mocked-stream tests proving capped output spans early/middle/late intervals, repeated runs are identical, total matches remain exact, malformed timestamps fall back conservatively, and command safety is unchanged.
- [ ] Run the focused tests; expect earliest-line retention failures.
- [ ] Implement single-pass deterministic bounded reservoirs and route scheduled tasks through them.
- [ ] Run `python -m unittest tests.test_representative_sampling tests.test_core tests.test_scheduler_execution -v`; expect PASS.
- [ ] Commit with `feat: sample capped packet matches`.

### Task 5: Outcome, report, retention, and documentation integration

**Files:**
- Modify: `romulus/investigation/scheduler.py`
- Modify: `romulus/reporting/report.py`
- Modify: `romulus/retention.py`
- Modify: `tests/test_scheduler.py`
- Modify: `tests/test_customer_report.py`
- Modify: `tests/test_retention.py`
- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Modify: `VALIDATION.md`

**Interfaces:**
- Consumes: bounded adapter sampling summaries from Tasks 2–4.
- Produces: normalized `search_outcomes[*].sampling`, bounded technical-report sampling lines, and compact `coverage.sampling_summary` aggregates.

- [ ] Write failing tests for outcome normalization, technical/customer report separation, compact aggregation, and capped nonclosure.
- [ ] Run the focused scheduler/report/retention tests; expect missing sampling metadata failures.
- [ ] Implement bounded propagation and documentation without retaining queries or per-request history.
- [ ] Run the focused tests, full suite, `compileall`, `git diff --check`, and corpus-identity scan; expect PASS/clean.
- [ ] Commit with `feat: report representative search coverage`.

### Task 6: Exact deployment, live validation, corpus evaluation, and PR

**Files:**
- Modify: `VALIDATION.md`
- Modify: this plan's execution status section.

**Interfaces:**
- Consumes: exact committed implementation from Tasks 1–5.
- Produces: dependency-complete VM evidence, isolated hunt metrics, compact-retention proof, corpus comparison, and an attached GitHub pull request.

- [ ] Run whole-branch review focused on the five Review Focus conditions; fix Critical/Important findings test-first.
- [ ] Deploy an exact Git archive to the development VM; verify SHA-256, full no-skip suite, compilation, and `doctor`.
- [ ] Run an isolated bounded live hunt with the same generic mission window and budgets used for the prior comparison. Prove sampled evidence spans the mission window before opening the external corpus.
- [ ] Finalize compact, verify report reopening and hunt-scoped working-data cleanup, then compare stage-level recall against the external corpus without changing runtime behavior during that run.
- [ ] Record supported matches, misses, false claims, sampling coverage, and the next capability gap in `VALIDATION.md`; remove exact disposable artifacts only.
- [ ] Run final local verification, push `codex/time-stratified-hunting`, create a PR against `main`, and attach it to this task.

## Execution status

- Plan authorized for native execution by the operator on 2026-10-12; no additional approval checkpoint is required.
- Implementation has not started.
