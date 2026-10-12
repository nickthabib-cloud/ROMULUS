# Behavioral Seed Catalog Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a portable offline behavior catalog, trusted local indicator matching, deterministic candidate ranking, initial Elasticsearch seed searches, and report visibility for prioritized leads.

**Architecture:** A new intelligence module validates the versioned JSON catalogs, binds semantic roles to dataset fields, compiles bounded Elasticsearch seed queries, matches collected evidence, and builds a deterministic candidate queue. The existing workflow executes applicable seed queries after mapping discovery, rebuilds the queue during analysis, and exposes only corroborated or trusted high-priority leads in the customer-facing report while retaining all candidates in the technical appendix.

**Tech Stack:** Python standard library, dataclasses, JSON, unittest, existing Elasticsearch DSL validation, existing report writers.

**Spec:** `docs/superpowers/specs/2026-10-12-strict-window-telemetry-coverage-design.md`

## Global Constraints

- The catalog is offline, versioned, editable, and uses no new runtime dependency or external service.
- Catalog predicates use semantic roles and bind only to fields present in the current dataset.
- Every generated source query preserves the existing mission time filter and result limits.
- Behavior anomalies remain leads; only trusted exact indicators or corroborated high-specificity behavior become customer-visible.
- Weak signals such as temporary-path execution and lookalike names start low and remain out of customer findings without corroboration.
- All candidate scores, dispositions, evidence references, and promotion reasons are deterministic and persisted in hunt state.

## Review Focus

- Malformed or duplicate catalog entries must fail closed with an actionable JSON path.
- Missing semantic fields must mark an analytic inapplicable instead of widening its query.
- Expired trusted indicators must never match or raise candidate priority.
- Loose substring matching must not turn common text mentions into exact IOC matches.
- Low-noise reporting rules must keep weak anomalies in the technical appendix until corroborated.

---

### Task 1: Catalog format, validation, and initial behavior pack

**Files:**
- Create: `romulus/intelligence/behavior_catalog.py`
- Create: `romulus/intelligence/behavior_catalog.json`
- Create: `romulus/intelligence/behavior_catalog.schema.json`
- Create: `romulus/intelligence/local_indicators.json`
- Test: `tests/test_behavior_catalog.py`

**Interfaces:**
- Produces: `CatalogValidationError`, `load_behavior_catalog(path=...)`, `load_local_indicators(path=...)`, `resolve_semantic_fields(fields)`, and `applicable_analytics(catalog, fields, source)`.

- [ ] Write failing tests proving the default catalog has at least 40 unique validated analytics across Windows, Linux, cross-platform, authentication, DNS, and network coverage; the default IOC list is empty; duplicate IDs and malformed predicates fail with an actionable path; missing roles make entries inapplicable.
- [ ] Run `python -m unittest tests.test_behavior_catalog.CatalogLoadingTests -v` and confirm failures are caused by the missing module and files.
- [ ] Implement the schema, loader, semantic-role aliases, validation, and initial catalog with provenance, ATT&CK references, benign cases, corroboration requirements, and follow-ups.
- [ ] Run the task tests and confirm they pass.
- [ ] Commit `feat: add behavioral seed catalogs`.

### Task 2: Query compilation and deterministic candidate ranking

**Files:**
- Modify: `romulus/intelligence/behavior_catalog.py`
- Modify: `tests/test_behavior_catalog.py`

**Interfaces:**
- Consumes: validated analytics and semantic field bindings from Task 1.
- Produces: `compile_elasticsearch_seed(analytic, bindings, timestamp_field, time_range)`, `build_candidate_queue(evidence, catalog, indicators, analytic_summary=None)`, and `customer_visible_candidates(candidates)`.

- [ ] Write failing tests for strict time-filtered query compilation, temp-path execution remaining low, independent corroboration promoting a candidate, lookalike-name matching requiring path context, exact trusted indicator priority, expiry handling, stable ordering, and non-substring IOC matching.
- [ ] Run the focused tests and verify each new behavior fails for the expected missing implementation.
- [ ] Implement approved predicate operators, event matching, exact indicator normalization, score components, dispositions, queue ordering, and customer visibility.
- [ ] Run the focused tests and confirm they pass.
- [ ] Commit `feat: rank behavior and indicator leads`.

### Task 3: Hunt workflow integration

**Files:**
- Modify: `romulus/investigation/workflow.py`
- Modify: `tests/test_behavior_catalog.py`

**Interfaces:**
- Consumes: query compilation and candidate ranking from Task 2.
- Produces: `behavior_catalog_status`, `behavior_seed_searches`, and `candidate_leads` in persisted hunt state; behavior searches appear in `queries`, `tool_runs`, and `completed_leads`.

- [ ] Write failing tests proving applicable catalog searches are compiled before model pivots, unsupported entries are recorded without execution, returned evidence retains the behavior ID, and analysis creates a stable candidate queue.
- [ ] Run the workflow-focused tests and confirm the expected failures.
- [ ] Load catalogs during engine initialization, add bounded behavior seed searches after mapping discovery, tag resulting evidence, and rebuild candidate leads during `_analyze`.
- [ ] Run the workflow-focused tests and confirm they pass.
- [ ] Commit `feat: run behavioral seeds during hunts`.

### Task 4: Reporting and operator maintenance guide

**Files:**
- Modify: `romulus/reporting/report.py`
- Create: `docs/behavior-analytics.md`
- Modify: `README.md`
- Modify: `tests/test_behavior_catalog.py`

**Interfaces:**
- Consumes: persisted `candidate_leads` and catalog status from Task 3.
- Produces: customer-facing prioritized-lead summary, complete technical candidate appendix, and operator editing instructions.

- [ ] Write failing tests proving customer output includes trusted/corroborated high leads, excludes weak temp-only leads from significant findings, and preserves those weak leads in the technical appendix.
- [ ] Run the report-focused tests and confirm the expected failures.
- [ ] Add TXT/DOCX sections, document the exact catalog paths and validation workflow, and link the guide from README.
- [ ] Run report-focused tests and confirm they pass.
- [ ] Commit `docs: explain behavioral analytic maintenance`.

### Task 5: Verification and compatibility

**Files:**
- Modify only if a failing compatibility test demonstrates a defect.

**Interfaces:**
- Consumes: all prior tasks.
- Produces: verified feature branch and recorded baseline limitations.

- [ ] Run `python -m unittest tests.test_behavior_catalog -v` and require all new tests to pass.
- [ ] Run `python -m unittest discover -s tests -v`, compare against the recorded baseline failures, and fix only regressions caused by this plan using a failing test first.
- [ ] Validate both JSON files using the production loaders and run `git diff --check`.
- [ ] Commit any compatibility fixes with a focused message.
