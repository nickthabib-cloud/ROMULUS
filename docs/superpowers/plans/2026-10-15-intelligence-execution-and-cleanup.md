# Intelligence Execution and Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give every retained ROMULUS intelligence asset an explicit consumer, remove redundant artifacts, and execute curated behaviors through source-correct search and correlation semantics.

**Architecture:** The research corpus and ATT&CK catalog remain authoritative inputs. A typed rule compiler emits source-aware direct, sequence, aggregate, baseline, and capability packs; deterministic runtime components execute or enrich from those packs while coverage records exact execution state. A reproducible asset auditor and a final independent repository crawl prevent orphaned data and misleading status from returning.

**Tech Stack:** Python 3.11+, standard library, JSON, SQLite, existing ROMULUS Elasticsearch/Arkime/TShark adapters.

**Spec:** `docs/superpowers/specs/2026-10-15-source-aware-intelligence-execution-design.md` and `docs/superpowers/specs/2026-10-15-intelligence-asset-lifecycle-design.md`

## Global Constraints

- Source access remains read-only and bounded by the mission window and configured allowlists.
- Generated files are changed through their authoritative input and generator.
- A reference cannot create, score, corroborate, or publish a finding.
- A rule is executable only when all required source and evaluation semantics validate.
- Missing, capped, failed, or budget-omitted work is never reported as a negative match.
- Existing user changes outside this plan are preserved.

## Review Focus

- A pack can load successfully while its rules remain inert; coverage must distinguish loaded, executable, and executed.
- Capability names can match ordinary administration; reference enrichment must not change scoring or findings.
- ATT&CK IDs outside the compact static knowledge set must remain useful context without producing malformed searches.
- Generated pack renames can leave stale filenames in manifests, docs, packaging, or tests.
- Cross-source rules can appear complete when one stage was capped or lacks a join key; they must remain partial.

---

### Task 1: Intelligence asset ownership and generated-pack cleanup

**Files:**
- Create: `romulus/intelligence/intelligence_assets.json`
- Create: `scripts/audit_intelligence_assets.py`
- Modify: `scripts/build_behavior_packs.py`
- Modify: `scripts/behavior_pack_translations.json`
- Modify: `romulus/intelligence/behavior_packs/__init__.py`
- Modify: `docs/research/common-indicator-corpus.json`
- Delete: `docs/research/common-indicator-index.csv`
- Replace: `romulus/intelligence/behavior_packs/references.json` with `capabilities.json`
- Test: `tests/test_intelligence_assets.py`

**Interfaces:**
- Produces: `audit_assets(root: Path) -> dict[str, Any]`, `load_behavior_packs(...)` with `capabilities`, and manifest counts separated by execution state and source.

- [ ] Write failing tests for pack ownership, capability-only generation, retired-file rejection, count reconciliation, and stale status detection.
- [ ] Run the focused tests and confirm failures describe missing ownership/audit behavior.
- [ ] Implement the asset registry, pack rename, ATT&CK-copy removal, corrected status metadata, and offline audit.
- [ ] Regenerate packs from the authoritative corpus.
- [ ] Run focused and full verification, inspect generated diffs, and commit only Task 1 files.

### Task 2: Bounded capability and ATT&CK reference consumers

**Files:**
- Create: `romulus/intelligence/reference_intelligence.py`
- Modify: `romulus/intelligence/attack_catalog.py`
- Modify: `romulus/investigation/workflow.py`
- Modify: `romulus/agent/ollama.py`
- Test: `tests/test_reference_intelligence.py`
- Test: `tests/test_scheduler_execution.py`

**Interfaces:**
- Produces: `compile_capability_index(records)`, `attach_capability_context(candidates, evidence, index, limit=5)`, and bounded ATT&CK planning context.

- [ ] Write failing tests proving exact executable lookup, evidence attribution, bounded results, zero score/disposition changes, and directed ATT&CK context.
- [ ] Run the focused tests and confirm the missing consumer behavior.
- [ ] Implement the capability index and candidate enrichment without changing candidate scores.
- [ ] Integrate bounded ATT&CK references into deterministic planning and post-telemetry model context; remove the unused model hypothesis entry point if it remains unreachable.
- [ ] Run focused and full verification and commit Task 2.

### Task 3: Typed source-aware rule model and direct compilers

**Files:**
- Create: `romulus/intelligence/rule_model.py`
- Create: `romulus/intelligence/source_compilers.py`
- Modify: `romulus/intelligence/behavior_catalog.py`
- Modify: `romulus/intelligence/search_matrix.py`
- Modify: `romulus/intelligence/search_matrix_catalog.json`
- Modify: `romulus/intelligence/windows_event_catalog.json`
- Modify: `romulus/investigation/scheduler.py`
- Modify: `romulus/investigation/workflow.py`
- Test: `tests/test_source_aware_rules.py`
- Test: `tests/test_scheduler_execution.py`

**Interfaces:**
- Produces: typed source stages, Elasticsearch clauses, Arkime expressions, TShark display filters, and preserved behavior/stage/signature attribution.

- [ ] Write failing tests for source-language separation, mapping-aware Elasticsearch compilation, Arkime escaping, TShark field validation, and per-signature hit attribution.
- [ ] Run focused tests and confirm they fail on the current Elasticsearch-only and attribution behavior.
- [ ] Implement the closed typed rule model and source compilers.
- [ ] Migrate current runnable catalogs and scheduler metadata to the typed contract.
- [ ] Run focused and full verification and commit Task 3.

### Task 4: Sequence correlation and translation

**Files:**
- Create: `romulus/intelligence/sequence_analytics.py`
- Modify: `scripts/behavior_pack_translations.json`
- Modify: `scripts/build_behavior_packs.py`
- Modify: `romulus/investigation/workflow.py`
- Test: `tests/test_sequence_analytics.py`

**Interfaces:**
- Produces: `evaluate_sequences(evidence, definitions, source_outcomes) -> tuple[list[dict], dict]` for all 89 sequence records.

- [ ] Write failing tests for ordered, unordered-threshold, same-asset, same-actor, same-path, and cross-source joins plus missing/capped-stage behavior.
- [ ] Implement bounded normalized observation envelopes and the deterministic sequence engine.
- [ ] Translate all sequence records into source-specific stages and explicit joins; records without defensible semantics become structured reference-only gaps.
- [ ] Reconcile all 89 IDs and verify no record is silently absent.
- [ ] Run focused and full verification and commit Task 4.

### Task 5: Aggregate execution and translation

**Files:**
- Create: `romulus/intelligence/aggregate_analytics.py`
- Modify: `scripts/behavior_pack_translations.json`
- Modify: `scripts/build_behavior_packs.py`
- Modify: `romulus/intelligence/analytics.py`
- Modify: `romulus/investigation/workflow.py`
- Test: `tests/test_aggregate_analytics.py`

**Interfaces:**
- Produces: explicit filter/group/window/measure/sample/threshold definitions and `evaluate_aggregates(...)` for all 206 aggregate records.

- [ ] Write failing tests for count, distinct count, fan-out, rate, transition, volume, ratio, duration, periodicity, and truncation semantics.
- [ ] Implement the closed aggregate primitive registry with source-native execution metadata and bounded local evaluation.
- [ ] Translate every aggregate record or classify it with a structured missing-semantics reason; never infer thresholds silently.
- [ ] Reconcile all 206 IDs and coverage states.
- [ ] Run focused and full verification and commit Task 5.

### Task 6: Baseline execution and translation

**Files:**
- Create: `romulus/intelligence/baseline_analytics.py`
- Modify: `scripts/behavior_pack_translations.json`
- Modify: `scripts/build_behavior_packs.py`
- Modify: `romulus/store.py`
- Modify: `romulus/investigation/workflow.py`
- Test: `tests/test_baseline_analytics.py`

**Interfaces:**
- Produces: versioned baseline storage, comparison/update functions, and complete execution or structured gap states for all 58 baseline records.

- [ ] Write failing tests for warm-up, first-seen, prevalence, peer rarity, deviation, contamination exclusion, idempotent updates, and partial history.
- [ ] Implement compact versioned baseline state and completed-hunt-only updates.
- [ ] Translate every baseline record or classify it with a structured missing-semantics reason.
- [ ] Reconcile all 58 IDs and readiness states.
- [ ] Run focused and full verification and commit Task 6.

### Task 7: Operator documents and truthful coverage

**Files:**
- Create: `docs/research/README.md`
- Create: `scripts/build_intelligence_docs.py`
- Modify: `docs/research/common-indicator-research.md`
- Modify: `docs/research/indicator-priority-inventory.md`
- Modify: `docs/research/elasticsearch-dsl-search-matrix.md`
- Modify: `docs/research/windows-event-log-threat-hunting.md`
- Modify: `README.md`
- Modify: `romulus/reporting/report.py`
- Test: `tests/test_intelligence_assets.py`

**Interfaces:**
- Produces: reproducible operator inventory and coverage terms aligned with actual execution.

- [ ] Write failing tests for generated priority content, document ownership links, and prohibited misleading status phrases.
- [ ] Implement the document generator and research index; remove duplicate tables from the narrative research document.
- [ ] Replace count-only coverage labels with executable/executed/reference/unsupported/partial states.
- [ ] Regenerate operator documents and commit Task 7.

### Task 8: Secondary repository audit and repair

**Files:**
- Modify: files identified by the fresh audit when corrections are within the approved architecture.
- Create: `docs/research/2026-10-15-secondary-project-audit.md`

**Interfaces:**
- Consumes: clean outputs from Tasks 1 through 7.
- Produces: a repository-wide audit record with evidence, corrected findings, and explicit remaining limitations.

- [ ] Run independent searches for unused modules/functions/data, duplicate authorities, stale generated files, wrong query languages, misleading statuses, silent exception paths, large unowned assets, and commit contamination.
- [ ] Record each finding before editing and classify severity and scope.
- [ ] For each in-scope defect, write a failing regression check, implement the smallest correction, and rerun the relevant suite.
- [ ] Document unrelated or environment-only limitations without changing unrelated product behavior.
- [ ] Run the asset audit, pack check, document check, complete automated suite, syntax compilation, and diff checks.
- [ ] Perform a final whole-branch code review, address critical and important findings, and commit the audit report and corrections.

## Completion criteria

- Every retained intelligence asset has one owner and an explicit consumer.
- Redundant CSV and ATT&CK copies are removed.
- Retained capability and ATT&CK references contribute bounded context without affecting evidence scores.
- All 902 curated behaviors are accounted for as executable, reference-only, unsupported, not applicable, partial, or budget-omitted with source-correct semantics.
- Generated documentation and manifests reconcile with authoritative data.
- The independent secondary audit and full verification complete without unresolved critical or important findings.
