# Indicator Corpus Runtime Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Install the 3,863-record indicator research corpus as bounded, explainable ROMULUS runtime knowledge, with 902 curated behaviors represented and 78 low-noise rules active by default.

**Architecture:** A deterministic compiler turns the reviewed research corpus plus an explicit translation registry into versioned direct, sequence, aggregate, baseline, and reference packs. ROMULUS loads those packs at startup, evaluates supported executable rules through indexed matchers and bounded state machines, exposes unsupported semantics as coverage gaps, and preserves the current candidate, scheduler, evidence, and reporting contracts.

**Tech Stack:** Python 3.11+, JSON, SQLite, existing ROMULUS catalog and workflow modules, standard-library-only runtime additions.

**Spec:** `docs/superpowers/specs/2026-10-15-indicator-corpus-runtime-design.md`

## Global Constraints

- Do not run a hunt or access Elasticsearch, Arkime, TShark, Ollama, or any other live source.
- Do not add or invoke the repository test suite; use the standalone deterministic validator and syntax compilation defined in Task 8.
- Keep Elasticsearch, Arkime, and TShark access read-only.
- Do not encode scenario-specific IP addresses, filenames, timestamps, expected attack paths, or known answers.
- Preserve the existing 63 catalog IDs and their matching behavior.
- Keep reference records out of runtime evaluation and collection seeding.
- Only `active` direct rules may seed collection; `observe` rules evaluate collected evidence without consuming tool calls.
- Cap observe-only candidate scores at 39 and prevent observe-only rules from independently becoming customer visible or corroborating one another above that ceiling.
- Retain complete match counts with at most 40 cited evidence IDs per candidate.
- Generated JSON must be byte-for-byte stable for the same corpus and translation registry.
- Missing semantics must fail closed as `supported: false` with a coverage reason; do not infer thresholds or relationships from prose at runtime.
- Leave unrelated untracked operational and SL700 import artifacts untouched.

## Review Focus

- A case-insensitive semantic alias collision must resolve deterministically without rewriting the evidence or silently choosing an arbitrary field. Task 2's validator case pins this behavior.
- An active rule with a missing or malformed translation must stop pack generation or startup; an observe-only rule with unavailable semantics must remain unsupported and visible in coverage. Tasks 1 and 2 pin both paths.
- Sequences with missing timestamps, unequal required entities, repeated evidence IDs, or out-of-order stages must not match. Task 4 pins these cases.
- Observe-only signals must never cross the score ceiling through repetition, sequence relationships, aggregate agreement, or baseline deviation. Tasks 3, 4, 5, 6, and 7 pin the boundary at every integration point.
- Corpus drift, duplicate IDs, unknown ATT&CK IDs, count mismatches, or pack hash changes must make `--check` fail with a useful location. Tasks 1 and 8 pin these failures.

---

### Task 1: Deterministic Corpus Compiler and Versioned Packs

**Files:**
- Add: `docs/research/common-indicator-corpus.json`
- Add: `docs/research/common-indicator-index.csv`
- Add: `docs/research/common-indicator-research.md`
- Create: `scripts/behavior_pack_translations.json`
- Create: `scripts/build_behavior_packs.py`
- Create: `romulus/intelligence/behavior_packs/manifest.json`
- Create: `romulus/intelligence/behavior_packs/direct.json`
- Create: `romulus/intelligence/behavior_packs/sequences.json`
- Create: `romulus/intelligence/behavior_packs/aggregates.json`
- Create: `romulus/intelligence/behavior_packs/baselines.json`
- Create: `romulus/intelligence/behavior_packs/references.json`

**Interfaces:**
- Consumes: research corpus schema version `1.0.0`, the pinned ATT&CK IDs from `romulus/intelligence/attack_catalog.json`, and explicit translations from `scripts/behavior_pack_translations.json`.
- Produces: `load_corpus(path: Path) -> dict[str, Any]`, `compile_corpus(corpus: dict[str, Any], translations: dict[str, Any], attack_ids: set[str]) -> dict[str, dict[str, Any]]`, `write_packs(packs: dict[str, dict[str, Any]], output_dir: Path) -> dict[str, Any]`, and CLI modes `--write` and `--check`.

- [ ] **Step 1: Define the explicit translation registry**

  Record canonical stage definitions for the five active sequences, aliases for already implemented aggregate signals, and any supported aggregate or baseline primitive with exact filters, group keys, measures, minimum samples, thresholds, and windows. Mark every untranslated sequence, aggregate, and baseline record unsupported with a stable reason; do not derive executable semantics from its prose.

- [ ] **Step 2: Implement corpus validation**

  Validate the exact totals `3,863`, `902`, `549`, `89`, `206`, `58`, `1,216`, and `1,745`; unique IDs; source references; required metadata; predicate operators; semantic roles; ATT&CK IDs; translation targets; and the activation policy of 73 active direct plus five active sequence rules. Require every active sequence stage to resolve to a canonical signal that the direct or aggregate runtime can emit.

- [ ] **Step 3: Implement deterministic transforms**

  Compile direct records into existing Boolean predicate structure with `all` semantics for multi-observable compounds. Compile the other curated classes into typed specifications with `supported`, `support_reason`, and `activation_mode`. Copy LOLBAS and GTFOBins capability metadata into the reference pack and index ATT&CK analytic references through their pinned IDs without duplicating the ATT&CK catalog.

- [ ] **Step 4: Write stable pack files and manifest**

  Sort objects and lists by stable identifiers, serialize with fixed UTF-8 and newline settings, and record source hashes, output hashes, class counts, activation counts, compiler version, and corpus version in `manifest.json`.

- [ ] **Step 5: Exercise compiler checks**

  Run: `python scripts/build_behavior_packs.py --write`

  Expected: five pack files and one manifest are written with 549 direct, 89 sequence, 206 aggregate, 58 baseline, and 1,216 reference records.

  Run: `python scripts/build_behavior_packs.py --check`

  Expected: exit 0 with stable hashes, exact counts, 78 active curated rules, and no unknown or duplicate IDs.

- [ ] **Step 6: Commit the compiler and generated data**

  Commit message: `feat: compile indicator research into behavior packs`

### Task 2: Pack Loading, Validation, and Semantic Roles

**Files:**
- Create: `romulus/intelligence/behavior_packs/__init__.py`
- Modify: `romulus/intelligence/behavior_catalog.py`
- Modify: `romulus/intelligence/normalization.py`
- Modify: `romulus/intelligence/behavior_catalog.schema.json`

**Interfaces:**
- Consumes: Task 1's manifest and generated pack schemas.
- Produces: `load_behavior_packs(directory: Path = BEHAVIOR_PACK_DIR) -> dict[str, Any]`, `load_behavior_catalog(path: Path = BEHAVIOR_CATALOG_PATH, pack_dir: Path = BEHAVIOR_PACK_DIR) -> dict[str, Any]`, expanded `SEMANTIC_ROLE_ALIASES`, and pack coverage metadata under `catalog["pack_status"]`.

- [ ] **Step 1: Implement fail-closed pack loading**

  Verify the manifest hashes before parsing executable packs, reject duplicate IDs across the compatibility catalog and packs, require all active rules to be supported, and retain supported and unsupported observe-only specifications for coverage.

- [ ] **Step 2: Extend executable rule validation**

  Add `activation_mode`, `research_id`, `signal_name`, and `supported` validation while preserving compatibility for the original 63 entries by defaulting them to active and supported.

- [ ] **Step 3: Expand semantic aliases**

  Add the event, identity, process, file, network, cloud, container, Kubernetes, geography, device, and risk roles named by the spec. Keep aliases additive and return matches in declared alias order with duplicates removed.

- [ ] **Step 4: Normalize audit and structured event fields**

  Extend `normalize_elasticsearch_event(hit: dict[str, Any]) -> dict[str, Any]` only where source data needs a derived structured role. Preserve all original fields and values.

- [ ] **Step 5: Add standalone validator cases**

  Add Task 8 validator cases for valid pack loading, a changed hash, a duplicate compatibility-pack ID, an unsupported active rule, an unsupported observe rule, and a case-insensitive alias collision with deterministic declared-order output.

- [ ] **Step 6: Commit pack loading and semantic roles**

  Commit message: `feat: load versioned behavior packs`

### Task 3: Indexed Direct Matching and Activation-Aware Scoring

**Files:**
- Modify: `romulus/intelligence/behavior_catalog.py`

**Interfaces:**
- Consumes: Task 2's merged catalog and semantic-role bindings.
- Produces: `compile_matcher_plan(catalog: dict[str, Any]) -> dict[str, Any]`, `build_behavior_observations(evidence: list[dict[str, Any]], catalog: dict[str, Any], analytic_summary: dict[str, Any] | None = None, matcher_plan: dict[str, Any] | None = None) -> list[dict[str, Any]]`, and backward-compatible `build_candidate_queue(..., observations: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]`.

- [ ] **Step 1: Compile the matcher plan once**

  Partition supported direct rules by source and required-role signature; build exact-value indexes; group contains, prefix, suffix, and regular-expression predicates by anchor role; and precompile regular expressions. Reference and unsupported rules must never enter the plan.

- [ ] **Step 2: Extract normalized role values once per event**

  Cache semantic values for each evidence record during one evaluation call. Preserve the existing path normalization and scalar/list flattening behavior and include the source evidence ID in every observation.

- [ ] **Step 3: Emit canonical behavior observations**

  For every deterministic match, emit rule ID, signal name, time bounds, exact evidence IDs, normalized entity maps, activation mode, priority, noise, specificity, and ATT&CK metadata. Sort observations by timestamp, evidence ID, and rule ID.

- [ ] **Step 4: Make candidate scoring activation aware**

  Preserve current scores for the original catalog. Apply the 39 ceiling to observe-only records after every contribution, keep them non-customer-visible, prevent observe-only mutual corroboration, and include activation and rule class in score reasons.

- [ ] **Step 5: Add standalone validator cases**

  Add Task 8 cases proving a compound `/etc/shadow` command matches only when both predicates share one event, a Linux firewall rule matches the correct command, a process-name-only capability reference does not match, evidence order does not change output, the 40-reference cap holds, and repeated observe rules remain at or below 39.

- [ ] **Step 6: Commit indexed direct evaluation**

  Commit message: `feat: index direct behavior matching`

### Task 4: Bounded Sequence Evaluation

**Files:**
- Create: `romulus/intelligence/sequence_analytics.py`
- Modify: `romulus/intelligence/behavior_catalog.py`

**Interfaces:**
- Consumes: Task 1 sequence definitions and Task 3 canonical observations.
- Produces: `evaluate_sequences(observations: list[dict[str, Any]], definitions: list[dict[str, Any]], max_observations_per_rule: int = 2048) -> tuple[list[dict[str, Any]], dict[str, Any]]`.

- [ ] **Step 1: Validate sequence definitions**

  Require two or more canonical stages, a positive time window, explicit order mode, a bounded per-rule observation limit, and one or more exact shared-entity constraints for supported definitions.

- [ ] **Step 2: Implement deterministic bounded state**

  Sort input by timestamp, evidence ID, and signal name; maintain deques by rule and entity key; evict expired and excess observations; and deduplicate output by rule, entity key, and supporting evidence set.

- [ ] **Step 3: Enforce stage and entity semantics**

  Support ordered, unordered threshold, and either-direction relationships. Treat missing timestamps and required entities as non-matches with coverage counters. Never substitute time proximity for entity equality.

- [ ] **Step 4: Emit sequence observations**

  Include exact stage evidence, shared entity values, rule window, activation mode, relationship basis, and a bounded relationship score contribution. Reapply the observe score ceiling before candidate conversion.

- [ ] **Step 5: Add standalone validator cases**

  Add Task 8 cases for the five active sequence definitions plus mismatched assets, actors, accounts, paths, missing time, out-of-order time, duplicate evidence, and cap truncation. Prove unsupported sequence definitions report coverage and emit no observation.

- [ ] **Step 6: Commit sequence evaluation**

  Commit message: `feat: evaluate bounded behavior sequences`

### Task 5: Generic Aggregate Specifications

**Files:**
- Create: `romulus/intelligence/aggregate_analytics.py`
- Modify: `romulus/intelligence/analytics.py`
- Modify: `romulus/intelligence/behavior_catalog.py`

**Interfaces:**
- Consumes: Task 1 aggregate specifications, normalized evidence, and existing `summarize_evidence` aggregate rows.
- Produces: `evaluate_aggregate_specs(evidence: list[dict[str, Any]], definitions: list[dict[str, Any]], existing_summary: dict[str, Any] | None = None, limit: int = 12, max_groups: int = 4096) -> tuple[list[dict[str, Any]], dict[str, Any]]`.

- [ ] **Step 1: Define a closed primitive registry**

  Implement only the data-driven primitives in the spec: count, distinct count and fan-out, burst rate, failure-to-success, volume, ratio, duration, periodicity, current-evidence rarity, multi-source agreement, and telemetry degradation. Reject arbitrary code, expressions, and unknown primitive names.

- [ ] **Step 2: Reuse existing aggregate signals**

  Adapt current cited summary rows into canonical aggregate observations before evaluating new specifications. Keep current aggregate names and behavior compatible.

- [ ] **Step 3: Bound grouping and evidence**

  Enforce definition windows, group caps, minimum samples, deterministic group ordering, and bounded cited evidence. When a cap is reached, mark aggregate coverage truncated and do not claim a complete negative result.

- [ ] **Step 4: Keep untranslated aggregates visible and inert**

  Record unsupported definitions and reasons in coverage. They must never match, seed, score, or corroborate.

- [ ] **Step 5: Add standalone validator cases**

  Add Task 8 cases for every supported primitive, exact boundary thresholds, missing measures, malformed numeric values, deterministic group-cap truncation, bounded citations, unsupported definitions, and the observe score ceiling.

- [ ] **Step 6: Commit aggregate evaluation**

  Commit message: `feat: add bounded aggregate behavior runtime`

### Task 6: Historical Baseline State and Evaluation

**Files:**
- Create: `romulus/intelligence/baseline_analytics.py`
- Modify: `romulus/store.py`

**Interfaces:**
- Consumes: Task 1 baseline specifications, Task 3 normalized observations, and completed-hunt evidence supplied by Task 7.
- Produces: `Store.load_baseline_states(rule_ids: list[str] | None = None) -> dict[tuple[str, int, str], dict[str, Any]]`, `Store.apply_baseline_updates(investigation_id: str, updates: list[dict[str, Any]]) -> int`, `compare_baselines(observations: list[dict[str, Any]], definitions: list[dict[str, Any]], states: dict[tuple[str, int, str], dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]`, and `build_baseline_updates(...) -> list[dict[str, Any]]`.

- [ ] **Step 1: Add versioned SQLite baseline tables**

  Create idempotent `baseline_snapshots` and `baseline_updates` tables keyed by rule ID, metric version, and normalized entity key. Store compact JSON statistics, source coverage, observation count, covered interval, and update time; never copy raw evidence.

- [ ] **Step 2: Implement comparison primitives**

  Support the explicit first-seen, rare relationship, frequency, cardinality, mean/variance, and quantile specifications present in the translation registry. Unknown baseline primitives remain unsupported.

- [ ] **Step 3: Enforce warm-up and contamination controls**

  Report `warming` until minimum history, samples, and source coverage are met. Exclude findings and high-priority candidates from updates, never train on the current hunt before comparison, and make repeated update application for one investigation idempotent.

- [ ] **Step 4: Emit observe-only baseline observations**

  Include state version, history bounds, sample support, deviation basis, exact evidence, and readiness. Baseline observations remain capped at 39 and cannot independently become customer visible.

- [ ] **Step 5: Add standalone validator cases**

  Add Task 8 cases for empty state, warm-up, first-seen and rarity comparison, duplicate update application, rule-version isolation, corrupt state, exclusion of risky observations, and rollback by selecting the previous rule version.

- [ ] **Step 6: Commit baseline storage and evaluation**

  Commit message: `feat: persist behavior baselines safely`

### Task 7: Workflow, Scheduler, Candidate, and Coverage Integration

**Files:**
- Modify: `romulus/investigation/workflow.py`
- Modify: `romulus/investigation/scheduler.py`
- Modify: `romulus/intelligence/investigation_graph.py`
- Modify: `romulus/store.py`

**Interfaces:**
- Consumes: Task 2 loaded packs, Task 3 matcher plan and observations, Task 4 sequences, Task 5 aggregates, and Task 6 baseline state.
- Produces: one deterministic analysis pipeline invoked by `HuntEngine._analyze`, active-only seed plans, persisted technical observations, and `coverage["behavior_packs"]`.

- [ ] **Step 1: Load and compile runtime state once**

  In `HuntEngine.__init__`, load validated packs, compile the direct matcher plan, and retain typed executable definitions. Keep the offline synthetic path and existing catalog status fields compatible.

- [ ] **Step 2: Restrict seed planning**

  Update `_behavior_seed_queries` so only supported active direct rules may seed. Group compatible one-role literals without changing Boolean meaning, preserve compound queries, maintain current source-family fairness and tool-call limits, and record unsupported roles plus budget-skipped eligible rules.

- [ ] **Step 3: Integrate the analysis pipeline**

  In `_analyze`, evaluate complete persisted evidence in this order: normalize and direct-match, adapt and evaluate aggregates, compare baselines, evaluate sequences, convert observations to candidates, merge trusted indicators, persist the full candidate set, and promote bounded context.

- [ ] **Step 4: Persist observations and coverage**

  Add bounded technical observations to investigation state and compact persisted state. Record total, active, observe, reference, supported, unsupported, applicable, missing-role, sequence-stage, aggregate truncation, baseline readiness, and seed-budget counts.

- [ ] **Step 5: Apply baseline updates only after completion**

  In `_report`, after the hunt status is determined, apply updates only when status is `completed`. A partial or failed hunt must leave persistent baseline state unchanged.

- [ ] **Step 6: Preserve candidate and hypothesis gates**

  Keep observed candidates below the hypothesis threshold, preserve trusted-indicator handling, and require the existing customer-visible and cited-evidence gates for escalation.

- [ ] **Step 7: Add standalone validator cases**

  Add Task 8 cases that instantiate the pipeline with local fixture dictionaries only and prove active-only seeds, observe-only post-collection evaluation, unsupported coverage, no live adapter calls, candidate persistence bounds, score ceilings after all contributions, and completed-only baseline updates.

- [ ] **Step 8: Commit workflow integration**

  Commit message: `feat: integrate indicator packs into hunts`

### Task 8: Reporting, Documentation, and Standalone Verification

**Files:**
- Create: `scripts/validate_behavior_runtime.py`
- Modify: `romulus/reporting/report.py`
- Modify: `docs/behavior-analytics.md`
- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Modify: `VALIDATION.md`

**Interfaces:**
- Consumes: all runtime and coverage interfaces from Tasks 1 through 7.
- Produces: `validate_runtime() -> dict[str, Any]`, CLI exit status 0 only when all deterministic checks pass, and report sections that distinguish matches from coverage gaps.

- [ ] **Step 1: Build the deterministic validator**

  Assemble the cases assigned by Tasks 1 through 7 without importing or invoking live source adapters. Use temporary directories and SQLite files, emit one JSON summary, and return nonzero on any failed invariant.

- [ ] **Step 2: Extend technical reporting**

  Show active and observe counts, supported and unsupported counts, technical observations, baseline readiness, sequence evidence and shared entities, aggregate truncation, missing roles, skipped seeds, and pack versions. State whether a rule matched, did not match, or did not run.

- [ ] **Step 3: Preserve customer report gates**

  Keep observe-only and unsupported rules out of customer-visible findings. Allow active supported rules to appear only through the existing candidate and evidence rules.

- [ ] **Step 4: Document maintenance and activation**

  Explain pack generation, translation review, active/observe/reference modes, coverage semantics, score ceilings, baseline lifecycle, hash checks, and the process for promoting an observed rule after representative replay.

- [ ] **Step 5: Run offline verification**

  Run: `python scripts/build_behavior_packs.py --check`

  Expected: exact counts and hashes, 78 active plus 824 observe curated records, and no validation errors.

  Run: `python scripts/validate_behavior_runtime.py`

  Expected: exit 0 and a JSON summary in which every deterministic case passes and `live_source_calls` is 0.

  Run: `python -m compileall -q romulus scripts`

  Expected: exit 0 with no syntax errors.

  Run: `git diff --check`

  Expected: exit 0 with no whitespace errors.

- [ ] **Step 6: Inspect the final repository state**

  Confirm that no hunt report, live telemetry artifact, credential, `.env`, temporary database, `.codex-tmp` content, or unrelated untracked file enters the change set.

- [ ] **Step 7: Commit reports and verification**

  Commit message: `docs: document indicator pack runtime`

## Completion Criteria

- All 3,863 research records are represented in generated packs or the pinned ATT&CK index.
- All 902 curated records have a runtime class and activation mode.
- Exactly 78 curated rules are active and 824 are observe-only by default.
- Every active rule is supported; every unsupported rule is inert and disclosed in coverage.
- Direct, sequence, aggregate, and baseline observations use exact cited evidence and bounded state.
- Observe-only data cannot independently become customer visible or exceed score 39.
- The existing 63-rule catalog loads and behaves compatibly.
- Offline pack checks, the standalone validator, syntax compilation, and diff checks pass.
- No hunt or live-source access occurs.
