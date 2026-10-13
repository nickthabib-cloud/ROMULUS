# Attack Discovery Promotion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn evidence-backed candidates into entity-scoped searches and a diverse, time-bounded discovery frontier without allowing the model or same-asset coincidence to invent corroboration.

**Architecture:** Add a deterministic candidate-triage boundary for evidence relationships and frontier selection. Reuse the existing guarded Arkime/TShark compilers for candidate pivots, retain current candidate IDs and scheduler ownership, and expose only bounded candidate-owned evidence to the investigator/critic.

**Tech Stack:** Python 3.12, `unittest`, existing ROMULUS scheduler/search compilers, typed dictionaries and immutable copies.

**Spec:** `docs/superpowers/specs/2026-10-13-attack-discovery-promotion-design.md`

## Global Constraints

- No evaluated-dataset identity, product, tool, timestamp, or attack sequence may enter runtime code, prompts, catalogs, tests, or fixtures.
- No hypothesis exists without a deterministic candidate and visible evidence citation.
- Candidate relationships require distinct analytic groups, a shared typed entity, and parseable timestamps within 1,800 seconds.
- Temporal/entity association is an investigative lead, never causation.
- Candidate-owned network searches require one safe entity family and retain existing read-only validators, allowlists, time bounds, caps, and scheduler ownership.
- Candidate score or relationship changes cannot publish a finding or relax critic/admission gates.
- Existing candidate IDs, dispositions, follow-up histories, telemetry gaps, and finding links remain backward compatible.

## Review Focus

- Multi-valued or malformed candidate entities must select one safe primary family or fail closed, never broaden silently; Task 1 tests IPv4, hostname, multiple-IP, and missing-entity inputs.
- Candidate relationship timestamps at exactly and just beyond the 1,800-second boundary must behave deterministically; Task 2 tests both boundaries.
- Same group, same prose, or same asset without a cited shared typed entity must not earn corroboration; Task 2 contains independent negative controls.
- A large candidate must not monopolize or disappear from the case file when its evidence count exceeds the budget; Task 3 tests bounded per-candidate evidence and visible ownership.
- Repetitive high-scoring candidates must not starve a distinct lower-scoring evidence-backed behavior forever; Task 3 tests first-pass diversity and later-pass eligibility.

---

### Task 1: Entity-scoped deterministic network pivots

**Files:**
- Modify: `romulus/investigation/search_planner.py`
- Modify: `romulus/investigation/workflow.py`
- Create: `tests/test_attack_discovery.py`

**Interfaces:**
- Produces: `candidate_network_spec(lead: Mapping[str, Any], technique: Mapping[str, Any], *, require_entity: bool) -> dict[str, Any]` in `search_planner.py`.
- Consumes: existing `compile_arkime(spec) -> str` and `compile_tshark(spec) -> tuple[str, list[str]]`.
- Produces: `_lead_network_expression(lead) -> str` and `_lead_pcap_filter(lead) -> str` backed by the same validated spec.

- [ ] **Step 1: Write failing query-scope tests**

Add `CandidateNetworkPivotTests` proving:

- a `T1046` candidate whose `ips` begin with `10.40.5.9` compiles Arkime and TShark expressions containing only that primary IP plus TCP/UDP behavior;
- additional evidence IPs do not widen the deterministic candidate pivot;
- a DNS candidate without an IP may use its first safe hostname with DNS behavior;
- a candidate with no safe IP/hostname raises `ValueError`;
- a non-candidate coverage lead can still compile bounded behavior-only selectors.

- [ ] **Step 2: Run the focused tests and verify RED**

Run: `python -m unittest tests.test_attack_discovery.CandidateNetworkPivotTests -v`

Expected: FAIL because `candidate_network_spec` does not exist and current deterministic pivots omit candidate entities.

- [ ] **Step 3: Implement the guarded candidate network spec**

Implement `candidate_network_spec` using the first normalized IP, otherwise the first safe hostname, plus bounded integer ports and supported protocols from the technique metadata. A lead with `candidate_id` sets `require_entity=True`; invalid/missing entity input raises before compilation. Update the workflow helpers to call the existing Arkime/TShark compilers and preserve legacy non-candidate lead behavior.

- [ ] **Step 4: Run focused query and scheduler tests**

Run: `python -m unittest tests.test_attack_discovery.CandidateNetworkPivotTests tests.test_scheduler_execution -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```text
git add romulus/investigation/search_planner.py romulus/investigation/workflow.py tests/test_attack_discovery.py
git commit -m "fix: scope candidate network pivots"
```

### Task 2: Evidence-backed candidate relationships

**Files:**
- Create: `romulus/investigation/candidate_triage.py`
- Modify: `romulus/intelligence/behavior_catalog.py`
- Modify: `romulus/investigation/workflow.py`
- Modify: `tests/test_attack_discovery.py`
- Modify: `tests/test_behavior_catalog.py`

**Interfaces:**
- Produces: `relate_candidates(candidates: Sequence[Mapping[str, Any]], evidence: Sequence[Mapping[str, Any]], window_seconds: int = 1800) -> list[dict[str, Any]]`.
- Produces metadata: behavior candidates contain `corroboration_group` and `analytic_source`; aggregate synthetic observations contain timestamps derived from cited evidence.
- Consumes: Task 3 reads `corroboration_group`, `related_candidates`, recalculated `priority_score`, and stable candidate IDs.

- [ ] **Step 1: Write failing relationship tests**

Add `CandidateRelationshipTests` proving literal expected records for:

- two distinct analytic groups sharing a typed IP at 1,800 seconds receive reciprocal relationships and one ten-point bonus;
- a pair at 1,801 seconds receives no relationship;
- same-group events, missing timestamps, and unrelated typed entities receive no relationship or bonus;
- input reversal produces byte-for-byte equivalent candidate ordering and relationship content;
- the relationship cites the two evidence IDs, shared entity type/value, delta, confidence, and non-causality caveat.

Update the existing independent-behavior ranking test so mere same-asset membership no longer promotes a candidate before triage. Add an aggregate test proving cited evidence timestamps hydrate `first_observed`/`last_observed`.

- [ ] **Step 2: Run the focused tests and verify RED**

Run: `python -m unittest tests.test_attack_discovery.CandidateRelationshipTests tests.test_behavior_catalog.CandidateRankingTests tests.test_candidate_loop.AggregateSignalTests -v`

Expected: FAIL because evidence-backed relationship logic and aggregate timestamp hydration do not exist, while the old asset-wide bonus still applies.

- [ ] **Step 3: Implement relationship derivation and remove the asset-wide bonus**

Implement typed structured-field normalization and cited-pair time comparison in `candidate_triage.py`. Enrich copies only, cap relationship score bonuses at twenty, and deterministically recompute priority tier/customer visibility/disposition without changing terminal dispositions. Preserve catalog source/group metadata and derive aggregate timestamps from supporting evidence. Call `relate_candidates` in `_analyze` before `merge_candidate_queue`.

- [ ] **Step 4: Run focused candidate, graph, and workflow tests**

Run: `python -m unittest tests.test_attack_discovery.CandidateRelationshipTests tests.test_behavior_catalog tests.test_candidate_loop tests.test_investigation_graph -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```text
git add romulus/investigation/candidate_triage.py romulus/intelligence/behavior_catalog.py romulus/investigation/workflow.py tests/test_attack_discovery.py tests/test_behavior_catalog.py
git commit -m "feat: relate candidates with cited evidence"
```

### Task 3: Diverse candidate frontier and bounded case-file ownership

**Files:**
- Modify: `romulus/investigation/candidate_triage.py`
- Modify: `romulus/investigation/workflow.py`
- Modify: `romulus/investigation/casefile.py`
- Modify: `tests/test_attack_discovery.py`
- Modify: `tests/test_casefile.py`
- Modify: `tests/test_candidate_loop.py`

**Interfaces:**
- Produces: `select_candidate_frontier(candidates: Sequence[Mapping[str, Any]], limit: int = 8, exploration_slots: int = 2, max_per_group: int = 2, preferred_ids: Collection[str] | None = None, minimum_score: int = 40) -> list[dict[str, Any]]`.
- Consumes: `_candidate_hypotheses` selects from candidates not already represented by a hypothesis.
- Consumes: `build_case_file` prefers unresolved-hypothesis candidates and exposes at most six evidence IDs per candidate plus `evidence_total`.

- [ ] **Step 1: Write failing frontier and case-file tests**

Add tests proving:

- eight candidates from one scan analytic plus three distinct behaviors select no more than two scan candidates in the first eight-slot pass;
- exactly two strongest cited sub-threshold candidates may use the exploration reserve;
- trusted indicators and critical candidates remain ahead of ordinary diversity selection;
- after first-pass candidate IDs are represented by hypotheses, the next call selects previously excluded candidates;
- preferred unresolved-hypothesis candidates appear in a bounded case file before ordinary candidates;
- a candidate owning thirty evidence IDs appears with six deterministic visible IDs and `evidence_total == 30` rather than disappearing;
- visible-case ownership excludes the other twenty-four IDs, so reasoning admission cannot cite them.

- [ ] **Step 2: Run the focused tests and verify RED**

Run: `python -m unittest tests.test_attack_discovery.CandidateFrontierTests tests.test_casefile tests.test_candidate_loop.CandidateHypothesisTests -v`

Expected: FAIL because selection is score-only and large candidates are currently skipped when they exceed the evidence budget.

- [ ] **Step 3: Implement shared diverse selection**

Implement `select_candidate_frontier` with stable sort keys, preferred-ID precedence, trusted/critical precedence, a two-per-group pass, and the two-slot exploration reserve. Filter already represented candidates before calling it in `_candidate_hypotheses`. In `build_case_file`, derive preferred IDs from unresolved hypotheses, select candidates through the shared frontier, then expose at most six sorted owned evidence IDs per candidate while recording the full owned count.

- [ ] **Step 4: Run focused frontier, admission, and case-file tests**

Run: `python -m unittest tests.test_attack_discovery.CandidateFrontierTests tests.test_casefile tests.test_candidate_loop tests.test_reasoning_admission -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```text
git add romulus/investigation/candidate_triage.py romulus/investigation/workflow.py romulus/investigation/casefile.py tests/test_attack_discovery.py tests/test_casefile.py tests/test_candidate_loop.py
git commit -m "feat: diversify candidate discovery frontier"
```

### Task 4: End-to-end synthetic discovery proof and documentation

**Files:**
- Modify: `tests/test_attack_discovery.py`
- Modify: `VALIDATION.md`
- Modify: `docs/superpowers/plans/2026-10-13-attack-discovery-promotion.md`

**Interfaces:**
- Consumes: scoped pivots from Task 1, candidate relationships from Task 2, and frontier selection from Task 3.
- Produces: one generic workflow regression and the milestone validation record.

- [ ] **Step 1: Write the failing workflow regression**

Create a generic synthetic state containing repetitive benign scanner candidates plus distinct evidence-backed DNS and host-execution behaviors on unrelated synthetic entities. Assert that `_analyze`:

- creates no hypothesis without a candidate;
- places at least one distinct non-scan candidate in the first hypothesis frontier;
- records only evidence-backed candidate relationships;
- compiles the scan candidate's Arkime task with its primary IP and TCP/UDP behavior; and
- publishes no finding merely because candidates are related or highly scored.

- [ ] **Step 2: Run the workflow regression and verify RED if integration is incomplete**

Run: `python -m unittest tests.test_attack_discovery.AttackDiscoveryWorkflowTests -v`

Expected: FAIL on any missing integration between Tasks 1–3; if it passes immediately, document that it is a coverage proof and add the smallest missing end-to-end assertion that fails against the pre-milestone base.

- [ ] **Step 3: Make only the minimal integration corrections**

Wire existing task interfaces without adding scenario-specific selectors or changing admission/finding thresholds.

- [ ] **Step 4: Run complete local proof**

Run:

```text
python -m unittest discover -s tests -v
python -m compileall -q romulus tests
git diff --check
```

Expected: all available tests pass with only documented dependency skips; compilation and diff checks pass.

- [ ] **Step 5: Record exact validation and commit**

Record the baseline, RED/GREEN evidence, test totals, known scope boundary, and absence of oracle-specific data in `VALIDATION.md`. Check completed plan items.

```text
git add tests/test_attack_discovery.py VALIDATION.md docs/superpowers/plans/2026-10-13-attack-discovery-promotion.md
git commit -m "test: prove evidence-scoped attack discovery"
```

### Task 5: Review, VM proof, and bounded live validation

**Files:**
- Modify: `VALIDATION.md`
- Modify: `docs/superpowers/plans/2026-10-13-attack-discovery-promotion.md`

**Interfaces:**
- Consumes: the complete feature-branch diff and exact committed archive.
- Produces: independent review findings, dependency-complete proof, configured diagnostics, and measured live discovery behavior.

- [ ] **Step 1: Complete a fresh whole-diff review**

Review specifically for query broadening, entity overconstraint, false corroboration, candidate starvation, unstable IDs/order, citation ownership, and accidental finding/admission relaxation. Reproduce every Critical or Important finding with a failing test before correction.

- [ ] **Step 2: Run an exact-candidate VM proof**

Archive the committed candidate, match its SHA-256 on the VM, run the dependency-complete suite with zero unexpected skips, run `compileall`, and run configured `doctor` against isolated writable directories.

- [ ] **Step 3: Run one bounded generic live hunt**

Use the operator-authorized telemetry and broad objective without supplying oracle facts. Measure candidate diversity, candidate-owned query matched/returned totals and cap rates, investigator/critic admission, supported relationships, findings, paths, stop basis, and source gaps. Do not claim improved attack-path recall unless cited findings and paths actually demonstrate it.

- [ ] **Step 4: Record proof and clean disposable artifacts**

Preserve only durable reports and validation summaries. Remove exact transfer archives, extracted validation trees, isolated runtimes, and disposable hunt bulk after verifying report integrity and exact paths.

- [ ] **Step 5: Commit, push, and open a stacked PR**

Open the PR against `codex/reasoning-contract-hardening`, attach it to the task, and mark the plan complete only after the pushed branch contains the final validation record.
