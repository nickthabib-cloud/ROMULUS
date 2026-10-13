# Schema-aware deterministic discovery implementation plan

**Goal:** Make deterministic Elasticsearch analytics execute against heterogeneous mappings and promote generic repeated encoded-DNS behavior without scenario-specific knowledge.

**Base:** `codex/schema-aware-discovery` stacked on PR #8 commit `4f3794f`.

### Task 1: Preserve queryable field capabilities

**Files:** `romulus/investigation/workflow.py`, `tests/test_retrieval_contracts.py`

- [x] Add RED tests for object-container exclusion, concrete leaf types, multi-fields, family capability maps, and persisted inventory.
- [x] Implement stable mapping flattening and derive existing field lists from queryable leaves.
- [x] Run focused retrieval tests; include in the milestone commit.

### Task 2: Compile behavior queries by field capability

**Files:** `romulus/intelligence/behavior_catalog.py`, `romulus/investigation/workflow.py`, `tests/test_behavior_catalog.py`, `tests/test_retrieval_contracts.py`

- [x] Add RED tests proving incompatible object/numeric/IP aliases are skipped, keyword/text fields receive compatible clauses, exact indicators remain exact, and required predicates without compatible fields are unsupported.
- [x] Thread capability maps through deterministic behavior and indicator seed planning without changing the model/native-query contract.
- [x] Run focused compiler/workflow tests; include in the milestone commit.

### Task 3: Promote repeated encoded DNS behavior

**Files:** `romulus/intelligence/analytics.py`, `romulus/intelligence/behavior_catalog.json`, `tests/test_candidate_loop.py`

- [x] Add RED tests for strongest-label detection and a five-query, ten-minute, same-source/suffix encoded-label burst with stable citations.
- [x] Add benign controls for cross-source, cross-suffix, low-entropy, repeated-identical, and out-of-window traffic.
- [x] Implement the aggregate and catalog entry without adding evaluated-dataset facts; prove that it creates a candidate but no finding.
- [x] Prove candidate-owned DNS evidence reaches a candidate-grounded hypothesis and the bounded reasoning case file.
- [x] Run focused aggregate/catalog tests; include in the milestone commit.

### Task 4: Review and exact proof

**Files:** `VALIDATION.md`, this plan

- [x] Run the complete local suite, compilation, and diff validation.
- [x] Complete a fresh Critical/Important review and fix findings through RED/GREEN tests.
- [ ] Archive the exact commit, match its digest on the VM, run all dependency-complete tests, compilation, and configured diagnostics.
- [ ] Run a read-only live query-compatibility probe that executes every planned host seed query against the configured index with size one and records pass/fail totals without retaining events.
- [ ] Record proof, remove disposable artifacts, commit, push, and open a stacked PR against `codex/attack-discovery`.
