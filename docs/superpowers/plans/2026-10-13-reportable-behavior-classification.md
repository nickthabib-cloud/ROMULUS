# Reportable Behavior Classification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make ROMULUS reliably deliver evidence-backed suspicious and malicious behavior while preserving weaker unresolved anomalies in a separate analyst-readable report and constraining any possible-activity narrative to accepted evidence.

**Architecture:** A new pure classification module owns classification, legacy migration, lifecycle status, and reportability independently of priority/confidence. Catalog entries provide reviewed deterministic policy; one normalized report-item projection feeds both primary reports and the bounded narrative case. An optional anomaly TXT is verified as a first-class report before existing compact retention removes working bulk.

**Tech Stack:** Python 3.10+, JSON catalogs and schemas, `unittest`, LangGraph state, Ollama structured JSON, `python-docx`, SQLite retention, PowerShell/SSH validation.

**Spec:** `docs/superpowers/specs/2026-10-13-reportable-behavior-classification-design.md`

## Global Constraints

- Classification is exactly `anomalous`, `suspicious`, or `malicious`; investigation status is exactly `new`, `investigating`, `follow_up_exhausted`, `resolved`, or `dismissed`.
- Priority and confidence never promote classification. Model output never creates or changes classification, evidence, findings, or causal graph edges.
- Singular reporting requires a reviewed catalog policy plus valid owned evidence and required context. Missing policy/context fails closed to anomalous and non-primary-report handling.
- Malicious admission is limited in this slice to an explicit current trusted indicator marked malicious, with exact typed matching, confidence at least 90, provenance, and non-expiration. Behavior analytics cannot default to malicious.
- Undirected hunts still form no hypothesis and make no model call before deterministic telemetry creates a candidate.
- Search caps, errors, timeouts, and missing sources remain coverage gaps, never negative evidence.
- Finalized hunts create an anomaly TXT only when an unresolved anomalous-only candidate exists. The main DOCX/TXT pair always remains required.
- Report generation and reopening succeed before compact cleanup. Compact retention preserves all report files and reportable cited evidence, but anomaly evidence may exist only as compact human-readable facts in the anomaly report.
- Runtime logic, prompts, tests, and catalogs contain no evaluated-dataset identity, address, timestamp, expected tool, or attack sequence.

## File Structure

- Create `romulus/investigation/classification.py`: policy application, conservative migration, lifecycle derivation, audit history, and candidate selectors.
- Create `romulus/reporting/report_items.py`: one normalized projection for classified candidates and legacy findings, with linked-item de-duplication.
- Create `romulus/investigation/narrative.py`: bounded narrative case, relationship IDs, deterministic admission, and safe fallback.
- Create `tests/test_classification.py` and `tests/test_activity_narrative.py`: focused pure-unit coverage.
- Modify `romulus/intelligence/behavior_catalog.json`, `behavior_catalog.schema.json`, and `behavior_catalog.py`: reviewed policy data, fail-closed validation, and candidate policy provenance.
- Modify `romulus/investigation/candidate_triage.py`, `casefile.py`, and `workflow.py`: independent classification/status semantics and final narrative orchestration.
- Modify `romulus/models.py` and `romulus/agent/ollama.py`: suspicious default for legacy findings and structured narrative synthesis only.
- Modify `romulus/reporting/report.py` and `romulus/retention.py`: classified primary sections, anomaly TXT, report verification, and compact state.
- Modify existing focused tests plus `README.md`, `docs/behavior-analytics.md`, `CHANGELOG.md`, and `VALIDATION.md`.

## Review Focus

- A legacy or compact candidate missing new fields must load as anomalous and never become malicious; Task 2 adds this regression.
- One evidence record matching multiple analytics must not satisfy independent corroboration or aggregate minimum evidence; Task 2 pins distinct owned evidence and existing relationship rules.
- An explicitly malicious indicator that is expired, low-confidence, unprovenanced, or substring-only must be rejected or remain non-malicious; Task 1 covers each input.
- Missing, empty, duplicate, mismatched-generation, or undeclared anomaly report paths must prevent compact cleanup without harming reports; Task 4 exercises these transitions.
- Narrative output containing unknown IDs, invisible evidence, invented IP/domain/time facts, or a disconnected multi-item cluster must be rejected without changing report items; Task 5 covers every case.

---

### Task 1: Reviewed catalog classification policy

**Files:**
- Modify: `romulus/intelligence/behavior_catalog.json`
- Modify: `romulus/intelligence/behavior_catalog.schema.json`
- Modify: `romulus/intelligence/behavior_catalog.py`
- Modify: `tests/test_behavior_catalog.py`

**Interfaces:**
- Consumes: existing analytic matching, evidence ownership, semantic roles, and exact indicator normalization.
- Produces: validated `classification_policy` objects on every analytic and trusted-indicator candidates carrying `classification`, `classification_reason`, `classification_policy_version`, and `classification_history`.

- [ ] **Step 1: Write failing catalog-policy tests**

Add tests asserting all shipped analytics contain:

```python
policy = analytic["classification_policy"]
self.assertIn(policy["default_classification"], {"anomalous", "suspicious"})
self.assertIsInstance(policy["single_record_reportable"], bool)
self.assertGreaterEqual(policy["minimum_owned_evidence"], 1)
self.assertTrue(set(policy["required_context_roles"]) <= {p["role"] for g in ("all", "any") for p in analytic["match"][g]})
self.assertIn(policy["upgrade_rule"], {"none", "independent_typed_entity_within_30m"})
self.assertEqual(policy["downgrade_rule"], "explicit_benign_evidence_only")
self.assertGreaterEqual(policy["policy_version"], 1)
self.assertTrue(policy["policy_reason"].strip())
```

Also assert validation rejects missing policy fields, behavior default `malicious`, required context outside predicate roles, singular reportability with `minimum_owned_evidence != 1`, and invalid upgrade/downgrade rules.

- [ ] **Step 2: Run the catalog tests and verify RED**

Run: `python -m unittest -v tests.test_behavior_catalog.CatalogLoadingTests`

Expected: FAIL because shipped/test analytics lack `classification_policy` and the loader does not validate it.

- [ ] **Step 3: Implement policy validation and annotate the catalog**

Add `_validate_classification_policy(analytic, prefix)` in `behavior_catalog.py` and mirror the required object in the JSON schema.

Use `anomalous`, `single_record_reportable=false`, and `upgrade_rule=independent_typed_entity_within_30m` for:

`BH-XPLAT-001`, `BH-LNX-002`, `BH-LNX-007`, `BH-LNX-008`, `BH-LNX-009`, `BH-AUTH-001`, `BH-AUTH-003`, and `BH-NET-001` through `BH-NET-008`.

Use `suspicious` for every other shipped analytic. Elasticsearch suspicious analytics use `minimum_owned_evidence=1` and `single_record_reportable=true`. Aggregate suspicious analytics use `single_record_reportable=false` with exact minima: `BH-AUTH-002=2`, `BH-AUTH-004=2`, `BH-NET-009=2`, `BH-NET-010=5`. Required context roles are the predicate roles whose presence makes the rule specific; no policy may rely on prose or score.

- [ ] **Step 4: Write failing trusted-indicator malicious-gate tests**

Extend indicator validation/build tests with an explicit `classification` field. Assert a current exact indicator marked `malicious`, confidence 90+, and complete provenance becomes malicious; missing classification defaults suspicious. Assert malicious plus confidence 89, missing source/created time, expiration, and substring-only observations do not become malicious.

- [ ] **Step 5: Implement indicator and behavior candidate metadata**

Update `load_local_indicators()` to accept only `suspicious|malicious`, default absent values to suspicious, and reject malicious entries below confidence 90. Update `_behavior_candidate(...)` to copy validated policy and provenance into the candidate without using priority as truth. Keep compatibility fields for now, derived from classification rather than score.

- [ ] **Step 6: Run focused tests and commit**

Run: `python -m unittest -v tests.test_behavior_catalog`

Expected: PASS.

```bash
git add romulus/intelligence/behavior_catalog.json romulus/intelligence/behavior_catalog.schema.json romulus/intelligence/behavior_catalog.py tests/test_behavior_catalog.py
git commit -m "feat: define reviewed behavior classifications"
```

### Task 2: Candidate classification and investigation lifecycle

**Files:**
- Create: `romulus/investigation/classification.py`
- Modify: `romulus/investigation/candidate_triage.py`
- Modify: `romulus/investigation/casefile.py`
- Modify: `romulus/investigation/workflow.py`
- Modify: `romulus/models.py`
- Create: `tests/test_classification.py`
- Modify: `tests/test_attack_discovery.py`
- Modify: `tests/test_candidate_loop.py`
- Modify: `tests/test_casefile.py`

**Interfaces:**
- Consumes: candidate `classification_policy`, owned evidence IDs, deterministic relationships, follow-up records, and linked finding IDs.
- Produces:
  - `apply_classification(candidate: Mapping[str, Any], *, relationship_count: int = 0) -> dict[str, Any]`
  - `migrate_candidate(candidate: Mapping[str, Any]) -> dict[str, Any]`
  - `refresh_investigation_status(candidate: Mapping[str, Any]) -> dict[str, Any]`
  - `reportable_candidates(candidates: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]`
  - `unresolved_anomalous_candidates(candidates: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]`

- [ ] **Step 1: Write failing pure classification tests**

Assert:

```python
self.assertEqual(apply_classification(specific_singular)["classification"], "suspicious")
self.assertEqual(apply_classification(weak_high_score)["classification"], "anomalous")
self.assertEqual(apply_classification(weak_with_relation, relationship_count=1)["classification"], "suspicious")
self.assertEqual(migrate_candidate({"priority_score": 100})["classification"], "anomalous")
self.assertNotEqual(migrate_candidate({"kind": "trusted_indicator", "customer_visible": True})["classification"], "malicious")
```

Use distinct evidence IDs for minimum counts and prove duplicate IDs do not qualify. Prove every classification change appends prior/new value, rule, cited evidence IDs, and timestamp; repeated application is idempotent.

- [ ] **Step 2: Run the pure tests and verify RED**

Run: `python -m unittest -v tests.test_classification`

Expected: FAIL because `classification.py` does not exist.

- [ ] **Step 3: Implement the pure classification module**

Derive customer visibility only as `classification in {suspicious, malicious}` and status not dismissed. The relationship upgrade requires at least one current `related_candidates` record produced by `relate_candidates`; it never keys off score. Conservative migration uses anomalous plus status derived from old follow-up/finding/disposition state and never fabricates history.

`refresh_investigation_status()` uses: explicit benign/dismissed → dismissed; linked finding → resolved; pending/in-progress follow-up or history with unfinished work → investigating; all attempted follow-ups terminal → follow_up_exhausted; otherwise new.

- [ ] **Step 4: Write failing workflow and case-file lifecycle tests**

Replace old score/corroboration visibility assertions with classification assertions. Add tests proving one record cannot self-corroborate, a relationship upgrades only a policy-authorized anomaly, scheduled follow-up changes status but not classification, terminal failed/capped follow-up becomes `follow_up_exhausted`, and linked findings resolve the candidate. Assert the case file exposes classification/status but cannot reconstruct a higher classification from visible score or hidden relationships.

- [ ] **Step 5: Wire classification through triage, merge, workflow, and case files**

Call `migrate_candidate()` on prior/current candidates, apply relationship-based classification after `relate_candidates`, and refresh lifecycle after `_record_scheduled_followups()` and `_link_candidates_to_findings()`. Preserve `disposition` and `customer_visible` only as derived compatibility fields. Add `classification: str = "suspicious"` to `Finding` as a trailing default so existing positional constructors remain compatible; model-authored and deterministic legacy findings cannot be malicious by default.

- [ ] **Step 6: Run focused lifecycle tests and commit**

Run: `python -m unittest -v tests.test_classification tests.test_behavior_catalog tests.test_attack_discovery tests.test_candidate_loop tests.test_casefile`

Expected: PASS.

```bash
git add romulus/investigation/classification.py romulus/investigation/candidate_triage.py romulus/investigation/casefile.py romulus/investigation/workflow.py romulus/models.py tests/test_classification.py tests/test_attack_discovery.py tests/test_candidate_loop.py tests/test_casefile.py
git commit -m "feat: separate candidate truth from investigation status"
```

### Task 3: Normalized suspicious and malicious report items

**Files:**
- Create: `romulus/reporting/report_items.py`
- Modify: `romulus/reporting/report.py`
- Modify: `tests/test_customer_report.py`
- Modify: `tests/test_behavior_catalog.py`

**Interfaces:**
- Consumes: Task 2 `reportable_candidates(...)`, candidate/finding links, evidence, follow-up history, and coverage gaps.
- Produces: `build_report_items(state: Mapping[str, Any]) -> list[dict[str, Any]]`, ordered malicious before suspicious and de-duplicated by explicit `finding_ids` links only.

- [ ] **Step 1: Write failing report-item projection tests**

Assert a singular suspicious reverse-shell-style candidate produces one item with exact evidence, benign alternatives, status, follow-up result, and next actions; an anomalous candidate produces none. Assert a malicious trusted indicator is first, a linked candidate/finding pair becomes one item, an unlinked legacy finding remains suspicious, and overlapping evidence without an explicit link does not silently merge two behaviors.

- [ ] **Step 2: Run the projection tests and verify RED**

Run: `python -m unittest -v tests.test_customer_report tests.test_behavior_catalog.CandidateReportingTests`

Expected: FAIL because report items and classified sections do not exist.

- [ ] **Step 3: Implement `build_report_items()`**

Return stable items with `item_id`, `classification`, `title`, `observation`, `why_it_matters`, `evidence_ids`, `assets`, `first_observed`, `last_observed`, `investigation_status`, `follow_up_results`, `benign_alternatives`, `coverage_gaps`, `recommended_actions`, `confidence`, and ATT&CK IDs. Never infer a link from prose, score, or ATT&CK overlap.

- [ ] **Step 4: Update TXT and DOCX primary reports**

Replace customer visibility/score gates with normalized report items. Add separate `MALICIOUS BEHAVIOR` and `SUSPICIOUS BEHAVIOR` sections in TXT and matching Word subsections. Render exact citations, follow-up outcomes, alternatives, limitations, and actions. Preserve factual supported paths as a separate section; do not suppress unconnected items. Update verdict/count/priority calculations to use report items.

- [ ] **Step 5: Run report tests and commit**

Run: `python -m unittest -v tests.test_customer_report tests.test_behavior_catalog.CandidateReportingTests`

Expected: PASS, including a one-record suspicious item in both primary reports and no anomaly leakage into customer sections.

```bash
git add romulus/reporting/report_items.py romulus/reporting/report.py tests/test_customer_report.py tests/test_behavior_catalog.py
git commit -m "feat: report evidence-backed suspicious behavior"
```

### Task 4: Analyst-readable anomaly report and report-gated retention

**Files:**
- Modify: `romulus/reporting/report.py`
- Modify: `romulus/retention.py`
- Modify: `tests/test_customer_report.py`
- Modify: `tests/test_retention.py`
- Modify: `tests/test_core.py`

**Interfaces:**
- Consumes: Task 2 `unresolved_anomalous_candidates(...)`, in-memory evidence and authoritative task/outcome history.
- Produces: optional `reports/anomalous/<hunt-id>-anomalous-leads-<stamp>.txt` included in `report_paths` and `retention.reports_verified`, plus a compact `report_manifest.anomaly_expected` verification flag.

- [ ] **Step 1: Write failing anomaly-report tests**

Assert a completed state, or a partial state carrying `finalized_at`, with one unresolved anomaly returns three report paths, sets `report_manifest.anomaly_expected=true`, creates the anomaly subdirectory, and includes hunt/window, candidate ID, compact observed fact and evidence ID, why unusual, performed searches/outcomes, benign alternatives, coverage gaps, next pivot, and a “lead, not conclusion” warning. Assert an ordinary resumable partial state and dismissed/resolved/reportable-only completed hunts return only DOCX/TXT with `anomaly_expected=false`. Assert raw query bodies, packet payloads, model internals, and credentials are absent.

- [ ] **Step 2: Run report tests and verify RED**

Run: `python -m unittest -v tests.test_customer_report`

Expected: FAIL because no anomaly companion is generated.

- [ ] **Step 3: Implement bounded anomaly rendering**

Add `_anomaly_content(state, candidates)` and have `generate_report()` write the optional file with the same UTC stamp as the primary pair only when `state.status == "completed"` or `finalized_at` exists. Build evidence facts only from owned IDs and bounded `observation`, `source`, `observed_at`, `asset`, and compact provenance; render task intent/outcome summaries without native queries. Set `state["report_manifest"]={"generation_stamp": stamp, "anomaly_expected": bool}` before returning the paths.

- [ ] **Step 4: Write failing retention verification tests**

Extend `_reports()` fixtures and assert valid primary pair plus declared anomaly file compacts successfully and preserves all files/digests and `report_manifest` while dropping anomaly-only evidence/candidates from compact SQLite state. Assert missing, empty, wrong-hunt, wrong-directory, duplicate, unexpectedly present, or expected-but-undeclared anomaly TXT prevents cleanup and leaves the prior state/evidence intact. Preserve legacy two-report compaction with no manifest by treating anomaly expectation as false.

- [ ] **Step 5: Generalize `_verify_reports()` safely**

Change verification to `_verify_reports(hunt_id, report_paths, *, anomaly_expected=False)`. Require exactly one DOCX and one same-stem primary TXT. Require exactly one additional TXT when `anomaly_expected` is true and none otherwise; the anomaly parent must be named `anomalous`, its filename must match the hunt and primary generation stamp, and its identity line must reopen correctly. `apply_retention()` derives the flag from `report_manifest` and `_compact_state()` preserves that manifest for idempotent retries. Verify every declared artifact and retain its hash; reject all other extras. Keep anomaly evidence disposable because its human-readable facts are already verified in the durable report.

- [ ] **Step 6: Run report/retention tests and commit**

Run: `python -m unittest -v tests.test_customer_report tests.test_retention tests.test_core`

Expected: PASS.

```bash
git add romulus/reporting/report.py romulus/retention.py tests/test_customer_report.py tests/test_retention.py tests/test_core.py
git commit -m "feat: retain separate anomalous lead reports"
```

### Task 5: Evidence-constrained possible activity narrative

**Files:**
- Create: `romulus/investigation/narrative.py`
- Modify: `romulus/agent/ollama.py`
- Modify: `romulus/investigation/workflow.py`
- Modify: `romulus/reporting/report.py`
- Modify: `romulus/retention.py`
- Create: `tests/test_activity_narrative.py`
- Modify: `tests/test_customer_report.py`
- Modify: `tests/test_retention.py`
- Modify: `tests/test_core.py`

**Interfaces:**
- Consumes: Task 3 normalized report items, visible owned evidence, admitted candidate relationships/graph facts, and remaining model-call capacity.
- Produces:
  - `build_narrative_case(state: Mapping[str, Any], items: Sequence[Mapping[str, Any]]) -> dict[str, Any]`
  - `admit_activity_narrative(case: Mapping[str, Any], proposal: Mapping[str, Any]) -> dict[str, Any]`
  - `unavailable_activity_narrative(items, reason: str) -> dict[str, Any]`
  - `Ollama.synthesize_activity_narrative(case_file: dict) -> dict`

- [ ] **Step 1: Write failing narrative case/admission tests**

Build a generic case with two related suspicious items and one unrelated item. Assert the case contains only reportable items/owned evidence and stable `REL-<digest>` relationship IDs. Valid model output may cluster the related pair, must leave the third unconnected, and cannot change classification. Assert rejection of unknown item/evidence/relationship IDs, invisible citations, repeated placement, disconnected clusters, and IP/domain/ISO-time tokens absent from allowed visible facts.

- [ ] **Step 2: Run narrative tests and verify RED**

Run: `python -m unittest -v tests.test_activity_narrative`

Expected: FAIL because `narrative.py` does not exist.

- [ ] **Step 3: Implement bounded case construction and deterministic admission**

Limit the case to 12 report items and 48 owned evidence records. A multi-item cluster must cite admitted relationships that connect all members; a single-item cluster needs no relationship. Normalize omissions to `unconnected_item_ids`. Store no chain-of-thought. On any structural/fact validation failure, return `no_coherent_narrative=true`, all visible items unconnected, and a bounded rejection reason.

- [ ] **Step 4: Write failing Ollama contract and workflow tests**

Assert `_activity_narrative_schema(case)` enumerates only visible item/evidence/relationship IDs and has no classification, entity, time, finding, query, or tool-action fields. Assert broad candidate-free hunts make no narrative call; no reportable items and exhausted/unavailable model capacity use safe fallback; valid output is admitted once during `_report`; invalid/model-failed output cannot suppress factual reports or mutate candidates/findings/graph.

- [ ] **Step 5: Implement synthesis and report orchestration**

Add `synthesize_activity_narrative()` with a prompt that treats telemetry as untrusted, permits “no coherent narrative,” forbids new facts/causality, and emits only the strict schema. In `_report`, call it through existing audited `_call` only when reportable items exist, Ollama is enabled, and capacity remains; otherwise create the fallback. Record bounded coverage counters and store only the admitted narrative, never raw prompt/response, in compact state.

- [ ] **Step 6: Render and retain the hypothesis section**

Add `Hypothesis: Possible Activity Narrative` to TXT/DOCX after factual suspicious/malicious sections. Render model-selected clusters using canonical report-item facts and relationship caveats, clearly label them unconfirmed, and list unconnected items. If unavailable or incoherent, say so explicitly. Add `activity_narrative` and bounded narrative coverage summary to compact state.

- [ ] **Step 7: Run focused narrative/report/retention tests and commit**

Run: `python -m unittest -v tests.test_activity_narrative tests.test_customer_report tests.test_retention tests.test_core tests.test_candidate_loop tests.test_reasoning_admission`

Expected: PASS.

```bash
git add romulus/investigation/narrative.py romulus/agent/ollama.py romulus/investigation/workflow.py romulus/reporting/report.py romulus/retention.py tests/test_activity_narrative.py tests/test_customer_report.py tests/test_retention.py tests/test_core.py
git commit -m "feat: add constrained activity narrative"
```

### Task 6: Documentation, full proof, review, deployment validation, and PR

**Files:**
- Modify: `README.md`
- Modify: `docs/behavior-analytics.md`
- Modify: `CHANGELOG.md`
- Modify: `VALIDATION.md`
- Modify: any files required by Critical/Important review findings, each with a regression test.

**Interfaces:**
- Consumes: completed Tasks 1–5.
- Produces: reviewed exact commit, local and VM proof, one isolated generic live hunt, retained reports, cleanup evidence, and a stacked GitHub PR.

- [ ] **Step 1: Update operator and maintainer documentation**

Document the three independent candidate dimensions, catalog policy fields, singular suspicious admission, malicious gate, anomaly report location/contents, narrative limits, and compact retention. State plainly that classification is not a compromise declaration and anomaly reports are fallback lead queues.

- [ ] **Step 2: Run complete local verification**

Run:

```bash
python -m unittest discover -s tests -v
python -m compileall -q romulus tests
git diff --check
```

Expected: every available test passes; only documented optional-dependency skips are allowed; compilation and diff checks are clean.

- [ ] **Step 3: Run an isolated offline end-to-end hunt**

Use temporary ROMULUS data/log/report directories and compact retention. Prove a singular suspicious synthetic behavior reaches the primary report, an unrelated anomaly reaches only the anomaly TXT, the narrative does not force them together, all report paths reopen, and uncited working data is removed. Delete only the exact disposable runtime after recording hashes/results.

- [ ] **Step 4: Request a fresh whole-branch review**

Review from the parent milestone through HEAD for score/classification leakage, false malicious promotion, legacy migration, follow-up state loss, report de-duplication, anomaly report safety, narrative authority leakage, report verification, compact cleanup, and evaluated-dataset leakage. Fix every Critical/Important issue RED→GREEN, rerun focused tests, then rerun the full suite. Record Minor issues as deferred.

- [ ] **Step 5: Validate the exact archive on the development VM**

Commit the reviewed code, create a source archive excluding secrets/runtime state, record SHA-256, transfer through the previously authorized SSH path, verify the same digest remotely, and extract into a unique disposable directory. In a fresh dependency-complete shell run the full suite, `compileall`, and configured read-only `doctor`. Do not place credentials in commands, files, logs, reports, or the repository.

- [ ] **Step 6: Run one isolated generic read-only live hunt**

Use the operator-authorized time boundary and a broad objective that contains no expected identity, tool, behavior, or attack sequence. Finalize/compact before evaluation. Verify that genuine deterministic matches are classified and delivered with exact citations; unresolved anomalies appear in the companion report; unsupported items remain separate; and the possible narrative either cites admitted relationships or declines to connect them. Compare the finalized outputs to the operator-supplied story only after the hunt, never as runtime input. Report false positives, misses, source gaps, and the fact that a match is not automatically attack activity.

- [ ] **Step 7: Record validation and clean exact disposable artifacts**

Append exact commits, archive digest, test/skip counts, diagnostics, hunt ID/outcome, classification counts, report hashes, narrative admission result, retention proof, limitations, and review result to `VALIDATION.md`. Resolve and verify cleanup paths before deleting only the exact local/remote archive, extracted checkout, isolated runtime, and temporary logs. Preserve user-relevant reports.

- [ ] **Step 8: Final verification, push, and open the stacked PR**

Run the full local suite, `compileall`, `git diff --check`, and `git status --short` once more. Commit validation documentation, push `codex/reportable-behavior-classification`, open a PR against `codex/schema-aware-discovery` while its parent PR remains unmerged, and attach the PR to this chat. The PR body must state the evidence contract, anomaly/report retention behavior, exact validation, and honest remaining limitations.
