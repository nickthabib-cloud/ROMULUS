# Validation record

This file records engineering validation performed against the development deployment. It is evidence of observed behavior, not an operational authorization or a claim that the environment is clean.

## 2026-10-12 — representative bounded retrieval (local proof; live hunt paused)

### Implemented behavior

- Capped Elasticsearch results are retained across deterministic time strata within one PIT. When a mission window is absent, the adapter derives the matching time extent; inability to do so is explicitly reported as a fallback.
- Capped Arkime results use deterministic ordered rank windows inside one logical scheduler operation. Duplicate session IDs are suppressed, and windows beyond Arkime's accepted offset are reported rather than silently replaced with early rows.
- TShark still scans the complete filtered packet stream and reports the exact match count. Retained rows use deterministic per-time-stratum reservoirs; malformed or unavailable timestamps use a disclosed whole-stream reservoir.
- Sampling policy is code-controlled and part of exact task identity. Bounded outcome metadata reaches the technical report and compact aggregate coverage, while raw queries, rank-window requests, and per-request history do not survive compact retention.
- Capped work remains partial and cannot resolve candidate or hypothesis coverage.

### Validation boundary

- Generic synthetic regressions prove cross-window retention, stable repetition, duplicate suppression, conservative fallbacks, report audience separation, and compact aggregation without importing holdout identities, indicators, commands, tools, hostnames, or timestamps into runtime behavior.
- The complete post-review local suite passed all 152 tests available in this environment, with six dependency-backed checks reserved for the development VM. The focused scheduler/report/retention suite passed 41 tests with one VM dependency skip. `compileall`, `git diff --check`, and a runtime/test corpus-identity scan were clean before the final review corrections and are rerun at the deployment gate.
- Whole-branch review found that unbounded scheduled Elasticsearch calls did not pass their mapped timestamp explicitly, duplicate suppression could leave unused sample slots, and one failed Elasticsearch stratum discarded successful strata. Failing regressions reproduced all three conditions. The corrected adapters backfill only within a bounded two-times-cap read ceiling, retain successful strata with a disclosed failure count, and carry bounded matched/retained per-stratum counts through the technical report. The customer report receives only a plain-language sampled-coverage limitation.
- The operator paused another live hunt after determining that the expected attack path is not currently present in the loaded telemetry dataset. No hunt will be used as detection proof until the dataset/ingestion path is diagnosed and the expected telemetry is confirmed present independently of ROMULUS.
- The remaining deployment gate is therefore dependency-complete VM tests, compilation, diagnostics, and read-only ingestion-path diagnosis. A later live evaluation must start from a confirmed dataset and remain blind to the external oracle during execution.

## 2026-10-12 — unified search scheduler (validated with a coverage limitation)

### Implemented behavior

- Every evidence search now enters one persisted task registry and queue. Exact source/target/query/window fingerprints merge duplicate origins and owners without treating registration as completion.
- Discovery scheduling reserves capacity across healthy host and network telemetry families. Investigation ordering is code-derived from candidate severity, grounding, and remaining coverage; model output cannot choose its tier.
- Candidate follow-ups and hypothesis coverage consume the exact outcome of their named task. A confirmed uncapped zero-result search may resolve its bounded question; partial, capped, failed, skipped, interrupted, timed-out, or budget-limited work cannot produce closure.
- Broad undirected hunts remain deterministic until telemetry produces a candidate. Grounded model searches must cite visible candidate/evidence IDs and still pass source grammar, field, time, and read-only validation.
- Resume migrates legacy partial state before graph continuation. A task interrupted during read-only execution is requeued once with possible-duplicate disclosure and cannot enter an infinite retry loop.
- The technical text report records bounded task ownership and exact outcome metadata without query bodies. The customer Word report omits scheduler internals. Compact retention removes full scheduler working state and retains only aggregate counts and unresolved/fairness gaps.

### Local proof

- Registration, ordering, fairness, authoritative-outcome, resume, reporting, retention, candidate, and workflow changes were developed with focused RED/GREEN tests. A dedicated regression proves report termination consults scheduler task status rather than the obsolete legacy lead queue.
- A source-fairness review found that Elasticsearch network indices were marked healthy without receiving an initial network task when Arkime/PCAP were absent. A failing regression reproduced the gap; deterministic network-index discovery and host-target scoping fixed it.
- Exact-execution review also found that source-family and scope-description labels could create two tasks for the same source/targets/query/fixed bounds. A failing regression reproduced it; fingerprint identity now excludes those nonexecuting labels.
- Resume review found that rolling mission windows could be rematerialized across registrations and that legacy migration omitted pending leads or treated completeness-unknown zero rows as resolving. Strengthened failing tests now prove one persisted absolute window, queued pending legacy work, and nonresolving completeness-unknown attempts.
- Whole-branch review also found inconsistent mapping-based source classification, timezone-equivalent fingerprint duplication, nonexecutable pending legacy tasks, late-owner outcome loss, model-call priority inversions, and queued work without terminal outcomes. Each finding received a failing regression before its fix. Network-only Elasticsearch is now reported honestly, pre-telemetry model calls are eliminated, queued source searches outrank optional planning, and report finalization records every unrun task without contacting a source.
- The first dependency-complete live-graph test exposed a state-boundary defect: inventory nodes set `source_health`, but the key was absent from the LangGraph state schema and was discarded between nodes. That made working host and network sources appear unavailable and could falsely close incomplete searches as explicit telemetry gaps. The integration test failed on the false closure before the schema fix; it now asserts preserved source health, both scheduled source families, task-linked completion IDs, and nonresolving completeness-unknown outcomes.
- The complete local suite ran 127 tests successfully, with six expected checks skipped for LangGraph/SQLite resume, Arkime/Ollama adapters, and full offline-graph execution on the development VM.
- `python -m compileall -q romulus tests` and `git diff --check` both completed successfully.
- The dependency-complete VM suite ran all 127 tests successfully with no skips. This includes the real SQLite/LangGraph interrupted-task resume regression, full offline graph/report/retention execution, adapter checks, and the corrected live-graph source-health/false-closure regression.
- The first exact-commit `doctor` run found that planner-supported `tcp.port` and `udp.port` were absent from the TShark adapter output-field allowlist. VM `tshark -G fields` confirmed both are valid fields. A focused planner/adapter subset regression failed before the fix and passed after the adapter allowlist was synchronized; the complete local suite remained 127/127 green with six dependency-gated skips. Exact-commit VM redeployment and a second `doctor` remain required.
- Exact commit `ae382ec` then passed `doctor` with every configured dependency/source/capture green. Its isolated offline hunt completed with one deduplicated scheduled task/outcome, reopened both reports, retained only cited evidence, preserved a compact scheduler summary, and removed task/query/outcome/audit/checkpoint bulk; the disposable root was deleted afterward.
- The first holdout-blind live hunt, `HUNT-0B92EB7C96`, remained evidence-safe but exposed scheduler starvation: deterministic discovery produced 24 telemetry-backed candidates, then 65 candidate-follow-up tasks expanded to 83 unique tasks (42 TShark tasks) and consumed all 60 calls without a model reasoning turn. ROMULUS correctly returned a partial incomplete investigation with no finding and no closure, but this did not satisfy the super-hunter workflow.
- Two focused regressions failed before remediation. Generic network pivots now prefer Arkime and use PCAPs only as a fallback, eliminating redundant per-candidate full-capture fan-out. The graph router now drains critical/high candidate tasks before admitting grounded model reasoning, then reasons ahead of model/coverage/medium-low breadth while preserving the last call for queued source work. Explicit TShark requests and discovery still retain one exact task per approved capture. The complete local suite now passes 129 tests with six dependency-gated skips; compilation and diff checks are clean.
- Exact commit `36db042` passed the dependency-complete VM suite with all 129 tests and no skips, then passed every `doctor` check. Replacement hunt `HUNT-37F6782AF6` stayed undirected, used the explicit UTC mission window, discovered 26 candidates from both telemetry families before reasoning, tested all seven high-priority candidates first, and then made its first model call ahead of lower-value breadth. Generic candidate follow-ups used Arkime rather than repeating every PCAP.
- That replacement run also exposed a safety defect, so its single reported lead is rejected as validation evidence. The lead labeled ordinary HTTP traffic as ATT&CK `T1110`, and its three citations did not describe the same connection: only one record contained the claimed source/destination pair. A later model search intent also contained a malformed IPv4 address. The run therefore proves the scheduler transition but fails the no-hallucinated-findings gate.
- Four focused tests reproduced unsupported ATT&CK admission, cross-contaminated citations, unrelated supported assessments, and malformed search-intent indicators before the fix. Model-created hypotheses are now disabled; supported assessments must share a deterministic candidate entity; findings must name an already supported hypothesis, use its technique or remain unmapped, and retain at least two records that each contain all claimed IPs. Published finding prose is generated from the checked hypothesis and records rather than copied from the model. The complete local suite now passes 133 tests with six dependency-gated skips.
- The initial replacement run accidentally used prefixed directory variables that ROMULUS does not read; its uniquely identified artifacts landed in the normal runtime directories. This was a validation-harness mistake, not a runtime routing defect. Cleanup removed only hunt `HUNT-37F6782AF6`: 4,672 evidence rows, one finding, one investigation record, one checkpoint, 41 audit rows, two finding-event rows, and its exact report pair. Residual counts for that hunt were zero; no other operational hunt or telemetry data was changed.
- Exact commit `3ded319` passed all 133 dependency-complete VM tests with no skips, `compileall`, and every `doctor` check. The deployed archive SHA-256 was `6A30B6627237E2E6ECC692FCB0035CDD880C4ABE5EF55147AE3AEFC19DA2357D` on both systems.
- Corrected isolated hunt `HUNT-B30F91BFF5` stayed undirected across the full 2024-11-13 UTC mission window. Both telemetry families produced 26 deterministic candidates; all seven high-priority candidates were tested before the first model call. Four model calls proposed ten searches, of which three passed the deterministic admission checks. No model hypothesis was accepted, all 14 hypotheses had `observed_candidate` basis, and no finding was published. The hunt ended honestly as `partial / incomplete_investigation` at depth four with 55 of 60 calls used, 49 distinct tasks/outcomes/fingerprints, and no clean-environment claim.
- Explicit compact finalization reopened the matching Word/text reports, retained 28 of 5,667 evidence rows, removed 5,639 uncited rows, 55 audit rows, and one checkpoint, and removed the full task, queue, outcome, history, tool-run, host, and network collections. The compact summary retained all 49 task aggregates, 471 avoided duplicate registrations, 22 unresolved tasks, and no source-fairness gap.

### Holdout isolation

- The external `attack_log.json` and `attackmate.json` files remained outside the repository and runtime and were opened only after the blind hunt was explicitly finalized and compacted. They were used solely as a post-hunt oracle and did not alter prompts, analytics, selectors, fixtures, or scheduler priority. Commands and sensitive values were not copied into the repository.
- The oracle describes 53 actions from approximately 19:17 through 20:37 UTC: external reconnaissance, exploitation of a public-facing application, transfer/execution and privilege escalation, then post-root persistence/defense-evasion and credential/discovery activity. ROMULUS published no unsupported finding, but it also detected none of those ground-truth stages.
- The 28 retained evidence rows span only approximately 16:04:20 through 16:05:34 UTC and describe unrelated early-window candidates. Although source queries covered the full day and reported large match totals, result caps admitted a narrow early slice into analysis context, so the later observable attack never reached candidate promotion or model assessment. This is a material query-execution/coverage failure, not evidence that the model rejected the attack.
- The holdout therefore demonstrates conservative reporting but inadequate full-window recall. No runtime behavior was tuned against this dataset. A future milestone must implement source-agnostic, time-stratified bounded retrieval and prove it first with synthetic or independent data before evaluation on a new holdout.

## 2026-10-12 — cited attack paths and safe retention

### Implemented behavior

- ROMULUS builds a deterministic evidence/entity/activity graph and derives finding paths only from evidence IDs cited by that finding. Cross-event time/entity relationships are labeled inferred, include their reasons and confidence, and explicitly do not claim causation.
- Word and text reports include supported attack paths. The technical report preserves path steps, citations, relationship basis, caveats, and disconnected-evidence gaps.
- `compact` retention is the default. It reopens and hunt-matches exactly one DOCX/TXT report pair before removing uncited evidence, hunt-scoped JSONL working records, and checkpoints. Reports, conclusions, findings, cited evidence, compact coverage, source errors, and supported paths remain.
- Partial hunts remain resumable until explicit finalization. `full` retains all working data; irreversible compact transitions, legacy compact-finalized states, and full-to-compact report/policy truth are guarded by regression tests.
- JSONL append and rewrite operations share an interprocess lock so one hunt's cleanup cannot discard another hunt's concurrent event.

### Local proof

- The focused graph, customer-report, and retention suite passed 25 tests before the upgrade-compatibility review; added legacy-state and full-to-compact truth tests were then exercised red/green.
- The final complete local suite passed all 86 tests available in this environment, with five dependency-backed checks skipped for execution on the VM.
- `python -m compileall -q romulus tests` and `git diff --check` completed successfully on the final local tree.

### Live-validation defect and remediation

- The first bounded isolated live attempt, `HUNT-35466BAA8A`, was stopped when the broad phrase `host and network telemetry` was incorrectly classified as operator direction and triggered pre-telemetry hypothesis generation.
- Root cause was an entity-selector regular expression whose separator was optional: ordinary prose was parsed as a `host=and` selector, while clear `host: srv-01` syntax was missed.
- Positive targeting grammar now accepts explicit, quoted, directive, anchored, or structured entity targets while rejecting ordinary scope prose such as `host and network telemetry`, `host was`, and `host endpoints`. The exact failed live objective has both classifier and no-pretelemetry-model regression coverage.
- The corrected bounded live rerun collected deterministic telemetry and candidates before the only model reasoning stage. The failed and corrected attempts both used isolated `/tmp` state and read-only source access.

### Development VM proof

- The deployed archive for code commit `a08b3ed` matched SHA-256 `07622decace6b67726b81c6e7ed29ee44f8037b8cfb29f239ce7dd510cbb533f` locally and on the VM.
- The complete dependency-backed VM suite passed all 86 tests with no skips, and `python -m compileall -q romulus tests` succeeded. `doctor` was fully green for America/New_York time handling, the Python dependencies, Enterprise ATT&CK v19.2 (697 techniques, 697 detection strategies, 1,745 analytics), Ollama `qwen3:8b`, two allowlisted Elasticsearch indexes, Arkime with 19,068 sessions, TShark 4.2.2, three configured PCAPs, and writable runtime paths.
- Disposable offline hunt `HUNT-D83D7125ED` completed as `evidence_supported_lead`. Both reports reopened, one supported three-step path referenced exactly three real cited evidence records, compact state omitted the bulky host/network/tool-run collections, and the retained state preserved the finding, conclusion, cited evidence, compact graph/coverage, and source errors.
- The offline hunt had zero remaining checkpoints and zero hunt-scoped audit/finding JSONL rows after retention, demonstrating report-gated hunt-scoped cleanup rather than broad log deletion.
- Corrected bounded live hunt `HUNT-A4473617E3` used a twelve-minute historical window, compact policy, a 35-call ceiling, one reasoning round, depth one, 50-record search caps, a 200-session Arkime cap, and no PCAP scan. It accumulated 150 analysis-context records and 19 deterministic candidates before its first and only model stage, `analyst_reasoning`; neither `hypothesis_generation` nor `initial_search_planning` ran.
- The live run made 14 calls, retained 300 evidence records durably, and based hypotheses only on `observed_candidate` or `model_proposal_from_visible_context`. It produced one cited finding and one supported path, then correctly remained `partial / evidence_supported_lead` and resumable at the intentional depth cap with its checkpoint and 14 audit rows retained.
- All milestone validation roots, temporary validation scripts, and transfer archives were removed from `/tmp` after verification. Operational `/home/user/ROMULUS/data`, `logs`, `reports`, and `.env` were not modified or deleted.

## 2026-10-12 — candidate-driven investigation loop

### Implemented behavior

- Broad, undirected missions now enter deterministic telemetry discovery with zero initial hypotheses and do not call the model until a deterministic candidate exists.
- Focused missions may create initial hypotheses, but each records `operator_direction` as its basis.
- Candidate-backed hypotheses record stable candidate IDs and cited evidence IDs. Model follow-up hypotheses are accepted only when their claimed basis is a visible evidence or candidate ID; model findings remain evidence-ID-only.
- All 13 aggregate behavior-catalog signals have deterministic generators and a catalog-completeness regression test.
- Candidate disposition and structured follow-up history survive repeated analysis, and actionable high-priority candidates or unfinished required follow-ups prevent clean closure.

### Defects found by live validation

- The first disposable live run revealed that `mission_mode` was not declared in the LangGraph state type. LangGraph therefore dropped the field at the node boundary, allowing undirected collection to reach model-generated initial searches. The run was stopped, `mission_mode` was added to the graph schema, and a dependency-complete graph-boundary regression test now proves that a candidate-free undirected hunt makes no model call.
- The next isolated run reached candidates correctly but exposed an `AttributeError` because candidate-grounded reasoning expected `model_initial_search_plan` to be an object while undirected deferral recorded a status string. The adapter now normalizes either representation, and its model-context test covers the deferred status and candidate queue.
- Final review found that legacy/offline mission state, artifact-ID grounding, candidate follow-up completion, aggregate evidence retention, and coverage closure were looser than the stated evidence contract. Each path now has a regression test. `pivot_results` was also added to the LangGraph schema after the VM suite showed that otherwise valid pivot outcomes were discarded at node boundaries.

### Development VM proof

- The final deployed archive for commit `48c0631` matched SHA-256 `34c2e981c19c005f4bfbc7b9668ed8ba054accf4ea5e89743a32baeada78546d`.
- Deployment diagnostics remained green for Ollama `qwen3:8b`, two allowlisted Elasticsearch indexes, Arkime with 19,068 sessions, TShark 4.2.2, three configured PCAPs, the pinned ATT&CK catalog, and writable runtime paths.
- The complete VM suite passed all 48 tests with no skips. The local dependency-light suite also passed all available tests; dependency-backed adapter, LangGraph, and Word checks were then exercised on the VM.
- Bounded live investigation `HUNT-2903D1FB0C` used isolated `/tmp` state, a twelve-minute 2024 telemetry window, 35-call/one-round limits, 50-record search caps, a 200-session Arkime cap, and no PCAP scan.
- The live sequence was deterministic discovery first: seven behavior searches and one Arkime search produced 250 retained context records and 20 candidates before any model call. State contained eight hypotheses, all with `observed_candidate` basis. The audit contained exactly one model stage, `analyst_reasoning`; there was no `hypothesis_generation` or `initial_search_planning` call.
- Candidate-grounded reasoning returned two accepted, bounded searches: an Arkime evidence-anchored outbound-connection pivot and an Elasticsearch evidence-anchored process/account pivot. Both executed read-only.
- The hunt correctly remained `partial / incomplete_investigation` at the intentional depth and Arkime result caps. It did not publish a finding or claim the environment clean. Both Word and text reports reopened successfully.

### Post-review proof

- The complete VM suite passed all 57 tests with no skips after the final-review corrections; the local dependency-light suite passed the same 57 tests with five dependency-backed checks skipped and then exercised on the VM.
- A second twelve-minute isolated live hunt, `HUNT-113777FD15`, again collected 250 telemetry records and 20 deterministic candidates before its only model call. It formed only candidate-backed hypotheses; no initial hypothesis-generation or search-planning model stage ran.
- Both accepted model pivots cited visible evidence and used bounded evidence windows. The deterministic candidate fallback also compiled an entity-and-time-scoped Elasticsearch pivot even though its ATT&CK technique was unmapped; it returned 50 of 7,997 matches and correctly stayed unresolved because the result cap was reached.
- The run remained `partial / incomplete_investigation` at its intentional one-round depth and source caps, published no unsupported finding, and generated structurally valid Word and nonempty text reports.
- Both disposable live-hunt directories and the deployment transfer archive were deleted after verification. Operational reports, state, logs, and telemetry were not modified by validation cleanup.

### Scope boundary

This milestone does not yet build the temporal/entity attack-path graph or implement compact-on-finalization retention. Disposable validation data was isolated from operational state; the next reporting/retention milestone will implement the hunt-scoped cleanup policy rather than relying on manual validation cleanup.

## 2026-10-12 — super-hunter correctness foundation

### Defects and stale checks resolved

- Host/network correlation now recognizes normalized top-level host IP evidence while still requiring a shared entity, temporal proximity, and relevant host/network behavior.
- A reasoning configuration with `MIN_REASONING_ROUNDS` greater than `MAX_DEPTH` previously re-entered the exhausted reasoning node until LangGraph raised `GraphRecursionError`. The depth limit is now terminal and has a focused regression test.
- Deterministic runs now stop with `coverage_frontier_exhausted` after the last bounded ATT&CK search rather than reporting a model-unavailable reason when model use was intentionally disabled.
- Integration assertions were updated for the current Arkime-specific cap, compact graph context plus durable SQLite evidence, streaming TShark execution, UTC-normalized date bounds, and the separate checkpoint database.

### Development VM proof

- `doctor` was fully green: all Python dependencies, the pinned Enterprise ATT&CK v19.2 catalog, Ollama `qwen3:8b`, two allowlisted Elasticsearch indexes, Arkime with 19,068 sessions, TShark 4.2.2, three configured PCAPs, and the runtime directories were available.
- The full VM suite passed all 37 tests with no skips.
- A disposable offline investigation completed as `evidence_supported_lead`, generated reopenable Word and text reports, retained three evidence records and one finding in SQLite, and retained one checkpoint.
- The offline validation and deployment-staging directories were removed after verification. No validation hunt reports, state, checkpoints, or JSONL logs were added to the operational runtime directories.

### Scope boundary

This checkpoint proves the existing engine is internally consistent and deployable. It does not yet implement the candidate-first undirected discovery loop, attack-path graph, or automatic post-hunt retention policy described in the super-hunter design.

## 2026-10-11 — ROMULUS 0.4.0 live hunt and 0.4.1 remediation

### Readiness

`doctor` confirmed the configured Ollama model, structured reasoning response, two allowlisted Elasticsearch indexes, Arkime session API, TShark 4.2.2, three allowlisted PCAP files, writable runtime directories, and the pinned Enterprise ATT&CK v19.2 catalog.

### Controlled hunt

- Investigation: `HUNT-E5ED6B713B`
- Mission: broad malicious-actor discovery over the available historical host and network data, with an explicit 2024-11-13 window
- Limit: 600 seconds
- Result: partial / evidence-supported lead
- Calls: 36 of 160
- Analyst reasoning rounds: 4 of 10
- High-priority hypotheses tested: 8 of 9
- Initial retained context: 1,000 host events, 9,751 Arkime sessions, and 1,500 packet records
- TShark matched packets represented by the retained records: 1,035,828
- Finding: one moderate-confidence suspected credential-access lead with cited evidence and benign alternatives
- Termination: runtime resource limit after 617,286 ms

The run did not crash. It generated both Word and text reports and preserved the audit trail. The finding is an investigative lead rather than confirmation of compromise.

### Issues observed

- Some model proposals used schema or field names as literal terms.
- One TShark expression exceeded the adapter limit after the mandatory packet-time expression was appended.
- A deterministic fallback attempted an empty host text query for an unmapped hypothesis.
- Evidence anchors accumulated IP, hostname, and term constraints that could overconstrain a pivot.
- Repeated full-state LangGraph snapshots expanded the SQLite database to 14,622,371,840 bytes.

### 0.4.1 remediation

- Reject schema/field names as terms and reinforce the structured-search prompt.
- Reserve filter length for the packet-time expression and bound TShark text fields.
- Skip hypothesis fallback searches when no mapped selector exists.
- Use one anchor entity family and a ±15-minute evidence window.
- Store all unique evidence once while bounding graph analysis context per source and baseline/pivot phase.
- Move checkpoints to a separate database and retain only the newest resumable checkpoint.
- Rebuild the legacy store only after table-count and integrity verification.

The production-like database was compacted to 286,113,792 bytes while preserving 12,251 unique evidence records, the finding, investigation state, reports, and audit logs. The compactor reclaimed 14,336,258,048 bytes.

### Post-fix checks

- Python compilation and imports succeeded on the Ubuntu deployment.
- Broad ATT&CK seed selection covered common behaviors across the intrusion lifecycle.
- Focused lateral-movement selection emphasized remote services, SMB, RDP, credential use, and adjacent behavior.
- Field-name terms were rejected.
- The representative TShark expression compiled to 164 characters before the time bound.
- Anchor expansion chose IPs without adding a conflicting hostname family.
- A disposable offline graph run completed with a 45,056-byte operational database, a 32,768-byte checkpoint database, one retained checkpoint, and no checkpoint tables in the operational database.
- `doctor` was fully green after deploying 0.4.1.

### Next validation

Run a fresh controlled live hunt to measure whether the corrected query compiler produces fewer rejected or zero-result pivots and whether checkpoint storage stays bounded under several live analyst rounds. Extend runtime only if the audit shows productive hypothesis expansion near the configured ceiling.

## 2026-10-11 — ROMULUS 0.4.2 time-scope and native-query validation

### Live findings

- A timezone-free mission window of `2024-11-13T10:58:00` through `2024-11-13T15:50:49` initially produced zero Elasticsearch and Arkime results because it was interpreted as UTC even though the analyst-facing UI displayed America/New_York time.
- The same attempt exposed an oversized broad TShark filter after the mandatory packet-time clause was appended.
- After adding `MISSION_TIMEZONE=America/New_York`, the shared scope normalized to `2024-11-13T15:58:00.000Z` through `2024-11-13T20:50:49.000Z` for Elasticsearch, Arkime, and TShark.
- The initial model hypothesis call completed with eight structured hypotheses instead of truncating. Elasticsearch immediately returned 500 retained events from 56,613 matches in the corrected window.
- Investigation `HUNT-B81229529A` then stopped with a native Elasticsearch validation helper naming error before executing the six generated search plans. The helper wiring was corrected and the disposable failed hunt was removed after recording the result here.

### Focused post-fix checks

- `doctor` was fully green on the VM for ROMULUS 0.4.2, including the configured IANA mission timezone.
- The broad initial packet expression measured 390 characters before and 472 characters after the time clause, within the adapter's 512-character bound.
- A direct live `qwen3:8b` planning call produced three valid plans: an accepted Elasticsearch Query DSL candidate, a selector-compiled Arkime plan, and an accepted TShark display filter.
- Elasticsearch native DSL validation enforced discovered fields and wrapped the candidate in the normalized mission-time filter.
- Source-native query validation remains a guardrail rather than a fixed search library: the model chooses the query, while code enforces read-only operators, mapped fields, time scope, and execution limits.

### Storage cleanup

Only the completed controlled hunt `HUNT-E5ED6B713B` was retained in operational state. Earlier disposable test investigations, reports, findings events, audit lines, checkpoints, temporary archives, and Python caches were removed. SQLite integrity remained `ok`, with 12,251 evidence records and one finding retained. Runtime storage changed from 275 MB of data, 960 KB of logs, and 137 MB of reports to 30 MB of data, 52 KB of logs, and 740 KB of reports.

### Next validation

Start the next session with one bounded live hunt on 0.4.2. Confirm that model-authored native queries execute or fall back cleanly, inspect zero-result and rejected-query rates, and extend past ten minutes only when the audit shows productive hypothesis expansion near the runtime ceiling.
