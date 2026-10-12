# Validation record

This file records engineering validation performed against the development deployment. It is evidence of observed behavior, not an operational authorization or a claim that the environment is clean.

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

### Development VM proof

- The final deployed archive for commit `48c0631` matched SHA-256 `34c2e981c19c005f4bfbc7b9668ed8ba054accf4ea5e89743a32baeada78546d`.
- Deployment diagnostics remained green for Ollama `qwen3:8b`, two allowlisted Elasticsearch indexes, Arkime with 19,068 sessions, TShark 4.2.2, three configured PCAPs, the pinned ATT&CK catalog, and writable runtime paths.
- The complete VM suite passed all 48 tests with no skips. The local dependency-light suite also passed all available tests; dependency-backed adapter, LangGraph, and Word checks were then exercised on the VM.
- Bounded live investigation `HUNT-2903D1FB0C` used isolated `/tmp` state, a twelve-minute 2024 telemetry window, 35-call/one-round limits, 50-record search caps, a 200-session Arkime cap, and no PCAP scan.
- The live sequence was deterministic discovery first: seven behavior searches and one Arkime search produced 250 retained context records and 20 candidates before any model call. State contained eight hypotheses, all with `observed_candidate` basis. The audit contained exactly one model stage, `analyst_reasoning`; there was no `hypothesis_generation` or `initial_search_planning` call.
- Candidate-grounded reasoning returned two accepted, bounded searches: an Arkime evidence-anchored outbound-connection pivot and an Elasticsearch evidence-anchored process/account pivot. Both executed read-only.
- The hunt correctly remained `partial / incomplete_investigation` at the intentional depth and Arkime result caps. It did not publish a finding or claim the environment clean. Both Word and text reports reopened successfully.

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
