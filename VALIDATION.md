# Validation record

This file records engineering validation performed against the development deployment. It is evidence of observed behavior, not an operational authorization or a claim that the environment is clean.

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
