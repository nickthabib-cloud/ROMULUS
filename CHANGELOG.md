# Changelog

All notable ROMULUS changes are recorded here. Dates use the project maintainer's local date.

## 0.4.4 — 2026-10-12

### Customer Word report

- Replaced the technical Word dump with a concise, styled customer report focused on the assessment, findings, scope, ATT&CK context, confidence, and recommended actions.
- Kept internal reasoning, tool runs, search artifacts, raw evidence listings, and the full candidate working list in the plain-text technical report.
- Added report-boundary tests that prevent technical-only material and low-priority candidates from leaking back into the customer Word report.

## 0.4.3 — 2026-10-12

### Behavioral hunt seed catalog

- Added 55 cross-platform and platform-specific behavioral analytics to guide initial hunting across endpoint, authentication, DNS, and network telemetry.
- Added exact trusted-indicator matching, candidate prioritization, corroboration, and separate customer-facing and technical lead lists.
- Validate catalog ATT&CK references against the pinned offline Enterprise catalog and fail closed when required query predicates cannot be compiled safely.
- Documented how to extend and maintain the behavioral analytics and trusted-indicator catalogs.

## 0.4.2 — 2026-10-11

### Time-scope and model-output reliability

- Added `MISSION_TIMEZONE` so timestamps without an explicit offset are interpreted in the analyst display timezone and normalized consistently for Elasticsearch, Arkime, and TShark.
- Added deployment diagnostics for the configured IANA timezone and made reported scope disclose how timezone-free values were interpreted.
- Bounded the broad initial TShark filter before the mandatory packet-time clause is appended, preventing valid broad hunts from exceeding the adapter grammar limit.
- Reduced the maximum initial model hypothesis batch to eight and increased its structured output allowance, avoiding the truncation observed with the local `qwen3:8b` model while deterministic ATT&CK seeds continue to supply broad coverage.
- Added model-authored Elasticsearch Query DSL, Arkime expression, and TShark display-filter candidates. Each candidate is checked against a bounded read-only grammar and the discovered source fields; the mission time range is still enforced by code and rejected candidates fall back to structured selector compilation.
- Fixed the native Elasticsearch validation helper wiring error found by the first 0.4.2 live validation attempt.

## 0.4.1 — 2026-10-11

### Controlled hunt validation

- Ran broad historical hunt `HUNT-E5ED6B713B` against the configured host and network sources with a 600-second ceiling.
- Completed four analyst reasoning rounds and 36 audited external calls without a workflow crash.
- Retained one moderate-confidence, evidence-cited credential-access lead while preserving benign alternatives and partial-coverage language.
- Confirmed initial retrieval of 1,000 host events, 9,751 Arkime sessions, and 1,500 retained packets representing 1,035,828 TShark matches.
- The run stopped at the runtime limit with 8 of 9 high-priority hypotheses tested; a longer hunt was deferred until the query and storage issues observed during this run were fixed.

### Storage and query controls

- Separated LangGraph checkpoints into `data/checkpoints.sqlite3` and prune checkpoint history after every node while retaining the newest resumable state.
- Bounded graph analysis context by source and baseline/pivot phase while preserving every unique evidence record in the durable evidence table.
- Added `scripts/compact_store.py` to remove legacy checkpoint history and normalize retained context after verifying record counts and SQLite integrity.
- Rejected model search terms that are source field names or schema labels, strengthened the model prompt, and prevented empty fallback host queries.
- Reduced generated TShark filter size so the enforced packet-time expression stays within the adapter grammar limit.
- Changed evidence anchor expansion to choose one entity family and widened evidence-centered correlation searches from ±5 to ±15 minutes.
- Corrected the curated Enterprise ATT&CK v19.2 release date to 2026-08-05 and made `doctor` verify the pinned catalog hash and counts.

## 0.4.0 — 2026-10-11

### Investigation reasoning

- Replaced a narrow fixed-search workflow with a persistent hypothesis, assessment, pivot, and coverage loop.
- Added structured Ollama hypothesis generation, initial search planning, iterative evidence assessment, new hypotheses, and cited candidate findings.
- Added deterministic coverage scheduling so each reasoning round reserves capacity for an untested ATT&CK-backed analytic while retaining model-directed searches.
- Added a pinned offline catalog generated from the official Enterprise ATT&CK v19.2 STIX bundle, containing 697 active techniques/sub-techniques, 697 Detection Strategy links, and 1,745 platform Analytic links.
- Added bounded mission-relevant and tactic-diverse catalog selection while retaining a curated 39-technique query-enrichment layer with search selectors and benign alternatives.
- Fixed iterative reasoning failures caused by a missing regular-expression import.
- Required initial model searches to cover the mission time scope; evidence-anchored windows are reserved for later pivots.

### Telemetry and analytics

- Added bounded Elasticsearch PIT and `search_after` pagination with exact totals, stable ordering, timeout and shard-failure metadata, and fallback behavior.
- Added stable Arkime pagination, overlap-aware time handling, richer session fields, safe session identifiers, and duplicate suppression.
- Changed TShark scanning to drain the complete filtered capture under a timeout and retain a bounded number of matches. This prevents an early packet-read limit from hiding later matches.
- Added behavioral summaries for authentication sequences, fan-out, low-frequency external destinations, cadence, byte outliers, entity distributions, and telemetry quality.
- Limited tool-name behavioral signals to command and artifact context so software feature strings and search expressions do not masquerade as execution.
- Added stable evidence identities and duplicate suppression for Elasticsearch documents, Arkime sessions, and PCAP frames.
- Added typed host/network correlation with direction, scores, reasons, and NAT/DHCP/clock-skew caveats.

### Reliability and reporting

- Fixed equal-timestamp packet sorting that could raise a dictionary comparison error during behavioral analytics.
- Fixed workflow error handling so reports preserve the latest persisted call counts, hypotheses, coverage, and reasoning depth.
- Added SQLite WAL mode and busy timeouts.
- Added bounded reports with hypothesis coverage, behavioral analytics, search artifacts, cited evidence, and explicit partial-coverage language.
- Expanded `doctor` to validate the model, iterative reasoning schema, source connectivity, PCAP allowlists, planner/adapter contracts, and writable runtime paths.

### Deployment verification

- Deployed version 0.4.0 to `/home/user/ROMULUS` on the development VM.
- Confirmed Ollama `qwen3:8b`, two allowlisted Elasticsearch indexes, Arkime, TShark 4.2.2, and three configured PCAP files.
- Confirmed a 600-second hunt ceiling and matching local/VM source checksums.
- Recovered failed hunt `HUNT-0EB88B77AE` from its LangGraph checkpoint and regenerated accurate partial reports without resuming searches.

### Known limitations

- Official catalog updates are an explicit maintainer operation; automatic release discovery and schema validation beyond the importer checks remain planned.
- The current `qwen3:8b` deployment produced useful iterative assessments but sometimes proposed vague or overconstrained selectors; compiler validation now rejects the observed failure classes, and another controlled hunt is needed to measure the improvement.
- Elasticsearch rarity and historical baseline analytics currently operate mainly on bounded retrieved evidence; source-side aggregations remain planned.
- Arkime field discovery and session-to-PCAP escalation need further deployment-specific work.
- The project is an evaluation build and has not completed an operational authorization or adversarial validation program.
