# Changelog

All notable ROMULUS changes are recorded here. Dates use the project maintainer's local date.

## Unreleased

### Cited attack paths and safe finalization

- Added a deterministic evidence/entity/activity graph and finding-specific attack paths that include only cited evidence, preserve disconnected segments, and label shared-entity/time relationships as inference rather than causation.
- Added supported attack paths, evidence citations, relationship reasons, caveats, and gaps to the technical report, with a concise supported-path section in the customer Word report.
- Added `compact` (default) and `full` retention policies. Compact retention verifies and reopens a matching DOCX/TXT report pair before keeping conclusions, findings, cited evidence, compact graph/coverage, and source errors while removing uncited evidence, hunt-scoped JSONL records, and checkpoints.
- Kept partial hunts resumable by default and added explicit `compact --id` and `finalize --id` commands. Finalized hunts cannot be resumed or relabeled after irreversible compaction.
- Serialized hunt-scoped JSONL append/rewrite operations to prevent concurrent cleanup from discarding another hunt's event, and made incomplete cleanup visible through a warning and distinct CLI exit status.
- Rejected structured ECS containers as entity values so only usable leaf host, address, account, process, service, and task identities enter the investigation graph.

### Candidate-driven investigation loop

- Made broad, undirected missions start with deterministic host/network discovery and explicitly prohibited pre-telemetry model hypothesis generation; focused missions retain initial hypotheses with an `operator_direction` basis.
- Added deterministic candidate-backed hypotheses with stable candidate and evidence citations, and blocked model reasoning entirely when an undirected hunt has no candidate.
- Completed all 13 aggregate catalog generators, including privileged-logon/execution, authentication fan-out, remote-service/execution, DNS entropy and NXDOMAIN bursts, protocol/port mismatch, outbound-volume outliers, rare process/destination pairs, and staging followed by transfer.
- Added persistent candidate dispositions and structured follow-up histories that survive analysis rounds, plus candidate IDs in bounded model context with deterministic citation validation.
- Made coverage closure candidate-aware: actionable candidates, incomplete required follow-ups, unlinked corroboration, and unresolved leads without documented telemetry gaps prevent clean completion.
- Preserved mission mode explicitly in the LangGraph state schema so the undirected-hunt guard survives node/checkpoint boundaries, and made candidate-grounded reasoning tolerate a deferred initial-plan status.
- Hardened legacy, offline, and resumed hunts so a missing mission mode fails closed to undirected discovery for generic objectives, and prevented search-artifact IDs from grounding model hypotheses or assessments.
- Bound candidate pivots to their cited evidence, observed entities, and ±15-minute evidence window; a follow-up closes only after every bound search succeeds, while failed, skipped, partial, or capped searches remain open.
- Tightened authentication and remote-execution correlations with bounded time, identity, prevalence, and initiator checks, while retaining every supporting evidence ID in aggregate candidates.
- Required every planned high-priority analytic to resolve and have an evidence-cited assessment (or an explicit unavailable-source gap) before hypothesis closure; merely attempting a query no longer counts as resolution.

### Super-hunter correctness foundation

- Generalized host/network correlation so normalized host evidence that exposes a top-level `ip` can correlate with network source and destination roles when time and behavior also agree.
- Prevented the reasoning router from re-entering an exhausted depth budget when the configured minimum reasoning rounds exceed the maximum depth.
- Made deterministic-only runs report `coverage_frontier_exhausted` instead of incorrectly blaming an unavailable model.
- Reconciled integration tests with the current Arkime-specific result cap, compact in-memory evidence model, streaming TShark adapter, normalized mission time bounds, and dedicated checkpoint database.
- Recorded the evidence-basis contract for the next investigation-loop milestone: undirected hunts begin with deterministic discovery, and model hypotheses, leads, and findings must cite visible evidence or deterministic candidates.
- Revalidated the development VM with 37 passing tests, fully green deployment diagnostics, and a disposable offline hunt whose Word and text reports were reopened successfully before all test artifacts were removed.

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
