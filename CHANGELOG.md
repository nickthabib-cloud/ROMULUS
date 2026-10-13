# Changelog

All notable ROMULUS changes are recorded here. Dates use the project maintainer's local date.

## Unreleased

### Adaptive evidence-grounded stopping

- Replaced duplicated post-analysis/post-reasoning branches with one deterministic router. Critical/high searches retain priority, grounded reasoning runs before lower-value breadth, the last external-call slot remains available for queued telemetry work, and model `continue_investigation` advice cannot override the measured frontier.
- Added a bounded persisted progress ledger for admitted evidence, resolving outcomes, candidate/hypothesis changes, factual graph/path expansion, and closed coverage gaps. Prose churn, duplicate records, raw count changes, and incomplete/capped outcomes do not create progress.
- Raised production emergency defaults to one hour, 40 reasoning rounds, and 500 external calls, with a three-cycle stagnation stop. `MIN_REASONING_ROUNDS` remains environment-compatible but is no longer a routing requirement.
- Added explicit `coverage_closure_reached`, `no_productive_frontier`, runtime, call, and depth stop reporting. Open coverage at stagnation or a safety ceiling remains partial and cannot become a clean-environment conclusion.
- Extended report-gated compact retention with aggregate progress counts and the final stop basis while deleting detailed progress history and baselines alongside other bulky working data.

### Representative bounded telemetry retrieval

- Replaced earliest-only capped retention with source-native representative retrieval: Elasticsearch time strata inside one PIT, Arkime stable rank windows, and deterministic TShark reservoirs over the complete matching stream.
- Added a code-controlled `TIME_SAMPLING_STRATA` policy (default 8, constrained to 2–24) to scheduler task identity. Model output cannot raise, lower, or otherwise replace the active policy.
- Preserved exact matched totals where the source provides them, suppressed duplicate Elasticsearch documents and Arkime sessions across windows, and disclosed unknown totals, malformed timestamps, sparse coverage, and Arkime offset-limit fallbacks.
- Kept every capped search partial and nonresolving. Representative samples improve what reaches analysis context; they do not support a complete-coverage or clean-environment claim.
- Added bounded sampling metadata to exact outcomes and the technical report only. Compact retention keeps aggregate strategies, requested/covered strata, retained counts, and fallback counts while deleting task/query/request bulk.
- Added synthetic early/middle/late, deterministic-repeat, deduplication, malformed-time, offset-limit, scheduler, report-boundary, and compact-retention regressions without embedding holdout identities or attack-specific indicators.
- Final review made the mapped timestamp explicit for unbounded Elasticsearch tasks, backfilled duplicate-suppressed sample slots within a two-times-cap read ceiling, preserved successful strata when another fails, retained bounded per-stratum matched counts, and added a plain-language sampled-coverage limitation to the customer report.

### Unified search scheduling and exact outcomes

- Routed deterministic behavior/indicator discovery, operator-directed work, candidate follow-ups, grounded model proposals, and coverage-frontier work through one persisted scheduler instead of parallel host, network, model, and fallback queues.
- Added stable execution fingerprints that deduplicate only exact source/target/query/window matches, merge all owners and origins, and retain code-derived priority that model output cannot override.
- Added deterministic discovery fairness across healthy host/network telemetry families and fixed investigation tiers that favor required critical/high candidate work before model or breadth work.
- Made task-specific outcomes authoritative for candidate and hypothesis closure. Only complete, uncapped searches with a confirmed matched total resolve work; failed, skipped, partial, timed-out, interrupted, capped, and budget-limited attempts remain visible gaps.
- Preserved the evidence-first rule: an undirected hunt registers and runs deterministic telemetry searches without any model call until a real candidate exists; model proposals may reference only visible evidence/candidate identifiers.
- Added conservative resume migration for legacy partial hunts and one-retry recovery for interrupted read-only searches, including explicit possible-duplicate disclosure.
- Added a bounded unified-scheduler appendix to the technical text report while keeping scheduler internals out of the customer Word report and raw query bodies out of both.
- Extended compact retention with scheduler counts by origin/source/status, duplicate merges avoided, unresolved-task count, and source-fairness gaps while deleting full task, queue, outcome, query, and scheduler-history bulk after verified final reporting.
- Removed the obsolete direct model-search, host-pivot, network-pivot, coverage-fallback, legacy follow-up, and related dead helper paths. New hunts no longer initialize the former lead queue, reasoning-complete flag, or model-only fingerprint list.
- Added deterministic Elasticsearch network-index discovery so a healthy network index receives a real discovery task even when Arkime and PCAP are unavailable; host discovery is constrained to effective host targets.
- Canonicalized fingerprints to the actual source, targets, query, and fixed bounds, so source-family classification and prose-only scope labels cannot defeat exact-execution deduplication.
- Persisted one absolute mission window across discovery, investigation, resume, and repeated registration so rolling `now-*` scopes cannot generate duplicate tasks as the clock advances.
- Made legacy migration conservative: pending catalog work becomes queued scheduler work, and old attempts without explicit matched-total/cap/timeout/shard completeness remain nonresolving.
- Classified Elasticsearch indices consistently from their mappings across inventory, discovery, follow-up compilation, evidence routing, coverage closure, and reporting; network-only deployments no longer claim host coverage merely because an index name lacks `network`.
- Removed optional pre-telemetry model hypothesis generation. Directed missions start from deterministic operator-constrained ATT&CK hypotheses, while all model reasoning waits for telemetry and yields to already queued deterministic work.
- Preserved host/network source-health state across LangGraph node and checkpoint boundaries so incomplete searches cannot be falsely closed as unavailable-telemetry gaps.
- Synchronized the TShark execution-field allowlist with the planner contract for the valid `tcp.port` and `udp.port` fields, restoring a green deployment diagnostic and preventing valid planned packet fields from being rejected at execution.
- Made generic network follow-ups query Arkime first and use configured PCAPs only when Arkime is unavailable; explicit TShark proposals still target every approved capture.
- Enforced the intended graph-level order of critical/high deterministic candidate work, then evidence-grounded model reasoning, then model/coverage/medium-low breadth while reserving the final external-call slot for queued source work.
- Removed model-authored hypothesis creation from iterative reasoning. Broad hunts now receive hypotheses only from deterministic telemetry candidates, while focused hunts receive deterministic operator-directed hypotheses; the model can assess and test those hypotheses but cannot invent another one.
- Hardened model assessment and finding admission after a holdout-blind live run exposed citation cross-contamination and an unsupported ATT&CK label. Supported assessments must share a deterministic candidate entity, model findings must name an already supported hypothesis, use that hypothesis's mapping (or remain unmapped), and retain at least two cited records that each contain the claimed IP set.
- Replaced model-authored finding titles, observations, confidence justifications, benign alternatives, and follow-up text with deterministic hypothesis/evidence-derived text at publication, and reject malformed IPv4-like text before it can become a scheduled search intent.
- Canonicalized fixed time bounds to UTC for execution identity, rejected invalid or half-bounded windows, compiled pending legacy leads into executable source queries, propagated prior terminal outcomes to late duplicate owners, and gave every unrun task an explicit report-time budget outcome without a source call.
- Local verification runs 133 tests with six dependency-gated checks reserved for the development VM; exact commit `3ded319` passed all 133 tests without skips on the VM, plus compilation and fully green deployment diagnostics. Its corrected isolated live hunt exercised 49 unique scheduled searches across both telemetry families, tested every high-priority candidate before model reasoning, published no unsupported finding, and compacted 5,667 evidence rows to 28 while preserving reports and aggregate coverage.
- Post-hunt comparison against the isolated external oracle found zero supported attack-stage matches. Result caps had concentrated retained analysis context near 16:04 UTC even though the observable attack occurred around 19:17–20:37 UTC. This remains a material full-window sampling limitation: conservative no-finding behavior is working, but broad-window recall is not yet acceptable. No selector, prompt, catalog, fixture, or priority rule was tuned against that holdout.

### Cited attack paths and safe finalization

- Added a deterministic evidence/entity/activity graph and finding-specific attack paths that include only cited evidence, preserve disconnected segments, and label shared-entity/time relationships as inference rather than causation.
- Added supported attack paths, evidence citations, relationship reasons, caveats, and gaps to the technical report, with a concise supported-path section in the customer Word report.
- Added `compact` (default) and `full` retention policies. Compact retention verifies and reopens a matching DOCX/TXT report pair before keeping conclusions, findings, cited evidence, compact graph/coverage, and source errors while removing uncited evidence, hunt-scoped JSONL records, and checkpoints.
- Kept partial hunts resumable by default and added explicit `compact --id` and `finalize --id` commands. Finalized hunts cannot be resumed or relabeled after irreversible compaction.
- Serialized hunt-scoped JSONL append/rewrite operations to prevent concurrent cleanup from discarding another hunt's event, and made incomplete cleanup visible through a warning and distinct CLI exit status.
- Rejected structured ECS containers as entity values so only usable leaf host, address, account, process, service, and task identities enter the investigation graph.
- Revalidated the corrected VM with 86 passing tests, a completed disposable hunt proving three-step cited-path compaction, and a bounded live undirected hunt proving deterministic candidates precede the only model reasoning stage.

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
- Fixed mission classification so broad phrases such as `host and network telemetry` cannot be misread as concrete entity selectors and trigger model hypotheses before deterministic discovery; typed validation still recognizes concrete alphabetic and structured targets.

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
