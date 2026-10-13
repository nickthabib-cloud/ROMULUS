# Validation record

This file records engineering validation performed against the development deployment. It is evidence of observed behavior, not an operational authorization or a claim that the environment is clean.

## 2026-10-13 — evidence-scoped attack discovery promotion (local proof; live validation pending)

### Implemented behavior

- Candidate-owned Arkime and TShark follow-ups now require one validated primary IP or hostname together with the applicable bounded protocol/port behavior. Missing candidate entities fail closed; coverage-only work may retain a behavior-only selector.
- Behavior candidates no longer receive an asset-wide "independent behavior" bonus. Corroboration requires distinct analytic groups, distinct cited evidence records, a shared typed structured entity, parseable timestamps within 1,800 seconds, and an explicit non-causality caveat. Bonuses are idempotent and capped at twenty points; score or relationship changes do not publish findings.
- Hypothesis creation uses a deterministic diverse frontier: no more than two candidates per analytic group in one pass, up to two cited sub-threshold exploration candidates, and protected precedence for trusted indicators and critical candidates. Represented candidates are filtered before later passes, so excluded work remains eligible instead of being discarded.
- Reasoning case files prefer candidates owned by unresolved hypotheses. Each visible candidate exposes at most six deterministically selected owned records plus its full `evidence_total`; hidden owned records do not become valid model citations. Visible relationship records are limited to selected candidates and evidence.
- Aggregate candidate observation bounds are derived from their cited source evidence. Runtime logic and tests contain no evaluated-dataset identity, tool, command, timestamp, attack sequence, or oracle label.

### RED/GREEN and local proof

- Query-scope regressions first showed that candidate pivots omitted their entity and could become protocol-wide. Relationship regressions then showed the missing triage boundary, empty aggregate timestamps, and same-record/same-asset self-corroboration. Frontier regressions reproduced scan-group crowding, one-pass candidate exhaustion, preferred-work loss, critical displacement by exploration, and oversized candidate disappearance.
- A generic end-to-end fixture used eight unrelated scanner sources, a distinct high-entropy DNS observation, and a separate host-execution observation. Thirty-four records produced ten deterministic candidates. The first hypothesis frontier included the distinct DNS behavior, admitted no more than two scan candidates, recorded the DNS/host relationship with its two source evidence IDs, compiled the scan candidate's Arkime task with its primary IP plus TCP/UDP behavior, and published no finding merely from score or association.
- The integration proof passed immediately after the three component slices were wired. Its assertions are still pre-milestone regressions: the original implementation lacked relationships and entity-scoped pivots and allowed repetitive scan candidates to crowd the DNS behavior from the first frontier.
- The complete local suite passed all 255 tests with seven expected dependency-gated skips. `python -m compileall -q romulus tests` and `git diff --check` passed.

### Scope boundary

This local proof establishes deterministic candidate promotion and bounded reasoning visibility, not full attack-path recall. Dependency-complete VM execution, configured diagnostics, whole-branch review, and one bounded oracle-blind live hunt remain required before claiming operational improvement. Identity continuity across NAT/VPN leases and richer process/session lineage remain later work unless live evidence shows they are required for this slice.

## 2026-10-13 — evidence-grounded reasoning contract hardening (no new hunt)

### Implemented behavior

- The model no longer authors bookkeeping IDs. ROMULUS assigns stable, globally unique proposal IDs only after a complete structured response parses, then resolves bounded `NEW-HYPOTHESIS-N` references before independent critic review and deterministic admission.
- Ollama structured responses are assembled from NDJSON streaming so the read timeout detects a stalled connection rather than rejecting active inference. Malformed events, premature EOF, data after terminal completion, provider length stops, and incomplete JSON all fail closed.
- The investigator retains up to three new hypotheses and three searches per pass while using tighter field and array limits and a conservative estimated schema envelope below 18,000 characters. An empty proposal set no longer spends a critic call.
- Citation, evidence ownership, causal-language, finding, critic-coverage, and atomic-admission gates were not relaxed. No Russell Mitchell entity, indicator, attack step, oracle timestamp, or attack-specific rule was added.

### Review and local proof

- RED/GREEN coverage proves deterministic ID assignment, new-hypothesis/search linkage through actual admission, complete valid responses beyond the former 24,000-character slice, NDJSON assembly, explicit provider completion, malformed and truncated failure modes, the schema-size envelope, and empty-proposal accounting.
- Fresh review first exposed unresolved positional hypothesis references and later exposed acceptance of EOF without `done:true`; both were reproduced with failing regressions before correction. Final whole-diff re-review found no remaining Critical or Important issue.
- The complete local suite passed all 237 tests with seven expected dependency-gated skips. Python `compileall` and `git diff --check` passed.

### Exact dependency-complete and configured-model proof

- The first exact candidate, commit `92848dc36a120ab91250c802432f87d739ca3fe4`, matched its VM archive digest and passed all 235 then-current tests with no skips, compilation, and configured diagnostics. Its live investigator still timed out on the non-streaming path; a streamed diagnostic then reached the 5,200-token provider cap with incomplete JSON. The observed schema could permit roughly 38,000 serialized characters with one existing hypothesis, establishing output-envelope mismatch rather than context allocation as the root cause.
- Final candidate commit `e1d285ff2690a84ab9f597a57138d0613e1dbd33` was archived with SHA-256 `7588D85F93F3360EC66522D37CB9430C2D05ABE97E95F285A2150A764FF0DBEF`, which matched locally and on the VM. A fresh shell passed all 237 dependency-complete tests with no skips and passed `compileall`. One earlier test invocation inherited deployment environment variables and was discarded as contaminated rather than counted as proof.
- Configured `doctor` was fully green for `qwen3:8b`, one allowlisted Elasticsearch index, Arkime with 919,300 sessions, TShark, all 13 configured captures, and isolated writable runtime directories.
- A generic synthetic production-adapter probe, with no hunt and no oracle facts, completed the investigator in 75.26 seconds and critic in 24.29 seconds. It returned one assessment, one new hypothesis, two searches, and one finding. All five assigned IDs were present and unique, and critic coverage exactly matched them. Deterministic admission accepted the assessment and two searches while rejecting the unsupported hypothesis and finding, demonstrating the intended hallucination-resistant boundary.

### Scope boundary

This milestone proves the investigator/critic transport and structured admission contract, not attack discovery. No hunt was launched and no telemetry was modified. Generic candidate promotion, cross-source correlation, and temporal attack-path construction remain the next milestone.

## 2026-10-13 — retrieval contract hardening (local/VM proof; no new hunt)

### Implemented behavior

- Elasticsearch mappings can belong to both host and network telemetry families when their fields support both roles. Timestamp and index availability are preserved independently for each family; an explicit mission window still fails closed when no supported timestamp is mapped.
- Each record from a dual-family index is admitted exactly once. Network modules/categories retain network precedence, endpoint and authentication semantics route to host, and sparse host event context is preserved without converting source/destination firewall schemas into host telemetry.
- `doctor` and the TShark runtime now use one canonical path validator. It requires an existing regular file inside a configured directory and accepts canonical `.pcap`/`.pcapng` names plus numeric generated suffixes such as `.pcap.1642684647`; arbitrary extensions and paths outside the allowlist remain rejected.
- The implementation and tests contain no Russell Mitchell indicator, entity, attack step, tool, technique sequence, or oracle timestamp. The live dataset was used only to verify the generic source contract after blind evaluation.

### Review and local proof

- Focused RED/GREEN regressions cover mixed mapping membership, timestamp propagation, discovery registration, exact document routing, authentication records with and without categories, sparse Windows event-code records, explicit network-category precedence, firewall-only mappings, missing-timestamp failure, capture-name boundaries, allowlist escape, and diagnostic/runtime parity.
- Review repeatedly challenged the classification boundary and exposed network-first dual-index routing, authentication compatibility, category-less `system.auth` routing, and explicit network-category precedence. Each material finding received a failing regression before correction. Final re-review found no remaining Critical or Important issue.
- The complete local suite passed all 231 tests with seven expected dependency-gated skips. All 12 retrieval-contract tests, Python `compileall`, and `git diff --check` passed.

### Exact dependency-complete and live source proof

- Initial exact candidate `7b87478e505211cbad2f0a2463b5b22e7bd6a5c9` matched its archive digest on the VM. A first run was invalidated because deployment environment values were loaded before tests. The clean rerun then exposed a real dependency-only live-graph routing regression: a sparse host event mapped to both families but reached network analytics. The responsible routing layer was corrected and reviewed rather than weakening the integration assertion.
- Final runtime commit `4c7dda551c1ddc07faeac352d5d341f9d8ebff55` was archived with SHA-256 `F0DA4EE989950D9F209C69E21A4B33B3CB07F99973F9710D9F7DD94FC47D9228`, which matched locally and on the VM. The exact archive passed all 231 dependency-complete tests with no skips and passed `compileall`.
- Configured diagnostics were fully green for the timezone, dependencies, pinned Enterprise ATT&CK v19.2 catalog, `qwen3:8b` structured reasoning preparation, one allowlisted Elasticsearch index, Arkime with 919,300 sessions, TShark 4.2.2, all 13 configured captures, and isolated writable runtime directories. No secret was displayed and no service configuration changed.
- A separate read-only assertion passed all 13 configured capture paths through the runtime validator. A live mapping assertion found one dual-family index and confirmed a supported timestamp in both host and network field inventories. No hunt was launched and no telemetry was modified.
- The exact VM archives, checkouts, isolated runtimes, and local transfer archives were removed after proof. Only this validation record and the ignored implementation ledger remain.

## 2026-10-13 — blind Russell Mitchell generalization evaluation (partial; no validated attack path)

### Evaluation boundary and exact candidate

- ROMULUS received only a broad undirected hunt objective and the operator-authorized mission window. No attack identity, host, account, domain, product, vulnerability, command, filename, technique, or sequence from the external oracle was supplied to the runtime. The oracle was first consulted after the hunt was finalized and compacted.
- Exact candidate commit `5bdc888b941eb3e568db4e53f20cf3bd6e743ccb` was archived with SHA-256 `031BDFD972FDD80CC0F94F13C91ED18C5FE81EF173DDE84114309C6EFD38892D`; the digest matched locally and on the development VM. Configured read-only diagnostics were green for the model and structured schemas, Elasticsearch, Arkime, TShark, all configured captures, the pinned ATT&CK catalog, timezone, and isolated writable directories.
- Hunt `HUNT-65EE9C609B` ran from the exact isolated candidate with production backstops of 3,600 seconds, 40 analyst rounds, 500 external calls, and three stagnant cycles. It stopped after 1,546,254 ms, 35 calls, and nine rounds as `partial / incomplete_investigation` with `no_productive_frontier`; it did not reach coverage closure.
- The pre-model invariant held: deterministic telemetry produced candidates before any model call. The run created 20 behavior candidates and eight candidate-derived hypotheses. No model proposal, assessment, search, finding, or attack-path edge was admitted.

### Blind result and oracle scoring

- Final customer finding and attack-stage recall was **0/7**. ROMULUS published zero findings and zero supported attack paths, so precision is undefined rather than 100%. It made no unsupported final finding and assigned no incorrect technique to a final finding.
- Candidate-stage recall was **1/7**: a deterministic `T1046 Network Service Discovery` candidate correctly surfaced the attacker IP `192.168.230.122` and its scan/fan-out behavior, but it remained unassessed. The report's raw evidence also contained the distinctive DNS-transfer traffic, so raw-evidence visibility was **2/7** for reconnaissance and DNS exfiltration; that exfiltration was not promoted into a finding or path. A separate early high-entropy-DNS candidate mapped to `T1071.004` was unassessed and was not established as the oracle's exfiltration.
- Entity recall was limited to the attacker IP and nearby network endpoints. The attacker identity, compromised account, web-service account, WordPress foothold, password-cracking activity, reverse shell, and privileged action were not surfaced as hunt conclusions. No attack relationships or temporal stage sequence were constructed, so relationship and reported temporal-ordering recall were zero.
- The report accurately disclosed that the hunt was incomplete, host telemetry was not searched, network retrieval was partial, model reasoning was unavailable, source errors remained, and no conclusion about the absence of suspicious activity was supported. This honest fail-closed result is materially better than a hallucinated chain, but it does not satisfy the threat-hunting objective.

### Responsible-layer diagnosis

- **Retrieval:** host inventory inspected one 695-field mapping but reported no usable timestamp field, registered no executable host discovery task, and returned zero host events. Initial Elasticsearch network retrieval did use timestamped data, so this is a field-role/inventory compatibility defect rather than proof that the dataset lacks time. Eight host follow-ups were consequently finalized as `budget_limited`. Network coverage was also heavily capped: Elasticsearch returned 500 of 154,043 matching events, Arkime discovery returned 20,000 of 610,789, and most Arkime pivots returned 20,000 from much larger totals.
- **Source contract:** diagnostics accepted all 13 configured capture paths, while runtime validation rejected 11 capture names containing suffixes after `.pcap`; only two direct capture names executed. Doctor and runtime therefore disagree about valid configured captures, causing avoidable network loss.
- **Candidate generation and normalization:** the correct attacker scan became a candidate, but readily visible DNS-transfer records were left in raw evidence instead of becoming a correlated exfiltration candidate. The foothold, discovery, credential, shell, and privilege-escalation stages had no usable host retrieval path and were never promoted.
- **Hypothesis reasoning:** all nine grounded-investigator calls failed closed because structured Ollama output was either truncated or violated global proposal-ID requirements. The critic was never called. Deterministic work continued safely, but the reasoning layer contributed no hypothesis refinement, competing explanation, discriminating search, assessment, or finding.
- **Correlation and admission:** no correlation or attack-path edge was built. Admission correctly rejected unusable model output and allowed no unsupported claim through; reporting then truthfully described the partial state. The primary failures are upstream retrieval, candidate promotion, and model-contract robustness, not report honesty.

### Reporting, retention, and cleanup

- Final reports `HUNT-65EE9C609B-20261013T113354Z.docx` and `.txt` reopened successfully. Their SHA-256 digests are `BE29B71D5204A4682F5695BB88E09C56BD9173C97682E4A0AF376CEDB95CA531` and `2ADDC699C104DB5D858A1185FA3AF183945A12F36E6269A2F832837707CF5921`. They contain the hunt identity, exact partial outcome, source/model limitations, scheduler and progress aggregates, and no raw model prompt or query body.
- Compact retention removed all 111,777 working evidence rows, 35 audit rows, the checkpoint, detailed reasoning/model payloads, host/network working arrays, tools, tasks/outcomes, queries, and progress detail. No finding, evidence, checkpoint, or write row remained because no finding had cited support. Only the ignored final report pair was preserved locally, consistent with the operator's request not to retain disposable hunt bulk.
- The exact remote archive, isolated checkout, runtime, hunt log, and diagnostic log plus the local transfer archive were resolved and removed. Operational telemetry and service configuration were not changed.
- Because the oracle has now been consulted, this dataset is a regression corpus for subsequent generic fixes, not a fresh holdout. Any fix must be developed from general behavior with unrelated synthetic variants and benign controls; no oracle-specific indicator or sequence may enter runtime code, prompts, selectors, catalogs, tests, or fixtures.

## 2026-10-13 — evidence-grounded investigator and critic (local/VM proof; holdout remains blind)

### Implemented behavior

- Undirected candidate-free hunts still create no hypothesis and make no model call. Once a telemetry-backed lead exists, ROMULUS builds a bounded case file containing only visible candidates, their owned evidence, factual path context, exact search outcomes, and coverage gaps.
- The investigator and critic are separate structured model calls over the same case. Neither response changes hunt state directly. Deterministic admission requires a known critic decision and validates proposal identifiers, evidence/candidate ownership, entity overlap, ATT&CK ownership, falsifiers and benign alternatives, search anchors, source fields, and query constraints.
- A competing model hypothesis is committed only when an approved discriminating search creates a new scheduler task. Invalid or duplicate searches cannot commit an orphan hypothesis. Model priority fields cannot change scheduler order.
- ROMULUS reserves capacity for both calls before starting the pair. Investigator output is discarded when the critic is unavailable, and deterministic candidate work continues.
- The technical text report records aggregate calls, admissions, rejections, rejection reasons, and availability gaps without raw case files, proposal identifiers, prompts, query bodies, or critic payloads. The customer Word report contains only customer-facing findings and coverage.
- Compact retention preserves `coverage.reasoning_summary` when it exists while removing detailed reasoning history and all case/investigator/critic working payloads. Legacy and offline state without a summary remains absent rather than inventing zero historical calls.

### Exact local and dependency-complete proof

- The complete post-review local suite passed all 219 tests with seven expected dependency-gated skips. Six focused review regressions passed, as did the broader reasoning/admission gates, Python `compileall`, and `git diff --check`.
- Fresh whole-branch review found no Critical issues and four Important admission/atomicity gaps: cross-candidate evidence borrowing, anchorless directed support, mapped hypotheses publishing unmapped findings, and partially committed or stale reasoning state after failure. One permitted RED-to-GREEN fix pass corrected all four in commit `2c42c0d44f08e40a52c9bea435cfe307816eb243`. A Minor aggregate-report issue remains deferred: a later successful reasoning call can clear `last_gap`, so `unavailable_passes` may be nonzero while the final availability-gap list is empty.
- Exact candidate commit `2c42c0d44f08e40a52c9bea435cfe307816eb243` was archived with SHA-256 `EA2D19203F8DA51B791F4769155265C6D9BF406467BA4F73E25FDC10E322B87E`; the digest matched on Windows and the development VM.
- The exact archive passed all 219 dependency-complete VM tests with no skips and passed `compileall`.
- An initial diagnostic invocation lacked the deployment `.env` and failed closed on unavailable credentials. After loading the existing deployment configuration without copying or displaying it, diagnostics were fully green: America/New_York mission time, all Python dependencies, the pinned Enterprise ATT&CK v19.2 catalog, `qwen3:8b` plus both structured reasoning schemas, one allowlisted Elasticsearch index, Arkime with 919,300 sessions, TShark 4.2.2, all configured Russell Mitchell captures, and writable runtime directories. No service configuration was changed.

### Disposable compact-retention proof

- Synthetic offline investigation `HUNT-A7A9450BFA` completed as `evidence_supported_lead` with `coverage_closure_reached`, generated one DOCX and one TXT report, and compacted successfully in an isolated `/tmp` runtime from the exact final candidate.
- Both reports reopened successfully. The technical report contained `INVESTIGATOR AND CRITIC COVERAGE` and truthfully stated that the offline run had no grounded investigator/critic aggregate; compact state likewise omitted `reasoning_summary` rather than inventing prior calls. Populated-summary preservation and customer/technical audience separation passed in the dependency-complete report/retention tests.
- Compact state retained two cited evidence records and one finding. It removed `reasoning_history`, host/network arrays, tool runs, search tasks/outcomes, queries, case/proposal/critic payloads, and every checkpoint/write row.
- The validation archive, extracted checkout, and synthetic runtime were isolated from operational state and removed after proof. Operational reports, hunt state, logs, and telemetry were not modified by the synthetic hunt or cleanup.

### Blind-evaluation boundary and limitation

- No Russell Mitchell holdout identity, indicator, hostname, command, tool, timestamp, attack step, or oracle label was added to runtime code, prompts, catalogs, tests, or fixtures. Diagnostics verified source availability only; this milestone did not execute a hunt against the newly loaded telemetry.
- The synthetic offline fixture cannot evaluate live model judgment or recall against a real attack. This milestone proves bounded reasoning, fail-closed admission, reporting, and retention mechanics. The authorized read-only Russell Mitchell hunt remains the next blind Milestone 9 evaluation, after branch review and integration.

## 2026-10-13 — adaptive evidence-grounded stopping (local/VM proof; no live holdout hunt)

### Implemented behavior

- Hunt continuation is now controlled by deterministic material progress: new stable evidence, candidate/follow-up transitions, resolving task outcomes, hypothesis changes, graph/path growth, and coverage-gap closure. Model prose, duplicate records, and raw count churn do not count as progress.
- Broad undirected hunts still wait for a telemetry-backed candidate before creating a hypothesis or invoking model reasoning. Model requests to continue are retained only as audit context and cannot override queue, closure, stagnation, or safety decisions.
- High-value queued work runs before stagnation can stop a hunt. Grounded reasoning runs before low-value breadth, while the final available tool call is reserved for already-queued telemetry work.
- Normal hunts stop on validated closure or an exhausted productive frontier. Production defaults are finite emergency backstops rather than validation-era caps: 3,600 seconds, depth 40, and 500 tool calls, with three stagnant cycles by default.
- Technical reports record the exact progress stop basis, productive/stagnant aggregate counts, and safety backstops. Customer reports use plain language and omit progress-ledger internals.
- Compact retention keeps reports, cited evidence, findings, and the aggregate progress summary while removing detailed progress history and bulky host, network, query, task, tool-run, and checkpoint working state.
- The detailed progress ledger remains bounded to 100 entries, but separate cumulative totals preserve full-hunt counts. Resumed legacy state is migrated and interrupted work is recovered before the progress baseline is established.
- Coverage closure is shared by routing and reporting. It requires an actual assessed hypothesis or candidate and is blocked by source/model failures, missing live source families, incomplete/capped coverage, scheduler gaps, or an incomplete stop reason. LangGraph recursion capacity scales with configured tool/depth ceilings.

### Local and dependency-complete proof

- The complete local suite passed all 188 tests with seven expected dependency-gated skips. Python `compileall` and `git diff --check` passed.
- Dependency-complete VM execution exposed that LangGraph conditional-edge callbacks selected the correct route but did not merge the callback's termination-reason mutation into graph state. The decision is now persisted by the preceding analysis/reasoning node; a focused regression covers the state boundary.
- The same VM run exposed two stale dependency-only assertions that still expected legacy exhaustion labels. They now assert `coverage_closure_reached` for validated closure and `no_productive_frontier` for an open exhausted frontier.
- Final whole-branch review found five additional correctness gaps: final reasoning used stale coverage, graph recursion had a hidden 100-step ceiling, resume established its baseline before migration/recovery, report closure could contradict routing closure, and aggregate totals were derived from the truncated detail ring. The single review-fix pass corrected each responsible layer and added focused regressions. It also prevented an empty directed frontier from becoming vacuous coverage closure.
- Exact candidate commit `1bc238da95c847ddd32cc5729d9b4bac267ef324` was archived with SHA-256 `19BFBA9BBB68397F0EA4BA7E0BEBE921EE57658FE62D915E815A5E7904DE3C26`, which matched locally and on the VM. All 188 dependency-complete tests passed with no skips, including the real graph execution beyond 100 steps; `compileall` succeeded.
- Deployment diagnostics were fully green for the configured model, structured reasoning schema, Elasticsearch, Arkime, TShark, pinned ATT&CK catalog, configured captures, and writable operational directories. Diagnostics were read-only.

### Disposable retention proof

- Offline investigation `HUNT-E6BCEC25C1` completed as `evidence_supported_lead` with `coverage_closure_reached`, generated Word and text reports, and reopened both reports successfully.
- The technical report contained the progress stop basis and safety-backstop record. The retained aggregate recorded two productive cycles, zero stagnant cycles, and the final closure basis.
- Compact retention completed after report verification. It retained two cited evidence records from three working records and one finding, while removing host/network arrays, tool runs, search tasks/outcomes, detailed progress history/baseline/totals, queries, one uncited evidence record, two finding events, two checkpoints, and 46 graph writes.
- Validation used only the synthetic offline fixture in an isolated `/tmp` runtime. It did not execute a live hunt against the holdout telemetry and did not modify operational state, reports, logs, or telemetry.
- The exact VM checkout, disposable runtime, transfer archive, and local transfer archive were removed after proof.

## 2026-10-12 — representative bounded retrieval (local/VM proof; no new live hunt)

### Implemented behavior

- Capped Elasticsearch results are retained across deterministic time strata within one PIT. When a mission window is absent, the adapter derives the matching time extent; inability to do so is explicitly reported as a fallback.
- Capped Arkime results use deterministic ordered rank windows inside one logical scheduler operation. Duplicate session IDs are suppressed, and windows beyond Arkime's accepted offset are reported rather than silently replaced with early rows.
- TShark still scans the complete filtered packet stream and reports the exact match count. Retained rows use deterministic per-time-stratum reservoirs; malformed or unavailable timestamps use a disclosed whole-stream reservoir.
- Sampling policy is code-controlled and part of exact task identity. Bounded outcome metadata reaches the technical report and compact aggregate coverage, while raw queries, rank-window requests, and per-request history do not survive compact retention.
- Capped work remains partial and cannot resolve candidate or hypothesis coverage.

### Validation boundary

- Generic synthetic regressions prove cross-window retention, stable repetition, duplicate suppression, conservative fallbacks, report audience separation, and compact aggregation without importing holdout identities, indicators, commands, tools, hostnames, or timestamps into runtime behavior.
- The initial post-review local suite passed all 152 tests available in this environment, with six dependency-backed checks reserved for the development VM. A final candidate review then found four conservative-closure gaps: unequal returned/matched totals could resolve, resumed execution could prefer a changed state sampling policy over the fingerprinted task policy, partial hunts could persist a contradictory closure-ready flag, and conservative fallback retrieval could be called representative in the customer report. Each received a focused failing regression before correction. The complete local suite now passes all 159 tests, with the same six dependency-backed checks reserved for the development VM.
- Whole-branch review found that unbounded scheduled Elasticsearch calls did not pass their mapped timestamp explicitly, duplicate suppression could leave unused sample slots, and one failed Elasticsearch stratum discarded successful strata. Failing regressions reproduced all three conditions. The corrected adapters backfill only within a bounded two-times-cap read ceiling, retain successful strata with a disclosed failure count, and carry bounded matched/retained per-stratum counts through the technical report. The customer report receives only a plain-language sampled-coverage limitation.
- Final review tightened completion semantics across scheduler, analytics, and compact summaries: a task resolves only when its returned and matched totals are exact and equal, Elasticsearch's total relation is exact, and no cap, timeout, shard failure, or incomplete flag is present. Arkime also revalidates its probe against the retrieval response before declaring an uncapped result exhaustive. Fingerprinted task sampling is authoritative on resume, partial status cannot coexist with coverage closure, and customer wording distinguishes representative stratification from incomplete nonrepresentative fallback retrieval.
- The operator paused another live hunt on the working assumption that the expected attack path was absent. The requested read-only ingestion diagnosis was completed before any further hunt, and the evidence below shows that the raw observable telemetry is already loaded. The ground-truth labels and AttackMate timeline are not loaded, which is the correct blind-evaluation boundary.

### Dependency-complete VM proof

- The exact candidate tree passed all 152 dependency-complete VM tests with no skips and passed `compileall`. `doctor` confirmed the configured model, Elasticsearch, Arkime, TShark, and all three configured PCAPs without exposing credentials or changing service state.
- The VM-only live-graph integration test exposed an incorrect test expectation: its fake Arkime source declared a one-result exhaustive response, but the test asserted that no source outcome could resolve. The assertion now proves the intended split: completeness-unknown host results do not resolve, while a declared exhaustive network result does. This correction changes no runtime behavior.
- Final runtime commit `e6e8668ff367621adad406703bb7e53636fc0c4e` was archived with SHA-256 `B64391078A67D154104CD82912EF23B4022166679FF14D45FC4D9A90E8AF43E3`, which matched locally and on the VM. The exact archive passed all 159 dependency-complete tests with no skips, `compileall`, and fully green deployment diagnostics. Final review reported no remaining Critical or Important issues.
- No new hunt was launched. The existing operational hunt data and telemetry indices were not modified.
- The exact VM checkout, archive, test log, and diagnostic log plus the local transfer archive were removed after proof.

### Read-only ingestion diagnosis

- The source archive contains the raw run, the labeled derivative, and the 53-action oracle. The operational Elasticsearch indices contain 840,850 host events from `2024-11-13T15:57:54.478Z` through `20:51:49Z` and 108,237 network events from `15:59:11.386Z` through `20:49:33.460Z`. The oracle interval, approximately `19:17` through `20:37Z`, is inside both ranges.
- The oracle interval contains 202,092 indexed host records. The target server contributes 148,740 of them: 117,709 audit, 28,771 web access, 1,260 syslog, 907 application, and 93 authentication records.
- The labeled derivative identifies 3,740 malicious audit records, four syslog records, and thirteen authentication records on the target server. All 3,740 audit records matched indexed records by timestamp and audit record type; every labeled syslog and authentication timestamp was also present in the matching indexed source. The live index intentionally contains raw telemetry rather than the `malicious`, description, or MITRE label fields.
- The configured captures span the same source packet ranges. The labeled derivative contains 46,439 malicious packets in the later perimeter capture and 7,622 in the DNS capture; Arkime reports 8,353 sessions overlapping the oracle interval. The source archive's later perimeter PCAP ends with one incomplete packet, but both archive inspection and the configured readable capture report the same 575,045 complete packets and the same start/end times.
- Across the target-host and network labeled telemetry there are 57,878 malicious records covering 31 of the oracle's 32 unique ATT&CK techniques. `T1498` has no labeled telemetry event, so a telemetry-only hunter must not be expected to prove that one action without another source.
- Conclusion: loading the AttackMate or labeled files into the hunt indices would give ROMULUS the answer and invalidate the evaluation. The attack evidence is already present as raw host/network telemetry; the next proof should therefore evaluate retrieval, candidate promotion, correlation, and reporting against the confirmed interval, while keeping the oracle outside the runtime.

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
