# ROMULUS Super Hunter Investigation Loop Design

**Date:** 2026-10-12
**Status:** Proposed for implementation
**Scope:** Investigation control flow, candidate triage, attack-path reconstruction, reporting, verification, and post-hunt retention

> **Current product-priority clarification (2026-10-15):** Indicator and suspicious-behavior discovery, ranking, and escalation are the primary goals. Correlation enriches those findings and guides pivots. Attack-path reconstruction is optional secondary analysis after the findings and must never gate or delay indicator escalation. The approved indicator-runtime and anomaly-escalation designs supersede any wording below that could imply otherwise.

## Goal

ROMULUS will behave like a coordinated Air Force CPT host analyst, network analyst, and intelligence analyst. It will begin with repeatable host and network discovery, turn unusual observations into shared candidate leads, pursue the strongest leads across sources and time, reconstruct the supported portions of an attacker path, and deliver evidence-cited findings with explicit uncertainty and coverage gaps.

Success means ROMULUS can:

1. Discover unusual host and network behavior without requiring the operator to name a specific TTP.
2. Promote detections into persistent, ranked investigation candidates rather than leaving them as report-only observations.
3. Pivot backward and forward from a lead across hosts, users, processes, sessions, addresses, domains, and time windows.
4. Represent a multi-step attack path with evidence, relationships, competing benign explanations, and missing telemetry.
5. Stop for defensible reasons: candidates are resolved, required follow-ups are impossible, or a recorded resource limit was reached.
6. Produce a concise customer report and a detailed technical report.
7. Remove bulky completed-hunt artifacts while preserving reports and the small amount of structured material needed to understand and defend the findings.

## Non-goals

- ROMULUS will not perform active scanning, containment, endpoint changes, or other disruptive actions.
- The language model will not receive arbitrary shell, Elasticsearch, Arkime, or TShark access.
- ATT&CK coverage will guide planning but will not be treated as a checklist or proof of investigation quality.
- The first implementation will not require an external threat-intelligence service. It will preserve an enrichment interface for later infrastructure, campaign, and reputation sources.
- Existing source-specific safety controls, time bounds, allowlists, and evidence caveats will not be weakened.

## Design Principles

1. **Leads drive work.** A detection that cannot affect search priority, pivots, closure, or findings is not part of the investigation loop.
2. **Evidence and interpretation stay separate.** Facts, inferred relationships, hypotheses, and conclusions have distinct fields and provenance.
3. **Complete-population measurements precede context sampling.** Counts, rarity, fan-out, cadence, and other distribution analytics must use source-side aggregation or streaming summaries over all retrieved matches before raw records are capped for model context.
4. **One scheduler owns every search.** Deterministic seeds, surveys, model plans, and evidence pivots use the same validated `SearchPlan`, fingerprinting, execution history, and budget rules.
5. **Closure is explicit.** Queue exhaustion alone is not completion.
6. **Reports are durable; working bulk is disposable.** Cleanup occurs only after successful report generation and only for a terminal investigation.

## Target Workflow

### 1. Mission and telemetry inventory

ROMULUS validates the mission scope, time interpretation, configured sources, mappings, and source health. It produces a telemetry inventory describing which host, authentication, DNS, flow, packet, and other categories can be searched and which semantic roles are available.

Hypotheses are ordered by mission relevance and telemetry support. Unsupported hypotheses remain visible as coverage gaps but do not consume search calls until another observation makes them actionable.

An operator-directed mission may create initial hypotheses from the behavior, entity, indicator, or question the operator supplied; each such hypothesis records `operator_direction` as its basis. An undirected mission such as a general request to hunt for threats creates only coverage questions and deterministic discovery searches at this stage. It does not ask the model to invent initial hypotheses before telemetry exists.

After discovery begins, every new hypothesis must cite at least one visible evidence ID or a deterministic candidate ID. Every model-proposed lead or finding must cite visible evidence IDs. ROMULUS rejects output whose claimed basis is absent, unknown, or outside the context supplied to the model. Prompt instructions reinforce this rule, but deterministic validation is the enforcement boundary.

### 2. Initial host, network, and intelligence discovery

The logical analyst roles run through one guarded scheduler:

- **Host discovery:** behavior catalog entries, trusted indicators, authentication patterns, process execution, persistence, defense evasion, and host-change telemetry.
- **Network discovery:** Arkime/session behavior, Elasticsearch network events, DNS behavior, fan-out, protocol/port anomalies, cadence, transfer patterns, and selective PCAP escalation.
- **Intelligence context:** pinned ATT&CK knowledge, trusted local indicators, mission context, and a future enrichment interface.

Each detector emits normalized observations and zero or more `CandidateLead` records. Detector execution is recorded even when it returns zero results or cannot run.

### 3. Shared candidate triage

`CandidateLead` becomes the central unit of work. It contains:

- Stable candidate ID, detector/indicator provenance, title, and description.
- Evidence IDs, entities, first/last observed times, and relevant source categories.
- Deterministic priority score and reasons.
- Disposition: `observed`, `investigating`, `corroborated`, `benign_likely`, `dismissed`, or `unresolved`.
- Corroborating facts, contradicting facts, benign explanations, and telemetry-quality caveats.
- Required follow-up intents and the status of each follow-up.
- Links to any investigation-graph nodes and finding produced from the candidate.

Candidate state is persisted and merged across analysis rounds. Re-analysis must not overwrite a prior disposition or completed follow-up history.

### 4. Lead-driven expansion

The scheduler selects the highest-value unresolved candidate while reserving bounded capacity for broader hypothesis coverage. For a selected lead ROMULUS may:

- Search backward for initial access, credential use, staging, or precursor activity.
- Search forward for execution, persistence, lateral movement, command and control, collection, or exfiltration.
- Pivot across host and network sources using one validated entity family at a time.
- Follow process ancestry, account/session relationships, host/address mappings, domains, ports, and network sessions.
- Run searches that distinguish malicious and benign explanations.

The model proposes bounded search intent and assessments. Deterministic code validates fields, source class, syntax, time scope, duplicate fingerprints, evidence references, and budgets before execution.

### 5. Investigation graph

ROMULUS stores a compact graph in investigation state:

- **Evidence nodes:** immutable source records or aggregate measurements.
- **Entity nodes:** host, address, account, process, file, domain, session, service, and task.
- **Activity nodes:** authentication, connection, execution, transfer, modification, and other normalized actions.
- **Edges:** observed relationships such as `executed_on`, `authenticated_to`, `connected_to`, `spawned`, `resolved_to`, `transferred`, `preceded`, and `possibly_related`.

Every edge records evidence IDs, time delta, confidence, reasons, and caveats. Inferred edges remain visibly different from source-observed relationships. Findings reference an ordered or branched path through this graph rather than only a flat evidence list.

### 6. Closure and findings

A high-priority candidate is closed only when it is:

- Corroborated and represented in a finding;
- Downgraded or dismissed with cited evidence and a benign explanation;
- Unresolved because a specifically recorded telemetry gap prevents the required follow-up; or
- Interrupted by a resource limit, making the overall hunt partial.

Coverage closure requires no actionable high-priority candidate and no unexecuted required follow-up. Merely executing one search per hypothesis is insufficient.

A finding contains:

- Plain-language observation and interpretation.
- Ordered attack-path steps with timestamps, entities, and evidence citations.
- ATT&CK context where exact.
- Confidence per important relationship and overall confidence.
- Benign alternatives, contradicting evidence, and missing telemetry.
- Recommended validation, containment, or collection actions for a human analyst.

## Unified Search Scheduling

All initial and iterative searches use one `SearchPlan` representation with:

- Source and source class.
- Hypothesis and candidate IDs.
- Intent, selectors, optional native query, mission or anchor time window, and priority.
- Origin: catalog, indicator, survey, model, or evidence pivot.
- Stable fingerprint and execution status.
- Returned count, matched total, cap/timeout/error information, and search artifact ID.

This eliminates duplicate execution layers and gives later reasoning a complete summary of what has already been attempted. Behavioral seed searches and initial surveys are no longer invisible to the iterative planner.

## Removal of Special-case Finding Logic

The hardcoded SMB and command-line tooling publishers will be migrated into generic candidate corroboration and finding-promotion policies. Scenario-specific behavior belongs in the versioned behavior catalog or a small, testable promotion-rule layer, not in the central workflow engine.

The large workflow module will be split incrementally as behavior moves behind stable interfaces. Expected boundaries are:

- Telemetry collection and normalization.
- Search scheduling and execution.
- Candidate triage.
- Investigation graph construction.
- Reasoning and closure.
- Finding construction and reporting.
- Retention/finalization.

No standalone refactor will be performed without a behavioral test proving the boundary.

## Post-hunt Retention

The default policy will be `compact`, configurable through an environment setting and a CLI override.

### Compact policy

After a terminal hunt successfully generates both reports, ROMULUS keeps:

- The `.docx` customer report and `.txt` technical report.
- A compact investigation manifest containing identity, objective, timestamps, outcome, termination reason, coverage summary, report paths, and finding metadata.
- Structured findings and only the cited evidence needed to understand those findings and customer-visible candidates.
- Small count/hash metadata proving what was removed.

ROMULUS removes for that hunt:

- Uncited raw evidence rows.
- Bulky host/network arrays from serialized investigation state.
- Per-node checkpoint history and the final resumable checkpoint.
- Detailed model reasoning payloads and completed search/tool-run bulk already represented in the technical report.
- Per-hunt audit and finding-event JSONL records after their final summaries have been written to the technical report and manifest.

Cleanup is hunt-ID scoped, idempotent, and occurs only after report files exist and can be reopened. Database changes occur in a transaction. Shared JSONL files are rewritten through a temporary file and atomic replacement. A cleanup failure marks retention incomplete but does not delete reports or change the investigation conclusion.

### Full policy

`full` retains the current durable evidence, state, audit, event, and checkpoint behavior for development, adversarial validation, or cases requiring complete forensic retention.

### Partial and failed hunts

A partial hunt remains resumable and is not compacted automatically. The operator may resume it or explicitly finalize it, which generates the final reports and applies the selected retention policy. A hunt whose report generation failed is never compacted.

Existing completed hunts are not silently rewritten. A deliberate `compact --id HUNT-...` command will apply the new policy to an older hunt after the same report checks.

## Persistence and Migration

New state fields and database objects are additive. Loaders tolerate older investigations that lack candidates, graph state, retention metadata, or unified search plans. Existing evidence IDs and report paths remain valid.

The implementation will not place credentials, source secrets, or SSH information in state, logs, reports, fixtures, or documentation.

## Testing and Validation

### Local tests

- Restore a green test baseline for correlation, time windows, TShark process mocking, and the Ollama interface.
- Add unit tests for all aggregate catalog signals so no enabled rule is unreachable.
- Add persistence tests proving candidates retain disposition and follow-up history across rounds and resumes.
- Add scheduler tests proving catalog, survey, model, and pivot searches deduplicate through one fingerprint path.
- Add graph tests for entity normalization, process lineage, temporal ordering, inferred-edge caveats, and branched paths.
- Add closure tests proving unresolved candidates prevent clean completion.
- Add retention tests proving reports survive, cited evidence remains under `compact`, uncited bulk is deleted, partial hunts remain resumable, and cleanup is hunt-ID scoped and idempotent.

### Synthetic scenario

Extend the offline fixture into a small multi-stage intrusion containing a precursor, authentication, network session, remote execution, and follow-on activity plus a plausible benign alternative. The completed report must reconstruct the supported path and name the unsupported gap without claiming confirmed compromise.

### VM validation

After each approved milestone, deploy through the previously authorized SSH path without recording credentials in the repository. Run `doctor`, the full test suite, and the offline scenario. Live Elasticsearch/Arkime/TShark validation remains bounded and read-only. A fresh controlled hunt is required before claiming that new scheduling, analytics, graph construction, or retention behavior works on the development deployment.

## Milestones and Greenlight Points

1. **Correctness foundation:** repair the current test baseline, normalize correlation fields, and prove the offline scenario works. Pause for review.
2. **Candidate-driven loop:** persist candidates, complete all aggregate signal generators, feed candidates into reasoning, and make closure candidate-aware. Pause for review.
3. **Unified scheduler:** route every search through one history/fingerprint path and remove redundant initial work. Pause for review.
4. **Attack-path graph:** add entity/activity relationships, backward/forward expansion, and path-aware findings. Pause for review.
5. **Reporting and retention:** present the supported path in both reports and implement safe compact-on-finalization behavior. Pause for review.
6. **VM validation:** deploy and run bounded end-to-end validation, then record measured limitations and remaining work.

Each milestone must include focused tests, the full available suite, a clean working-tree review, and a concise summary of behavior changed before the next milestone begins.

Because the overall program spans several independently reviewable subsystems, each milestone receives its own implementation plan only after the preceding greenlight. Approval of this design authorizes planning Milestone 1; it does not silently authorize later milestones if evidence changes the architecture.
