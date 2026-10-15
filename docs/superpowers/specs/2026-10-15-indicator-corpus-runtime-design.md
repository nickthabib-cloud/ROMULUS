# Indicator Corpus Runtime Design

**Date:** 2026-10-15  
**Status:** Approved design, pending implementation plan  
**Research inputs:** `docs/research/common-indicator-corpus.json`, `docs/research/common-indicator-index.csv`, and `docs/research/common-indicator-research.md`

## Purpose

ROMULUS must turn the researched indicator corpus into reusable hunt knowledge without converting common administrative tools into high-confidence alerts. The runtime must find concrete suspicious activity, elevate meaningful relationships, preserve weak signals as context, and explain what telemetry or engine capability was required for every rule.

The implementation covers all 902 curated behavioral records. It also retains the 1,216 LOLBAS and GTFOBins capability records and 1,745 ATT&CK analytic references as searchable research indexes. Capability and analytic references do not become process-name-only alerts.

No hunt will be executed as part of this implementation. Verification is limited to offline catalog validation, deterministic compilation, pure evaluator checks, syntax compilation, and repository diff checks.

## Existing Architecture

ROMULUS currently has one live behavior catalog containing 63 analytics. Each analytic has semantic roles, a single-event Boolean predicate, a priority, expected noise, ATT&CK mappings, benign explanations, follow-up guidance, and provenance.

The scheduler compiles a bounded subset of applicable live analytics into Elasticsearch seed searches. Complete persisted evidence is then analyzed deterministically. `build_candidate_queue` matches the catalog against individual events plus a fixed set of aggregate signals. Candidate scoring combines base priority, specificity, repetition, independent corroboration, and an expected-noise penalty. Bounded candidate evidence is promoted into checkpoint and model context.

The existing evaluator cannot express ordered event sequences, historical baselines, generic rate or cardinality rules, or normalized cloud, identity, and Kubernetes resource relationships. It also performs a nested analytic-to-event scan that would become unnecessarily expensive if thousands of research references were loaded as executable rules.

## Corpus Classification

The research corpus contains four runtime classes:

| Class | Records | Runtime treatment |
|---|---:|---|
| Direct event predicates | 549 | Compile into direct behavior packs |
| Ordered or cross-source relationships | 89 | Compile into sequence packs |
| Aggregate signals | 206 | Compile into aggregate specifications |
| Historical baseline deviations | 58 | Compile into baseline specifications |

The remaining 2,961 source-derived records are reference material:

| Reference class | Records | Runtime treatment |
|---|---:|---|
| LOLBAS command/use-case references | 485 | Searchable index; predicate extraction required before activation |
| GTFOBins executable/function references | 731 | Searchable index; privilege and argument context required before activation |
| ATT&CK detection analytics | 1,745 | Searchable translation backlog linked to the pinned ATT&CK catalog |

## Selected Architecture

### Versioned behavior packs

Create `romulus/intelligence/behavior_packs/` with independent versioned files:

- `direct.json` for 549 direct predicates;
- `sequences.json` for 89 ordered or cross-source relationships;
- `aggregates.json` for 206 rate, cardinality, protocol, identity, cloud, and Kubernetes signals;
- `baselines.json` for 58 historical deviations;
- `references.json` for the 1,216 LOLBAS and GTFOBins capability references;
- ATT&CK analytic references remain in the existing pinned `attack_catalog.json` and are indexed by ID rather than copied.

The existing `behavior_catalog.json` remains the built-in compatibility pack. `load_behavior_catalog` merges it with the direct pack and exposes the other pack classes through explicit loaders. Duplicate IDs across any executable pack fail closed.

Each executable rule has:

- a stable ID and version;
- an activation mode;
- supported platforms and event sources;
- required and optional semantic roles;
- deterministic matching or aggregation logic;
- priority, specificity, and expected noise;
- ATT&CK mappings and provenance;
- benign explanations, escalation conditions, and follow-up guidance;
- a review date and research-corpus source ID.

### Activation modes

Rules use three modes:

- `active`: can seed collection, create normal candidates, corroborate other signals, and become customer visible under the existing evidence rules;
- `observe`: evaluates already collected evidence and records technical observations, but cannot seed collection, independently become customer visible, or elevate another observation above the medium tier;
- `reference`: searchable metadata only and never evaluated against hunt evidence.

Default activation is deliberately narrow:

- 73 high or critical, low-noise direct records are active;
- five high or critical, low-noise sequences are active;
- 824 remaining curated records are observed;
- all LOLBAS, GTFOBins, and untranslated ATT&CK records are references.

This installs the entire researched corpus while preventing a common binary name, weak rarity signal, or immature baseline from overwhelming the candidate queue.

### Deterministic corpus compiler

Add `scripts/build_behavior_packs.py`. It reads the research JSON and deterministically produces the pack files. Generation must be stable for identical input and must fail when it encounters:

- an unknown source or activation mode;
- duplicate IDs;
- an unknown semantic role, operator, ATT&CK ID, aggregate primitive, baseline primitive, or sequence stage;
- a direct rule without a usable predicate;
- a sequence without at least two stages and an explicit time bound;
- an aggregate or baseline without group, measure, minimum support, and threshold semantics;
- a non-reference rule without provenance, benign context, escalation guidance, or follow-up guidance.

Generated packs include source-corpus hashes and counts so a reviewer can reproduce their contents and detect drift.

## Direct Predicate Runtime

### Expanded semantic roles

Extend semantic normalization with commonly available fields for:

- event outcome, category, dataset, provider, and operation;
- user ID, target user, group, role, authentication method, and session;
- process entity ID, parent entity ID, effective user, integrity, signature, and hash;
- file operation, owner, extension, size, and destination path;
- network direction, community ID, connection duration, packet counts, HTTP method, HTTP user agent, TLS fingerprint, and certificate attributes;
- cloud provider, account, organization, region, service, resource type, resource ID, request parameters, and assumed role;
- container ID, image, name, runtime, privilege, capabilities, and host mounts;
- Kubernetes verb, user, user agent, resource, namespace, object name, response code, impersonation, and request attributes;
- source geography, ASN, device, and identity-risk context.

Aliases remain additive. Original evidence is never rewritten or discarded.

### Indexed matching plan

Replace the catalog-wide nested scan with a compiled matcher plan:

1. Extract normalized semantic-role values from each evidence record once.
2. Partition rules by source and required-role signature.
3. Index exact values, action names, process names, and aggregate-signal names directly.
4. Group path-prefix, suffix, and substring predicates by anchor role.
5. Precompile regular expressions once when the catalog loads.
6. Evaluate a rule only when its required roles exist and its anchor predicate has a possible match.

The matcher produces the same deterministic match result regardless of evidence order. It retains the existing 40-evidence-reference bound and complete match counts.

### Seed planning

Only active direct rules may produce collection seeds. Observed and reference rules never consume tool calls.

The seed planner groups compatible one-role literals into bounded queries by platform, role, operator, and priority. Compound rules remain separate when merging would change Boolean meaning. Exact post-collection matching remains authoritative, so a grouped seed can retrieve a superset without admitting false candidates.

The scheduler's existing tool-call budget and source-family fairness remain authoritative. Unsupported roles are reported as coverage gaps rather than silently dropped.

## Sequence Runtime

### Canonical behavior observations

Every direct or aggregate match produces an internal behavior observation containing:

- rule ID and canonical signal name;
- event time range;
- exact evidence IDs;
- actor, asset, account, process, object, path, source, destination, and session entities when present;
- priority, noise, mode, and ATT&CK metadata.

Sequence rules consume these observations. They do not search raw prose for conceptual stage names.

### Sequence definition

A sequence contains:

- two or more ordered or unordered stages;
- a maximum time window;
- required shared-entity constraints;
- optional maximum gap per stage;
- minimum supporting evidence;
- explicit handling for missing timestamps or entities;
- active or observe mode.

The compiler maps every research relationship to canonical stage signals. A sequence that lacks implemented stages remains present with `supported: false` and an explicit reason. Unsupported sequences do not match and appear in coverage reporting.

### Evaluation algorithm

Sort behavior observations deterministically by time and evidence ID. Maintain bounded deques per rule and shared-entity key. Discard observations older than the rule window. Emit one sequence observation for each unique supporting evidence set, deduplicated by rule and entity key.

Sequences require exact normalized entity equality. Time proximity without a shared actor, asset, account, object, path, address, destination, or session is insufficient.

## Aggregate Runtime

Aggregate specifications use a small set of reusable primitives:

- event count;
- distinct count and fan-out;
- burst rate;
- failure-to-success transition;
- byte or packet volume;
- outbound-to-inbound ratio;
- duration;
- periodicity and jitter;
- first or rare relationship within the current evidence set;
- multi-source agreement;
- coverage or telemetry-health degradation.

Each specification declares source filters, group keys, measure fields, threshold, minimum samples, window, evidence bound, and canonical signal name. Thresholds remain data and cannot invoke arbitrary code.

Identity, cloud, and Kubernetes concepts first normalize into structured event actions and resources. Exact administrative changes can then use direct predicates. Rate, fan-out, and behavioral combinations use aggregate primitives. Observed aggregate rules remain technical context until promoted after representative replay.

Aggregate output uses the existing `aggregate.signal` bridge, preserving current candidate scoring and evidence promotion.

## Historical Baseline Runtime

### Baseline store

Add versioned SQLite tables for baseline snapshots and rule state. A snapshot stores only normalized grouping keys and aggregate statistics required by a rule. Raw evidence remains governed by existing retention.

Baseline state includes:

- rule and metric version;
- entity or peer-group key;
- observation count and covered time span;
- first and last observation;
- bounded frequency, cardinality, mean, variance, and quantile summaries as required by the primitive;
- source coverage and sensor-health metadata;
- last update time.

### Warm-up and contamination controls

A baseline rule cannot create a normal candidate until its minimum history, sample count, and source coverage are satisfied. Before that point it reports `warming` coverage.

Only evidence from completed hunts may update persistent baselines. Findings and high-priority candidates are excluded from updates by default. Baseline updates are deterministic, versioned, and reversible by rule version. The current hunt never trains the baseline it is being compared against.

Baseline observations begin in observe mode. They cannot independently become customer visible.

## Candidate Scoring and Reporting

Active direct and sequence observations use existing base-priority, specificity, expected-noise, repetition, and independent-corroboration scoring.

Additional rules apply:

- an observed rule has a score ceiling of 39;
- observed rules never independently become customer visible;
- multiple observed rules may be shown together in the technical appendix but do not promote one another beyond the ceiling;
- an active low-noise sequence may receive a bounded relationship bonus;
- a baseline deviation contributes context but requires a concrete active behavior for high-priority escalation;
- a source capability reference never creates a candidate;
- unsupported rules appear in coverage, not candidate output.

Score reasons identify activation mode, direct or relationship basis, baseline state, exact shared entities, threshold contributions, noise penalties, and supporting evidence counts.

## Coverage and Explainability

Each hunt records pack coverage by:

- total, active, observed, reference, supported, and unsupported rule counts;
- platform and source applicability;
- missing semantic roles;
- aggregate and baseline readiness;
- sequence stages unavailable because their component signals were unsupported;
- rules skipped by seed budgets while remaining eligible for post-collection evaluation;
- baseline warm-up and history bounds.

A rule that did not run is never described as a non-match. A negative result distinguishes no matching evidence from missing telemetry, unsupported semantics, an unwarmed baseline, and budgeted collection that did not include the rule's seed.

## Performance and State Bounds

- Reference records are never evaluated against evidence.
- Observed rules do not generate collection queries.
- Direct matching extracts role values once per event and uses the compiled rule index.
- Sequence deques are bounded by rule window, entity key, and a fixed per-rule observation cap.
- Aggregate specifications retain bounded cited evidence and compact group state.
- Baseline snapshots retain statistics rather than raw event copies.
- Checkpoint and model context remain bounded by existing candidate-promotion limits.
- Candidate storage continues to keep complete counts with bounded evidence references.

## Files and Interfaces

Expected implementation areas:

- `scripts/build_behavior_packs.py`: deterministic corpus compiler;
- `romulus/intelligence/behavior_packs/*.json`: generated runtime packs;
- `romulus/intelligence/behavior_catalog.py`: pack loading, validation, activation modes, matcher plan, and direct observations;
- `romulus/intelligence/sequence_analytics.py`: sequence definitions and evaluator;
- `romulus/intelligence/aggregate_analytics.py`: generic aggregate primitives and registry;
- `romulus/intelligence/baseline_analytics.py`: baseline comparison and snapshot updates;
- `romulus/intelligence/normalization.py`: expanded semantic aliases and derived structured roles;
- `romulus/store.py`: versioned baseline tables and storage methods;
- `romulus/investigation/workflow.py`: applicability, observations, sequence and baseline analysis, coverage, and candidate integration;
- `romulus/reporting/report.py`: coverage and technical-observation presentation;
- `docs/behavior-analytics.md`, `README.md`, `CHANGELOG.md`, and `VALIDATION.md`: operator and maintenance documentation.

Existing public function signatures remain compatible where possible. New pack loaders and evaluators use explicit arguments and return plain deterministic dictionaries suitable for persistence.

## Failure Behavior

- Malformed or duplicate executable rules stop startup before source access.
- A missing research file does not affect runtime after generated packs exist.
- An unsupported role or sequence stage produces a coverage record and no match.
- Corrupt or incompatible baseline state is ignored for detection, reported, and never silently rebuilt from the current hunt.
- An aggregate exceeding its group cap reports truncation and does not claim complete negative coverage.
- A pack hash mismatch stops startup.

## Security and Compatibility

- Elasticsearch, Arkime, and TShark access remains read-only.
- No scenario-specific IP address, filename, timestamp, or expected attack path is added.
- Research references never become exact trusted indicators.
- Original telemetry and provenance remain unchanged.
- Pack generation and runtime evaluation use local deterministic code and data.
- The model remains downstream of deterministic collection and candidate creation.
- Attack-path construction is not required for indicator escalation.
- Existing catalog entries retain their IDs and behavior.

## Verification Boundary

Implementation verification will not run a hunt or access Elasticsearch, Arkime, TShark, or another live source. It will establish:

1. deterministic pack generation and stable counts;
2. successful loading and validation of every pack;
3. zero duplicate IDs, unknown ATT&CK IDs, invalid source references, or missing rule metadata;
4. correct activation totals: 78 active and 824 observed curated rules;
5. direct matching, observed score ceilings, sequence entity constraints, aggregate thresholds, and baseline warm-up through a standalone offline validator with deterministic cases;
6. bounded evidence, sequence state, aggregate groups, and baseline summaries;
7. backward-compatible loading of the existing 63-rule catalog;
8. syntax compilation and clean repository diffs.

No claim about real telemetry efficacy will be made until a later user-authorized hunt or replay is performed.

