# ROMULUS Source-Aware Intelligence Execution Design

## Purpose

ROMULUS contains a large researched behavior corpus, but the current pack generator treats every directly executable record as an Elasticsearch rule and emits sequence, aggregate, and baseline records as unsupported reference descriptions. That creates a misleading inventory: research can appear present without becoming a valid search against the telemetry source that can actually answer it.

This design makes the execution contract explicit. Every runnable behavior must identify its telemetry source, compile into that source's native query language, retain its behavior identity through collection, and define any required correlation separately from source retrieval. Reference material remains available for planning and enrichment, but it cannot count as an executed search.

## Success criteria

- Every runnable search declares one of `elasticsearch`, `arkime`, or `tshark` as its execution source.
- Elasticsearch searches are mapping-aware Elasticsearch Query DSL clauses wrapped by the adapter in the immutable mission window.
- Arkime searches are valid Arkime session expressions using Arkime expression-field names and explicit start and stop times.
- TShark searches are valid Wireshark display filters and include the mission-window frame-time constraint.
- A multi-event behavior contains source-specific stage searches plus a deterministic correlation specification. It is never represented as one ambiguous cross-source query.
- Aggregate behaviors define their filter, grouping keys, time window, measure, minimum sample size, and threshold.
- Baseline behaviors define their observation query, entity, peer group, historical lookback, warm-up, contamination handling, and deviation threshold.
- Every collected result retains the originating behavior ID, query ID, stage ID where applicable, and source language.
- A behavior that cannot be translated completely is visibly `reference_only` or `not_applicable`; it is not labeled supported and does not count toward search coverage.
- Generated packs fail closed when a runnable record lacks source, query semantics, required fields, or correlation semantics.
- Search-budget limits report exactly which runnable behaviors were omitted. They do not silently turn omitted records into tested coverage.

## Design principles

### Native syntax at the source boundary

Each adapter accepts only its own query representation:

- Elasticsearch accepts a validated Query DSL clause and source-target list.
- Arkime accepts a validated Arkime expression and explicit time interval.
- TShark accepts a validated display filter and allowlisted capture list.

No adapter accepts prose, a generic query string, or syntax intended for another source.

### Canonical behavior semantics before compilation

Catalog records describe behavior through typed semantic roles and operators. Source compilers bind those roles to discovered source fields. The canonical layer prevents hundreds of copied raw queries while still ensuring that the final request is native to its destination.

Raw native clauses may be used only for carefully reviewed capabilities that cannot be represented by the canonical operator set. They still declare a source, pass the same validation, and cannot introduce unbounded time or target selection.

### Retrieval and correlation are separate

A source query retrieves candidate events or sessions. A correlation specification determines whether those results form the researched behavior. This distinction is required for ordered process sequences, cross-source attack paths, fan-out, failure-then-success patterns, and historical deviations.

### Coverage reflects execution

A record contributes to `tested` coverage only after all required stages were applicable and executed successfully over the requested window. The following remain distinct:

- `tested_not_observed`
- `observed`
- `not_applicable_missing_fields`
- `not_executed_budget`
- `not_executed_source_error`
- `reference_only_untranslated`
- `partial_correlation_input`

## Rule model

### Common metadata

Every behavior retains its stable ID, title, description, priority, specificity, expected noise, ATT&CK mappings, provenance, benign explanations, corroboration requirements, and review date.

Every executable behavior also has:

- `execution_kind`: `direct`, `sequence`, `aggregate`, or `baseline`.
- `activation_mode`: `active` or `observe`.
- `source_plan`: one or more source-specific stages.
- `coverage_requirements`: telemetry categories and semantic roles required to execute honestly.
- `result_contract`: entity roles and values that must be normalized from matching results.

`supported` is derived by validation and is not an authored Boolean that can drift from the actual rule content.

### Source stage

Each stage defines:

- Stable `stage_id`.
- One execution source.
- Canonical predicates or an explicitly reviewed native query.
- Required semantic roles.
- Result fields needed by later correlation.
- Expected maximum result volume and truncation behavior.
- Whether absence is meaningful or merely inconclusive.

The compiler produces a source-native query and records the resolved field bindings. A stage with missing or ambiguous required fields is not applicable to that dataset.

### Direct behavior

A direct behavior has one source stage and no temporal join. Process, file, authentication, Windows Event Log, Linux audit, and cloud audit searches normally target Elasticsearch. Session and protocol metadata normally target Arkime. Packet-only protocol details target TShark.

Tool names such as `nmap`, `nc`, and `socat` remain candidate signals with their researched priority and context. The source compiler controls syntax; scoring and corroboration control escalation.

### Sequence behavior

A sequence defines:

- Ordered or unordered stages.
- Required and optional stages.
- Overall time window and optional maximum gap between adjacent stages.
- Join roles such as host, user, source address, destination address, process, file path, account, or session.
- Minimum number of distinct stages or entities.
- Direction and normalization rules for network entities.
- Conditions under which capped, missing, or failed stage input makes the result partial.

Each stage is compiled and executed against its declared source. The local sequence engine correlates normalized results without inventing missing joins. A cross-source sequence is complete only when the required join keys exist on both sides.

### Aggregate behavior

An aggregate defines:

- Source filter.
- Group-by entity or entities.
- Fixed or sliding time window.
- Measure such as count, distinct count, sum, ratio, rate, cardinality, or inter-arrival variance.
- Minimum sample count.
- Threshold and comparison operator.
- Optional success/failure or inbound/outbound partition.
- Result fields required for evidence and follow-up.

Elasticsearch-native aggregations are preferred for indexed event data. Arkime session, unique-value, or field aggregation endpoints are used for session metadata when they preserve the rule semantics. Cross-source aggregates use bounded source retrieval and local calculation. A capped input cannot satisfy a high-confidence aggregate unless the threshold was crossed before the cap and the measure is monotonic.

### Baseline behavior

A baseline defines:

- Current observation stage.
- Historical source and lookback period.
- Entity and peer-group roles.
- Warm-up period and minimum observations.
- Statistic such as first seen, prevalence, median and deviation, percentile, or categorical rarity.
- Deviation threshold.
- Excluded maintenance periods or known contamination inputs when configured.
- Expiration and refresh policy for stored baseline state.

Baseline-only matches begin in observe mode. They can contribute to escalation when joined with a concrete suspicious behavior or high-value context.

## Source compilers

### Elasticsearch compiler

The Elasticsearch compiler:

1. Resolves semantic roles against per-index field metadata.
2. Rejects missing, ambiguous, non-searchable, or type-incompatible bindings.
3. Emits only the allowlisted Query DSL operators supported by the adapter.
4. Uses keyword-capable fields for exact equality and text-capable fields for analyzed matching.
5. Adds stable named clauses for behavior and stage attribution.
6. Applies the immutable timestamp range through the adapter.
7. Validates the resulting clause locally and, when available, through Elasticsearch's read-only query validation endpoint.
8. Keeps host and network index classes separate unless the rule explicitly defines a cross-index stage.

Search Matrix and Windows Event Log rules remain Elasticsearch-specific. They share this compiler and evidence-attribution contract rather than maintaining a separate looser execution path.

### Arkime compiler

The Arkime compiler:

1. Resolves canonical network roles to Arkime expression-field names, not Elasticsearch database-field names.
2. Emits parenthesized Arkime expressions with escaped literals and allowlisted operators.
3. Rejects fields unavailable in the connected Arkime field catalog.
4. Sends explicit start and stop time on every request.
5. Uses the sessions endpoint for direct session matches and the appropriate unique or aggregation endpoint for supported aggregate semantics.
6. Uses Arkime's read-only build-query capability when available to confirm how the expression will be translated before collection.
7. Preserves behavior and stage IDs in the scheduled task and normalized evidence.

### TShark compiler

The TShark compiler:

1. Resolves canonical packet roles against the allowlisted Wireshark field catalog.
2. Emits Wireshark display-filter syntax, never capture-filter or Arkime syntax.
3. Escapes literals according to display-filter rules.
4. Adds the immutable frame-time bounds.
5. Rejects unavailable fields before scanning captures.
6. Treats parser errors, timeouts, and truncated output as explicit coverage states.

## Correlation engine

The correlation engine consumes normalized evidence envelopes rather than raw source documents. Each envelope contains:

- Evidence ID.
- Behavior ID and stage ID.
- Source and native query language.
- Event or session time.
- Normalized entity values with original field provenance.
- Source record locator.
- Truncation and source-health metadata.

Correlation uses deterministic joins and sorted event time. It cannot use model inference to manufacture an entity match. The model may interpret a completed or partial correlation after the deterministic engine records the contributing evidence and limitations.

Correlation state is bounded by the mission window, rule window, entity count, evidence cap, and persisted checkpoint limits. Evictions are recorded so the report can distinguish no match from incomplete correlation.

## Catalog and file responsibilities

### `scripts/behavior_pack_translations.json`

Replace the current blanket `unsupported_semantics` messages with versioned translations for canonical signals, source eligibility, semantic roles, operators, sequence stages, aggregate measures, and baseline types. The registry must not supply guessed thresholds for underspecified research records.

### `scripts/build_behavior_packs.py`

Compile every curated record through the typed rule model. It must:

- Stop assigning `source: elasticsearch` to every direct record.
- Derive support from complete validated semantics.
- Emit source stages and correlation definitions.
- Fail the build when a record marked executable is incomplete.
- Emit intentionally untranslated records as `reference_only` with a structured reason.
- Produce manifest counts for executable, reference-only, active, observe, and each source language.

Generated JSON files are outputs. Corrections belong in the research corpus, translation registry, schemas, or compiler so regeneration cannot reintroduce the defect.

### `romulus/intelligence/behavior_catalog.json`

Migrate the existing base analytics to the shared rule model. Its current deterministic semantics remain authoritative during migration.

### `romulus/intelligence/windows_event_catalog.json`

Keep Windows Event Log source selectors and message/script predicates as Elasticsearch stages. Event IDs, provider/channel fields, script-block text, process context, and account/network context must be combined in one mapping-aware Query DSL clause where the rule requires same-event evidence.

### `romulus/intelligence/search_matrix_catalog.json`

Keep this catalog Elasticsearch-specific. Each signature receives a stable named clause or equivalent deterministic post-match evaluator. Batched searches retain the list of possible signatures, and each returned hit records only the signatures whose predicates matched that hit.

### `romulus/intelligence/behavior_packs/direct.json`

Emit validated one-stage rules with an explicit source. Elasticsearch, Arkime, and TShark records remain distinguishable in the generated pack and manifest.

### `romulus/intelligence/behavior_packs/sequences.json`

Replace prose-only relationship lists with stage references, source definitions, joins, ordering, windows, and completeness rules. The 89 current records remain visible throughout migration; no record becomes executable until all required stages and joins are defined.

### `romulus/intelligence/behavior_packs/aggregates.json`

Replace aggregate marker names with complete filter, grouping, window, measurement, sample, and threshold definitions. The 206 current records remain visible and individually report translation state.

### `romulus/intelligence/behavior_packs/baselines.json`

Replace baseline marker names with complete current and historical retrieval plus statistical definitions. The 58 current records remain visible and individually report translation state.

### `romulus/intelligence/behavior_packs/references.json` and `attack_catalog.json`

Mark the 1,216 capability references and 1,745 ATT&CK analytic references as reference-only. A targeted retriever may use them to recommend a curated behavior or follow-up, but references do not schedule searches directly and do not increase tested coverage.

### Runtime scheduling and workflow

The scheduler carries behavior ID, stage ID, source language, native query, resolved bindings, correlation ID, and result contract. Workflow evidence retains those fields. Discovery reserves budget for evidence-driven pivots and reports every rule omitted by budget. Aggregate and sequence processing uses the full persisted evidence eligible for the rule window rather than only a small model-context slice.

## Migration program

The work is divided into coherent implementation increments. All increments use the same schema and status model, so partial delivery cannot misrepresent untranslated research as executable coverage.

### Increment 1: execution foundation and current runnable catalogs

- Add the typed rule model and validators.
- Add source-specific compilers.
- Migrate the base behavior catalog, Windows catalog, Search Matrix, and 549 direct records.
- Preserve exact per-signature attribution through scheduling and evidence.
- Update manifest and coverage accounting.

### Increment 2: sequence execution

- Add the deterministic correlation engine.
- Translate all 89 sequence and cross-source records into stages and joins.
- Add partial-input and truncation handling.

### Increment 3: aggregate execution

- Add source-native aggregate planning and bounded local aggregate evaluation.
- Translate all 206 aggregate records with explicit measures and thresholds.

### Increment 4: baseline execution

- Add historical baseline state and contamination controls.
- Translate all 58 baseline records.

### Increment 5: reference contribution

- Add targeted retrieval over reference-only capability and ATT&CK material.
- Record which references influenced a hypothesis, rule selection, or follow-up.
- Keep reference retrieval outside executed-search coverage.

## Failure handling

- A malformed executable rule prevents the affected generated pack from loading.
- A source syntax error records the rule, source, compiler version, and validation failure without falling back to another query language.
- Missing mappings make the stage not applicable; they do not trigger broad text search.
- Failed required stages make a sequence or correlation incomplete.
- Truncated results propagate into the aggregate, sequence, or baseline confidence state.
- Source outages produce failed coverage, not tested/no-match coverage.
- An unknown operator or signal type fails generation instead of being ignored.

## Design-flaw checks

Every implementation increment is reviewed for these failure patterns:

- A catalog count is presented as a search count.
- A description or marker is treated as executable logic.
- A source query is routed to the wrong adapter.
- A generic field name is emitted without mapping resolution.
- A batched query loses per-signature attribution.
- A sequence is evaluated from a bounded presentation subset instead of eligible evidence.
- A cap, timeout, or missing stage is reported as no match.
- A threshold is invented without documented provenance or explicit project policy.
- An unsupported record is silently omitted from operator-visible coverage.
- Regenerating derived files reverses a manual correction.

Finding any of these conditions blocks activation of the affected rule family until it is corrected or explicitly classified as reference-only.

## Acceptance evidence

Implementation is complete when the repository can demonstrate:

- Generated-pack manifests reconcile the full curated corpus into executable and reference-only states with no missing IDs.
- Every executable stage identifies exactly one native query language.
- All generated Elasticsearch clauses pass mapping-aware validation.
- All generated Arkime expressions pass the local compiler and connected build-query validation when Arkime is configured.
- All generated TShark filters pass display-filter parsing against the configured field inventory.
- Direct hits retain their exact behavior IDs after query batching.
- Representative same-source and cross-source sequences correlate only on declared entity keys and time windows.
- Aggregate and baseline results expose sample counts, caps, windows, and thresholds.
- Reports distinguish executed, omitted, unavailable, partial, and reference-only behaviors.
- The operator-facing indicator list shows words, priorities, source, and execution state without exposing large query bodies.

## Security and operational boundaries

All source operations remain read-only and bounded by the mission window, allowlisted indices, allowlisted captures, result caps, and timeouts. Native query validation cannot expand the configured data scope. Model-generated proposals remain candidates that must pass the same source compiler and adapter validation as curated rules.
