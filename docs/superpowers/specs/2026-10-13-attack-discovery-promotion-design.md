# Attack Discovery Promotion Design

## Purpose

ROMULUS must turn deterministic behavioral observations into useful, bounded investigative work without inventing a story. The retrieval and investigator/critic contracts are now reliable enough that the next limiting layer is candidate promotion: repeated candidates can crowd out distinct behaviors, deterministic network follow-ups can ignore the candidate entity and return huge protocol-wide result sets, and a same-asset match can currently receive a corroboration bonus without a time-bounded evidence relationship.

This milestone improves candidate-to-search discovery and pre-finding relationships. It does not add scenario indicators, expected attack sequences, autonomous model control, or relaxed finding admission.

## Measured Failure

The blind evaluation produced a correct scan candidate and a separate DNS-behavior candidate, but seven scan hypotheses occupied seven of eight deterministic hypothesis slots. Candidate-owned Arkime follow-ups were compiled from ATT&CK protocol metadata without the candidate IP, so several searches returned capped subsets of hundreds of thousands of sessions. Candidate scoring also treated any other analytic group on the same asset as independent corroboration even when the supporting records had no demonstrated temporal relationship.

These are responsible-layer failures:

- retrieval may contain the relevant records, but the deterministic pivot is too broad to make them useful;
- ranking rewards repeated instances of one behavior more than distinct investigative coverage;
- corroboration is inferred from an asset-wide count rather than cited, time-bounded evidence; and
- reasoning can omit evidence-backed candidates when a large candidate owns more records than the case-file evidence budget.

## Success Criteria

- A deterministic candidate network follow-up uses the candidate's primary validated entity family and the behavior selector together. For IP-backed candidates, Arkime and TShark expressions contain one primary candidate IP plus the applicable protocol or port selector.
- A candidate-owned network follow-up with no safe entity selector fails closed instead of becoming a protocol-wide search. Non-candidate coverage searches may remain behavior-only.
- Candidate corroboration requires distinct analytic groups, a shared typed entity, and supporting timestamps no farther than 30 minutes apart. Same-asset activity outside the window, the same analytic group, missing timestamps, or merely similar prose earns no bonus.
- Every corroboration relationship records the related candidate ID, shared typed entity, evidence IDs, time delta, and the standard non-causality caveat.
- Candidate selection is deterministic and behavior-diverse. One reasoning pass selects at most two candidates from the same analytic group while reserving two of eight hypothesis slots for the strongest evidence-backed candidates below the normal score threshold. Remaining candidates stay eligible in later passes.
- A case file preferentially includes candidates owned by current unresolved hypotheses, then fills remaining slots diversely. A candidate with more evidence than the case-file budget remains visible through a deterministic cited subset and an `evidence_total` count; the model may cite only the visible subset.
- No hypothesis is created without a deterministic candidate and cited evidence. No relationship becomes a finding or causal path edge without the existing critic and deterministic admission gates.
- All runtime logic and tests remain independent of the evaluated dataset's identities, products, tools, timestamps, and attack order.

## Approaches Considered

### Raise limits and rely on the model

Increasing candidate, evidence, or reasoning limits would expose more data but would preserve the broad deterministic queries and unsupported corroboration. It would spend more time on the same weak frontier and is rejected.

### Build a new probabilistic attack-graph engine now

A full entity-resolution and probabilistic path engine could eventually rank episodes across NAT, DHCP, and identity changes. It would introduce a large new trust boundary before the simpler measured defects are fixed. It is deferred.

### Evidence-scoped promotion with deterministic relationships

The selected approach keeps existing candidates and the unified scheduler, then adds three narrow controls: entity-scoped candidate queries, evidence-backed candidate relationships, and diverse bounded selection. It improves discovery while preserving current IDs, persistence, admission, reporting, and retention contracts.

## Architecture

### Candidate triage boundary

A focused `romulus/investigation/candidate_triage.py` module owns deterministic candidate relationship and frontier selection logic.

`relate_candidates(candidates, evidence, window_seconds=1800)` returns copied candidate records enriched with:

- `related_candidates`: relationship records containing `candidate_id`, `shared_entity_type`, `shared_entity`, `evidence_ids`, `time_delta_seconds`, `confidence`, and `caveat`;
- `corroboration_reasons`: concise machine-authored reasons; and
- a bounded score bonus of ten points per distinct related corroboration group, capped at twenty.

The function normalizes typed entities from structured fields, not arbitrary prose. It considers host names, host/source/destination IPs, users, domains, processes, and sessions. A relationship requires at least one cited evidence pair with parseable timestamps inside the configured window. Temporal/entity association remains explicitly non-causal.

`select_candidate_frontier(candidates, limit=8, exploration_slots=2, max_per_group=2, preferred_ids=None)` returns stable candidate records. Trusted indicators and critical candidates remain first. Preferred candidates tied to unresolved hypotheses are considered before ordinary candidates. The selector then favors distinct `corroboration_group` or `analytic_id` values, limits one group's occupancy per pass, and uses the exploration reserve only for evidence-backed lower-score candidates. Excluded candidates are not closed or discarded.

### Candidate metadata and aggregate time

Behavior candidates retain their catalog `corroboration_group` and `analytic_source`. Aggregate observations derive first/last timestamps from their supporting evidence IDs. The old asset-wide independent-group bonus is removed; only `relate_candidates` may add a corroboration bonus.

Candidate IDs remain unchanged. Merge behavior continues to preserve dispositions, follow-up histories, telemetry gaps, and finding links. Relationship fields are recalculated from current evidence and then merged without erasing terminal analyst decisions.

### Entity-scoped deterministic pivots

Candidate hypotheses already place their primary asset before other extracted entities. Deterministic network compilation will construct an ordinary validated search specification from:

- the first safe candidate IP, otherwise the first safe candidate domain/hostname;
- the technique's bounded protocol and port metadata; and
- the existing evidence-anchored time window.

The existing `compile_arkime` and `compile_tshark` validators generate the final expressions. Candidate-owned queries require an entity selector. Coverage-only queries that have no candidate owner may use their existing bounded behavior selector.

This intentionally uses one entity family at a time. It avoids the two unsafe extremes: a protocol-only query that floods the result cap, and an IP-plus-hostname-plus-term query that overconstrains the pivot.

### Diverse hypotheses and case files

`_candidate_hypotheses` calls the shared frontier selector over candidates not already represented by a hypothesis. It creates at most eight hypotheses per pass, no more than two from one analytic group, with two slots available to the strongest cited lower-score signals. On later analysis passes, previously represented candidates are excluded before selection so the frontier advances rather than repeating.

`build_case_file` derives preferred candidate IDs from unresolved hypotheses and uses the same selector before applying the evidence budget. Each selected candidate contributes at most six deterministically ordered evidence records. The case file records the candidate's total owned evidence count but exposes only the selected IDs. Admission continues to treat only those visible IDs as owned citations.

## Data Flow

1. Deterministic analytics emit ordinary candidates and cited evidence.
2. Aggregate candidate timestamps are hydrated from their cited source records.
3. Candidate triage derives only time-bounded typed-entity relationships and recalculates bounded corroboration scores.
4. The diverse frontier creates candidate-backed hypotheses and lead records.
5. Candidate-owned network leads compile one entity family plus behavior into validated, evidence-anchored queries.
6. Returned evidence re-enters analysis; relationships and frontier selection are recalculated from the expanded evidence set.
7. The investigator/critic sees a bounded, diverse case file and may propose discriminating work. Existing deterministic admission remains authoritative.

## Failure and Safety Behavior

- Missing or invalid candidate entities cause candidate-owned network compilation to fail closed and record an unexecuted task outcome through existing scheduler behavior.
- Missing or invalid timestamps prevent corroboration; they never imply proximity.
- Relationship calculation never reads model prose, ATT&CK descriptions, or oracle data.
- A capped or timed-out search remains unresolved and cannot corroborate a candidate by itself.
- Candidate score changes never publish a finding. Customer visibility and finding admission retain their existing evidence requirements.
- The change introduces no active scanning, endpoint action, credential use, new network service, or write access to telemetry.

## Testing

Tests use unrelated synthetic hosts, users, addresses, domains, and behaviors.

- Query tests prove candidate IP plus behavior compilation for Arkime/TShark, primary-entity selection, hostname fallback, and fail-closed missing-entity behavior.
- Triage tests prove near/shared/distinct-group corroboration and negative controls for distant time, same group, missing time, no shared typed entity, and input-order stability.
- Frontier tests prove per-group diversity, two exploration slots, trusted/critical precedence, later-pass eligibility, preferred unresolved-hypothesis candidates, and stable ordering.
- Case-file tests prove large candidates remain visible through a bounded owned subset and that invisible evidence cannot be cited.
- A workflow test uses a generic multi-behavior synthetic fixture plus repetitive benign scanner noise to prove a distinct non-scan candidate reaches the hypothesis/case frontier and its network task is entity-scoped.
- The full local suite, compilation, diff checks, dependency-complete VM suite, configured diagnostics, and a bounded generic live hunt are required before claiming improved attack discovery.

## Scope Boundary

This milestone improves the discovery frontier and the evidence relationships available to reasoning. It does not claim full attack-path reconstruction. Identity resolution across NAT/VPN leases, richer process/session lineage, source-side complete-population aggregation, and branched path promotion remain separate later milestones unless validation proves one is required for this slice to function.
