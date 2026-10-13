# Reportable Behavior Classification Design

## Purpose

ROMULUS succeeds when it finds legitimate behavior that deserves analyst attention, investigates it as far as the available telemetry permits, and reports its conclusion honestly. A complete attack path is valuable but cannot be the admission requirement: attackers may cover tracks, telemetry may be incomplete, and a single high-specificity observation can still be operationally important.

This milestone introduces an explicit anomalous/suspicious/malicious classification contract, separates that classification from investigation status and urgency, admits sufficiently specific singular behaviors to the primary report, preserves weaker unresolved anomalies in a separate analyst-readable report, and adds a constrained possible-activity narrative. It does not lower evidence ownership, citation, schema, time-window, or source-provenance controls.

## Success Criteria

- Every evidence-backed candidate has three independent dimensions:
  - `classification`: `anomalous`, `suspicious`, or `malicious`;
  - `investigation_status`: `new`, `investigating`, `follow_up_exhausted`, `resolved`, or `dismissed`; and
  - priority/confidence: analyst urgency and evidence strength, neither of which silently changes classification.
- The behavior catalog declares the default classification and evidence contract for each analytic. A numeric score alone never establishes suspicious or malicious behavior.
- A high-specificity deterministic behavior may enter the primary report with one valid owned evidence record when its catalog contract explicitly permits singular reporting. Lack of a second artifact becomes a stated limitation, not automatic suppression.
- Weak or merely unusual observations remain anomalous, receive bounded follow-up, and do not appear as suspicious merely because they are high volume or high priority.
- Malicious classification requires an explicit deterministic gate such as a current trusted indicator with provenance or an unambiguous observed hostile action defined by a reviewed analytic. Model output cannot create or promote malicious evidence.
- The main report presents suspicious and malicious items even when they cannot be connected into a path. It states what was observed, why it matters, what follow-up ran, benign alternatives, confidence, limitations, and recommended analyst action.
- Each finalized hunt with unresolved anomalous-only candidates writes one compact plain-text companion under `reports/anomalous/`. The file remains useful after compact retention removes raw working data.
- The model may propose a clearly labeled `Hypothesis: Possible Activity Narrative` only from accepted report items and their visible evidence. It may cluster or sequence related items, leave items unconnected, or state that no coherent narrative is supported. It cannot create evidence, findings, classifications, or causal edges.
- Existing anti-hallucination, bounded-search, report-verification, and hunt-scoped retention controls remain authoritative.
- Runtime logic and tests remain independent of evaluated datasets' identities, products, addresses, timestamps, and expected attack sequences.

## Approaches Considered

### Reuse priority and disposition as classification

This is the smallest code change, but it preserves the current ambiguity: a high-priority observation can still be a weak anomaly, while a low-volume singular observation can be strongly suspicious. Investigation progress also changes over time whereas evidentiary meaning should not change without new evidence. This approach is rejected.

### Publish every candidate to one report

This maximizes recall but would bury analysts in weak baselines, repeats, and telemetry artifacts. It would make the report less trustworthy and encourage the model to connect unrelated noise. This approach is rejected.

### First-class classification with two report streams

The selected approach gives classification, investigation status, priority, and confidence distinct meanings. Suspicious and malicious behavior goes to the primary hunt report; unresolved anomalous behavior goes to a compact companion report. This preserves recall without presenting every anomaly as a threat and keeps the possible narrative subordinate to evidence.

## Classification Contract

### Anomalous

An anomalous candidate is unusual relative to a deterministic behavior rule, aggregate, or available context, but the observation is not yet specific enough to assert adversary-relevant behavior. It must own at least one valid evidence record and identify the analytic that created it. It is a lead requiring follow-up, not a reportable threat conclusion.

Examples include an uncommon connection, a high-entropy DNS pattern without enough source/suffix consistency, or a process pattern with common administrative explanations. Volume and rarity may raise priority but do not upgrade classification by themselves.

### Suspicious

A suspicious candidate is evidence-backed behavior with a credible adversary-relevant interpretation. It may be admitted through either:

- a reviewed deterministic analytic whose catalog contract permits singular reporting and whose contextual requirements are satisfied; or
- corroboration by separate evidence that satisfies existing typed-entity, time, ownership, and source rules.

A singular reverse-shell construction or log-removal command may therefore be reportable when the exact observed record matches the analytic's reviewed semantics. The report must still identify realistic benign alternatives, record the result of bounded follow-up, and state when corroboration was not found. A model assessment alone cannot make an anomalous candidate suspicious.

### Malicious

Malicious means the evidence explicitly establishes hostile activity under a narrow reviewed rule. Admission requires a machine-verifiable reason, such as a matching current trusted indicator with provenance and applicability, or a deterministic analytic representing an unambiguous hostile action with all required context present.

The default for behavior analytics is never malicious. Neither high score, model confidence, ATT&CK mapping, suspicious tool name, nor narrative coherence is sufficient. When the available evidence supports only suspicion, ROMULUS must say suspicious.

### Catalog metadata

Each behavior analytic gains an explicit classification policy containing:

- `default_classification`;
- whether one owned record may be reportable;
- minimum owned evidence and required field/context families;
- required aggregate or relationship conditions, if any;
- common benign explanations and discriminating follow-ups;
- whether deterministic upgrade or downgrade is allowed and the exact rule; and
- provenance/version information for the policy.

Catalog validation fails closed for missing or inconsistent classification metadata. Existing priority score and tier remain queue-ordering signals. Confidence describes strength of the evidence and analytic match. Neither field substitutes for the classification policy.

## Investigation Lifecycle

All admitted candidates enter the same bounded investigation queue. Suspicious and malicious work is ordered before anomalous work at equal operational priority, but high-value anomalies remain eligible and cannot be starved indefinitely.

Follow-up searches attempt to answer catalog-declared discriminating questions using the candidate's owned entities and evidence-anchored time range. Results update `investigation_status` and may change classification only through deterministic upgrade/downgrade rules. The model may recommend a follow-up, but the existing validator and scheduler remain responsible for accepting and running it.

The lifecycle is intentionally independent of classification:

- `new`: admitted but not yet investigated;
- `investigating`: at least one bounded follow-up is active or eligible;
- `follow_up_exhausted`: useful configured follow-up was completed or cannot proceed, with the reason recorded;
- `resolved`: sufficient evidence produced a supported analyst-facing conclusion; and
- `dismissed`: deterministic evidence supports a benign explanation or an analyst explicitly dismisses it.

Failure to find corroboration does not erase a high-specificity suspicious observation. It moves the item to `follow_up_exhausted` and adds a limitation. Weak anomalies may remain anomalous when follow-up is exhausted. A classification change records the prior value, new value, reason, rule identifier, evidence IDs, and timestamp.

## Primary Hunt Report

The customer-facing hunt report has separate suspicious and malicious sections. Every item includes:

- stable candidate/finding ID and classification;
- concise observed behavior, affected entities, and time range;
- exact cited evidence IDs and source provenance;
- why the deterministic analytic considers it reportable;
- investigation status and bounded follow-up performed;
- result, confidence, coverage limitations, and plausible benign alternatives; and
- prioritized analyst next steps.

Unconnected reportable items remain individually visible. ROMULUS must not withhold them because no complete path exists and must not force them into one story. Existing supported graph paths remain factual report material when their admission gates are met.

## Anomalous Lead Reports

The report generator creates `reports/anomalous/` beneath the configured reports directory. A finalized hunt with at least one unresolved candidate whose final classification is only `anomalous` writes:

`<hunt-id>-anomalous-leads-<UTC timestamp>.txt`

No anomaly file is created when the hunt has no qualifying candidates. This avoids empty-file clutter while the primary report continues to state the hunt's coverage and outcome.

The plain-text anomaly report is designed for an analyst who has exhausted stronger leads. It contains:

- hunt identity, objective, time boundary, completion state, and creation time;
- a ranked list of unresolved anomalous candidates;
- for each candidate: analytic name, entity/time summary, why it was unusual, compact human-readable evidence facts with evidence IDs, investigation status, searches performed and their outcomes, benign explanations, coverage gaps, and the next recommended pivot;
- an explicit warning that these are leads, not confirmed suspicious or malicious activity; and
- a note that compact retention may remove uncited working records and raw query history.

The anomaly report excludes model chain-of-thought, raw payload bulk, complete query bodies, credentials, packet payloads, and uncited logs. It is generated and reopened successfully before compact cleanup. Its path is included in `report_paths` and the compact manifest so retention verification treats it as a first-class report artifact.

## Possible Activity Narrative

After reportable items are finalized, the model receives a bounded narrative case file containing only:

- accepted suspicious and malicious item summaries;
- their visible owned evidence;
- already admitted graph relationships and compact time/entity facts;
- material coverage gaps; and
- stable identifiers the response is allowed to cite.

The response schema supports zero or more evidence-linked clusters, a possible sequence for each cluster, confidence, supporting item/evidence IDs, alternate explanations, missing evidence, and a list of unconnected reportable item IDs. `no_coherent_narrative` is a valid and preferred result when the evidence does not support a connection.

The report labels this section exactly `Hypothesis: Possible Activity Narrative` and states that it is an investigative interpretation, not a confirmed path. Deterministic validation rejects unknown IDs, invisible citations, classification changes, invented entities/times, and causal assertions lacking an admitted relationship. Rejected narrative output is omitted or replaced with a factual “no supported narrative” notice; it never affects findings or retention.

## Data Flow

1. Deterministic analytics produce evidence-owning candidates under catalog classification policies.
2. Candidate triage assigns independent classification, priority, confidence, and investigation status.
3. The scheduler runs bounded candidate-specific follow-ups and records authoritative outcomes.
4. Deterministic rules update investigation status and, only with cited qualifying evidence, classification.
5. Suspicious and malicious items enter the primary report even when singular or unconnected.
6. Unresolved anomalous-only items enter the companion text report.
7. The narrative model receives only accepted primary-report material and returns a non-authoritative possible interpretation.
8. All required report artifacts are written and verified before compact retention removes disposable working data.

## Compatibility and Migration

New fields are additive. Loaders tolerate legacy candidates without them and derive conservative defaults:

- missing classification becomes `anomalous` unless a current catalog policy can re-evaluate the candidate from its retained owned evidence;
- existing `observed` maps to investigation status `new` or `investigating` from recorded follow-up state;
- existing terminal benign/dismissed states map to `dismissed` without asserting a new classification;
- existing corroboration may support re-evaluation but does not automatically imply suspicious; and
- old score, customer visibility, ATT&CK mapping, or finding status never maps directly to malicious.

Legacy report generation continues to work. During the migration window, writers may preserve old disposition/customer-visibility fields as derived compatibility values, but new logic reads the explicit classification contract as authoritative.

## Failure and Safety Behavior

- Missing catalog classification metadata, required fields, evidence ownership, or provenance fails closed to non-reportable anomaly handling.
- Search errors, caps, timeouts, and unavailable sources remain coverage gaps; they do not prove or disprove a behavior.
- Model unavailability cannot suppress deterministic suspicious/malicious items or block the two factual report streams.
- A narrative validation failure cannot mutate candidates, findings, graph edges, classifications, or reportable evidence.
- Report verification failure prevents automatic compact cleanup. A partial hunt remains resumable unless explicitly finalized under existing policy.
- This change adds no active scanning, endpoint action, credential use, telemetry mutation, or scenario-specific knowledge.

## Testing

Tests use generic synthetic identities, addresses, commands, domains, and attack ordering.

- Catalog tests prove complete/valid classification metadata, fail-closed invalid policies, and separation of classification from priority/confidence.
- Candidate tests prove a reviewed singular high-specificity behavior becomes suspicious, a weak unusual event remains anomalous, and score alone cannot promote either.
- Malicious-admission tests prove only explicit deterministic provenance/context gates work and that model output, tool names, scores, and ATT&CK mappings cannot promote an item.
- Workflow tests prove all anomalies receive bounded follow-up, suspicious/malicious work is prioritized without starving anomalies, exhausted singular suspicious items remain reportable, and deterministic evidence can upgrade/downgrade with an audit trail.
- Main-report tests prove suspicious and malicious items appear separately, singular and unconnected items are preserved, benign alternatives and follow-up results are present, and unsupported attack paths are not claimed.
- Anomaly-report tests prove the directory/file naming, readable content, no-file case, partial/finalized behavior, path registration, and exclusion of raw bulk.
- Narrative tests prove accepted clustering, unrelated items left separate, `no_coherent_narrative`, rejected unknown or invisible IDs, rejected invented facts, and model-unavailable fallback.
- Retention tests prove all primary and anomaly reports reopen before cleanup, the anomaly text survives compact retention, sufficient compact facts remain readable, uncited working evidence/log/query bulk is removed, and cleanup stays hunt-ID scoped and idempotent.
- End-to-end validation proves the current generic analytics can emit properly classified report items from synthetic behavior and then uses bounded read-only live validation to measure results without assuming they are attack activity.

## Scope Boundary

This milestone changes admission, lifecycle semantics, report organization, narrative framing, and compact report retention. It does not promise complete attack-path reconstruction, universal benign-baseline learning, identity resolution across NAT/VPN leases, or automatic proof that live matches are hostile. Improving analytic coverage remains an ongoing library task; this design ensures that valid signals already found are investigated and delivered honestly instead of being discarded for lack of a complete chain.
