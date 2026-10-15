# Anomaly Escalation and Evidence Completeness Design

## Purpose

ROMULUS must elevate suspicious deviations from available telemetry without requiring a predefined attack path or a scenario-specific indicator list. A broad hunt succeeds when it discovers defensible anomalous activity, preserves the evidence that caused the escalation, and makes related activity available for subsequent correlation.

## Existing Architecture

ROMULUS has four distinct layers:

1. The scheduler registers and orders bounded searches across Elasticsearch, Arkime, and TShark. Deterministic catalog and trusted-indicator work outranks model proposals, while source-family fairness prevents host or network starvation.
2. Source adapters execute validated read-only queries and persist every unique normalized record in SQLite.
3. Hunt state retains a bounded evidence context for checkpoints and model prompts.
4. Deterministic analytics summarize evidence, create scored candidates, derive follow-up work, and only then allow model reasoning over cited evidence.

The last hunt exposed an architectural boundary violation: layer 4 analyzed only layer 3's bounded context instead of layer 2's complete persisted evidence. Arkime records from the attack period were safely stored but were not eligible for anomaly detection because the first 1,000 earlier Arkime records filled the context bucket.

## Root Causes From the Last Hunt

### Complete evidence was mistaken for model context

`_record_evidence` persisted every unique record and then retained the first configured number per source and phase. `_analyze` consumed only the retained `host` and `network` arrays. This made collection completeness and detection completeness diverge silently.

### Linux audit command content was not normalized

Linux `EXECVE` records can encode unsafe arguments as hexadecimal strings. The catalog expected `process.command_line`, while the indexed records often exposed only raw `a0`, `a1`, and `a2` values inside `message`. The decoded command therefore did not exist for exact post-collection evaluation.

### Symbol-sensitive text was queried as analyzed prose

The `BH-LNX-003` seed used `match_phrase` for values such as `| sh`. Elasticsearch analyzes text before phrase matching, so punctuation is not a reliable literal boundary. The query matched ordinary shell records at very high volume. Context7's Elasticsearch documentation confirms that `match_phrase` uses the field analyzer and that term-level exact matching requires suitable keyword mappings.

### Existing aggregate analytics were starved of representative records

ROMULUS already detects high port fan-out, periodic edges, and other deviations. Those analytics could not see the later Arkime sessions. It also lacked explicit aggregate signals for DNS-name enumeration, HTTP-path enumeration, scanner user agents, and a multi-port probe followed by traffic in the reverse direction.

### Priority metadata was incomplete

Candidate scoring used base priority, specificity, repetition, and independent analytic groups. `expected_noise` was documented but did not affect the score. This could promote noisy rules as strongly as low-noise rules and made the ordering harder to explain.

## Selected Design

### Persisted evidence is the deterministic truth set

At each analysis pass, ROMULUS loads the hunt's complete persisted evidence from `Store`. It splits records into host and network domains and runs deterministic summaries and catalog matching over that set. Correlation graphs and model prompts remain bounded so state and prompt size do not grow with the evidence store.

Coverage records will distinguish:

- persisted records available to deterministic analysis;
- records retained in checkpoint context;
- candidate-related records promoted into checkpoint context.

### Candidate-driven context promotion

After deterministic candidate scoring, ROMULUS promotes a bounded set of records into hunt context:

- evidence directly cited by the highest-priority candidates;
- records containing the same structured IP, host, or asset entities;
- records ordered by candidate priority and timestamp;
- no more than 200 additional records per analysis pass.

This lets later correlation and model reasoning inspect the activity surrounding a detected entity without making the model responsible for initial discovery.

### Audit execution normalization

A focused normalization module will parse Linux audit `EXECVE` argument fields from `message`. Quoted arguments remain unchanged. Hexadecimal arguments are decoded only when they are valid, printable UTF-8. The normalized record adds `process.args`, `process.command_line`, `process.name`, and `process.executable` without deleting the original message.

### Safer behavior seeds

The direct-download-to-shell analytic becomes a composite requiring both a downloader and a pipe-to-shell expression. Seed compilation retains analyzer-compatible text clauses and adds hexadecimal prefix alternatives for command tokens in raw audit text fields. Exact candidate admission still occurs after normalization through the catalog predicate evaluator.

### Generic network deviation signals

Deterministic summaries will add:

- many distinct DNS questions from one source;
- many distinct HTTP paths from one source to one destination;
- recognized automated web-scanner user agents;
- a multi-port probe followed by a reverse-direction connection between the same peers.

These signals are based on behavior and local cardinality. They do not include scenario IPs, filenames, timestamps, or expected attack steps.

### Explainable priority

Candidate scores retain catalog base priority and specificity, add bounded repetition and independent corroboration, and subtract a fixed expected-noise penalty:

- low noise: 0;
- medium noise: 6;
- high noise: 12.

Each contribution appears in `score_reasons`. Independent aggregate signals that identify the same entity can elevate one another. A single high-noise anomaly remains a lead, while multiple distinct behaviors on the same entity rise in the queue.

## Alternatives Considered

### Increase context and query caps

Rejected. A larger cap changes where records are lost and increases checkpoint and prompt cost. It does not establish detection completeness.

### Send all persisted evidence to the model

Rejected. The model should interpret prioritized evidence, not replace deterministic collection, normalization, and anomaly detection. Full raw context also exceeds practical prompt limits.

### Add the scenario's IPs and filenames as indicators

Rejected. That would give future testing an unfair advantage and would not generalize to new data sets.

## Safety and Compatibility

- Source access remains read-only.
- Search validation and scheduler ordering remain authoritative.
- Original evidence and provenance remain unchanged; normalization only adds derived fields to the stored normalized record.
- Existing context caps continue to bound checkpoint growth.
- Findings still require cited evidence and the existing finding-admission rules.
- Attack-path construction is not required for candidate escalation.

## Verification

Tests must prove:

1. Valid audit hex arguments become a searchable command line while invalid hex remains unchanged.
2. The pipe-to-shell seed requires downloader and shell behavior and includes a hex command-token alternative.
3. Evidence excluded by the context cap still creates deterministic anomaly candidates.
4. Candidate-related later records are promoted into bounded context.
5. DNS fan-out, HTTP-path fan-out, scanner user agents, and role reversal generate cited aggregate signals.
6. Expected-noise penalties affect ordering and are recorded in score reasons.
7. The complete suite and compile checks pass without changing source safety boundaries.
