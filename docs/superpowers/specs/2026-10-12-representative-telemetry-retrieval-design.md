# Representative Telemetry Retrieval Design

## Purpose

ROMULUS must examine a bounded, representative cross-section of a hunt's full mission window when a source contains more matching records than the configured evidence cap. The current earliest-first behavior can fill the cap from one narrow interval and make later observable activity invisible to candidate generation and reasoning.

This milestone fixes retrieval coverage before adding new detection logic. The external attack corpus may measure whether a generic capability works, but no corpus-specific address, account, hostname, filename, command, tool name, timestamp, or attack sequence may enter runtime code, prompts, catalogs, or committed test fixtures.

## Intended outcome

- A capped search represents multiple portions of the effective telemetry interval instead of only its beginning.
- Retrieval stays deterministic, read-only, bounded, source-native, and attributable to one scheduler task.
- Uncapped searches retain their current exhaustive behavior.
- Capped searches remain `partial` and cannot satisfy coverage closure merely because their sample is more representative.
- Hypotheses remain evidence-first: representative retrieval can expose observations, but it cannot manufacture a candidate, hypothesis, ATT&CK mapping, or finding.
- Compact finalization keeps a bounded sampling summary and cited evidence while deleting detailed working state.

## Architecture

### Shared sampling contract

Add a small investigation-layer module that owns source-independent sampling decisions:

- Validate and normalize an effective UTC interval.
- Choose at most `TIME_SAMPLING_STRATA` deterministic strata, reduced when the result cap is smaller.
- Allocate the cap across strata without exceeding it; when the cap permits, every selected stratum receives at least one retained slot.
- Produce stable per-stratum identifiers and safe aggregate metadata only.
- Produce evenly distributed rank windows for ordered sources that expose a total and offset API.

`TIME_SAMPLING_STRATA` defaults to 8 and is constrained to 2–24. The policy is code-controlled; model output cannot change it.

### Elasticsearch

The adapter will preserve the existing PIT/search-after path for uncapped results. For a capped query with a usable timestamp field, it will determine the effective matching interval from the explicit task bounds or bounded earliest/latest probes inside the same PIT. It will then run deterministic time-stratum searches and allocate the original result cap across them.

Each stratum uses the validated original query plus an internally generated timestamp range. The adapter returns at most the original cap, suppresses duplicate hits, reports the total matched count when Elasticsearch confirms it, and returns a sampling summary. If bounds cannot be established or stratified execution fails, it returns the bounded original sample with an explicit fallback reason; it never presents fallback output as complete coverage.

### Arkime

Arkime returns a stable first-packet order, a matched total, and an offset. When the total exceeds the cap, the adapter will allocate the cap across deterministic rank windows spread over the complete ordered result set instead of paging only from offset zero. Requests remain constrained to the configured expression and mission bounds. Duplicate sessions are suppressed and the result includes sampled rank-window coverage.

The multiple HTTP requests are one bounded adapter operation, consistent with Elasticsearch's internal pagination. ROMULUS records the internal request count and sampling summary without exposing credentials.

### TShark

TShark already drains the complete filtered capture but retains only the earliest matches. Replace that retention rule with a deterministic bounded reservoir. When explicit mission bounds exist, use per-time-stratum reservoirs; otherwise use a deterministic whole-stream reservoir. The wrapper still reads the capture once, retains no payload bytes beyond the selected field rows, and never invokes a shell.

### Workflow, provenance, and reporting

Scheduler task identity will include the code-generated sampling policy so resumed work cannot silently change execution semantics. Each outcome and technical report will record:

- sampling strategy and policy version;
- requested and covered stratum count;
- matched and retained counts by stratum or rank window;
- fallback or unavailable-bound reason;
- whether the source result remained capped.

Sampling detail is bounded and credential-free. The customer report receives only a plain-language limitation when coverage is sampled. Compact retention keeps aggregate sampling coverage, not queries or per-request history.

## Error handling

- A failed stratum makes the task partial and records the missing stratum; successful strata remain usable evidence.
- A timeout, unknown total, missing timestamp, offset limit, or source error cannot be converted into complete coverage.
- Duplicate records do not consume additional retained slots.
- Reversed or invalid mission bounds fail validation before source access.
- Runtime and result caps remain hard ceilings.

## Validation

Tests use synthetic records with unrelated addresses, names, times, and behaviors.

- A late and middle synthetic event must be retained from a capped day-long Elasticsearch result where earliest-first retrieval would miss it.
- A capped Arkime result must issue rank windows across the total result range and retain sessions from early, middle, and late ranks.
- A capped TShark stream must retain deterministic records across its mission interval rather than only its first lines.
- Repeated execution over identical input must produce identical retained IDs and sampling metadata.
- Uncapped searches must return the same records and completion status as before.
- Failed or missing strata must remain partial and visible in coverage/reporting.
- A repository scan must confirm that external-corpus identifiers were not added to runtime code or tests.
- The complete local and dependency-backed VM suites, compilation, diagnostics, isolated offline proof, and bounded live proof must pass before evaluation against the external corpus.

## Non-goals

- Exhaustively ingesting every matching event.
- Raising storage retention or preserving uncited raw hunt logs after finalization.
- Encoding the evaluation corpus's attack story or artifacts.
- Allowing model-selected sampling, priorities, or source offsets.
- Claiming that representative sampling makes a capped search exhaustive.
- Adding behavior detectors before retrieved evidence proves which general detection stages are actually missing.

## Follow-on milestone

After representative retrieval is validated, classify any remaining corpus misses as normalization, candidate detection, correlation, assessment, or reporting gaps. Add only ATT&CK-aligned, source-supported behavior primitives with synthetic variants and benign controls. The existing corpus becomes a regression dataset; a separate dataset is required for final generalization evidence.
