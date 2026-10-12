# ROMULUS Strict Window and Telemetry Coverage Design

## Purpose

ROMULUS is a proof of concept for autonomous threat hunting over bounded host and network datasets. Every live hunt must search one explicit time window, discover the schema of the dataset it is given, measure which defensive telemetry is actually present in that window, prioritize hypotheses that the dataset can support, and stop without model reasoning when the window contains no searchable data.

The objective is to improve hunt effectiveness and make missed activity explainable. ROMULUS may seek all malicious activity represented in the dataset, but it must measure that claim against known or seeded ground truth and recorded source coverage. It must not describe an unvalidated hunt as exhaustive.

## Success criteria

- A live hunt cannot begin without an explicit start and end time.
- Elasticsearch, Arkime, and TShark use the same normalized UTC interval for every search.
- No configuration option permits an all-history or implicit rolling-window search.
- Telemetry presence and field quality are measured before hypothesis generation.
- If all successfully checked configured sources contain zero records in the requested window, ROMULUS writes a short no-data report and stops before any Ollama call or analytic search.
- If every configured source fails, ROMULUS reports telemetry failure rather than claiming the window is empty.
- The planner ranks hypotheses and searches by measured telemetry support without depending on current index names or one fixed schema.
- Out-of-window records cannot support findings and produce a recommendation for a separate hunt.
- Existing investigation records remain readable; incompatible old hunts are not silently resumed under new scope rules.

## Scope

### Included telemetry

ROMULUS inventories host and network data available through the proof-of-concept source types:

- Endpoint process, command, file, service, task, package, registry, and other host activity in allowlisted Elasticsearch indices.
- Host authentication and account-use telemetry in allowlisted Elasticsearch indices.
- DNS telemetry in Elasticsearch, Arkime, or PCAP data.
- Network session, flow, and firewall-style telemetry in Elasticsearch or Arkime.
- Packet telemetry in explicitly allowlisted PCAP/PCAPNG files through TShark.

### Excluded integrations

- Identity-provider APIs.
- AWS, Azure, Google Cloud, or other cloud-provider APIs.
- New MCP servers for telemetry access.
- Active collection, scanning, containment, or remediation.

The existing direct, read-only Python adapters remain the trusted execution boundary.

## Mission window contract

Add an immutable `MissionWindow` value with:

- `start`: timezone-aware UTC datetime.
- `end`: timezone-aware UTC datetime.
- `source_timezone`: configured `MISSION_TIMEZONE` when an input omits an offset.
- `display`: canonical `start through end` UTC string.

The end must be later than the start. A date-only end remains inclusive through `23:59:59.999` in the source timezone before conversion to UTC. The maximum permitted window is configurable through `MAX_MISSION_WINDOW_DAYS`, default 31 and bounded from 1 to 366.

### CLI

`hunt` requires:

```text
python main.py hunt --start <ISO-8601> --end <ISO-8601> --objective <text>
```

For one compatibility release, if both flags are absent and the objective contains exactly two ISO date or datetime values, ROMULUS extracts them and prints a deprecation warning. Supplying only one flag, supplying an invalid or reversed range, or supplying neither flags nor exactly two objective dates fails before any external call.

`resume` uses the persisted mission window. A pre-change investigation with no persisted window remains inspectable but cannot resume; ROMULUS instructs the operator to start a new hunt with an explicit range.

`demo` uses the fixed timestamp range represented by its synthetic fixtures and prints that range.

### Removed settings

Remove these settings and their behavior:

- `HISTORICAL_SEARCH`
- `ES_LOOKBACK_HOURS`
- `ARKIME_DATE_HOURS`

If any of these legacy variables are present, `doctor` reports that they are ignored and identifies the replacement `--start` and `--end` arguments. They do not alter hunt behavior.

## Workflow

The live graph becomes:

```text
validate scope -> inventory telemetry -> no-data report OR plan -> collect -> analyze -> reason/pivot -> report
```

Scope validation occurs before the graph invokes any source or model. Telemetry inventory occurs before ATT&CK seed selection and Ollama hypothesis generation.

### Empty-window behavior

The inventory calculates a record count for every successfully checked configured source:

- If at least one source reports records, the hunt continues.
- If all successful sources report zero and no source reports records, the hunt ends with `termination_reason=no_data_in_window`, `outcome=no_telemetry_in_window`, and a completed short report.
- If no source succeeds, the hunt ends partial with `termination_reason=telemetry_inventory_failed` and `outcome=failed_telemetry_retrieval`.
- If some sources fail and the successful sources are empty, the result is partial and inconclusive, not a clean no-data result, because the failed sources might contain relevant data.

The empty-window path makes no Ollama call and executes no hypothesis-driven searches.

## Telemetry inventory

Add a focused `romulus/telemetry/` package:

- `models.py`: telemetry category, availability, source measurement, and inventory types.
- `profiles.py`: deterministic field-family definitions and scoring.
- `inventory.py`: combines adapter measurements into the hunt inventory.

Each adapter implements a read-only `measure(window)` operation in addition to its existing search operations.

## Dataset portability and schema discovery

ROMULUS must not depend on the existing AInception index names, current sample hosts, a single operating system, or one field convention. Index patterns remain deployment configuration, while telemetry roles are inferred from the fields and values found in each configured dataset.

Schema discovery proceeds in layers:

1. Recognize common host and network conventions when present, including Elastic Common Schema, Winlogbeat, Sysmon, Linux audit, Zeek, Suricata, Arkime, and TShark field families.
2. Match type-safe aliases and field-name patterns for semantic roles such as event time, host, user, process, command, action, source/destination address, port, protocol, DNS question, file path, service, and bytes.
3. Preserve all remaining searchable fields in a bounded dataset-specific catalog. The model may use those discovered fields in guarded native searches even when deterministic code cannot assign them a standard semantic role.
4. Record ambiguous or conflicting role assignments instead of silently choosing a misleading interpretation.

Category detection is based on field capabilities and bounded sample values, not substrings in index names. Index names may be used only as a low-confidence tie-breaker. Each resolved semantic role records the original source field, field type, resolution method, and confidence.

Every searchable index must have an enforceable timestamp role. When several date fields exist, ROMULUS evaluates configured preferred names, field capabilities, and bounded samples, selects one deterministically, and records the choice. An index without a trustworthy timestamp is inventoried but cannot be searched in a strict-window hunt.

“Analyze anything it sees” means ROMULUS will inventory and expose previously unseen host/network fields rather than dropping them. It cannot recover semantics absent from the data, inspect encrypted content that was not decoded, or make an exhaustive claim when timestamps or essential entities are missing. Those conditions become explicit coverage limitations.

### Elasticsearch measurement

For configured, allowlisted indices:

1. Discover matching indices.
2. Use the field-capabilities API to identify searchable and aggregatable fields.
3. Select the timestamp field per index class.
4. Run a fixed `size=0` range-filtered request to obtain the exact or explicitly approximate record count and minimum/maximum timestamp inside the mission window.
5. Record mapping conflicts, unmapped fields, shard failures, timeouts, and count relation.

The field-capabilities request uses the mission-window range as an index filter where supported. Internal measurement queries are fixed code, never model-authored, and operate only on allowlisted indices.

### Arkime measurement

Issue an authenticated session request with the exact start and stop time, `length=1`, stable ordering, and no all-history `date=-1` behavior. Record the reported total, returned sample count, endpoint status, and requested interval.

### TShark measurement

For each allowlisted configured capture, execute a time-only display filter for the mission window, retain at most one representative packet, and drain matching output under the configured timeout to obtain the matched count. Record timeout or filter errors per capture. No packet outside the mission interval is eligible for collection.

## Telemetry categories and ranking

The inventory uses these categories:

1. `host_process`
2. `host_change`
3. `authentication`
4. `dns`
5. `network_flow`
6. `packet`
7. `unclassified_host`
8. `unclassified_network`

Each category has one status:

- `available`: records exist and the core time/entity/behavior fields are searchable.
- `partial`: records exist but one or more core fields are missing, conflicting, capped, timed out, or available from only part of the configured sources.
- `absent`: the source check succeeded but found no records or no usable fields for this category.
- `error`: the category could not be measured because every supporting source failed.

Each category records:

- Supporting source names and index/capture identifiers.
- Record count and whether it is exact.
- First and last observed timestamp inside the requested interval.
- Present core fields and missing core fields.
- Searchable and aggregatable field capability.
- Errors, timeouts, mapping conflicts, and caps.
- A numeric planning score derived from status, field completeness, and source health.

The numeric score is used only for ordering. The report always displays the underlying measurements and status.

### Core field families

- Host process: timestamp, host, process name/executable, command line, parent process, user, event/action.
- Host change: timestamp, host, user/process, target file/service/task/package/registry object, action/result.
- Authentication: timestamp, host or destination, account/user, result/action, source address, authentication method or logon type when present.
- DNS: timestamp, source/destination entity, query name, answer or response code when present.
- Network flow: timestamp, source and destination addresses, source/destination port, protocol, action/result, byte/packet counts when present.
- Packet: frame time, source/destination address, transport ports or protocol, and protocol-specific fields.
- Unclassified host/network: enforceable timestamp plus fields or sample values that indicate the domain, while standard semantic roles remain incomplete. These categories are always `partial` and retain their original field catalog for guarded model searches.

## Planning and collection behavior

The inventory, not the model, determines available source categories and field catalogs.

- ATT&CK seeds receive a support score based on their required data components and the measured categories.
- Initial hypothesis ordering prefers high-value techniques supported by `available` telemetry, then `partial` telemetry.
- Unsupported hypotheses may remain in coverage as `could not test: telemetry absent`; they do not consume search slots unless evidence from another category creates a concrete pivot.
- Model-generated searches can target only sources and fields declared available or partial by the inventory.
- Previously unseen fields remain eligible for guarded native searches when they are searchable, have bounded scalar types, and belong to an index with an enforceable timestamp.
- The deterministic coverage slot prioritizes the highest-value untested hypothesis with the strongest telemetry support.
- Report coverage distinguishes tested, not observed; not tested; and could not test because telemetry was absent or failed.

This ranking does not allow the model to select additional tools or bypass source-specific query validation.

## Strict time enforcement

Every query compiler and adapter requires a `MissionWindow` for live hunts.

- Elasticsearch wraps every query in the normalized timestamp range.
- Arkime always receives explicit `startTime` and `stopTime`.
- TShark always receives a frame-time predicate.
- Evidence-centered pivots may narrow the interval but cannot expand beyond the mission window.
- Native model-authored queries cannot supply, remove, or widen time clauses; deterministic code applies the final interval.

`_record_evidence` validates each event timestamp against the mission window. An out-of-window event is persisted with disposition `out_of_window`, excluded from reasoning, analytics, correlations, and findings, and summarized in coverage.

If an out-of-window event contains suspicious context, ROMULUS states that it was not investigated in this hunt and recommends a separate explicit interval around that timestamp. ROMULUS does not automatically launch or widen a hunt.

ROMULUS cannot infer malicious activity in dates it never queried. Reports must not imply otherwise.

## Reporting

The report trust foundation consumes the telemetry inventory and mission window.

The customer report includes:

- The exact UTC hunt window once in the assessment header.
- Telemetry category status and field completeness.
- Source counts and observed min/max timestamps.
- Empty, failed, partial, capped, and timed-out coverage in plain language.
- Unsupported hypotheses as `could not test`, separate from tested/not observed.
- Out-of-window discrepancies and recommended follow-up windows.

The technical appendix preserves field-capability details, fixed measurement queries, adapter responses without secrets, and out-of-window evidence references.

## Effectiveness evaluation

“Find all malicious activity” is evaluated only on datasets with documented ground truth.

For a fixture or controlled dataset, validation records:

- Ground-truth malicious behaviors and evidence identifiers.
- Which behavior families had supporting telemetry.
- Detected behaviors, missed behaviors, and false positive findings.
- Hypothesis/search coverage for each behavior.
- Whether a miss resulted from missing telemetry, planner/query failure, model assessment, evidence filtering, or resource limits.
- Precision and recall at the finding level when the fixture supports those metrics.

For datasets without ground truth, ROMULUS reports coverage and leads but does not claim it found all malicious activity.

## Migration and rollback

This is a behavioral contract migration; stored evidence is not modified.

### Forward path

1. Add `MissionWindow`, telemetry inventory models, and measurement methods without changing current search routing.
2. Add CLI window arguments and persist the normalized window in new hunts.
3. Route planning through inventory and enforce the empty-window stop.
4. Require mission windows in all live adapter calls and remove historical/rolling settings.
5. Update reports, documentation, examples, and validation fixtures.

Each step is testable before the next contract is enabled. Measurement calls are read-only and idempotent.

### Compatibility

- Existing SQLite investigations and evidence stay readable.
- Existing completed reports are not regenerated automatically.
- Old hunts without a mission window cannot resume.
- Legacy environment variables are ignored with a diagnostic notice.
- Objective-embedded date extraction remains for one compatibility release and is visibly deprecated.

### Rollback

Rollback restores the previous application version and configuration file. No database downgrade is required because new mission-window and inventory data live inside the existing JSON investigation state. Newer hunts remain inspectable as JSON state by the prior version, although the prior version will ignore unfamiliar fields. Rollback must not re-enable an old hunt automatically; operators start a new explicitly scoped hunt after returning to the fixed version.

## Error handling

- Invalid time input fails locally before source or model calls.
- One source measurement failure does not hide healthy sources; it marks dependent categories partial or error.
- All-source failure produces a partial failure report.
- Successful zero counts with other source failures produce an inconclusive partial report.
- Timestamp-field absence prevents searches against that index because the interval cannot be enforced.
- An adapter response outside the requested interval is quarantined and audited as a scope violation.
- Count estimates or non-equal total relations are labeled approximate.

## Testing strategy

Tests are written before production changes and cover:

- CLI requirements, timezone conversion, date-only inclusivity, maximum range, reversed ranges, and objective-date compatibility.
- Removal and non-effect of historical and rolling-window settings.
- Elasticsearch field capabilities and fixed range/count/min/max measurement.
- Arkime requests containing explicit start and stop values with no all-history behavior.
- TShark time-only measurement and timeout handling.
- Telemetry category classification, field completeness, and deterministic ranking.
- Dataset portability across ECS-style, flattened/non-ECS, Windows, Linux audit, Zeek/Suricata, and unfamiliar host/network schemas.
- Unknown searchable fields retained in guarded field catalogs rather than discarded.
- Empty-window early stop with zero Ollama calls and zero analytic searches.
- Partial empty window when another source failed.
- All-source inventory failure.
- Strict time wrapping for initial, native, indicator, and pivot searches.
- Out-of-window evidence quarantine and follow-up-window recommendation.
- Resume rejection for pre-window hunts and successful resume for scoped hunts.
- Ground-truth fixture detection, misses, and coverage attribution.

## Dependencies

This design is implemented before or alongside the report trust foundation. The report model consumes `MissionWindow` and `TelemetryInventory` as validated factual inputs. No new external service, provider credential, MCP server, or active-response dependency is introduced.
