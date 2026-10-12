# ROMULUS Report Trust Foundation Design

## Purpose

ROMULUS will produce a concise threat-hunting report that tells a decision maker what was found, how confident ROMULUS is, what coverage limits apply, and what action should happen next. A separate technical appendix will preserve the evidence, search, reasoning, and run details required by a SOC analyst to reproduce every factual claim.

This design covers the report trust foundation and the evidence-quality defects that directly affect report conclusions. ATT&CK Navigator output and source-side aggregation queries are separate follow-on changes because they extend external output formats and data acquisition behavior.

## Success criteria

- Pages one and two of the customer report communicate verdict, confidence, affected assets, scope, material limitations, and the next action without internal tool names or raw telemetry.
- Every reported finding resolves to durable evidence records. Unresolvable evidence references prevent the affected finding from appearing as a supported customer finding and create a visible validation warning.
- The technical appendix contains the investigation trace, search artifacts, source errors, hypotheses, evidence index, and exact reproducibility references that are removed from the customer report.
- Counts, timestamps, technique names, technique URLs, coverage states, and verdicts are derived deterministically from one validated model.
- Rebuilding outputs from the same normalized report JSON produces the same factual content and ordering.

## Scope

### Included

- A validated intermediate report model serialized as JSON.
- A customer-facing DOCX report.
- A technical-appendix DOCX.
- Evidence-ID resolution against the durable evidence store.
- Full bundled ATT&CK catalog lookup for technique ID, name, tactics, platforms, version, and official URL.
- Deterministic overall verdict, finding status, severity, confidence, coverage, and limitation rules.
- Curated, evidence-cited timelines without raw log lines.
- Entity and observable extraction with cautious assessments.
- Detection of collection artifacts, ambiguous audit PATH lookup records, audit-rule labels, and insufficiently contextualized sensitive-file records.
- Plain-language treatment of source failures, caps, incomplete hypotheses, and resource-limit termination.
- Updated report tests and offline integration tests.

### Deferred

- ATT&CK Navigator layer JSON.
- New Elasticsearch or Arkime aggregation APIs.
- Scheduled or continuous hunt orchestration.
- Automated containment or remediation.
- LLM-written report prose. Version one uses deterministic prose assembled from validated facts; a later narrative provider can be added behind the same report model.

## Architecture

The reporting package is split into three responsibilities:

1. `report_model.py` defines the validated intermediate schema and enums.
2. `report_builder.py` converts investigation state, durable evidence, and audit records into that schema. It performs evidence resolution, ATT&CK lookup, timeline selection, entity extraction, artifact classification, and verdict calculation.
3. `report.py` renders the validated model into the customer DOCX, technical appendix DOCX, and canonical JSON.

The hunt workflow passes the complete durable evidence set and its audit records to report generation. Report generation no longer relies only on the bounded graph context.

The generated files are:

- `<hunt-id>-report.docx`
- `<hunt-id>-technical-appendix.docx`
- `<hunt-id>-report.json`

The JSON is the source of truth for both documents. Stable filenames intentionally replace the timestamped filenames; regeneration updates the same investigation artifacts.

## Intermediate model

Pydantic v2 supplies strict validation and JSON serialization. Unknown fields are rejected within the report model. Input hunt state remains backward compatible and is normalized before validation.

The top-level `HuntReport` contains:

- `schema_version`: fixed to `1.0`.
- `metadata`: hunt ID, objective, generated timestamp taken from recorded state, hunt window in UTC, report status, explicit information marking, prepared-by, prepared-for, and ATT&CK release.
- `assessment`: overall verdict, severity, confidence, confidence rationale, strongest benign alternative, decision requested, and actions that could raise or lower confidence.
- `findings`: normalized findings with stable IDs, status, severity, confidence, evidence references, affected assets, ATT&CK mappings, benign alternatives, and follow-up actions.
- `timeline`: at most 20 significant normalized events, ordered by UTC timestamp. Repeated equivalent events may be collapsed with a deterministic count and first/last time.
- `entities`: hosts, accounts, processes, paths, IPs, and domains extracted from cited evidence.
- `observables`: observed values with context and cautious assessments. The model uses `observed`, `suspicious`, or `known_malicious`; the builder never assigns `known_malicious` without an explicit validated finding field.
- `attack`: observed or suspected technique rows for the main report and tested/not-observed, not-tested, and could-not-test rows for compact coverage.
- `coverage`: hypothesis outcomes, source scopes, caps, errors, incomplete searches, and material gaps.
- `limitations`: plain-language statements with their effect on conclusions.
- `recommendations`: prioritized actions with owner role, timeframe, validation steps, and related finding IDs.
- `validation_warnings`: unresolved citations, invalid ATT&CK mappings, platform mismatches, scope discrepancies, and malformed input.
- `appendix`: reasoning history, stage history, tool runs, search artifacts, hypotheses, correlations, run metrics, and the evidence index.

Every factual customer-facing finding references at least one evidence ID in `appendix.evidence_index`. Coverage claims use search artifact IDs or run records rather than pretending a search operation is an event.

## Evidence classification

Each durable evidence record receives one of these report dispositions:

- `eligible`: may support findings and customer timeline entries.
- `collection_artifact`: contains an explicitly configured or recognized ROMULUS/AInception collection path or collector process. It remains in the appendix but cannot support a customer finding by itself.
- `audit_path_lookup`: an audit PATH record with `nametype=UNKNOWN` and no paired successful open/read syscall context. It remains in the appendix and cannot support sensitive-file-access claims.
- `detection_label_only`: the only ATT&CK-like support is an audit rule `key`; the key is retained as metadata but cannot establish technique evidence.
- `insufficient_context`: a sensitive-file record lacks process, effective user, audit user, or syscall/access context. It may appear in limitations and the appendix but not as a supported finding.

Classification is conservative. Records are preserved rather than deleted. A finding whose citations are all ineligible is demoted to inconclusive appendix material and produces a customer-visible validation warning.

For `/etc/shadow`, `/etc/passwd`, PAM, and other sensitive authentication files, the normalized context includes process/executable, `uid`, `auid`, syscall, and known daemon context when available. `auid=4294967295` is described as an unset login audit identity, commonly associated with system or daemon context; it is not automatically declared benign.

## ATT&CK validation

The bundled Enterprise ATT&CK catalog is the authority for technique identifiers, names, tactics, platforms, version, and URLs. Curated search knowledge may add selectors but is not the report lookup authority.

- Unknown or blank technique IDs never appear in the customer ATT&CK table.
- Exploratory hypotheses remain in the appendix and coverage section with an explicit `exploratory/unmapped` state.
- A mapped technique must be compatible with the evidence platform when the platform can be determined. Windows-only mappings cannot be supported solely by Linux evidence, and Linux-only mappings cannot be supported solely by Windows evidence.
- A platform mismatch demotes the mapping from the customer finding, records a validation warning, and preserves the original hypothesis in the appendix.
- The report records ATT&CK release `v19.2` and includes the official technique URL.

## Deterministic assessment rules

Verdict, confidence, and severity are separate fields.

### Verdict

- `Confirmed Malicious` is never assigned automatically in this version.
- `Suspicious - Triage Needed` requires at least one eligible finding with resolvable evidence and moderate or high confidence, with no fatal evidence-validation warning for that finding.
- `Inconclusive` applies when findings exist only at low confidence, evidence is insufficient, material source failures/caps prevent discrimination, the run ended on a resource or workflow limit with open high-priority coverage, or findings were demoted during validation.
- `No Evidence Found` applies only when no eligible findings exist, required sources completed without material errors, and high-priority coverage is closed. It explicitly means no evidence was found in the tested scope.

### Confidence

- `High`: multiple independent eligible evidence sources corroborate the same finding and material benign alternatives were tested.
- `Moderate`: eligible evidence supports the finding but corroboration or benign-alternative testing is incomplete.
- `Low`: evidence is singular, sampled, ambiguous, weakly attributed, or follow-up searches returned no support.

If all completed follow-up searches related to a finding returned zero results, the finding confidence cannot exceed Low and the report says so.

### Severity

Severity describes potential defensive impact, not confidence. It is derived from explicit finding severity when validated; otherwise ROMULUS uses a small deterministic technique-impact table and defaults to `Informational`. Severity never changes the evidence threshold for a verdict.

## Customer report

The customer report uses this order:

1. Header and assessment block.
2. Executive summary and at-a-glance table.
3. Scope and approach.
4. Findings.
5. Attack narrative and curated timeline.
6. ATT&CK mapping and compact coverage.
7. Affected assets and entities.
8. Indicators and observables.
9. Hunt coverage and gaps.
10. Assessment and confidence.
11. Recommendations.
12. Short glossary and appendix pointer.

The report uses the configured information marking; the default is `UNMARKED`, not an inferred TLP designation. Headers and footers contain the report ID, marking, and page number. Tables repeat header rows across page breaks. Blank values render as `Not recorded` or the row is omitted. Python representations, JSON blobs, raw log lines, internal tool names, reasoning prompts, and query DSL do not appear.

## Technical appendix

The appendix contains:

- Validation warnings and model/schema version.
- Run metrics and termination details.
- Source coverage, caps, errors, and search artifacts.
- Full hypotheses and assessments.
- Reasoning and stage history.
- Tool-call audit metadata with credentials redacted.
- Correlations and caveats.
- Evidence index with normalized observation, source, timestamp, asset, provenance reference, disposition, and bounded raw excerpt.

The appendix does not reproduce secrets. Exact large queries and complete raw events remain in the existing audit log and SQLite store, with paths stated in the appendix.

## Configuration

Add these environment-backed settings:

- `REPORT_MARKING`, default `UNMARKED`.
- `REPORT_PREPARED_BY`, default `ROMULUS`.
- `REPORT_PREPARED_FOR`, default empty and rendered as `Not specified`.
- `COLLECTION_ARTIFACT_PATHS`, comma-separated path prefixes, defaulting to `/home/user/ainception-agent/data/staging`.
- `COLLECTION_ARTIFACT_PROCESSES`, comma-separated process names, default empty.

These values become fields on `Settings` and are passed to the report builder. They are not inferred by the model.

## Error handling

- Schema validation errors fail report generation and leave the hunt in a partial state with the validation class recorded.
- Finding-level unresolved citations or ATT&CK mismatches do not crash the entire report. They demote the affected finding and add prominent warnings.
- Missing optional metadata renders neutral placeholders.
- A missing `python-docx` dependency remains a report-generation failure.
- XML-invalid telemetry characters are removed before model construction and rendering.

## Testing strategy

Tests are written before implementation and cover:

- Schema acceptance and rejection.
- Stable JSON serialization and deterministic ordering.
- Evidence-ID resolution and finding demotion.
- Collection artifact, ambiguous PATH lookup, detection-key, and sensitive-file context classification.
- Full-catalog ATT&CK lookup and platform mismatch handling.
- Verdict behavior for suspicious, inconclusive, no-evidence, capped, errored, and resource-limited hunts.
- Separate customer and appendix rendering, including prohibited customer-report content.
- Offline synthetic hunt integration using durable evidence and audit records.
- Backward-compatible normalization of sparse or older hunt states.

The existing live-hunt record is not stored as a portable fixture in this checkout, so a golden test for `HUNT-E5ED6B713B` requires a sanitized state/evidence fixture before it can be added. The implementation will instead add an equivalent synthetic regression fixture covering the documented failure modes.

## Migration and compatibility

The `generate_report` entry point remains available but accepts optional full evidence, audit records, and settings. Callers that provide only state continue to receive valid reports built from state evidence. The returned `report_paths` list expands from two timestamped files to the stable customer DOCX, appendix DOCX, and report JSON. README and tests are updated to describe these artifacts.

No stored investigation schema migration is required. Existing hunts can be regenerated by loading their state, durable evidence, and audit records.
