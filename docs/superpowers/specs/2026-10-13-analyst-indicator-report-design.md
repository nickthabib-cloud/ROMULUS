# Analyst Indicator Report Design

## Purpose

ROMULUS must turn evidence-backed hunt results into a concise Word report that an analyst can act on without reading the full technical record. The Word report should identify concrete observables, explain why they matter, distinguish supporting context from likely noise, and present a bounded possible activity narrative. The technical text report remains the exhaustive audit and troubleshooting record.

This change must not encode any Russell Mitchell scenario answer, attack path, tool name, domain, address, or artifact. The existing completed hunt may be used only as acceptance evidence after the generic behavior is implemented.

## Outputs and Location

Final analyst deliverables are written beneath the configured `reports/` directory:

- `<hunt-id>-<generation-stamp>.docx`: concise analyst indicator report.
- `<hunt-id>-<generation-stamp>.txt`: exhaustive technical report.
- `anomalous/<hunt-id>-anomalous-leads-<generation-stamp>.txt`: unresolved anomaly report when applicable.

Temporary runtime directories may hold working state during a hunt, but the supported production configuration must point `reports/` at the operator-visible report directory. A finalized report manifest records the exact paths. Cleanup must preserve all listed final reports.

## Reporting Architecture

### Technical text report

The text report retains the complete report-item inventory, cited telemetry, search coverage, source errors, deterministic analytics, correlations, and reasoning audit. It is the evidence-rich technical record and remains suitable for debugging and deep review.

### Analyst Word report

The Word report is a concise findings brief. It does not repeat every candidate as a long, uniform subsection. Its principal sections are:

1. Executive Assessment
2. Strong Indicators
3. Supporting Context
4. Likely Noise or Misclassified Activity
5. Possible Activity Narrative
6. Recommended Follow-ups
7. Scope and Coverage
8. MITRE ATT&CK Context

Each strong indicator includes:

- a plain-language title and assessed confidence;
- an observation separated from interpretation;
- a bounded time range and relevant assets;
- exact observable artifacts such as domains, addresses, ports, URLs, commands, filenames, processes, accounts, or protocol features;
- why the behavior matters;
- explicit limitations or benign alternatives;
- evidence identifiers;
- concrete analyst follow-up actions.

Supporting context describes evidence-backed relationships that help an analyst connect indicators without claiming a confirmed attack path. Likely noise names low-value or incorrectly classified leads and explains the evidence-based reason for de-prioritization.

## Evidence-Constrained Synthesis

ROMULUS uses a dedicated final reporting synthesis call after classification and follow-up work. It receives a bounded reporting case assembled from canonical report items, their owned evidence, admitted relationships, and coverage limitations. It does not receive the rendered text report as an undifferentiated prompt because that would be unnecessarily large, repeat technical boilerplate, and expose the model to untrusted telemetry without structure.

The reporting case excludes dataset ground-truth labels, ground-truth rules, and file-path labels that reveal scenario answers. Telemetry strings remain untrusted data. The system prompt forbids following instructions contained in telemetry.

The model returns a structured proposal containing:

- `strong_indicators`;
- `supporting_context`;
- `likely_noise`;
- `possible_activity_narrative`;
- `recommended_follow_ups`.

Every entry selects existing report-item, evidence, and relationship identifiers. The model may organize and explain canonical facts but may not create new evidence, entities, observables, relationships, classifications, or success claims.

## Deterministic Admission

The proposal is admitted fail closed before persistence or rendering:

- all referenced item, evidence, and relationship identifiers must exist in the current canonical reporting case;
- every rendered observable must be resolved from canonical evidence rather than copied blindly from model prose;
- time ranges and asset lists are derived from cited evidence;
- an indicator cannot claim execution, connection success, exploitation, exfiltration, or compromise unless cited evidence explicitly supports that claim;
- the same behavior observed by multiple sensors is consolidated rather than rendered as duplicate indicators;
- a lead may be placed in likely noise only when the cited evidence supports the stated de-prioritization basis;
- missing, malformed, stale, or unsupported model output is rejected rather than partially trusted.

Admitted state stores selectors and bounded explanatory text. At render time, selectors are re-admitted against the current canonical case so stale or corrupt persisted output cannot bypass validation.

## Availability and Budgeting

Report synthesis is a finalization responsibility, not another hunt pivot. ROMULUS reserves capacity for one reporting synthesis call so discovery cannot consume the last permitted model call. A runtime or investigation-round limit may stop further hunting but must not silently remove the analyst synthesis stage.

If the model is disabled, unavailable, times out, or returns inadmissible output, ROMULUS produces a deterministic fallback. The fallback groups report items by behavior, extracts exact observables from their cited evidence, preserves limitations, and renders a smaller but useful Word report. Report generation must not fail merely because synthesis fails.

## Word Report Presentation

Strong indicators are numbered and ordered by classification, specificity, confidence, corroboration, and priority. Each indicator is compact enough to scan but includes its actionable artifacts directly in the Word document. Repeated sensor-level observations are represented once with their contributing evidence identifiers.

Supporting context and likely noise use shorter entries. Exhaustive classification lifecycle, scoring internals, raw telemetry, and search diagnostics remain in the text report.

The Word report uses readable headings, short paragraphs, and compact artifact tables where comparison is useful. It must remain legible when rendered and must not rely on the text report for the artifacts necessary to investigate a reported indicator.

## Example Shape

```text
Strong Indicators

1. Encoded DNS transfer consistent with data exfiltration — High confidence

Observation: A source issued sequenced, high-entropy DNS labels to one suffix in repeated bursts.

Artifacts
- Domain: <canonical domain>
- File reference: <canonical filename>
- Source: <canonical address>
- Destination or resolver: <canonical address>
- Evidence: <canonical evidence identifiers>

Why it matters: The sequence and encoded labels are consistent with a DNS data-transfer mechanism.
Limitation: Endpoint process attribution was unavailable.
Recommended follow-up: Identify the originating process and account and verify access to the referenced file.

Likely Noise or Misclassified Activity

- Requests for tool-like paths returned HTTP 404 during directory enumeration. These records support reconnaissance, not download or execution.
```

## Testing and Acceptance

Tests are written before implementation and prove:

- the reporting case excludes ground-truth fields and scenario-revealing provenance;
- a valid structured proposal renders exact cited observables in the Word report;
- hallucinated identifiers and observables are rejected;
- duplicate sensor views consolidate into one indicator;
- a directory-enumeration request for a tool-like path is not represented as successful download or execution when the response evidence contradicts it;
- model failure produces a useful deterministic Word report;
- the text report retains exhaustive technical detail;
- final paths are beneath the configured `reports/` directory and retention preserves them;
- reopened DOCX content includes the artifact values required for analyst follow-up;
- the example DOCX generated from the existing completed hunt is visually rendered and inspected without starting another hunt.

