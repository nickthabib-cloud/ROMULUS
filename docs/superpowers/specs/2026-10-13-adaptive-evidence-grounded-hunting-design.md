# Adaptive Evidence-Grounded Hunting Design

## Purpose

ROMULUS must behave like a persistent host, network, and intelligence analyst team without inventing an attack story. A broad hunt begins with deterministic telemetry discovery. It creates no hypothesis until telemetry produces a concrete lead. After a lead exists, model reasoning may formulate and test competing explanations, search backward and forward in time, and assemble an evidence-cited attack path. Deterministic code remains the authority for what was observed, what may be searched, and what may be published.

This continuation fixes two limitations left after representative retrieval and scheduler consolidation:

1. The current production defaults of ten minutes, ten reasoning rounds, and 160 external calls can end a productive hunt because early validation needed short runs.
2. The model currently assesses deterministic hypotheses but cannot contribute enough evidence-grounded investigative reasoning to reconstruct a novel attack path.

The design does not make the model an unconstrained autonomous agent. It gives the model a richer case file and a disciplined investigator/critic loop while keeping source access, evidence identity, query validation, scheduling priority, finding admission, and reporting deterministic.

## Success Criteria

- An undirected hunt makes no model call and creates no hypothesis before a deterministic telemetry candidate exists.
- Every model hypothesis, assessment, search, and finding cites visible candidate or evidence identifiers. Unsupported output is rejected and recorded, never repaired by inventing facts.
- ROMULUS continues while measurable investigative progress or a productive unresolved frontier exists, rather than stopping at an ordinary ten-minute or ten-round threshold.
- Configured runtime, call, and round limits remain emergency safety backstops. Hitting one produces a partial, resumable hunt and never a clean conclusion.
- Repeated reasoning or searches that add no evidence, disposition change, path expansion, or coverage improvement eventually stop through an explicit stagnation policy.
- Findings and attack paths contain only validated evidence records and qualified relationships. Missing stages remain named gaps.
- Completed compact hunts retain reports, cited evidence, compact path/coverage/progress summaries, and source errors while removing working bulk.
- A blind holdout hunt can be scored after completion without exposing oracle identities, timestamps, tools, commands, or sequence details to runtime code, prompts, catalogs, or committed fixtures.

## Chosen Architecture

Three approaches were considered:

1. Raising or removing limits only would allow longer hunts but would also allow duplicate, low-yield work to consume time without improving reasoning.
2. Giving the model direct control of hypotheses, priorities, and tools would increase flexibility but make hallucinated leads and unsafe or redundant searches materially more likely.
3. A progress-aware hybrid controller preserves deterministic evidence and execution boundaries while allowing grounded model reasoning after a lead. This is the selected design.

The implementation is divided into three sequential milestones. Each milestone produces independently testable behavior and a durable validation record.

## Milestone 7: Adaptive Stopping and Progress Ledger

### Progress model

A focused `romulus/investigation/progress.py` module will compare persisted investigation snapshots. The module does not inspect prose and does not call the model. It measures only stable state transitions:

- newly admitted evidence IDs;
- newly created deterministic candidates;
- candidate disposition or required-follow-up changes;
- new accepted execution fingerprints;
- completed resolving or informative search outcomes;
- hypothesis assessment changes;
- new evidence/entity/activity graph nodes or relationships;
- supported attack-path growth; and
- closed source, candidate, or hypothesis coverage gaps.

Large raw counts alone are not progress. Re-reading the same records, registering a duplicate task, repeating an assessment, or generating unsupported output is explicitly non-progress.

Each reasoning/search cycle records a bounded progress entry containing counters, changed IDs, a machine-readable reason, and whether a productive frontier remains. Full entries are working state; compact retention preserves aggregate totals and the final stop basis.

### Stop controller

Routing uses a deterministic stop decision with this precedence:

1. Invalid mission scope or an empty checked telemetry window stops before reasoning.
2. A hard runtime, external-call, or reasoning-round ceiling stops the hunt as partial and resumable.
3. Candidate-aware coverage closure with no productive queued work completes the hunt.
4. Queued critical/high work or an evidence-grounded unresolved frontier continues.
5. Consecutive cycles with no material progress and no high-value queued work increment a stagnation counter. Three stagnant cycles stop with `no_productive_frontier`; incomplete coverage remains partial.

The model's `continue_investigation` value is advisory. It cannot override a hard safety ceiling, declare coverage closed, or keep an investigation alive without new admissible work.

### Runtime settings

Production defaults become high safety backstops rather than expected run length:

- `MAX_RUNTIME_SECONDS=3600`
- `MAX_DEPTH=40`
- `MAX_TOOL_CALLS=500`
- `MAX_STAGNANT_CYCLES=3`

The accepted finite ranges are 1–5,000 external calls, 1–200 reasoning rounds, 10–86,400 seconds, and 1–10 stagnant cycles. Existing names stay compatible. `MIN_REASONING_ROUNDS` remains loadable for one compatibility cycle but is deprecated as a routing requirement: ROMULUS must not force empty model turns merely to satisfy a minimum. Tests and bounded validation commands set small limits explicitly in their own settings instead of changing production defaults.

The report distinguishes `coverage_closure_reached`, `no_productive_frontier`, `runtime_budget`, `tool_call_budget`, and `depth_budget`. Only validated closure can support a completed coverage status.

## Milestone 8: Evidence-Grounded Investigator and Critic

### Case file

Each reasoning turn receives a bounded structured case file rather than an undifferentiated evidence sample. It contains:

- mission and explicit time scope;
- visible candidate IDs and their exact evidence IDs;
- existing hypotheses, status, expected observations, and benign alternatives;
- compact entity/activity timeline and supported path fragments;
- exact completed-search outcomes and unresolved follow-ups;
- source health, sampling limits, and coverage gaps; and
- a novelty summary identifying recently changed facts.

Telemetry text remains untrusted data. The case file exposes no arbitrary tool interface and contains only source fields and evidence already admitted by deterministic code.

### Grounded hypothesis admission

After a deterministic lead exists, the investigator may propose a small number of competing hypotheses. A proposal is admitted only when it:

- cites at least one visible candidate ID and one visible evidence ID owned by that candidate;
- identifies the observed entity or time cluster that anchors the explanation;
- states expected supporting observations and at least one falsifying or competing observation;
- uses the candidate's deterministically supported ATT&CK mapping or remains `unmapped`; and
- proposes only searches that can discriminate the explanation through configured read-only sources.

No lead means no model hypothesis. An unknown citation, unrelated entity, unsupported ATT&CK mapping, or prose-only assertion causes rejection. Rejection never creates a replacement fact.

### Investigator/critic cycle

The investigator assesses current explanations and proposes bounded discriminating searches. A separate critic pass reviews only the structured proposal and cited case file, looking for citation mismatch, unsupported causality, ignored benign explanations, duplicated work, and a cheaper decisive search. Deterministic validators apply the final decision.

The critic cannot add evidence, create a new lead, change scheduler priority, or publish a finding. If the critic or model is unavailable, deterministic candidate investigation continues and the report records the reasoning gap.

### Search and path behavior

Accepted searches use the existing unified scheduler and exact execution fingerprinting. Code assigns priority. The investigator expands both backward and forward from evidence anchors and may pivot across host and network sources, but every time window and entity selector is derived from validated evidence or the operator's explicit mission.

The existing evidence graph remains factual. Temporal proximity is not causation. Model-proposed relationships may guide searches but enter a reported path only when deterministic graph rules can express their evidence basis and caveat. Alternative branches and missing stages remain visible instead of being collapsed into one confident story.

### Finding admission

The existing evidence-citation and entity checks remain mandatory. A finding must name an admitted supported hypothesis and cite the checked records that support its observation. Published title, observation, confidence basis, ATT&CK mapping, and path are constructed from validated state rather than copied from model prose.

## Milestone 9: Blind Generalization Evaluation

The newly loaded Russell Mitchell telemetry is a blind holdout. Its storyline and supporting oracle files remain outside ROMULUS runtime inputs. Exact addresses, accounts, domains, products, vulnerability identifiers, commands, filenames, shell paths, and timestamps from that storyline must not enter runtime code, prompts, analytic catalogs, or committed test fixtures.

After Milestones 7 and 8 pass synthetic, local, and dependency-complete VM checks, ROMULUS will run one read-only hunt over the operator-authorized holdout window. Only after the hunt is finalized will an evaluation tool or manual comparison read the oracle. Scoring will cover:

- attack-stage recall and precision;
- key entity and relationship recall;
- temporal ordering of supported steps;
- unsupported findings and incorrect technique labels;
- whether gaps are honestly named;
- source coverage and retrieval limitations; and
- runtime, reasoning turns, external calls, duplicate suppression, and stop basis.

Misses are classified as retrieval, normalization, candidate generation, hypothesis reasoning, correlation/path construction, admission, or reporting defects. Fixes must be general behavior primitives expressed with independent synthetic variants and benign controls. The holdout never becomes a list of indicators or an expected sequence ROMULUS searches directly.

If a generic fix is made after examining the oracle, the Russell dataset becomes a regression corpus rather than fresh generalization evidence. A later independent dataset is required before claiming general attack-path generalization.

## Persistence and Retention

Progress snapshots, critic payloads, rejected proposals, and detailed reasoning histories are working data. Under the default `compact` policy, successful report verification occurs before cleanup. Compact state keeps:

- report paths and conclusions;
- findings and cited evidence;
- supported path and explicit gaps;
- aggregate scheduler, sampling, reasoning, and progress counts;
- the final stop decision and safety ceiling usage; and
- source and model availability errors.

It removes uncited evidence, full proposals and critic payloads, detailed progress history, query/task history, hunt-scoped JSONL working rows, and checkpoints. Partial hunts remain resumable until explicitly finalized.

## Error and Safety Behavior

- Source failures do not become zero-result evidence and cannot close coverage.
- Model failure does not erase deterministic progress or trigger invented fallback findings.
- Invalid or duplicate model searches are rejected before source access.
- Safety-ceiling exhaustion records every unexecuted queued task and produces a partial report.
- Stagnation can stop wasteful work but cannot convert incomplete or unavailable telemetry into a clean conclusion.
- Resume restores the last progress baseline and stagnation count so a restart neither forgets work nor immediately double-counts it.
- No active scan, endpoint modification, credential use beyond configured read-only services, or arbitrary command execution is introduced.

## Testing Strategy

Milestone 7 tests use synthetic states to prove each progress signal, duplicate/non-progress behavior, persisted stagnation, resume behavior, priority precedence, higher production defaults, explicit low test bounds, and honest report status.

Milestone 8 tests prove the no-lead/no-hypothesis invariant, valid grounded competing hypotheses, rejection of unknown or unrelated citations, unsupported mapping rejection, investigator/critic role separation, scheduler authority, model-unavailable fallback, and path/report citation integrity. Fixtures use unrelated synthetic identities and behaviors.

Milestone 9 begins only after the full local suite, compilation, diff checks, dependency-complete VM suite, `doctor`, and a disposable offline hunt pass. The live holdout hunt remains bounded, read-only, isolated from operational hunt state, and followed by exact cleanup of disposable working artifacts.

## Roadmap and Checkpoints

1. Implement and validate adaptive stopping and the progress ledger.
2. Implement and validate the evidence-grounded investigator/critic cycle.
3. Run the blind Russell Mitchell holdout evaluation and classify misses.
4. Add only general, independently tested behavior improvements for demonstrated misses.
5. Re-run regression evaluation and record what is and is not proven.

Progress summaries are provided at each checkpoint. These are visibility checkpoints, not authorization pauses; implementation continues unless verification fails, the design must materially change, or an external side effect requires specific approval.
