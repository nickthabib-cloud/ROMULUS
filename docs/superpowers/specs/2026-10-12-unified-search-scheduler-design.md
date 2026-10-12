# ROMULUS Unified Search Scheduler Design

**Date:** 2026-10-12  
**Status:** Conversational design approved; pending written-spec review  
**Scope:** Search registration, prioritization, deduplication, execution outcomes, budgets, coverage, and resume behavior

## Purpose

ROMULUS currently schedules work through separate baseline-collection loops, a one-shot initial model plan, iterative model planning, and deterministic coverage fallback. Those paths do not share one ordering policy or one outcome contract. Exact duplicate suppression applies mainly to model searches, host collection can consume budget before network discovery, and candidate follow-up bookkeeping can receive a prior pivot's result instead of the result of its own search.

This milestone gives one deterministic scheduler ownership of every evidence-retrieval search while preserving ROMULUS's existing guarded source adapters and evidence-first reasoning rules. Success means finite hunt time is spent on the highest-value nonduplicate work, every configured telemetry family receives fair initial attention, and closure is based on the exact outcome of each required task.

This specification narrows the unified-scheduler milestone in `2026-10-12-super-hunter-investigation-loop-design.md`. The already-delivered candidate, attack-path, reporting, and retention contracts remain authoritative.

## Goals

1. Represent deterministic catalog searches, indicator searches, directed surveys, candidate follow-ups, model proposals, and coverage-frontier work as one search-task type.
2. Register and deduplicate tasks before execution, merging ownership when one execution satisfies multiple hypotheses or candidate follow-ups.
3. Select work through one deterministic priority and source-fairness policy.
4. Persist the queue, attempts, and terminal outcomes so resumes do not reconstruct a different plan.
5. Give candidate and hypothesis coverage the exact outcome of the task that tested them.
6. Preserve the rule that an undirected hunt makes no model call before deterministic telemetry produces a candidate.
7. Preserve all source-specific validation, allowlists, time bounds, caps, and read-only execution controls.

## Non-goals

- Add new telemetry sources, behavior analytics, threat-intelligence providers, or active-response capabilities.
- Rewrite Elasticsearch, Arkime, or TShark query languages or adapters.
- Let a model create evidence, alter deterministic candidate scores, bypass validation, or force a task ahead of a higher scheduler tier.
- Remove the existing scenario-specific finding publishers; they require a separate behavior-preserving milestone.
- Change customer-report or compact-retention policy.
- Promise exactly-once remote execution across a process crash. Searches are read-only; interrupted attempts remain visible and may be retried once under the normal budget.

## Current Structural Problems

1. `_collect_host` executes behavior seeds, indicators, surveys, and initial model host searches directly.
2. `_collect_network` independently executes broad Arkime/PCAP work, indicators, and initial model network searches.
3. `_reason` combines up to two model searches with `_coverage_fallback`, then `_pivot` uses a different execution path for fingerprinted and static leads.
4. `dynamic_plan_created` is set before an undirected hunt has candidates, making the initial-plan lifecycle one-shot and phase-dependent.
5. `completed_leads` records attempts before or outside authoritative result creation. It therefore cannot distinguish successful resolution from failed, capped, skipped, or budget-limited work.
6. Fingerprints cover validated model specifications but not every deterministic search.
7. Candidate follow-up recording reads the last generic pivot record; model search outcomes live elsewhere, so the recorded result can be stale or unrelated.

## Architecture

### Scheduler boundary

Create `romulus/investigation/scheduler.py` as a pure scheduling and state-transition module. It does not call adapters or the model. It accepts normalized tasks, merges duplicates, chooses the next runnable task, and records outcomes supplied by the workflow.

`workflow.py` remains the orchestration boundary. It discovers schemas and source health, compiles source-safe tasks, asks the model for proposals only when allowed, executes the scheduler's selected task through existing adapters, records evidence, and returns the exact execution outcome to the scheduler.

Schema discovery, mapping retrieval, source health checks, and report generation are prerequisites or lifecycle operations rather than evidence searches. They continue to use the existing guarded call wrapper and hunt-wide budget, but they do not enter the search queue.

### Search task contract

Each task is a JSON-serializable lifecycle wrapper around the existing validated `SearchPlan` contract, not a second query language. It has these fields:

- `task_id`: stable ID derived from the execution fingerprint.
- `execution_fingerprint`: hash of the normalized source, effective source targets/class, compiled selectors or native query, and effective time window.
- `source`: `elasticsearch`, `arkime`, or `tshark`.
- `source_family`: `host` or `network` for fairness accounting.
- `source_targets`: sorted effective index names, capture identifiers, or the Arkime deployment identifier used by the task.
- `phase`: `discovery` or `investigation`.
- `origin`: `behavior_catalog`, `trusted_indicator`, `directed_survey`, `candidate_follow_up`, `model_proposal`, or `coverage_frontier`.
- `intent`: bounded analyst-readable purpose.
- `query_spec`: the already validated source-specific plan or deterministic compiled query inputs.
- `time_range`: mission range or an evidence-anchored subrange that cannot exceed it.
- `candidate_ids`, `follow_up_ids`, and `hypothesis_ids`: all owners satisfied by the execution.
- `anchor_evidence_ids`: retained evidence that justifies an anchored task.
- `priority_tier` and `priority_score`: deterministic scheduling values; model-supplied priority is ignored.
- `status`: `queued`, `running`, `completed`, `partial`, `failed`, `skipped`, `budget_limited`, or `interrupted`.
- `attempt_count`, `created_sequence`, and `last_attempt_at`: resume and stable-order metadata.

Task payloads contain no credentials, response bodies, or uncapped raw evidence.

### Deduplication and ownership merging

Deduplication uses what will actually execute, not the task's prose or origin. Two tasks are duplicates only when their normalized source, source targets/class, effective query/selectors, and effective time range match. Similar intents with different selectors, targets, or windows remain separate.

When a duplicate is registered, the scheduler keeps one task and merges candidate, follow-up, hypothesis, anchor, and origin references. The strongest deterministic priority wins. One terminal outcome is then applied to every merged owner, preventing redundant searches without losing closure credit.

Fingerprint registration does not imply completion. A fingerprint moves to terminal history only after an execution outcome is recorded.

### Scheduling phases and priority

#### Discovery phase

An undirected hunt registers deterministic tasks only. A directed hunt may additionally register searches grounded in the operator's explicit behavior, entity, indicator, or technique. Model planning remains prohibited for an undirected hunt until at least one deterministic candidate exists.

Before additional work from one telemetry family runs, every healthy configured family with an executable discovery task receives one opportunity. If the remaining hunt budget cannot cover both host and network discovery, the scheduler records the unserved family as a budget gap and the hunt remains partial.

After the fairness reservation, remaining discovery tasks are ordered by:

1. Valid, unexpired trusted indicators.
2. Higher behavior-catalog priority and specificity.
3. Operator-directed surveys.
4. Remaining broad coverage value.
5. Stable creation order as the final tie-breaker.

#### Investigation phase

After analysis creates candidates, work is ordered in these tiers:

1. Required follow-ups for critical candidates or trusted-indicator matches.
2. Required follow-ups for high-priority candidates and explicit operator-directed hypotheses.
3. Evidence-anchored model proposals and remaining candidate follow-ups.
4. Unexecuted deterministic coverage-frontier tasks.
5. Bounded review of unresolved medium/low candidates when higher tiers are exhausted.

Within a tier, the scheduler prefers the source family with fewer completed attempts, then higher deterministic candidate/coverage score, then stable creation order. The model cannot choose or override the tier.

Each reasoning round may register new validated tasks, but execution still flows through the same persisted queue. A default round selects at most three tasks, retaining the existing bounded investigation shape without creating a new configuration surface.

### Authoritative outcomes

Every task attempt produces one outcome containing:

- Task and attempt identity.
- Start/end timestamps and source.
- `status`, returned count, matched total when known, cap/timeout indicators, and bounded error class/reason.
- Search artifact ID and effective time range.
- Whether the result is closure-resolving.

Only an uncapped successful `completed` outcome is resolving. A successful zero-result search may resolve its task when the source confirms zero matches. `partial`, `failed`, `skipped`, `budget_limited`, and `interrupted` outcomes remain unresolved and must surface as coverage limitations.

The outcome is passed directly to every owning candidate follow-up and hypothesis. Code no longer infers a candidate result from the most recent unrelated pivot record.

`completed_leads` remains as a compatibility projection of task IDs with terminal attempts. Coverage and closure use scheduler outcomes, not membership in that list.

### Budget behavior

The existing `MAX_TOOL_CALLS`, runtime limit, result caps, and reasoning-depth limit remain authoritative. No new budget setting is added.

The scheduler never selects a task when the workflow reports no remaining call or runtime capacity. Unrun queued tasks receive `budget_limited` outcomes at report time so the technical report identifies exactly what remained. Budget exhaustion cannot become clean closure.

Prerequisite schema and health calls still count toward the hunt-wide call budget. Fairness applies to the remaining executable search capacity; it does not conceal an impossibly small configured budget.

### Persistence and resume

Add these fields to hunt state:

- `search_tasks`: a mapping from stable task ID to task record.
- `search_queue`: ordered runnable task IDs.
- `search_outcomes`: append-only bounded attempt summaries.
- `scheduler_history`: registration, merge, selection, and budget-gap summaries.

Terminal tasks are not re-executed on resume. Queued tasks retain deterministic order. A task persisted as `running` without a terminal outcome becomes `interrupted`; it may be requeued once because all supported searches are read-only, and the retry is explicitly recorded.

For legacy partial hunts, a migration helper converts uncompleted `lead_catalog` entries into scheduler tasks. Existing completed leads with a matching result become terminal outcomes. A completed legacy lead with no matching result becomes a non-resolving `skipped` outcome whose reason is `legacy_attempt_unknown`; it is not automatically repeated. Existing completed hunts and reports remain readable without migration.

## Workflow Changes

1. Host and network collection compile and register deterministic discovery tasks, then drain the scheduler rather than executing private loops.
2. Initial directed model proposals, when allowed, register through the same validation and queue path. The `dynamic_initial_queue` and one-shot `dynamic_plan_created` mechanism are removed.
3. `_analyze` continues to build candidates, graphs, findings, and coverage, then registers candidate-owned deterministic follow-ups.
4. `_reason` may assess visible evidence and propose grounded work, but it only registers validated scheduler tasks.
5. `_pivot` becomes a generic select-execute-record cycle. Source-specific execution helpers remain responsible for safe query compilation, adapter calls, and evidence normalization.
6. `_coverage_fallback` is replaced by scheduler-owned coverage-frontier registration and selection.
7. `build_coverage_ledger` consumes authoritative task outcomes and merged ownership references.
8. The technical report uses unified outcome history for search coverage while keeping existing customer-report content unchanged.

## Error Handling and Safety

- Invalid or unsupported task specifications are rejected before registration and recorded as planning rejections, not failed searches.
- Adapter failures create task-specific outcomes without removing other queued work.
- Missing credentials or source configuration mark dependent tasks `skipped` with a telemetry gap.
- A cap, timeout, or partial page/capture result never counts as resolved.
- A scheduler-state inconsistency fails closed to a partial report rather than discarding queue or outcome history.
- Native model queries remain subject to existing source grammar, live-field, source-class, mission-window, and allowlist validation.
- No task or outcome stores secrets.

## Testing Strategy

Tests are written before production changes and prove:

1. Identical tasks from catalog, candidate, model, or coverage origins execute once while all owners receive the outcome.
2. Different time windows or selectors do not deduplicate merely because their prose intent matches.
3. A healthy configured host and network family each receive discovery capacity before extra work from one family.
4. An undirected candidate-free hunt registers and executes deterministic discovery without calling the model.
5. Critical/trusted and high candidate follow-ups outrank model and breadth tasks; stable ordering survives serialization and resume.
6. A model proposal cannot set its own scheduler tier or reference invisible candidates/evidence.
7. The exact model-search outcome updates its candidate follow-up; a stale prior pivot cannot do so.
8. Failed, capped, skipped, interrupted, and budget-limited work cannot satisfy hypothesis or candidate closure.
9. A successful authoritative zero-result search can resolve its bounded task.
10. A persisted terminal task is not repeated; an interrupted read-only task is retried at most once and remains audited.
11. Legacy partial state migrates without false closure or automatic repetition of an outcome-less completed lead.
12. Existing candidate, attack-path, reporting, retention, CLI, and offline behavior remains green.

## Validation and Rollout

1. Run focused scheduler, candidate-loop, coverage, and workflow tests locally, followed by the complete suite and compilation.
2. Run a disposable offline hunt proving merged ownership, authoritative outcomes, report generation, and compact retention still work together.
3. Review the whole milestone for priority inversion, duplicate execution, false closure, resume loops, secret handling, and source starvation.
4. Deploy the exact committed code to the development VM and run the dependency-complete suite plus `doctor`.
5. Run one bounded, isolated, read-only live hunt. Verify both host and network discovery occur, no duplicate execution fingerprint appears, every candidate follow-up points to its own outcome, and model work begins only after a valid basis exists.
6. Remove only the disposable validation artifacts and update the durable plan, validation record, and changelog before pausing for the next greenlight.

## Acceptance Criteria

The milestone is accepted when:

- All evidence searches appear in one persisted scheduler history and use one deduplication path.
- The live and offline proofs show no identical execution fingerprint ran twice.
- Configured host and network telemetry receive fair discovery opportunity or an explicit budget/source gap.
- Candidate and hypothesis closure use exact task outcomes and cannot be satisfied by partial or unrelated work.
- Undirected hunts retain the no-model-before-candidate rule.
- Existing source safety, report evidence standards, and retention guarantees remain intact.
- Local and VM suites pass, the bounded live proof is recorded honestly, and disposable artifacts are removed without touching operational hunt data.
