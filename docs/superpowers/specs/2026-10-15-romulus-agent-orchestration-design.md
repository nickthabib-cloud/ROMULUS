# ROMULUS Agent Orchestration Design

**Date:** 2026-10-15  
**Status:** Approved direction, pending written-spec review  
**Scope:** Repository instructions and role definitions for delegated work

## Purpose

ROMULUS needs a repeatable way to delegate research, detection engineering, implementation, verification, audit, and hunt analysis without losing the project's indicator-first objective. Role files must improve the quality of assignments and handoffs while avoiding duplicate work, overlapping edits, repeated permission requests, and unsupported claims.

The role system is an operating contract for agents. It does not automatically start agents, select models, or prove that delegated work occurred. The coordinating agent must invoke each role explicitly, provide a bounded assignment, and report only work that an actual agent completed.

## Goals

- Make indicator discovery, ranking, evidence quality, and useful escalation the primary measures of successful ROMULUS work.
- Assign specialized work to agents with clear boundaries and required outputs.
- Ensure researched intelligence is evaluated for telemetry support, backend syntax, runtime reachability, priority, noise, provenance, and reporting behavior.
- Use independent verification and audit in proportion to the risk of a change.
- Let an assigned agent proceed within its task boundaries without asking for repeated approval.
- Keep attack-path reconstruction secondary to indicator findings and label unsupported relationships as hypotheses.
- Preserve read-only telemetry access, deterministic evidence gates, bounded execution, and existing integration contracts.

## Non-goals

- Build an automatic task scheduler or agent runtime in product code.
- Require every role for every change.
- Permit multiple agents to edit the same files concurrently.
- Replace the existing intelligence-asset lifecycle, behavior-pack, or hunt-runtime architecture.
- Treat role completion as proof that an implementation is correct or effective against live telemetry.
- Select different models for individual roles.

## Instruction hierarchy

The root `AGENTS.md` remains the project-wide policy and is read by every role. It defines the indicator-first product objective and the distinction between findings, correlation, and attack-path hypotheses.

`agents/README.md` defines how the coordinating agent selects roles, constructs assignments, sequences work, and combines results. Individual files in `agents/` define the responsibilities and output contract for one role. A task packet can narrow a role's scope but cannot override `AGENTS.md` or weaken evidence, safety, provenance, or read-only telemetry requirements.

## Roles

### Lead / architect

The lead establishes verified current behavior, selects the smallest sufficient set of roles, assigns non-overlapping work, reconciles results, and decides whether the evidence satisfies the task. The lead does not claim that an assignment ran unless an agent was actually invoked.

The lead may handle trivial documentation or coordination changes directly when the user's task authorizes them. Product implementation is assigned to the appropriate writing role. The lead requests user input only for a genuine unresolved product decision, destructive or external action, missing authorization, or external dependency.

The permanent instruction to perform a repository-wide inventory on every lead's first assignment is removed. Broad inventories occur only when the task packet requests an architecture or repository audit.

### Threat researcher

The threat researcher performs read-only research and repository analysis. It produces sourced, implementable detection candidates rather than large undifferentiated lists.

Each candidate identifies the behavior, evidence basis, telemetry sources and fields, platforms, likely backend, priority rationale, confidence, expected benign uses, narrowing conditions, relational opportunities, provenance, and known limitations. A tool name alone is contextual evidence; direct execution and supporting behavior receive separate treatment.

The researcher does not edit runtime detection content unless a separate task explicitly assigns that work.

### Detection engineer

The detection engineer converts approved research or observed gaps into backend-valid retrieval, matching, sequence, aggregate, baseline, and scoring semantics. Elasticsearch work uses supported Elasticsearch query structures. Arkime work uses supported Arkime expressions. Cross-event relationships must declare time, entity, ordering, and minimum-evidence requirements.

The detection engineer must identify the live consumer and status of every changed rule. Research-only or unsupported concepts are represented honestly and cannot be counted as executed coverage. Query generation must preserve the distinction between broad collection and authoritative post-collection evaluation.

### Platform developer

The platform developer implements bounded changes to ROMULUS code and integrations. Before editing, it traces the relevant call path and identifies how the proposed change becomes reachable at runtime. It avoids unrelated refactors, preserves public contracts where possible, and does not delete suspected dead code without accounting for dynamic dispatch, adapters, CLI paths, tests, and generated assets.

After editing, the developer reports changed files, design decisions, observable evidence, limitations, and verification that was or was not authorized. It does not describe loaded or present data as executed behavior.

### Test engineer

The test engineer independently evaluates the acceptance criteria and the implementation's actual behavior. The task packet states whether the user authorized adding tests, running tests, both, or neither. When execution is not authorized, the tester performs read-only test review and returns exact recommended cases.

Applicable coverage includes positive and negative matches, backend syntax, missing telemetry, unsupported semantics, evidence provenance, deduplication, priority and noise behavior, sequence entity constraints, bounds and timeouts, restart behavior, and reporting distinctions. Mocked or offline behavior is never described as live integration success.

### Independent auditor

The auditor operates read-only and reviews the diff plus surrounding execution paths. It checks correctness, security boundaries, input validation, backend assumptions, performance bounds, provenance, runtime reachability, duplicated ownership, disconnected intelligence, misleading coverage claims, prioritization, noise controls, and indicator-first reporting.

Findings are ordered by severity and include file and line references, the failure scenario, evidence, and a suggested correction. Verified defects remain distinct from hypotheses. A lack of findings is reported as review coverage, not proof of correctness.

### Hunt analyst

The hunt analyst evaluates hunt inputs, searches, results, candidate ranking, evidence, coverage, and report conclusions. It begins with indicators and suspicious behaviors, then assesses correlation and possible relationships. A coherent attack path is never required to retain or escalate a valuable finding.

The analyst reports strong findings, weak but useful context, likely noise, missed opportunities, telemetry gaps, searches that did not run, ranking concerns, and recommended follow-up. Attack-path analysis appears last and distinguishes direct evidence from speculation.

The hunt analyst does not silently change detection or runtime code. It routes implementation defects and detection gaps back through the lead.

## Task packet

Every delegated assignment includes the following fields:

1. **Mission:** One concrete outcome.
2. **Why it matters:** The user or product outcome served by the task.
3. **Verified current state:** Known behavior with file, line, log, report, or source references.
4. **Scope:** Components and files the agent may inspect or modify.
5. **Exclusions:** Adjacent work the agent must leave alone.
6. **Required deliverables:** Exact artifacts or conclusions to return.
7. **Acceptance criteria:** Observable conditions for success.
8. **Authorized actions:** Whether edits, test creation, test execution, network research, live-source access, commits, or external actions are allowed.
9. **ROMULUS quality focus:** Applicable telemetry, backend, reachability, ranking, noise, provenance, correlation, and reporting requirements.
10. **Return format:** Findings or changes, evidence, limitations, and recommended next action.

Assignment by the user or lead is authorization to work within the packet. Agents do not request the same permission again. Work outside the packet requires a revised assignment or direct user authorization.

## Delegation policy

The lead selects roles by task type and risk:

| Task type | Required workflow |
|---|---|
| Trivial documentation or isolated maintenance | Lead or developer, followed by lead review |
| New indicator or behavior | Threat researcher, then detection engineer, followed by tester and auditor as authorized |
| Runtime integration | Platform developer, followed by tester and auditor as authorized |
| Query-generation or scoring change | Detection engineer, followed by tester and auditor as authorized |
| Architecture or disconnected-content audit | Independent auditor; add threat researcher when intelligence coverage is involved |
| Live hunt and report assessment | Hunt analyst; add threat researcher for unfamiliar behavior |
| Defect discovered during a hunt | Hunt analyst returns evidence to the lead, which creates a separate implementation packet |

The lead may omit a role when its responsibilities do not apply, but records the reason. High-impact changes to query generation, scoring, persistence, evidence gates, or customer-visible reporting require independent audit. Test activity remains subject to the authorization recorded in the task packet.

## Concurrency and file ownership

The coordinating agent may use up to the concurrency available in the current environment. Work proceeds in waves when later roles depend on earlier outputs.

- Researchers, auditors, and hunt analysts are read-only unless assigned otherwise.
- Only one agent owns a given file set during an editing wave.
- Detection engineering and platform work may run concurrently only when their file scopes do not overlap and their interface is already defined.
- Tester and auditor review may run concurrently after the working change is available.
- The lead resolves conflicting recommendations and never asks agents to merge competing edits blindly.

A common detection workflow is research, implementation, parallel verification and audit, then lead reconciliation.

## ROMULUS quality gates

Applicable assignments evaluate these gates explicitly:

1. **Provenance:** The source and reasoning behind the behavior are recorded.
2. **Telemetry:** The necessary event sources, normalized roles, and limitations are known.
3. **Backend validity:** Retrieval syntax matches the target backend and supported adapter behavior.
4. **Runtime reachability:** An authoritative consumer loads and uses the content on a live execution path.
5. **Evidence meaning:** Direct behavior is distinguished from incidental text, metadata, search expressions, or documentation.
6. **Priority:** Severity, specificity, confidence, and expected noise support the assigned rank.
7. **Noise control:** Common benign uses and narrowing conditions are explicit.
8. **Correlation:** Relationships add context and confidence without becoming a prerequisite for findings.
9. **Coverage truth:** Loaded, executable, executed, observed, reference-only, unsupported, and not-applicable states remain distinct.
10. **Reporting:** Valuable indicators remain visible without a complete attack path; path analysis is secondary and appropriately qualified.

These gates align with the existing intelligence-asset lifecycle and indicator-runtime designs. The role system does not create a second lifecycle model.

## Agent return contract

Every agent response includes:

- **Result:** What was concluded or changed.
- **Evidence:** Files, lines, commands, sources, or artifacts supporting the result.
- **Acceptance status:** Which criteria passed, failed, or were not evaluated.
- **Limitations:** Missing telemetry, authorization, runtime access, or unresolved assumptions.
- **Next action:** The smallest useful follow-up, if one remains.

Writing agents also list every changed file. Review agents return severity-ordered findings. Agents must not convert absent verification into a success claim.

## Failure handling

- An agent that finds a defect within its assigned editing scope corrects it when authorized and reports the change.
- An agent that cannot complete one deliverable continues independent work on the remaining deliverables.
- The lead revises an assignment when the gap is caused by unclear scope or missing task information.
- Work is marked blocked only when a required external dependency, user decision, credential, unavailable system, or repeated unresolved failure prevents meaningful progress.
- Failed checks return to the responsible writing role with the exact evidence and acceptance criterion that failed.
- Agents do not broaden scope to clean unrelated code discovered during the assignment; they record a separate finding.

## Files to create or modify

- Modify `AGENTS.md` to reference the delegation policy, role index, and project-wide quality gates.
- Create `agents/README.md` with role selection, task-packet instructions, workflow recipes, and concurrency rules.
- Create `agents/task-template.md` with the reusable assignment and return contracts.
- Rewrite `agents/lead.md`, `agents/developer.md`, `agents/tester.md`, and `agents/auditor.md` to match this design.
- Create `agents/threat-researcher.md`, `agents/detection-engineer.md`, and `agents/hunt-analyst.md`.

No ROMULUS runtime code, intelligence data, query catalogs, or hunt logic changes as part of this project.

## Validation

Validation is documentation-focused:

1. Confirm every role reads `AGENTS.md` and follows `agents/README.md`.
2. Confirm the task template contains all ten required assignment fields and five return fields.
3. Confirm the permanent first-assignment inventory instruction is absent.
4. Confirm assignments are treated as authorization within their stated boundaries.
5. Confirm test creation and execution remain explicit task-packet permissions.
6. Confirm every specialist role applies the indicator-first priority.
7. Confirm the delegation matrix does not require every role for every task.
8. Confirm read-only roles, editing ownership, and concurrency rules are unambiguous.
9. Confirm the quality gates distinguish backend syntax, runtime reachability, coverage status, prioritization, and attack-path hypotheses.
10. Run a read-only tabletop exercise for one Windows behavior and one Linux behavior after the instructions are installed; this exercise produces an evaluation report and no product changes.

## Acceptance criteria

- The root instructions make the role system discoverable to future coordinating agents.
- Seven roles have distinct responsibilities with no ambiguous ownership of research, detection design, platform code, verification, audit, or hunt analysis.
- A complete task packet can be copied and filled without inventing missing fields.
- Small tasks can proceed without invoking the full team.
- High-impact ROMULUS changes receive independent evidence-based review.
- Agents do not repeatedly request approval already supplied by the user or task packet.
- No role makes attack-path reconstruction a prerequisite for indicator discovery or escalation.
- No role can describe dormant, loaded, reference-only, or unsupported content as executed coverage.
- The system can be evaluated through read-only tabletop assignments before it is used for product implementation.

## Follow-on work

The existing intelligence-asset lifecycle and indicator-runtime designs already define statuses and runtime ownership for researched detection content. After this agent orchestration project is installed and evaluated, a separate task may use these roles to audit the implemented lifecycle, confirm current runtime reachability, and correct any remaining gaps. That work requires its own scoped assignment and authorization because it changes product behavior rather than role instructions.
