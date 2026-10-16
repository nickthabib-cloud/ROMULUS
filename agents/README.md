# ROMULUS agent delegation

## Purpose and instruction hierarchy

This directory defines a repeatable contract for delegating ROMULUS research, detection engineering, implementation, verification, audit, and hunt analysis. The coordinating lead invokes roles explicitly; no role starts automatically, and role files do not prove that delegated work occurred.

Every role reads the root [`AGENTS.md`](../AGENTS.md) first, then this file, its role file, and its task packet. The root policy has highest priority. This guide defines coordination, role files define specialist responsibilities, and a task packet may narrow scope but cannot override the higher-level instructions or weaken evidence, safety, provenance, read-only telemetry, indicator-first reporting, or coverage truth.

ROMULUS work begins with evidence-backed indicators and suspicious behaviors. Correlation may adjust confidence, priority, noise, and follow-up searches. Attack-path reconstruction is optional secondary analysis and remains a hypothesis unless every relationship is directly supported. Coverage claims must distinguish loaded, executable, executed, observed, reference-only, unsupported, and not-applicable content.

## Role index

1. [Lead / architect](lead.md) — verifies current behavior, selects the smallest sufficient role set, assigns work, and reconciles results.
2. [Threat researcher](threat-researcher.md) — performs read-only research and returns sourced, implementable detection candidates.
3. [Detection engineer](detection-engineer.md) — designs backend-valid retrieval, matching, correlation, baseline, and scoring semantics and identifies their live consumer.
4. [Platform developer](developer.md) — implements bounded code and integration changes with a traced runtime path.
5. [Test engineer](tester.md) — independently evaluates acceptance criteria and authorized verification.
6. [Independent auditor](auditor.md) — performs read-only review of diffs and surrounding execution paths.
7. [Hunt analyst](hunt-analyst.md) — evaluates hunt inputs, evidence, ranking, coverage, and conclusions, beginning with indicators.

## Delegation matrix

The lead chooses roles in proportion to task type and risk and records why an otherwise expected role was omitted.

| Task type | Required workflow |
|---|---|
| Trivial documentation or isolated maintenance | Lead or developer, followed by lead review |
| New indicator or behavior | Threat researcher, then detection engineer, followed by tester and auditor as authorized |
| Runtime integration | Platform developer, followed by tester and auditor as authorized |
| Query-generation or scoring change | Detection engineer, followed by tester and auditor as authorized |
| Architecture or disconnected-content audit | Independent auditor; add threat researcher when intelligence coverage is involved |
| Live hunt and report assessment | Hunt analyst; add threat researcher for unfamiliar behavior |
| Defect discovered during a hunt | Hunt analyst returns evidence to the lead, which creates a separate implementation packet |

High-impact changes to query generation, scoring, persistence, evidence gates, or customer-visible reporting require independent audit. Test work remains limited to the authorization in the task packet.

## Task packets and authorization

Copy [`task-template.md`](task-template.md) for every delegated assignment. Complete all ten assignment fields: mission, why it matters, verified current state, scope, exclusions, required deliverables, acceptance criteria, authorized actions, ROMULUS quality focus, and return format.

The user or lead's assignment authorizes the agent to act within the completed packet. The agent does not ask again for permissions already granted there. Work outside the packet requires a revised assignment or direct user authorization. Authorization must explicitly cover edits, test creation, test execution, network research, live-source access, commits, and external actions.

## Read-only and writing boundaries

- Threat researchers, independent auditors, and hunt analysts are read-only unless a task packet explicitly grants a different boundary.
- Detection engineers own assigned detection content and its backend semantics; they do not imply that present or loaded content ran.
- Platform developers own assigned code and integration files and verify how their change becomes reachable at runtime.
- Test engineers add or run tests only when the packet separately authorizes each action.
- The lead may directly handle trivial documentation or coordination work when authorized. Other product edits go to the appropriate writing role.
- Live telemetry stays read-only. Network research, live-source access, commits, and external actions require explicit authorization.

## Concurrency and file ownership

Use no more concurrency than the environment provides, and work in dependency-ordered waves. Only one agent owns a file set during an editing wave. Detection and platform changes may proceed concurrently only when their file scopes do not overlap and their interface is already defined. Tester and auditor review may proceed concurrently once the working change is available.

The lead assigns explicit file ownership, resolves conflicting recommendations, and never asks agents to merge competing edits blindly. Read-only roles may inspect overlapping paths, but they must not modify them without a revised packet and exclusive ownership.

## Workflow recipes

### Small maintenance

1. The lead verifies current behavior and either handles an authorized trivial change or assigns it to the developer.
2. The writer makes the smallest coherent change within exclusive file ownership.
3. The lead reviews the diff, evidence, and acceptance status.

### New detection content

1. The threat researcher returns prioritized candidates with sources, telemetry, expected benign uses, narrowing conditions, provenance, and limitations.
2. The lead selects approved candidates for a separate detection-engineering packet.
3. The detection engineer defines backend-valid semantics, evidence requirements, priority, noise controls, coverage status, and the live consumer.
4. As authorized, the tester verifies behavior and the auditor independently reviews the change; the lead reconciles both results.

### Runtime integration

1. The platform developer traces the relevant call path and implements the bounded integration.
2. As authorized, the tester evaluates acceptance criteria and the auditor reviews runtime reachability, safety boundaries, provenance, and coverage claims.
3. The lead reconciles evidence and unresolved limitations before accepting the change.

### Architecture or content audit

1. The independent auditor receives a read-only packet naming the system boundary, evidence sources, and risk questions.
2. Add a threat researcher when intelligence coverage is in scope.
3. The lead separates verified defects from hypotheses and creates new implementation packets for accepted corrections.

### Hunt analysis

1. The hunt analyst reviews mission inputs, searches, results, ranking, evidence, telemetry coverage, and reporting.
2. Add a threat researcher for unfamiliar behavior when authorized.
3. The analyst reports strong indicators first, then weak context, likely noise, gaps, searches that did not run, and follow-up work. Any attack-path hypothesis appears last and distinguishes evidence from inference.
4. The lead creates a separate implementation packet for any detection or runtime defect found during the hunt.

## Agent return contract and lead reconciliation

Every return contains five fields: **Result**, **Evidence**, **Acceptance status**, **Limitations**, and **Next action**. Writing agents also list every changed file. Review agents order findings by severity and include file and line references, the failure scenario, evidence, and a suggested correction. An agent must not turn absent verification into a success claim.

The lead confirms which agents actually ran, compares each return with its packet, reconciles conflicting recommendations, and checks the applicable ROMULUS quality gates: provenance, telemetry, backend validity, runtime reachability, evidence meaning, priority, noise control, correlation, coverage truth, and reporting. The lead reports combined evidence and limitations and decides whether acceptance criteria passed; a role's completion alone is not proof of correctness or live effectiveness.

## Failure and blocking behavior

- Correct an in-scope defect when editing is authorized, and report the correction.
- If one deliverable cannot be completed, continue independent work on the remaining deliverables.
- Return a failed check to the responsible writing role with the exact evidence and acceptance criterion that failed.
- Revise the packet when unclear scope or missing task information caused the gap.
- Mark work blocked only when a required external dependency, user decision, credential, unavailable system, or repeated unresolved failure prevents meaningful progress.
- Do not broaden scope to clean unrelated code; record a separate finding for the lead.
- Preserve useful indicators even when correlation is incomplete or no coherent attack path exists.
