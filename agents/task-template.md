# ROMULUS delegated task packet

Copy and complete every field before assigning a role. The assignee must read the root [`AGENTS.md`](../AGENTS.md), [`agents/README.md`](README.md), and its role file first. This packet is authorization only within the stated boundaries.

ROMULUS quality starts with evidence-backed indicators and suspicious behaviors. Do not require a coherent attack path to retain or escalate a finding. Treat attack-path reconstruction as optional secondary analysis, and keep coverage states truthful.

## Assignment

1. **Mission**
   One concrete outcome:

2. **Why it matters**
   User or product outcome served:

3. **Verified current state**
   Known behavior with file/line, log, report, artifact, or source references:

4. **Scope**
   Components and files the agent may inspect or modify; identify exclusive file ownership for edits:

5. **Exclusions**
   Adjacent work the agent must leave alone:

6. **Required deliverables**
   Exact artifacts or conclusions to return:

7. **Acceptance criteria**
   Observable conditions for success:

8. **Authorized actions**
   Select exactly one value for each category. A checked **Allowed** box authorizes that action only within this packet; **Not allowed** is the default when neither box is checked.

   - Edits: [ ] Allowed  [ ] Not allowed
   - Test creation: [ ] Allowed  [ ] Not allowed
   - Test execution: [ ] Allowed  [ ] Not allowed
   - Network research: [ ] Allowed  [ ] Not allowed
   - Live-source access: [ ] Allowed  [ ] Not allowed
   - Commits: [ ] Allowed  [ ] Not allowed
   - External actions: [ ] Allowed  [ ] Not allowed

   Additional action limits, approved targets, or commit message:

9. **ROMULUS quality focus**
   Identify applicable requirements for telemetry, backend validity, runtime reachability, evidence meaning, priority/ranking, noise control, provenance, correlation, coverage truth, and reporting. Distinguish loaded, executable, executed, observed, reference-only, unsupported, and not-applicable states:

10. **Return format**
    Use the five return fields below. Writing agents must list every changed file; review agents must provide severity-ordered findings with file/line references, failure scenarios, evidence, and suggested corrections. Include any task-specific status token or destination:

## Return

1. **Result**
   What was concluded or changed; for writing work, include the exact changed files:

2. **Evidence**
   Files, lines, commands, sources, or artifacts supporting the result:

3. **Acceptance status**
   Criteria passed, failed, or not evaluated:

4. **Limitations**
   Missing telemetry, authorization, runtime access, or unresolved assumptions; do not present absent verification as success:

5. **Next action**
   Smallest useful follow-up, or `None` when the packet is complete:
