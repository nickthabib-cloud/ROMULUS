# ROMULUS delegated task packet

Copy and complete every field for one role and one delegated agent turn before assigning it. Do not reuse a completed packet for another role or turn. A shared immutable scenario or evidence envelope may be referenced, but this packet must still contain the assignee's role-specific mission, deliverables, authorized actions, stage-specific acceptance criteria, and return path. The assignee must read the root [`AGENTS.md`](../AGENTS.md), [`agents/README.md`](README.md), and its role file first. This packet is authorization only within the stated boundaries.

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
   Exact artifacts or conclusions to return. Name the exact path for every file-backed deliverable and every upstream artifact the role must consume:

7. **Acceptance criteria**
   Observable conditions for this role's stage. Do not assign downstream or combined-workflow acceptance to an upstream role; mark those criteria pending or not evaluated until the responsible stage runs. Only the lead reconciles combined acceptance:

8. **Authorized actions**
   Select exactly one value for each category. A checked **Allowed** box authorizes that action only within this packet; **Not allowed** is the default when neither box is checked.

   - Tracked product/repository edits: [ ] Allowed  [ ] Not allowed
   - Coordination artifact/report write: [ ] Allowed  [ ] Not allowed
   - Test creation: [ ] Allowed  [ ] Not allowed
   - Test execution: [ ] Allowed  [ ] Not allowed
   - Network research: [ ] Allowed  [ ] Not allowed
   - Live-source access: [ ] Allowed  [ ] Not allowed
   - Commits: [ ] Allowed  [ ] Not allowed
   - External actions: [ ] Allowed  [ ] Not allowed

   Exact allowed product/repository edit paths:

   Exact allowed coordination artifact/report paths:

   Additional action limits, approved targets, or commit message:

   A coordination artifact/report permission authorizes only the exact paths above. It does not authorize tracked product or repository edits. A product-read-only assignment may allow an ignored scratch report while keeping tracked edits prohibited.

9. **ROMULUS quality focus**
   Identify applicable requirements for telemetry, backend validity, runtime reachability, evidence meaning, priority/ranking, noise control, provenance, correlation, coverage truth, and reporting. Distinguish loaded, executable, executed, observed, reference-only, unsupported, and not-applicable states:

10. **Return format**
    Use the five return fields below. Every role must list each artifact actually written by exact path; writing agents must also list every changed product or repository file. Review agents must provide severity-ordered findings with file/line references, failure scenarios, evidence, and suggested corrections. An upstream role must mark downstream and combined-workflow criteria pending or not evaluated. A downstream role must consume the named upstream handoff, verify the claims needed for its own stage, and emphasize additions, disagreements, and stage-specific conclusions instead of repeating the entire upstream task. Include the exact return path and any task-specific status token or destination:

## Return

1. **Result**
   What was concluded or changed; list every artifact actually written by exact path and, for writing work, every changed product or repository file:

2. **Evidence**
   Files, lines, commands, sources, or artifacts supporting the result:

3. **Acceptance status**
   Criteria passed, failed, or not evaluated:

4. **Limitations**
   Missing telemetry, authorization, runtime access, or unresolved assumptions; do not present absent verification as success:

5. **Next action**
   Smallest useful follow-up, or `None` when the packet is complete:
