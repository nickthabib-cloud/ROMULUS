# ROMULUS agent orchestration tabletop review

**Date:** 2026-10-15

**Scope:** Read-only Windows and Linux orchestration tabletop

**Specification:** `docs/superpowers/specs/2026-10-15-romulus-agent-orchestration-design.md`

**Result:** Substantive scenario acceptance passed with limitations; three orchestration defects were corrected and reviewed in commit `e68dfaa68a7aeebf1cb378cf563825d1d8b5c913`

## Executive verdict

The tabletop demonstrated that the installed role system can produce complete, useful, indicator-first handoffs from bounded synthetic evidence. The Windows and Linux workflows identified direct behaviors, separated incidental text and metadata from execution, specified telemetry and backend requirements, traced static runtime consumers, ranked findings with expected-noise rationale, and used correlation only as optional enrichment. Both scenario packets passed their substantive acceptance criteria after lead reconciliation.

The original packet pattern had three orchestration defects: each scenario packet was reused across two role turns, packet language prohibited the handoff files that the coordinating assignments required, and shared acceptance criteria encouraged upstream roles to claim combined success and downstream roles to repeat work. A scoped correction updated the delegation contracts, and the final fix review found all three defects addressed with no new Critical, Important, or Minor finding. The corrected packet pattern was reviewed statically; these two scenarios were not rerun with new role-specific packets after the correction.

This was a synthetic, static exercise. No ROMULUS product code was changed or executed. No tests were created or run. No parser, compiler, hunt workflow, Elasticsearch source, Arkime source, live telemetry, credential, network research, external source, deployment, or other external action was used. The exercise did not evaluate live detection efficacy, recall, precision, runtime loading, deployment mappings, source health, search completion, or observed coverage.

## Evidence reviewed

The review used the approved orchestration specification; `AGENTS.md`; `agents/README.md`; `agents/task-template.md`; all seven role files; the two scenario packets; four specialist handoffs; the lead reconciliation; the correction brief and implementation report; the correction commit; and the correction review.

Primary Task 5 artifacts:

- `.superpowers/sdd/2026-10-15-romulus-agent-orchestration/task-5-lead-report.md`
- `.superpowers/sdd/2026-10-15-romulus-agent-orchestration/task-5-windows-packet.md`
- `.superpowers/sdd/2026-10-15-romulus-agent-orchestration/task-5-windows-detection.md`
- `.superpowers/sdd/2026-10-15-romulus-agent-orchestration/task-5-windows-hunt.md`
- `.superpowers/sdd/2026-10-15-romulus-agent-orchestration/task-5-linux-packet.md`
- `.superpowers/sdd/2026-10-15-romulus-agent-orchestration/task-5-linux-detection.md`
- `.superpowers/sdd/2026-10-15-romulus-agent-orchestration/task-5-linux-hunt.md`
- `.superpowers/sdd/2026-10-15-romulus-agent-orchestration/task-5-reconciliation.md`
- `.superpowers/sdd/2026-10-15-romulus-agent-orchestration/task-5-fix-brief.md`
- `.superpowers/sdd/2026-10-15-romulus-agent-orchestration/task-5-fix-report.md`
- `.superpowers/sdd/2026-10-15-romulus-agent-orchestration/task-5-fix-review.md`

The specialist handoffs cite static repository paths for field aliases, normalization, detection definitions, search compilation, workflow planning and execution accounting, candidate construction, correlation, and reporting. Those citations support static behavior and reachability claims only.

## Roles actually invoked

The Task 5 workflow actually used these ROMULUS roles:

1. **Lead / architect** prepared the two scenario packets, selected the role sequence, and reconciled the four handoffs.
2. **Detection engineer** completed one Windows and one Linux repository-only detection handoff.
3. **Hunt analyst** completed one Windows and one Linux hunt handoff after consuming the corresponding detection handoff.

The files returned by the detection engineer and hunt analyst, and the hunt handoffs' citations to their upstream detection handoffs, are the evidence that those roles ran. Role files by themselves were not counted as execution evidence.

The following roles were intentionally omitted:

- **Threat researcher:** the scenarios used familiar behaviors with dated, checked-in research and provenance.
- **Platform developer:** no product implementation was authorized.
- **Test engineer:** test creation and execution were expressly prohibited.
- **Independent auditor:** the scenario packets involved no product diff; the hunt analyst supplied the read-only evidence assessment and the lead reconciled it. A separate reviewer later assessed the scoped orchestration-contract fix.

The correction artifacts show a scoped documentation implementation and a final review. They do not identify that reviewer as one of the seven named ROMULUS roles, so this report does not count an additional project-role invocation.

## Task packets

### Windows PowerShell behavior packet

The Windows packet supplied five synthetic records:

- **W1:** Security 4688 PowerShell with applied hidden-window and encoded-command parameters, Office ancestry, host, actor, and process entity.
- **W2:** PowerShell Operational 4104 script content specifying remote retrieval to a temporary file and later invocation of that target.
- **W3:** an approved analyst session in which the suspicious PowerShell token appeared as a quoted search needle.
- **W4:** runbook text with no process or Windows-event identity.
- **W5:** direct PowerShell download behavior with packet-supplied approved deployment context.

The packet required source-aware Windows retrieval, authoritative post-collection evaluation, direct-behavior classification, priority and expected-noise reasoning, runtime and lifecycle analysis, and optional bounded W1/W2 correlation that could not suppress either standalone finding.

Its intended action boundary was repository reading only: no product or documentation edits, test creation, test execution, project execution, network research, live-source access, credentials, commits, or external actions. The packet's blanket prohibition on file writes conflicted with the coordinating assignments that required the two handoff files; this was recorded as an orchestration defect rather than ignored.

### Linux dual-use network utility packet

The Linux packet supplied six synthetic records:

- **L1:** Auditd EXECVE Nmap scan-mode execution on a production host.
- **L2:** grep handling `nmap` as a search argument.
- **L3:** EDR Netcat connectivity probing with approved monitoring context.
- **L4:** Auditd EXECVE Netcat listener and shell-capable arguments, run as root from a temporary-path parent.
- **L5:** Bash/printf writing Socat command text into documentation.
- **L6:** Nmap package inventory metadata without process execution identity.

The packet required source-aware Auditd and EDR retrieval, authoritative executable and argument evaluation, direct-execution classification, priority and expected-noise reasoning, runtime and lifecycle analysis, and optional bounded relationships that could not suppress L1, L3, or L4 as standalone findings.

Its intended action boundary was the same repository-only boundary as the Windows packet. It had the same historical conflict between a blanket no-write rule and the required handoff artifact paths.

## Workflow outputs

### Windows detection-engineering handoff

The detection engineer classified W1 and W2 as direct, high-priority behaviors; W3 as direct analyst-search behavior with incidental suspicious text; W4 as reference-only text; and W5 as direct download behavior with strong benign context. It recommended:

- bounded, source-aware Elasticsearch retrieval for Security 4688 and PowerShell Operational 4104;
- exact event code, provider, channel, timestamp, process or script field, host, actor, process/entity, and parent requirements;
- authoritative source-typed evaluation that distinguishes applied parameters and invoked commands from comments and string literals;
- missing-field behavior that records unsupported or unavailable coverage rather than a clean result;
- stable evidence and candidate deduplication without merging W1 and W2;
- a five-minute, ordered W1-to-W2 relationship using host plus process entity and two independently qualifying records; and
- Arkime only as an optional network follow-up, never as proof of endpoint execution.

The handoff traced checked-in definitions through loaders, search compilation and planning, execution accounting, candidate construction, and reporting. It kept repository-present, statically loadable, conditionally executable, recommended, planned, executed, observed, reference-only, unavailable, unsupported, and not-applicable states distinct. It reported `DONE_WITH_CONCERNS` because the static trace exposed product gaps described later in this report.

### Windows hunt handoff

The hunt analyst preserved W1 and W2 as separate high-priority indicators, placed W1 first because of encoded and hidden applied parameters plus Office ancestry, retained W5 as direct but likely benign activity, and excluded W3 and W4 from encoded-execution findings. The optional W1/W2 relationship appeared after the standalone findings and remained a hypothesis.

The hunt handoff consumed the detection handoff and added material observations: broad Windows matrix predicates can carry labels or priorities stronger than their evidence, the exact W2 ampersand plus same-output-target relationship is not encoded, exact matrix attribution does not feed candidate scoring, and generated report ordering can place hypotheses before prioritized findings.

### Linux detection-engineering handoff

The detection engineer classified L1, L3, and L4 as direct utility execution; L2 and L5 as direct execution of other programs handling utility names as text; and L6 as package metadata. It ranked the supplied direct behaviors **L4 above L1 above L3** and recommended:

- separate, bounded Elasticsearch source families for Auditd EXECVE and EDR process-start data;
- event time, source/type, process name/executable, complete argv or command line, host, actor, parent, process/entity, asset, allowlist, destination, and port context;
- explicit handling for raw Auditd identifiers and normalization or parse failures;
- authoritative utility identity before token-aware Nmap, Netcat, or Socat argument evaluation;
- retention of source-qualified direct indicators when actor or benign context is missing;
- deduplication by immutable source evidence without collapsing distinct L1, L3, and L4 activity; and
- Arkime only as independent network-session context.

The static consumer trace distinguished repository presence and loader reachability from deployed executability, planning, execution, and observation. The handoff reported `DONE_WITH_CONCERNS` because existing static semantics can promote incidental text and miss stronger argument combinations.

### Linux hunt handoff

The hunt analyst kept L4 as the strongest supplied lead, L1 as a high-priority scan lead, and L3 as separately reportable direct activity whose approved monitoring context lowered residual escalation. It excluded L2, L5, and L6 from named-utility execution findings.

The hunt handoff consumed the detection handoff and added material observations: L2 and L5 could become separate false candidates and then mutually corroborate, the EDR L3 probe lacks a source-aware matrix path, L4 can be retrieved without an established exact candidate path, and operator-facing candidate identity can duplicate one source event across analytics.

### Lead reconciliation

The lead reconciled both workflows as `DONE_WITH_CONCERNS`. It found no material disagreement in record classification, ranking, backend choice, lifecycle status, or correlation. It accepted both scenarios substantively, isolated three orchestration defects, and kept the static product observations outside the orchestration acceptance decision.

## Substantive acceptance status

### Cross-scenario criteria

| Criterion | Status | Evidence-based conclusion |
|---|---|---|
| Complete assignments and useful handoffs | **Passed with process concerns** | Both detection and hunt stages returned five-field, repository-grounded handoffs; the original packet structure required correction. |
| Telemetry and field requirements | **Passed** | Windows named 4688/4104 selectors and process/script fields; Linux named Auditd/EDR identity and process/argument fields. Both covered actor, host, entity, parent, time, mapping, and collection gaps. |
| Backend-specific recommendations | **Passed** | Elasticsearch was bounded and source-aware. Arkime was limited to separate network evidence and never used as proof of endpoint execution. |
| Runtime consumer and lifecycle analysis | **Passed for static evidence; live state not evaluated** | The handoffs traced loaders, planners, execution accounting, evaluators, candidates, and reports without upgrading repository presence to live coverage. |
| Priority and expected-noise rationale | **Passed** | Windows prioritized W1/W2 and down-ranked validated deployment activity; Linux ranked L4 above L1 above L3 and separated behavior confidence from intent confidence. |
| Direct behavior versus incidental text | **Passed in the tabletop conclusions** | W3/W4 and L2/L5/L6 were not promoted to execution of the named suspicious tools. Static product risks were separately recorded. |
| Correlation without suppressing findings | **Passed** | W1/W2 and L1/L3/L4 remained standalone findings; relationships required bounded time, ordering, minimum evidence, and real entity or destination keys. |
| Explicit limitations and next actions | **Passed** | All four specialist handoffs stated unavailable evidence, prohibited actions, unresolved assumptions, and bounded follow-up. |
| No repeated authorization request | **Passed** | No role asked again for repository-reading authority already provided. |
| No live efficacy overclaim | **Passed** | Every handoff stated that the records were synthetic and runtime or live efficacy was not evaluated. |

### Windows disposition

| Record | Reconciled classification | Priority and limits |
|---|---|---|
| W1 | Direct encoded and hidden PowerShell process behavior | Highest Windows priority; payload content, command outcome, and compromise unproved. |
| W2 | Direct 4104 remote-retrieval and same-target invocation content | Separate high-priority finding; download, file creation, execution success, and compromise unproved. |
| W3 | Direct analyst search with suspicious text used as data | Context only; no encoded-execution finding. |
| W4 | Reference-only runbook text | No process or event identity; endpoint execution not applicable. |
| W5 | Direct PowerShell download behavior with strong benign context | Retain the occurrence; lower review priority only when actor, parent, destination, and maintenance context are validated. |

### Linux disposition

| Record | Reconciled classification | Priority and limits |
|---|---|---|
| L4 | Direct Netcat listener and shell-capable execution | Strongest supplied Linux lead; socket, connection, shell use, and compromise unproved. |
| L1 | Direct Nmap scan-mode execution | High-priority lead; authorization and prevalence unavailable. |
| L3 | Direct Netcat connectivity probe | Low residual escalation with supplied monitoring context; allowlist context was not independently verified. |
| L2 | Direct grep execution with `nmap` as search text | No Nmap execution finding. |
| L5 | Direct Bash/printf documentation write containing Socat text | No Socat execution finding. |
| L6 | Package metadata | No Nmap execution finding. |

## Duplicated work, contradictions, and missing fields

### Duplicated work

The detection and hunt stages repeated record classification, backend selection, lifecycle tracing, correlation constraints, and several product gaps. Some repetition provided useful independent confirmation, and the hunt analysts added distinct findings. The duplication exceeded what was needed because each shared scenario packet assigned both roles largely the same deliverables and acceptance criteria.

The reviewed correction now requires downstream roles to consume a named upstream handoff, verify only what their stage needs, and emphasize additions, disagreements, ranking, coverage, and conclusions.

### Contradictions

No material substantive contradiction was found:

- Windows handoffs agreed on W1 above W2, W5 retained but down-ranked, W3 as analyst-search context, and W4 as reference-only.
- Linux handoffs agreed on L4 above L1 above L3 and on excluding L2, L5, and L6 from direct named-utility execution.
- Detection's “critical or highest high” recommendation for L4 and hunt's “critical” wording express the same escalation judgment within an unspecified product scale.
- Both scenarios agreed that Elasticsearch is the endpoint backend and Arkime is optional independent network context.

### Missing or incorrectly owned fields

No specialist return omitted one of the five required return fields. Two contract-quality gaps remained in the historical returns:

1. The handoffs did not consistently list their exact coordination artifact paths even though each wrote one.
2. The detection-stage returns marked the full scenario criteria passed even though hunt-stage work and lead reconciliation were still pending.

Both gaps followed from the original shared packets and were covered by the reviewed correction.

## Orchestration defects and reviewed corrections

Commit `e68dfaa68a7aeebf1cb378cf563825d1d8b5c913` (`docs: tighten agent handoff contracts`) changed exactly:

- `agents/README.md`
- `agents/task-template.md`
- `agents/lead.md`
- `agents/detection-engineer.md`
- `agents/hunt-analyst.md`

| Tabletop defect | Correction in `e68dfaa` | Review result |
|---|---|---|
| One scenario packet was reused for detection and hunt turns. | `agents/README.md`, `agents/task-template.md`, and `agents/lead.md` now require one distinct role-specific packet per delegated turn. A shared immutable scenario or evidence envelope may be referenced but cannot replace the role-specific mission, deliverables, actions, acceptance criteria, or return path. | **Addressed.** |
| Packets prohibited writes while coordinating assignments required handoff files. | The template now separates tracked product/repository edits from coordination artifact/report writes, requires exact allowed paths, and states that scratch-report permission does not expand the product-edit boundary. README, detection, and hunt instructions enforce the same separation and exact artifact reporting. | **Addressed.** |
| Shared acceptance criteria caused premature combined acceptance and excess downstream repetition. | The template and README now require stage-specific acceptance. Detection must leave hunt and combined criteria pending or not evaluated. Hunt must consume the upstream handoff and report deltas. Lead instructions reserve combined acceptance for reconciliation. | **Addressed.** |

The correction implementation report records content and Git checks and no test execution. The final correction review examined the scoped diff, marked all three defects addressed, identified no new Critical, Important, or Minor breakage, and returned **PASS**.

The original two packets remain historical evidence of the defects; commit `e68dfaa` corrected the reusable instruction contracts rather than rewriting those artifacts. A future tabletop should confirm the improved workflow with separate role-specific packets.

## Product observations for future tasks

The following items are separate from the orchestration verdict. They are static observations with concrete failure scenarios, based on repository reading and synthetic inputs. They were not reproduced by executing ROMULUS and are not live efficacy findings.

1. **Direct-behavior evidence gates can accept incidental text.** Generic command-line aliases include script blocks and raw text, while substring evaluation does not always require source or executable identity. Synthetic shapes like W4, L2, and L5, and conditionally L6, could therefore become technical behavior candidates. The Linux handoff also describes how L2/L5 false candidates could corroborate each other.
2. **Search-matrix attribution does not feed candidate construction.** Source-qualified signature attribution is stored on search outcomes but is not consumed by `build_candidate_queue`. Strong W1/W2 semantics can be under-ranked, while L4 can be retrieved without an established exact candidate path.
3. **Some Windows matrix labels and priorities exceed their predicates.** `-nop` substring behavior can accept `-NoProfile`; `-OutFile` can receive a download-then-shell label without an invocation; and W2's ampersand plus same-output-target relation is not encoded.
4. **Linux source and semantic coverage has gaps.** The exact short-name Netcat matrix family is Auditd-bound, leaving the EDR L3 probe without a source-aware path. The observe-only `nc -e` literal can miss L4 when grouped listener flags and a port intervene.
5. **Context-aware ranking and operator-facing deduplication are incomplete.** The cited candidate scoring path does not consume all actor, parent, asset, target, and maintenance context used in the tabletop ranking. Candidate identity can also produce multiple analytic candidates for one source record.
6. **Generated report order can violate the indicator-first objective.** The statically inspected report path emits hypotheses before prioritized leads and significant findings.

Each observation needs a separate bounded implementation packet, explicit test permissions, and proportional independent review before any code or lifecycle-status change. The tabletop itself made no product correction.

## Limitations

- W1-W5 and L1-L6 are compact synthetic rows, not raw source documents. Field shape, quoting, normalization, mappings, provenance, and token parsing were not validated.
- Packet-supplied benign context, allowlists, schedules, asset roles, parent trust, and destinations were not independently checked.
- Static source reading can establish repository presence, code paths, and plausible failure scenarios. It cannot establish deployed mappings, live loading, successful compilation, search execution, observation, result completeness, recall, precision, or false-positive rates.
- No live or offline product evaluation ran, so direct-behavior classifications are judgments about the supplied synthetic facts rather than measured ROMULUS outputs.
- The corrected orchestration contract was reviewed in the fix diff but was not exercised by rerunning both scenarios with role-specific packets.

## Final acceptance

The Task 5 tabletop is **accepted with documented limitations and reviewed orchestration corrections**.

- Both scenarios passed their substantive tabletop criteria.
- The original packet pattern failed three process checks.
- Commit `e68dfaa` addressed all three process defects, and the correction review passed without a new finding.
- The product observations remain separate future work.
- Nothing in this report establishes live detection efficacy or observed telemetry coverage.
