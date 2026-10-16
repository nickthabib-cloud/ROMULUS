# ROMULUS Agent Orchestration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Install a discoverable, indicator-first agent operating model with seven specialized roles, bounded task packets, proportional delegation, and evidence-based handoffs.

**Architecture:** The root `AGENTS.md` owns project-wide priorities and points coordinating agents to `agents/README.md`. The README owns orchestration policy, `agents/task-template.md` owns assignment and return contracts, and seven role files own specialized behavior. This project changes repository instructions only; ROMULUS runtime code and intelligence data remain unchanged.

**Tech Stack:** Markdown repository instructions, Git, PowerShell content checks

**Spec:** `docs/superpowers/specs/2026-10-15-romulus-agent-orchestration-design.md`

## Global Constraints

- Indicator discovery, ranking, evidence quality, noise control, telemetry coverage, and useful escalation remain primary.
- Correlation enriches findings but does not require a coherent attack path.
- Attack-path analysis is secondary and is labeled as a hypothesis unless directly supported.
- Telemetry integrations remain read-only.
- An assignment authorizes work only within its explicit task-packet boundaries.
- Test creation and test execution are separate explicit permissions in every task packet.
- Only one agent owns a file set during an editing wave.
- Unrelated untracked files and product code are not modified.
- No automated product tests are added or run for this documentation-only project.

## Review Focus

- A future coordinating agent sees the role system from the root instructions and can locate every role without prior conversation context.
- Small tasks do not trigger all seven roles, while high-impact query, scoring, evidence, persistence, and reporting changes receive independent audit.
- Assigned agents proceed within their packet without asking for authorization already granted there.
- Detection content cannot be described as executed merely because it exists, loads, or appears in a reference catalog.
- Hunt analysis starts with indicators and retains valuable findings even when no coherent attack path exists.

---

### Task 1: Install the orchestration entry point and task contract

**Files:**
- Modify: `AGENTS.md`
- Create: `agents/README.md`
- Create: `agents/task-template.md`

**Interfaces:**
- Consumes: The product priorities already defined in `AGENTS.md` and the approved orchestration design.
- Produces: A discoverable role index, delegation matrix, authorization model, concurrency rules, workflow recipes, and reusable assignment/return template used by every later task.

- [ ] **Step 1: Update `AGENTS.md` with the delegation entry point**

Add a concise `Agent delegation` section that:

- points to `agents/README.md` and `agents/task-template.md`;
- requires every delegated role to read `AGENTS.md` first;
- states that role agents are invoked explicitly and do not start automatically;
- requires proportional delegation and non-overlapping file ownership;
- carries the indicator-first and coverage-truth requirements into every assignment.

- [ ] **Step 2: Create `agents/README.md`**

Include these sections:

- purpose and instruction hierarchy;
- seven-role index with links;
- task-type delegation matrix from the specification;
- task-packet usage and authorization semantics;
- read-only and writing-role boundaries;
- concurrency and file-ownership rules;
- workflow recipes for small maintenance, new detection content, runtime integration, audits, and hunt analysis;
- agent return contract and lead reconciliation responsibilities;
- failure and blocking behavior.

- [ ] **Step 3: Create `agents/task-template.md`**

Provide one copyable template containing the ten assignment fields and five return fields from the specification. Include explicit checkboxes or values for edits, test creation, test execution, network research, live-source access, commits, and external actions.

- [ ] **Step 4: Verify the entry point and contract**

Run:

```powershell
rg -n "Agent delegation|agents/README.md|agents/task-template.md|indicator|attack.path" AGENTS.md agents/README.md agents/task-template.md
```

Expected: all three files expose the delegation entry point, indicator-first priority, and task contract; the task template contains every authorization category.

- [ ] **Step 5: Review and commit Task 1**

Review only these three files for contradictions and unintended product requirements. Commit them together with:

```text
docs: add agent delegation framework
```

---

### Task 2: Rewrite the lead and platform developer roles

**Files:**
- Modify: `agents/lead.md`
- Modify: `agents/developer.md`

**Interfaces:**
- Consumes: Role-selection and task-packet rules from Task 1.
- Produces: A coordinating role that routes work proportionally and a writing role that proves runtime reachability and bounded implementation behavior.

- [ ] **Step 1: Rewrite `agents/lead.md`**

Require the lead to:

- read the root and orchestration instructions;
- establish current behavior from evidence;
- create complete task packets;
- select the smallest sufficient role set;
- prevent overlapping edits;
- distinguish work actually delegated from proposed assignments;
- reconcile findings and acceptance criteria;
- continue independent work when one deliverable is blocked;
- request user input only for genuine unresolved decisions or dependencies.

Remove the permanent first-assignment repository inventory. Allow direct handling of trivial documentation or coordination work while assigning product implementation to a writing role.

- [ ] **Step 2: Rewrite `agents/developer.md` as the platform developer role**

Require the developer to:

- treat a bounded assignment as authorization;
- trace the relevant call path before editing;
- identify the runtime consumer and reachability evidence;
- preserve read-only telemetry, deterministic evidence gates, provenance, bounds, and integration contracts;
- avoid unrelated refactors and unverified deletion;
- distinguish loaded content from executed behavior;
- return changed files, evidence, acceptance status, limitations, and next action.

- [ ] **Step 3: Verify the role boundaries**

Run:

```powershell
rg -n "first assignment|smallest sufficient|task packet|runtime|loaded|executed|repeated|authorization" agents/lead.md agents/developer.md
```

Expected: the old first-assignment instruction is absent; task authorization, proportional delegation, runtime reachability, and coverage truth are explicit.

- [ ] **Step 4: Review and commit Task 2**

Have a fresh reviewer compare both files with the specification and Task 1 contracts. Commit with:

```text
docs: specialize lead and developer agent roles
```

---

### Task 3: Rewrite the verification and audit roles

**Files:**
- Modify: `agents/tester.md`
- Modify: `agents/auditor.md`

**Interfaces:**
- Consumes: Authorization categories and return contract from Task 1.
- Produces: Independent verification and audit roles with ROMULUS-specific coverage and evidence requirements.

- [ ] **Step 1: Rewrite `agents/tester.md`**

Require the tester to:

- read the task packet's separate test-creation and test-execution permissions;
- perform read-only test review when execution is not authorized;
- evaluate positive and negative matches, backend syntax, missing telemetry, unsupported semantics, provenance, deduplication, priority, noise, sequence entity constraints, bounds, restart behavior, and reporting distinctions as applicable;
- report exact commands and outcomes only when execution is authorized;
- avoid representing offline or mocked results as live-source success.

- [ ] **Step 2: Rewrite `agents/auditor.md`**

Require the auditor to:

- remain read-only;
- inspect the diff and surrounding call paths;
- review backend validity, runtime reachability, disconnected intelligence, duplicated ownership, coverage claims, ranking, noise controls, and indicator-first reporting;
- consider dynamic dispatch, adapters, CLI paths, generated assets, and tests before declaring code unused;
- return severity-ordered findings with references, evidence, failure scenario, and suggested correction;
- distinguish verified defects, hypotheses, coverage, and gaps.

- [ ] **Step 3: Verify independent-review semantics**

Run:

```powershell
rg -n "test creation|test execution|read.only|backend|runtime reachability|disconnected|severity|live" agents/tester.md agents/auditor.md
```

Expected: authorization and read-only boundaries are explicit, and both roles contain ROMULUS-specific review criteria.

- [ ] **Step 4: Review and commit Task 3**

Have a fresh reviewer compare the roles with the approved quality gates. Commit with:

```text
docs: strengthen tester and auditor agent roles
```

---

### Task 4: Add the three ROMULUS specialist roles

**Files:**
- Create: `agents/threat-researcher.md`
- Create: `agents/detection-engineer.md`
- Create: `agents/hunt-analyst.md`

**Interfaces:**
- Consumes: Project priorities, orchestration policy, task template, and existing intelligence status semantics.
- Produces: Specialized research, backend-aware detection design, and indicator-first hunt analysis outputs.

- [ ] **Step 1: Create the threat researcher role**

Define read-only research output for each candidate: behavior, evidence basis, telemetry and fields, platform, backend, priority, confidence, benign uses, narrowing conditions, relational opportunities, provenance, and limitations. Require implementable proposals instead of undifferentiated indicator lists.

- [ ] **Step 2: Create the detection engineer role**

Require backend-valid Elasticsearch or Arkime retrieval, explicit cross-event time/entity/order semantics, authoritative post-collection evaluation, live-consumer identification, priority and noise rationale, and honest unsupported/reference-only status.

- [ ] **Step 3: Create the hunt analyst role**

Require analysis of searches, evidence, ranking, coverage, missed indicators, noise, and follow-up. Findings come first; correlation enriches them; attack-path hypotheses appear last. The analyst returns implementation gaps to the lead and does not silently edit product code.

- [ ] **Step 4: Verify all seven roles**

Run:

```powershell
$files = Get-ChildItem -File agents/*.md | Where-Object Name -NotIn @('README.md','task-template.md')
$files | Select-Object Name
rg -l "AGENTS.md" agents/*.md
rg -l "Result|Evidence|Acceptance|Limitations|Next action" agents/*.md
```

Expected: exactly seven role files exist; every role reads the root instructions and implements the common return contract.

- [ ] **Step 5: Review and commit Task 4**

Have a fresh reviewer check role overlap, missing responsibilities, and contradictions. Commit with:

```text
docs: add romulus specialist agent roles
```

---

### Task 5: Perform the read-only orchestration tabletop

**Files:**
- Create: `docs/superpowers/reviews/2026-10-15-romulus-agent-orchestration-tabletop.md`

**Interfaces:**
- Consumes: The installed instructions, task template, and all seven role files.
- Produces: An evidence-based evaluation of whether the new system yields complete assignments and useful handoffs without product edits.

- [ ] **Step 1: Prepare two read-only task packets**

Create one Windows behavior scenario involving event and script telemetry and one Linux behavior scenario involving process and command telemetry. Authorize repository reading only. Do not authorize product edits, test creation, test execution, live-source access, commits, or external actions.

- [ ] **Step 2: Run the role walkthroughs**

Task agents according to the installed delegation rules. Evaluate whether the roles produce:

- telemetry and field requirements;
- backend-specific retrieval recommendations;
- runtime consumer and status analysis;
- priority and expected-noise rationale;
- direct-behavior versus incidental-text distinctions;
- correlation opportunities that do not suppress standalone findings;
- explicit limitations and next actions;
- no repeated authorization request.

- [ ] **Step 3: Write the tabletop report**

Record the two task packets, roles invoked, returned evidence, acceptance status, contradictions, duplicated work, missing fields, and any instruction corrections made. Do not present the tabletop as live detection efficacy.

- [ ] **Step 4: Validate documentation consistency**

Run:

```powershell
rg -n "TBD|TODO|FIXME" AGENTS.md agents docs/superpowers/reviews/2026-10-15-romulus-agent-orchestration-tabletop.md
git diff --check
git status --short
```

Expected: no placeholders or whitespace errors in changed files; only intended orchestration and tabletop files are included in the task commits; unrelated existing files remain untouched.

- [ ] **Step 5: Review and commit Task 5**

Have a final reviewer compare the complete change with the specification and report any remaining severity-ordered findings. Correct in-scope documentation defects, repeat the content checks, and commit with:

```text
docs: validate romulus agent orchestration
```

## Completion evidence

Before declaring the project complete, report:

- every created or modified file;
- the seven installed roles;
- delegation and authorization rules;
- tabletop roles and outcomes;
- review findings and corrections;
- the fact that no ROMULUS runtime code, detection content, product tests, or live telemetry were changed or executed;
- any remaining limitations or follow-on product work.
