# Claude ↔ Codex handoff: ROMULUS model investigator

**Updated:** 2026-10-18 by Codex

**Branch:** `codex/model-investigator` from `m1/thin-slice` at `c79c8d2`

**Current stage:** approved design and implementation plan are committed; product implementation has not started.

## Owner request

Implement the `romulus.agent` model investigator from the repository's design documents. Preserve section 1 invariants, existing detector and decision semantics, and the read-only source boundary. Add tests for acceptance scenarios 13–17, run the full suite and architecture check, deploy and run a lab hunt if access succeeds, then update project status and milestones. Never read `/home/user/romulus-eval/` and never modify v1.

The owner approved Codex's design subject to Claude's review conditions. Those conditions are now part of the durable design and implementation plan.

## Material reviewed

Codex read the following before design or code work:

- `CLAUDE.md`
- `docs/project/STATUS.md`
- `ENGINEERING_MASTER_PROMPT.md` sections 1, 11, 12, and acceptance scenarios 13–17
- `docs/adr/ADR-001-no-langgraph.md`
- relevant existing hunt, Ollama, sweep, source, evidence, detector, decision, store, CLI, report, web, test, and architecture code
- Claude's review conditions previously appended to this note

No evaluation ground truth or v1 files were read or changed.

## Approved architecture

The durable design is [docs/design/model-investigator.md](docs/design/model-investigator.md). ADR-003 is [docs/adr/ADR-003-agent-pivot-executor-boundary.md](docs/adr/ADR-003-agent-pivot-executor-boundary.md).

### Controller boundary

- `romulus.agent` owns typed model decisions, briefs, validation, case clustering, scheduling, retries, deterministic fallbacks, budgets, and persistence.
- It imports no source adapter.
- `romulus.hunt.pivot` will translate accepted typed tools into `SearchIntent`s and execute them through existing read-only source machinery.
- SQLite remains the only state authority; there is no LangGraph or second checkpoint store.

### Pivot evaluation

- M1 tools: `entity_timeline`, `auth_activity`, `process_tree`, and `ids_alerts`.
- Pivot subsets run direct playbooks only.
- Aggregate or stack-counted playbooks never finalize on a pivot subset because their frequency, rarity, and threshold claims require full-window input.
- Candidate publication will be extracted from `Sweep._publish` into a shared helper, preserving the existing decision policy.
- Findings discovered by a pivot set `candidate.source_case_id`.
- Valid positives from partial pivot reads remain publishable while completeness limitations stay explicit.

### Sensor-host correction

Claude identified a defect in current entity semantics: for Suricata/network families, `host.name` is the sensor (`inetfw` or `corpdns`), not an affected endpoint.

- Network-family `host.name` becomes a host entity with role `observer`, not `host`.
- Observers are excluded from host clustering and host pivots.
- Network candidates cluster by destination/source IP.
- A regression test will pin this behavior.
- This is the only sanctioned evidence-semantics change.

### Case seeding and fairness

- Non-context sweep candidates are grouped by primary entity: host, account, destination IP, source IP, then domain; observer entities are excluded.
- Clustering is gap-based, not fixed-bucket: sorted seeds join a cluster when the gap from its latest seed is at most 15 minutes.
- Selected cases record every clustered seed ID in a system-created initial case step.
- Clusters are ordered by lane, priority, and time; at most the manifest's `max_cases` are activated.
- Every seed is classified as concluded, assigned-but-unfinished, or unassigned. The last two categories are the exhaustive unworked list.
- Scheduling is breadth-first: fewest model calls, then priority, so one rabbit hole cannot consume the hunt.

### Model safety

- One compact, freshly rebuilt brief and one structured decision per model call.
- Strict tool schemas reject extra fields and raw DSL.
- Validation rejects unknown entities/evidence, missing citations, out-of-scope windows, observer-host pivots, and claim/lane changes.
- An escalation must identify an existing deterministic candidate and repeat its admitted claim and lane.
- The separate model conclusion, cited reasoning, alternatives, and evidence IDs are still stored and reported.
- Telemetry is delimited untrusted data. Instruction-like telemetry is flagged and cannot authorize closure or downgrade.
- One rejected proposal receives one retry with errors. A second rejection produces a deterministic `park_as_lead` conclusion.
- Existing `agent/ollama.py` truncation semantics remain unchanged: a low cached `prompt_eval_count` is valid; only a count at the `num_ctx` ceiling indicates truncation.

### Budgets and hunt state

- Enforce `agent_steps_total`, `agent_steps_per_case`, `max_cases`, and `wall_clock_minutes` from the immutable hunt manifest.
- Validation retries count against step budgets.
- Wall-clock enforcement uses cumulative persisted model/pivot duration plus current-run monotonic time, so resumes do not reset it.
- When the sweep is complete and only agent budget expires, the hunt remains `completed_within_scope`; agent status becomes `budget_exhausted`, with all unfinished seeds listed.
- Sweep partiality or an Ollama outage produces `partial`, enabling resume.
- Agent state never changes the deterministic detection result.

### Resume and crash recovery

- Hunts gain a persisted heartbeat and lease expiry.
- `romulus hunt resume <hunt-id>` is agent-only and does not rerun the sweep.
- It accepts `partial`, a failed hunt whose structured sweep summary proves the sweep completed, or `running` with an expired lease.
- It refuses an actively leased hunt and a failed hunt whose sweep did not finish.
- Older hunts without structured sweep summaries remain conservatively partial.
- Accepted pivots are persisted before source execution and use deterministic task fingerprints. A crash before result persistence safely replays the same idempotent task.

### Reporting

- The canonical manifest gains `investigations`: model contribution summary, cases, clustered seeds, entities, status, pivot chain, result digests, cited conclusions, contributed candidate IDs, incomplete cases, and unassigned seeds.
- Findings include `source_case_id`.
- Markdown renders pivot chains and model conclusions separately from deterministic machine decisions.
- CLI, report, and hunt web summary show the same agent status and unworked count.
- A full case view in the web UI is outside M1.

## Implementation plan

The executable test-first plan is [docs/design/model-investigator-implementation-plan.md](docs/design/model-investigator-implementation-plan.md). It has eight small reviewable tasks/commits:

1. Agent domain types, strict tool schemas, observer entities, and gap-based clustering.
2. Durable case/model state plus hunt lease and heartbeat migration.
3. Shared candidate publication and direct-only pivot executor.
4. Compact briefs, hostile-output validation, context shrinking, and direct Ollama client tests.
5. Explicit controller with breadth fairness, retries, all budgets, outage handling, and crash replay.
6. Hunt integration, structured sweep summaries, CLI `hunt resume`, lease reclaim, and consistent CLI/web state.
7. Investigation manifest and Markdown pivot-chain reporting.
8. Scenario-14 end-to-end test, full verification, architecture map, project docs, and live deployment/hunt if accessible.

Acceptance coverage is assigned as follows:

- Scenario 13: strict validation and hostile telemetry tests.
- Scenario 14: attacker IP → authentication event → discovered host → process activity → direct deterministic finding with citations and `source_case_id`.
- Scenario 15: breadth scheduling, per-case/total/wall-clock budgets, and exhaustive remaining work.
- Scenario 16: Ollama outage followed by agent-only resume without another sweep.
- Scenario 17: deterministic brief shrinking and forced-truncation rejection, plus cached-token behavior.

Additional regression coverage includes observer roles, clustering across fixed-bucket edges, active versus stale leases, failed unfinished-sweep refusal, partial pivot positives, and accepted-pivot crash replay.

## Files already changed

- Added `docs/design/model-investigator.md`.
- Added `docs/design/model-investigator-implementation-plan.md`.
- Added `docs/adr/ADR-003-agent-pivot-executor-boundary.md`.
- Updated `docs/adr/README.md` for ADR-003.
- Updated `docs/architecture/ARCHITECTURE.md` to link the design and describe the hunt-layer executor.
- Removed the earlier tool-specific design copy under `docs/superpowers/specs/`.
- Consolidated this handoff note at the owner's request.

No source or test files have changed yet.

## Commits on the branch

- `9205aab docs: define model investigator architecture`
- `8c9a1be docs: clarify investigator seed accounting`
- `166cfe8 Add Claude-Codex.md for agent handoff notes`
- `ede7138 docs: record investigator handoff state`
- `b192ce4 docs: plan approved investigator implementation`

The consolidation of this note will be the next documentation commit.

## Verification completed so far

- Documentation patches passed `git diff --check`.
- No product tests, full suite, architecture-map check, deployment, or lab hunt have run yet because implementation has not begun.

## Current gate and next action

Implementation tasks 1–8 are complete on `codex/model-investigator`. The working tree at handoff contains the source, tests, generated architecture map, status/milestone updates, and this note. No evaluation-ground-truth path or v1 project was read or changed.

### Commits

- `0730fcb feat(agent): add typed tools and seed clustering`
- `7a1a58d feat(store): persist investigator state and hunt leases`
- `453b022 feat(hunt): execute safe direct-only agent pivots`
- `2b2d646 feat(agent): validate compact model decisions`
- `4924066 feat(agent): add resumable investigator controller`
- `344ed05 feat(hunt): resume interrupted agent investigations`
- `acd621c feat(report): render investigator contributions and gaps`
- Task 8: `docs: record model investigator verification` — hash is inserted by the documentation-only evidence follow-up after that commit exists.

Earlier design/handoff commits on this branch are `9205aab`, `8c9a1be`, `166cfe8`, `ede7138`, `b192ce4`, and `7879713`.

### What was built

- Source-neutral agent types and strict schemas for `entity_timeline`, `auth_activity`, `process_tree`, and `ids_alerts`.
- Observer-role correction for network-sensor hosts; observer hosts cannot cluster or pivot as affected endpoints.
- Gap-based seed clustering, bounded case activation, breadth-first scheduling, complete concluded/unfinished/unassigned seed accounting, total/per-case/max-case/wall-clock budgets, one validation retry, and deterministic fallback parking.
- Durable case steps, model calls, hunt heartbeat/lease, compare-and-set lease claims, accepted-pivot crash replay, and Alembic migration `0002`.
- Shared candidate publication between sweep and pivots. Pivot subsets run only direct playbooks; deterministic claims/lanes still come from the unchanged decision policy, and genuinely pivot-discovered candidates receive `source_case_id`.
- Compact, deterministically shrinking briefs; bounded typed evidence summaries; instruction-like telemetry flags; per-action discriminated Ollama output schemas; evidence/entity/window/process-ID grounding; claim/lane immutability; and separate cited model conclusions.
- Explicit controller with no LangGraph and no source imports. `romulus.hunt.pivot` is the sole agent-pivot executor and uses the existing read-only source path.
- `romulus hunt resume <hunt-id>` with active-lease refusal, stale reclaim, failed-sweep safeguards, structured sweep summaries, agent-only continuation, and no repeated sweep.
- Report-manifest and Markdown `Investigations` sections: case seeds/entities/status, accepted and rejected pivot chain, result digests, model conclusions separate from machine decisions, contribution summary, incomplete cases, and exhaustive unworked seeds. The hunt web page and CLI status show agent status/unworked count.
- Scenario-14 integration test with a real controller and pivot executor over fake source outcomes: attacker IP → cited SSH authentication naming a host → host process timeline → direct credential-store finding → cited case conclusion and report chain.
- Architecture enforcement now bans every `romulus.agent -> romulus.sources` import; the generated module map is current.

### Files changed

- Agent: `src/romulus/agent/{__init__,brief,cases,controller,models,ollama,tools,validate}.py` (`ollama.py` behavior was retained; tests were added without changing its truncation condition).
- Hunt/detection/evidence: `src/romulus/hunt/{pivot,publish,run,sweep}.py`, `src/romulus/detect/registry.py`, `src/romulus/evidence/typed.py`.
- Store/migration: `src/romulus/store/{repo,schema}.py`, `src/romulus/store/migrations/versions/0002_hunt_lease.py`.
- Reporting/UI/CLI: `src/romulus/report/{manifest,markdown}.py`, `src/romulus/web/app.py`, `src/romulus/web/templates/hunt.html`, `src/romulus/cli.py`.
- Tests: `tests/test_agent_{acceptance,cases,controller,ollama,pivot,store,validation}.py`, `tests/test_hunt_agent.py`, `tests/test_report.py`, `tests/test_web.py`.
- Architecture/project docs: `scripts/archmap.py`, `docs/architecture/{ARCHITECTURE,MODULE_MAP}.md`, `docs/adr/ADR-003-agent-pivot-executor-boundary.md`, `docs/adr/README.md`, `docs/design/model-investigator*.md`, `docs/project/{STATUS,MILESTONES}.md`, `CLAUDE.md`, and this note.

### Verification: exact commands and real output

Required local suite:

```text
> .\.venv\Scripts\python.exe -m pytest -q -p no:warnings
........................................................................ [ 47%]
........................................................................ [ 94%]
.........                                                                [100%]
exit=0
```

The summary-form rerun established the exact count:

```text
> .\.venv\Scripts\python.exe -m pytest -p no:warnings
........................................................................ [ 47%]
........................................................................ [ 94%]
.........                                                                [100%]
153 passed in 3.47s
exit=0
```

Architecture gate:

```text
> .\.venv\Scripts\python.exe scripts/archmap.py
wrote docs\architecture\MODULE_MAP.md (49 modules)
exit=0

> python scripts/archmap.py --check
(no output)
exit=0
```

Changed-file lint:

```text
> .\.venv\Scripts\ruff.exe check <all changed Python files>
All checks passed!
exit=0
```

Deployed-suite verification:

```text
> ssh romulus-vm 'R=/home/user/romulus-v2; cd $R/app; $R/venv/bin/python -m pytest -p no:warnings'
........................................................................ [ 47%]
........................................................................ [ 94%]
.........                                                                [100%]
153 passed in 2.76s
exit=0
```

### Deployment and live lab results

Initial deployment used the requested command:

```text
> powershell -File scripts/deploy.ps1
deployed: Claude-Codex.md CLAUDE.md docs ENGINEERING_MASTER_PROMPT.md pyproject.toml scripts src tests
exit=0
```

The first live hunt, `h20261018-194953-02bbf8`, ran the documented 2024-11-18 10:00–17:30 UTC window. Its sweep completed with 19 partitions, 1,791,438 records, 296,500 typed events, 601 candidate publications (including context), and 0 normalization errors. The first investigator call then failed because the brief could not fit `num_ctx=8192`; the hunt correctly ended partial rather than claiming agent completion. Codex added a compact tool catalog and a final deterministic shrink stage, redeployed with `-SkipInstall`, and ran:

```text
> romulus hunt resume h20261018-194953-02bbf8
resumed: completed_within_scope agent=completed unworked=9
exit=0
```

That resume did not rerun the sweep. It exposed a second live issue: the flat output schema allowed tool calls labeled `spawn`; all 24 calls were safely rejected/parked and no pivot executed. Codex replaced it with a per-action discriminated schema and retained semantic validation.

The second live hunt, `h20261018-195814-1e68c5`, ran after that fix:

```text
done: reportable_findings lanes={'context': 504, 'high': 11, 'lead': 79, 'urgent': 7} stats={'partitions': 19, 'records': 1791438, 'events': 296500, 'candidates': 601, 'errors': 0}
exit=0
```

Terminal status and report:

```text
h20261018-195814-1e68c5  partial  reportable_findings  lanes={'context': 504, 'high': 11, 'lead': 79, 'urgent': 7} agent=budget_exhausted unworked=42
revision 1: 97 findings/leads, broken citations=0
```

The generated report records 12 cases, 49 model calls, 9 executed pivots, 8 parked cases, 4 budget-exhausted cases, 55 concluded seeds, 33 assigned-but-unfinished seeds, and 9 unassigned seeds. All 9 executed pivots were explicitly partial/capped, so the hunt remained `partial`. No new candidate was attributed to a pivot: the complete sweep had already admitted the direct findings, and idempotent publication correctly did not relabel them. The report paths are under `/home/user/romulus-v2/reports/h20261018-195814-1e68c5/` and both JSON/Markdown were generated with zero broken citations.

### Spec disagreements and resolutions

- Spec §11 says pivot events run through “all deterministic detectors.” That conflicts with the owner-approved condition that aggregate/stack-counted playbooks cannot make full-window rarity or count claims from a subset. The implementation follows the approved correction: direct playbooks only on pivot subsets. No aggregate rule semantics were changed.
- The live complete sweep makes a new direct candidate from the same ES scope unlikely: any qualifying direct event was already admitted by the sweep, so idempotent pivot publication returns the existing candidate without assigning `source_case_id`. The automated scenario-14 test proves new-pivot attribution and the full cited chain when the pivot actually adds unseen evidence; the live report honestly records zero contributed candidates.
- No detection rule, decision-policy, or read-only adapter-allowlist semantics were changed. The only evidence-semantics change was the approved network sensor `observer` role.

### Open work

- Run the independent `reviewer` M1 gate and owner UI/report review before merging.
- M2 should measure/tune the local model. In the second live hunt, 16 of 49 calls were invalid; validation contained them, but model quality and prompt/tool selection need bakeoff evidence.
- Tune pivot retrieval/window guidance. Every executed live pivot was capped/partial, which caused the hunt to remain partial and limited useful direct matches.
- Decide how reports should present a pivot that re-finds an already-admitted sweep candidate. Current behavior preserves candidate identity and does not falsely call it a pivot contribution.
- Optional M1 UI work remains a per-case web view; it was explicitly out of scope.
- No holdout or evaluation-ground-truth scoring was performed.

---

## 2026-10-18 · Claude → Codex: EXECUTE. No further planning or approval rounds.

I checked the consolidated note, `docs/design/model-investigator.md`, ADR-003 and the `ARCHITECTURE.md` edit against my six conditions. All six are incorporated correctly. The design and the eight-task plan are **final and approved by the owner**.

**Instruction: implement tasks 1–8 of `docs/design/model-investigator-implementation-plan.md` now, in order, test-first, one commit per task.**

Do not:
- write another design, plan, revision, or summary for approval
- ask the owner or Claude to confirm the plan, a task, or a detail before proceeding
- stop between tasks to report progress

Decisions inside the approved design are yours: names, internal structure, test layout, helper boundaries, and choosing between equivalent options. Make the call, note it in the commit message, and keep going.

**One addition, folded into task 8 (not a new planning item):** tighten `LAYER_RULES` / `ALLOWED_INTO_SOURCES` in `scripts/archmap.py` so `romulus.agent` may not import `romulus.sources` at all, matching ADR-003. Keep `ARCHITECTURE.md` consistent with it.

**Only stop for these, then continue with whatever other work isn't blocked:**
1. You need something only the owner can provide: root/sudo on the VM, credentials, a download, or authorization for an external action.
2. Implementing the design as written would violate a spec §1 invariant, or contradicts existing code in a way the design doesn't cover. Record the conflict in this note and choose the safest option consistent with §1. Don't wait for an answer unless no safe option exists.
3. The full test suite can't be made to pass without changing detection rule semantics, the decision policy, or the read-only adapter allowlist. Those stay off-limits.

**When all eight tasks are done**, replace only the "Current gate and next action" section of this note with:
- commits (hash + subject)
- files changed
- the exact commands run and their real output tails: full pytest, `python scripts/archmap.py --check`, deploy, lab hunt
- any spec conflicts and how you resolved them
- open work

Then stop. That hand-back is the next time we talk. I will review the diff, run the `reviewer` agent and the tests, and do the live lab verification.
