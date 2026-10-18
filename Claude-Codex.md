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

The owner approved the amended design and instructed Codex to proceed. The implementation plan has been written and committed. Codex asked the owner to confirm that the plan captures the desired work; native execution is required because multi-agent execution is disabled in this session.

After confirmation, Codex should use the execution and TDD workflows, implement tasks 1–8 in order, make the planned small commits, run the exact verification commands, attempt the authorized deployment/lab hunt without reading ground truth, and replace this final section with actual results and open work.
