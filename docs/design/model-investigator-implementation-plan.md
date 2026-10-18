# Model Investigator Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the durable M1 model investigator, safe typed pivots, agent-only resume, and investigation reporting required by acceptance scenarios 13–17.

**Architecture:** `romulus.agent` owns model judgment and durable case state but no source adapter. `romulus.hunt.pivot` executes validated requests through existing read-only source machinery, evaluates only direct playbooks, and shares candidate publication with the sweep.

**Tech Stack:** Python 3.12+, Pydantic 2, SQLAlchemy Core/Alembic, httpx/Ollama, pytest.

**Spec:** `docs/design/model-investigator.md`

## Global Constraints

- Preserve spec section 1 invariants, detector semantics, decision policy, and the source write-method allowlist.
- Never read `/home/user/romulus-eval/` or modify v1.
- Model output is untrusted; no raw DSL, shell, paths, invented evidence, lane changes, or claim changes.
- Pivot subsets evaluate direct playbooks only; all work and omissions remain durable and reportable.
- Use the manifest's immutable `agent_steps_total`, `agent_steps_per_case`, `max_cases`, and `wall_clock_minutes` budgets.
- Keep `agent/ollama.py` truncation threshold semantics unchanged.

## Review Focus

- Sensor `host.name` on network events must remain an `observer` and never become a victim-host pivot.
- A crash after accepting a pivot but before saving its result must replay one deterministic task without duplicate evidence or findings.
- Partial pivot reads must retain valid positives while reporting the incomplete result.
- Malformed, extra-field, out-of-scope, uncited, nonexistent-evidence, and prompt-injected proposals must execute nothing.
- Active hunt leases must refuse resume; expired leases and older hunts without sweep summaries must fail conservatively.

---

### Task 1: Agent domain types, tool schemas, and seed clustering

**Files:**
- Create: `src/romulus/agent/models.py`
- Create: `src/romulus/agent/tools.py`
- Create: `src/romulus/agent/cases.py`
- Modify: `src/romulus/evidence/typed.py`
- Test: `tests/test_agent_cases.py`

**Interfaces:**
- Produces: `EntityRef`, `SeedCluster`, `AgentDecision`, `ToolRequest`, `PivotResult`, strict argument models for the four M1 tools, `parse_tool_request(decision) -> ToolRequest`, and `cluster_seed_candidates(candidates, gap=timedelta(minutes=15)) -> list[SeedCluster]`.
- Network families expose `host.name` as `("host", value, "observer")`; clustering ignores observers and uses gap-from-latest grouping.

- [ ] Write failing tests for the observer regression, destination/source-IP precedence, and two seeds 2 seconds across a clock-bucket edge joining the same cluster.
- [ ] Run `.\.venv\Scripts\python -m pytest tests/test_agent_cases.py -q -p no:warnings`; expect missing modules/failed observer assertions.
- [ ] Implement the domain models, strict `extra="forbid"` tool schemas, entity precedence, and gap clustering.
- [ ] Re-run the focused test; expect all tests to pass.
- [ ] Commit: `feat(agent): add typed tools and seed clustering`.

### Task 2: Durable case state and hunt leases

**Files:**
- Modify: `src/romulus/store/schema.py`
- Modify: `src/romulus/store/repo.py`
- Create: `src/romulus/store/migrations/versions/0002_hunt_lease.py`
- Test: `tests/test_agent_store.py`

**Interfaces:**
- Produces: `Repo.claim_hunt(hunt_id, lease_seconds, resume=False, now=None) -> dict`, `heartbeat_hunt(hunt_id, lease_seconds, now=None)`, `latest_audit(hunt_id, action) -> dict | None`, case CRUD/step methods keyed by case ID, model-call methods keyed by call ID, and `agent_elapsed_ms(hunt_id) -> int`.
- `claim_hunt(..., resume=True)` accepts `partial`, `failed`, or `running` only when its persisted lease expired; terminal transitions clear the lease.

- [ ] Write failing repository tests for active/expired leases, valid transitions, idempotent deterministic case creation, pending pivot steps, and ordered model-call history.
- [ ] Run `.\.venv\Scripts\python -m pytest tests/test_agent_store.py -q -p no:warnings`; expect schema/API failures.
- [ ] Add the migration, table metadata, and transactional repository methods.
- [ ] Re-run the focused test; expect all tests to pass.
- [ ] Commit: `feat(store): persist investigator state and hunt leases`.

### Task 3: Shared publication and the direct-only pivot executor

**Files:**
- Create: `src/romulus/hunt/publish.py`
- Create: `src/romulus/hunt/pivot.py`
- Modify: `src/romulus/hunt/sweep.py`
- Modify: `src/romulus/detect/registry.py`
- Test: `tests/test_agent_pivot.py`

**Interfaces:**
- Produces: `publish_match(repo, hunt_id, playbook, match, task_id, raw_sources, source_case_id=None) -> dict | None`, `fresh_direct_pack()`, and `PivotExecutor.run(case_id, request) -> PivotResult`.
- Pivot task IDs and fingerprints derive from case ID plus canonical tool arguments. `PivotResult` contains task/event/candidate IDs, discovered entities, bounded event summaries, completeness reasons, and duration.

- [ ] Write failing tests proving direct findings use the shared policy and `source_case_id`, aggregate playbooks never finalize on a pivot subset, IP timelines query network sides plus a safe journal superset, and partial outcomes retain positives.
- [ ] Run `.\.venv\Scripts\python -m pytest tests/test_agent_pivot.py -q -p no:warnings`; expect missing executor/helper failures.
- [ ] Extract publication without changing its row semantics, add `fresh_direct_pack`, and implement typed intent building, execution, normalization, local tool filtering, persistence, and compact result digests.
- [ ] Re-run `tests/test_sweep.py tests/test_agent_pivot.py`; expect all tests to pass.
- [ ] Commit: `feat(hunt): execute safe direct-only agent pivots`.

### Task 4: Brief construction, validation, and Ollama failure coverage

**Files:**
- Create: `src/romulus/agent/brief.py`
- Create: `src/romulus/agent/validate.py`
- Test: `tests/test_agent_validation.py`
- Test: `tests/test_agent_ollama.py`

**Interfaces:**
- Produces: `build_brief(repo, case_id, tool_catalog, num_ctx, max_out=900, retry_errors=()) -> BuiltBrief` and `validate_decision(decision, brief_context, hunt_window) -> ValidationResult`.
- `BuiltBrief` carries system/user text, known candidates/evidence/entities, injection flags, shrink actions, and token estimate.

- [ ] Write failing scenario-13 tests for raw DSL/extra fields, uncited and nonexistent evidence, out-of-scope windows, observer-host pivots, claim/lane changes, and telemetry-instruction-driven closure.
- [ ] Write failing scenario-17 Ollama tests: low cached `prompt_eval_count` succeeds, a count at `num_ctx - TRUNCATION_MARGIN` fails as truncated, length-limited output fails, and an oversized brief shrinks deterministically.
- [ ] Run both focused files; expect missing brief/validator failures while documenting current Ollama behavior.
- [ ] Implement bounded briefs, injection flagging, shrink stages, strict semantic validation, and error feedback without changing the existing truncation condition.
- [ ] Re-run both focused files; expect all tests to pass.
- [ ] Commit: `feat(agent): validate compact model decisions`.

### Task 5: Explicit controller, fairness, budgets, and crash replay

**Files:**
- Create: `src/romulus/agent/controller.py`
- Modify: `src/romulus/agent/__init__.py`
- Test: `tests/test_agent_controller.py`

**Interfaces:**
- Produces: `Investigator(settings, repo, pivot_executor, hunt_id, window, model_client=None, heartbeat=None, clock=None).run() -> dict` with statuses `completed`, `budget_exhausted`, `unavailable`, or `failed`.
- Model calls, validation retries, accepted decisions, deterministic fallbacks, conclusions, and result digests are persisted before subsequent transitions.

- [ ] Write failing tests for one-call breadth before depth, retries counting toward step budgets, bounded spawn, complete unworked-seed accounting, wall-clock exhaustion across resumed persisted duration, outage leaving cases open, and replay of an accepted pivot lacking a result.
- [ ] Run the focused file; expect missing controller failures.
- [ ] Implement deterministic seeding, round-robin scheduling, model-call logging, validation/retry/fallback, action transitions, cumulative budgets, heartbeat calls, and pending-pivot replay.
- [ ] Re-run the focused file; expect all tests to pass.
- [ ] Commit: `feat(agent): add resumable investigator controller`.

### Task 6: Hunt integration and agent-only resume

**Files:**
- Modify: `src/romulus/hunt/run.py`
- Modify: `src/romulus/cli.py`
- Modify: `src/romulus/web/app.py`
- Modify: `src/romulus/web/templates/hunt.html`
- Test: `tests/test_hunt_agent.py`
- Modify: `tests/test_web.py`

**Interfaces:**
- Produces: `resume_hunt(settings, hunt_id) -> dict`; `romulus hunt resume <hunt-id>` never invokes `Sweep`.
- New runs audit `hunt.sweep_summary`. Budget exhaustion with complete sweep ends `completed_within_scope`; outage or sweep partiality ends `partial`. CLI, report data, and web summary use the latest `hunt.agent_summary`.

- [ ] Write failing scenario-16 tests for outage then resume without sweep calls, active lease refusal, expired-lease reclaim, eligible failed-agent resume, rejection of a failed unfinished sweep, old missing sweep-summary conservatism, and budget-exhausted state semantics.
- [ ] Run the focused hunt/web tests; expect missing resume/status failures.
- [ ] Integrate leases, heartbeat, structured sweep audit, pivot executor/controller construction, final-state rules, CLI parsing/output, and web agent summary.
- [ ] Re-run the focused hunt/web tests; expect all tests to pass.
- [ ] Commit: `feat(hunt): resume interrupted agent investigations`.

### Task 7: Investigation manifest and Markdown chain

**Files:**
- Modify: `src/romulus/report/manifest.py`
- Modify: `src/romulus/report/markdown.py`
- Modify: `tests/test_report.py`

**Interfaces:**
- Produces: manifest key `investigations` with summary, cases, conclusions, pivot steps, contributed candidate IDs, and exhaustive seed partitions; findings include `source_case_id`.

- [ ] Write failing tests that every non-context seed appears exactly once, pivot-discovered findings link to their case chain, cited model conclusions remain separate from machine claims, and hostile strings render inert.
- [ ] Run `.\.venv\Scripts\python -m pytest tests/test_report.py -q -p no:warnings`; expect missing investigation data/section failures.
- [ ] Build investigations from the consistent report transaction inputs and render model contribution, chains, conclusions, and unworked work without re-evaluating evidence.
- [ ] Re-run the focused report tests; expect all tests to pass.
- [ ] Commit: `feat(report): render investigator contributions and gaps`.

### Task 8: End-to-end acceptance, architecture, and project handoff

**Files:**
- Create: `tests/test_agent_acceptance.py`
- Modify: `docs/architecture/MODULE_MAP.md` via generator
- Modify: `docs/project/STATUS.md`
- Modify: `docs/project/MILESTONES.md`
- Append: `Claude-Codex.md`

**Interfaces:**
- Proves scenario 14 with real controller and pivot executor over fake source outcomes: attacker IP -> authentication host -> host process -> direct deterministic finding with a full cited case chain.

- [ ] Write and run the scenario-14 integration test; expect failure until all chain details and citations connect.
- [ ] Fix only integration defects exposed by that test, then rerun all agent tests.
- [ ] Run `python scripts/archmap.py`, then `python scripts/archmap.py --check`; expect a current map and no layer violations.
- [ ] Run `.\.venv\Scripts\python -m pytest -q -p no:warnings`; record the exact pass count.
- [ ] Update STATUS, MILESTONES, and append a dated Codex handoff entry with files, commits, exact test output, disagreements, live-run results, and open work.
- [ ] Commit: `docs: record model investigator verification`.
- [ ] Deploy with `powershell -File scripts/deploy.ps1` and run a VM hunt from CLAUDE.md if access succeeds; never read evaluation ground truth, and record exact commands/output in the handoff. Commit any resulting documentation-only evidence separately.
