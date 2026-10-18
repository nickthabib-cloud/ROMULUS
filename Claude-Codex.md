# Codex handoff: model investigator

## Current state

- Date: 2026-10-18
- Branch: `codex/model-investigator`, created from `m1/thin-slice` at `c79c8d2`.
- Stage: design is written and awaiting owner approval. No investigator implementation or test changes have been made yet.
- Never read `/home/user/romulus-eval/` and never touched the v1 project.

## Work completed

Read the required project material before designing anything:

- `CLAUDE.md`
- `docs/project/STATUS.md`
- `ENGINEERING_MASTER_PROMPT.md` sections 1, 11, 12, and acceptance scenarios 13–17
- `docs/adr/ADR-001-no-langgraph.md`
- the existing hunt, Ollama, sweep, source, evidence, detector, decision, store, report, CLI, test, and architecture code relevant to integration

Created and committed:

- `docs/superpowers/specs/2026-10-18-model-investigator-design.md`
- `docs/adr/ADR-003-agent-pivot-executor-boundary.md`

Commits:

- `9205aab docs: define model investigator architecture`
- `8c9a1be docs: clarify investigator seed accounting`

## Approved conversational design and owner conditions

The owner approved the architectural direction subject to these requirements, all now recorded in the written design:

1. `romulus.agent` owns structured decisions, briefs, validation, scheduling, retries, fallbacks, and persistence. It imports no source adapter. A hunt-layer executor translates accepted tools to typed `SearchIntent`s.
2. Pivot subsets run only direct playbooks. Aggregate and stack-counted playbooks are excluded because their counts and rarity claims require full-window input. Candidate publication will be extracted from `Sweep._publish` into a shared helper, and pivot candidates will set `source_case_id`.
3. Non-context candidates are clustered by a primary shared entity and a 15-minute UTC bucket. Entity precedence is host, account, destination IP, source IP, then domain. At most the manifest's `max_cases` clusters are activated. Every seed is reported as concluded, assigned-but-unfinished, or unassigned; the latter two form the complete unworked-seed list.
4. The scheduler is breadth-first across cases: fewest steps used, then priority. It enforces per-case and total-step budgets.
5. Add agent-only `romulus hunt resume <hunt-id>`. It must use the existing `partial -> running` transition, rebuild contracts, continue open cases, and not rerun the sweep. New hunts persist a structured sweep summary; old hunts without one stay conservatively partial.
6. The model cannot change a deterministic candidate's claim or lane. Its separate case conclusion, cited reasoning, alternatives, and evidence IDs are still stored and rendered.
7. The report manifest and Markdown renderer gain an Investigations section with case seeds, entities, statuses, pivot chains, result digests, model conclusions, model-contribution totals, incomplete work, and unassigned seed IDs. A web case view is optional and excluded from M1.
8. M1 tools are `entity_timeline`, `auth_activity`, `process_tree`, and `ids_alerts`. `entity_timeline` supports IPs against network telemetry and hosts against host telemetry. An IP pivot may retrieve a safe journal superset and locally filter normalized authentication events, avoiding an invented IP-to-host mapping.
9. All tool arguments use strict schemas. Validation rejects raw DSL or extra fields, unknown entities/evidence, missing citations, out-of-scope windows, unsupported claim/lane changes, and unsafe reactions to instructions embedded in telemetry. One retry is allowed; a second validation failure deterministically parks the case as a lead.
10. Keep `agent/ollama.py` truncation semantics unchanged: low `prompt_eval_count` can result from caching and is valid; only a count at the `num_ctx` ceiling signals truncation. Add direct client tests.
11. Acceptance tests must cover scenarios 13–17, including the attacker-IP -> authentication -> host process -> direct-rule chain, case breadth and remaining work, outage/resume without a second sweep, context shrinking, and forced truncation.
12. Update `docs/project/STATUS.md` and `docs/project/MILESTONES.md`, run the complete local test suite and architecture check, deploy and run a lab hunt if available, and report only commands that actually ran.

## Architecture decision

ADR-003 places source execution in the hunt layer. This preserves the explicit controller from ADR-001 while preventing model orchestration from becoming a second adapter path. The executor uses existing read-only source execution, normalization, evidence persistence, and shared candidate publication. No layer-rule relaxation is planned.

## Remaining workflow

1. Owner reviews and approves the written design at `docs/superpowers/specs/2026-10-18-model-investigator-design.md` and ADR-003.
2. Write and commit the detailed implementation plan.
3. Implement test-first on `codex/model-investigator` in small commits.
4. Run `\.\.venv\Scripts\python -m pytest -q -p no:warnings` and `python scripts/archmap.py --check`.
5. Run the requested deployment and lab hunt if the environment permits it, recording exact output without reading evaluation ground truth.
6. Update project status, milestones, and this handoff with the final file list, commits, test/live output, spec disagreements, and open work.

## Approval gate

Do not begin implementation yet. The written design has not yet received the owner's explicit approval.
