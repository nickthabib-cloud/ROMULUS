# How the ROMULUS team works

ROMULUS is built by one **lead** (the main Claude Code session) with four specialist subagents defined in `.claude/agents/`. This file is the operating manual. Keep it short and keep it true.

## Why this team, and no bigger

v1 had seven roles, task-packet templates, tabletop reviews of those packets, and reviews of the reviews. It produced paperwork while the core matcher still used substring checks. Its own tabletop review found the main failure modes: packets reused across roles, upstream roles claiming combined success, and downstream roles redoing upstream work.

A role earns a slot here only if it does at least one of these:

1. **Independence**: someone other than the author has to check the work (review, evaluation).
2. **Information isolation**: someone must hold knowledge the builders must not see (holdout labels).
3. **Context isolation**: deep, bulky work that would flood the lead's context (detection research, VM log digging).

Everything else, including architecture, implementation, UI, and reports, is the lead's job. The lead may implement through a general-purpose subagent for a well-scoped mechanical task, but there is no standing "developer" role.

| Agent | Why it exists | Writes | Never |
|---|---|---|---|
| `detection-engineer` | Context isolation; specialist semantics | `content/` (playbooks, rules, fixtures, selection cards), detector code under `src/romulus/detect/` when briefed | Reads ground truth; tunes against holdout; claims recall |
| `reviewer` | Independence | A review report (returned in its final message) | Edits code; approves its own suggestions |
| `eval-custodian` | Information isolation and independence | `eval/` harness code, `docs/eval/` results (aggregate only), the ground-truth directory (outside the repository) | Shares labels, per-opportunity answers, or holdout contents with the builders; changes rules or prompts |
| `integration-tester` | Context isolation (deployment host and live services) | Deployment and integration logs, local environment facts | Writes to Elasticsearch, Arkime, or PCAPs; runs root commands; changes source configs |

Security review uses the `/security-review` skill plus the `reviewer` with a security brief. UI and report design are lead work, checked by the owner at milestone demos.

## Delegation rules

1. **One brief per delegated turn**, written for that role only. Never reuse a brief across roles.
2. Every brief contains:
   - **Goal**: one or two sentences.
   - **Context**: spec sections and files to read (paths, not pasted content).
   - **Scope**: exact files and directories the agent may change, and what it must not touch.
   - **Acceptance**: what "done" means *for this stage only*. Stages do not claim combined or milestone acceptance; only the lead does that.
   - **Return**: summary; files changed; commands run with real results; open issues; anything that contradicts the spec.
3. Downstream agents **consume** upstream output and report additions and disagreements; they don't redo it.
4. Parallel subagents never edit the same files.
5. The lead **verifies** every report before recording it: read the diff, rerun the key command. A subagent's report is a claim, not evidence.
6. No subagent spawns its own subagents.

## Definition of done (any change)

- Tests for the change exist and pass locally. Semantic changes also add adversarial negative fixtures.
- `python scripts/archmap.py --check` passes (architecture map current).
- `reviewer` has reviewed any change touching detection semantics, coverage accounting, admission/decision policy, agent validation, adapters, or security boundaries. Blocking findings are fixed or explicitly accepted by the owner.
- `docs/project/STATUS.md` is updated: what changed, what was verified and how, and what is next.
- Decisions that are hard to reverse have an ADR in `docs/adr/`.
- Integration claims use only the words the spec allows (`implemented`, `locally tested`, `integration tested`, `lab evaluated`, `holdout evaluated`, `production validated`).

## Milestone gate (lead only)

At the end of each milestone, the lead:

1. Checks every item in `docs/project/MILESTONES.md` for that milestone, with evidence links.
2. Asks `reviewer` for a whole-milestone review against spec §1 and §15 gates.
3. Asks `eval-custodian` for a metrics run (from M2 on).
4. Demos to the owner, records the outcome and the owner's decisions in STATUS.md, then starts the next milestone.

## Session continuity

If a chat is lost, a new lead session must be able to resume from the repository alone:

1. `CLAUDE.md` (auto-loaded) points to everything.
2. `docs/project/STATUS.md` → **Resume here** section: current milestone, in-flight work, next three actions, blockers.
3. `docs/project/MILESTONES.md`: acceptance checklist with evidence.
4. `docs/adr/`: why things are the way they are.
5. `docs/architecture/ARCHITECTURE.md` + generated `MODULE_MAP.md`: what exists and how it connects.
6. `docs/project/ENVIRONMENT.md`: lab facts.

The lead updates STATUS.md **before** ending any session where state changed, not only at milestones.
