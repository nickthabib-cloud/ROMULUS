# ROMULUS v2

Defensive, AI-assisted threat-hunting tool for Cyber Protection Team analysts. A deterministic sweep runs over Elasticsearch/OpenSearch host and network logs, Arkime sessions, and PCAPs (TShark). Deterministic expansion follows typed links from the strongest findings. Then an AI agent (planned; any OpenAI-compatible endpoint) develops hypotheses from all the indicators, follows leads, finds more indicators, and writes a cited, labelled AI assessment. Outputs are an attack path, partner recommendations, an executive DOCX, a technical Markdown report, and a web UI.

## Start here (every session)

1. If present, read `docs/project/STATUS.md` → **Resume here**. That is the current state. (STATUS, the spec `ENGINEERING_MASTER_PROMPT.md`, the ADRs in `docs/adr/`, `docs/project/ENVIRONMENT.md` and `docs/eval/` are kept locally and are not in the repository.)
2. The design principles below are non-negotiable; the spec's §1 has the full text where it is available.
3. Team and process: `docs/project/TEAM.md`. Subagents are in `.claude/agents/`.
4. Milestone checklists: `docs/project/MILESTONES.md`. Code map: `docs/architecture/ARCHITECTURE.md` and the generated `docs/architecture/MODULE_MAP.md`.
5. Site-specific setup (hosts, paths, model server, evaluation data) lives in a local, untracked `CLAUDE.local.md`, imported here when present:

@CLAUDE.local.md

## Invariants, short form

- A mention is not an action. Use typed fields only; never substring-match serialized records.
- Strong indicators are reported on their own, immediately. Correlation and attack paths are secondary, and inferred links are labeled as hypotheses.
- Negatives must be complete, or they are `unresolved`. Caps, timeouts, missing fields, and partial responses are never "no match".
- Nothing reportable is lost to UI limits, model context, or rendering. One report manifest feeds every renderer.
- The model proposes typed actions only. It never writes DSL, Arkime expressions, TShark filters, shell commands, or paths. All model output is validated, and telemetry is untrusted data.
- Read-only toward telemetry. No external transmission (one exception: a hosted model used for evaluation on public data only, behind a bootstrap switch). Secrets never appear in the repo, logs, prompts, reports, or memory.

## Detection scope (owner direction)

- Detection breadth is a primary goal. ROMULUS should find any malicious activity the telemetry can show, on any mission network.
- The catalog comes from systematic research, covering:
  - all of MITRE ATT&CK (Enterprise and ICS);
  - an offensive and dual-use tool catalog;
  - living-off-the-land techniques;
  - cross-cutting themes such as process lineage and masquerading;
  - the public detection corpora;
  - every telemetry family a CPT may meet.
- Event IDs, protocols and playbook classes named anywhere are examples, never limits. Don't scope detection work down to them, or to any one evaluation dataset.

## Commands

Filled in as they come to exist. Keep this list accurate.

- Architecture map: `python scripts/archmap.py` (write) / `python scripts/archmap.py --check` (CI gate)
- Tests: `python -m pytest -q -p no:warnings`
- Deploy to a Linux host: `powershell -File scripts/deploy.ps1 -Target <ssh-host> -RemoteHome <path> [-SkipInstall]`
- On the host (`romulus --env-file $ROMULUS_HOME/.env ...`):
  - `doctor`
  - `hunt start --start <ISO> --end <ISO> [--no-agent]`, `hunt resume <id>`, `hunt status [id]`
  - `findings <hunt> [--lane urgent --lane high]`
  - `report <hunt>`
  - `user add <name> --role lead|analyst` (interactive)
  - Web UI: `bash $ROMULUS_HOME/app/scripts/web-restart.sh`

## Working rules

- Work in vertical slices toward the current milestone. Use `reviewer` before merging semantic, security, or adapter changes; a reviewer verdict quoted in a hand-back is not the merge gate. Update STATUS.md (local) before ending a session where state changed.
- Use the status words exactly: `implemented`, `locally tested`, `integration tested`, `lab evaluated`, `holdout evaluated`, `production validated`.
- Keep the repository setup-agnostic: no site hosts, addresses, paths, model names or hardware in tracked files. They belong in `CLAUDE.local.md`, `.env` or local docs.
