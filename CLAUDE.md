# ROMULUS v2

Defensive, AI-assisted threat-hunting tool for USAF CPT analysts. A deterministic sweep runs over Elasticsearch/OpenSearch host and network logs, Arkime sessions, and PCAPs (TShark). Then a local Ollama model works the leads: it pivots on entities, follows hypotheses, and escalates with citations. Outputs are an attack path, partner recommendations, an executive DOCX, a technical Markdown report, and a web UI.

## Start here (every session)

1. Read `docs/project/STATUS.md` → **Resume here**. That is the current state.
2. The spec is `ENGINEERING_MASTER_PROMPT.md`. §1 invariants are non-negotiable.
3. Team and process: `docs/project/TEAM.md`. Subagents are in `.claude/agents/`.
4. Milestone checklists: `docs/project/MILESTONES.md`. Decisions: `docs/adr/`. Code map: `docs/architecture/ARCHITECTURE.md` and the generated `docs/architecture/MODULE_MAP.md`. Lab facts: `docs/project/ENVIRONMENT.md`.

## Invariants, short form

- A mention is not an action. Use typed fields only; never substring-match serialized records.
- Strong indicators are reported on their own, immediately. Correlation and attack paths are secondary, and inferred links are labeled as hypotheses.
- Negatives must be complete, or they are `unresolved`. Caps, timeouts, missing fields, and partial responses are never "no match".
- Nothing reportable is lost to UI limits, model context, or rendering. One report manifest feeds every renderer.
- The model proposes typed actions only. It never writes DSL, Arkime expressions, TShark filters, shell commands, or paths. All model output is validated, and telemetry is untrusted data.
- Read-only toward telemetry. No external transmission. Secrets never appear in the repo, logs, prompts, reports, or memory.

## Detection scope (owner direction)

- Detection breadth is a primary goal. ROMULUS should find any malicious activity the telemetry can show, on any mission network.
- The catalog comes from systematic research, covering:
  - all of MITRE ATT&CK (Enterprise and ICS);
  - an offensive and dual-use tool catalog;
  - living-off-the-land techniques;
  - cross-cutting themes such as process lineage and masquerading;
  - the public detection corpora;
  - every telemetry family a CPT may meet.

  See spec §7 *Detection breadth*.
- Event IDs, protocols and playbook classes named in the spec are examples, never limits. Don't scope detection work down to them.

## Environment

- Develop on Windows (this folder). Deploy and run on the Ubuntu VM: SSH alias `romulus-vm` (`192.168.36.128`). Ollama is at `http://192.168.36.1:11434`.
- From PowerShell, run remote scripts with `scp` to `/tmp/` and then `ssh romulus-vm bash /tmp/x.sh`. Don't pipe scripts into `ssh` (that adds a BOM and CRLF).
- The VM's sudo needs the owner's password. Ask the owner to run root commands.
- **Never touch v1** (`C:\Users\nthca\Documents\ChatGPT\romulus_old`, VM `/home/user/ROMULUS`) except to read it for lessons.
- Ground truth is at VM `/home/user/romulus-eval/`. Only the `eval-custodian` reads it.

## Commands

Filled in as they come to exist. Keep this list accurate.

- Architecture map: `python scripts/archmap.py` (write) / `python scripts/archmap.py --check` (CI gate)
- Local tests (Windows): `.\.venv\Scripts\python -m pytest -q -p no:warnings`
- Deploy to VM: `powershell -File scripts/deploy.ps1` (add `-SkipInstall` when dependencies are unchanged)
- On the VM (`R=/home/user/romulus-v2; $R/venv/bin/romulus --env-file $R/.env ...`):
  - `doctor`
  - `hunt start --start <ISO> --end <ISO> [--no-agent]`, `hunt resume <id>`, `hunt status [id]`
  - `findings <hunt> [--lane urgent --lane high]`
  - `report <hunt>`
  - `user add <name> --role lead|analyst` (interactive; run with `ssh -t`)
  - Web UI: `bash $R/app/scripts/web-restart.sh` → `http://192.168.36.128:8443`

## Working rules

- Work in vertical slices toward the current milestone. Use `reviewer` before merging semantic, security, or adapter changes. Update STATUS.md before ending a session where state changed.
- Use the spec's status words exactly: `implemented`, `locally tested`, `integration tested`, `lab evaluated`, `holdout evaluated`, `production validated`.
