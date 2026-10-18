# ROMULUS status

## Resume here

_Last updated: 2026-10-18 by lead._

- **Current milestone:** pre-M1 (project setup complete; M1 not started).
- **State:** spec rewritten and owner-reviewed; lab surveyed; team, agents, and project docs created; no product code yet.
- **Next three actions:**
  1. Owner installs Git for Windows (`winget install --id Git.Git -e`) and `uv` (see ENVIRONMENT.md). Then the lead runs `git init` with an initial commit and creates a matching bare repo or deploy path on the VM.
  2. M1 step 1: package skeleton (`pyproject.toml`, `src/romulus/`), config loading from `.env`, `doctor` against ES, Arkime, Ollama, and TShark on the VM.
  3. M1 step 2: ES source profile and field contract from the live `romulus-*-sl700-e-a` mapping; the first typed normalizers (linux.audit, apache.access, suricata.eve.*).
- **Blockers:** none for M1. Git and uv are missing on Windows (owner install).
- **Owner decisions pending:**
  - Load SL700 `f_a` as the holdout (download ≈3.7 GB from Zenodo).
  - Separate Malcolm VM (≈16 GiB) for M4.
  - Resize the VM to 12 GiB / 8 vCPU before M3.

## Milestone summary

| Milestone | State | Evidence |
|---|---|---|
| Pre-M1 setup | done | this file, TEAM.md, `.claude/agents/`, ENVIRONMENT.md |
| M1 thin end-to-end slice | not started | |
| M2 evaluation and model bakeoff | not started | |
| M3 full sources and coverage truth | not started | |
| M4 detection depth (incl. Zeek, ICS, Malcolm) | not started | |
| M5 synthesis and reports | not started | |
| M6 hardening and holdout | not started | |

## Open risks

| Risk | Impact | Mitigation |
|---|---|---|
| Lab data is one small, Linux-only storyline (SL700); all SL700 variants share attacker scripts | Overfitting; weak generalization claims | f_a holdout plus at least one different-storyline dataset before claiming general effectiveness |
| Lab mapping was produced by v1's custom importer, not a standard shipper | Field contracts may not transfer to real mission data | Profile-driven field contracts; add standard-shipper fixtures (Elastic Agent, Winlogbeat, Zeek, Malcolm) |
| 8 GiB VRAM limits model size and context | Weak agent judgment | Bakeoff (spec §12); one decision per call; digests instead of raw dumps |
| AttackMate timestamps have no stated timezone | Misaligned scoring | eval-custodian aligns against telemetry before scoring |
| No Malcolm or ICS-protocol data in the lab | ICS playbooks only fixture-tested | Public ICS PCAPs; Malcolm VM in M4 |
| VM RAM headroom ~4.6 GiB | Hunts compete with ES and Kibana | nice'd TShark, bounded concurrency; resize before M3 |

## Session log

Newest first. One entry per session where state changed: what was done, what was verified and how, and what was decided.

- **2026-10-18**: Created the project folder. Critiqued and rewrote the Codex master prompt (no LangGraph; agent-centric loop; aggregation-first sweep; web UI; DOCX/Markdown reports; ICS/Zeek/Malcolm; measured model bakeoff). Surveyed the VM, ES, Arkime, and Ollama (facts in ENVIRONMENT.md). Located the e_a ground truth (AttackMate) and extracted it to `/home/user/romulus-eval/sl700_e_a/`. Confirmed no ICS protocols in SL700 PCAPs. Set up the dedicated SSH key and `romulus-vm` alias. Defined the team (lead plus four agents) and the project docs.
