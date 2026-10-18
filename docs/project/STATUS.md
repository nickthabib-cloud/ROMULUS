# ROMULUS status

## Resume here

_Last updated: 2026-10-18 by lead._

- **Current milestone:** M1, mostly done, on branch `m1/thin-slice`. Everything except the model investigator is implemented and integration tested on the VM.
- **State:**
  - Sweep → decisions → coverage ledger → report manifest (immutable revisions, citation integrity) → technical Markdown/JSON → web UI (login, live stream, finding detail with highlighted raw evidence, triage, reports).
  - 107 tests pass locally and on the VM.
  - Lab hunt `h20261018-181953-decca8` (SL700 e_a, 10:00–17:30 UTC): `completed_within_scope`, 1,791,438 records evaluated, 0 parse errors, 7 urgent / 11 high / 79 leads / 504 context, 0 broken citations.
  - Web UI: `http://192.168.36.128:8443` (plain HTTP lab exception); restart with `scripts/web-restart.sh`.
- **Model investigator:**
  - **Not implemented.** `agent/ollama.py` (structured-output client with truncation detection) exists.
  - The pivot-tool and controller modules were not written: an automated safety check on the assistant side stopped that generation twice, and the assistant was instructed not to retry it. Owner permission does not change that.
  - `hunt/run.py` records `agent.status = not_available` and reports leads as not agent-investigated.
  - This needs an owner decision on how the investigator gets built (see Owner decisions pending).
- **Next three actions:**
  1. Owner creates their web account (see CLAUDE.md commands) and reviews the UI and the report.
  2. `reviewer` pass on M1 (semantics, coverage, web security), then fix Blocking items.
  3. Owner decision on the model investigator path, then M2 (gold inventory and evaluation harness via eval-custodian).
- **Blockers:** the model investigator, as above.
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

- **2026-10-18 (M1 build)**:
  - Built the M1 slice except the investigator.
  - Live findings drove fixes:
    - auditd hex decoding of numeric fields
    - per-hunt candidate identity
    - stack counting for web-user executions (23,619 → 1 context item per routine shape)
    - downloader→interpreter sequence rule (the cron and SSH-key persistence)
    - per-host grouping of firewall changes
    - per-source/destination grouping of Suricata alerts
    - empty-argv handling
    - adaptive partition splitting (two capped partitions in the attack window previously left ~200k records unevaluated, correctly reported as partial)
  - Verified against AttackMate ground truth informally (eval-custodian has not scored it yet). Missed: discovery commands after the SSH login (agent-pivot territory) and the editor-based cron edit (no file-write telemetry rule). Found: every other step.
- **2026-10-18**: Created the project folder. Critiqued and rewrote the Codex master prompt (no LangGraph; agent-centric loop; aggregation-first sweep; web UI; DOCX/Markdown reports; ICS/Zeek/Malcolm; measured model bakeoff). Surveyed the VM, ES, Arkime, and Ollama (facts in ENVIRONMENT.md). Located the e_a ground truth (AttackMate) and extracted it to `/home/user/romulus-eval/sl700_e_a/`. Confirmed no ICS protocols in SL700 PCAPs. Set up the dedicated SSH key and `romulus-vm` alias. Defined the team (lead plus four agents) and the project docs.
