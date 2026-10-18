# ROMULUS status

## Resume here

_Last updated: 2026-10-18 by Codex._

- **Current milestone:** M1, implemented and locally tested on branch `codex/model-investigator`; the investigator is also integration tested on the VM. Reviewer and owner-demo gates remain open.
- **State:**
  - Sweep → decisions → coverage ledger → report manifest (immutable revisions, citation integrity) → technical Markdown/JSON → web UI (login, live stream, finding detail with highlighted raw evidence, triage, reports).
  - The local suite includes acceptance scenarios 13–17, hostile input, budget/fairness, lease/resume, crash replay, direct-only pivots, and investigation reporting.
  - Lab hunt `h20261018-181953-decca8` (SL700 e_a, 10:00–17:30 UTC): `completed_within_scope`, 1,791,438 records evaluated, 0 parse errors, 7 urgent / 11 high / 79 leads / 504 context, 0 broken citations.
  - Investigator lab hunt `h20261018-195814-1e68c5`: the complete sweep evaluated 1,791,438 records and 296,500 typed events with 0 errors; the model made 49 calls and executed 9 pivots. Eight cases parked after two invalid proposals, four exhausted their case budgets, and every one of 97 seeds was accounted for (55 concluded, 33 assigned unfinished, 9 unassigned). All executed pivots were explicitly partial, so the hunt ended `partial`; the report had 0 broken citations.
  - Web UI: `http://192.168.36.128:8443` (plain HTTP lab exception); restart with `scripts/web-restart.sh`.
- **Model investigator:**
  - **Implemented, locally tested, and integration tested.** The explicit controller uses SQLite state, clustered cases, breadth-first scheduling, typed tools, strict validation, one retry plus deterministic fallback, cumulative budgets, Ollama truncation checks, and durable model/case/pivot records.
  - `romulus hunt resume <hunt-id>` performs agent-only recovery under an active/stale lease policy and never reruns the sweep. New hunts retain a structured sweep summary.
  - Pivot subsets run direct playbooks only through the hunt-layer executor. Aggregate playbooks remain full-window only. Pivot publications use the sweep's shared deterministic policy and set `source_case_id` for genuinely new candidates.
  - Reports contain an Investigations section with seed accounting, case status, pivot chain/results, cited model conclusions separate from machine decisions, contributions, and incomplete work.
  - Live model quality remains a measured risk: on `h20261018-195814-1e68c5`, 16 of 49 calls were invalid and all 9 executed pivots were capped/partial. No new candidate was attributed to a pivot because the complete sweep had already admitted the applicable direct findings.
- **Next three actions:**
  1. Run the `reviewer` M1 gate, with special attention to model proposal quality, pivot caps, lease behavior, and report semantics.
  2. Owner reviews the web UI and live report, including the explicit 42-seed unworked list.
  3. Begin M2 model bakeoff and evaluation; tune the compact prompt/tool choice against fixed tasks before changing the default model or budgets.
- **Blockers:** no implementation blocker. M1 sign-off still requires reviewer and owner-demo gates.
- **Owner decisions pending:**
  - Load SL700 `f_a` as the holdout (download ≈3.7 GB from Zenodo).
  - Separate Malcolm VM (≈16 GiB) for M4.
  - Resize the VM to 12 GiB / 8 vCPU before M3.

## Milestone summary

| Milestone | State | Evidence |
|---|---|---|
| Pre-M1 setup | done | this file, TEAM.md, `.claude/agents/`, ENVIRONMENT.md |
| M1 thin end-to-end slice | integration tested | local acceptance suite; lab hunt `h20261018-195814-1e68c5`; reviewer and owner demo remain |
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

- **2026-10-18 (model investigator)**:
  - Implemented the eight-task investigator plan: source-neutral schemas and clustering; durable cases/model calls/leases; direct-only pivot execution; compact hostile-input-safe briefs; strict action and citation validation; explicit fair controller; agent-only resume; and investigation reporting.
  - Added ADR-003 and enforced the boundary that `romulus.agent` cannot import any `romulus.sources` module; source access lives in `romulus.hunt.pivot`.
  - Automated scenario 14 proves attacker IP → authentication host → host process → direct deterministic finding with citations and `source_case_id`. Scenarios 13, 15, 16, and 17 cover hostile inputs, budgets/fairness, outage/resume, and context/truncation behavior.
  - First live run `h20261018-194953-02bbf8` exposed an oversized brief; deterministic final shrinking fixed it, and agent-only resume completed without rerunning the sweep. The same run exposed a flat output-schema ambiguity; per-action discriminated output schemas fixed tool calls mislabeled as `spawn`.
  - Second live run `h20261018-195814-1e68c5` executed 9 model pivots and produced a zero-broken-citation report. It honestly ended partial because all executed pivots were capped; 42 seeds remained unworked and were listed exhaustively.

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
