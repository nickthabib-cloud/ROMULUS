# ROMULUS status

## Resume here

_Last updated: 2026-10-18 by Codex (M1 gate re-run fix handoff)._

- **M1 reviewer gate: RE-RUN FIXES COMPLETE; not merged; reviewer re-run pending (2026-10-18).** The first gate failed, and its first re-run passed the investigator with issues but still failed core.
  - Claude fixed core B1–B5 and the `.env` inline-comment session-secret bug in `7d019b9`. `2663e1d` merges auditd split long-argv EXECVE records (32 linpeas records in the attack window had been silently mishandled), scopes partiality per event family, and fixes `deploy.ps1`, which had silently uploaded a stale archive.
  - Model-off lab hunt `h20261018-221847-d52592`: `completed_within_scope`, 102,457 exec records evaluated, 0 normalization errors, 0 broken citations.
  - Codex implemented and locally verified the assigned core B6/B7 and investigator B1/B2/B3 fixes in `6b4d2b1` through `5c3efc1`. The fixes preserve quoted shell punctuation, evaluate interpreter indicators before shape collapse, reject host-scoped `ids_alerts`, fence workers with lease-owner tokens, and keep validation fallbacks explicitly unworked as `fallback_parked` with analyst flags.
  - Fresh lab verification on deployed commit `13f0a43`: model-off hunt `h20261018-224208-b2cc27` and agent hunt `h20261018-224406-923663` both completed within scope over 10:00–17:30 UTC with 1,791,438 records, 296,500 typed events, 0 normalization errors, and 0 broken citations.
  - Claude fixed cross-partition sequence raw retention in `b332dac`. Codex then fixed the five gate re-run findings in `8b274fe` through `82c1372`: shell comments/escapes/heredocs, explicit partial coverage for unmodelled shell syntax, owner-fenced pivot data writes, resume-preflight lease cleanup, and IP-only `ids_alerts` validation/catalog entries.
  - Gate re-run verification deployed clean commit `8a09957`. Model-off hunt `h20261018-232714-ad664a` completed within scope over 10:00–17:30 UTC with the unchanged 7 urgent / 11 high counts, 1,791,438 records, 296,500 typed events, 0 normalization errors, and report r1 with 0 broken citations.
  - Important findings from the gate are still open (the next round after these Blocking items): I2/I3 (sequence order, interpreter-from-stdin requirement), I5 (per-target source failure handling, retries), I7 (typed events/raw copies shared across hunts), I8/I9 (Markdown newlines, CLI ANSI escapes), I10 (context items absent from the manifest), I12/I13 (index-name substring scoping, naive timestamps), I14 (no ingestion watermark), I15 (`ignore_above`), and investigator I1–I7.
  - Next: re-run the reviewer gate; merge `codex/model-investigator` into `m1/thin-slice` only if it passes.

- **Current milestone:** M1, implemented and locally tested on branch `codex/model-investigator`; the investigator and its pivot fix round are integration tested on the VM. Reviewer and owner-demo gates remain open.
- **State:**
  - Sweep → decisions → coverage ledger → report manifest (immutable revisions, citation integrity) → technical Markdown/JSON → web UI (login, live stream, finding detail with highlighted raw evidence, triage, reports).
  - The 232-test local suite includes acceptance scenarios 13–17, hostile input, shell-data/unevaluable parsing regressions, budget/fairness, owner-fenced lease/resume and pivot persistence, crash replay, direct-only pivots, and investigation reporting.
  - Lab hunt `h20261018-181953-decca8` (SL700 e_a, 10:00–17:30 UTC): `completed_within_scope`, 1,791,438 records evaluated, 0 parse errors, 7 urgent / 11 high / 79 leads / 504 context, 0 broken citations.
  - Fix-round lab hunt `h20261018-211924-b1edf9`: `completed_within_scope` / `reportable_findings`; the complete sweep evaluated 1,791,438 records and 296,500 typed events with 0 errors. The model made 52 calls, executed 2 complete pivots, and had 4 duplicate pivot proposals blocked before source execution. The attacker-IP `ids_alerts` pivot returned 969/969 alert records with complete coverage and no cap. All 97 seeds were accounted for; 43 remained unworked. Report revision 1 contained 97 findings/leads and 0 broken citations.
  - Gate-fix model-off hunt `h20261018-224208-b2cc27`: `completed_within_scope` / `reportable_findings`; 7 urgent, 11 high, 79 leads, 504 context; 0 errors; agent disabled with all 97 seeds unworked; report r1 had 0 broken citations.
  - Gate-fix agent hunt `h20261018-224406-923663`: `completed_within_scope` / `reportable_findings`; the investigator ended `budget_exhausted` after 54 model calls, 3 pivots (1 partial), and 9 rejected pivot proposals. Eight cases became `fallback_parked` with analyst flags, four cases exhausted budgets, no seed concluded, 88 seeds were assigned-but-unfinished, 9 were unassigned, and all 97 remained explicitly unworked. Report r1 had 0 broken citations.
  - Gate re-run model-off hunt `h20261018-232714-ad664a`: `completed_within_scope` / `reportable_findings`; 7 urgent, 11 high, 79 leads, 504 context; 1,791,438 records, 296,500 typed events, 0 errors; report r1 had 97 findings/leads and 0 broken citations.
  - Web UI: `http://192.168.36.128:8443` (plain HTTP lab exception); restart with `scripts/web-restart.sh`.
- **Model investigator:**
  - **Implemented, locally tested, and integration tested.** The explicit controller uses SQLite state, clustered cases, breadth-first scheduling, typed tools, strict validation, one retry plus deterministic fallback, cumulative budgets, Ollama truncation checks, and durable model/case/pivot records.
  - `romulus hunt resume <hunt-id>` performs agent-only recovery under an active/stale lease policy and never reruns the sweep. New hunts retain a structured sweep summary.
  - Pivot subsets run direct playbooks only through the hunt-layer executor. Aggregate playbooks remain full-window only. Pivot publications use the sweep's shared deterministic policy and set `source_case_id` for genuinely new candidates.
  - Reports contain an Investigations section with seed accounting, case status, pivot chain/results, cited model conclusions separate from machine decisions, contributions, and incomplete work.
  - Source-family constraints, whole-window/anchor sampling, exact covered and unresolved ranges, and normalized duplicate-pivot rejection are implemented. Pivot gaps remain visible in Investigations but no longer make a complete-sweep hunt partial.
  - Live model quality remains a measured risk: on `h20261018-211924-b1edf9`, 4 of 12 cases exhausted their step budgets, 43 seeds remained unworked, and no pivot contributed a new candidate. Case `case-fddc19830be15d0c` was seeded with the 15:16 UTC root SSH login and later `videoserver` activity, but the model used all 8 calls without a pivot or conclusion; no accepted pivot independently reached that later host activity. This is an effectiveness gap, not hidden as an execution or coverage failure.
  - The newer `h20261018-224406-923663` run makes the risk more visible rather than hiding it: 8 validation fallbacks are now analyst-flagged and unfinished, all 97 seeds remain in the unworked partition, and no pivot contributed a candidate. One pivot was partial. This is an investigator-effectiveness issue for the reviewer/model bakeoff, not a sweep completeness or citation-integrity failure.
- **Next three actions:**
  1. Run the `reviewer` M1 gate, with special attention to model proposal quality, lease behavior, exact pivot coverage, and report semantics.
  2. Owner reviews the web UI and fresh live report, including the explicit 43-seed unworked list and the model's failure to act on seeded post-login `videoserver` activity.
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
| M1 thin end-to-end slice | integration tested | 232-test suite; latest model-off lab hunt `h20261018-232714-ad664a`; reviewer re-run and owner demo remain |
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

- **2026-10-18 (M1 gate re-run fix round)**:
  - Fixed shell data/code separation for escaped punctuation, comments, and heredocs; made parse failures, command substitutions, and heredocs produce partial detector coverage rather than complete negatives.
  - Fenced pivot task/evidence/candidate persistence by lease owner, closed resume preflight failures without leaving a live lease, and restricted `ids_alerts` schemas/catalog text to IP entities.
  - Verified the 232-test suite with `.\\.venv\\Scripts\\python -m pytest -q -p no:warnings`; `.\\.venv\\Scripts\\python scripts\\archmap.py --check` passed. Deployed clean commit `8a09957` with `scripts/deploy.ps1 -SkipInstall`.
  - Model-off hunt `h20261018-232714-ad664a` swept 1,791,438 records into 296,500 events with 0 normalization errors, retained the expected 7 urgent / 11 high counts, and produced report r1 with 97 findings/leads and 0 broken citations.

- **2026-10-18 (M1 gate fix round)**:
  - Fixed quoted shell-operator parsing/newline separation; made web-service interpreter indicators per-event and indicator-first; made host-scoped `ids_alerts` explicitly unsupported; added durable lease-owner fencing and sweep/pivot heartbeats; and changed validation fallbacks to `fallback_parked` with unworked accounting and analyst flags in CLI, reports, and web.
  - Verified `210 tests` locally with `.\\.venv\\Scripts\\python -m pytest -q -p no:warnings`; `python scripts/archmap.py --check` passed. Deployed commit `13f0a43` with `scripts/deploy.ps1 -SkipInstall`; did not run the test suite on the VM.
  - Model-off hunt `h20261018-224208-b2cc27` and agent hunt `h20261018-224406-923663` each swept 1,791,438 records into 296,500 events with 0 normalization errors and reports with 0 broken citations. The agent run exposed a remaining effectiveness gap: `budget_exhausted`, 54 calls, 3 pivots (1 partial), 8 analyst-flagged fallback cases, and all 97 seeds unworked.

- **2026-10-18 (investigator pivot fix round)**:
  - Constrained every investigator tool to its supported event families at source query time; added shared-PIT head/tail and anchor sampling, exact half-open coverage ranges, and fail-closed consistency checks for dense capped windows.
  - Added per-case normalized duplicate-pivot rejection and restored the approved state rule: pivot gaps are investigation results, while only sweep incompleteness, missing sweep evidence, or model unavailability make the hunt partial.
  - Verified 176 tests and the architecture map locally, deployed without reinstalling, repeated all 176 tests on the VM, and ran fresh hunt `h20261018-211924-b1edf9` over 10:00–17:30 UTC.
  - The attacker-IP alert pivot completed once at 969/969 with no cap; two repeat proposals were rejected without source execution. The hunt completed within scope and report r1 had 0 broken citations. A case contained both the 15:16 root SSH seed and later `videoserver` evidence, but the model exhausted 8 calls without acting on it; 43 seeds remained unworked.

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
