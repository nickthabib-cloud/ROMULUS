# ROMULUS status

## Resume here

_Last updated: 2026-10-19 by Claude (lead), M2 started: protocol and e_a gold v1 done._

- **M1 gate: concluded with owner decision "option B" (2026-10-19).** Seven gate rounds on the shell/argv path showed one structural cause: every host rule assured its *negative* by interpreting text (argv[0], argv operands, script parses), and an adversarial reviewer can always find another form. Option B makes negatives honest by construction:
  - All 10 host rules and `net.tool_user_agent_http` are positive-only (`assures_negative = False`): their findings, lanes and lab results are unchanged; coverage reads "not assessable by design" with a per-rule reason, never "complete". Network rules (typed fields) keep real negatives.
  - Negative assurance for host behaviour moves to M3: kernel-recorded auditd PATH (item 0 = the file actually executed, incl. `#!` scripts), `nametype=CREATE` writes, CWD, and watch keys. `EXEC_COMPANIONS` currently omits PATH.
  - Option 2 before it (2026-10-18) made script-text rules positive-only; option B extends the same principle to argv.
  - **Merged 2026-10-19:** `m1/thin-slice` fast-forwarded to `codex/model-investigator` at `a76f155` after the final scoped check ("can any rule claim a negative it cannot prove?"). Its three Blocking findings (legacy stored cells rendering complete, DNS answer records counted as evaluated, self-reported user agent assuring a negative) and the malformed-EVE crash were fixed in `a76f155` and verified with the reviewer's own reproduction probes; no Blocking item is open. **M1 accepted 2026-10-19** after the owner demo (report walkthrough of `h20261019-093029-32dfef`, owner explored the web UI). Carried into M2: uv lockfile (generate on the VM); cadence check should tolerate missed runs (the 8 TODO.md cron runs skip two 15-minute slots, so no 'regular cadence' note); lead volume (80 leads incl. benign boot-time activity) to be measured by M2 evaluation; the investigator has not yet added findings on the lab (M2 model bakeoff).
- **Lab baseline (model-off, SL700 e_a 10:00–17:30 UTC):** `completed_within_scope`, 1,791,438 records, 296,500 events, 0 normalization errors, 0 broken citations, 7 urgent / 10 high / 80 lead / 504 context. The ZoneMinder exploit payload is a lead because its injected commands share a shell line with unmodelled `$(...)`; its spawned children are urgent.
- **Follow-ups (not blocking M1):**
  - M3 kernel-record rules: exec-from-temp via PATH item 0; authorized_keys writes and /etc/shadow reads via PATH/watch records; restore the exploit payload to high via process-tree evidence (its shell has child execs, proving the line ran).
  - Gate leftovers: interpreter location via PATH when no exe (I1); `ncat --lua-exec`; `busybox awk -f`; exec_from_temp_dir wording for failed execs (SYSCALL.exe is the caller); `script_from_temp_dir` should cite `process.executable` over argv[0] (I1 of last check); non-absolute/`(null)` exe values should be unevaluable (I2 of last check).
  - Earlier gate Important items still open: per-target source failure retries (I5), typed events/raw copies shared across hunts (I7), Markdown newlines and CLI ANSI escapes (I8/I9), context items absent from the manifest (I10), index-name substring scoping (I12), naive timestamps (I13), ingestion watermark (I14), `ignore_above` (I15), sshd-session journal identifier (gate N4), investigator I1–I7.
  - Model quality (M2 bakeoff): ~33% invalid model outputs; agent has contributed no new findings on the lab yet.
- **Process notes:** Claude does not edit the shell parser or the investigator (an assistant-side safety check stopped that work); those go to Codex via `Claude-Codex.md` (replace Claude's last message; date+time headers; execute-only rounds).

- **Owner direction, 2026-10-19: detection breadth is a primary goal.** The tool must find any malicious activity, anywhere. The catalog comes from systematic research:
  - a full ATT&CK Enterprise + ICS technique walk;
  - an offensive and dual-use tool catalog (behavior first, names as leads);
  - living-off-the-land coverage based on context and rarity;
  - cross-cutting themes;
  - the public detection corpora;
  - every telemetry family. The spec's example event IDs, protocols and playbook classes are samples, not limits. Recorded in:
  - spec intro and §7 *Detection breadth*;
  - §15 breadth datasets and metrics;
  - §17 milestones: research starts by M3 and may begin during M2; M4 is the bulk; standing work continues after M6;
  - MILESTONES.md, CLAUDE.md, and the `detection-engineer` brief.
- **Owner request, 2026-10-19: a detection catalog page in the web UI.** It shows everything being searched (ATT&CK, tools, LOTL, themes, telemetry), applicability to the current sources, per-rule performance and gaps. Analysts add to the catalog in three tiers:
  - indicator lists;
  - detection requests with "flag more like this";
  - a structured local-rule builder (never DSL), promoted by a `lead`.

  The design is in spec §7 *Detection catalog page*. The page and tiers 1–2 are in M4; tier 3 is in M6.
- **Current milestone:** M2 (evaluation harness and model bakeoff), **in progress** on branch `m2/evaluation` (from `main` at `8296a27`, 2026-10-19). M1 is accepted and merged into `main` (2026-10-19). Order of work: the `eval-custodian` gold opportunity inventory for SL700 e_a (ground truth on the VM at `/home/user/romulus-eval/sl700_e_a/`), then the scoring scripts, the simple-baseline runner and the model bakeoff (spec §12, §15; `docs/project/MILESTONES.md` → M2). Include the M1 carry-overs listed above.
- **State:**
  - Sweep → decisions → coverage ledger → report manifest (immutable revisions, citation integrity) → technical Markdown/JSON → web UI (login, live stream, finding detail with highlighted raw evidence, triage, reports).
  - The 455-test local suite includes acceptance scenarios 13–17, hostile input, positive-only shell coverage, argv-layout and line-safe partial-prefix regressions, budget/fairness, owner-fenced lease/resume and pivot persistence, crash replay, direct-only pivots, and investigation reporting.
  - Lab hunt `h20261018-181953-decca8` (SL700 e_a, 10:00–17:30 UTC): `completed_within_scope`, 1,791,438 records evaluated, 0 parse errors, 7 urgent / 11 high / 79 leads / 504 context, 0 broken citations.
  - Fix-round lab hunt `h20261018-211924-b1edf9`: `completed_within_scope` / `reportable_findings`; the complete sweep evaluated 1,791,438 records and 296,500 typed events with 0 errors. The model made 52 calls, executed 2 complete pivots, and had 4 duplicate pivot proposals blocked before source execution. The attacker-IP `ids_alerts` pivot returned 969/969 alert records with complete coverage and no cap. All 97 seeds were accounted for; 43 remained unworked. Report revision 1 contained 97 findings/leads and 0 broken citations.
  - Gate-fix model-off hunt `h20261018-224208-b2cc27`: `completed_within_scope` / `reportable_findings`; 7 urgent, 11 high, 79 leads, 504 context; 0 errors; agent disabled with all 97 seeds unworked; report r1 had 0 broken citations.
  - Gate-fix agent hunt `h20261018-224406-923663`: `completed_within_scope` / `reportable_findings`; the investigator ended `budget_exhausted` after 54 model calls, 3 pivots (1 partial), and 9 rejected pivot proposals. Eight cases became `fallback_parked` with analyst flags, four cases exhausted budgets, no seed concluded, 88 seeds were assigned-but-unfinished, 9 were unassigned, and all 97 remained explicitly unworked. Report r1 had 0 broken citations.
  - Gate re-run model-off hunt `h20261018-232714-ad664a`: `completed_within_scope` / `reportable_findings`; 7 urgent, 11 high, 79 leads, 504 context; 1,791,438 records, 296,500 typed events, 0 errors; report r1 had 97 findings/leads and 0 broken citations.
  - Shell allow-list model-off hunt `h20261019-001401-d6328f`: `completed_within_scope` / `reportable_findings`; 7 urgent, 10 high, 80 leads, 504 context; 1,791,438 records, 296,500 typed events, 0 normalization errors; report r1 had 97 findings/leads and 0 broken citations. Both shell-script negative claims are unresolved with 17 `evaluated_partial` partitions; the TODO.md and README.txt.1 downloader→stdin-shell urgent findings remain.
  - Final parser model-off hunt `h20261019-005148-03348c`: `completed_within_scope` / `reportable_findings`; 7 urgent, 11 high, 79 leads, 504 context; 1,791,438 records, 296,500 typed events, 0 errors; report r1 had 97 findings/leads and 0 broken citations. Both shell-script rules show `positive_only=17` and “not assessable by design.” The recovered ZoneMinder high finding cites three retained raw records and states that its indicators use the clean modelled prefix only.
  - Final gate model-off hunt `h20261019-012238-c13596`: `completed_within_scope` / `reportable_findings`; 7 urgent, 10 high, 80 leads, 504 context; 1,791,438 records, 296,500 typed events, 0 errors; report r1 had 97 findings/leads and 0 broken citations. Both script-text rules show `positive_only_partial=17` with explicit per-rule assurance wording. The one-line ZoneMinder payload is now a rarity lead because no indicator precedes the parser cut on a fully terminated earlier line.
  - Temp-dir operand gate model-off hunt `h20261019-014722-06695c`: `completed_within_scope` / `reportable_findings`; 7 urgent, 10 high, 80 leads, 504 context; 1,791,438 records, 296,500 typed events, 0 errors; report r1 had 97 findings/leads and 0 broken citations.
  - Executable/operand split model-off hunt `h20261019-020720-4448fd`: `completed_within_scope` / `reportable_findings`; 7 urgent, 10 high, 80 leads, 504 context; 1,791,438 records, 296,500 typed events, 0 errors; report r1 had 97 findings/leads and 0 broken citations. Eighteen interpreter-operand findings moved to the positive-only script rule; one kernel-recorded temp executable stayed under the negative-assuring executable rule.
  - Web UI: `http://192.168.36.128:8443` (plain HTTP lab exception); restart with `scripts/web-restart.sh`.
- **Model investigator:**
  - **Implemented, locally tested, and integration tested.** The explicit controller uses SQLite state, clustered cases, breadth-first scheduling, typed tools, strict validation, one retry plus deterministic fallback, cumulative budgets, Ollama truncation checks, and durable model/case/pivot records.
  - `romulus hunt resume <hunt-id>` performs agent-only recovery under an active/stale lease policy and never reruns the sweep. New hunts retain a structured sweep summary.
  - Pivot subsets run direct playbooks only through the hunt-layer executor. Aggregate playbooks remain full-window only. Pivot publications use the sweep's shared deterministic policy and set `source_case_id` for genuinely new candidates.
  - Reports contain an Investigations section with seed accounting, case status, pivot chain/results, cited model conclusions separate from machine decisions, contributions, and incomplete work.
  - Source-family constraints, whole-window/anchor sampling, exact covered and unresolved ranges, and normalized duplicate-pivot rejection are implemented. Pivot gaps remain visible in Investigations but no longer make a complete-sweep hunt partial.
  - Live model quality remains a measured risk: on `h20261018-211924-b1edf9`, 4 of 12 cases exhausted their step budgets, 43 seeds remained unworked, and no pivot contributed a new candidate. Case `case-fddc19830be15d0c` was seeded with the 15:16 UTC root SSH login and later `videoserver` activity, but the model used all 8 calls without a pivot or conclusion; no accepted pivot independently reached that later host activity. This is an effectiveness gap, not hidden as an execution or coverage failure.
  - The newer `h20261018-224406-923663` run makes the risk more visible rather than hiding it: 8 validation fallbacks are now analyst-flagged and unfinished, all 97 seeds remain in the unworked partition, and no pivot contributed a candidate. One pivot was partial. This is an investigator-effectiveness issue for the reviewer/model bakeoff, not a sweep completeness or citation-integrity failure.
- **M2 progress (2026-10-19):** `docs/eval/PROTOCOL.md` written by the `eval-custodian`, with the matching rule (§6), lanes (§7), metrics (§8) and miss funnel (§10) pre-registered before any scoring. AttackMate times are naive UTC (offset 0 h, 7 anchors). Gold `sl700_e_a` v1 is on the VM: 27 opportunities, **22 observable** (13 critical+high), 1 inferable-only, 4 not observable; 0 in the early third of the hunt window, so e_a cannot test early-window detection. Contamination log C-001…C-004: e_a can never support a release claim.
- **First scored run (dev, model-off, 2026-10-19):** `docs/eval/results/2026-10-19-sl700_e_a-1.md` = owner-demo hunt `h20261019-093029-32dfef`. Tier A recall: reported 11/22 (0.50, Wilson 0.31–0.69), surfaced 15/22; critical+high reported 9/13 (0.69), surfaced 10/13. By source: host 10/22, network 1/10 (7/10 surfaced), Arkime 0/12 and PCAP 0/12 (no adapters). P@10 1.00, P@20 0.85; 97 surfaced = 37 hits + 19 true-unlisted + 41 benign → 5.07 false leads/modelled hour. Citations 117/117 resolve with matching digests. 0 false complete negatives (no rule claims one). First actionable finding 52.5 s; hunt 99 s. Run 2 (`h20261019-091850-00987d`, same pack) scored identically: model-off determinism holds. Well short of the spec targets (≥0.90 crit+high, ≥0.80 all).
  - **Miss funnel (11 misses, class level):** 2 c2_channel stop at *retrieved* (connect/SOCKADDR audit groups without EXECVE are never normalized; no Suricata flow; Arkime/PCAP not queried); 5 stop at *evaluated* with no rule matching (4 discovery, 1 privesc); 4 surfaced only as leads (recon_dns, 2 recon_scan, a critical remote_login).
  - **Model-on vs. model-off (2026-10-19, `docs/eval/results/2026-10-19-sl700_e_a-ablation-1v3.md`):** agent-on hunt `h20261019-192853-9da2b5` (same window, pack `m1-pack@2`, config digest; qwen3:8b, num_ctx 8192, think off) scores **identically** to model-off on every finding metric: the agent produced 0 candidates, 0 conclusions, 0 escalations, and 0 opportunities hit only with the model on. Cost: +508.6 s wall (99 → 608 s), 44 model calls, ~182k prompt / 12k completion tokens, 419.5 s model time. 21/44 model outputs invalid (48%); 12 cases (10 fallback-parked, 2 budget-exhausted); 14 pivots proposed, 5 executed (3 complete, 2 partial); all 97 seeds unworked. Its pivots retrieved gold records for 4 opportunities, all already surfaced by the sweep. One sample per arm: no variance estimate. **The agent currently adds cost and no detection value; this is the main M2 finding to fix.**
  - **Agent data gaps the ablation found:** model-on hunt had no report revision; pivot retrieval is only recoverable as a lower bound (result digests cap at ~50 event IDs; `raw_record.first_task_id` records first retrieval only); no case lineage (spawn → case); no agent-phase start/end timestamps; per-case step budgets (sum 96) do not reconcile with the hunt budget (60).
  - **Product gaps the scorer found:** `typed_event`/`raw_record` are not hunt-scoped and only candidate-supporting raw records are kept (the funnel has to infer retrieval and replay the normalizer); no ES request/byte cost accounting or per-task durations; candidates carry a single `ts`; context items absent from the manifest (I10); `evaluated_complete` is easy to misread as a complete negative. Hunt deletion should warn or export first, since eval runs depend on retained hunts.
- **Next three actions:**
  1. Model bakeoff, now the priority given the ablation: custodian owns the task set and expected decisions (weighted toward the observed failure classes: unknown evidence IDs, duplicate pivots, spawns without a discovered entity); lead builds the runner (`romulus model bakeoff`); then the ADR selecting triage/synthesis models and `num_ctx`. Investigator code changes go to Codex via `Claude-Codex.md`.
  2. `eval-custodian`: simple standard-searches baseline runner (PROTOCOL §8.1) and the AMiner/Telosian comparison (§8.2). Gold v1.1 is deferred: it would change no recall, P@k or denominator.
  3. Product follow-ups from scoring (not M2 blockers): hunt-scoped retrieval records, cost accounting, case lineage, agent-phase timestamps, a report revision for every completed hunt, and a warning or export before hunt deletion.
- **Blockers:** none.
- **Owner decisions pending:**
  - Load SL700 `f_a` as the holdout (download ≈3.7 GB from Zenodo).
  - Isolate ground truth from the runtime (needs sudo): move `/home/user/romulus-eval` to a dedicated account, or run ROMULUS as its own service user (PROTOCOL §11).
  - Set the false-leads-per-hour ceiling, confirm the spec targets, and confirm the modelled review time of 5 min per surfaced item (PROTOCOL §14).
  - Choose a different-storyline dataset with early-window activity (AIT-LDS v2, OTRF, or an owner-run emulation).
  - Separate Malcolm VM (≈16 GiB) for M4.
  - Resize the VM to 12 GiB / 8 vCPU before M3.

## Milestone summary

| Milestone | State | Evidence |
|---|---|---|
| Pre-M1 setup | done | this file, TEAM.md, `.claude/agents/`, ENVIRONMENT.md |
| M1 thin end-to-end slice | accepted 2026-10-19 | 455-test suite; reviewer gate (option B, ADR-004); owner demo on `h20261019-093029-32dfef`; merged to `main` |
| M2 evaluation and model bakeoff | in progress | branch `m2/evaluation`; protocol, gold v1, scorer; model-off recall 11/22; model-on identical (agent adds no value yet) |
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

- **2026-10-19 (M2 start)**:
  - Branched `m2/evaluation` from `main` (`8296a27`); refreshed stale M1 lines in this file.
  - `eval-custodian` wrote `docs/eval/PROTOCOL.md`, resolved the AttackMate timezone (UTC), built gold `sl700_e_a` v1 on the VM (27 opportunities, 22 observable), extracted the AMiner/Telosian alerts into the eval folder, tightened eval-folder modes to 700/600, and verified no runtime config path reaches it. It read no ROMULUS output.
  - Lead reviewed PROTOCOL.md (aggregate only, no per-opportunity answers) and accepted the matching rule and lane split. Dataset quirks added to ENVIRONMENT.md. Committed `3d75cad`.
  - `eval-custodian` built the scorer (`eval/`, 12 tests on synthetic gold and a synthetic store DB), deployed with `scripts/deploy.ps1 -SkipInstall` (it already ships untracked files), and scored two model-off hunts; results in `docs/eval/results/`. Scoring decisions are logged in PROTOCOL §13. Lead verified locally: 472 tests pass, `archmap --check` clean, no gold IDs in the results files, and the ES fetcher only issues `_search`. Committed `e07143f`.
  - Lead ran agent-on hunt `h20261019-192853-9da2b5` on the VM (demo window and pack; product code unchanged since the demo). `eval-custodian` added `eval/agent.py` and `eval/ablation.py`, rescored run 1 with the same build, and scored run 3; model-on equals model-off on every finding metric. Lead verified: 474 tests pass, `archmap --check` clean, no gold IDs in the results.

- **2026-10-18 22:10 EDT (executable-versus-operand split round)**:
  - Split temp execution into a negative-assuring executable-path rule and a positive-only interpreter-operand rule; fixed shell `-s`/`-c` ordering and rejected late awk `-f` operands. Each of the three requested items was developed red-first and committed separately (`a7220c3`, `e59732f`, `ea2c410`).
  - The required 455-test suite passed; `scripts/archmap.py --check` exited 0 with no output.
  - Deployed clean commit `ea2c410` and verified the VM stamp. Model-off hunt `h20261019-020720-4448fd` completed within scope with 1,791,438 records, 296,500 events, 0 errors, and 7 urgent / 10 high / 80 lead / 504 context; report r1 had 97 findings/leads and 0 broken citations.
  - The requested linpeas temp-rule expectation could not be met soundly: the retained live event has no cwd/CWD telemetry, so it remains a web-service interpreter lead instead of acquiring an unsupported temp-path claim.

- **2026-10-18 21:49 EDT (temp-dir operand gate round)**:
  - Restricted temp-dir script operands to shells and actual script-taking interpreters; added exact `awk`/`gawk -f FILE` handling and prevented nc/ncat/netcat/socat data operands from becoming execution claims.
  - Required a slash before resolving executable paths against cwd, canonicalized exactly two leading slashes, modelled shell `-s`/clusters as stdin mode, and made the Markdown coverage legend rule-specific.
  - The required 433-test suite passed; `scripts/archmap.py --check` exited 0 with no output. Each fix was developed red-first and committed separately (`aa0d9d7` through `0b9a66a`).
  - Deployed clean commit `0b9a66a` and verified the VM stamp. Model-off hunt `h20261019-014722-06695c` completed within scope with 1,791,438 records, 296,500 events, 0 errors, and 7 urgent / 10 high / 80 lead / 504 context; report r1 had 97 findings/leads and 0 broken citations.

- **2026-10-18 21:24 EDT (final M1 gate-fix round)**:
  - Normalized login-shell and versioned interpreter argv names everywhere the interpreter allow-list is checked. Added a shared option scanner for shell script files, made non-shell option layouts explicitly unevaluable, resolved relative paths with POSIX semantics, and made missing path context partial rather than a negative.
  - Preserved positive-only partial coverage and every report caveat; added rule-specific assurance wording. Restricted shell-prefix indicators to fully terminated earlier lines, discarded every parser-error prefix, and added `elif`, `else`, and `esac` to the reserved set.
  - The required 406-test suite and architecture check passed. Claude's three Python probes passed, `prefix_bash.py` reported all cases sound, and the real-shell `tmpdir.sh` cases executed their expected scripts.
  - Deployed clean commit `bf7e5ee` and verified the VM stamp. Model-off hunt `h20261019-012238-c13596` completed within scope with 0 errors; report r1 had 97 findings/leads and 0 broken citations. Counts are 7 urgent / 10 high / 80 lead / 504 context because the one-line ZoneMinder exploit cannot soundly contribute a pre-cut prefix under the final gate rule.

- **2026-10-18 20:54 EDT (final M1 parser round)**:
  - Stopped shell option scanning at the first script-file argument; recognised login-shell argv names; classified zsh, ksh, fish and csh-family `-c` input as explicit unknown; and strengthened adversarial coverage assertions per rule.
  - Retained only the clean parser prefix before an unsupported construct for positive web-interpreter indicators. Direct script-text rules remain positive-only and never use a partial prefix to support a negative.
  - The 346-test suite and architecture check passed. Deployed clean commit `72d0da0`; model-off hunt `h20261019-005148-03348c` completed within scope over 10:00–17:30 UTC with 1,791,438 records, 296,500 events, 0 errors, and report r1 with 0 broken citations.
  - Lane counts returned to 7 urgent / 11 high / 79 lead / 504 context. The ZoneMinder exploit payload is high again from two indicators wholly before the unmodelled substitution, with an explicit clean-prefix-only note; the two process-level persistence findings remain urgent.

- **2026-10-18 20:17 EDT (shell allow-list gate round)**:
  - Replaced the permissive shell parser with one quote/comment/escape-aware allow-list lexer. Unsupported expansion, substitution, compound syntax, dynamic wrappers, redirects, whitespace, and ambiguous shell `-c` layouts now fail closed as unevaluable.
  - Removed parse failure as a web-interpreter suspicion indicator while preserving rarity leads, and propagated explicit unknown layouts to partial coverage for both direct shell-script rules. Added parser, detector, and persisted sweep-cell tests for every supplied hostile fixture.
  - The 325-test suite and architecture check passed. Deployed clean commit `65593a9`; model-off hunt `h20261019-001401-d6328f` completed within scope over 10:00–17:30 UTC with 1,791,438 records, 296,500 events, 0 normalization errors, and report r1 with 0 broken citations.
  - Lane counts were 7 urgent / 10 high / 80 lead / 504 context. The one prior high item was reclassified to lead because its only indicator was an unmodelled parse; both required downloader sequence findings remained urgent.

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
