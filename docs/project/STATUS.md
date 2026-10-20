# ROMULUS status

## Resume here

_Last updated: 2026-10-20 16:55 EDT by Claude (lead)._

- **Direction (owner, 2026-10-19):**
  - Deterministic search comes first; the model is optional and off by default. ADR-006 (accepted) supersedes ADR-005 decisions 2–5: deterministic expansion finds, and an optional model only explains leads and drafts the narrative.
  - The New hunt page has an "Agentic hunt" checkbox, unchecked by default. `AGENT_MODE` defaults to `off`.
  - The spec (`ENGINEERING_MASTER_PROMPT.md`) is a set of suggestions, not requirements. Propose better routes when they exist. The goal is to find indicators of compromise wherever ROMULUS is sent, correlating host logs with network telemetry.
- **Owner proposals (2026-10-20), documented, not implemented, shape pending sign-off.** The roadmap entry is Track A in MILESTONES.md.
  - **ADR-007, an API-key model provider.** Recommended shape: one OpenAI-compatible adapter, which also serves vLLM, llama.cpp and Ollama `/v1`. Remote endpoints need the bootstrap switch `ROMULUS_MODEL_EGRESS=lab-public-data` and may be used on public lab data only, with banners and manifest provenance. Evaluate a frontier model as the ceiling and a mission-class open-weight model as the claim.
  - **ADR-008, a capable-model agent.** A replay gate comes first; then a native tool-calling loop over SQLite rows that may add `agent` findings (≤ `high`) and never subtract. Still no LangGraph: a stronger model removes ADR-001's small-model objection, not its state-authority one.
  - **ADR-009, a settings page.** Lead-only, writing `$ROMULUS_HOME/config/settings.env` atomically. Secrets are write-only, bootstrap keys can't be edited, and TLS comes first, so web TLS moves up from M7.
- **Branch under review:** `codex/expansion` at the eleven-step expansion fix series, based on `m2/evaluation` at `d59a79f`; independently reviewed, live-tested on the VM, and not pushed. The base merges:
  - investigator v2 (`codex/investigator-v2`, `0bfd0d2`);
  - host↔network correlation and Arkime (`m2/network-correlation`);
  - the research register (round 1).
- **What's in it now:**
  - `net_socket` events from auditd connect/SOCKADDR.
  - `host.interpreter_external_connection`.
  - `corr.process_network_link`: a host connect() joined to Suricata or Arkime records, disk-staged, with the link worded as inferred.
  - Arkime session indices as a target (`net_session`), with `net.long_external_connection`, `net.beaconing` and `net.rare_client_fingerprint`.
  - Investigator modes model / deterministic / off.
  - The replay harness (`romulus replay export|run|summary`).
  - Deterministic expansion with persisted anchors and typed links, global tiered round-robin scheduling, a depth reserve, durable physical-query checkpoints, two anchor-gated context playbooks, crash-safe resume, canonical cross-hunt manifests, explicit accounting, and incident-graph reporting.
  - Tests: 740 pass; changed-file Ruff, `archmap --check`, and `git diff --check` are clean. The independent final reviewer returned PASS.
- **Latest lab hunts** (model-off, e_a 10:00–17:30 UTC):
  - Default runs `h20261020-110635-1f8437` and `h20261020-110952-5bb543` both completed within scope over 1,816,068 records / 326,534 events with 0 errors and identical lanes: 7 urgent / 18 high / 95 lead / 511 context. Each immutable r1 report has 120 findings/leads, no broken finding/incident/investigation citations, and is finalizable.
  - Expansion distributed the 180 physical-source-query budget across 25 anchors (22 depth 0, 2 depth 1, 1 depth 2), all honestly `expanded_partial`. It produced three high `context.post_access_discovery` findings and formed 96 incidents: 91 size 1, one size 4, two size 5, one size 7, and one size 8, with 53 observed and 45 inferred edges.
  - The two canonical manifests are byte-identical: 1,669,044 bytes, SHA-256 `d5d11e72aa397583a25295ac7f0a33cc54edae15234df67d8f1a032ee490c5ff`.
  - `--no-expand` run `h20261020-111303-330c65` completed within scope with 0 errors, 7 urgent / 15 high / 95 lead / 511 context, 117 singleton incidents, 0 anchors/links, and no broken citations. Wall/RSS: default A 3:09.37 / 2,621,356 KiB; default B 3:04.48 / 2,620,320 KiB; no-expand 1:53.43 / 2,620,396 KiB. No ground-truth scoring was performed by Codex.
- **Evaluation so far (dev set e_a, gold v1: 22 observable):**
  - Model-off before the network work: recall 11/22 reported, 15/22 surfaced; P@10 1.00; 5.07 false leads per modelled hour.
  - Off, deterministic and model hunts are identical on every finding metric (`docs/eval/results/2026-10-19-sl700_e_a-ablation-456.md`).
  - Replay: v1 free-JSON 0.22 → v2 menu 0.53 with retry. The remaining error is escalating benign seeds.
- **Since the merge (2026-10-19 evening):**
  - **Arkime is live.** The owner granted `romulus_agent` read-only access to `arkime_sessions3-*` (role `romulus_arkime_reader`; doctor confirms no write rights), and `ES_INDEX_PATTERNS` includes it. Long-connection rules catch both Meterpreter sessions and the exploit's held HTTP connection; beaconing catches the cron `curl` every 900 s.
  - **Noise fix:** external-connection findings are grouped per (host, program, account, port); kernel-record lineage lowers web-service daemons to lead (it never raises a lane); NTP verified by the parser goes to context.
  - **Field-role indicator matcher** (`ioc.indicator_match`, `content/indicators/*.yaml`). The seed list has about 80 exact tool names. On the lab, LinPEAS run by the attacker is high, and commands that only name it are context.
  - **ATT&CK Enterprise 20.0 STIX** is vendored at `content/attack/` (pinned and verified).
  - **v1 audit:** no v1 rule is kept; 15 ideas are queued as `v1_ports` in `content/research/backlog.yaml`. Spec lessons 11–14 added.
- **Scores** (dev, gold v1; eval-custodian, `docs/eval/results/`):

  | Run | Recall reported | Recall surfaced | P@10 | False leads/hour |
  |---|---|---|---|---|
  | 4: model-off baseline | 11/22 | 15/22 | 1.00 | 5.07 |
  | 7: host↔network correlation | 12/22 | 17/22 | 0.80 | 6.23 |
  | 8: + Arkime + noise fix | 12/22 | 17/22 (critical+high 12/13) | 0.90 | 5.28 |

  Remaining misses are discovery ×4 and privesc ×1 (no rule matched), plus 5 lead-only (c2_channel, recon ×3, remote_login). The expansion engine and context rules target these.
- **Deployed/live-tested product tree:** the final `codex/expansion` source tree. The canonical projection was corrected after the hunts from their persisted, identical semantic data, reviewed again, and redeployed. Nothing is pushed: the owner pushes.
- **Codex expansion fix round:** complete and handed back in `Claude-Codex.md`. It includes fair bounded scheduling, safe inferred-link handling, normalized login sessions, honest IP coverage, durable resume budgets, context deduplication, incident correlation, canonical manifests, and local plus live validation.
- **Owner decisions recorded (2026-10-19):**
  - f_a holdout on hold.
  - A different-storyline dataset later.
  - Malcolm after deterministic search is built out.
  - Ground-truth account isolation: explained as defence in depth, not required now; revisit before any holdout.
- **Next:**
  1. Lead reviews the handback and merges the eleven-step `codex/expansion` series if accepted; the independent reviewer gate is PASS.
  2. Lead: network slice 3, TShark on the packets of specific Arkime sessions (v1's explicit-ID PCAP fetch and TShark safety patterns).
  3. Detection engineer: context-rule catalog (after the engine), plus lab-testable `v1_ports` and backlog items.
  4. The eval-custodian scores after each step.
  5. Once the owner signs off on ADR-007/008/009, Track A runs in this order: A1 web TLS → A2 settings page → A3 provider port → A4 capable-model replay gate (eval-custodian, thresholds pre-registered) → A5 agent only if A4 passes.
- **Merge gates and known issues:**
  - Investigator v2 re-review findings on `0abb1fc` (spawned-case stall, stale schema after shrink, seed cards dropped, `valid_first` metric, deterministic errors treated as outages). Several may be fixed in Codex's later commits but are not re-verified. They only matter for agent mode, which is off by default.
  - The live 180-query budget is now fair and bounded, but all 25 anchors remain partial and later broad link tiers (`source_ip` and `account`) were not reached. Tune the budget/tier policy only with explicit completeness and false-lead measurements.
- **Process notes:**
  - Investigator and shell-parser code goes to Codex via `Claude-Codex.md`. The file is gitignored; replace Claude's last message; old text may be cleared at a new conversation.
  - The eval-custodian never deploys without asking.
  - Owner direction: detection breadth is a primary goal (spec §7), plus a detection catalog page (spec §7; M4/M6).

## Milestone summary

| Milestone | State | Evidence |
|---|---|---|
| Pre-M1 setup | done | this file, TEAM.md, `.claude/agents/`, ENVIRONMENT.md |
| M1 thin end-to-end slice | accepted 2026-10-19 | 455-test suite; reviewer gate (option B, ADR-004); owner demo on `h20261019-093029-32dfef`; merged to `main` |
| M2 evaluation (bakeoff dropped, ADR-005/006) | in progress | protocol, gold v1, scorer, replay harness; v2 investigator, network correlation and Arkime merged; deterministic default |
| M3 full sources and coverage truth | not started | |
| M4 detection depth (incl. Zeek, ICS, Malcolm) | not started | |
| M5 synthesis and reports | not started | |
| M6 hardening and holdout | not started | |

## Open risks

| Risk | Impact | Mitigation |
|---|---|---|
| Lab data is one small, Linux-only storyline (SL700); all SL700 variants share attacker scripts | Overfitting; weak generalization claims | f_a holdout plus at least one different-storyline dataset before claiming general effectiveness |
| Lab mapping was produced by v1's custom importer, not a standard shipper | Field contracts may not transfer to real mission data | Profile-driven field contracts; add standard-shipper fixtures (Elastic Agent, Winlogbeat, Zeek, Malcolm) |
| 8 GiB VRAM limits model size and context | Weak agent judgment | ADR-005: menu-driven, constrained decisions sized for qwen3:8b; replay evaluation on every investigator change. ADR-007/008 (proposed): test a capable model through an OpenAI-compatible endpoint |
| Developing against a frontier API model overstates what a CPT kit can run | Agent looks good in the lab and fails on the mission | ADR-007: product claims only from a mission-class open-weight model; frontier numbers labelled "ceiling"; agent wins converted to deterministic rules (ADR-008) |
| Hosted model egress used on non-public data | Data spill | ADR-007: bootstrap-only switch the UI cannot set; doctor fails without it; banners; unset in release builds and release-gate checks |
| AttackMate timestamps have no stated timezone | Misaligned scoring | eval-custodian aligns against telemetry before scoring |
| No Malcolm or ICS-protocol data in the lab | ICS playbooks only fixture-tested | Public ICS PCAPs; Malcolm VM in M4 |
| VM RAM headroom ~4.6 GiB | Hunts compete with ES and Kibana | nice'd TShark, bounded concurrency; resize before M3 |

## Session log

Newest first. One entry per session where state changed: what was done, what was verified and how, and what was decided.

- **2026-10-20 16:55 EDT (owner proposals: model providers, capable agent, settings page; Claude)**:
  - The owner asked for an API-key model provider (for example OpenAI) as a stand-in for a strong local model, a re-examination of LangGraph, and a credentials page in the UI. The lead scrutinized the proposals against the evidence from ADR-005 and ADR-006 and the invariants, and wrote ADR-007, ADR-008 and ADR-009 (all *proposed*).
  - Updated MILESTONES.md (Track A, A1–A7; web TLS moved up from M7), the README, the spec (§0.4, §4, §5, §11, §14 and §15 gate 8 pointers), CLAUDE.md (the egress invariant note) and the expansion design's invariants row.
  - Docs only: no code changed and no tests were run.

- **2026-10-20 EDT (expansion reviewer-fix round, Codex)**:
  - Merged the current evaluation base and addressed every reviewer finding in ten ordered fix commits after the merge: event-backed incident edges; inferred flow-host links; fair global-tier scheduling; context dedupe; aggregate-key fan-out; audit-login normalization; honest IP coverage; durable query checkpoints and exception safety; canonical manifests; and controller/report hardening.
  - Two independent follow-up reviews found and verified seven additional boundary defects. Fixes preserve unresolved IP inventory coverage, checkpoint before I/O, restart earlier tiers for new anchors, reject unusable flow endpoints, cap inferred direct findings at lead, preserve the child-query reserve, and sort canonical collections after rekeying. Final reviewer result: PASS.
  - Final local proof: 740 tests pass; changed-surface Ruff, architecture map, and diff checks pass. Deployed and ran two default hunts plus one no-expand hunt. Default expansion adds three cited high context findings and forms multi-finding incidents; both canonical manifests are byte-identical. No model calls or ground-truth scoring were performed.

- **2026-10-20 UTC (deterministic expansion, Codex)**:
  - Implemented the ADR-006 expansion slice in seven commits: session/IP truth, typed links, anchor-gated context rules, crash-safe controller, incident graph, replay rename, and verification hardening. Source access remains in the hunt layer; `romulus.agent` cannot import `romulus.sources`.
  - Developed the slices red-first. Final local proof: 670 tests pass; changed-file Ruff passes; `scripts/archmap.py --check` passes. A live manifest comparison exposed nondeterministic Suricata signature-note ordering; a tie-breaker and regression test fixed it without changing detection semantics.
  - Deployed the clean product tree and ran two matching expanded hunts plus one `--no-expand` hunt. The expanded reports are semantically identical, finalizable, and have zero broken citations. Live accounting also exposed the source-budget concentration issue described above; no expansion-derived finding was claimed.

- **2026-10-19 (evening: direction change, network correlation, merges)**:
  - Owner dropped the model bakeoff (ADR-005), then set deterministic search first with the model optional (ADR-006, from a parallel design thread). Codex built investigator v2. The custodian showed off, deterministic and model hunts identical on findings; replay 0.22 → 0.53.
  - Lead built host↔network correlation and Arkime-as-ES-target on `m2/network-correlation`. The reviewer failed then passed slice 1 after fixes (B1/B2/I1–I4, N1/N2, M1–M7). 541 tests at merge.
  - Merged v2, network and research into `m2/evaluation`; added the agentic-hunt checkbox (default off). 590 tests; deployed `b8be0dc`. Lab hunt `h20261019-225437-045bc8` finds the C2 connect at high.
  - v1 search code reviewed by the lead. Discard the query construction: model-written DSL, `*term*` substring search over `message`/`event.original` and `json.dumps(raw)`, silent selector truncation, lab-tuned indicator terms. Keep for slice 3: Arkime per-session PCAP fetch (explicit IDs, byte cap, streamed); the TShark wrapper's argv-only exec, allowlist via `resolve()`, timeout kill, and its lesson that `-c` caps packets before the display filter (false negatives). Ideas worth porting: protocol-on-any-port via Arkime `protocols`, and edit-distance-one process-name masquerade. The detection engineer is auditing the v1 rule catalogs and packs.

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
