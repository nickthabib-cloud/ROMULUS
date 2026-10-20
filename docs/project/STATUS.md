# ROMULUS status

## Resume here

_Last updated: 2026-10-20 17:45 EDT by Claude (lead, Milestone2 session)._

- **Direction (owner, 2026-10-19):**
  - Deterministic search comes first; the model is optional and off by default. ADR-006 (accepted) supersedes ADR-005 decisions 2–5: deterministic expansion finds, and an optional model only explains leads and drafts the narrative.
  - The New hunt page has an "Agentic hunt" checkbox, unchecked by default. `AGENT_MODE` defaults to `off`.
  - The spec (`ENGINEERING_MASTER_PROMPT.md`) is a set of suggestions, not requirements. Propose better routes when they exist. The goal is to find indicators of compromise wherever ROMULUS is sent, correlating host logs with network telemetry.
- **Owner decisions (2026-10-20):**
  - **Build the AI investigating agent** (ADR-008, accepted; `docs/design/investigating-agent.md`). It forms hypotheses from all the indicators, follows leads, finds more indicators, and paints the bigger picture. The report opens with its cited, labelled AI assessment.
  - The agent is a native tool-calling loop in the explicit controller, over SQLite rows, with no LangGraph. It adds `agent` findings (≤ `high`) and hypothesis links, and never subtracts.
  - **Model access** (ADR-007, accepted): any OpenAI-compatible endpoint. Teams run their own powerful model. The lab uses a hosted API on public data behind `ROMULUS_MODEL_EGRESS=lab-public-data`.
  - **Credentials page deferred** (ADR-009); configuration stays in `.env`.
  - Roadmap: Track A1–A9 in MILESTONES.md.
- **Reconciliation (2026-10-20 17:45):**
  - `main` was fast-forwarded to `codex/expansion@fdac0ba` and pushed. That relied on Codex's hand-back, which cited Codex's own reviewer PASS.
  - **The project's merge-gate `reviewer` had FAILED `fdac0ba`:**
    - **Blocking B-1:** a network anchor's "victim host" was an IP used as a `host.name` predicate, so host-side links came back complete with no events. That is a false complete negative.
    - **Important:** I-1 (an inferred reach capped strong direct findings at lead); I-2 (the per-fetch query cap was soft); I-3 (aggregate findings bridged unrelated incidents).
  - The lead fixed all of these and the minors on `m3/expansion-fixes`. The reviewer re-checked twice and passed `47b3270`.
  - Those fixes, plus the reviewed packet stage, are merged into `m2/evaluation` (`f0069ef`).
  - **This merge brings them into `main`.** Branch `m3/main-sync` = `main` + `m2/evaluation`; the owner fast-forwards `main` to it and pushes.
- **What's in it now** (beyond the M2 base: investigator v2, host↔network correlation, Arkime, indicators, storage):
  - **Packet stage** (M4 slice 3; reviewer PASS after four rounds):
    - **Selection:** Arkime HTTP sessions whose body Arkime typed as text or an executable, overlapping the window. Mid-save segments are grouped into one logical session.
    - **Fetch:** packets come from Arkime by explicit id. A multi-segment session is fetched one segment at a time in order, then merged with `mergecap`.
    - **TShark:** a fixed JSON query with pinned reassembly preferences and `prlimit` limits.
    - **Rule:** `pcap.disguised_script_or_executable`.
    - **Honest coverage:** every lost-work path is partial, and the ids of sessions not judged are listed.
    - **Order:** it runs before expansion, so its findings can anchor.
  - **Deterministic expansion** (ADR-006), with the lead's review fixes:
    - **Victim host:** a network-only anchor has no host identity. Each internal endpoint is resolved per hunt by a durable, budgeted lookup (`host.name` where `host.ip` equals it), or the host-side links are unsupported with the reason.
    - **Flow host side:** `flow_host_side` without a host searches every host's audit sockets by the flow endpoint.
    - **Lanes:** direct findings keep their lane through inferred links.
    - **Budget:** the per-fetch query cap is hard, including sampling.
    - **Incidents:** aggregate and packet findings are incident leaves.
    - **Flow strength:** `network_flow` is observed only within 10 min.
    - **Context findings** are not seeded as anchors.
    - **Determinism:** canonical manifests are content-ordered.
  - **Auth:** auth events carry `auth.phase`. The SSH-login rule counts logins ("at least N"), and an account is never taken from the logging uid.
  - **Tests:** 907 pass; `archmap --check` is clean; changed-file Ruff is clean.
- **Deployed:** `f0069ef` (on the VM).
  - Latest default hunts `h20261020-210803-c6bef1` and `h20261020-211120-9d97a4` (agent off, expansion on, e_a 10:00–17:30 UTC):
    - `partial`; the only partial reason is 2 ZoneMinder streaming responses TShark could not rebuild;
    - 7 urgent / 17 high / 97 lead / 511 context; 0 errors; about 3:10 wall time and 2.6 GB RSS each.
  - **Expansion:** 22 root anchors, all `expanded_partial`.
    - The budget stopped at the root share: 144 of 180 queries, with the 20% reserve for discovered anchors unused, because no anchor was discovered.
    - It added 2 high `context.post_access_discovery` findings.
    - Incidents: 110 singletons, 2 of size 3 and 1 of size 5; 43 observed and 40 inferred edges; 0 broken citations.
    - **Lab facts:**
      - `login_session` is unsupported everywhere: the anchors are www-data and cron processes with an unset audit session.
      - `host.ip` is mapped but empty, so network anchors' host sides are unsupported. Their socket side is found by endpoint (9 complete).
  - **Determinism:** the two canonical manifests are byte-identical (SHA-256 `17ce90e3…`), after `f0069ef` fixed an ordering leak this check found.
  - These replace the round-1 Codex hunts recorded earlier. Those ran the failed `fdac0ba` and counted 3 context findings, 25 anchors and larger incidents, partly through context-finding cascades and the bridging I-3 removed.
- **Scores** (dev set e_a, gold v1, 22 observable; eval-custodian, `docs/eval/results/`):

  | Run | Recall reported | Recall surfaced | P@10 | False leads/hour |
  |---|---|---|---|---|
  | 4: model-off baseline | 11/22 | 15/22 | 1.00 | 5.07 |
  | 7: host↔network correlation | 12/22 | 17/22 | 0.80 | 6.23 |
  | 8: + Arkime + noise fix | 12/22 | 17/22 (critical+high 12/13) | 0.90 | 5.28 |
  | 9: + packet stage (no expansion) | 12/22 | 17/22 (critical+high 12/13) | 0.90 | 5.14 |
  | 10: + expansion | being scored | | | |

  Run 9: both packet leads match gold (the `/TODO.md` stager and the `authorized_keys` drop), but each is for an opportunity already reported. The remaining misses are discovery ×4 and privesc ×1, plus 5 lead-only (c2_channel, recon ×3, remote_login).
- **Owner actions pending:**
  1. Fast-forward `main` to `m3/main-sync` and push. Claude Code cannot push.
  2. Copy the run 9 private eval files from the VM's `/tmp/r9priv/` into `/home/user/romulus-eval/sl700_e_a/`, then delete `/tmp/r9priv` and `/tmp/r9h`. The session's permissions blocked the eval-custodian from doing it.
  3. Decide the false-leads-per-hour ceiling (PROTOCOL §14).
- **Next:**
  1. Run 10 scoring (expansion), then tune the expansion budget and tiers by score and false leads.
  2. Detection engineer: the context-rule catalog aimed at the discovery and privesc misses, plus lab-testable `v1_ports` and backlog items.
  3. Track A (agent): A1 provider port (lead) → A2 dossier and tools, A3 controller and hypotheses, A4 admission (Codex via `Claude-Codex.md`) → A5 AI assessment and A6 UI (lead) → A7 safety tests → A8 scoring. `reviewer` gates each slice. **Track A builds on the reconciled `main`, not on `fdac0ba`.**
  4. The eval-custodian scores after each step.
- **Merge gates and known issues:**
  - **Merge gate:** the project's own `reviewer` agent, not a reviewer cited inside a Codex hand-back.
  - Investigator v2 re-review findings on `0abb1fc` (agent mode only, which is off by default).
  - **Expansion limits:**
    - Host-resolution spend happens at slot building, so root anchors can use part of the depth ≥ 1 reserve (reviewer minor; fix at the next scheduler tuning).
    - Session links do not stop at a reboot when `host.boot.id` is absent.
    - Context findings are not anchors. That trades some recall (for example, no `source_ip` or `account` expansion from a promoted login) for budget.
    - The web and DOCX do not draw the incident graph yet; the technical report carries it.
  - `host.ssh_authorized_keys_write` misses key appends made inside downloaded scripts. The packet rule catches the lab case; kernel file records are the general fix (M4).
- **Process notes:**
  - Investigator, shell-parser and agent code goes to Codex via `Claude-Codex.md`. The file is gitignored; replace Claude's last message; old text may be cleared at a new conversation.
  - The eval-custodian never deploys without asking.
  - Owner direction: detection breadth is a primary goal (spec §7), plus a detection catalog page (spec §7; M4/M6).

## Milestone summary

| Milestone | State | Evidence |
|---|---|---|
| Pre-M1 setup | done | this file, TEAM.md, `.claude/agents/`, ENVIRONMENT.md |
| M1 thin end-to-end slice | accepted 2026-10-19 | 455-test suite; reviewer gate (option B, ADR-004); owner demo on `h20261019-093029-32dfef`; merged to `main` |
| M2 evaluation (bakeoff dropped, ADR-005/006) | closing (on `main`) | protocol, gold v1, scorer, replay harness; v2 investigator, network correlation and Arkime merged; deterministic default |
| M3 deterministic expansion and attack-path view | in progress | expansion engine with the lead's review fixes (reviewer PASS `47b3270`), live-tested and deterministic; packet stage (M4 slice 3) merged; run 10 scoring |
| Track A AI investigating agent | accepted, not started | ADR-007, ADR-008, `docs/design/investigating-agent.md` |
| M4 detection depth (incl. Zeek, ICS, Malcolm) | not started | |
| M5 synthesis and reports | not started | |
| M6 hardening and holdout | not started | |

## Open risks

| Risk | Impact | Mitigation |
|---|---|---|
| Lab data is one small, Linux-only storyline (SL700); all SL700 variants share attacker scripts | Overfitting; weak generalization claims | f_a holdout plus at least one different-storyline dataset before claiming general effectiveness |
| Lab mapping was produced by v1's custom importer, not a standard shipper | Field contracts may not transfer to real mission data | Profile-driven field contracts; add standard-shipper fixtures (Elastic Agent, Winlogbeat, Zeek, Malcolm) |
| 8 GiB VRAM limits model size and context | Weak agent judgment | ADR-005: menu-driven, constrained decisions sized for qwen3:8b; replay evaluation on every investigator change. ADR-007/008: the agent uses the team's powerful model through an OpenAI-compatible endpoint; the lab uses a hosted API |
| The lab's hosted model may differ from the model a team fields | Agent quality in the lab may not carry over | ADR-007: every result names its model; rerun on the team's model class before a release claim; agent wins converted to deterministic rules (ADR-008) |
| Hosted model egress used on non-public data | Data spill | ADR-007: bootstrap-only switch; doctor fails without it; banners; unset in release builds and release-gate checks; teams' own servers count as local |
| Prompt injection through telemetry steers a capable agent | Misleading hypotheses or agent findings | Typed read-only tools; add-never-subtract; claim checker; scenario 13 extended to tool calls (Track A7) |
| AttackMate timestamps have no stated timezone | Misaligned scoring | eval-custodian aligns against telemetry before scoring |
| No Malcolm or ICS-protocol data in the lab | ICS playbooks only fixture-tested | Public ICS PCAPs; Malcolm VM in M4 |
| VM RAM headroom ~4.6 GiB | Hunts compete with ES and Kibana | nice'd TShark, bounded concurrency; resize before M3 |

## Session log

Newest first. One entry per session where state changed: what was done, what was verified and how, and what was decided.

- **2026-10-20 17:45 EDT (reconciliation, Claude, Milestone2 session)**:
  - Found `main` fast-forwarded to `fdac0ba`, the commit the project reviewer had failed (B-1 false-complete host links).
  - Built `m3/main-sync`, which merges `m2/evaluation` into `main`. It carries the packet stage, the lead's expansion fixes (reviewer PASS `47b3270`), the canonical-ordering fix, and the run 9 eval docs.
  - The only conflict was this file. It now keeps the owner's 2026-10-20 decisions and corrects the expansion facts and next steps.
  - Verified: the full suite passes on the merge; two live default hunts gave identical canonical manifests.
  - The owner fast-forwards and pushes.
- **2026-10-20 17:45 EDT (merge and push, Claude)**: Ran the local suite on `codex/expansion` (exit 0, about 740 tests). The owner directed the merge, so `main` was fast-forwarded to it (61 commits ahead of `origin/main` at `8296a27`) and pushed.

- **2026-10-20 17:30 EDT (owner decisions: AI agent accepted, credentials page deferred; Claude)**:
  - The owner decided to build the hypothesis-driven agent, with no build gate. Teams will run their own powerful model, not public APIs; the lab uses a hosted API on public data. The owner asked for the single best way to run the agent, and deferred the credentials page.
  - ADR-007 and ADR-008 were rewritten as accepted, and ADR-009 marked deferred. Wrote `docs/design/investigating-agent.md`: dossier, tools, hypotheses, loop, admission, AI assessment, safety, budgets, measurement and work split. Track A is now A1–A9, web TLS is back in M7 hardening, and the settings page is in M7. README, spec §0.4, §4, §5 and §11, CLAUDE.md and the expansion design §6 were updated to match.
  - Docs only: no code changed and no tests were run.

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
