# ROMULUS status

## Resume here

_Last updated: 2026-10-20 08:40 EDT by Claude (lead)._

- **Direction (owner, 2026-10-19):**
  - Deterministic search comes first; the model is optional and off by default. ADR-006 (accepted) supersedes ADR-005 decisions 2–5.
  - The New hunt page has an "Agentic hunt" checkbox, unchecked by default. `AGENT_MODE` defaults to `off`.
  - The spec is a set of suggestions. The goal is to find indicators of compromise wherever ROMULUS is sent, correlating host logs with network telemetry.
- **Branches:**
  - **`m2/evaluation` at `082e94c`** (not pushed). It merges the packet stage (M4 slice 3, `m2/packets`). The reviewer passed it after four rounds.
  - **`codex/expansion` at `fdac0ba`.** The ADR-006 expansion engine plus Codex's fix round 1. The merge-gate reviewer **FAILED** it:
    - **Blocking B-1:** a network anchor's victim host is an IP string used as a `host.name` predicate, so the host-side links come back as false-complete.
    - **Important:** I-1 (a direct indicator is capped at lead when reached through an inferred link); I-2 (the per-fetch query cap is soft); I-3 (aggregate findings bridge incidents).
    - **Fix round 2** is briefed in `Claude-Codex.md` (2026-10-20 07:49 EDT) and is waiting for the owner to start Codex. It includes merging `m2/evaluation` (the packet stage runs before expansion; the pack is `m3-pack@2`).
  - **`m2/integration-trial` at `8baae62`:** the lead's trial merge of packets onto `fdac0ba`, kept as Codex's reference for resolving the conflicts.
- **Packet stage (new):**
  - **Selection:** Arkime HTTP sessions whose body Arkime typed as text or an executable, overlapping the hunt window. Mid-save segments are grouped into one logical session.
  - **Fetch:** packets come from Arkime by explicit id. A multi-segment session is fetched one segment at a time in order, then merged with `mergecap`.
  - **TShark:** a fixed JSON query, pinned reassembly preferences, limits applied through `prlimit`.
  - **Rule:** `pcap.disguised_script_or_executable` (positive-only). Heuristic matches are lead lane, medium confidence.
  - **Honest coverage:** every lost-work path is partial. The selection used, and the ids of any sessions not judged, are stated in coverage.
- **Deployed:** `8baae62`. Latest hunt `h20261020-115054-da2ab3` (no-expand, agent off, e_a 10:00–17:30 UTC):
  - `partial`; the only reason is 2 ZoneMinder streaming responses TShark could not rebuild;
  - 7 urgent / 15 high / 97 lead / 511 context; 1:56 wall time; 2.6 GB RSS.
- **Scores** (dev set e_a, gold v1, 22 observable; eval-custodian, `docs/eval/results/`):

  | Run | Recall reported | Recall surfaced | P@10 | False leads/hour |
  |---|---|---|---|---|
  | 4: model-off baseline | 11/22 | 15/22 | 1.00 | 5.07 |
  | 7: host↔network correlation | 12/22 | 17/22 | 0.80 | 6.23 |
  | 8: + Arkime + noise fix | 12/22 | 17/22 (critical+high 12/13) | 0.90 | 5.28 |
  | 9: + packet stage (no expansion) | 12/22 | 17/22 (critical+high 12/13) | 0.90 | 5.14 |

  - **Run 9:** both packet leads match gold: the stager served as `/TODO.md` and the authorized_keys drop. But each is for an opportunity the host rules already reported, so recall is unchanged.
  - **Misses:** discovery ×4 and privesc ×1 (no rule matched); 5 lead-only (c2_channel, recon ×3, remote_login).
  - Expansion plus context rules are the next lever for these. Codex's round-1 live run added 3 high context findings and connected incidents, but it is not scored yet because of the review FAIL.
- **Owner actions pending:**
  1. Start Codex on expansion fix round 2 (`Claude-Codex.md`).
  2. Copy the run 9 private eval files from the VM's `/tmp/r9priv/` into `/home/user/romulus-eval/sl700_e_a/`, then delete `/tmp/r9priv` and `/tmp/r9h`. The session's permission rules blocked the eval-custodian from writing there.
  3. Push `m2/evaluation`; Claude Code cannot push.
  4. Decide the false-leads-per-hour ceiling (PROTOCOL §14).
- **Next:**
  1. Codex fix round 2. Then the reviewer re-checks, the lead merges into `m2/evaluation`, deploys, runs a default (expansion) hunt, and the eval-custodian scores it as run 10.
  2. Then tune the expansion budget and tiers by score, and add the context-rule catalog (detection-engineer) aimed at the discovery and privesc misses.
  3. The attack-path timeline page and template narrative (M3).
- **Known issues:**
  - Investigator v2 re-review findings on `0abb1fc` (agent mode only, which is off by default).
  - `host.ssh_authorized_keys_write` misses key appends made inside downloaded scripts. The packet rule catches the lab case; kernel file records are the general fix (M4).
- **Process notes:**
  - Investigator, shell-parser and expansion code goes to Codex via `Claude-Codex.md`. The file is gitignored; replace Claude's last message; old text may be cleared at a new conversation.
  - The eval-custodian never deploys without asking.
  - Detection breadth is a primary goal (spec §7).

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
| 8 GiB VRAM limits model size and context | Weak agent judgment | ADR-005: menu-driven, constrained decisions sized for qwen3:8b; replay evaluation on every investigator change |
| AttackMate timestamps have no stated timezone | Misaligned scoring | eval-custodian aligns against telemetry before scoring |
| No Malcolm or ICS-protocol data in the lab | ICS playbooks only fixture-tested | Public ICS PCAPs; Malcolm VM in M4 |
| VM RAM headroom ~4.6 GiB | Hunts compete with ES and Kibana | nice'd TShark, bounded concurrency; resize before M3 |

## Session log

Newest first. One entry per session where state changed: what was done, what was verified and how, and what was decided.

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
