# Milestone acceptance checklists

Each item maps to the spec (`ENGINEERING_MASTER_PROMPT.md`). Check an item only with an **evidence** link: a test name, command output in a results file, a commit, or a demo note. The lead owns this file. Subagents propose evidence; the lead verifies it and ticks the box.

Status words: `implemented` · `locally tested` · `integration tested` · `lab evaluated` · `holdout evaluated` · `production validated`.

## M1: thin end-to-end slice (spec §17)

- [~] Package skeleton, `.env.example`, config loader with secret redaction (§4). Evidence: `src/romulus/config.py`. **Open:** the uv lockfile; uv can't use the Windows Store Python, so generate the lock on the VM.
- [x] SQLite plus Alembic migrations; hunt manifest fixed at creation; profile drift is audited (§8). Evidence: migrations `0001`–`0003`, owner-fenced hunt leases in `hunt/run.py` and `store/repo.py`, `tests/test_agent_store.py`.
- [x] `doctor`, integration tested on the VM 2026-10-18: ES 9.5.5 `romulus_reader` read-only; Arkime, Ollama, TShark, DB and `.env` mode all OK; refuses superuser accounts.
- [x] ES adapter: allowlist plus write-trap tests (`tests/test_sources_es.py`); PIT plus `search_after`; composite aggregations; cap, shard and lower-bound totals become partial.
- [x] Source profile and field contract from the live mapping (`sources/profile.py`); `text` fields refuse `contains`, which would not be a retrieval superset.
- [x] Typed normalizers, live-verified with 0 errors on 1.79M records: audit exec groups (EXECVE+SYSCALL+CWD), journal sshd/sudo (audit copies flagged as duplicates), apache access/error, Suricata EVE.
- [x] 15 playbooks with positive and adversarial-negative fixtures (`tests/test_playbooks.py`). Stack counting, a sequence rule, aggregate grouping. Kernel-recorded temp executables are separate from positive-only interpreter script operands; script-text rules report per-rule assurance limits, and their allow-list parser handles conservative argv layouts and permits web-interpreter positives only from fully terminated lines before unsupported syntax (`tests/test_evidence.py`, `tests/test_sweep.py`).
- [~] Admission and lanes (`decide/policy.py`). Direct rules publish while the sweep runs; aggregate rules publish at sweep end.
- [x] Agent loop, **integration tested**: explicit SQLite-backed controller, compact briefs, discriminated decisions, hostile-input validation, four M1 typed tools, direct-only pivots, exact dense-window coverage, duplicate rejection, fairness/budgets, owner-fenced leases, pivot persistence and agent-only resume. Validation fallbacks remain unworked as `fallback_parked` and raise analyst flags. Evidence: `tests/test_agent_*.py`, `tests/test_hunt_agent.py`, lab hunt `h20261018-224406-923663` (54 calls, 3 pivots, 9 rejected proposals, 8 analyst-flagged fallback cases).
- [x] Web UI: login (argon2, rate limit), CSRF, CSP; hunt list; live SSE view; finding detail with highlighted predicate fields and retained raw records; triage; reports (`tests/test_web.py`).
- [x] Report manifest (immutable revisions, citation resolution, degraded mode, investigator chains/conclusions/contributions/unworked seeds) plus JSON plus technical Markdown (`tests/test_report.py`).
- [x] Deployed and **integration tested** on the VM. Executable/operand split deploy `ea2c410`; model-off hunt `h20261019-020720-4448fd` completed within scope with 7 urgent / 10 high / 80 lead / 504 context, 0 errors, and 0 broken citations. The 455-test suite covers the negative-assuring kernel executable rule, the positive-only interpreter operand rule, shell `-s` followed by `-c`, and awk option-section boundaries. Eighteen package-maintenance findings moved to restrained script-operand claims and the single real temp executable retained its prior rule. The live linpeas event has no cwd/CWD telemetry, so it soundly remains a web-service interpreter lead rather than a temp-path finding. Earlier agent hunt `h20261018-224406-923663` exhaustively lists all 97 unworked seeds and 8 fallback analyst flags; live model effectiveness remains open.
- [x] `reviewer` milestone review: no Blocking findings open. Concluded 2026-10-19 after the final scoped check; fixes in `a76f155`, verified with the reviewer's own probes; merged to `m1/thin-slice` (ADR-004 option B).
- [x] Owner demo recorded in STATUS.md (2026-10-19: technical report walkthrough of `h20261019-093029-32dfef` and owner exploration of the web UI).

## M2: evaluation harness and model bakeoff

- [ ] Gold opportunity inventory for e_a (eval-custodian; on the VM, not the repo)
- [ ] Scoring scripts plus `docs/eval/PROTOCOL.md`
- [ ] Simple "standard searches" baseline runner
- [ ] Model bakeoff task set, runner, and results; ADR selecting triage/synthesis models and `num_ctx`
- [ ] First lab evaluation results file with miss funnel

## M3: full sources and coverage truth

- [ ] Arkime adapter plus field contract from `/api/fields`; aggregate endpoints; count semantics
- [ ] TShark adapter: path allowlist, AST filters, one-pass extraction cache
- [ ] Per-rule × source × partition coverage ledger
- [ ] Fault-injection suite: no false complete negatives (§9, gate 3)
- [ ] Entity profiles plus full pivot catalog
- [ ] Kernel-record Linux host rules (auditd PATH/CWD/watch) that can assure negatives (ADR-004)
- [ ] Detection-breadth research started (spec §7 *Detection breadth*): vendored ATT&CK Enterprise and ICS STIX; a research register with the full technique walk and a disposition for every technique; a generated `docs/detection/ATTACK_COVERAGE.md` checked in CI. May start during M2.
- [ ] Crash/resume tests at task transitions

## M4: detection breadth and depth

The scope is the whole research-driven catalog (spec §7 *Detection breadth*), not a short list. The examples in the spec are samples, not limits.

- [ ] Playbooks and rules across every ATT&CK tactic for each supported telemetry family. Every observable technique has an active rule or a documented reason it has none.
- [ ] Windows/AD normalizers and playbooks:
  - Security, Sysmon, PowerShell, Defender, Task Scheduler, WMI, RDP;
  - Kerberos and AD;
  - field contracts from Winlogbeat and Elastic Agent profiles.
- [ ] Corpus harvest recorded in the register, with licenses: SigmaHQ, CAR, Elastic and Splunk rules, Atomic Red Team, LOLBAS/GTFOBins/LOLDrivers, ET Open, CISA advisories.
- [ ] Offensive and dual-use tool catalog in the register (spec §7 item 6):
  - ATT&CK Software, C2 and post-exploitation frameworks, credential and AD tooling, enumeration scripts, tunnels, remote-access and admin tools;
  - behavioral detections first, with name, hash and command-line leads layered under them.
- [ ] Living-off-the-land coverage (spec §7 item 7): every LOLBAS/GTFOBins binary and abuse pattern has a register entry, and its detection rests on context (parent, account, arguments, effect, rarity against baseline).
- [ ] Cross-cutting themes (spec §7 item 8): process lineage, unusual execution paths, masquerading, persistence, privilege escalation, credential access, lateral movement, defense evasion, discovery bursts, C2/exfiltration, first-seen activity.
- [ ] Sigma import (with upstream commit provenance)
- [ ] Offline indicator sets (STIX 2.1 / MISP / CSV), typed matching, provenance and age cited
- [ ] Breadth datasets vetted and loaded (Windows/AD, network, ICS), with per-family evaluation results and per-rule precision
- [ ] Zeek normalizers plus playbooks
- [ ] OpenSearch/Malcolm source contract (fixtures; live pending until the Malcolm VM exists)
- [ ] ICS playbooks plus baselines on public ICS PCAP fixtures; CCTV/RTSP Loss-of-View playbook on SL700
- [ ] Discovery lane with separate budget and measured incremental value
- [ ] Triage workflow, suppressions with expiry, `lead`/`analyst` roles

## M5: synthesis and reports

- [ ] Attack-path assembly (observed vs. inferred edges)
- [ ] Narrative with per-sentence citation checking
- [ ] Recommendations linked to findings and ATT&CK mitigations
- [ ] Executive DOCX from template; read-back consistency test; LibreOffice page renders
- [ ] Technical Markdown complete; IOC export; report revisions
- [ ] Owner readability review of both reports

## M6: hardening and holdout

- [ ] Web authentication, TLS, CSP, CSRF; XSS and formula-injection tests (§16 #21)
- [ ] Security review (`/security-review` plus reviewer security brief)
- [ ] Backup/restore drill; offline wheelhouse install
- [ ] Holdout pre-registered and run once; results published
- [ ] Release gate review (§15 gates 1–9)

## After M6: standing detection work

Not a milestone that closes. Keep the research register current with each ATT&CK release and new advisories, add telemetry families and datasets as missions meet them, and keep every coverage-matrix gap visible until it is closed or retired with a reason.
