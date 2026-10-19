# ROMULUS evaluation protocol

Owner of this file: `eval-custodian`. Created 2026-10-19 (M2). Changes to the matching rule, metric definitions or denominators after a scored run must be recorded in §13 (Change log) with the reason. They never apply retroactively to a run that has already been scored.

This file is aggregate-only. It holds no per-opportunity answers. Labels, the gold inventory and evidence locators live only on the VM under `/home/user/romulus-eval/` (mode 700).

## 1. Purpose

Unit tests show the code does what it says. This protocol measures whether ROMULUS finds attackers: recall on observable attacker opportunities, the precision an analyst sees, noise per review hour, citation integrity, speed and cost. It also measures what the agent adds over model-off operation and over a simple baseline (spec §15).

## 2. Datasets

| ID | Role | Status | Exposure | Can support a release claim? |
|---|---|---|---|---|
| `sl700_e_a` | **Dev set** (tuning allowed) | Loaded: `romulus-host-logs-sl700-e-a`, `romulus-network-logs-sl700-e-a`, Arkime node `server` (4 PCAPs under `/opt/arkime/ainception-input/sl700_variant_e_a/`). Gold inventory v1 built 2026-10-19. | Known exposure (§12: C-001 to C-004). | **No, never.** |
| `sl700_f_a` | **Holdout candidate** | Not downloaded, not loaded. Loading needs the owner's decision. | None recorded. | Yes, if §9 is followed and no contamination is logged. Even then it is a *variant-robustness* claim only: every SL700 run shares the storyline and attacker scripts. |
| `sl700_a_b` | Excluded | v1 loaded it (`ainception-*-a-b`); extracted under `~/ainception-agent/data/staging/run_a_b`. | Contaminated (C-001). | No. |
| `sl700_a_a`, `a_c`, `b_a` | Spare SL700 variants | Not loaded. | Storyline known (shared scripts). | Variant robustness only. |
| Different-storyline set (AIT-LDS v2, OTRF, owner emulation, …) | Required before any general-effectiveness claim | Not chosen. | n/a | Yes, with its own protocol entry. |

Dev-set facts used by the protocol (verified 2026-10-19):

- The hunt window used for time positions is **2024-11-18 10:00–17:30 UTC**. The full loaded span is 2024-06-05T14:08:35Z → 2024-11-18T17:17:30Z (host) and 2024-06-21 → 2024-11-18T17:13:20Z (network).
- `inetfw_suricata_1731927869.pcap` is **truncated** at its end: capinfos reports a packet cut short. Any PCAP-derived negative from that file must be `partial`.
- The `alerts/` folder (AMiner, Telosian) was extracted into the eval folder. AMiner alert records embed `GroundTruthLabels`, so the folder is **label-bearing**. It must never be loaded into ROMULUS sources.
- The labeled subset (`attack_e_a_labeled`) is extracted for auth/syslog/attacker files only. Its `malicious` flags are documented as unreliable and were not used as truth.

## 3. Who may see what (blinding)

This is a single-owner project, so blinding is **partial**. The table states actual access, not intent.

| Party | Dev ground truth (`romulus-eval/sl700_e_a`) | Holdout ground truth | Holdout telemetry before freeze | ROMULUS output | Receives from custodian |
|---|---|---|---|---|---|
| Owner | Can read anything (sudo, same machine). Has seen the AttackMate summary in spec §15. | Can read anything. Asked not to inspect before freeze. | Asked not to inspect. | Yes | Everything on request; results files. |
| Lead (Claude main session) | Has read the spec §15 storyline and informally compared M1 output with the AttackMate log (C-003). Must not read the eval folder. | Must not read. | Must not read. | Yes | Dev: aggregate metrics, plus misses by funnel stage and behavior class. Holdout: aggregate only. |
| `detection-engineer`, `integration-tester`, `reviewer` | Must not read the eval folder (agent briefs say so). Can read spec §15, which contains the storyline. | Must not read. | Must not read. | Yes | Aggregate metrics in `docs/eval/` only. |
| `eval-custodian` | Reads and owns it. | Builds it **after** freeze (§9). | Only after freeze. | Reads it for **scoring**, never while building or amending gold before a run. | n/a |
| Hunt runtime (ROMULUS process, local model) | No configured path reaches it (§11). Same Unix user, so the filesystem does not block it. | Same. | Reads it only during the frozen run. | n/a | Nothing. |

Bakeoff task sets (spec §12) follow the same rule: builders receive only scores and failure categories.

## 4. The opportunity

An **opportunity** is one meaningful attacker action on an entity in a time window that an analyst would want surfaced. Gold is built from the AttackMate log plus raw telemetry, **without any ROMULUS output**. Every AttackMate action is accounted for in an action map: it becomes an opportunity, or it is excluded with a reason (`sleep`, `session_control`, editor keystrokes and terminal setup folded into the opportunity they belong to). Attacker-caused activity that AttackMate does not list as its own action (for example, automatic repeats of a planted mechanism) may be added as a **derived** opportunity, flagged `derived_from`.

Fields (schema `gold-opportunity/1`):

| Field | Meaning |
|---|---|
| `opp_id` | Stable ID (`E01`…). Never reused; retired IDs stay listed with a reason. |
| `title` | Plain description of the action (VM only). |
| `behavior_class` | One of: `recon_dns`, `recon_scan`, `exploit_public_app`, `c2_channel`, `tool_transfer`, `interactive_shell`, `discovery`, `privesc`, `persistence`, `remote_login`, `credential_access`, `defense_evasion`, `impact`, `staging`. |
| `attack` | ATT&CK technique IDs (Enterprise; ICS IDs prefixed `ICS:`). |
| `severity` | `critical` / `high` / `medium` / `low`: potential impact if the action is adverse (spec §10), never evidence quality. |
| `entities` | `hosts`, `ips`, `accounts` involved. Host↔IP aliases are recorded in the inventory (DNAT and dual-homed addresses). |
| `window_utc` | `start`/`end` of the action, from telemetry where it exists, else from AttackMate. |
| `time_position` | `hunt_window` = early / middle / late third of 10:00–17:30 UTC, by window start; plus the fractional position in the hunt window and in the full loaded span. |
| `sources` | For each loaded source (`host_index`, `network_index`, `arkime`, `pcap`): `status` (`direct` / `indirect` / `none`), locator count, evidence roles present, and a reason when `none`. |
| `observability` | `observable` (≥1 source `direct`), `inferable_only` (only `indirect`), `not_observable`. |
| `not_observable_reason` | Reason class, e.g. `attacker_host_logs_not_loaded`, `command_not_recorded`, `in_c2_no_process`. |
| `attackmate_actions`, `derived_from`, `note` | Traceability. |

Evidence rows (schema `gold-opportunity/1`, file `gold_evidence.v1.jsonl`) list the **complete** locator set per opportunity and source, not a sample:

- `kind: es` → `index`, `id` (`_id`), `ts`, `dataset`;
- `kind: arkime` → `node`, `session_id`, first/last packet;
- `kind: pcap` → `file`, `file_sha256`, `frames` (list of frame numbers).

Each row carries a `role`:

| Role | Meaning |
|---|---|
| `action` | Records the act itself. |
| `outcome` | Records its direct effect. |
| `indirect` | Implies the act only through a later consequence or volume. |
| `context` | Related but proves nothing alone, e.g. delayed flow logs or an encrypted session carrying the command. |

journald copies of auditd records are included alongside the auditd records.

Hard negatives (`hard_negatives.v1.jsonl`, schema `gold-hard-negative/1`): benign lookalikes with a selector scope, an event count and sample locators. They are guaranteed disjoint from gold evidence. They are used to explain false positives, not to define them.

Files on the VM: `/home/user/romulus-eval/sl700_e_a/gold/` holds `gold_opportunities.v1.jsonl`, `gold_evidence.v1.jsonl`, `attackmate_action_map.v1.jsonl`, `hard_negatives.v1.jsonl`, `MANIFEST.json` (SHA-256 of every file, of the inputs and of the builder scripts) and `TIMEZONE.md`. Builders live in `/home/user/romulus-eval/tools/`. They are label-bearing and never go into the repo.

## 5. AttackMate timezone (dev set)

AttackMate `start-datetime` values have no zone.

**Method.** The AttackMate start times of seven independent anchors were aligned against telemetry whose timestamps carry an explicit zone or are epoch-based. The anchors are: the high-volume reconnaissance bursts (DNS enumeration, port scan, web scanner, content fuzzer), the exploit request, the SSH session start, and one host command. The telemetry families were:

- apache access log `+0000`;
- Suricata EVE `+0000`;
- auditd epoch;
- dnsmasq and kernel logs on the target hosts;
- Arkime and PCAP packet epochs.

**Result.** The offset is **0 h**: AttackMate times are naive UTC. For anchors that the telemetry records directly, the residual is ≤ ~1 s. The exploit anchor lags by up to 17 s, which is module runtime, not clock skew. Any whole-hour offset would place every burst on empty or unrelated telemetry. All sensor clocks agree to well under 1 s.

## 6. Matching rule (pre-registered 2026-10-19, before any scoring)

A ROMULUS **item** is any finding, lead or context entry in the report manifest, including agent-produced items. An item **hits** opportunity *O* at:

- **Tier A (strict, the headline tier)** when all three hold:
  1. at least one raw locator cited by the item is in *O*'s evidence set with role `action` or `outcome`. For opportunities that are `inferable_only`, role `indirect` counts, but those are scored only in their own table;
  2. the item's affected entities intersect *O*'s `entities`, after host↔IP alias resolution;
  3. the item's event time range overlaps *O*'s `window_utc` extended by ±120 s.

  If a locator matches but (2) or (3) fails, the item is not a hit. It is logged as an anomaly for custodian review.

- **Tier B (loose, reported separately, never in headline recall)**: (2) and (3) hold with the window extended by ±10 min, but no cited locator is in the evidence set, or only `context`-role locators are. Tier B measures "pointed at the right place without the proving record".

Locator equality:

| Locator | Match condition |
|---|---|
| ES | `index` + `_id` exact. |
| Arkime | session ID exact. |
| PCAP | file (by SHA-256, or by basename if the hash is unavailable) + frame number in the frame set. |
| Retained raw copy in the ROMULUS store | Matches through the native locator stored with it. |

No text or substring matching is used to decide a hit.

Further rules:

- One item may hit several opportunities.
- An opportunity counts once for recall, however many items hit it.
- Further items hitting an already-hit opportunity are true positives for precision but are counted as **duplicates**, and the duplicate rate is reported.
- An item that hits no opportunity at Tier A is adjudicated by the custodian against raw telemetry as one of:
  - `true_unlisted`: malicious, but not in the inventory. This triggers an inventory amendment, logged in §13;
  - `benign` (cites hard-negative records where applicable);
  - `unsupported`: the item's claim is not supported by its citations.

An amendment may **add** opportunities. It never removes one after a miss, and it never shrinks a denominator for the run that prompted it. Amended opportunities are scored from the next run on and listed in that result file.

## 7. Lanes: reported vs surfaced

| Set | Lanes | Use |
|---|---|---|
| **Reported** | `urgent`, `urgent validation`, `high` | Headline recall, P@k, time to first actionable finding |
| **Surfaced** | Reported ∪ `lead` | Secondary recall (`recall_surfaced`), false leads per hour |
| **Mentioned** | `context` | Reported in a separate column. Never counted as found. |
| Not surfaced | `benign` / `suppressed`, items dropped or unworked | A Tier A hit here is a **suppression miss** and is listed in the funnel. |

## 8. Metrics (denominators fixed by the inventory version)

Every metric names its inventory version, run ID, config digest, rule-pack digest, prompt digest and model.

1. **Recall**:
   - `recall_reported` = observable opportunities with ≥1 Tier A item in Reported, divided by observable opportunities.
   - `recall_surfaced` is the same over Surfaced.
   - Slices:
     - by severity, by behavior class, and by time position, using the observable opportunities in each slice;
     - by source: the denominator is the opportunities with `direct` status in that source, and the numerator needs a Tier A locator *from that source*.
   - The **critical+high** slice is the spec's ≥90% target, and **all observable** is the ≥80% target.
   - `inferable_only` and `not_observable` opportunities are reported in their own tables and never enter the headline.
   - Uncertainty: Wilson 95% interval on every proportion. With n ≈ 20, intervals are wide; the result files must say so.
2. **Miss funnel** (dev only; aggregated by stage × class): see §10.
3. **Precision at review ranks**:
   - Order: the report manifest's review order (lane rank, then priority, then finding ID).
   - `P@10` and `P@20` = TP / min(k, n), where TP = Tier A hit or adjudicated `true_unlisted`.
   - Always report n when n < k.
4. **False leads per review hour** = (`benign` + `unsupported` items in Surfaced) / review hours.
   - Review hours are measured when a human reviews with a timer.
   - Otherwise they are **modeled** at 5 min per surfaced item. That constant is pre-registered and labeled "modeled" wherever it is used.
5. **Citation validity**: the share of citations in Reported items whose locator resolves (in the source, or in the retained copy with a matching digest) and whose cited record's typed fields support the claim type (execution vs mention vs network). The check is automated for resolution and field match. The custodian reviews claim support manually: all Reported items plus a 20-item random sample of leads (seed recorded). Also report the **unsupported-claim count**.
6. **Time to first actionable finding**: wall-clock from hunt start to the first Reported item that is a Tier A hit on a critical or high opportunity. Also report total hunt wall time and time to first finding of any kind.
7. **Cost**:
   - ES requests, documents and bytes fetched;
   - Arkime API calls;
   - TShark CPU-seconds;
   - model calls, prompt and completion tokens, model wall time;
   - peak RSS if available.
8. **Coverage-claim accuracy**: every `no_match_complete` coverage cell whose partition contains a gold `action`/`outcome` record of a class the rule claims to detect is a *candidate false complete negative*. The custodian adjudicates each one. The target is zero.
9. **Breadth**:
   - per-rule hit counts and precision on this dataset;
   - rules that never fired on any dataset with known activity, listed as unproven.

   These come from ROMULUS's coverage matrix plus Tier A hits.
10. **Ablations**:
    - **Model-on vs model-off**: same window, sources, rule pack and config, with `--no-agent`. Report every metric for both, plus the opportunities hit only with the model on, and the time-to-first and cost deltas.
    - **ROMULUS vs simple baseline**: see §8.1.
11. **AMiner / Telosian comparison**: see §8.2.

### 8.1 Simple baseline ("run the standard searches and review")

A fixed list of standard analyst searches, executed read-only by `eval/` over the same window and the same sources, with results stacked and reviewed under the **same review budget** (the same number of review items as ROMULUS Surfaced, ranked by search order then by rarity):

- Suricata alerts stacked by signature;
- rare process names and executables per host;
- successful authentications per source IP and account, with external sources first;
- sudo commands;
- new or rare outbound destinations per host;
- HTTP 4xx bursts per client;
- DNS query volume per client;
- long-duration and high-volume sessions (Arkime);
- iptables, cron, SSH-key and shell-history file names in process arguments.

Baseline items are scored with the §6 rule. Their locators are the records the search returned.

**Bias note.** The custodian wrote this list knowing the dev answers. Dev-set baseline numbers are therefore optimistic for the baseline. For a holdout, the baseline list is frozen in the pre-registration block (§9) and not changed afterwards.

### 8.2 AMiner and Telosian alerts

- The AMiner and Telosian alert files in the dataset's `alerts/` folder are scored as two more systems.
- An alert carries host or log-line context (AMiner) or a netflow tuple and time range (Telosian), but no ES locators. A Tier A hit therefore needs an alert's raw log line to equal an evidence record's raw original (exact string equality of the whole line, after trimming the line ending), or its flow tuple and time to equal an evidence flow record.
- Matches that are entity+time only are scored as Tier B.
- Report recall on the same denominators, alert volume, and precision over a review budget equal to ROMULUS Surfaced (ranked by alert order).
- The `GroundTruthLabels` fields in those files are ignored during scoring.

## 9. Run procedure

**Dev runs** (`sl700_e_a`):

- Any number of runs is allowed. Each gets a run ID `<date>-sl700_e_a-<n>` and a result file `docs/eval/results/<date>-sl700_e_a-<n>.md` with aggregate metrics, the funnel, digests and the inventory version.
- Feedback to builders: misses by funnel stage and behavior class. Class-level wording is preferred over exact records, times or commands.

**Holdout** (`f_a` or a successor):

1. The owner approves the download. The custodian, or the integration-tester with the custodian present, downloads from the official Zenodo record and verifies checksums. Data is loaded into separate indices (`romulus-*-sl700-f-a`) and a separate Arkime node, and ground truth is extracted to `/home/user/romulus-eval/holdout_f_a/` (mode 700). Nobody opens the telemetry or the ground truth beyond what the load requires. Every exception goes in §12.
2. **Freeze**: the lead names the release candidate. The custodian fills §14: git commit, rule-pack digest, prompt digests, model names and digests, `num_ctx`, config digest (secrets excluded), baseline search list digest, the review-time constant, and target thresholds agreed with the owner.
3. The custodian builds the holdout gold inventory **after** the freeze. The custodian's view of holdout content cannot flow back into a frozen system. The inventory's SHA-256 is added to §14 before the run.
4. **One** run: model-on, then model-off and the baseline on the same frozen inputs.
   - A rerun is allowed only for a documented infrastructure failure (service down, VM out of memory) that leaves the hunt unable to complete, and every attempt is reported.
   - A rerun is never allowed because of the scores.
5. Aggregate-only result file. Builders get the aggregate numbers and nothing else, so the holdout stays usable for comparing later versions only if it was never tuned against. After a release claim, it is retired as a holdout.

## 10. Miss funnel (dev set)

For each observable opportunity not hit at Tier A in Reported, the furthest stage reached is determined per source in which it is `direct`, from the hunt DB (spec §8 tables):

| Stage | Reached when |
|---|---|
| source | Gold says the record exists in the source (by construction). |
| queried | A `compiled_query`/`task` targeting this source covered the opportunity's entity partition and time window, from its `partition` and `search_outcome`. |
| retrieved | A `raw_record` with one of the opportunity's action or outcome locators exists. |
| normalized | That raw record has a `typed_event` without a blocking `normalization_error`. |
| evaluated | A `rule_run` or `coverage_cell` shows a rule evaluated that typed event or its partition, including the evaluation state (`partial`, `unsupported`, …). |
| candidate | A `candidate_evidence` row references the record. |
| reported | A finding in Reported cites it (a hit). Surfaced-but-not-Reported is listed as `surfaced_only`. |

- The stage is the furthest reached across sources, and the per-source stages are kept.
- Also recorded: whether an agent case touched the opportunity's entities (`agent_touched`), and the coverage state of the relevant cells.
- Dev result files show counts by stage × behavior class.
- Holdout result files show counts by stage only.

## 11. Isolation checks

Run 2026-10-19 by the custodian; rerun before every holdout run.

| Check | Result |
|---|---|
| `/home/user/romulus-eval` and every child | Mode 700/600. Owner `user`. 0 files with group or other permissions. |
| `/home/user/romulus-v2/.env` path-valued settings | Only `ROMULUS_HOME=/home/user/romulus-v2` and `PCAP_ALLOWED_DIRS=/opt/arkime/ainception-input`. `ES_INDEX_PATTERNS` names only the two lab indices. No setting references the eval folder. |
| Symlinks under the PCAP allowlist | None. The real paths are disjoint from `/home/user/romulus-eval`. |
| App source and config | The eval path appears only in `doctor.py`, as the forbidden root for the overlap check. Defaults in `config.py`/`cli.py` point to `/home/user/romulus-v2`. |
| `romulus doctor` | PCAP allowlist OK, `.env` 0600, and no `paths.eval_isolation` failure. |
| Model path control | By invariant, the model proposes no paths. PCAP paths are validated against the allowlist. |

**Residual risk.** The hunt runtime runs as the same Unix user (`user`) that owns the eval folder. File permissions therefore do **not** stop a runtime bug or a malicious input from reading it. Isolation rests on configuration and code (allowlists, typed actions). Owner remedy (needs sudo): move ground truth to a dedicated account, e.g. `romulus-eval`, that the runtime user cannot read, or run ROMULUS under its own service user.

## 12. Contamination log

| ID | Date | Dataset | Who | What was seen | Consequence |
|---|---|---|---|---|---|
| C-001 | before 2026-10-18 | `e_a`, `a_b` | v1 developer (owner, with v1 tooling) | v1 rules and prompts were tuned against `e_a` and `a_b`. `a_b` was loaded into `ainception-*-a-b` and extracted to `run_a_b`. | v1 results are not independent evidence. `a_b` is excluded as a holdout. |
| C-002 | 2026-10-18 | `e_a` (and the SL700 storyline generally) | Owner and lead | Ground truth was located and extracted. The e_a AttackMate storyline summary (tools, exploit, privilege-escalation path, persistence, impact, and the attacker and target addresses) was written into spec §15. That spec is read by every agent and is deployed on the VM under `/home/user/romulus-v2/app/`. | Every builder knows the dev storyline. Because all SL700 runs share scripts, the storyline of any SL700 holdout is also known in outline. |
| C-003 | 2026-10-18 (M1 build) | `e_a` | Lead | Informally compared M1 hunt output with the AttackMate log. STATUS.md records which steps were found and which were missed (post-login discovery, the editor-based cron-target edit). | Builders have step-level dev feedback. `e_a` stays a dev set with known exposure and **can never support a release claim**. |
| C-004 | 2026-10-19 | `e_a` | eval-custodian | Read `attackmate.json`, `attack_log.json`, readme, infra, the AMiner/Telosian alerts, the labeled auth/syslog files, and raw telemetry (ES, Arkime, PCAP). Built gold v1. Did **not** read any ROMULUS hunt DB, report or finding. Had read spec §15 and STATUS.md (C-002, C-003) beforehand. Label-bearing working copies were deleted from the Windows scratchpad and VM `/tmp`. This session's transcript and tool-output spill files under the owner's Windows Claude profile (outside the repo) still contain ground-truth detail. | Expected custodian access. Gold v1 is independent of ROMULUS output, but not of the spec's storyline summary. Builder agents must not be pointed at custodian transcripts. |
| — | 2026-10-19 | `f_a` | — | Not downloaded. No exposure. | Usable as a holdout if §9 is followed. |

## 13. Change log

| Date | Change | Reason |
|---|---|---|
| 2026-10-19 | Protocol created. Matching rule (§6), lanes (§7), metrics (§8), funnel (§10) pre-registered before any scoring. Gold `sl700_e_a` v1 built. | M2 start |
| 2026-10-19 | The lead accepted §6 and §7 as written. | Review |
| 2026-10-19 | **Scoring source: the hunt DB**, opened read-only (`mode=ro` URI plus `query_only`). The latest report-manifest revision is used only for the review order and its rule-level coverage claims. | The manifest omits context-lane items (open item I10), and the funnel needs `task`, `rule_run` and `candidate` rows. Items are rebuilt from `candidate` → cited `typed_event` → raw refs (`target` = index, `native_id` = `_id`), the same native locators the retained raw copies carry. |
| 2026-10-19 | Interpretations of §6, fixed before the first scored run: | Typed events log Suricata flows at log time, which can be minutes after the activity. |
| | • **Item time range** = the union of the cited typed events' `ts` and, where present, EVE `flow.start`/`flow.end`. | |
| | • **Item entities** = candidate entity values plus the cited events' hosts, lower-cased, with any `host\` prefix removed from accounts. | |
| | • Host↔IP aliases come from a new gold file, `aliases.v1.json`, listing DNAT and dual-homed addresses. This is not an opportunity or evidence change. | |
| 2026-10-19 | **Adjudications** are keyed by an item signature = SHA-256 of (rule ID, sorted cited locators). Candidate IDs differ between hunts, so this signature is what lets a verdict carry over to the same evidence in a later hunt. Stored on the VM only (`romulus-eval/sl700_e_a/adjudications.v1.jsonl`). | Run-to-run reuse |
| 2026-10-19 | **Funnel determination** (§10), made concrete because the store retains only candidate-supporting records and `typed_event`/`raw_record` are not hunt-scoped: | Store limitation, reported to the lead as a product issue |
| | • *retrieved* = a covering task (target, window, dataset filter) finished `complete`; | |
| | • *normalized* and *evaluated* = replay of the product normalizer over the gold action/outcome records, fetched read-only from ES (cap 3,000 per opportunity and source), then a rule of the hunt's pack consuming that family with an evaluated cell covering the event time; | |
| | • Arkime/PCAP stop at *source* until adapters exist. | |
| 2026-10-19 | **Coverage-claim accuracy** (§8.8) uses only `no_match_complete` cells plus the report's rule-level `complete` claims. | `evaluated_complete` means "fully evaluated", not "no match"; cells in that state contain matched partitions. |
| 2026-10-19 | **Known limitation.** For `inferable_only` opportunities, the indirect evidence can lie outside the action window (later use of a transferred file). A citation of it then fails the time check and is logged as an anomaly, not a hit. Kept as pre-registered; revisit with the lead before any holdout. | Found in the first scored run (1 anomaly, reviewed) |
| 2026-10-19 | **Gold amendment v1.1 pending.** Adjudication found attacker-caused executions outside the v1 evidence sets of two observable opportunities: the exploit's vulnerability-check and payload-stage executions, and enumeration-script descendants reached through forked subshells that leave no exec record. The amendment will add them as evidence. No opportunity is added or removed, denominators are unchanged, and it applies from the next scored run. Run 1–2 precision counts them as `true_unlisted`. | §6 amendment rule |
| 2026-10-19 | The agent-on hunt `h20261018-224406-923663` (pre option B) was deleted from the store on 2026-10-19 01:14 UTC (`hunt.delete` audit event). No agent-on hunt exists, so model-on vs model-off is pending a new agent-on run. | Scoring round 1 |

## 14. Pre-registration block (holdout)

Status: **not yet frozen**. Fill in before the holdout run; do not edit afterwards.

| Item | Value |
|---|---|
| Holdout dataset and checksum | pending |
| Git commit | pending |
| Rule-pack digest | pending |
| Prompt digests | pending |
| Triage and synthesis models (name, digest), `num_ctx`, think setting | pending |
| Config digest (secrets excluded) | pending |
| Baseline search list digest | pending |
| Review-time constant | 5 min per surfaced item (unless measured) |
| Targets | ≥90% `recall_reported` on observable critical+high; ≥80% on all observable; P@10 ≥ 0.8; false-lead-per-hour ceiling: pending owner |
| Gold inventory SHA-256 (built after freeze) | pending |

## 15. Dev-set denominators: gold `sl700_e_a` v1 (aggregate)

Inventory v1: 27 opportunities, built 2026-10-19. The `gold_opportunities.v1.jsonl` SHA-256 is recorded in the VM manifest. All 61 AttackMate actions are accounted for: 40 map to opportunities, 19 are sleeps and 2 are session-control actions.

| | Count |
|---|---|
| Observable (headline denominator) | **22** |
| Inferable only | 1 |
| Not observable | 4 (attacker-host logs not loaded: 2; command not recorded: 1; inside the C2 implant, no process: 1) |
| Derived (attacker-caused, not an AttackMate action) | 2 (both observable) |

| Severity | All | Observable |
|---|---|---|
| critical | 6 | 6 |
| high | 8 | 7 |
| medium | 1 | 1 |
| low | 12 | 8 |
| **critical+high** | 14 | **13** |

| Behavior class (observable / all) | |
|---|---|
| discovery | 5 / 7 |
| recon_scan | 3 / 3 |
| c2_channel, interactive_shell, persistence, privesc | 2 / 2 each |
| recon_dns, exploit_public_app, remote_login, credential_access, defense_evasion, impact | 1 / 1 each |
| tool_transfer | 0 / 1 (inferable only) |
| staging | 0 / 2 (attacker host only) |

| Source (`direct`) | Observable opportunities with direct evidence in that source |
|---|---|
| host index | 22 |
| network index | 10 |
| Arkime | 12 |
| PCAP | 12 |

Further source breakdown:

- 10 observable opportunities are host-index-only.
- Of the 13 observable critical+high opportunities, 6 are directly visible in all four sources, 2 in three, and 5 in the host index only.

Time position (hunt window thirds):

- all 27: 0 early, 13 middle, 14 late;
- observable 22: 0 early, 9 middle, 13 late.

In the full loaded span every opportunity sits in the last 0.08% (fractions 0.9992–0.9996).

There are **no early-window opportunities** in this dataset. The spec's early/middle/late coverage requirement cannot be met by `e_a` alone; it needs fixtures or another dataset.

Hard negatives v1: 5 benign-lookalike families, disjoint from gold evidence. They are administrative root sessions, scheduled jobs, service-spawned shells, PAM shadow reads and normal web-application use.
