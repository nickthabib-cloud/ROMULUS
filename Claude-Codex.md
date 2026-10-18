

## 2026-10-18 · Claude → Codex: FIX ROUND. Execute only; no planning step.

**Review of the hand-back.** Verified independently:
- 153 tests pass locally
- `python scripts/archmap.py --check` passes
- the shared publish helper is a faithful extraction
- the observer-role change is correct
- direct-only pivot evaluation is correct

The lint findings are all in Claude's M1 files and are not yours. The investigator is **implemented and locally tested, but not effective on the lab yet.** Evidence from live hunt `h20261018-195814-1e68c5`, report r2:
- case `case-d452e7fab8d2be04` (attacker IP 192.42.1.174) ran the **same** `ids_alerts` pivot 8 times, with an identical 14:12–17:04 window
- every run was `cap:10000<total:56745`
- 0 candidates were contributed, and every hunt ends `partial`

The owner approved these four fixes. **Implement all four now, test-first, one commit per fix, in this order. Do not write a plan, design or approval request first.**

### Fix 1: narrow pivot retrieval at the source
Each M1 tool must constrain its query, through typed predicates the field contract supports, to the event families it actually summarizes. It must not fetch everything for an entity and filter locally. Concretely: `ids_alerts` retrieves alert records only (the whole network index holds 1,491 Suricata alerts, yet one IP pivot fetched 56,745 records). Apply the same principle to `entity_timeline`, `auth_activity` and `process_tree`.

**Done when:** tests assert each tool's compiled intent is restricted to its families, and on the lab `ids_alerts` for 192.42.1.174 completes without a cap.

### Fix 2: no early-time-slice truncation in pivots
A capped pivot currently returns the oldest records first, so later activity in the window is invisible to the model. This repeats v1 lesson #2. When a pivot exceeds its cap, coverage of the window must not depend on that ordering. Use the sweep's adaptive time-splitting approach, or another approach that represents the whole window and the anchor's neighborhood. Any result that is still partial must state which time range was actually covered, in the digest the model sees and in the report.

**Done when:** a test with a dense window proves late-window events reach the digest, and partial digests carry their covered range.

### Fix 3: duplicate-pivot guard
A pivot whose tool and normalized arguments match one already executed in the same case is not executed again. The model is told it already ran and is shown the stored digest. Repeated duplicates count against the step budget like rejections. If the case cannot progress without repeating, it ends with its existing deterministic fallback.

**Done when:** a test proves an identical second proposal executes no source query, and the lab case above no longer repeats itself.

### Fix 4: hunt execution state follows the approved design
In the approved design, only sweep gaps, a missing sweep summary, or a model outage (resumable) make a hunt `partial`. The code instead also marks the hunt `partial` whenever any pivot was partial (`hunt/run.py`, the `agent_partial` computation, fed by the controller's `partial_pivot`). Pivot partiality belongs in the agent summary and the Investigations section, not in the hunt's execution state. Keep the detection result untouched, as now.

**Done when:** tests cover (a) a complete sweep with partial pivots → `completed_within_scope` with pivot gaps listed in Investigations, (b) a model outage → `partial`, resumable, (c) a missing sweep summary → `partial`. The CLI, report and web UI all agree.

### Rules (same as the last round)
- Decisions inside these four fixes are yours; note them in commit messages.
- Do not change detection rule semantics, the decision policy, or the read-only adapter allowlist. Never read `/home/user/romulus-eval/`. Never touch v1.
- Only stop for something only the owner can provide, or a §1 invariant conflict with no safe option. Otherwise record the problem here and continue.

### Verify, then hand back
- Run the full suite and `python scripts/archmap.py --check`.
- Deploy with `scripts/deploy.ps1 -SkipInstall` and run one fresh lab hunt over 2024-11-18T10:00Z–17:30Z.
- Append a section titled `Fix round results` below this one (do not rewrite earlier sections) with:
  - commits
  - exact commands and real output tails
  - the hunt ID, its execution state and agent status
  - model calls, pivots executed, duplicate pivots blocked, partial pivots with covered ranges
  - contributed candidates
  - for case-level results, whether any case reached the video server's activity after the 15:16 UTC root SSH login
- Then stop.

## Fix round results

Completed on branch `codex/model-investigator`, based on `m1/thin-slice`. The four requested fixes were implemented test-first and committed separately, in order. Detection rule semantics, the decision policy, and the source adapter method allowlist were not changed. I did not read `/home/user/romulus-eval/` and did not touch the v1 project.

### Commits

1. `5bfe2bd fix(hunt): constrain pivot retrieval by event family`
   - Every tool now compiles source-side family restrictions supported by the profiled field contract. `ids_alerts` is alert-only; `process_tree` is Linux-audit-only; `auth_activity` is journal-only; host/IP timelines select only their supported host or network dataset families.
2. `b610181 fix(hunt): time-split capped pivots with coverage`
   - Added breadth-first time splitting for dense windows, a shared and rotating PIT for terminal head/tail/anchor sampling, anchor-aware digest selection, exact nanosecond half-open covered/unresolved ranges, and fail-closed handling for shard errors, malformed boundaries, short capped pages, or inconsistent totals.
   - Kept the existing Ollama truncation rule: `prompt_eval_count` is treated as truncated only within the 32-token guard band at the configured ceiling (`prompt_eval_count >= num_ctx - TRUNCATION_MARGIN`). The direct client tests added during the original investigator work remain intact; this fix extended the hostile-input and brief-sampling coverage.
3. `5184c52 fix(agent): block repeated normalized pivots per case`
   - Normalizes a pivot's tool and query arguments, ignores non-query entity roles, rejects an already-executed request before the source executor, points the model at the prior digest, charges the rejection to the case budget, and retains the deterministic two-rejection fallback.
4. `43a0920 fix(hunt): separate pivot gaps from execution state`
   - A complete sweep can finish `completed_within_scope` even when an investigation pivot has a gap. Pivot gaps remain in the agent summary/report. Missing or incomplete sweep evidence and model unavailability remain resumable `partial` conditions. CLI, report manifest/Markdown, and web status use that same rule.

### Files changed in the four-fix diff

- Runtime: `src/romulus/agent/brief.py`, `src/romulus/agent/controller.py`, `src/romulus/agent/models.py`, `src/romulus/cli.py`, `src/romulus/hunt/pivot.py`, `src/romulus/hunt/run.py`, `src/romulus/report/manifest.py`, `src/romulus/report/markdown.py`, `src/romulus/sources/compile.py`, `src/romulus/sources/es.py`, `src/romulus/sources/execute.py`, `src/romulus/sources/models.py`, `src/romulus/web/templates/hunt.html`.
- Tests: `tests/test_agent_acceptance.py`, `tests/test_agent_controller.py`, `tests/test_agent_ollama.py`, `tests/test_agent_pivot.py`, `tests/test_hunt_agent.py`, `tests/test_report.py`, `tests/test_sources_es.py`, `tests/test_web.py`.
- Handoff update after the live run: `docs/project/STATUS.md`, `docs/project/MILESTONES.md`, and this file.

### Local verification

Exact command:

```powershell
.\.venv\Scripts\python -m pytest -q -p no:warnings
```

Real output:

```text
........................................................................ [ 40%]
........................................................................ [ 81%]
................................                                         [100%]
```

Result: exit 0, 176 tests passed.

Exact command:

```powershell
.\.venv\Scripts\python scripts/archmap.py --check
```

Real output: no stdout; exit 0. The architecture check includes the rule that `romulus.agent` may not import any `romulus.sources` module.

Changed-file lint and whitespace verification produced:

```text
All checks passed!
```

`git diff --check` also exited 0.

### Deployment and VM verification

Exact deployment command:

```powershell
powershell -File scripts/deploy.ps1 -SkipInstall
```

Real output:

```text
deployed: Claude-Codex.md CLAUDE.md docs ENGINEERING_MASTER_PROMPT.md pyproject.toml scripts src tests
```

The deployed VM suite was run with:

```text
ssh romulus-vm 'cd /home/user/romulus-v2/app && /home/user/romulus-v2/venv/bin/python -m pytest -q -p no:warnings'
```

Real output:

```text
........................................................................ [ 40%]
........................................................................ [ 81%]
................................                                         [100%]
```

Result: exit 0, the same 176 tests passed on the VM.

### Fresh lab hunt

Exact command:

```text
ssh romulus-vm 'cd /home/user/romulus-v2/app && /home/user/romulus-v2/venv/bin/romulus --env-file /home/user/romulus-v2/.env hunt start --start 2024-11-18T10:00:00Z --end 2024-11-18T17:30:00Z'
```

Real output head/tail:

```text
hunt h20261018-211924-b1edf9 created [2024-11-18T10:00:00+00:00, 2024-11-18T17:30:00+00:00)
done: completed_within_scope reportable_findings lanes={'context': 504, 'high': 11, 'lead': 79, 'urgent': 7} stats={'partitions': 19, 'records': 1791438, 'events': 296500, 'candidates': 601, 'errors': 0}
```

Exact status output:

```text
h20261018-211924-b1edf9  completed_within_scope   reportable_findings                      lanes={'context': 504, 'high': 11, 'lead': 79, 'urgent': 7} agent=budget_exhausted unworked=43 partial_pivots=0
```

The sweep therefore remained complete despite the investigator ending at its bounded case budget. The machine decision result remained `reportable_findings`.

Report command:

```text
ssh romulus-vm '/home/user/romulus-v2/venv/bin/romulus --env-file /home/user/romulus-v2/.env report h20261018-211924-b1edf9'
```

Real output:

```text
revision 1: 97 findings/leads, broken citations=0
  /home/user/romulus-v2/reports/h20261018-211924-b1edf9/h20261018-211924-b1edf9-r1.json
  /home/user/romulus-v2/reports/h20261018-211924-b1edf9/h20261018-211924-b1edf9-r1.md
```

### Investigation results from that hunt

- Seed population: 97 non-context candidates; 88 were assigned across 12 activated bounded cases and 9 remained unassigned under the case budget.
- Model calls: 52.
- Case states: 8 parked, 4 budget-exhausted.
- Pivot proposals: 13.
- Pivots actually executed: 2.
- Duplicate pivots blocked before source execution: 4.
- Partial pivots: 0; `pivot_gaps` is empty, so there are no partial covered/unresolved ranges to list for this run.
- Model-contributed candidates: 0.

Executed pivot coverage:

1. `process_tree`, case `case-1ce1a5ad48d6b2eb`, task `t-93d336b869344e8a9f74`: complete coverage `[2024-11-18T14:33:28.295000000Z, 2024-11-18T14:33:31.407000000Z)`, 5,058/5,058 source records retrieved, 2 matching process events retained. Two later normalized repeats were rejected without executing another source task.
2. `ids_alerts`, case `case-580688f629790a26`, task `t-08af4ccd1be9b02a82ad`: complete coverage `[2024-11-18T14:12:20.556317000Z, 2024-11-18T17:04:56.451367000Z)`, 969/969 source alert records retrieved and retained, with no cap. Its digest includes late-window activity through `2024-11-18T17:00:01.454003Z`. Two later normalized repeats were rejected without executing another source task.

This directly closes Fix 1's lab condition: `ids_alerts` for `192.42.1.174` completed without `cap:10000`. It also closes Fix 3's live condition: that request executed once, not eight times. Automated tests, run both locally and after deployment, prove Fix 2's capped splitting/covered-range path and Fix 4's partial-pivot state separation; the fresh hunt had no capped or partial pivot, so it did not exercise those two paths live.

At the case level, **yes**: `case-fddc19830be15d0c` was seeded with the `videoserver` root SSH candidate at `2024-11-18T15:16:59Z` (`b66e8e45c6ab8ca0ad38`) and later `videoserver` candidates for `/etc/shadow` at `15:19:35Z` (`b82f96f9a70e749a252a`) and iptables activity at 15:33/15:34 (`917aa2b19a09da979c44`, `9dc0c22f156c7b29d3f4`). It therefore reached the requested post-login host activity through its seed cluster. However, the model made 8 calls on that case, executed no pivot, produced no conclusion, and exhausted its case budget. Separately, no accepted pivot result contained a post-15:16 `videoserver` event (`VIDEOSERVER_AFTER_1516=[]`). The attacker-IP pivot did expose a 17:00 network alert, but the model did not use it to advance a host-side chain. This remains an explicit effectiveness gap.

All 43 unworked seeds are present in report revision 1. They consist of 34 seeds assigned to unfinished cases plus 9 seeds that could not be assigned within the 12-case budget.

Assigned but unfinished (34):

```text
10a8bbd8d68c059351be 1315bc0448282ad4617a 1670d64da368d3c43f78
19e0b7ebebe2210a934d 214c68076a299437a0ed 3447a2061b49dbc9dec3
366a4fa2680b888b97f0 3e62d1500300a1312a45 4968d97396256de1057b
5b93cf4c92b0f2a68c37 6c7fb438a6acb8bc48a7 7818b7fb808c2e605c16
80f7edbbf867d518bb7f 8d2dd21675ce09d14942 8f208930a89375687158
917aa2b19a09da979c44 92977842f8caa0c0fcd9 981a1c8f94c7cdc33725
9d7dcb2a1f54e23c5ed2 9dc0c22f156c7b29d3f4 9dc8cbea15e76d96f314
aec5bea254be5324a615 b17941b0c5c262e079ff b66e8e45c6ab8ca0ad38
b82f96f9a70e749a252a bc4e6e25d231e9ce2de2 c0925b5ac93cf9485ef4
c4afe5af8cf2395f4e27 d1a0b60ca171030ba948 d3e96bb88e25225ba1e3
e251baa7d4d95d04220b e4f794a7c4abcc7edb15 f11f2566752bd7f24a72
f9b6b2be96160f5fbee1
```

Unassigned (9):

```text
0b835f1f7737ab557818 3f94d841a893ecaad040 4828890f66801cc15dd7
625ae44a7176c3c73653 6576080cc8949e883806 925904e8433c040f34d7
c37e24fecb085ae6f294 daf61124ad38a69a9c41 dc2b86a214b3dc6f98c4
```

### Spec disagreements and remaining work

- No disagreement with the approved four-fix specification was necessary.
- The automated suite proves all four fixes; the fresh run additionally validates family-restricted alert retrieval and duplicate blocking against the lab. It does not live-exercise capped splitting or partial-pivot state separation because both executed pivots were complete. The local model still showed weak investigative effectiveness: it contributed no new candidate, did not act on the post-login `videoserver` evidence already present in a case, and left 43 seeds unworked under the approved 12-case and per-case budgets.
- M1's reviewer gate and owner demo remain open. Model prompt/tool-choice tuning belongs in the planned M2 bakeoff; I did not alter decision policy or budgets during this fix round to conceal the live result.
