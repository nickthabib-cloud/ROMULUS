# 2026-10-18 20:54 EDT · Codex → Claude: Final M1 parser results

## Outcome

All five requested items are implemented in order, test-first, with one commit per item. The final local suite and architecture check pass, the clean deployment stamp matched `HEAD`, and the requested model-off hunt completed within scope with the expected 7 urgent / 11 high result and zero errors or broken citations.

Claude’s `assures_negative` / `positive_only` semantics remain unchanged. I did not change detection-policy lanes, decision policy, or the read-only source allowlist. I did not read `/home/user/romulus-eval/` and did not touch v1.

## Commits

1. `5bcf13c fix(evidence): stop shell options at script file` — F6
2. `c9192f3 fix(evidence): recognize login shell argv names` — F7
3. `cf73582 fix(evidence): reject non-POSIX shell scripts` — F12
4. `a35b595 fix(detect): recover indicators from shell prefix` — prefix indicators
5. `0d500b6 test(sweep): assert shell coverage per rule` — F13
6. `72d0da0 docs: record final parser handoff` — committed your incoming task note so deployment used a clean, exact stamp.
7. `49ff068 docs: record final parser verification` — updated project status and milestone evidence after the live run; documentation-only and made after the tested deployment.

The commit containing this replacement handoff follows `49ff068` on `codex/model-investigator`.

## Implementation details

### 1. F6: shell option scanning stops at the script file

`src/romulus/evidence/shellparse.py` now scans shell options only until the first positional script argument. It consumes the value belonging to options such as `-o`, `+o`, `-O`, `+O`, `--init-file`, and `--rcfile`, so `bash -o pipefail -c S` remains conservatively unknown while `bash /tmp/x.sh -c` and `bash /tmp/x.sh -recursive` are correctly classified as script-file invocations with no `-c` script.

The exact direct forms `shell -c SCRIPT` and `shell -lc SCRIPT` remain the only mapped `-c` layouts. A candidate script beginning with either `-` or `+` is explicit `UnknownShellScript`. Fixtures cover:

- `bash -c -- S`
- `bash -o pipefail -c S`
- `bash -c +e S`
- `sh -c +e S`
- `bash -lc +e S`

`host.exec_from_temp_dir` now finds `/tmp/x.sh` for both supplied trailing-option-shaped argvs instead of treating them as unknown `-c` layouts.

### 2. F7: login-shell argv names

`shell_script_of()` strips exactly one leading `-` from the basename of `argv[0]` before the shell lookup. `-bash` and `-sh` therefore map their direct `-c` script exactly like `bash` and `sh`; a second leading dash is not silently stripped.

### 3. F12: non-POSIX shell grammar

The shell catalog is split into:

- POSIX-modelled names: `sh`, `bash`, `dash`, `ash`, `busybox`
- explicitly non-modelled names: `zsh`, `ksh`, `fish`, `csh`, `tcsh`

A `-c` request for any non-modelled shell returns `UnknownShellScript` with a shell-grammar reason. It is never parsed using the POSIX/bash allow-list.

### 4. Positive indicators from a clean partial prefix

The lexer now attaches the already completed tokens to `_Unmodelled` when it reaches the first unsupported construct. `ParsedScript` exposes `partial=True`; `parse_script()` parses only those completed tokens and retains only commands that are cleanly established before the cut. It never tokenizes or interprets text after the first unsupported construct.

The web-service interpreter rule may evaluate positive indicators over that retained prefix. If it publishes a match from a partial script, it:

- increments `missing_required` to preserve uncertainty;
- adds `script indicator evaluated from clean prefix only; remainder was not modelled`; and
- uses only indicators wholly supported by prefix commands.

The ZoneMinder-shaped fixture contains the application helper and encoded `echo` pipeline before the unmodelled `$(which python …)` substitution. It returns high with:

- `indicator: additional commands chained after application helper 'zmu'`
- `indicator: encoded payload text piped/echoed into another command`
- the explicit clean-prefix-only note.

A separate hostile fixture begins an unclosed construct before chaining-looking text. It produces no immediate indicator match; the text after the cut is not read, and the event remains only a rarity lead.

This is positive-only behavior. `host.download_piped_to_shell` and the script form of `host.ssh_authorized_keys_write` still require `parsed.ok`; neither uses `ParsedScript.partial` to make a script-content match or a negative claim. Their coverage remains `positive_only` regardless of retained prefixes.

### 5. F13: per-rule sweep assertions

The adversarial sweep matrix no longer collapses both states into a set. It independently asserts that each of these cells is not `no_match_complete`:

- `host.download_piped_to_shell`
- `host.ssh_authorized_keys_write`

This catches a regression in either rule even if the other rule remains positive-only or matched.

## Files changed

- `src/romulus/evidence/shellparse.py`
- `src/romulus/detect/host.py`
- `tests/test_evidence.py`
- `tests/test_playbooks.py`
- `tests/test_sweep.py`
- `docs/project/STATUS.md`
- `docs/project/MILESTONES.md`
- `Claude-Codex.md`

No architecture-layer rule changed, so `docs/architecture/ARCHITECTURE.md` did not require modification.

## Test-first evidence

F6 red run:

```text
.\.venv\Scripts\python -m pytest -q -p no:warnings tests/test_evidence.py tests/test_playbooks.py -k "option_scan or ambiguous_shell_command"
FF.....FFFFF                                                             [100%]
7 failed, 5 passed
```

The failures were the two script-file layouts being returned as `UnknownShellScript`, the three `+e` layouts being returned as strings, and both temp-directory matches being suppressed. After implementation:

```text
............                                                             [100%]
```

F7 red/green:

```text
# before
FF                                                                       [100%]
# after
..                                                                       [100%]
```

F12 red/green:

```text
# before: zsh, ksh, fish, csh, tcsh
FFFFF                                                                    [100%]
# after
.....                                                                    [100%]
```

Prefix-indicator red/green:

```text
# before
FF.                                                                      [100%]
# after
...                                                                      [100%]
```

The two red failures were the absent `ParsedScript.partial` prefix and the missing high match. The hostile post-cut test was already negative and remains a regression guard against reading past the cut.

Strengthened F13 matrix:

```text
.\.venv\Scripts\python -m pytest -q -p no:warnings tests/test_sweep.py -k adversarial_shell_construct
...................                                                      [100%]
```

## Final local verification

Exact project command:

```text
.\.venv\Scripts\python -m pytest -q -p no:warnings
........................................................................ [ 20%]
........................................................................ [ 41%]
........................................................................ [ 62%]
........................................................................ [ 83%]
..........................................................               [100%]
```

Exit code was 0. A separate collection pass reported:

```text
346 tests collected in 0.58s
```

Architecture gate:

```text
.\.venv\Scripts\python scripts/archmap.py --check
```

Exit code was 0 with no output.

## Deployment and live run

Deployment command and real output:

```text
powershell -File scripts/deploy.ps1 -SkipInstall
deployed commit 72d0da0: Claude-Codex.md CLAUDE.md DEPLOYED_COMMIT docs ENGINEERING_MASTER_PROMPT.md pyproject.toml scripts src tests
```

`cat /home/user/romulus-v2/app/DEPLOYED_COMMIT` returned `72d0da0`, exactly matching clean local `HEAD` at deployment time.

Hunt command:

```text
/home/user/romulus-v2/venv/bin/romulus --env-file /home/user/romulus-v2/.env hunt start \
  --start 2024-11-18T10:00:00Z --end 2024-11-18T17:30:00Z --no-agent
```

Real completion output:

```text
hunt h20261019-005148-03348c created [2024-11-18T10:00:00+00:00, 2024-11-18T17:30:00+00:00)
done: completed_within_scope reportable_findings lanes={'context': 504, 'high': 11, 'lead': 79, 'urgent': 7} stats={'partitions': 19, 'records': 1791438, 'events': 296500, 'candidates': 601, 'errors': 0}
```

Persisted status and report:

```text
h20261019-005148-03348c  completed_within_scope   reportable_findings                      lanes={'context': 504, 'high': 11, 'lead': 79, 'urgent': 7} agent=disabled unworked=97 partial_pivots=0 analyst_flags=0
revision 1: 97 findings/leads, broken citations=0
  /home/user/romulus-v2/reports/h20261019-005148-03348c/h20261019-005148-03348c-r1.json
  /home/user/romulus-v2/reports/h20261019-005148-03348c/h20261019-005148-03348c-r1.md
```

Manifest integrity:

```json
{
  "broken_citations": 0,
  "broken_investigation_citations": 0,
  "broken_investigation_event_ids": [],
  "finalizable": true
}
```

Both script-text rules preserved Claude’s positive-only semantics:

```json
{
  "rule_id": "host.download_piped_to_shell",
  "negative_claim": "not assessable by design: positive-only rule (script text can show intent but cannot prove that something did not run; see the process-level rules)",
  "records_evaluated": 102457,
  "states": {"not_applicable_no_events": 2, "positive_only": 17}
}
{
  "rule_id": "host.ssh_authorized_keys_write",
  "negative_claim": "not assessable by design: positive-only rule (script text can show intent but cannot prove that something did not run; see the process-level rules)",
  "records_evaluated": 102457,
  "states": {"not_applicable_no_events": 2, "positive_only": 17}
}
```

Recovered exploit finding `3858700981c65ea93bb5` is high with three retained citations and these notes:

```text
indicator: additional commands chained after application helper 'zmu'
indicator: encoded payload text piped/echoed into another command
script indicator evaluated from clean prefix only; remainder was not modelled
```

The two mandatory process-level urgent findings remain:

- `host.downloader_feeds_interpreter` for `http://192.42.1.174/TODO.md`: 8 paired occurrences, 48 retained citations.
- `host.downloader_feeds_interpreter` for `http://192.42.1.174/README.txt.1`: one paired occurrence, 6 retained citations.

No lane count differed from the expected 7 urgent / 11 high / 79 lead / 504 context.

## Spec disagreements and open work

- Spec disagreements: none.
- Open from this round: no implementation item. Claude should run the final M1 gate.
- I ran the requested model-off hunt only; I did not claim a new model-enabled integration run.
