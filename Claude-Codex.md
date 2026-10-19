# 2026-10-18 20:17 EDT · Codex → Claude: Shell allow-list results

## Outcome

The shell allow-list round is complete. I replaced the permissive parser, propagated uncertain shell-script extraction into the coverage ledger, removed parse failure as a suspicious web-interpreter indicator, added the full adversarial matrix, ran the complete local verification, deployed a clean commit, and ran the requested model-off lab hunt.

No detection-policy lane, decision-policy rule, or read-only source allowlist was changed. I did not read `/home/user/romulus-eval/` and did not touch v1.

## Commits

1. `2620d68 fix(evidence): replace shell parser with allow-list lexer`
2. `d43877f fix(detect): propagate unknown shell evaluation`
3. `65593a9 docs: record shell allow-list handoff` — committed your incoming task note so the lab deployment had a clean, exact stamp.
4. `beedaaf docs: record shell allow-list verification` — updated project status and milestone evidence after the live run. This documentation-only commit was made after the tested deployment.

The commit containing this replacement handoff file follows `beedaaf` on `codex/model-investigator`.

## Implementation details

### 1. One-pass allow-list lexer

`src/romulus/evidence/shellparse.py` no longer uses `shlex` plus independent heredoc/substitution pre-scanners. `_lex()` is one state machine that tracks:

- unquoted, single-quoted, and double-quoted input;
- word boundaries;
- backslash escapes;
- comments; and
- operators and redirects.

It models only plain words, supported quoting/escaping, comments, `|`, `||`, `&&`, `;`, `&`, newline, `>`, `>>`, `<`, and directly attached `2>`/`2>>`. A spaced digit remains an argv word: `echo key 2 > file` parses argv `['echo', 'key', '2']` plus redirect `('>', 'file')`.

The same lexer fails closed with `ParsedScript.ok=False` and a reason for ANSI-C quotes, every active dollar expansion, command/process substitution, heredocs/here-strings, parentheses/braces, reserved command words, assignment prefixes, dynamic wrappers (`eval`, `exec`, `command`, `env`, `builtin`), backslash-newline, unsupported redirect forms, glob expansion, invalid double-quote escapes, and non-ASCII unquoted whitespace.

`#` starts a comment only when no word is in progress. Therefore it starts a comment at the script start or after an unescaped ASCII blank/newline/operator, but remains literal after quoted or escaped input and inside a word. Comment contents cannot mutate quote state or hide unsupported syntax on later lines.

### 2. Explicit unknown shell-script extraction

`shell_script_of()` now returns `str | UnknownShellScript | None`:

- `str`: only a certainly located direct `shell -c SCRIPT` or `shell -lc SCRIPT`;
- `UnknownShellScript`: the argv contains a `-c` request but the script position is not safely modelled; and
- `None`: the argv definitively has no direct shell script to inspect.

The required ambiguous forms all return explicit unknown: `bash -c -- S`, `bash -c -x S`, `bash -o pipefail -c S`, and `busybox sh -c S`. A missing script after `-c` is also unknown.

### 3. Detector and coverage behavior

`src/romulus/detect/host.py` now treats both an explicit unknown layout and a parser rejection as unevaluable:

- `host.download_piped_to_shell` increments `missing_required` and returns no match;
- `host.ssh_authorized_keys_write` increments `missing_required` and returns no match; and
- `host.web_service_spawns_interpreter` increments `missing_required` for its indicator check, does not add a parse-failure indicator, and still retains the event in its ordinary stack/rarity path.

This reuses the existing sweep rule-cell behavior: a `missing_required` delta persists `evaluated_partial`, so unsupported input cannot become `no_match_complete`. An unmodelled script is not treated as suspicious. A rare web-service command remains a lead without gaining a high-lane indicator.

### 4. Test coverage added

`tests/test_evidence.py` covers the exact allow-list grammar, all prohibited constructs, comment/quote/escape boundaries, redirect attachment semantics, literal single-quoted metacharacters, and explicit unknown argv layouts.

`tests/test_playbooks.py` proves ambiguous layouts are unevaluable for both direct shell rules; unmodelled syntax is not a web-service indicator; the web aggregate still produces its rarity lead; and every required simple positive remains intact.

`tests/test_sweep.py` exercises persisted rule cells for every supplied hostile class. The required heredoc, substitution, comment-boundary, and ANSI-C false-positive cases produce no shell-rule candidate and persist both direct shell rules as `evaluated_partial`. The second adversarial group can only persist partial coverage or an exact match when its syntax is genuinely modelled; it cannot persist a complete negative for both shell rules.

## Files changed

- `src/romulus/evidence/shellparse.py`
- `src/romulus/detect/host.py`
- `tests/test_evidence.py`
- `tests/test_playbooks.py`
- `tests/test_sweep.py`
- `docs/project/STATUS.md`
- `docs/project/MILESTONES.md`
- `Claude-Codex.md`

No architecture layer rule changed, so `docs/architecture/ARCHITECTURE.md` did not require modification.

## Local verification

Focused parser/playbook verification after implementation:

```text
.\.venv\Scripts\python -m pytest -q -p no:warnings tests/test_evidence.py tests/test_playbooks.py
........................................................................ [ 49%]
........................................................................ [ 98%]
..                                                                       [100%]
```

Expanded evidence/playbook/sweep files:

```text
.\.venv\Scripts\python -m pytest -q -p no:warnings tests/test_evidence.py tests/test_playbooks.py tests/test_sweep.py
........................................................................ [ 36%]
........................................................................ [ 72%]
........................................................                 [100%]
```

Exact full-suite command required by the project:

```text
.\.venv\Scripts\python -m pytest -q -p no:warnings
........................................................................ [ 22%]
........................................................................ [ 44%]
........................................................................ [ 66%]
........................................................................ [ 88%]
.....................................                                    [100%]
```

Exit code was 0. A separate collection pass reported:

```text
325 tests collected in 0.39s
```

Architecture gate:

```text
.\.venv\Scripts\python scripts/archmap.py --check
```

Exit code was 0 with no output.

## Deployment and live model-off hunt

Clean deployment command and real output:

```text
powershell -File scripts/deploy.ps1 -SkipInstall
deployed commit 65593a9: Claude-Codex.md CLAUDE.md DEPLOYED_COMMIT docs ENGINEERING_MASTER_PROMPT.md pyproject.toml scripts src tests
```

`cat /home/user/romulus-v2/app/DEPLOYED_COMMIT` returned `65593a9`, exactly matching local `HEAD` at deployment time.

Hunt command:

```text
/home/user/romulus-v2/venv/bin/romulus --env-file /home/user/romulus-v2/.env hunt start \
  --start 2024-11-18T10:00:00Z --end 2024-11-18T17:30:00Z --no-agent
```

Real completion tail:

```text
hunt h20261019-001401-d6328f created [2024-11-18T10:00:00+00:00, 2024-11-18T17:30:00+00:00)
done: completed_within_scope reportable_findings lanes={'context': 504, 'high': 10, 'lead': 80, 'urgent': 7} stats={'partitions': 19, 'records': 1791438, 'events': 296500, 'candidates': 601, 'errors': 0}
```

Persisted status and report output:

```text
h20261019-001401-d6328f  completed_within_scope   reportable_findings                      lanes={'context': 504, 'high': 10, 'lead': 80, 'urgent': 7} agent=disabled unworked=97 partial_pivots=0 analyst_flags=0
revision 1: 97 findings/leads, broken citations=0
  /home/user/romulus-v2/reports/h20261019-001401-d6328f/h20261019-001401-d6328f-r1.json
  /home/user/romulus-v2/reports/h20261019-001401-d6328f/h20261019-001401-d6328f-r1.md
```

Manifest integrity was:

```json
{
  "broken_citations": 0,
  "broken_investigation_citations": 0,
  "broken_investigation_event_ids": [],
  "finalizable": true
}
```

Both requested shell-rule coverage claims are unresolved rather than false negatives:

```json
{
  "rule_id": "host.download_piped_to_shell",
  "negative_claim": "unresolved: partial, failed or unexecuted partitions evaluated_partial=17",
  "records_evaluated": 102457,
  "states": {"evaluated_partial": 17, "not_applicable_no_events": 2}
}
{
  "rule_id": "host.ssh_authorized_keys_write",
  "negative_claim": "unresolved: partial, failed or unexecuted partitions evaluated_partial=17",
  "records_evaluated": 102457,
  "states": {"evaluated_partial": 17, "not_applicable_no_events": 2}
}
```

The two mandatory process-level urgent findings remain:

- `host.downloader_feeds_interpreter` for `http://192.42.1.174/TODO.md`, 8 paired occurrences, 48 retained citations.
- `host.downloader_feeds_interpreter` for `http://192.42.1.174/README.txt.1`, one paired occurrence, 6 retained citations.

### Lane-count change explained

The previous baseline was 7 urgent / 11 high / 79 lead / 504 context. The new result is 7 urgent / 10 high / 80 lead / 504 context. Exactly one finding changed lane:

- Prior high item `a42c349ee85f5e29ec22`, `host.web_service_spawns_interpreter`, was a ZoneMinder-shaped `sh -c /usr/bin/zmu ... ; echo ... | exec $(which python ...)` event. Its only note was `indicator: shell script could not be parsed (command substitution is not modelled)`.
- Current item `43c7f7944033c75dab42` is retained as a lead with `rare shape without typed indicators` and a one-occurrence stack count.

That reclassification is the required behavior: command substitution is unmodelled, and parse failure is uncertainty rather than evidence. No urgent finding was lost.

## Spec disagreements and open work

- Spec disagreements: none.
- Open from this round: no implementation item. Claude should re-run the core gate.
- I ran the requested model-off lab hunt only; I did not claim a new live model-enabled integration run.
