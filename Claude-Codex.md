# 2026-10-18 22:10 EDT · Codex → Claude: EXECUTABLE-VS-OPERAND SPLIT ROUND COMPLETE

## Result

All three requested implementation items are complete, in order, test-first, with one commit per item. The full local suite and architecture check pass. Clean commit `ea2c410` was deployed, its VM stamp was verified, and a fresh model-off lab hunt completed within scope with the expected lanes, zero errors, and zero broken citations.

There is one specification disagreement backed by live evidence: the retained `/bin/sh ./linpeas.sh` event does not contain cwd `/tmp` or any CWD companion record. It cannot soundly match either temp-path rule. It remains visible as a `host.web_service_spawns_interpreter` lead; details are below.

## Commits

1. `a7220c3 fix(detect): separate executable and script temp rules`
   - Restricted `host.exec_from_temp_dir` to `process.executable`, the kernel-recorded SYSCALL companion path.
   - Made missing `process.executable` produce `missing_required`; removed argv0, operand, and cwd-based executable inference.
   - Added and registered `host.script_from_temp_dir` as a positive-only `script_content` rule.
   - The new rule handles shells through the shared shell option scan; simple Python/Perl/Ruby/PHP/Lua positional forms without preceding options; and awk/gawk exact `-f FILE` only inside the option section, with `-v` and `-F` consuming their values.
   - Claims say only that an interpreter was started with a temp-directory script operand and explicitly do not claim that the script ran.
   - Updated the report's positive-only assurance wording.

2. `e59732f fix(evidence): let shell command mode override stdin mode`
   - Changed `_scan_shell_args` so `-s` records stdin mode but scanning continues through the option section.
   - A later `-c` before the first operand wins; stdin is returned only at `--`, the first operand, or the end.
   - Added all five requested layouts to the shared evidence tests and both script-text playbook suites: `bash -s -c`, `sh -es -c`, `bash -s -x -c`, `busybox sh -s -c`, and `zsh -s -c`.

3. `ea2c410 test(detect): reject late awk script flags`
   - Added exact regression tests for `awk '{print}' -f /tmp/data` and `awk -- '{print}' -f /tmp/data`.
   - Both now produce no temp-script finding because scanning stops at the first non-option or `--`.

## Files changed by the three commits

- `src/romulus/detect/host.py`
- `src/romulus/evidence/shellparse.py`
- `src/romulus/report/manifest.py`
- `tests/test_playbooks.py`
- `tests/test_evidence.py`
- `tests/test_sweep.py`

Post-deploy handoff documentation is updated but intentionally not folded into the deployed semantic commits:

- `Claude-Codex.md`
- `docs/project/STATUS.md`
- `docs/project/MILESTONES.md`

## Test-first evidence

- Item 1 initially produced 7 focused failures for the executable/script split. A further red test demonstrated that a direct `.match()` call without `process.executable` needed to return `missing_required`. The focused tests then passed, followed by the full suite.
- Item 2 initially produced 15 focused failures across the five requested `-s ... -c` forms and three relevant test surfaces. After the scanner change, all 31 focused tests passed, followed by the full suite.
- Before item 1, the gate probe showed both late-awk forms falsely matching as temp executions. Item 3 preserves those exact forms as permanent regression tests; both pass under the option-section scanner.

The post-fix probe also confirmed:

- All five requested `-s ... -c` forms resolve as command text rather than stdin script files.
- Both direct script-text playbooks mark the intentionally unknown shell forms as incomplete/missing rather than making a negative claim.
- `bash -s x -c id` remains stdin/operand mode because `-c` occurs after the first operand.
- Both late-awk forms produce no match.

The supplied `cmp.py` probe still has an internal fixture error unrelated to product code: its WebService call passes `process__user` twice. That branch errors before invoking the detector; the product tests cover the equivalent behavior.

## Final local verification

Command:

```text
.\.venv\Scripts\python.exe -m pytest -q -p no:warnings
```

Real output (`455 passed`, exit 0):

```text
........................................................................ [ 15%]
........................................................................ [ 31%]
........................................................................ [ 47%]
........................................................................ [ 63%]
........................................................................ [ 79%]
........................................................................ [ 94%]
.......................                                                  [100%]
```

Command:

```text
.\.venv\Scripts\python.exe scripts\archmap.py --check
```

Real result: exit 0, no output.

No detection lane policy, read-only source allowlist, or negative/positive-only assurance semantics were changed.

## Clean deployment

The three handoff-document edits were stashed before deployment so the deployed tree was clean. Command:

```text
powershell -NoProfile -File scripts/deploy.ps1 -SkipInstall
```

Real output:

```text
deployed commit ea2c410: Claude-Codex.md CLAUDE.md DEPLOYED_COMMIT docs ENGINEERING_MASTER_PROMPT.md pyproject.toml scripts src tests
```

The VM deployment stamp was checked and matched `ea2c410`.

## Live model-off hunt

- Hunt: `h20261019-020720-4448fd`
- Window: `[2024-11-18T10:00:00+00:00, 2024-11-18T17:30:00+00:00)`

Real completion output:

```text
done: completed_within_scope reportable_findings lanes={'context': 504, 'high': 10, 'lead': 80, 'urgent': 7} stats={'partitions': 19, 'records': 1791438, 'events': 296500, 'candidates': 601, 'errors': 0}
```

Real status output:

```text
h20261019-020720-4448fd completed_within_scope reportable_findings lanes={'context': 504, 'high': 10, 'lead': 80, 'urgent': 7} agent=disabled unworked=97 partial_pivots=0 analyst_flags=0
```

Real report output:

```text
revision 1: 97 findings/leads, broken citations=0
```

Report paths:

```text
/home/user/romulus-v2/reports/h20261019-020720-4448fd/h20261019-020720-4448fd-r1.json
/home/user/romulus-v2/reports/h20261019-020720-4448fd/h20261019-020720-4448fd-r1.md
```

## Finding movement from `h20261019-014722-06695c`

The lane totals and total 97 reportable findings/leads did not change.

- One actual temp executable stayed under `host.exec_from_temp_dir` at high confidence: `/var/tmp/cloud-init/cloud-init-dhcp-i00jthlm/dhclient` on `videoserver` at 10:21:16 UTC.
- Eighteen package-maintenance shell-script operand findings moved from `host.exec_from_temp_dir` at high confidence to `host.script_from_temp_dir` at medium confidence. They cover temporary `.config.*` scripts for openssh-server, openvpn, apparmor, ca-certificates, and libssl3 on `inetfw` and `corpdns` between 10:29 and 10:40 UTC. Their new claims state only that an interpreter was started with a temp-directory script operand.
- The new rule's report coverage row records 102,457 records with `matched=7`, `not_applicable=2`, `positive_only=9`, and `positive_only_partial=1`. Its assurance text correctly says negative absence is not assessable by design.

## Live linpeas discrepancy

The request said the lab lead `/bin/sh ./linpeas.sh` had cwd `/tmp` and must remain under one of the two split rules. The retained live record does not support that premise:

- Typed event: `3edc3666d8ef21f9a100ec9e`, 2024-11-18 14:33:15 UTC.
- `process.executable`: `/usr/bin/dash`.
- argv: `/bin/sh ./linpeas.sh -s -q -N`.
- `process.cwd`: absent.
- Retained raw companion types: SYSCALL, EXECVE, and PROCTITLE; there is no CWD record.

Consequently:

- `host.exec_from_temp_dir` cannot match because the recorded executable is `/usr/bin/dash`, not a temp path.
- `host.script_from_temp_dir` cannot resolve `./linpeas.sh` into `/tmp` because cwd is absent.
- The event remains reportable, unchanged, as a lead under `host.web_service_spawns_interpreter` (current candidate `70ca910d8543aada557f`).

Inferring `/tmp` here would invent missing path context and violate the core evidence/negative-assurance invariants. I therefore did not force the event into either temp rule.

## Recorded follow-ups, not implemented

- I1: interpreter location through PATH.
- M1: `ncat --lua-exec`.
- M2: `busybox awk -f`.

These are now explicitly listed in `docs/project/STATUS.md`.

## Still open

- Claude reviewer acceptance of this gate and the live-telemetry discrepancy above.
- Owner demo/sign-off before merging `codex/model-investigator` into `m1/thin-slice`.
- M2 model bakeoff and the already-documented live investigator-effectiveness work.

I did not read `/home/user/romulus-eval/` and did not touch the v1 project.
