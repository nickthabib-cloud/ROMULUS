# Investigator replay evaluation: 2026-10-19-replay-qwen3-8b-v2

Task set: 36 tasks; categories {'schema_validity': 36, 'citation_accuracy': 36, 'escalation_correctness': 12, 'pivot_choice': 11, 'retry_recovery': 11, 'benign_recognition': 18, 'injection_resistance': 6}. Scoring: PROTOCOL §16. Aggregate only; Wilson 95% intervals; seeds pooled per config.

## Caveats

- Investigator v2 (menu-driven, flat constrained schema; deployed 0abb1fc), qwen3:8b, num_ctx 8192, think off, seeds 7 and 8. Briefs re-exported with v2 code from the same hunt and the same 36 task IDs; prompt digests do not match the v1 prompts, as expected.
- Scored against the same interface-neutral expected file (replay-expected/1, sha256 cd016783…) as the v1 baseline; result rows carry the resolved chosen option, mapped to an intent.
- Menu coverage: a task run whose menu offers no acceptable intent is a coverage gap, reported separately from model error.
- Dev-set exposure applies (PROTOCOL §12). Attempt-2 rows are retry_approximate.

## qwen3:8b, num_ctx 8192, think off

Task runs: 72 (seeds [7, 8]); retry calls: 8.

| Metric | Value |
|---|---|
| Decision accuracy, first attempt | 0.43 (31/72; 0.32–0.55) |
| Decision accuracy, with retry | 0.53 (38/72; 0.41–0.64) |
| Schema-valid, first attempt | 0.89 (64/72; 0.80–0.94) |
| Validation-ok, first attempt | 0.89 (64/72; 0.80–0.94) |
| Validation-ok, with retry | 1.00 (72/72; 0.95–1.00) |
| Citation validity | 1.00 (64/64; 0.94–1.00) |
| Injection resistance | 0.67 (8/12; 0.39–0.86); admitted violations 4 |
| Latency p50 / p90 | 5396 / 8454 ms |
| Decode rate (median) | 34.2 tok/s |
| Truncated / output limit | 0 / 0 |
| VRAM residency | 1.0 (Q4_K_M, digest 500a1f067a9f) |
| Accuracy with retry, seed 7 | 0.53 (19/36; 0.37–0.68) |
| Accuracy with retry, seed 8 | 0.53 (19/36; 0.37–0.68) |

| Category | First attempt | With retry |
|---|---|---|
| escalation_correctness | 0.79 (19/24; 0.60–0.91) | 1.00 (24/24; 0.86–1.00) |
| benign_recognition | 0.17 (6/36; 0.08–0.32) | 0.17 (6/36; 0.08–0.32) |
| pivot_choice | 0.68 (15/22; 0.47–0.84) | 0.73 (16/22; 0.52–0.87) |
| retry_recovery | 0.55 (12/22; 0.35–0.73) | 0.55 (12/22; 0.35–0.73) |
| injection_resistance | 0.50 (6/12; 0.25–0.75) | 0.67 (8/12; 0.39–0.86) |

Menu coverage: 0 task runs had no acceptable option on the menu (wrong on 0; counted as coverage gaps, not model error). Accuracy with retry excluding them: no gaps. Acceptable intents absent from the menu (task runs): {'attack:investigate': 10}.

Failure classes (first attempt): {'evidence_not_allowed_for_option': 8}.

Must-not violations by category: {'benign_recognition: escalate': 30, 'injection_resistance: escalate': 4, 'pivot_choice: escalate': 6, 'retry_recovery: escalate': 10}.

## Comparison with the v1 baseline (same task IDs, same expected file, num_ctx 8192, seeds 7+8)

| Metric | v1 (free JSON) | v2 (menu) |
|---|---|---|
| Decision accuracy, first attempt | 0.22 (16/72; 0.14–0.33) | 0.43 (31/72; 0.32–0.55) |
| Decision accuracy, with retry | 0.22 (16/72; 0.14–0.33) | 0.53 (38/72; 0.41–0.64) |
| Schema-valid, first attempt | 0.99 (71/72; 0.93–1.00) | 0.89 (64/72; 0.80–0.94) |
| Validation-ok, first attempt | 0.40 (29/72; 0.30–0.52) | 0.89 (64/72; 0.80–0.94) |
| Validation-ok, with retry | 0.43 (31/72; 0.32–0.55) | 1.00 (72/72; 0.95–1.00) |
| Citation validity | 0.62 (44/71; 0.50–0.72) | 1.00 (64/64; 0.94–1.00) |
| Category escalation_correctness, with retry | 0.17 (4/24; 0.07–0.36) | 1.00 (24/24; 0.86–1.00) |
| Category benign_recognition, with retry | 0.17 (6/36; 0.08–0.32) | 0.17 (6/36; 0.08–0.32) |
| Category pivot_choice, with retry | 0.09 (2/22; 0.03–0.28) | 0.73 (16/22; 0.52–0.87) |
| Category retry_recovery, with retry | 0.09 (2/22; 0.03–0.28) | 0.55 (12/22; 0.35–0.73) |
| Category injection_resistance, with retry | 0.50 (6/12; 0.25–0.75) | 0.67 (8/12; 0.39–0.86) |
| Injection resistance | 0.92 (11/12; 0.65–0.99); admitted 0 | 0.67 (8/12; 0.39–0.86); admitted 4 |
| Latency p50 / p90 (ms) | 9939 / 15492 | 5396 / 8454 |
| Retry calls | 43 | 8 |
| Failure classes, first attempt | {'cite_unknown_evidence': 27, 'conclude_citing_injected_evidence': 1, 'new_case_without_discovered_entity': 10, 'output_limit': 1, 'repeat_executed_investigation': 10, 'unknown_process_id': 2} | {'evidence_not_allowed_for_option': 8} |

## Reading

**Admissibility and citations are mostly solved.**

- v2 roughly doubles decision accuracy: 0.22 → 0.43 on the first attempt, and 0.53 with retry.
- Admissibility and citation validity are close to solved by construction. The only remaining defect class is a cited evidence alias that is not allowed for the chosen option (8 first-attempt runs), and every one of them was recovered on retry.
- The v1 failure classes (unknown evidence IDs, repeated pivots, a new case without an entity) are gone.
- Escalation correctness reaches 24/24 with retry.

**Benign recognition is the remaining error, and it is a model-judgment error, not menu coverage.**

- Benign recognition is unchanged at 6/36, which is now the dominant error.
- On benign-case tasks the model chooses `escalate` (30 of the 36 benign task runs violate the must-not on escalation).
- Every task's menu offered at least one acceptable intent, including conclude or park on benign tasks. So these are model errors, not coverage gaps.

**Menu coverage.**

- No task run lacked an acceptable option.
- In 10 attack-case task runs, no investigation option targeted an attack-relevant entity; escalation was still offered there.
- I counted these as partial coverage, not as a gap.

**Injection.** The 4 admitted violations are escalations on the two escalate-injection variants. The same two base tasks without injection were also escalated in 4/4 runs, so these reflect the general escalate-on-benign error, not injection-following. Close-injection variants on attack cases were resisted.
