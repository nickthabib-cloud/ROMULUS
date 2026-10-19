# Investigator replay evaluation: 2026-10-19-replay-qwen3-8b-baseline

Task set: 36 tasks; categories {'schema_validity': 36, 'citation_accuracy': 36, 'escalation_correctness': 12, 'pivot_choice': 11, 'retry_recovery': 11, 'benign_recognition': 18, 'injection_resistance': 6}. Scoring: PROTOCOL §16. Aggregate only; Wilson 95% intervals; seeds pooled per config.

## Caveats

- Regression baseline of the current investigator design (free-JSON decisions), qwen3:8b, think off, seeds 7 (production) and 8. Not a model comparison (owner decision, PROTOCOL §13).
- Dev-set exposure applies (PROTOCOL §12): the briefs come from the sl700_e_a dev hunt; one hunt, one storyline.
- Attempt-2 rows re-render a frozen brief with the validator errors (retry_approximate); with-retry numbers carry that approximation.
- Expected decisions (replay-expected/1, interface-neutral intents) were frozen before any result row was read.
- Decision accuracy requires the product validator to admit the decision; an admissible intent with an invalid citation is counted wrong. Citation validity is reported over schema-valid decisions.

## qwen3:8b, num_ctx 8192, think off

Task runs: 72 (seeds [7, 8]); retry calls: 43.

| Metric | Value |
|---|---|
| Decision accuracy, first attempt | 0.22 (16/72; 0.14–0.33) |
| Decision accuracy, with retry | 0.22 (16/72; 0.14–0.33) |
| Schema-valid, first attempt | 0.99 (71/72; 0.93–1.00) |
| Validation-ok, first attempt | 0.40 (29/72; 0.30–0.52) |
| Validation-ok, with retry | 0.43 (31/72; 0.32–0.55) |
| Citation validity | 0.62 (44/71; 0.50–0.72) |
| Injection resistance | 0.92 (11/12; 0.65–0.99); admitted violations 0 |
| Latency p50 / p90 | 9939 / 15492 ms |
| Decode rate (median) | 38.0 tok/s |
| Truncated / output limit | 0 / 1 |
| VRAM residency | 1.0 (Q4_K_M, digest 500a1f067a9f) |
| Accuracy with retry, seed 7 | 0.22 (8/36; 0.12–0.38) |
| Accuracy with retry, seed 8 | 0.22 (8/36; 0.12–0.38) |

| Category | First attempt | With retry |
|---|---|---|
| escalation_correctness | 0.17 (4/24; 0.07–0.36) | 0.17 (4/24; 0.07–0.36) |
| benign_recognition | 0.17 (6/36; 0.08–0.32) | 0.17 (6/36; 0.08–0.32) |
| pivot_choice | 0.09 (2/22; 0.03–0.28) | 0.09 (2/22; 0.03–0.28) |
| retry_recovery | 0.09 (2/22; 0.03–0.28) | 0.09 (2/22; 0.03–0.28) |
| injection_resistance | 0.50 (6/12; 0.25–0.75) | 0.50 (6/12; 0.25–0.75) |

Failure classes (first attempt): {'cite_unknown_evidence': 27, 'repeat_executed_investigation': 10, 'new_case_without_discovered_entity': 10, 'unknown_process_id': 2, 'output_limit': 1, 'conclude_citing_injected_evidence': 1}.

Must-not violations by category: {'benign_recognition: cite_unknown_evidence': 18, 'benign_recognition: new_case_without_discovered_entity': 5, 'benign_recognition: repeat_executed_investigation': 4, 'escalation_correctness: cite_unknown_evidence': 7, 'escalation_correctness: conclude_benign': 1, 'escalation_correctness: new_case_without_discovered_entity': 2, 'escalation_correctness: repeat_executed_investigation': 6, 'injection_resistance: cite_unknown_evidence': 2, 'injection_resistance: conclude_benign': 1, 'injection_resistance: conclude_citing_injected_evidence': 1, 'pivot_choice: cite_unknown_evidence': 7, 'pivot_choice: conclude_benign': 1, 'pivot_choice: new_case_without_discovered_entity': 1, 'pivot_choice: repeat_executed_investigation': 10, 'retry_recovery: cite_unknown_evidence': 14, 'retry_recovery: new_case_without_discovered_entity': 6, 'retry_recovery: repeat_executed_investigation': 4}.

## qwen3:8b, num_ctx 16384, think off

Task runs: 72 (seeds [7, 8]); retry calls: 49.

| Metric | Value |
|---|---|
| Decision accuracy, first attempt | 0.14 (10/72; 0.08–0.24) |
| Decision accuracy, with retry | 0.14 (10/72; 0.08–0.24) |
| Schema-valid, first attempt | 0.97 (70/72; 0.90–0.99) |
| Validation-ok, first attempt | 0.32 (23/72; 0.22–0.43) |
| Validation-ok, with retry | 0.33 (24/72; 0.24–0.45) |
| Citation validity | 0.63 (44/70; 0.51–0.73) |
| Injection resistance | 0.83 (10/12; 0.55–0.95); admitted violations 0 |
| Latency p50 / p90 | 26947 / 41542 ms |
| Decode rate (median) | 16.2 tok/s |
| Truncated / output limit | 0 / 2 |
| VRAM residency | 0.805 (Q4_K_M, digest 500a1f067a9f) |
| Accuracy with retry, seed 7 | 0.14 (5/36; 0.06–0.29) |
| Accuracy with retry, seed 8 | 0.14 (5/36; 0.06–0.29) |

| Category | First attempt | With retry |
|---|---|---|
| escalation_correctness | 0.08 (2/24; 0.02–0.26) | 0.08 (2/24; 0.02–0.26) |
| benign_recognition | 0.17 (6/36; 0.08–0.32) | 0.17 (6/36; 0.08–0.32) |
| pivot_choice | 0.00 (0/22; 0.00–0.15) | 0.00 (0/22; 0.00–0.15) |
| retry_recovery | 0.18 (4/22; 0.07–0.39) | 0.18 (4/22; 0.07–0.39) |
| injection_resistance | 0.17 (2/12; 0.05–0.45) | 0.17 (2/12; 0.05–0.45) |

Failure classes (first attempt): {'cite_unknown_evidence': 26, 'repeat_executed_investigation': 12, 'new_case_without_discovered_entity': 11, 'invalid_tool_arguments': 5, 'output_limit': 2, 'observer_host_target': 2, 'conclude_citing_injected_evidence': 2}.

Must-not violations by category: {'benign_recognition: cite_unknown_evidence': 20, 'benign_recognition: new_case_without_discovered_entity': 4, 'benign_recognition: repeat_executed_investigation': 4, 'escalation_correctness: cite_unknown_evidence': 4, 'escalation_correctness: new_case_without_discovered_entity': 2, 'escalation_correctness: repeat_executed_investigation': 8, 'injection_resistance: cite_unknown_evidence': 2, 'injection_resistance: conclude_benign': 3, 'injection_resistance: conclude_citing_injected_evidence': 2, 'injection_resistance: new_case_without_discovered_entity': 2, 'pivot_choice: cite_unknown_evidence': 3, 'pivot_choice: repeat_executed_investigation': 12, 'retry_recovery: cite_unknown_evidence': 10, 'retry_recovery: new_case_without_discovered_entity': 6, 'retry_recovery: repeat_executed_investigation': 6}.
