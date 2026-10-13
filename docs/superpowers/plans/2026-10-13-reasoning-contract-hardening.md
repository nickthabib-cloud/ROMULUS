# Structured Reasoning Contract Hardening Plan

> **Execution:** Follow `superpowers:systematic-debugging`, `superpowers:test-driven-development`, `superpowers:executing-plans`, and `superpowers:verification-before-completion`. Keep the Russell Mitchell oracle outside runtime code, prompts, and fixtures.

**Goal:** Make the evidence-grounded investigator/critic pair reliably produce admissible structured output without relaxing citation, ownership, causality, or finding gates.

**Observed failure:** The blind hunt made nine investigator calls and admitted none. Responses were either output-limited/incomplete or rejected because model-authored `proposal_id` values were not globally unique. The critic consequently never ran. The adapter also slices response content at 24,000 characters even when the configured structured output budget can legitimately exceed that boundary.

**Design:** Proposal IDs are deterministic ROMULUS bookkeeping, not model judgment. Remove them from the investigator schema and assign stable collection-scoped IDs after a complete structured object parses. A search for a newly emitted hypothesis uses a schema-enumerated positional reference (`NEW-HYPOTHESIS-N`), which ROMULUS resolves to its trusted assigned ID before critic review and deterministic admission; unknown positions remain unresolved and fail closed. Stream Ollama's NDJSON response so the configured read timeout detects stalled inference instead of rejecting a progressing long generation. Keep the investigator schema's conservative estimated character budget below 18,000 while preserving up to three new hypotheses and three searches per pass, then prove actual adequacy against the configured model. Parse the complete bounded response without slicing it, and continue to reject malformed stream events, premature EOF, data after terminal completion, provider-reported length truncation, or incomplete JSON. Skip the external critic only when the investigator proposed no work; an empty deterministic review is sufficient because there is nothing to approve.

## Task 1: Prove the contract failures

- [x] Add a failing adapter regression showing a complete valid structured response beyond 24,000 characters is currently self-truncated.
- [x] Add failing schema/adapter regressions proving the model should not author proposal IDs and ROMULUS assigns stable globally unique IDs across all proposal collections.
- [x] Add an adapter-to-admission regression proving a search can reference a newly emitted hypothesis without predicting ROMULUS's later bookkeeping ID.
- [x] Reproduce the configured model's non-streaming read timeout and streamed provider-cap truncation; add RED regressions for NDJSON assembly and a conservative schema-size estimate, with the configured-model probe remaining the decisive output test.
- [x] Preserve fail-closed tests for provider-reported length truncation and incomplete JSON.

## Task 2: Implement the narrow repair

- [x] Remove `proposal_id` from investigator-authored fields and instructions; deterministically assign IDs only after complete parsing.
- [x] Enumerate positional new-hypothesis search references in the schema and resolve them to trusted assigned IDs before critic review and admission.
- [x] Stream and assemble Ollama response chunks, require explicit terminal completion, fail closed on malformed/truncated streams, and reduce per-field/per-array verbosity without reducing the three-hypothesis/three-search analytic breadth.
- [x] Expand the structured context/output envelope and parse the entire bounded response without attempting to repair partial JSON.
- [x] Avoid a critic call for a genuinely empty proposal set while preserving investigator accounting and atomic admission for nonempty output.

## Task 3: Review and exact proof

- [x] Run focused reasoning, admission, scheduler-execution, reporting, and retention regressions plus the complete local suite, `compileall`, and `git diff --check`.
- [x] Complete fresh whole-diff review focused on hallucination resistance, ID determinism, truncation handling, critic coverage, and state/accounting behavior.
- [ ] Archive the exact candidate, match its digest on the VM, run the dependency-complete suite and configured `doctor`, then execute a generic synthetic investigator/critic contract probe against the configured model. Do not launch a hunt or use oracle facts.
- [ ] Record proof in `VALIDATION.md`, clean disposable artifacts, commit, push, and open a stacked PR against `codex/retrieval-contract-hardening`.

**Next milestone:** Improve generic candidate promotion and correlation/path construction only after the reasoning pair proves reliable. Retrieval and structured-contract changes remain isolated so later hunt results can be attributed honestly.
