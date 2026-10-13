# Retrieval Contract Hardening Implementation Plan

> **Execution:** Follow `superpowers:executing-plans`, `superpowers:systematic-debugging`, and `superpowers:test-driven-development`. Keep Russell Mitchell oracle details out of runtime code and committed fixtures.

**Goal:** Restore generic host discovery for mixed Elasticsearch indices and make configured PCAP validation identical in diagnostics and hunt execution.

**Root-cause hypotheses:** Elasticsearch mapping classification currently assigns each index to exactly one telemetry family; an index containing both endpoint and network fields can therefore expose its timestamp only to the network family and suppress all host discovery. PCAP diagnostics check only existence and allowlist membership, while runtime also requires the final suffix to equal `.pcap` or `.pcapng`; safe dataset-generated suffixes pass diagnostics and fail execution.

**Scope:** This milestone fixes only those two retrieval contracts. Candidate logic, model prompts/schemas, scheduler priority, source caps, and oracle-specific detections remain unchanged.

## Task 1: Prove and fix mixed-index field roles

- [ ] Add failing synthetic tests showing that one mapping with both endpoint and network semantic fields belongs to both families, including its timestamp field and index name.
- [ ] Replace exclusive mapping classification with deterministic multi-family membership while preserving pure host, pure network, and unclassified behavior.
- [ ] Run the focused mapping/inventory and scheduler tests.

## Task 2: Unify capture validation

- [ ] Add failing filesystem tests for existing allowlisted `.pcap`, `.pcapng`, and safe suffixed capture names, plus arbitrary-extension and outside-allowlist rejection.
- [ ] Introduce one validator used by both TShark runtime approval and `doctor`; retain canonical path resolution and no-shell execution.
- [ ] Run focused TShark, doctor, and representative-sampling tests.

## Task 3: Verify and publish

- [ ] Run the complete local suite, `compileall`, and `git diff --check`.
- [ ] Run a fresh review focused on cross-family duplication, timestamp safety, path validation, and diagnostic/runtime parity; allow one RED/GREEN correction pass for material findings.
- [ ] Archive the exact candidate, match its digest on the VM, run the dependency-complete suite and configured `doctor`, and confirm all configured captures pass the runtime validator without launching another hunt.
- [ ] Record proof in `VALIDATION.md`, remove exact disposable artifacts, commit, push, and open a stacked PR against `codex/blind-generalization-evaluation`.

**Next milestone:** Harden the structured investigator/critic contract and output-budget behavior separately, then improve generic candidate promotion/correlation. This keeps retrieval defects isolated from reasoning changes.
