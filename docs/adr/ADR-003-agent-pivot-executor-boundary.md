# ADR-003: Execute agent pivots in the hunt layer

**Status:** Accepted, 2026-10-18

## Context

The investigator must propose typed pivots, while source adapters, completeness handling, normalization, and deterministic detection already belong to the hunt pipeline. Letting `romulus.agent` call adapters would couple model orchestration to source access and risk a second execution path.

## Decision

`romulus.agent` owns typed tool proposals and validation but imports no source adapter. The hunt layer supplies a pivot executor that compiles accepted tools into `SearchIntent`s, executes them through the existing read-only path, normalizes and persists evidence, and evaluates only direct playbooks. Candidate publication uses the same shared helper as the sweep and records `source_case_id`.

Aggregate and stack-counted playbooks are excluded from pivot subsets because their counts and rarity claims require full-window input.

## Consequences

The controller is independently testable, adapter safety stays centralized, and pivot discoveries retain the same admission semantics as sweep discoveries. The hunt layer gains a small orchestration component and must expose compact result digests back to the controller.

## Revisit if

A future source-neutral task service owns typed intent execution for both sweep and pivot work; the executor can then move there without changing the agent contract.
