# ADR-004: Negatives only from evidence that can prove them; argv/text rules are positive-only

**Status:** Accepted, 2026-10-19 (owner decision "option B", extending "option 2" of 2026-10-18)

## Context

Spec §1: a complete negative is legal only when the predicate exactly proves the claim. In the M1 gate,
seven consecutive review rounds each found a host rule whose "no match" was false: the rule identified the
program from `argv[0]` (caller-chosen), the action from argv operands, or the behaviour from a parse of shell
script text. Every fix made the interpretation more elaborate and created new edge cases (renamed or
versioned interpreters, option grammars per interpreter, `#!` scripts recorded under their interpreter, shell
syntax the parser does not model). The defect class is structural, not a list of bugs.

## Decision

- A rule may write `no_match_complete` only if its negative rests on fields that actually prove the claimed
  behaviour did not occur (typed network fields today; kernel-recorded auditd PATH/CWD/watch records later).
- Rules that identify programs or actions by interpreting text (argv, script content, log-message regex) are
  **positive-only** (`Playbook.assures_negative = False`). They publish the same findings, with wording scoped
  to what the text shows; their coverage is `positive_only` / `positive_only_partial`, rendered as
  "not assessable by design" with a per-rule reason.
- All 10 M1 host rules are positive-only. The 5 network rules keep negative assurance.

## Rejected alternatives

- **Keep hardening text interpretation:** does not converge; static interpretation cannot decide what executes.
- **Keep negatives with caveats ("complete for argv-identified programs"):** analysts read "complete" as
  complete; bespoke caveats per rule invite drift.

## Consequences

Detection (findings, lanes, lab results) is unchanged. Host coverage reports almost no complete negatives in
M1, which is the truthful state. Negative assurance for host behaviour is M3 work: normalize auditd PATH
records (item 0 is the file actually executed, including `#!` scripts; `nametype=CREATE` writes), CWD and
watch keys, then add rules whose negatives rest on them. A test enforces that every host rule is positive-only
and that no positive-only claim points to another positive-only rule as its assurance.

## Revisit if

A kernel-record rule for a behaviour exists; that rule then assures the negative for that behaviour.
