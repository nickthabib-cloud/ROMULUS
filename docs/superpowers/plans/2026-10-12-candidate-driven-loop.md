# Candidate-Driven Investigation Loop — Milestone 2

**Goal:** Make undirected hunts discover telemetry-backed candidates before forming hypotheses, complete the deterministic aggregate analytics, persist candidate investigation state, and make reasoning and closure candidate-aware.

## Task 1: Gate hypothesis creation on mission direction or observed candidates

- Add failing tests for directed versus undirected mission classification.
- Prove undirected live planning creates no hypothesis and does not call the model before telemetry exists.
- Prove directed planning labels initial hypotheses with an `operator_direction` basis.
- Convert deterministic candidates into evidence-backed hypotheses after analysis and prioritize them for pivots.

## Task 2: Complete deterministic aggregate signal generation

- Add table-driven failing tests covering every aggregate behavior in the catalog.
- Implement the missing host/network sequence, DNS, protocol, volume, rarity, and staging signals.
- Drive aggregate catalog events from one complete analytic summary while retaining compatibility with existing fields.

## Task 3: Persist candidate state and make reasoning/closure candidate-aware

- Add failing tests for stable candidate merge, follow-up status/history, and disposition preservation.
- Include the bounded candidate queue in model context and accept only visible evidence/candidate IDs as hypothesis bases.
- Keep findings evidence-only.
- Add candidate-aware closure tests so actionable candidates or unfinished follow-ups prevent clean completion.

## Task 4: Verify, document, and deploy

- Run the focused tests, then the complete local suite.
- Update validation/change notes and record isolation/implementation rulings.
- Deploy the changed tree to the authorized VM, run the complete VM suite and a representative hunt, and inspect the saved report/state.
- Request a final focused code review, address any material findings, and pause for operator review.
