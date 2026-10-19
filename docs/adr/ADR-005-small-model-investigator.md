# ADR-005: Keep qwen3:8b; make the investigator succeed by construction

**Status:** Accepted, 2026-10-19 (owner direction; design, deterministic fallback and acceptance targets approved by the owner the same day)

## Context

The M2 ablation (`docs/eval/results/2026-10-19-sl700_e_a-ablation-1v3.md`) scored the agent-on hunt identical to model-off on every finding metric, at +508.6 s, 44 model calls and ~194k tokens. 21 of 44 outputs were rejected:

| Rejection | Count |
|---|---|
| Unknown evidence IDs | 8 |
| Duplicate pivot | 5 |
| Spawn needs a known discovered entity, plus unknown IDs | 4 |
| Spawn needs a known discovered entity | 2 |
| Invalid tool arguments | 1 |
| Unknown process ID | 1 |

Every one of these is the model *composing* a value the controller already knew: an ID, an entity, a timestamp, a tool/argument pairing. The model was asked to write a free-form structured proposal and then had it checked. 39 of 44 briefs were also shrunk to fit `num_ctx` 8192, so the model often saw cut-down evidence.

The spec (§12) called for a multi-model bakeoff. The owner decided on 2026-10-19 not to run one: ROMULUS stays on the current model and the architecture is changed so a model of this size produces what we want by how the task is set up.

## Decision

1. **No model bakeoff.** `OLLAMA_MODEL_TRIAGE=qwen3:8b` remains the default. The bakeoff tooling becomes the *investigator replay evaluation*: frozen briefs from real hunts, expected decisions owned by the eval-custodian, scored on every investigator change.
2. **The model chooses; the controller composes.** At each step the controller deterministically enumerates the legal next moves for the case as a short numbered menu. The model returns the option it picks, the evidence it relies on, and a short rationale. The controller fills in every typed field (tool, entity, window, claim, lane, IDs) from the chosen option.
3. **Constrained decoding.** Each call's JSON schema is generated for that call, with `enum`s for the option IDs and evidence aliases actually in the brief. Ollama's structured output then cannot emit an unknown ID, entity or tool. Server-side validation stays as defence in depth.
4. **Short aliases.** Evidence, entities and candidates appear in the brief as `E1…`, `N1…`, `C1…`, mapped back to real IDs by the controller. Long hashes are never copied by the model.
5. **Illegal moves are absent, not rejected.** Executed pivots, observer hosts, unknown process IDs, out-of-window ranges and spawns of already-cased entities are never offered.

Details: `docs/design/investigator-v2.md`.

## Consequences

- The rejection classes above become impossible by construction. Remaining model risk is judgment quality: which option, which evidence. The replay evaluation measures that.
- Option generation is deterministic, so it is testable and model-off reproducible. It can also drive a model-off fallback that works seeds without any model.
- The model can no longer propose a pivot the menu does not contain. Menu breadth is a design responsibility: new tools and pivot templates must be added to the generator, not discovered by the model.
- Spec §12 is replaced by a pointer to this ADR. The M2 checklist item "Model bakeoff… ADR selecting models" becomes "investigator replay evaluation and ADR-005".
- Investigator code changes are implemented by Codex via `Claude-Codex.md` (standing process note), after owner approval of the design, and reviewed by `reviewer`.

## Revisit if

The redesigned investigator still adds no detection value on the replay set and in an e_a ablation, or the hardware changes enough that a larger model fits in VRAM.
