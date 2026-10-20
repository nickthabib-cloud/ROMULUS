# ADR-007: Any OpenAI-compatible model endpoint; remote endpoints only in a lab egress mode

**Status:** Proposed 2026-10-20 (owner direction: allow an API-key model provider such as OpenAI so a capable model can stand in for the strong local model a team would run). The lead's recommended shape is below; it awaits the owner's sign-off. Not implemented.

## Context

ROMULUS talks only to Ollama (`romulus.agent.ollama.OllamaClient`). On this laptop's 8 GiB GPU that means qwen3:8b. Its judgment was measured and found weak: replay decision accuracy 0.22, then 0.53 with the v2 menu, and 3 of 9 escalations correct (ADR-005, ADR-006). The owner wants to find out what a capable model adds. In the field, a team would run a strong model on its own hardware.

Two facts shape the decision:

1. **The lab data is public** (AInception SL700 on Zenodo). Sending it to a hosted model discloses nothing that isn't already published. Mission telemetry is the opposite. It is sensitive, often CUI or classified, and usually sits on an air-gapped kit. Sending it to a commercial API would be a data spill.
2. **"OpenAI-compatible" is the common interface of local servers too.** vLLM, SGLang, llama.cpp `server`, LM Studio, TGI and Ollama's own `/v1` all serve the Chat Completions API, with tool calling and JSON-schema output. So do Azure OpenAI and most on-prem gateways. One adapter therefore covers the lab experiment *and* the strong local model a mission kit would actually run.

## Decision

1. **A model-provider port with two adapters.** `ollama` is the existing client. `openai_compatible` speaks Chat Completions with tool calls and `json_schema` structured output, with a configurable base URL, API key and model ID. Each role (`investigator`, `narrative`, `explain`) names its own provider and model. The existing truncation, token-estimate and output-limit checks move behind the port, so every adapter must report usage and finish reasons.
2. **Endpoint egress class.** An endpoint is `local` when it resolves to loopback, RFC 1918 or the host-only network. The existing doctor check already decides this. Every other endpoint is `remote`.
3. **Remote needs a bootstrap switch that the web UI cannot set.** It is used only when the bootstrap `.env` contains `ROMULUS_MODEL_EGRESS=lab-public-data`. Without it, hunt start refuses a remote provider and doctor fails the check. With it:
   - doctor warns;
   - the New hunt page, the live view and every report carry a banner ("Telemetry excerpts were sent to <host> (<model>)");
   - the hunt manifest records the provider, host, model ID, the snapshot the provider reports, and the egress class.

   The release build and the air-gap wheelhouse ship with it unset.
4. **What crosses the wire** is only what the agent design already allows: briefs, alias cards and typed tool results. Secrets are never in prompts (`redact_text` stays as a final filter). Telemetry excerpts *are* sent, which is the point, and the reason this mode is limited to public lab data.
5. **Pinned, logged and budgeted.** Use dated model snapshots, never `latest` aliases. Every call is logged as today: prompt digest, model ID and reported version, parameters, raw response, validation, usage and an estimated cost. Each hunt has a token and cost budget. Hitting it stops model work, and the report lists the unworked items. It is never read as "nothing found".
6. **Evaluate on two tiers.**
   - *Frontier*, the best hosted model: an upper bound.
   - *Mission-class*, an open-weight model a CPT kit can realistically run, 70B–120B class (for example gpt-oss-120b, Qwen3-235B-A22B, Llama 3.3 70B). It can be reached through a hosted open-weight endpoint today and a local GPU server later.

   Product claims ("the agent adds X") come only from mission-class results. Frontier results are labelled "ceiling, not deployable".

## Rejected alternatives

- **OpenAI-specific integration (OpenAI SDK, Assistants or the Agents SDK).** It locks ROMULUS to one vendor, and it does not reach local servers. The Agents SDK also exports traces to OpenAI by default, which is an egress path we would have to remember to disable.
- **Remote models on mission data, with redaction.** Hostnames, accounts, IPs, paths and command lines are the evidence. Removing them removes what the model must reason about, and leaving them in is the spill. Pseudonymization leaks through free-text fields such as argv and URLs. Redaction is not a spill control.
- **A web-UI toggle for egress.** One click on a mission kit would make a spill. The switch lives in the bootstrap file, which only someone with shell access can edit (ADR-009).
- **A native adapter per vendor now.** Add one only when a provider we actually need lacks a usable compatible endpoint, for example for structured output.

## Consequences

- Invariant "no external transmission" (spec §1, §0.4, §15 gate 8) gains one explicit, lab-only, opt-in exception. Release gates are checked with egress unset.
- New config: per-role provider, base URL, model and key, plus `ROMULUS_MODEL_EGRESS`. Keys are entered on the settings page (ADR-009).
- Doctor gains a provider check (reachability, model present, tool-call and schema support, egress class).
- The replay harness runs against any provider, so the ADR-008 gate needs only this adapter.

## Revisit if

An accredited model service is authorized for a mission's data at the right impact level, for example a government-cloud deployment approved under the mission's ATO. That would be a third class, `remote-authorized`, and it needs an owner decision and its own ADR.
