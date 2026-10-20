# ADR-007: Any OpenAI-compatible model endpoint; hosted endpoints only behind a lab egress switch

**Status:** Accepted 2026-10-20 (owner direction). Not implemented.

## Context

ROMULUS talks only to Ollama (`romulus.agent.ollama.OllamaClient`). On the lab laptop's 8 GiB GPU that means qwen3:8b, whose judgment was measured and found weak (ADR-005, ADR-006). The owner wants a real investigating agent (ADR-008) on a capable model.

- **Mission teams** will run a powerful model on their own infrastructure. They will not use public commercial APIs, so mission telemetry is not sent to a third party.
- **In the lab**, the owner will use a hosted API, for example OpenAI, as the stand-in for that model. The lab data (AInception SL700) is public, so sending it discloses nothing new.

The servers a team would use for its own model (vLLM, SGLang, llama.cpp `server`, LM Studio, TGI, Ollama `/v1`) speak the OpenAI Chat Completions API with tool calling and JSON-schema output. So do OpenAI, Azure OpenAI and most on-prem gateways.

## Decision

1. **A model-provider port with two adapters.**
   - `openai_compatible` is the primary adapter: Chat Completions with tool calls and `json_schema` output, plus a configurable base URL, API key and model ID. One adapter serves both the lab's hosted API and a team's own server.
   - `ollama` is the existing client, kept for small local runs.

   Each role (`agent`, and the lead explainer if it is kept) names its provider and model. Truncation, usage and finish-reason checks move behind the port, so every adapter must report them.
2. **Egress class.** An endpoint is `local` when it resolves to loopback, RFC 1918 or the host-only network; the doctor check that does this exists today. Every other endpoint is `remote`.
3. **Remote endpoints need a bootstrap switch.**
   - The switch is `ROMULUS_MODEL_EGRESS=lab-public-data`, set in the bootstrap `.env`. The web UI never sets it.
   - Without it, hunt start refuses a remote endpoint and doctor fails the check.
   - With it, doctor warns, hunts and reports carry a "Telemetry excerpts were sent to <host> (<model>)" banner, and the manifest records the provider, host, model ID, the snapshot the provider reports, and the egress class.

   This costs little and keeps a mis-set URL from ever sending mission data off-site. A team's own model server inside its enclave counts as `local`. If it sits on a routable enclave address that isn't RFC 1918, the team adds it to `MODEL_LOCAL_HOSTS`, an explicit allowlist, rather than setting the egress switch.
4. **Configuration lives in `.env` for now.** The settings page is deferred (ADR-009). Example keys: `AGENT_PROVIDER`, `AGENT_BASE_URL`, `AGENT_API_KEY`, `AGENT_MODEL`, plus the budgets in the agent design. Secrets follow the existing rules: `SecretStr`, redacted, never in prompts.
5. **Pinned, logged and budgeted.** Use dated model snapshots, not `latest` aliases. Every call is logged as today: prompt digest, model ID and reported version, parameters, raw response, validation, usage and an estimated cost. Each hunt has call, token, wall-clock and optional cost budgets. Hitting a budget stops agent work, and the report lists what was left unworked; it never reads as "nothing found".
6. **Results name the model.** Every evaluation result records the provider and model that produced it. Before a release claim, the agent is rerun on the class of model the team will field, once one is available.

## Rejected alternatives

- **An OpenAI-specific integration (OpenAI SDK, Assistants, Agents SDK).** It locks ROMULUS to one vendor and does not reach a team's own server. The Agents SDK also exports traces to OpenAI by default.
- **A web-UI egress toggle.** One click would be enough to send mission data off-site. The switch stays in the bootstrap file.
- **A native adapter per vendor now.** Add one only when a provider we actually need has no usable compatible endpoint.

## Consequences

- Spec invariant "no external transmission" gains one explicit lab exception. Release gates are checked with the switch unset.
- Doctor gains a provider check: reachability, model present, tool-call and schema support, and egress class.
- The replay harness can run against any provider.

## Revisit if

A mission must use an accredited hosted service, for example a government cloud approved under its ATO. That would be a `remote-authorized` class with its own ADR.
