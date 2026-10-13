# Optional OpenAI Provider Milestone

**Objective:** Let the existing evidence-constrained ROMULUS reasoning and report contracts run through either local Ollama or the OpenAI Responses API without weakening deterministic search, admission, reporting, or retention controls.

## Scope and decisions

- Ollama remains the default. `LLM_PROVIDER` is the single switch; both provider configuration blocks may coexist in `.env`.
- OpenAI requires a configured model and API key plus the separate `ALLOW_CLOUD_LLM=true` authorization gate.
- The provider boundary transports only the same bounded prompts and strict schemas already used by ROMULUS. It provides no search, shell, or direct telemetry-source access.
- Responses API requests use strict JSON schema for structured work and `store: false`. The provider boundary copies existing schemas into OpenAI's supported strict subset without changing Ollama's contracts. Provider errors are sanitized; audits retain only provider, model, request ID, duration, and token counts.
- Model-facing indicator synthesis is globally bounded and classification-stratified; the complete deterministic report remains authoritative outside that bounded context.
- `model-check` uses a fixed request with no hunt data. `model-report --id` re-synthesizes a deep copy of a saved hunt, performs no telemetry searches, never mutates the saved hunt, and writes to `reports/model-evaluations/`.

## Delivery status

- [x] Preserve and push the pre-change rollback checkpoint.
- [x] Add provider-neutral transport with Ollama and OpenAI adapters.
- [x] Add explicit cloud authorization and credential-safe audit metadata.
- [x] Make model call labels and diagnostics provider-aware.
- [x] Add no-hunt-data connectivity and saved-hunt report evaluation commands.
- [x] Document configuration, switching, output locations, and cloud-data boundary.
- [x] Close final review findings: strict-schema summaries and bounded large-hunt synthesis context.
- [x] Run focused and full regression suites (368 tests passed; 8 expected dependency skips).
- [x] Commit and push `codex/openai-provider`; open and attach [GitHub PR #11](https://github.com/nickthabib-cloud/ROMULUS/pull/11).
- [x] Deploy the non-secret branch to the VM without changing its network mode; provider-focused tests passed 32/32, compile verification passed, `doctor` passed, and the default Ollama no-hunt-data model check passed.
- [ ] Operator enables the VM NAT adapter, adds the secret locally, and runs the documented OpenAI checks; live API validation remains operator-executed.
