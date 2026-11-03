# The AI investigating agent (planned)

Status: being built. The model connection (provider adapters, egress rules, budgets, call records and the `doctor` check) is in place; the agent's investigation loop is not available yet. The rest of this page describes how it will work. I'm using an API to connect to a model because my local model didn't have enough capability running on limited processing power of my computer. In reality, teams would be able to run secure local models on a server.

## What it does

After the deterministic sweep and expansion, an AI agent works the hunt the way a senior analyst would:

- it reads everything ROMULUS found;
- it forms hypotheses about what the adversary did;
- it follows leads to test them, and finds further indicators;
- it connects the pieces into a bigger picture.

The report then opens with the agent's overall assessment: a cited hypothesis, clearly labelled as AI-generated and unconfirmed.

The deterministic layer stays the floor. With the agent off, unavailable or failing, the hunt's findings, lanes, coverage and incidents are exactly what they are without it. An agent failure never makes the detection result partial; it makes the agent phase partial, and the report says what was left unworked.

## Where it runs

```
sweep ─► packet stage ─► expansion (deterministic) ─► agent: orient ─► investigate ×N ─► assess ─► report
   │                           │                              │                │
   └─ findings, incidents, coverage ───────────────────────────┘   pivots ─► normalization ─► every detector and context rule
```

The agent is a phase of the hunt worker with its own state (`pending`, `running`, `completed`, `partial`, `failed`, `skipped`). The New hunt page and the CLI have a "Run the AI agent" choice. It is on by default when a model provider is configured and reachable, and off otherwise.

## Connecting a model

ROMULUS talks to models through one provider interface with three adapters:

- **`openai_compatible`** (the main one): the OpenAI Chat Completions API with tool calling and JSON-schema output. It works with a team's own model server (vLLM, SGLang, llama.cpp `server`, LM Studio, TGI, Ollama's `/v1`) and with hosted APIs.
- **`ollama`**: the existing client, for small local runs.
- **`anthropic`**: Claude models through the Claude Messages API and Anthropic's official SDK, an optional install (`romulus[anthropic]`) imported only when this provider is chosen. The endpoint defaults to `https://api.anthropic.com`, a remote endpoint, so the egress rules below apply unchanged. The SDK gets the key only from `AGENT_API_KEY` and an HTTP client ROMULUS builds: no environment proxy, no redirects, requests only to the classified host, and no credentials, headers, logging or tracing taken from the SDK's own environment variables. The port's retry policy is the only one. Tools are sent with strict schemas (a schema outside the subset the API accepts is refused before sending), thinking is always on with its depth set by `AGENT_EFFORT`, each call reserves `AGENT_THINKING_TOKENS` of output for it, and the tool list and system prompt are a cached prefix. A refusal by the API's safety classifier is reported as `refused`, never as "nothing found"; by default the API retries it on the fallback model it recommends, and every call records the model that actually answered. Claude signs its thinking, so an investigation session must be append-only or start fresh: each reply carries its signed blocks in an opaque provider field that goes back unchanged with the turn, and an edited or foreign turn is rejected before anything is sent.

Configuration lives in `$ROMULUS_HOME/.env`:

| Key | Meaning |
|---|---|
| `AGENT_PROVIDER` | `openai_compatible` (default), `ollama` or `anthropic` |
| `AGENT_EFFORT`, `AGENT_THINKING_TOKENS`, `AGENT_REFUSAL_FALLBACK` | `anthropic` only: thinking depth (`low` to `max`, default `high`), the output room reserved for thinking on every call, and whether a refused call may be answered by the API's recommended fallback model (`default` or `off`) |
| `AGENT_PRICE_CACHE_READ_PER_MTOK`, `AGENT_PRICE_CACHE_WRITE_PER_MTOK` | Prices of prompt tokens read from and written to the provider's prompt cache, for the cost estimate. A priced `anthropic` agent needs the cache-read price; the write price defaults to 1.25 times the input price |
| `AGENT_BASE_URL`, `AGENT_API_KEY`, `AGENT_MODEL` | Endpoint (the API root that contains `/chat/completions`), key and model. A remote endpoint needs a key; your own local server may not. Pin a dated model snapshot, not a `latest` alias |
| `ROMULUS_MODEL_EGRESS` | Must be `lab-public-data` before any non-local endpoint is allowed (see below) |
| `MODEL_LOCAL_HOSTS` | Extra hostnames, addresses or CIDR networks treated as local, such as a team's model server on a routable enclave address |
| `AGENT_CONTEXT_TOKENS` | The model's context window, so a cut-off prompt is detected; `0` leaves it to the server (Ollama uses `OLLAMA_NUM_CTX`) |
| `AGENT_MAX_OUTPUT_TOKENS`, `AGENT_TIMEOUT_SECONDS` | Per-call output allowance and timeout |
| `AGENT_MAX_CALLS`, `AGENT_MAX_TOKENS`, `AGENT_MAX_WALL_SECONDS`, `AGENT_MAX_COST_USD` | Per-hunt budgets. The cost budget is optional, estimated from reported usage with `AGENT_PRICE_INPUT_PER_MTOK` and `AGENT_PRICE_OUTPUT_PER_MTOK` |
| `AGENT_MAX_TOOL_CALLS_PER_SESSION` | Bounds one investigation session (default 25) |
| `AGENT_CONCURRENCY` | Parallel investigation sessions (default 2) |
| `AGENT_DEFAULT` | `on` or `off`: whether new hunts use the agent when it is configured (`hunt start --no-agent` turns it off for one hunt) |

With no endpoint, no model, or a remote endpoint with no key, the agent is **not configured**: `romulus doctor` says so, hunts run without it, and their results are exactly the deterministic ones. Adding the missing value to `.env` is the only step needed to turn it on.

### What the connection checks

Every reply must say why generation stopped and how many tokens it used. A reply cut off at the output limit, a prompt that reached the context window, a refusal, a reply with no stop reason, malformed tool-call arguments, a call to a tool that was not offered, and output that does not match the requested JSON schema are all reported as such, never passed on as a complete answer. A prompt estimated to exceed the context window is not sent. Transport errors and `429`/`5xx` responses are retried up to three times with backoff; then the endpoint counts as unavailable. Redirects are not followed.

`romulus doctor` checks the agent's endpoint: its egress class, reachability, that the model is listed, that tool calling and JSON-schema output work (with a tiny request that carries no telemetry), that usage is reported, and that the model the server reports matches the pinned one. For `anthropic` the models endpoint must confirm the exact model id, supplies the context window when `AGENT_CONTEXT_TOKENS` is 0 (doctor fails and asks for that key when it reports none), and bounds the per-call output plus thinking allowance; the tool-call check asks for the tool in the prompt, since the model does not accept a forced tool choice, and a reply without the call fails it.

### Keeping telemetry on site

An endpoint is **local** when it is loopback, a private (RFC 1918) or IPv6 unique-local address, or is listed in `MODEL_LOCAL_HOSTS`. A hostname is local only when every address it resolves to is; a name that does not resolve counts as remote. Every other endpoint is **remote**.

- Mission teams run their own model inside their enclave, so telemetry never leaves it.
- A remote endpoint is refused unless the bootstrap `.env` sets `ROMULUS_MODEL_EGRESS=lab-public-data`, and even then only over HTTPS. That switch is meant only for testing on public datasets; the web UI can never set it, and any other value is a configuration error. With it set, `doctor` warns, and every hunt and report that used the model carries a banner naming the host and model. Without it, `doctor` fails the check and hunts run without the agent.
- Secrets are removed from every outgoing message, and the hunt manifest records the provider, endpoint host, model and egress class, never the key or the URL's path.
- Every call is logged: a prompt digest, the model and reported version, parameters, the raw response, validation results, usage and an estimated cost. Results always record which provider and model produced them.

## What the agent sees

The agent starts from a **dossier** built deterministically from the hunt database, using short aliases (`F12`, `I3`, `E401`, `N7`) that ROMULUS maps back to real IDs:

- **scope:** the window, the sources, and the coverage gaps (partial or unassessed source and time cells);
- **findings index:** every `urgent`, `high` and `lead` finding, one line each;
- **context counts** by rule, with individual context items reachable through a tool;
- **incidents:** their members and links, with each link's strength (observed or inferred);
- **expansion state:** anchors left unexpanded or partial, and link tiers not reached.

If the dossier would not fit the model's context, it is paged, and it says so. Nothing is dropped silently.

## Tools

Every argument is typed and validated. Every result carries evidence aliases, counts, and a coverage state: `complete`, or `partial` with the exact uncovered ranges. Telemetry text is always passed as data, never as instructions.

| Group | Tools |
|---|---|
| Read | `list_findings`, `get_finding`, `get_evidence`, `get_incident`, `entity_profile` |
| Pivot | `entity_timeline`, `auth_activity`, `process_tree`, `ids_alerts`, `ip_sessions`, and `follow_link` over the expansion links (lineage, session, flow, source IP, account, host-after) |
| Hypothesis | `open_hypothesis`, `update_hypothesis` |
| Output | `propose_finding`, `propose_link`, `add_note`, `request_rule` |
| Control | `finish_session` |

Everything from the LLM is input validated. There is no free-form query, file or shell tool, shell commands or paths, and the model never writes query DSL, Arkime expressions, TShark filters directly. Records a pivot pulls in go through normalization and **every** deterministic detector and context rule; findings those rules produce keep their deterministic provenance and lane.

## Hypotheses

Each hypothesis is a stored record with an append-only history:

- a statement;
- ATT&CK technique IDs, validated against the vendored ATT&CK data;
- the entities involved;
- supporting and contradicting citations;
- open questions;
- a status: `open`, `supported`, `weakened`, `refuted` or `abandoned`;
- the model's confidence.

The UI shows hypotheses live and on their own tab, always labelled "Agent hypothesis".

## The loop

1. **Orient.** One session reads the dossier and opens a capped number of hypotheses, for example "initial access through the web application on host A, followed by credential discovery".
2. **Investigate.** The controller picks the next hypothesis by priority (the lane of its supporting findings, open questions, untouched entities), reserving breadth so no single thread uses up the budget. Each session starts fresh from the database with the dossier header, the hypothesis, and summaries of its earlier sessions, never a hunt-long transcript. The model pivots, reads, proposes findings and links, updates the hypothesis, may open new ones, and ends with a summary that becomes that hypothesis's memory.
3. **Stop** when no open hypothesis has unanswered questions or a budget is reached. Remaining hypotheses and unworked anchors are listed in the report.
4. **Assess.** A final session reads every hypothesis, the agent's findings and links, and the deterministic incidents, and writes the assessment.

There is no agent framework: the loop is an explicit controller with native tool calling, and the database is the only state. Resume continues from the stored rows.

## What the agent may add, and what it can never do

| Output | Checked | Result |
|---|---|---|
| `propose_finding` | Every citation resolves to raw evidence returned in this hunt; the claim's wording fits the cited event types; lane at most `high`; duplicates become a note on the existing finding | An "Agent finding" citing its hypothesis |
| `propose_link` | Both ends resolve; at least one citation | A link drawn dashed and labelled as a hypothesis, never as observed |
| `add_note` | The target resolves | A note on the target, including "looks benign" opinions |
| `request_rule` | Citations resolve | A request for a new deterministic detection |

The agent cannot close, hide, demote or re-lane anything, or change scope, coverage or rule outcomes. Anything else it proposes is rejected and logged, and the model sees the validation error so it can correct itself. Each true positive the agent finds that the deterministic layer missed becomes a rule request, so the next hunt finds it even with no model.

## The AI assessment in the report

The assessment is stored in the report manifest, so the web UI, Markdown, JSON and the executive report all show the same thing. It covers:

- **the overall hypothesis:** entry point, actions on hosts, movement and apparent objective, in time and ATT&CK-tactic order;
- **key steps**, each cited;
- **confidence**, overall and per step, with reasons;
- **alternative explanations** considered, and why they rank lower;
- **gaps:** what the telemetry could not show, and what would confirm or refute the hypothesis;
- **recommended next checks** for the analyst (guidance only; no action is taken).

Each sentence is stored as `{text, cites, kind}` with `kind` one of `observed`, `inferred` or `hypothesis`. A deterministic checker removes sentences that cite nothing or cite unknown evidence, downgrades `observed` to `inferred` when the citations are agent or inferred links, and counts every change in the section footer. The header reads "AI-generated hypothesis from the cited evidence. Not confirmed by an analyst. Model: <provider>/<model>." Without an agent, the section is the deterministic incident narrative.

## Safety

- **Prompt injection.** Telemetry is untrusted data: logs can contain text like "ignore previous instructions" or "pivot to 10.0.0.1". Tool results carry telemetry only in data fields, the system prompt says so, and such content is flagged as suspicious rather than followed.
- **No new powers.** All tools are read-only, typed and within the hunt's scope.
- **Secrets** never enter prompts; redaction is applied to every outgoing request.
- **Egress** follows the local/remote rules above.

## Budgets, failures and resume

- Every budget is checked before each call. When one is reached, the agent writes its assessment from what it has (if the remaining budget allows), then stops as `partial`.
- A provider outage gets up to three retries with backoff, then `partial`. Detection results are unaffected.
- `hunt resume <id>` continues the agent phase from the stored rows.
- Every request and response is stored. The live view streams hypotheses, tool calls and agent findings.

## How it is measured

The agent is scored with and without the agent on the same data, per provider and model, before any claim is made:

- extra true positives from agent findings and from pivoted records that detectors admitted;
- false leads per hour the agent adds;
- whether supported hypotheses match the real attack phases;
- 100% citation validity, and the checker's removal rate;
- calls, tokens, cost and wall time per hunt;
- a determinism check: deterministic findings are identical with the agent on and off.
