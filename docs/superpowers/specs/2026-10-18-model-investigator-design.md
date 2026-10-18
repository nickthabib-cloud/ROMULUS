# Model investigator design

**Status:** approved in chat on 2026-10-18; this document records the agreed M1 scope.

## Goal and boundaries

Implement the explicit, resumable controller from spec section 11. The model receives one compact brief and proposes one typed decision per call. SQLite remains the only state authority. Model output cannot change deterministic rule results, finding claims, lanes, hunt scope, coverage, or source access.

M1 includes `entity_timeline`, `auth_activity`, `process_tree`, and `ids_alerts`. Synthesis and the rest of the starter catalog remain later-milestone work.

## Components and flow

`romulus.agent` owns decision schemas, the tool catalog, brief construction and shrinking, validation, case scheduling, retries, fallbacks, and persistence. It has no adapter dependency. The hunt layer owns a pivot executor that converts an accepted tool request to one or more typed `SearchIntent`s and uses the existing read-only execution path. This boundary is recorded in ADR-003.

Each pivot persists its tasks and retained evidence. Normalized pivot events run only through direct playbooks. Aggregate and stack-counted playbooks require the full hunt window and must not publish from a pivot subset. Candidate publication is extracted from `Sweep._publish` into a shared helper, preserving the decision policy and setting `candidate.source_case_id` for pivot discoveries.

`entity_timeline` accepts host, account, and IP entities. Host retrieval targets host telemetry; IP retrieval targets both sides of network telemetry and locally filters normalized authentication events retrieved through a safe journal superset. This supports the scenario-14 attacker-IP starting pivot without inventing an IP-to-host mapping.

## Cases, fairness, and budgets

Non-context candidates are clustered deterministically by a primary shared entity and a fixed UTC time bucket. Entity precedence is host, account, destination IP, source IP, then domain; candidates without a usable entity remain individual seeds. Each selected case durably records every clustered seed ID in its system-created initial step.

Clusters are ordered by lane, priority, and time. At most the manifest's `max_cases` clusters are activated. Every seed outside those clusters is preserved in an explicit unassigned-seed list. The scheduler works cases round-robin by fewest steps used and then priority, so each eligible case receives breadth before any case consumes deeper pivots. Per-case and total-step budgets are enforced; unfinished cases and every unworked seed are listed in the agent summary and report.

## Model safety and failure behavior

Briefs contain deterministic summaries and bounded exemplars with evidence IDs, never raw dumps or a growing transcript. Telemetry is delimited as untrusted data and scanned for instruction-like content. Such content is flagged and cannot by itself authorize `close` or `park_as_lead`.

Tool arguments use strict per-tool schemas. Validation rejects raw DSL or extra fields, unknown entities or evidence IDs, uncited conclusions, out-of-scope windows, and unsupported claim or lane changes. An escalation must point to an existing deterministic candidate and repeat its admitted claim and lane. The model's separate case conclusion, cited reasoning, alternatives, and evidence IDs are still persisted.

A rejected proposal is logged and receives one retry containing the validation errors. A second rejection produces a deterministic `park_as_lead` conclusion. Transport outages leave cases open. Briefs shrink by a deterministic policy before a call. The existing Ollama truncation rule remains unchanged: a low cached `prompt_eval_count` is valid; only a count at the `num_ctx` ceiling indicates input truncation. Truncated or oversized calls are logged as failed and never executed.

## Resume and reporting

`romulus hunt resume <hunt-id>` is agent-only: it accepts a partial hunt, performs the existing `partial -> running` transition, rebuilds contracts, and continues durable open cases without rerunning the sweep. New hunts persist a structured sweep summary so resume can distinguish sweep partiality from an agent-only outage. Older hunts without that summary remain conservatively partial. Repeated resume is idempotent.

The canonical report manifest gains an `investigations` section containing case seeds, entities, status, pivot steps and digests, cited model conclusions, pivot-discovered candidate IDs, incomplete work, and unassigned seed IDs. Markdown renders the pivot chain behind findings and a model-contribution summary. These conclusions are explicitly separate from deterministic machine decisions. A web case view is optional and excluded from M1.

## Verification

Tests cover acceptance scenarios 13–17: hostile and invalid proposals are rejected and not executed; an attacker-IP case pivots through authentication to host process evidence and a direct rule publishes the cited finding; case and global budgets preserve breadth and list all remaining seeds; an Ollama outage resumes through the new command without another sweep; and context shrinking plus forced truncation are handled safely. Ollama client tests also prove cached-token counts are accepted while counts at the context ceiling fail.

The full local suite and `python scripts/archmap.py --check` must pass. Deployment and a lab hunt are reported only if they actually run.
