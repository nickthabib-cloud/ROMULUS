# Model investigator design

**Status:** Approved 2026-10-18, including the review conditions recorded in `Claude-Codex.md`.

## Scope

Implement the explicit, resumable controller from spec section 11. Each model call receives one compact brief and proposes one typed decision. SQLite is the only state authority. The model cannot change deterministic rule results, finding claims, lanes, hunt scope, coverage, or source access.

M1 includes `entity_timeline`, `auth_activity`, `process_tree`, and `ids_alerts`. Synthesis and the remaining starter tools stay in later milestones.

## Boundaries and pivot flow

`romulus.agent` owns schemas, briefs, validation, clustering, scheduling, retries, fallbacks, and persistence; it imports no source adapter. The hunt-layer executor from ADR-003 converts accepted tools to typed `SearchIntent`s and uses the existing read-only execution path.

Pivot events are normalized and persisted, but only direct playbooks evaluate a pivot subset. Aggregate and stack-counted playbooks require full-window input. Candidate publication is shared with the sweep and sets `candidate.source_case_id` for pivot discoveries.

For network event families, `host.name` identifies the sensor and is emitted as a host entity with role `observer`, not `host`. Observers are excluded from host clustering and host pivots. Network seeds therefore cluster by destination or source IP. `entity_timeline` accepts IPs against network telemetry and hosts against host telemetry; an attacker-IP pivot may also retrieve a safe journal superset and locally retain matching normalized authentication events, without inventing an IP-to-host mapping.

## Cases and budgets

Non-context sweep candidates are grouped by primary entity using host, account, destination IP, source IP, then domain, excluding observers. Within each entity, sorted seeds join the current cluster when the gap from its latest seed is at most 15 minutes. Selected cases durably record every clustered seed ID in a system-created initial step.

Clusters are ordered by lane, priority, and time. At most `max_cases` are activated. Reporting partitions every seed into concluded, assigned-but-unfinished, or unassigned work; the latter two are the complete unworked list. Scheduling is round-robin by fewest model calls and then priority. Validation retries count against per-case and total-step budgets. The cumulative persisted model/pivot duration plus current-run monotonic time enforces `wall_clock_minutes` across resumes.

If only agent budgets expire after a complete sweep, hunt execution remains `completed_within_scope`; the separate agent status is `budget_exhausted` and every unfinished seed is shown. Sweep partiality or an Ollama outage remains `partial` so it can be resumed. No agent status changes the deterministic detection result.

## Model safety

Briefs contain deterministic summaries and bounded exemplars with evidence IDs, never raw dumps or a growing transcript. Telemetry is delimited as untrusted data and instruction-like content is flagged. A flagged value cannot by itself authorize `close` or `park_as_lead`.

Strict per-tool schemas reject raw DSL and extra fields. Validation rejects unknown entities or evidence, missing citations, out-of-scope windows, and claim or lane changes. Escalation must reference an existing deterministic candidate and repeat its claim and lane, while separately recording the model's cited case conclusion, reasoning, and alternatives.

One rejected proposal is retried with its errors. A second rejection deterministically parks the case as a lead. Briefs shrink by policy before calls. Existing Ollama truncation semantics stay unchanged: low cached `prompt_eval_count` is valid; only a count at the `num_ctx` ceiling indicates truncation. Failed or truncated calls are logged and never executed.

## Resume and reporting

Hunts hold a persisted lease with heartbeat and expiry. `romulus hunt resume <hunt-id>` accepts `partial`, a `failed` hunt whose structured sweep summary proves the sweep finished, or `running` with an expired lease. It performs the valid transition or stale reclaim, rebuilds contracts, and continues pending/open cases without rerunning the sweep. It refuses an actively leased `running` hunt and a failed hunt whose sweep did not finish. Accepted pivots are persisted before execution, use deterministic task fingerprints, and safely replay after a crash.

New hunts persist a structured sweep summary so resume distinguishes sweep partiality from agent-only interruption. Older hunts without it remain conservatively partial.

The report manifest and Markdown renderer add Investigations: case seeds, entities, status, pivot chain and digests, cited model conclusion, pivot-discovered candidates, model contribution totals, incomplete cases, and unassigned seeds. These are separate from deterministic machine decisions. CLI, report, and hunt web summary show the same agent status and unworked count. A web case view is outside M1.

## Verification

Automated tests cover acceptance scenarios 13–17, the observer-role regression, gap clustering across clock-bucket edges, stale versus active leases, wall-clock exhaustion, budget state semantics, crash replay, and Ollama cached-token/truncation behavior. The full suite and architecture check must pass. Deployment and lab claims are reported only when actually run.
