# ADR-006: Deterministic expansion finds; an optional model explains and writes

**Status:** Accepted 2026-10-19 (owner direction in chat; the design doc's open questions are still open). Supersedes ADR-005 decisions 2–5 and spec §11's model-driven investigation loop. ADR-005 decision 1 (no model bakeoff) stands.

## Context

The v2 ablation (`docs/eval/results/2026-10-19-sl700_e_a-ablation-456.md`) ran the same e_a window in three agent modes:

| Mode | What it did | New admitted items |
|---|---|---|
| off | sweep only | — |
| deterministic | 59 complete pivots; 4 retrieved gold records | 0 |
| model (qwen3:8b) | 22 pivots; 9 escalations, 3 on gold and 6 on benign | 0 |

The replay baseline (`2026-10-19-replay-qwen3-8b-baseline.md`) scored decision accuracy at 0.22 at `num_ctx` 8192 and 0.14 at 16384, which was also 2.7× slower. A larger context made the model worse.

Two conclusions follow:

1. **Pivot choice is not the bottleneck.** The deterministic mode, with no model, reached attacker records and admitted nothing. Pivots rerun the same context-free direct pack (`romulus.hunt.pivot` → `fresh_direct_pack()`), which already saw those records in the sweep and did not fire. A better chooser cannot fix that.
2. **The miss funnel names the real gaps.** The sweep evaluated 5 missed opportunities with no rule matching (4 discovery, 1 privesc). Another 4 are leads only, including a critical remote login. Those events are benign out of context and suspicious in context. The remaining misses are source gaps: Arkime and PCAP are 0/12 each, and two C2 audit records are never normalized.

The owner wants a tool that finds evidence of compromise. Teams must also be able to use it with no language model at all.

## Decision

1. **Expansion replaces the model investigator.** After the sweep, a deterministic loop starts from urgent and high findings (the *anchors*). It follows typed links (process lineage, login session, same host after the anchor, network flow, source IP, account), re-detects the linked records, and loops on new anchors until nothing new appears or the budget runs out. It is reproducible and replayable, with no model calls.
2. **Context rules.** A new playbook kind evaluates only records reached through a link from an anchor. Its claim states the context and cites both the record and the anchor. A context finding reached through an inferred link (time proximity alone) is at most a `lead` and is labeled a hypothesis.
3. **Deterministic correlation, shown as a timeline.** Findings and links form an incident graph. Connected components, ordered by time and ATT&CK tactic, are the attack paths. The main analyst view is an attack-path timeline: proven links solid, suggested links dashed and labeled as hypotheses, and analyst-drawn links in a third style, never shown as proven.
4. **The model is optional and only explains and writes.** With a model, ROMULUS explains each lead in plain English with a labeled opinion, and drafts a cited narrative and executive summary per incident from the finalized report manifest. Without one, leads have no explanations and a deterministic template narrative is used. The model never admits, hides, filters, changes lanes, closes, or chooses queries. A "sort by model opinion" toggle may exist for leads only, after a replay gate shows it beats the deterministic order; the default order and the report stay deterministic. A model outage never makes a hunt partial.
5. **A per-hunt choice in the UI and CLI.** The New hunt page gets a "Use a language model to explain leads and draft the narrative" option. It is enabled by default only when a model is configured and reachable. The narrative can also be redrafted later as a new report revision.

Details: `docs/design/deterministic-expansion.md`.

## Rejected alternatives

- **Give the model all sweep results to correlate.** 97 surfaced items plus 504 context items and their evidence do not fit in 8k tokens. Correlation is a join on typed keys, which code does exactly and completely. A model does it approximately and cannot prove what it missed.
- **RAG or embedding retrieval over logs.** It does not enlarge the window, only chooses what to drop. Textual similarity is the wrong relevance for logs: the record that matters after a login shares a session ID, not wording. Top-k retrieval can never support a complete negative. It is fuzzy matching over serialized records, which the invariants forbid, and it puts more attacker-controlled text into prompts.
- **Keep improving model-chosen pivots (ADR-005).** Deterministic mode shows that even perfect choices admit nothing until pivots can produce findings.
- **The model as a triage gate or default ranker.** At 3 correct of 9 escalations it would add noise, and sneaky attacker activity is designed to look routine. v1 hid standalone indicators behind a score threshold (spec §2, lesson 3). The model may only label leads, and its sort is an opt-in view that must first pass a replay gate.
- **Model-written hypotheses linking findings.** Small models over-connect, and the single-attacker lab data would reward that. The timeline's suggested links and analyst-asserted links serve this need without a model.

## Consequences

- Detection value comes from expansion and context rules, and is the same with or without a model. Model-on and model-off reports have identical findings, lanes, links and coverage; only lead explanations and the narrative differ.
- Investigator v2 work is reused: named windows, the pivot executor (ADR-003 boundary), duplicate-pivot keys and the deterministic option enumeration. The model-call path for investigation (briefs, menus, constrained schema, resolver, escalation) is retired once expansion lands. The replay harness is repurposed to score narrative faithfulness.
- New spec text is needed in §5 (New hunt option), §11 (rewrite), §15 (the model-on/off metric becomes a narrative quality metric), §16 (scenarios 13–17) and §17 (milestones). It will be edited after sign-off.
- Context rules must be written from ATT&CK behaviour classes, not from the e_a commands. e_a is the dev set, and gains on it alone are not evidence.
- Strong session links need the auditd session ID (`ses`) normalized; today only `process.auid` is typed.
- Code in `romulus.agent` and the expansion engine goes to Codex via `Claude-Codex.md` (standing process note). `reviewer` reviews before merge.

## Revisit if

Expansion with context rules does not raise recall on the dev set *and* a holdout, or false leads per hour rise beyond the owner's ceiling. Also revisit if hardware or an approved mission model allows a larger model (roughly 30B or more): the expansion loop's pivot interface is the tool set an autonomous investigator would use, and the replay harness can score one on frozen real cases.
