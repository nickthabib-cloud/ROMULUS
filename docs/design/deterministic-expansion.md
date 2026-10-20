# Deterministic expansion and the optional narrative model

## Goal

Find more of the attack without a model: start from what the sweep is sure about, follow typed links, and judge each linked record in that context. Show the result as an attack-path timeline so the analyst can see how everything happened and connect it. If a team has a model, it can pivot, explain leads, and write the story. Every finding, lane, link and coverage cell is the same with or without the model.

## Pipeline

```
sweep (unchanged) ─► expansion loop ─► incident graph ─► report manifest ─► attack-path timeline, lead explanations (optional model), narrative (template or model) ─► renderers
                      anchors → links → re-detect → new anchors
```

The sweep still publishes strong indicators immediately. Expansion starts when the sweep's direct findings are in, and it publishes its own findings as it goes.

## 1. Anchors

An anchor is an admitted finding in lane `urgent` or `high`. Leads are not anchors: they are reached *from* anchors and may be promoted by context (§3). Each anchor records why it is an anchor, its depth (sweep findings are depth 0) and the finding that spawned it.

## 2. Links

A link is a typed relation between an anchor's entity and other records. Each link type has a fixed strength:

| Link | Typed keys | Strength | Direction |
|---|---|---|---|
| Process lineage | host + `process.pid` / `process.ppid`, within one boot | observed | descendants; ancestors up to the session leader |
| Login session | host + auditd `ses` + `process.auid` | observed | whole session, both ways in time |
| Network flow | `network.community_id`, or the exact 5-tuple and time | observed | both ends of the flow |
| Same source IP | `source.ip` across hosts, inside the hunt window | observed (the value matches), inferred (the actor) | forward from the anchor |
| Account | `user.name` or `process.auid` on another host | observed value, inferred actor | forward from the anchor |
| Host after anchor | same `host.name`, anchor time to +N (named windows) | **inferred** | forward |

Observed links may support `urgent` and `high` context findings. A finding reached only through an inferred link is at most `lead` and is worded as a hypothesis ("…on the same host 4 minutes after F-12; no session link was recorded").

**Prerequisite:** normalize auditd `ses` as `process.session_id`. Today only `process.auid` is typed, so session links would fall back to auid + host + time, which is weaker.

Each link is fetched through the existing `PivotExecutor` (hunt layer, ADR-003). Its tools map to links: `process_tree` gives lineage, `auth_activity` gives account and session, `entity_timeline` gives host after anchor, and `ids_alerts` and the future `ip_sessions` give IP and flow. A capped or partial fetch keeps its exact uncovered ranges, as pivots do today.

## 3. Context rules

A new playbook kind, `kind = "context"`, beside `direct` and `aggregate`:

```python
class ContextPlaybook(Playbook):
    kind = "context"
    anchor_classes: ClassVar[tuple[str, ...]]   # e.g. ("initial_access", "remote_login", "web_shell")
    link_types: ClassVar[tuple[str, ...]]       # which links may carry this rule
    def consume_linked(self, anchor: Anchor, link: Link, events: list[TypedEvent]) -> list[Match]: ...
```

- It only runs on records reached through an allowed link from an allowed anchor class. It never runs in the sweep, so it cannot add noise to the full window.
- Its claim names the context: "`sudo -l` ran in login session 42 on web01, which began with the SSH login in F-7." It cites the record, the anchor finding and the link evidence (the session or lineage records).
- Lane comes from the rule and the link strength, capped by the table above. It uses the same `FindingDecision` admission as every other rule.
- **Negatives are scoped to the link.** "No discovery commands in session 42" is complete only if that session's fetch was complete and every record had the required fields. Otherwise the cell is `unresolved`. Rules that read argv or script text stay positive-only (ADR-004).
- Same fixture rule as other playbooks: a positive fixture and adversarial negatives, plus a case with the same events *without* the anchor, which must not fire.

**Starter classes, chosen by ATT&CK behaviour and not by any dataset's commands:**

| Class | Fires when, after an anchor |
|---|---|
| Post-access discovery | identity, host, network, user and permission enumeration (T1033, T1082, T1016, T1087, T1069) in the anchor's session or lineage |
| Privilege probing and escalation | `sudo -l`, SUID searches, a uid→euid change, or capability use in the session |
| Credential access | reads of credential stores, history files or key files by the session |
| Staging and transfer | a downloader or archiver in the session, or a new outbound flow from the session's host |
| Entry-point promotion | a lead (for example a remote login) whose session contains an anchor-class finding becomes `high` with the claim "session that later performed F-…" |
| Lateral movement | a new login from the anchor host or account to another host (the new host becomes an expansion target) |

`detection-engineer` owns the catalog and fixtures. Each class gets a coverage row like any other rule.

## 4. The loop

```
frontier ← anchors from the sweep (depth 0)
while frontier and budget remains:
    a ← pop(frontier)                  # order: lane, severity, earliest time; breadth reserve per host
    for link in links_for(a):          # fixed order; each (anchor, link, window) key runs once
        events ← PivotExecutor.fetch(link)
        matches ← direct pack(events) + context pack(a, link, events)
        for m in admitted(matches):
            publish(m, source_anchor=a, link=link)
            if m.lane in (urgent, high) and m is new: frontier.push(anchor(m, depth=a.depth+1))
stop reason ∈ {fixpoint, depth_limit, budget, source_failure}
```

- **Deterministic.** The same sweep, pack and sources give the same anchors, links, findings and order. Two runs must produce identical manifests (a CI test plus a lab check).
- **Budgets:** maximum depth (default 3), source queries, wall clock, and a per-host breadth reserve so one busy host cannot take everything. Hitting a budget leaves explicit unexpanded anchors in the report, never silence.
- **Accounting:** every anchor is `expanded_complete`, `expanded_partial` (with uncovered ranges) or `unexpanded` (with a reason). This replaces seed and case accounting for the report's Investigations section.
- **Reuse:** the current `options.py` window and duplicate-key logic, `PivotExecutor`, leases and resume. Expansion resumes after a crash without rerunning the sweep, as the agent does today.

## 5. Incident graph and attack path

- Nodes: findings and leads, plus entities. Edges: links, typed and marked observed or inferred.
- Incidents: connected components over observed edges. Inferred edges may join components only as labeled hypotheses, drawn dashed, and never merge two incidents in the counts.
- Each incident is ordered by time and tagged with ATT&CK tactics from its rules. It names its entry point, the hosts and accounts touched, and its open ends (unexpanded anchors, unresolved links).
- The incident graph is part of the report manifest, so the web attack-path page, Markdown, JSON and DOCX all render from it.

### Attack-path timeline (the main analyst view)

The owner's main use: see the indicators on a timeline and connect them. The attack path is a hypothesis until it is proven.

- **Rows:** hosts, accounts and external IPs. **X-axis:** time in UTC. **Dots:** findings and leads, coloured by lane; clicking one opens the finding detail with the raw record and predicate fields highlighted.
- **Three link styles, never mixed up:**

  | Style | Meaning | Source |
  |---|---|---|
  | Solid | Proven: a typed key matched (process lineage, login session, network flow, exact IP or account value) | expansion (§2) |
  | Dashed | Suggested: same host or close in time only; a hypothesis | expansion (§2, inferred links) |
  | Analyst | Drawn, confirmed or rejected by an analyst, with a note | the UI; stored with the analyst's name and time |

- An analyst-asserted link is never shown or reported as proven. Rejecting a suggested link keeps it in the record (hidden by default, counted).
- **Filters:** lane, host, entity and time range. The default view shows urgent and high findings and the leads linked to them. A visible count says how many items the filter hides, with one click to show all (no silent loss).
- **Reports:** the Markdown and DOCX reports carry the same timeline (as an image plus a table of every link with its style, key and evidence), rendered from the manifest.

## 6. Narrative: template or model

The narrative is drafted **after** the manifest revision is final, one incident at a time, plus one executive summary.

**Template (always available).** Deterministic text per incident: entry point, then each finding in time order with its claim, then the open ends and coverage caveats. It is plain and complete. It is the default with no model and the fallback whenever the model step fails.

**Model (optional).**

- Input per incident: alias cards for its findings (`F1…`), links (`L1…`) and caveats (`K1…`), with claims and lanes. No raw telemetry. That keeps each call well inside 8k tokens and keeps attacker text out.
- Output (constrained schema): a list of sentences, each `{text ≤ 300 chars, cites: [F/L/K aliases, 1–4], kind: observed | inferred | caveat}`.
- A deterministic checker removes any sentence that cites nothing, cites an unknown alias, or calls something observed when its citations are inferred. The removals are counted and shown.
- The executive summary is drafted the same way from the incident summaries.
- Stored with the report revision: model, digest, prompt digest, per-sentence citations and checker results. The renderers label the section "Drafted by a language model from the cited findings".
- The model has no other role. It cannot change findings, lanes, coverage or incidents.

**Redraft later.** A "Draft narrative" action on the hunt or report page creates a new report revision with the model narrative. A team that adds a model later can use it on old hunts.

## 6b. Lead explanations (optional model)

Leads are where the rules can't decide, and where analyst time goes (41 of 97 surfaced items on the dev set were benign). With a model, each lead can get:

- a plain-English explanation of its command line, script or connection (what it does, decoded if obfuscated);
- the model's opinion, `looks suspicious` or `looks routine`, with one sentence of reasoning.

**What this is not.** It is not filtering, not a score threshold and not a lane change. v1 lost standalone indicators because admission needed a high score plus corroboration, and capped retrieval dropped late activity (spec §2, lessons 2 and 3). This feature has none of that:

- every lead is always listed and counted; the opinion is a label next to it;
- the default sort stays deterministic (lane, severity, time);
- "sort by model opinion" is an optional toggle in the leads list, and the report never uses it;
- the model sees one lead's alias card at a time, never raw telemetry from other records, and cannot change any finding, lane, link or coverage cell;
- the label is marked "model opinion" everywhere it appears.

**Known failure mode.** Sneaky attacker activity is designed to look routine, so the model will call some of it routine. That is exactly why it can only label, never hide.

**Gate before building.** Run a replay test on the 97 adjudicated dev-set items first (eval-custodian). Report:

1. how many attacker items (Tier A hits and `true_unlisted`) the model calls `looks routine` (the "sneaky miss" count; this is the number that matters);
2. whether sorting by its opinion puts attacker items higher than the deterministic order (P@10, P@20 over leads);
3. explanation accuracy on a sample, rated by the lead.

Ship the explanations if they are accurate. Ship the opinion label and sort toggle only if (2) beats the deterministic order. In either case show the sneaky-miss count in the release notes. Repeat on a holdout before any claim.

## 7. New hunt page and CLI

**Web (`new_hunt.html`, `POST /hunts`).** A new field:

```
[x] Use a language model to explain leads and draft the narrative
    Model: <model> at <model host> — reachable.
    Without a model, leads have no explanations and ROMULUS writes a plain narrative from the findings.
    Detection, lanes and the attack-path timeline are the same either way.
```

- The page runs the existing Ollama reachability check when it loads. Checked by default only when a model is configured, reachable and pulled. Otherwise it is unchecked and disabled, with the reason ("No model configured" or "Model endpoint not reachable").
- The form posts `narrative=model|template`. The handler validates the value (same pattern as `style`) and passes `--narrative` to the CLI. The hunt manifest and audit record the choice.
- If a model was chosen but fails at narrative time, the hunt still completes. The report uses the template narrative and says why.

**CLI.** `hunt start --narrative model|template` (default from `NARRATIVE_MODE`, else `template` when `OLLAMA_URL` is empty). `report <hunt> --narrative model` redrafts. `--no-agent` and `--agent-mode` are retired. `--no-expand` is kept for evaluation ablations only and is hidden from `--help`.

**Config and doctor.** `OLLAMA_URL` may be empty, and its default becomes empty. No address is hard-coded in `config.py`; each install sets its own in `.env`. With no URL, doctor reports `ollama: not configured (narrative uses template)` as `info`, not `fail`. With a URL, the existing private-address, reachability, model and `num_ctx` checks stay.

## 8. Invariants

| Invariant | How this design keeps it |
|---|---|
| A mention is not an action | Links and context rules use typed fields only. The claim names the link. |
| Strong indicators first | Sweep publishing is unchanged. Expansion adds findings afterwards. Correlation is secondary and inferred links are labeled. |
| Complete negatives or `unresolved` | Context negatives are scoped to a link and only complete when its fetch was complete. Capped fetches keep exact uncovered ranges. |
| Nothing lost | Incidents and narratives are in the manifest. Unexpanded anchors and removed narrative sentences are listed. |
| Model output validated; telemetry untrusted | The model sees alias cards, not telemetry, and outputs cited sentences only. A checker removes unsupported ones. |
| Read-only, no external transmission | Expansion uses the existing read-only adapters. The model endpoint must be a private or host-only address (ADR-007 allows a hosted model in the lab on public data only). |

## 9. Measurement and acceptance

On the dev set and, before any claim, on a holdout (f_a or a different storyline):

- **Recall.** Target the 5 "evaluated, no rule matched" misses and the leads with an anchor in session (report the count reached, with intervals). Recall must not fall in any class.
- **Noise.** False leads per hour must not rise above the owner's ceiling (pending, PROTOCOL §14). Every context finding is adjudicated.
- **Determinism.** Two runs produce identical manifests apart from timing.
- **Model independence.** With the model on and off, findings, lanes, coverage and incidents are identical; only the narrative differs.
- **Timeline.** Every link in the manifest is drawn with the right style; no proven link rests on an inferred key; filtered counts add up to the manifest totals.
- **Lead explanations.** The §6b replay gate, including the sneaky-miss count.
- **Narrative.** 100% of published sentences cite valid aliases. Report the share of removed sentences and an analyst rating of a sample. The replay harness is repurposed to freeze incident cards and score drafts.
- **Overfitting guard.** Context-rule fixtures are written from ATT&CK classes before looking at dev-set misses per opportunity. The eval-custodian scores; nobody else reads ground truth.

## 10. Work split and order

| Step | Piece | Owner |
|---|---|---|
| 1 | Normalize auditd `ses`; session and lineage link fetchers | Codex |
| 2 | `ContextPlaybook` kind, coverage rows and the starter classes with fixtures | `detection-engineer`; Codex for engine changes |
| 3 | Expansion loop, anchor accounting, resume (reusing `PivotExecutor` and the options logic) | Codex via `Claude-Codex.md` |
| 4 | Incident graph in the manifest; attack-path timeline page, analyst-asserted links, report rendering | Codex (manifest), lead (web page and reports) |
| 5 | Template narrative; model narrative, checker and redraft action; lead explanations after the §6b gate | lead; eval-custodian runs the gate |
| 6 | New hunt option, CLI flags, doctor `info` state | lead |
| 7 | Ablation (expansion on/off; narrative template/model) and holdout scoring | eval-custodian |
| — | Review of steps 1–4 before merge | `reviewer` |

Steps 5 and 6 do not depend on 1–4 and can run in parallel. The template narrative only needs findings in time order until the incident graph lands. The §6b replay gate needs no new product code and can run now.

## Owner decisions (2026-10-19)

1. **Depth and budget:** maximum expansion depth 3; expansion shares the hunt's wall-clock budget.
2. **Lanes:** a context finding reached through an observed link is capped at `high` until context rules are lab evaluated; then the cap is revisited.
3. **Report page:** yes, a "Draft narrative and explain leads" action for existing hunts, built after the deterministic work (low priority).
4. **Investigator v2:** landed on `m2/evaluation` (`0bfd0d2`); model-pivot work stops. Agent mode stays available behind the New hunt checkbox, off by default.

Order of work agreed: noise fix and the field-role indicator matcher (lead), Arkime and TShark (lead), expansion engine and context rules (Codex, detection engineer, reviewer), then backlog detections; the eval-custodian scores after each step.
