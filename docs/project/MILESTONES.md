# ROMULUS roadmap and milestone checklists

_Rewritten 2026-10-19 after the owner's direction changes (ADR-005, ADR-006). Track A (the AI investigating agent) added 2026-10-20 (ADR-007, ADR-008). This file supersedes the milestone list in spec §17; the spec is a set of suggestions, and this is the plan we actually follow._

Check an item only with **evidence**: a test, a results file, a commit or a demo note. The lead owns this file; subagents propose evidence, the lead verifies it. Status words: `implemented` · `locally tested` · `integration tested` · `lab evaluated` · `holdout evaluated` · `production validated`.

## Where we are going

**Goal (owner):** a tool a CPT can take to any mission network that finds indicators of compromise in host logs and network telemetry, correlates them, and helps the analyst follow leads. It works fully without a language model.

**Direction (decided):**
- **Deterministic floor** (ADR-006). The sweep, correlation and expansion find things with no model, and their results never depend on one.
- **An AI agent on top** (ADR-007, ADR-008). Teams run a powerful model on their own infrastructure, reached through any OpenAI-compatible endpoint. The lab uses a hosted API on public data only. The agent forms hypotheses from all the indicators, follows leads, finds more indicators, and writes the report's opening AI assessment. It adds cited, labelled findings and never removes or demotes any. Its wins become deterministic rules.
- **Host and network together.** auditd, journal and web logs; Suricata; Arkime sessions; packets through Arkime and TShark.
- **Breadth from research, not from the lab.** The ATT&CK v20 register, tool and LOTL catalogs and the backlog (`content/research/`) drive new detections. Evaluation datasets are dev sets only.
- **Trustworthy output stays non-negotiable.** Typed fields only, claims no stronger than their fields, honest negatives, every claim cited, read-only access.

## How we stay on track

1. **One plan.** This file. STATUS.md is the daily state; ADRs record hard-to-reverse decisions.
2. **Every detection change is scored.** The eval-custodian scores each change on the dev set (recall, P@10, false leads per hour, per-rule precision) and reports class-level misses only.
3. **Every semantic, adapter or security change is reviewed** by `reviewer` before merge.
4. **Overfitting guard.**
   - Rules are written from ATT&CK behaviour classes, with each threshold's rationale in its rule.
   - No scenario-specific values: no addresses, hosts or filenames from an evaluation dataset.
   - Dev-set numbers are labelled "dev set, optimistic".
   - Generalization claims need M6 evidence.
5. **Work split.**
   - **Lead:** sources, network, web and reports.
   - **Codex:** engine work in `romulus.agent` and the expansion engine, through `Claude-Codex.md`.
   - **`detection-engineer`:** rules and fixtures.
   - **`eval-custodian`:** scoring and datasets.
   - **`reviewer`:** gates.
6. **No mandatory demos.** Milestones close on evidence (tests, scores, review); the owner looks when useful.

## Owner decisions log (2026-10-19)

- **Models:** no multi-model bakeoff; the small local model stays as is; agentic hunt is a checkbox, off by default.
- **ADR-006 answers:** expansion depth 3; shared budget; context findings capped at `high`; report-page narrative action later.
- **Indicators:** a field-role indicator matcher instead of v1 substring search. v1 content is not kept as-is (15 ideas queued as `v1_ports`).
- **Arkime:** read through its session indices (read-only grant done). The viewer API is used only for packets.
- **Process:** no mandatory milestone demos.
- **Deferred:**
  - f_a holdout download;
  - a different-storyline dataset (later);
  - Malcolm (after deterministic search is built out);
  - a separate ground-truth account (not needed now).
- **Accepted:** ATT&CK Enterprise 20.0 STIX vendored.

## Owner decisions log (2026-10-20)

- **AI agent: build it** (ADR-008). It develops hypotheses from every indicator, follows further leads, finds more indicators and paints the bigger picture. The report opens with its overall hypothesis. The owner does not expect it to be always right; it is labelled and cited.
- **Model access** (ADR-007): one OpenAI-compatible adapter. Mission teams run their own powerful model, not public commercial APIs. Evaluation may use a hosted API on public data only, behind the bootstrap egress switch.
- **How to run it:** the lead's recommendation, accepted. A native tool-calling loop in an explicit controller, with SQLite as the only state, and no LangGraph or other agent framework (`docs/design/investigating-agent.md`).
- **Credentials page: deferred** (ADR-009). Configuration, including agent keys, stays in `.env` for now.

---

## M1: thin end-to-end slice. Accepted 2026-10-19

ES adapter, typed normalizers, 15 playbooks, decide/lanes, model investigator v1, web UI, report manifest, remote deployment. Reviewer gate concluded (ADR-004, option B). Open carry-over: a uv lockfile, generated on the VM.

## M2: evaluation and network foundation. Closing

- [x] Gold inventory for the dev set (27 opportunities, 22 observable), the evaluation protocol, and the scorer in `eval/`.
- [x] Investigator replay evaluation (small local model 0.22, rising to 0.53 with the v2 menu). The bakeoff was dropped (ADR-005).
- [x] Investigator v2 merged (`0bfd0d2`). Three-way ablation: off, deterministic and model are identical on findings, which led to ADR-006.
- [x] Host↔network correlation: the `net_socket` family, `host.interpreter_external_connection`, and `corr.process_network_link` (disk-staged, inferred links labelled). Reviewer passed.
- [x] Arkime session indices as a hunt target: `net_session`, long connections, beaconing, rare fingerprints. Integration tested.
- [x] Noise fix: grouping by program and port; kernel-lineage lane lowering; NTP verified by the parser goes to context.
- [x] Field-role indicator matcher (`ioc.indicator_match`) with a seed tool-name list.
- [x] Storage: a capped write-ahead log and `romulus db compact` (2.1 GB → 25 MB).
- [x] Scores (run 8): recall 12/22 reported and 17/22 surfaced (critical+high 12/13), P@10 0.90, 5.28 false leads per hour, 148/148 citations.
- [x] Pushed to GitHub: `main` fast-forwarded to `codex/expansion` on 2026-10-20 (owner direction).
- ~~Simple "standard searches" baseline~~ dropped by the owner (fixing gaps beats building a straw man).

## M3: deterministic expansion and the attack-path view. In progress

Goal: turn the five "evaluated, no rule matched" misses and the lead-only items into findings by judging records in context, and show the attack as a timeline.

- [x] **Codex, expansion round (completed and reviewer-passed 2026-10-20):**
  - `ses` normalization and honest IP timelines (the merge gate);
  - link fetchers;
  - the `ContextPlaybook` kind with two reference rules;
  - the deterministic loop (depth 3, anchor accounting, resume);
  - the incident graph in the manifest;
  - renaming `bakeoff` to `replay`.
- [x] `reviewer` gate on the expansion branch (PASS after live-found canonical ordering fix); merged to `main` and pushed 2026-10-20.
- [ ] **Context-rule catalog** (`detection-engineer`, from ATT&CK classes):
  - post-access discovery;
  - privilege probing and escalation;
  - credential access;
  - staging and transfer;
  - entry-point promotion;
  - lateral movement.

  Each has fixtures, including "the same events without the anchor must not fire".
- [ ] **Attack-path timeline page** (lead): rows by host, account and IP; solid, dashed and analyst link styles; filters with hidden counts; analyst-asserted links stored, never shown as proven.
- [ ] **Template narrative** per incident (deterministic) in the Markdown and JSON reports.
- [ ] **Scored:** recall on discovery and privesc rises without any class falling; false leads per hour stay within the ceiling; a determinism check passes.
- [ ] **Owner decision:** the false-leads-per-hour ceiling (PROTOCOL §14).

## Track A: the AI investigating agent. Accepted 2026-10-20

Goal: a hypothesis-driven agent that works every hunt after the deterministic layer, and a report that opens with its cited, labelled assessment. Design: `docs/design/investigating-agent.md`. Runs alongside M3 and M4. The engine is built by Codex through `Claude-Codex.md`, and `reviewer` gates every slice.

- [ ] **A1. Provider port** (lead, ADR-007):
  - `openai_compatible` and `ollama` adapters behind one interface;
  - truncation, usage and finish-reason checks for both;
  - egress class, the `ROMULUS_MODEL_EGRESS=lab-public-data` bootstrap switch and `MODEL_LOCAL_HOSTS`;
  - manifest provenance and banners;
  - per-hunt budgets;
  - doctor provider check;
  - `AGENT_*` keys in `.env.example`.
- [ ] **A2. Dossier and tools** (Codex):
  - the alias-based hunt dossier, with every finding, incident, gap and unexpanded anchor, paged and never silently cut;
  - read tools;
  - pivot tools over `PivotExecutor` and the expansion link fetchers;
  - complete or partial coverage state on every result.
- [ ] **A3. Controller and hypotheses** (Codex):
  - orient → investigate ×N → assess;
  - the `agent_hypotheses` table with history;
  - bounded sessions rebuilt from the DB, with breadth reservation and concurrency;
  - budgets, outage handling, `hunt resume`.
- [ ] **A4. Admission of agent output** (Codex):
  - `agent`-provenance findings, lane ≤ `high`, cites and claim checker;
  - agent links drawn as hypotheses;
  - notes;
  - `request_rule` items;
  - add-never-subtract tests.
- [ ] **A5. AI assessment in the report** (Codex for the manifest, lead for the renderers):
  - `ai_assessment` with sentence-level cites and kinds;
  - the deterministic checker and its removal counts;
  - labelled first section in Markdown, JSON and web;
  - template narrative fallback;
  - a "Re-run assessment" revision.
- [ ] **A6. UI and CLI** (lead):
  - New hunt "Run the AI agent" checkbox, on when a provider is reachable;
  - live view of hypotheses, tool calls and agent findings;
  - hypotheses tab;
  - `hunt start --agent/--no-agent`.
- [ ] **A7. Safety tests** (detection-engineer and Codex): spec scenario 13 extended to tool calls (injected close, benign or pivot instructions are ignored and flagged).
- [ ] **A8. Scored** (eval-custodian), agent on against off, per model, on the dev set and then a holdout:
  - incremental true positives;
  - added false leads per hour;
  - hypothesis and assessment accuracy at class level;
  - 100% citation validity;
  - cost and time;
  - deterministic findings identical either way.
- [ ] **A9. Agent wins become rules** (detection-engineer): each `request_rule` becomes a typed context rule with fixtures, or is retired with a reason.
- [ ] **Retire** the v2 menu investigator (`agent_mode=model|deterministic`) once A3 lands.

## M4: network and packet depth

Goal: use what the packets and kernel records can prove.

- [ ] **TShark on specific sessions:** fetch packets for explicit Arkime session IDs (byte cap, streamed), then run TShark with display filters built from typed fields. Never use `-c`, because it caps packets before the filter. The truncated-capture caveat applies.
- [ ] **Content rules on packets:** cleartext shell sessions, payload file type versus its claimed name, downloaded-script content (positive-only).
- [ ] **Network detections from the backlog:**
  - first-seen external destinations;
  - DNS tunnel shape;
  - horizontal sweeps;
  - self-signed or short-lived certificates;
  - protocol on a non-standard port (Arkime `protocols`).
- [ ] **Kernel-record host rules that can prove negatives** (ADR-004): file writes and deletes (`PATH nametype=CREATE/DELETE`), watched credential reads, exec from deleted or memfd files.
- [ ] **Lineage rules:** a shell started by a process holding an external connection (BL-02), and parent→child rarity (V1-03).
- [ ] **Coverage truth:** a fault-injection suite (caps, timeouts, shard failures, truncated PCAP) proving no false complete negatives.
- [ ] Scored per source: Arkime and PCAP recall on the dev set, and false leads per hour.

## M5: detection breadth

Goal: cover what CPTs meet, not what one dataset contains.

- [ ] **Coverage matrix** generated from the vendored STIX plus the research register (`docs/detection/ATTACK_COVERAGE.md`), checked in CI.
- [ ] **Backlog BL-01..BL-25 and lab-testable `v1_ports`** (V1-01..V1-07):
  - authorized-key write then login;
  - credential-material reads;
  - masquerading;
  - command-shape rarity;
  - cleanup sequences;
  - the baseline engine.
- [ ] **Indicator lists, tier 1:** analyst lists with attribution and expiry, plus STIX 2.1, MISP and CSV import, all typed and field-role matched.
- [ ] **Detection catalog page:** ATT&CK, tools, LOTL, themes and telemetry; applicability to current sources; per-rule performance; gaps. Plus tier 2 detection requests ("flag more like this").
- [ ] **Windows and AD normalizers and playbooks** (V1-08..V1-12 among them), against public EVTX datasets.
- [ ] **Sigma import** with upstream provenance (typed translation only).
- [ ] **Zeek normalizers,** and the OpenSearch/Malcolm source contract (fixtures first; the live Malcolm VM after deterministic search, per the owner).

## M6: generalization evidence

Goal: know how ROMULUS performs on data it was not built around. This can start alongside M4 and M5.

- [ ] **Attack-free noise check:** score false leads per hour on a clean window or clean lab data (no labels needed).
- [ ] **A different-storyline dataset with labels** (OTRF Security-Datasets, AIT-LDS, or an owner-run Atomic Red Team or emulation). Vetted, loaded with provenance, run blind, then scored.
- [ ] **Freeze before scoring:** rule-pack, list, config and model digests pre-registered (PROTOCOL §9 and §14); one run.
- [ ] **f_a holdout** (when the owner approves the download). It shows robustness to variants of the same storyline only.
- [ ] Owner-agreed targets checked: ≥90% of critical+high, ≥80% overall, P@10 ≥ 0.8, false leads under the ceiling. Where telemetry can't support a target, say so.

## M7: reports, settings, hardening

- [ ] **Executive DOCX** from a template, including the attack-path image; read-back consistency test; LibreOffice page renders.
- [ ] **Recommendations** linked to findings and ATT&CK mitigations; IOC export.
- [ ] **AI assessment in the executive DOCX** (Track A5's manifest section, labelled; template narrative when no agent ran).
- [ ] **Settings page** (ADR-009, deferred by the owner): lead-only credentials and provider settings in `settings.env`, write-only secrets, TLS first.
- [ ] **Triage:** suppressions with expiry; `lead`/`analyst` roles; detection catalog tier 3 (a typed local-rule builder, never DSL).
- [ ] **Hardening:** web TLS, security review (including the agent tools, the egress mode and the settings page), backup and restore drill, offline wheelhouse install, and the release gate review (spec §15 gates 1–9).

## After M7: standing work

Keep the research register current with each ATT&CK release and new advisories. Add telemetry families and datasets as missions meet them. Keep every coverage gap visible until it is closed or retired with a reason.
