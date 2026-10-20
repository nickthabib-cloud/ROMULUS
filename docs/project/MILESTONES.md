# ROMULUS roadmap and milestone checklists

_Rewritten 2026-10-19 after the owner's direction changes (ADR-005, ADR-006). Track A (model providers, settings page, capable-model agent) added 2026-10-20 (ADR-007/008/009, proposed). This file supersedes the milestone list in spec §17; the spec is a set of suggestions, and this is the plan we actually follow._

Check an item only with **evidence**: a test, a results file, a commit or a demo note. The lead owns this file; subagents propose evidence, the lead verifies it. Status words: `implemented` · `locally tested` · `integration tested` · `lab evaluated` · `holdout evaluated` · `production validated`.

## Where we are going

**Goal (owner):** a tool a CPT can take to any mission network that finds indicators of compromise in host logs and network telemetry, correlates them, and helps the analyst follow leads. It works fully without a language model.

**Direction (decided):**
- **Deterministic first** (ADR-006). The sweep, correlation and expansion find things. A model, if a team has one, only explains leads and drafts narrative, and it is off by default.
- **A capable model is tested, not assumed** (proposed, ADR-007/008). Any OpenAI-compatible endpoint can serve the model. That covers a strong local server on a mission kit, and a hosted API on public lab data only. A real tool-calling agent is built only if a mission-class model passes a pre-registered replay gate. It can add cited findings but never remove any. Its wins become deterministic rules.
- **Host and network together.** auditd, journal and web logs; Suricata; Arkime sessions; packets through Arkime and TShark.
- **Breadth from research, not from the lab.** The ATT&CK v20 register, tool and LOTL catalogs and the backlog (`content/research/`) drive new detections. The e_a lab is a dev set only.
- **Trustworthy output stays non-negotiable.** Typed fields only, claims no stronger than their fields, honest negatives, every claim cited, read-only access.

## How we stay on track

1. **One plan.** This file. STATUS.md is the daily state; ADRs record hard-to-reverse decisions.
2. **Every detection change is scored.** The eval-custodian scores each change on e_a (recall, P@10, false leads per hour, per-rule precision) and reports class-level misses only.
3. **Every semantic, adapter or security change is reviewed** by `reviewer` before merge.
4. **Overfitting guard.**
   - Rules are written from ATT&CK behaviour classes, with each threshold's rationale in its rule.
   - No scenario-specific values: no addresses, hosts or filenames from e_a.
   - e_a numbers are labelled "dev set, optimistic".
   - Generalization claims need M6 evidence.
5. **Work split.**
   - **Lead:** sources, network, web and reports.
   - **Codex:** engine work in `romulus.agent` and the expansion engine, through `Claude-Codex.md`.
   - **`detection-engineer`:** rules and fixtures.
   - **`eval-custodian`:** scoring and datasets.
   - **`reviewer`:** gates.
6. **No mandatory demos.** Milestones close on evidence (tests, scores, review); the owner looks when useful.

## Owner decisions log (2026-10-19)

- **Models:** no multi-model bakeoff; qwen3:8b; agentic hunt is a checkbox, off by default.
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

## Owner proposals (2026-10-20), shape pending sign-off

- **API-key model provider** (for example OpenAI) as a stand-in for the strong local model a team would run. Recommended shape: ADR-007. Build one OpenAI-compatible adapter, which also reaches vLLM, llama.cpp and Ollama `/v1`. Remote endpoints only with a bootstrap-file egress switch, only on public lab data, with a banner on every hunt and report. Evaluate a frontier model as the ceiling and a mission-class open-weight model as what actually ships.
- **A real investigating agent; LangGraph reconsidered.** Recommended shape: ADR-008. A stronger model removes ADR-001's small-model objection to tool-calling loops, but not its LangGraph objection. Run the replay gate first. Then build a native tool-calling loop over SQLite rows: the agent adds `agent`-provenance findings, at most `high`, and never subtracts.
- **Credentials page in the UI.** Recommended shape: ADR-009. Lead-only, writing `$ROMULUS_HOME/config/settings.env` atomically. Secrets are write-only, bootstrap keys can't be edited, and TLS is required before secret fields render.
- **Decisions the owner still owes:**
  - accept or amend ADR-007/008/009;
  - the per-hunt model spend ceiling;
  - which frontier and mission-class models to test;
  - the gate thresholds, which the eval-custodian pre-registers.

---

## M1: thin end-to-end slice. Accepted 2026-10-19

ES adapter, typed normalizers, 15 playbooks, decide/lanes, model investigator v1, web UI, report manifest, VM deployment. Reviewer gate concluded (ADR-004, option B). Open carry-over: a uv lockfile, generated on the VM.

## M2: evaluation and network foundation. Closing

- [x] Gold inventory for e_a v1 (27 opportunities, 22 observable), `docs/eval/PROTOCOL.md`, and the scorer in `eval/`.
- [x] Investigator replay evaluation (qwen3:8b 0.22, rising to 0.53 with the v2 menu). The bakeoff was dropped (ADR-005).
- [x] Investigator v2 merged (`0bfd0d2`). Three-way ablation: off, deterministic and model are identical on findings (`2026-10-19-sl700_e_a-ablation-456.md`), which led to ADR-006.
- [x] Host↔network correlation: the `net_socket` family, `host.interpreter_external_connection`, and `corr.process_network_link` (disk-staged, inferred links labelled). Reviewer passed.
- [x] Arkime session indices as a hunt target: `net_session`, long connections, beaconing, rare fingerprints. Live on the lab.
- [x] Noise fix: grouping by program and port; kernel-lineage lane lowering; NTP verified by the parser goes to context.
- [x] Field-role indicator matcher (`ioc.indicator_match`) with a seed tool-name list.
- [x] Storage: a capped write-ahead log and `romulus db compact` (2.1 GB → 25 MB).
- [x] Scores (run 8): recall 12/22 reported and 17/22 surfaced (critical+high 12/13), P@10 0.90, 5.28 false leads per hour, 148/148 citations.
- [ ] Push `m2/evaluation` to GitHub (owner; Claude's push is blocked).
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
- [x] `reviewer` gate on the expansion branch (PASS after live-found canonical ordering fix); merge remains with the lead/owner.
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

## Track A: model providers, settings page and the capable-model agent (proposed 2026-10-20)

Goal: stop editing `.env` by hand, and find out with numbers whether a capable model adds detection value. Runs alongside M3 and M4. A1–A3 are product work in any case. A5 happens only if A4's gate passes. Everything here waits on the owner's sign-off on ADR-007/008/009.

- [ ] **A1. Web TLS first** (lead; moved up from M7): `romulus web tls-init` (self-signed, under `$ROMULUS_HOME/tls/`), with the lab UI served over HTTPS. This is a prerequisite for A2.
- [ ] **A2. Settings page** (lead, ADR-009):
  - lead-only `/settings` for sources, model providers and hunt defaults;
  - the `settings.env` layer in `load_settings` with per-key source reporting;
  - write-only secrets;
  - bootstrap keys refused;
  - step-up password on save;
  - "Test" runs the doctor check on the submitted values;
  - tests for rendering, precedence, atomic write and redaction;
  - `reviewer` gate (security boundary).
- [ ] **A3. Model-provider port** (lead, ADR-007):
  - `ollama` and `openai_compatible` adapters behind one interface, with a provider per role;
  - truncation, usage and finish-reason checks for every adapter;
  - the egress class and `ROMULUS_MODEL_EGRESS=lab-public-data` bootstrap switch;
  - hunt and report banners;
  - manifest provenance;
  - per-hunt token and cost budget;
  - doctor provider check;
  - `reviewer` gate.
- [ ] **A4. Capable-model gate** (eval-custodian; no new agent code):
  - thresholds pre-registered first;
  - the replay harness on frozen v2 briefs with one frontier and one mission-class model;
  - the ADR-006 §6b lead-opinion replay (sneaky-miss count);
  - results in `docs/eval/results/`.

  Recommended pass bar: mission-class accuracy ≥ 0.80 (qwen3:8b scores 0.53), and sneaky misses no worse than the deterministic order.
- [ ] **A5. Tool-calling agent, only if A4 passes** (Codex via `Claude-Codex.md`; ADR-008):
  - design doc first;
  - a hunt dossier with read, pivot and proposal tools;
  - every turn and tool call is a SQLite row, and resume rebuilds from rows;
  - add-never-subtract (`agent` provenance, lane ≤ `high`, claim checker);
  - an "Agent contributions" report section;
  - the injection suite extended to tool calls;
  - `reviewer` gate.
- [ ] **A6. Agent wins become rules** (detection-engineer): each agent true positive the deterministic layer missed gets a `request_rule` item, turned into a typed context rule with fixtures, or retired with a reason.
- [ ] **A7. Scored** (eval-custodian), agent on against off, on e_a and then a holdout:
  - incremental true positives;
  - added false leads per hour;
  - 100% citation validity;
  - cost and wall time;
  - deterministic findings identical either way.

  The frontier-model numbers are labelled "ceiling, not deployable".

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
- [ ] Scored per source: Arkime and PCAP recall on e_a, and false leads per hour.

## M5: detection breadth

Goal: cover what CPTs meet, not what e_a contains.

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

## M7: reports, optional model features, hardening

- [ ] **Executive DOCX** from a template, including the attack-path image; read-back consistency test; LibreOffice page renders.
- [ ] **Recommendations** linked to findings and ATT&CK mitigations; IOC export.
- [ ] **Optional model** (ADR-006 §6–6b; any provider from Track A3):
  - lead explanations, after the replay "sneaky-miss" gate;
  - cited narrative drafts with a deterministic checker;
  - the report-page "draft narrative" action.
- [ ] **Triage:** suppressions with expiry; `lead`/`analyst` roles; detection catalog tier 3 (a typed local-rule builder, never DSL).
- [ ] **Hardening:** security review (including the settings page and the egress mode), backup and restore drill, offline wheelhouse install, and the release gate review (spec §15 gates 1–9).

## After M7: standing work

Keep the research register current with each ATT&CK release and new advisories. Add telemetry families and datasets as missions meet them. Keep every coverage gap visible until it is closed or retired with a reason.
