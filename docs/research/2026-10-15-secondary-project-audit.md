# ROMULUS secondary project audit

**Date:** 2026-10-15
**Scope:** Repository state after the intelligence asset, reference, query-language, sequence, aggregate, baseline, and operator-document corrections.
**Status:** Complete. All critical and important findings from this audit were corrected; no critical or important finding remains open.

## Findings recorded before repair

### Important — offline sequence and aggregate coverage was always partial

`HuntEngine._analyze` passed an empty live-search outcome list to the sequence and aggregate engines in offline mode. Those engines correctly interpret an empty outcome ledger as missing required telemetry, so every executable rule without a match became `partial`, and a matching high-priority result could not become corroborated. Baseline evaluation already passed `None` in offline mode to mean that the supplied fixture is the complete authorized source. Sequence and aggregate evaluation need the same contract.

### Important — structured process fields did not reliably derive execution signals

The sequence signal adapter recursively collected raw **values**, but some signal patterns searched that value string for literal field names such as `process.command_line`, `process.executable`, and `destination.ip`. A normal structured event with `process.command_line: /opt/payload` therefore failed to derive `execute` or `host_behavior` unless the value independently contained a shell keyword. The sequence, aggregate, and baseline field readers also handled nested ECS objects but not equivalent flat dotted keys returned by some adapters. Both representations need the same field-aware behavior.

### Important — one evidence record could satisfy multiple sequence stages

The ordered and unordered sequence walkers did not reject an evidence record already selected for an earlier stage. A single command event that carried several derived signals could therefore appear to complete a multi-event relationship. Stage selection must require distinct evidence IDs before a sequence can become a candidate.

### Important — baseline history had two unbounded dimensions

Baseline updates capped the number of scopes and the values stored inside each scope, but the reverse `value_scopes` index could accumulate unlimited distinct values across completed hunts. Deviation metrics could also accumulate unlimited new scopes across hunts. Both persisted dimensions need explicit limits so long-running deployments retain a predictable storage bound, and a reached history limit must turn later coverage partial rather than allowing a negative conclusion from incomplete history.

### Minor — status construction contained a duplicate key

The behavior-pack status dictionary assigned `capability_references` twice. Python retained only the second value, so current output happened to be correct, but the duplicate obscured which source was authoritative.

### Minor — obsolete helpers remained after architecture changes

Static reference scanning found private helpers that had no runtime or test caller after model-created hypotheses and older time-window paths were removed. These were `_summarize`, `_normalize_hypotheses`, `_timestamp_bounds`, and `_arkime_time_window` in the workflow, `stage_from_analytic` in the rule model, and `customer_visible_candidates` in the behavior catalog. The retained `_pcap_time_filter` still has a tested compatibility consumer.

### Minor — report and README limitation wording was logically inverted

Two operator-facing sentences said “No finding is not proof” or “No finding is never a claim.” The intended statement is that the absence of findings does not prove the environment is clean.

## Checks with no defect found

- Source-stage validation maps Elasticsearch to Query DSL, Arkime to Arkime expressions, and TShark to display filters; cross-language stages fail closed.
- Generated pack hashes and counts reconcile with 902 curated behaviors, 1,216 capability references, and the 697-technique pinned ATT&CK catalog.
- The largest tracked intelligence files are declared in the asset registry with an owner and consumer. The large corpus is authoritative input; the generated packs are hash-checked runtime products.
- The duplicate-file scan found copies only under ignored runtime/worktree directories. They are not tracked release content.
- Current untracked SL700 import files and operations notes predate this audit task and are excluded from its commits.

## Repair and verification

### Repairs completed

- Offline sequence, aggregate, and baseline evaluation now share the same complete-fixture coverage contract.
- Sequence stages require distinct evidence records and still enforce the declared order, time window, source family, and entity joins.
- Sequence signals use structured process, network, event-code, and outcome fields. Sequence, aggregate, and baseline readers accept nested ECS objects and flat dotted fields.
- Baseline state now caps total distinct values and deviation scopes as well as per-scope values. Reaching a history bound is persisted and makes later evaluation `partial` through `baseline_history_limit`.
- The duplicate status key and six unreachable private helpers were removed.
- Operator-facing absence-of-findings wording was corrected.
- This audit is registered as an owned operator document and linked from the intelligence index.

### Verification completed

- Focused intelligence, catalog, report, and asset suite: 55 tests passed.
- Complete discovered suite: 226 tests passed; 6 optional-dependency checks skipped.
- Python syntax compilation completed for `romulus`, `scripts`, and `main.py`.
- Behavior-pack reproducibility check passed: 549 direct, 89 sequence, 206 aggregate, 58 baseline, and 1,216 capability records.
- Generated priority inventory check passed for all 902 curated behaviors.
- Intelligence asset audit passed with 902 curated behaviors, 1,216 capability references, and 697 ATT&CK techniques.
- Static dead-reference scan left only one tested compatibility helper and two public Arkime adapter methods.
- Git whitespace and generated-file checks passed.

### Remaining verification limits

- Six integration checks require optional installed dependencies such as LangGraph, the Elasticsearch client, Requests, or the full Word-report environment and were skipped by the bundled test runtime.
- This audit did not contact live Elasticsearch, Arkime, Ollama, or packet sources. Source availability, credentials, target mappings, and local traffic still require `python main.py doctor` and an authorized live hunt on the deployment host.
- Ignored runtime validation reports and an old ignored worktree contain duplicate files, but they are outside tracked release content.
- The 266 curated reference-only behaviors retain explicit missing-semantics reasons. They remain visible gaps and cannot execute or create findings.
