# ROMULUS architecture

This file explains intent and boundaries. `MODULE_MAP.md` is **generated** from the code by `python scripts/archmap.py` and is checked by `--check`, so it cannot drift. When they disagree, the code and the generated map win; fix this file.

## Runtime topology

```
 Model server (optional)                  ROMULUS host (Linux)
 ┌──────────────────────┐                ┌───────────────────────────────────────────┐
 │ OpenAI-compatible or │◄── HTTP ───────│ romulus web (FastAPI/HTMX/SSE)            │◄── analyst browser
 │ Ollama endpoint      │                │ romulus worker (hunt controller)          │
 └──────────────────────┘                │   │ SQLite (WAL) — single state authority │
                                         │   ├─► Elasticsearch/OpenSearch (read-only)│
                                         │   ├─► Arkime viewer (read-only)           │
                                         │   └─► tshark on PCAPs (allowlisted dirs)  │
                                         └───────────────────────────────────────────┘
```

## Hunt data flow

```
mission ─► source inventory ─► SourceProfile + FieldContract
   │
   ▼
sweep: SearchIntent ─► compile ─► CompiledQuery ─► adapter ─► SearchOutcome
                                                                 │
                    evidence.normalize ◄── raw records ◄─────────┘
                            │
                     TypedEvent + entities
                            │
           detect (playbooks) ─► Candidate ─► decide ─► Finding (lane)
                            │
packet stage: Arkime sessions ─► packets ─► TShark ─► http_body events ─► packet rules
                            │
evidence ranking, pass 1 ─► Reported set ─► expansion seeds
                            │
expansion: anchors ─► typed links (lineage, session, flow, …) ─► context rules ─► incident graph
                            │
evidence ranking, pass 2 ─► ranked findings and entities (report manifest)
                            │
AI investigating agent (planned) ─► hypotheses, typed pivots, AI assessment
                            │
report ─► ReportManifest ─► JSON | Markdown | web (findings, incidents, narratives, timeline)
```

Coverage cells are written at every stage that can lose information (compile, execute, ingest, normalize, evaluate), so the report can say exactly what was and wasn't assessed.

## Evidence ranking

A finding's lane is its rule's own estimate. The report's headline comes instead from the structure of the evidence in the hunt itself (`decide/rank.py` holds the model, `hunt/rank.py` runs it, `store/ranks.py` stages and stores it):

- **Confirmed** findings (lane `urgent`) are always reported on their own.
- Every other admitted finding (`high` or `lead`) is in the **ranked pool**. Context and suppressed records stay outside it as supporting records.
- **Entities.** A host-telemetry finding counts toward its host and account. A network-telemetry finding counts toward its endpoints: internal addresses first, at most two. An internal endpoint is the host whose own telemetry owns that address unambiguously in the hunt, else the address; an external endpoint is an `ip` entity. A network sensor is never an entity, and well-known principals that exist on every host (SYSTEM, root) are not entities. A finding with none of these is `unattributed`: it is ranked on its own prior and listed.
- **Entity evidence**, from the hunt's deterministic findings only: confirmed findings (U), ATT&CK tactic breadth (T: a maximum matching of rules to the tactics each maps to, so each rule adds at most one tactic; tactics come from the vendored ATT&CK data), distinct rules (R), and pairs of rules that fire within an hour of each other (C, capped). A rule that fires on at least half of the hunt's hosts with any deterministic candidate (and at least three) over at least half of the window is *recurring fleet-wide*: it counts toward no entity, and its findings rank lower but are never removed. A short burst across the fleet is not penalized.
- **Entity score** = 40·U + 10·T + 5·R + 3·C + the strongest rule prior among its findings. **Finding rank** = its best entity's score + its own rule prior, less 30 for a recurring fleet-wide rule; ties break on time, then id. Every score carries its reasons.
- **Reported set**: every confirmed finding, plus every pool finding on an entity that meets the evidence bar (U ≥ 1, or T ≥ 2, or R ≥ 3 with C ≥ 1). It is a structural criterion, not a count budget. Nothing is hidden: findings below the bar are listed in rank order.
- Findings the AI agent proposes are ranked like any other, but never count toward an entity's evidence, so the model cannot raise the rank of its own targets.

Pass 1 runs after the sweep, packet and baseline stages and adds to expansion's seeds. The findings the rule estimate seeds (urgent and high) keep their budget share and order; the rest of the Reported set is anchored after them, in rank order, and spends only the budget left. Anchors the budget does not reach stay listed with the budget reason, so expansion never does less than it did by the rule estimate alone. Pass 2 runs after expansion and its context pass. Each pass is computed in keyset pages over temporary staging tables, so memory is bounded by one page whatever the hunt's size, and is published in one transaction that replaces the hunt's previous rows for that pass. A hunt stored without ranks renders exactly as it did.

## Packages (`src/romulus/`)

| Package | Responsibility |
|---|---|
| `config` | `.env` loading, secret redaction, runtime paths |
| `store` | SQLite schema, Alembic migrations, repositories, the single-writer coordinator |
| `sources` | Source profiles, field contracts, typed query compilation, read-only Elasticsearch/OpenSearch (one request allowlist per flavor, flavor and version confirmed from the cluster), Arkime and TShark adapters |
| `evidence` | Raw references, typed normalization with field lineage, entities |
| `baseline` | Pure versioned baseline specifications and canonical typed key extraction |
| `detect` | Playbooks and typed evaluators: sweep rules, context rules, packet rules, indicator lists |
| `decide` | Admission gates, lanes, priority, triage and suppressions; the evidence-ranking model |
| `hunt` | Hunt orchestration: manifest, sweep, packet stage, deterministic expansion, pivots, resume |
| `agent` | Optional model investigator today: cases, briefs, validated decisions, typed pivots. The planned AI investigating agent builds on it: [`ai-investigating-agent.md`](ai-investigating-agent.md) |
| `report` | Report manifest, incident graph and narratives, attack-path timeline layout, renderers |
| `web` | FastAPI app, server-rendered templates, local auth |
| `replay` | Replaying frozen investigator briefs through the model decision path |
| `cli`, `doctor` | Command-line entry points and environment checks |

Other top-level directories: `content/` (indicator lists, vendored ATT&CK), `tests/`, `scripts/`, `docs/`.

## Dependency rules (enforced by `archmap.py --check`)

- `web` and `cli` may import anything below them, but nothing imports `web` or `cli`.
- `detect`, `decide`, and `report` never import `sources` adapters directly. They work on stored typed data.
- `agent` emits validated typed pivots without importing any module under `romulus.sources`. The hunt-layer pivot executor converts them to `SearchIntent`s and owns source access.
- `baseline` defines source-neutral typed keys and imports neither `hunt` orchestration nor `sources` adapters.
- `store` imports no domain logic packages.

Update this section and `LAYER_RULES` in `scripts/archmap.py` together.
