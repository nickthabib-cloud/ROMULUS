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
expansion: anchors ─► typed links (lineage, session, flow, …) ─► context rules ─► incident graph
                            │
AI investigating agent (planned) ─► hypotheses, typed pivots, AI assessment
                            │
report ─► ReportManifest ─► JSON | Markdown | web (findings, incidents, narratives, timeline)
```

Coverage cells are written at every stage that can lose information (compile, execute, ingest, normalize, evaluate), so the report can say exactly what was and wasn't assessed.

## Packages (`src/romulus/`)

| Package | Responsibility |
|---|---|
| `config` | `.env` loading, secret redaction, runtime paths |
| `store` | SQLite schema, Alembic migrations, repositories, the single-writer coordinator |
| `sources` | Source profiles, field contracts, typed query compilation, read-only Elasticsearch/OpenSearch, Arkime and TShark adapters |
| `evidence` | Raw references, typed normalization with field lineage, entities |
| `baseline` | Pure versioned baseline specifications and canonical typed key extraction |
| `detect` | Playbooks and typed evaluators: sweep rules, context rules, packet rules, indicator lists |
| `decide` | Admission gates, lanes, priority, triage and suppressions |
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
