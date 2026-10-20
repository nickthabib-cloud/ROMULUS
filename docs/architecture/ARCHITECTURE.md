# ROMULUS architecture

The hand-written part (this file) explains intent and boundaries. `MODULE_MAP.md` is **generated** from the code by `python scripts/archmap.py` and is checked by `--check`, so it cannot drift. When they disagree, the code and the generated map win; fix this file.

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
mission ─► sources.inventory ─► SourceProfile + FieldContract
   │
   ▼
planner ─► SearchIntent ─► sources.compile ─► CompiledQuery ─► adapter ─► SearchOutcome
                                                                    │
                       evidence.normalize ◄── RawReference ◄────────┘
                               │
                         TypedEvent + Entity
                               │
              detect (playbooks/rules) ─► Candidate ─► decide ─► Finding (lane)
                               │                          ▲
                               ▼                          │
                agent (cases ─► brief ─► model ─► validate ─► pivot SearchIntent)
                               │
                 correlate ─► CorrelationEdge / AttackPath
                               │
                 report ─► ReportManifest ─► JSON | Markdown | DOCX | web
```

Coverage cells are written at every stage that can lose information (compile, execute, ingest, normalize, evaluate).

## Planned package layout (`src/romulus/`)

| Package | Responsibility (spec §3 table) | Status |
|---|---|---|
| `config` | `.env` loading, redaction, runtime paths | planned |
| `store` | SQLAlchemy Core tables, migrations, repositories, write coordinator | planned |
| `mission` | Hunt manifest, lifecycle state machine | planned |
| `sources` | Profiles, field contracts, compilers, ES/OpenSearch/Arkime/TShark adapters | planned |
| `evidence` | Raw references, normalizers per event family, entities | planned |
| `detect` | Playbook/rule loader and evaluators, coverage ledger | planned |
| `decide` | Admission gates, lanes, priority, triage, suppressions | planned |
| `agent` | Case queue, brief builder, model client, proposal validation, pivot tools | [M1 design](../design/model-investigator.md) |
| `correlate` | Entity graph, edges, attack path | planned |
| `report` | Manifest, renderers, recommendations | planned |
| `web` | FastAPI app, templates, static (vendored) assets, auth | planned |
| `cli` | Typer/argparse entry points | planned |
| `worker` | Background hunt process | planned |

Other top-level directories: `content/` (playbooks, rules, fixtures, vendored ATT&CK), `tests/`, `scripts/`, `docs/`.

## Dependency rules (enforced by `archmap.py --check`)

- `web` and `cli` may import anything below them, but nothing imports `web` or `cli`.
- `detect`, `decide`, `correlate`, and `report` never import `sources` adapters directly. They work on stored typed data.
- `agent` emits validated typed pivots without importing any module under `romulus.sources`. The hunt-layer executor described in
  ADR-003 converts them to `SearchIntent`s and owns source access.
- `store` imports no domain logic packages.

Update this section and `LAYER_RULES` in `scripts/archmap.py` together.
