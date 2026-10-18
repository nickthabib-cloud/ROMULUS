# ROMULUS architecture

The hand-written part (this file) explains intent and boundaries. `MODULE_MAP.md` is **generated** from the code by `python scripts/archmap.py` and is checked by `--check`, so it cannot drift. When they disagree, the code and the generated map win; fix this file.

## Runtime topology

```
 Windows host (192.168.36.1)              Ubuntu VM (192.168.36.128)
 ┌──────────────────────┐                ┌───────────────────────────────────────────┐
 │ Ollama :11434 (GPU)  │◄── HTTP ───────│ romulus web (FastAPI/HTMX/SSE)            │◄── analyst browser
 └──────────────────────┘                │ romulus worker (hunt controller)          │
                                         │   │ SQLite (WAL) — single state authority │
                                         │   ├─► Elasticsearch :9200 (read-only)     │
                                         │   ├─► Arkime viewer :8005 (read-only)     │
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
| `agent` | Case queue, brief builder, Ollama client, proposal validation, pivot tools | planned |
| `correlate` | Entity graph, edges, attack path | planned |
| `report` | Manifest, renderers, recommendations | planned |
| `web` | FastAPI app, templates, static (vendored) assets, auth | planned |
| `cli` | Typer/argparse entry points | planned |
| `worker` | Background hunt process | planned |

Other top-level directories: `content/` (playbooks, rules, fixtures, vendored ATT&CK), `eval/` (harness code only; no labels), `tests/`, `scripts/`, `docs/`.

## Dependency rules (enforced by `archmap.py --check`)

- `web` and `cli` may import anything below them, but nothing imports `web` or `cli`.
- `detect`, `decide`, `correlate`, and `report` never import `sources` adapters directly. They work on stored typed data.
- `agent` reaches sources only through `sources.compile` with typed `SearchIntent`s.
- `store` imports no domain logic packages.

Update this section and `LAYER_RULES` in `scripts/archmap.py` together.
