# ROMULUS v2

A defensive, AI-assisted threat-hunting tool.

ROMULUS runs a deterministic sweep over host and network telemetry: Elasticsearch/OpenSearch logs, Arkime sessions, and PCAPs read with TShark. Deterministic expansion then follows typed links from the strongest findings (process lineage, login session, network flow), judges the linked records in context, and assembles incidents. Every claim cites the raw evidence. ROMULUS works fully without a language model ([ADR-006](docs/adr/ADR-006-deterministic-expansion-optional-model.md)). An optional model can explain leads and draft the narrative.

*Planned (proposed 2026-10-20):*
- **Any OpenAI-compatible model endpoint.** That includes a strong local server such as vLLM or llama.cpp, and, on public lab data only, a hosted API ([ADR-007](docs/adr/ADR-007-model-providers-and-lab-egress.md)).
- **A capable-model investigating agent,** built only if it passes a measured gate ([ADR-008](docs/adr/ADR-008-capable-model-agent-no-langgraph.md)).
- **A settings page** for credentials ([ADR-009](docs/adr/ADR-009-settings-page-and-runtime-config.md)).

Outputs:

- ranked findings
- an attack path
- recommendations
- a technical Markdown/JSON report (an executive DOCX is planned)
- a browser UI for analysts

> **Status:** Milestone 1 (thin end-to-end slice) is **accepted**. M2 evaluation is closing and M3 (deterministic expansion) is in progress. Track A (model providers, settings page, capable-model agent) is proposed. This is lab software under active development and is not yet validated for production missions. See [`docs/project/STATUS.md`](docs/project/STATUS.md) for the current state and [`docs/project/MILESTONES.md`](docs/project/MILESTONES.md) for the roadmap.

## Detection scope

The goal is to find any malicious activity the telemetry can show, on any mission network. The detection catalog is built from systematic research:
- every MITRE ATT&CK Enterprise and ICS technique;
- the public detection corpora (Sigma, CAR, Atomic Red Team, LOLBAS/GTFOBins, ET Open and others);
- every telemetry family a hunt may meet: Windows, AD, Linux, macOS, identity and cloud logs, network devices, Zeek, Suricata, PCAP and ICS protocols.

A generated ATT&CK coverage matrix will show what is covered, what is evaluated, and where the gaps are. The M1 starter set is 15 Linux and network playbooks, chosen for the lab data.

## Design principles

These are non-negotiable. The full text is §1 of [`ENGINEERING_MASTER_PROMPT.md`](ENGINEERING_MASTER_PROMPT.md).

- **A mention is not an action.** Detection uses typed fields. It never substring-matches serialized records.
- **Strong indicators are reported on their own, immediately.** Correlation and attack paths come second. Inferred links are labeled as hypotheses.
- **Negatives must be complete, or they are `unresolved`.** Caps, timeouts, missing fields and partial responses never count as "no match". A rule may claim a complete negative only from evidence that proves absence ([ADR-004](docs/adr/ADR-004-negatives-only-from-kernel-records.md)).
- **Nothing reportable is lost** to UI limits, model context or rendering. One immutable report manifest feeds every renderer, and every citation is checked.
- **The model proposes typed actions only.** It never writes query DSL, Arkime expressions, TShark filters, shell commands or paths. All model output is validated, and telemetry is treated as untrusted data.
- **Read-only toward telemetry.** Nothing is transmitted externally. Secrets never appear in the repo, logs, prompts or reports. ADR-007 proposes one exception: a hosted model, allowed only for public lab data. It needs an install-time switch that the web UI cannot set, puts a banner on every hunt and report that used it, and is never on in release builds.

## How it works

```
mission ─► source inventory ─► field contracts
   │
   ▼
planner ─► search intent ─► compiled query ─► adapter (ES / Arkime / TShark)
                                                   │
                     typed events + entities ◄─────┘
                               │
            detect (playbooks) ─► candidates ─► decide ─► findings (lanes)
                               │                    ▲
                               ▼                    │
              agent: cases ─► brief ─► model ─► validate ─► typed pivot
                               │
                     report manifest ─► JSON | Markdown | web
```

A coverage ledger records every stage that can lose information: compile, execute, ingest, normalize and evaluate. That way the report can say exactly what was and wasn't assessed.

Findings are sorted into lanes: `urgent`, `high`, `lead` and `context`.

The full map is in [`docs/architecture/ARCHITECTURE.md`](docs/architecture/ARCHITECTURE.md). A generated module map is in [`docs/architecture/MODULE_MAP.md`](docs/architecture/MODULE_MAP.md).

## Stack

- **Core:** Python 3.12, organized as a modular monolith (`src/romulus/`).
- **State:** SQLite (WAL) is the single state authority; Alembic handles migrations.
- **Web UI:** FastAPI + Jinja + server-sent events. It has argon2 logins, lead/analyst roles, CSRF protection and a strict CSP.
- **Model:** optional local Ollama today. A provider port for any OpenAI-compatible endpoint is planned (ADR-007). Every model change is measured with the frozen replay harness.
- **No agent framework:** the investigator is an explicit controller with SQLite as the only state ([ADR-001](docs/adr/ADR-001-no-langgraph.md)). This was re-examined for a capable model in [ADR-008](docs/adr/ADR-008-capable-model-agent-no-langgraph.md). That model would get a native tool-calling loop, still without LangGraph.

## Repository layout

| Path | Contents |
|---|---|
| `src/romulus/` | `config`, `store`, `sources`, `evidence`, `detect`, `decide`, `hunt`, `agent`, `report`, `web`, `cli` |
| `tests/` | Unit, acceptance, hostile-input and regression tests |
| `scripts/` | `deploy.ps1` (deploy to the lab VM), `web-restart.sh`, `archmap.py`, `smoke_live.py` |
| `docs/adr/` | Architecture decision records |
| `docs/project/` | Status, milestones, team process, lab environment |
| `docs/design/` | Design notes (deterministic expansion, network correlation, investigator) |
| `.env.example` | Configuration template. Copy it to `$ROMULUS_HOME/.env`, then `chmod 600` |

## Getting started

### Install

```bash
python3.12 -m venv venv
venv/bin/pip install -e .
cp .env.example "$ROMULUS_HOME/.env"   # fill in sources, model endpoint and secret key
```

Use a **read-only** Elasticsearch account, never the `elastic` superuser. Keep `OLLAMA_NUM_CTX` explicit, because Ollama truncates prompts silently.

Today every setting lives in `.env`. A lead-only **Settings** page is planned (ADR-009). It will write source credentials, model keys and hunt defaults to `$ROMULUS_HOME/config/settings.env`. Secrets will be write-only, and the page will require TLS. Bootstrap keys stay in `.env`: home, bind address, TLS, session key and the model egress switch.

### Run

```bash
romulus --env-file .env doctor
```

```bash
romulus --env-file .env hunt start --start 2026-01-01T10:00:00Z --end 2026-01-01T17:30:00Z
```

| Command | What it does |
|---|---|
| `doctor` | Checks sources, privileges, the model endpoint, tools and storage |
| `hunt start --start <ISO> --end <ISO> [--no-agent]` | Runs a sweep and then the investigator. `--no-agent` runs the sweep only |
| `hunt resume <id>` / `hunt status [id]` | Resumes the investigator without rerunning the sweep / shows hunt state |
| `findings <hunt> [--lane urgent --lane high]` | Lists ranked findings |
| `report <hunt>` | Publishes a new immutable report revision (JSON + Markdown) |
| `user add <name> --role lead\|analyst` | Creates a web UI account (interactive) |
| `web` | Serves the browser UI on `ROMULUS_WEB_BIND` |

### Tests

```bash
python -m pytest -q -p no:warnings
```

Install the dev dependencies (`pytest`, `respx`, `ruff`) first.

## Lab and evaluation

Development is evaluated against the public AInception SL700 dataset, loaded into Elasticsearch and Arkime on a lab VM. Ground truth is kept out of the runtime and is read only by the evaluation role. Lab results are reported with the spec's status words (`implemented`, `locally tested`, `integration tested`, `lab evaluated`, `holdout evaluated`, `production validated`), never as general effectiveness claims.

## History

This repository previously held ROMULUS v1. The v1 `main` is preserved on the [`archive/v1-main`](https://github.com/nickthabib-cloud/ROMULUS/tree/archive/v1-main) branch.
