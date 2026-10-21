# ROMULUS
NOTE: This tool is a very early proof of concept in progress. I'm updating and making changes daily.

A defensive, AI-assisted threat-hunting tool.

ROMULUS runs a deterministic sweep over host and network telemetry: Elasticsearch/OpenSearch logs, Arkime sessions, and PCAPs read with TShark. Deterministic expansion then follows typed links from the strongest findings (process lineage, login session, network flow), judges the linked records in context, and assembles incidents. Every claim cites the raw evidence. ROMULUS can work with or without a large language model by performing deterministic searches.

**Planned: the AI investigating agent**. After the deterministic layer, the agent:
- reads every indicator found in initial sweeps;
- develops hypotheses about malicious activity;
- follows further leads through typed, read-only pivots, and finds more indicators;
- connects them into a bigger picture.

The final report opens with its **AI assessment**: the agent's overall hypothesis, every sentence cited, labelled as AI-generated and unconfirmed. The agent can add findings, labelled as agent findings and capped at `high`. It can never hide, close or demote findings.

For testing purposes the model is reached through any OpenAI API. Earlier iterations used a local LLM through Ollama, but compute limitations hindered adequate agentic investigations. Actual teams use their own LLM server.

The full plan (how the agent connects to a model, keeps telemetry on site, what it may add, the report's AI assessment, safety and budgets) is in [`docs/architecture/ai-investigating-agent.md`](docs/architecture/ai-investigating-agent.md).

Outputs:

- ranked findings
- incidents with a cited, template narrative
- an attack-path timeline
- recommendations
- a technical Markdown/JSON report (an executive DOCX is planned)
- a browser UI for analysts

> **Status:** under active development and not yet validated for production missions.

## Detection scope

The goal is to find any malicious activity the telemetry can show, on any mission network. The detection catalog is built from systematic research:
- MITRE ATT&CK Enterprise and ICS techniques;
- Public detection corpora (Sigma, CAR, Atomic Red Team, LOLBAS/GTFOBins, ET Open and others);
- Any telemetry family a hunt may meet: Windows, AD, Linux, macOS, identity and cloud logs, network devices, Zeek, Suricata, PCAP and ICS protocols.

A generated ATT&CK coverage matrix will show what is covered, what is evaluated, and where the gaps are.

## Design principles

- **Strong indicators are reported on their own, immediately.** Correlation and attack paths come second. Inferred links are labeled as hypotheses.
- **Nothing reportable is lost** to UI limits, model context or rendering. One immutable report manifest feeds every renderer, and every citation is checked.
- **The model proposes typed actions only.** It requires input validation for DSL queries, Arkime expressions, TShark filters. All model output is validated, and telemetry is treated as untrusted data.
- **Read-only toward telemetry.** Nothing is transmitted externally. Secrets never appear in the repo, logs, prompts or reports. One exception: a hosted model, used for testing on public data only. It needs an install-time switch, puts a banner on every hunt and report that used it, and is never on in release builds.

## How it works

A coverage ledger records every stage that can lose information: compile, execute, ingest, normalize and evaluate. That way the report can say exactly what was and wasn't assessed.

Findings are sorted into lanes: `urgent`, `high`, `lead` and `context`.

The full map is in [`docs/architecture/ARCHITECTURE.md`](docs/architecture/ARCHITECTURE.md). A generated module map is in [`docs/architecture/MODULE_MAP.md`](docs/architecture/MODULE_MAP.md).

## Stack

- **Core:** Python 3.12, organized as a modular monolith (`src/romulus/`).
- **State:** SQLite (WAL) is the single state authority; Alembic handles migrations.
- **Web UI:** FastAPI + Jinja + server-sent events. It has argon2 logins, lead/analyst roles, CSRF protection and a strict CSP.
- **Model:** optional. The agent's model connection takes any OpenAI-compatible endpoint (or Ollama), keeps telemetry on site unless a bootstrap switch allows a public-data test endpoint, and is checked by `romulus doctor`; the agent's investigation loop is still being built. The agent is scored on and off by the evaluation harness.
- **The Agent:** Uses native tool calling through the investigator, an explicit controller with SQLite as the only state.

## Repository layout

| Path | Contents |
|---|---|
| `src/romulus/` | `config`, `store`, `sources`, `evidence`, `detect`, `decide`, `hunt`, `agent`, `report`, `web`, `cli` |
| `tests/` | Unit, acceptance, hostile-input and regression tests |
| `scripts/` | `deploy.ps1` (deploy to a Linux host over SSH), `web-restart.sh`, `archmap.py`, `smoke_live.py` |
| `content/` | Indicator lists and vendored MITRE ATT&CK data |
| `docs/architecture/` | Architecture overview, the generated module map, and the planned AI investigating agent |
| `.env.example` | Configuration template. Copy it to `$ROMULUS_HOME/.env`, then `chmod 600` |

## Getting started

### Install

```bash
python3.12 -m venv venv
venv/bin/pip install -e .
cp .env.example "$ROMULUS_HOME/.env"   # fill in sources, model endpoint and secret key
```

Use a **read-only** Elasticsearch account, never the `elastic` superuser. The model is optional: leave `OLLAMA_URL` empty to run model-off. If you use Ollama, keep `OLLAMA_NUM_CTX` explicit, because Ollama truncates prompts silently.

Every setting, including agent provider keys, lives in `.env`. A lead-only Settings page for credentials is planned for a later release.

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

The web UI shows each hunt's findings, incidents and an attack-path timeline (`/hunts/<id>/timeline`).

### Tests

```bash
python -m pytest -q -p no:warnings
```

Install the dev dependencies (`pytest`, `respx`, `ruff`) first.

## Evaluation

Development is evaluated against the public Zenodo dataset, loaded into Elasticsearch and Arkime. Ground truth is kept out of the runtime and is read only by the evaluator (set `ROMULUS_EVAL_ROOT` so `doctor` checks that no source path overlaps it). Results on a development dataset are never presented as general effectiveness claims.
