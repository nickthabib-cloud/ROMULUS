# ADR-002: Modular monolith on the VM; FastAPI/HTMX; SQLite; Ollama on the Windows host

**Status:** Accepted, 2026-10-18 (owner confirmed the topology)

## Context

There is one operator today, a team lead and analysts later, and an eventual air-gapped CPT kit. The data sources (ES, Arkime, PCAPs) live on the Ubuntu VM. The GPU, and so Ollama, is on the Windows host. TShark must run where the PCAPs are.

## Decision

- One Python 3.12 application (`src/romulus`) deployed on the VM: a web process (FastAPI, Jinja2, HTMX, SSE) plus a hunt worker process, communicating only through SQLite (WAL, single writer coordinator, Alembic migrations).
- The VM reaches Ollama over the host-only network at `192.168.36.1:11434`.
- Reports: executive DOCX (`python-docx` with a styled template), technical Markdown, and canonical JSON.
- Search backends behind one port: Elasticsearch 9.x and OpenSearch 2.x (Malcolm).
- No Node build chain. Front-end libraries (HTMX, Cytoscape.js, chart library) are vendored for air-gap installs.

## Rejected alternatives

- **Microservices, a queue broker, or Postgres now**: there is no measured concurrency or volume need. The repository layer stays Postgres-capable.
- **React SPA**: it needs a build chain and a second language for little gain at this scale.
- **Running ROMULUS on Windows**: TShark would have to reach PCAPs remotely, and the web UI belongs next to the data.
- **PDF executive report**: the owner wants DOCX so the team lead can edit before release.

## Revisit if

Multiple concurrent hunts or many simultaneous analysts saturate SQLite, or a deployment target makes the VM/host split unavailable.
