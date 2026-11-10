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
| `sources` | Source profiles, field contracts, typed query compilation, read-only Elasticsearch/OpenSearch (one request allowlist per flavor, flavor and version confirmed from the cluster), Arkime and TShark adapters |
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

## Linux text logs

Known shipper shapes retain their existing normalization. The last host-log route, `linux.text`, identifies
otherwise unclaimed text by its content, including operator-named datasets and file or stream inputs without a
dataset value. A stateless classifier accepts at most 64 KiB per line and recognizes syslog envelopes, common
web access/error formats and documented native application formats. It separates the envelope from the daemon's
anchored message grammar; text that merely mentions an action is not an event. Structured fields retain their
source paths, while fields parsed from a line identify that line and parser in their provenance.

The indexed `@timestamp` remains the event time. Inline timestamps and clock differences are diagnostic fields;
timestamps without a year or zone use the indexed timestamp's year or zone for that comparison. A syslog header's
hostname is provenance, distinct from the shipper's host identity. Unrecognized and oversized lines are counted
skips, and unknown formats leave potentially affected text detection families unresolved. Recognized envelopes
from unsupported programs are counted without making those families partial. Module-owned unsupported records
retain their module's coverage scope; Windows and network targets do not use the Linux text fallback.

New daemon parsing checks every available trusted journal writer field against the program identity. A mismatch
is a named skip; missing writer evidence adds a caveat. Plain syslog cannot authenticate its program name.
PAM authentication records for services with a native decision grammar are skipped to avoid counting the same
attempt twice; their session records remain typed. OpenSSH helper PAM records use the helper's service name and
feed only the generic rules, while the existing SSH normalization keeps its original behavior.

Service authentication, resolver requests, proxy requests, firewall packets, scheduler observations and account
changes use the existing `auth`, `dns_query`, `http_access`, `net_flow`, `process_observed`, `service_change` and
`account_change` families. Authentication sessions are distinguished from authentication decisions. Firewall
log records do not invent connection counters, and a cron command log does not claim a kernel-observed exec.
Two additional families preserve information that those contracts cannot express:

| Family | Typed fields and limits |
|---|---|
| `mail_message` | `mail.service`, queue `mail.message_id`, explicit `mail.direction`, sender, recipients, size, relay, TLS and authenticated user where logged. `mail.to` retains at most 32 recipients with the full `mail.to_count` and a truncation caveat. Current MTA parsers supply no attachment names, so attachment detection is positive-only with that coverage limitation. Each line remains a separate event; rules join queue metadata with disk-backed state. |
| `vpn_session` | `vpn.service`, `vpn.action`, logged identity, peer address/port, assigned virtual addresses and native session ID where available. Assigned addresses are entity links. Connection overlap requires matching explicit start/end boundaries; a common name is not asserted to be an authenticated username. |

Generic authentication rules isolate each concrete service and preserve the separate SSH rules. Mail burst
analysis requires explicitly configured `mail_domains` to identify external recipients. VPN source novelty
requires sufficient historical baseline coverage. Aggregate evaluators spill state to disk; refused records
and incomplete fields remain visible as coverage gaps.

Source profiles preserve actual dataset names and counts, with a non-additive `linux.text` capability summary.
Doctor describes format and program counts from samples of at most 1,000 records per dataset; samples are not
extrapolated to whole-source typing claims. A dataset enters the text retrieval inventory only when its sample
contains a text payload; otherwise the report names the absent payload or incomplete sample. Reports name
unrecognized datasets and unsupported programs with the counts observed during the hunt. Text shape and skip
labels are bounded to 256 characters.

## Dependency rules (enforced by `archmap.py --check`)

- `web` and `cli` may import anything below them, but nothing imports `web` or `cli`.
- `detect`, `decide`, and `report` never import `sources` adapters directly. They work on stored typed data.
- `agent` emits validated typed pivots without importing any module under `romulus.sources`. The hunt-layer pivot executor converts them to `SearchIntent`s and owns source access.
- `baseline` defines source-neutral typed keys and imports neither `hunt` orchestration nor `sources` adapters.
- `store` imports no domain logic packages.

Update this section and `LAYER_RULES` in `scripts/archmap.py` together.
