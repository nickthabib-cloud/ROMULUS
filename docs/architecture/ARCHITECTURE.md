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
evidence ranking, pass 1 ─► Reported set on confirmed entities ─► expansion seeds
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
- Every other `high` or `lead` finding is in the **ranked pool**. That includes a cited positive whose admission is incomplete (a predicate field without lineage, or no affected entity): it is kept as a lead at medium severity at most, with a note naming what is missing, so a rule's positive never drops out of sight. Context and suppressed records stay outside the pool as supporting records.
- **Entities.** A host-telemetry finding counts toward its host and account. An account named with a domain or by SID is one entity across hosts; a bare local name is qualified by its host. A network-telemetry finding counts toward its endpoints: internal addresses first, at most two. An internal endpoint is the host whose own telemetry owns that address unambiguously in the hunt, else the address; an external endpoint is an `ip` entity. A network sensor is never an entity, and well-known principals that exist on every host (SYSTEM, root) are not entities. A finding with none of these is `unattributed`: it is ranked on its own prior and listed.
- **Entity evidence**, from the hunt's deterministic findings only: confirmed findings (U), ATT&CK tactic breadth (T: a maximum matching of rules to the tactics each maps to, so each rule adds at most one tactic; tactics come from the vendored ATT&CK data), distinct rules (R), and pairs of rules that fire within an hour of each other (C, capped). A rule whose confirmed and pool findings fall on at least half of the hunt's hosts with any deterministic candidate (and at least three) over at least half of the window is *recurring fleet-wide*: it counts toward no entity, and its findings rank lower but are never removed. A short burst across the fleet is not penalized.
- **Entity score** = 40·U + 10·T + 5·R + 3·C + the strongest rule prior among its findings. **Finding rank** = its best entity's score + its own rule prior, less 30 for a recurring fleet-wide rule; ties break on time, then id. Every score carries its reasons.
- **Reported set**: every confirmed finding, plus every pool finding on an entity that meets the evidence bar (U ≥ 1, or T ≥ 2, or R ≥ 3 with C ≥ 1). It is a structural criterion, not a count budget. Nothing is hidden: findings below the bar are listed in rank order.
- Findings the AI agent proposes are ranked like any other, but never count toward an entity's evidence, so the model cannot raise the rank of its own targets.

Pass 1 runs after the sweep, packet and baseline stages and adds to expansion's seeds. The findings the rule estimate seeds (urgent and high) keep their budget share and order; the rest of the Reported set whose listed entity (the finding's best-scoring entity) carries a confirmed finding is anchored after them, a page at a time in rank order, only while source queries and wall-clock time remain, and spends only the budget left; the seeds never reached are counted in the expansion summary. Each host a lead is on (each internal endpoint of a network lead, anchored while either end has a place) anchors at most ten timed such seeds, its best-ranked first and at most two from one rule: the leads on one host share its evidence, so further anchors there mostly fetch the same records again, and the bound keeps expansion's work proportional to the hosts an intrusion touched rather than to how many leads each carries. The bound is per host, never per account or address, so a lead listed under a compromised account or a command-and-control address is anchored on each host it was seen on. The findings past it stay Reported, and the summary counts them with the per-host reason. An entity reported for its tactic or rule breadth alone gives no extra seed: a busy server's benign activity spans tactics, and widening around every lead there multiplies link work and correlation items without reaching more of an intrusion. Anchors the budget does not reach stay listed with the budget reason, so expansion never does less than it did by the rule estimate alone. Pass 2 runs after expansion and its context pass. Findings stored after it (the AI agent's proposals and its pivots' rule matches) are placed into it when the agent's run ends: each is scored from the pass's stored entity scores and inserted by that score, and the pass is not recomputed, so nothing the agent stored changes an earlier finding's rank or an entity's score, or lowers the hunt's result; a rule match the agent's pivots found counts toward the result once placed. Each pass is computed in keyset pages over temporary staging tables, so memory is bounded by one page whatever the hunt's size, and is published in one transaction that replaces the hunt's previous rows for that pass. A hunt stored without ranks renders exactly as it did.

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

## Windows host source shapes

Windows event logs can arrive as Winlogbeat or Elastic Agent records, flat NXLog records, or native EVTX JSON.
The EVTX adapter accepts the `Event.System` envelope with nested `#attributes` or separate `*_attributes` maps.
It presents the same structured view to normalization, continuity and duplicate checks while every typed field
points back to its original JSON path. Provider, computer, channel and event identity are required. Malformed
identities are counted; an arbitrary application `Event` object or a wrapped export is not a Windows record.
Native timestamps retain their precision, and a pipeline `@timestamp` takes precedence when present. Recovered
records retain a caveat. Empty native values and renderer-specific differences remain visible in the evidence.

Live source classification uses dataset inventory or a bounded count of actual Windows markers. A shared
mapping alone does not turn a network index into a Windows host. Network targets retain their role and report
Windows records as not evaluated. Failed classification checks retain the conservative Windows hint and name
the uncertainty. Field aliases follow the classification and the mapping's actual types and keyword subfields.

A Windows host index can also contain Linux text. A bounded count looks for a text payload without Windows
markers. Windows and text alternatives share one source query, and dispatch assigns each record to one
normalizer. An unavailable text count makes text coverage unresolved; unsupported text affects its own families.
When a text record lacks an indexed hostname, a valid syslog header supplies its short lowercased hostname with
native provenance and a caveat. Indexed hostnames take precedence; nil values and localhost do not identify a
host, and an IP literal can supply only `host.ip`.

Source retrieval uses one mapped time field for ordered paging. A native timestamp is selected when the primary
pipeline field is absent from the mapping. Where records instead require another mapped time field, profile
checks count those omissions and affected retrieval remains unresolved. The report must not claim complete
coverage of rows that its time query cannot reach.

## eCAR endpoint evidence

The `ecar@1` producer reads the public [eCAR record schema](https://github.com/FiveDirections/OpTC-data/blob/master/ecar.md),
its [path and duplication errata](https://github.com/FiveDirections/OpTC-data/blob/master/errata.md), and the
[CAR object vocabulary](https://car.mitre.org/data_model/). `ecar_catalog.py` separates documented rows from
expected export vocabulary. Synthetic fixtures exercise each row; no data-specific assumptions are required.

The source uses its record UUID for duplicate identity, distinct from the acting process or process-object UUID.
Batch duplicates merge raw citations and cross-batch duplicates use disk-backed staging. Process identities
remain eCAR-specific; a parent identified only by PID retains the existing fenced-PID semantics. Device and
drive paths use the Windows canonicalizers. Epoch-millisecond `timestamp` and `timestamp_ms` are accepted,
with a pipeline timestamp taking precedence.

Raw sweep detection and UUID deduplication accept the UUID spellings allowed by the producer. UUID aliases
expose existence checks only: normalized process/event UUIDs cannot safely be matched or grouped by raw source
spellings, so UUID-keyed value pivots and links are unsupported. String IP, numeric and normalized account aliases
also withhold exact operations when their source spelling cannot guarantee a complete match. Host and supported
native-field expansion retain their ordinary coverage checks.

Catalogued rows feed existing event families. File MODIFY, WRITE and READ and local thread CREATE and TERMINATE
are counted as not typed. Unknown properties and malformed values are counted against the mapped family;
unknown object/action pairs are counted without assigning an invented family. Pair inventories retain a bounded
set of labels with an explicit overflow count, and catalogued pairs retain their own counts.

eCAR does not supply Windows event IDs, channels or providers. Rules whose class gates can be expressed through
process, socket, image, registry or file semantics use those fields and cite native object/action values.
Rules that require event-log-specific meaning remain unresolved with the missing Windows event identity reason.
Event-log collection settings do not attest an eCAR sensor: its collection remains explicitly unattested.

Hunt manifests record each evidence producer version. Resume compares every recorded producer with the running
build and refuses a mismatch before fetching more records. Older manifests retain the checks they recorded.

## Dependency rules (enforced by `archmap.py --check`)

- `web` and `cli` may import anything below them, but nothing imports `web` or `cli`.
- `detect`, `decide`, and `report` never import `sources` adapters directly. They work on stored typed data.
- `agent` emits validated typed pivots without importing any module under `romulus.sources`. The hunt-layer pivot executor converts them to `SearchIntent`s and owns source access.
- `baseline` defines source-neutral typed keys and imports neither `hunt` orchestration nor `sources` adapters.
- `store` imports no domain logic packages.

Update this section and `LAYER_RULES` in `scripts/archmap.py` together.
